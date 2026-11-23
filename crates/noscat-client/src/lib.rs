//! noscat-client: the UI-facing layer of the noscat stack.
//!
//! Everything a graphical client needs and a terminal does not: an owned
//! async runtime, identity/relay/mesh configuration resolved once, and an
//! event stream instead of stderr prints. The primitives are small:
//!
//! - [`Client::connect`] - dial a peer by npub, get the tunnel as a plain
//!   [`TunnelStream`] (`AsyncRead` + `AsyncWrite` of plaintext bytes),
//! - [`Client::listen`] - publish the advert and accept tunnels in the
//!   background; each surfaces as an [`Event::Incoming`] carrying its stream.
//!
//! Everything else is composition on those two: `pipe_stdio` and
//! `serve_stdio` bridge the streams to this process's stdio (that is the
//! whole CLI data plane), `expose` splices incoming streams to a local TCP
//! service, `forward` dials a tunnel per local TCP connection, and
//! `send_file`/`receive_file` delegate to the core's verified transfer
//! protocol. Outcomes arrive as events, so frontends never block on details
//! they do not care about.
//!
//! The CLI (`crates/noscat`) is built on this crate too - it is a terminal
//! skin over the same API a GUI consumes, which keeps the layer honest.
//!
//! ```no_run
//! use noscat_client::{Client, ClientConfig, Event};
//!
//! # fn main() -> Result<(), noscat_client::ClientError> {
//! let mut client = Client::start(ClientConfig::default())?;
//! let events = client.events().take().expect("fresh client");
//! client.pipe_stdio("<peer npub>")?; // blocks until the session closes
//! for ev in events {
//!     if let Event::TunnelClosed { error, .. } = ev {
//!         eprintln!("session ended: {error:?}");
//!     }
//! }
//! # Ok(())
//! # }
//! ```

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::mpsc as std_mpsc;
use std::sync::Arc;


use noscat_core::relay::DEFAULT_RELAYS;
use noscat_core::tunnel::{self, TunnelInlet, TunnelStream};
use noscat_core::Identity;
use tokio::io::AsyncWriteExt;

/// Where the client's identity comes from.
#[derive(Clone)]
pub enum IdentitySource {
    /// A fresh ephemeral keypair (the netcat default).
    Ephemeral,
    /// An existing identity, hex secret or `nsec1...`.
    Secret(String),
    /// A file holding the secret; generated and written on first use if missing.
    File(PathBuf),
}

impl std::fmt::Debug for IdentitySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // ClientConfig derives Debug and UIs log it; the secret must never
        // ride along.
        match self {
            Self::Ephemeral => write!(f, "Ephemeral"),
            Self::Secret(_) => write!(f, "Secret(<redacted>)"),
            Self::File(path) => write!(f, "File({path:?})"),
        }
    }
}

/// One-shot text payloads (chat, clipboard share) read into memory by
/// the node dispatcher: this caps them. A mesh peer streaming more is a
/// malformed sender, not a message to buffer.
const MAX_TEXT_BYTES: usize = 1 << 20;

/// Concurrent tunnel dials allowed per forward: each is a full handshake,
/// and a loopback client can open connections faster than they complete.
static FORWARD_DIAL_PERMITS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(16);

/// Everything a client session needs, resolved once at [`Client::start`].
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub identity: IdentitySource,
    /// Relay URLs. `None` uses the core's default public set.
    pub relays: Option<Vec<String>>,
    /// The UDP listen address for serve-side tunnels.
    pub listen: Option<SocketAddr>,
    /// A mesh device directory: tunnels are scoped to the group's epoch
    /// PSK, so only members can connect or be dialed.
    pub mesh_dir: Option<PathBuf>,
    /// Friendly device name published in the advert (peers display it).
    /// `None` keeps the advert unnamed; UIs then fall back to labels.
    pub device_name: Option<String>,
    /// Advert lifetime in seconds.
    pub advert_ttl_secs: u64,
    /// Receive-side disk cap per transfer (see
    /// [`noscat_core::tunnel::MAX_INCOMING_BYTES`] for the default's
    /// rationale). `None` keeps the wire ceiling (~5.4 TiB) as the only
    /// limit.
    pub max_incoming_bytes: Option<u64>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            identity: IdentitySource::Ephemeral,
            relays: None,
            listen: None,
            mesh_dir: None,
            device_name: None,
            advert_ttl_secs: noscat_core::advert::ADVERT_TTL_SECS,
            max_incoming_bytes: None,
        }
    }
}

/// What the client does on its own, surfaced for UIs.
pub enum Event {
    /// The serve side is up: the advert is published, tunnels are accepted.
    Listening {
        npub: String,
        addr: SocketAddr,
    },
    /// An inbound tunnel completed its handshake (listener mode).
    Incoming {
        peer: String,
        addr: SocketAddr,
        stream: TunnelStream,
    },
    /// A dialed or accepted tunnel is ready for traffic.
    TunnelUp {
        peer: String,
        addr: SocketAddr,
    },
    /// A tunnel ended; `error` is set when it was not a clean close.
    TunnelClosed {
        peer: String,
        error: Option<String>,
    },
    /// A file transfer finished cleanly (path is the source on send, the
    /// verified final path on receive).
    TransferDone {
        peer: String,
        path: PathBuf,
    },
    /// A receive ended WITHOUT a verified whole file: the kept
    /// `.noscat-part` is only a resume seed, not a usable file.
    TransferPartial {
        peer: String,
        path: PathBuf,
    },
    /// A file transfer is under way: `sent` of `total` bytes acked by the
    /// peer. Emitted per percent change, only for sends (the receiver has
    /// no ack stream of its own).
    TransferProgress {
        peer: String,
        path: PathBuf,
        sent: u64,
        total: u64,
    },
    /// A file transfer failed.
    TransferFailed {
        peer: String,
        path: Option<PathBuf>,
        error: String,
    },
    /// A file transfer was cancelled by this side (see
    /// [`Client::cancel_transfer`]): the receiver keeps its resumable
    /// partial, and a later send of the same file resumes.
    TransferCancelled {
        peer: String,
        path: PathBuf,
    },
    /// A forward ended: it was cancelled ([`Client::cancel_forward`]) or
    /// failed (`error` set - bind failure, accept failure). The id lets
    /// the UI drop it from its forward list.
    ForwardStopped {
        id: u64,
        error: Option<String>,
    },
    /// A one-shot chat message arrived over the node dispatcher.
    ChatMessage {
        peer: String,
        text: String,
    },
    /// A peer shared their clipboard: `text` should become the local
    /// clipboard contents.
    Clipboard {
        peer: String,
        text: String,
    },
    /// Sending a chat message failed (the UI keeps its optimistic copy and
    /// can mark it undelivered).
    ChatFailed {
        peer: String,
        error: String,
    },
    /// A chat message or clipboard share was delivered: the peer echoed
    /// the tunnel's FIN once the text was in hand. The UI's "delivered"
    /// tick.
    ChatDelivered {
        peer: String,
    },
    /// A background operation (listener, expose, forward) stopped.
    Stopped {
        what: &'static str,
        error: Option<String>,
    },
}

/// A stream with one byte pushed back in front of it: the node dispatcher
/// consumes the first byte to sniff the stream type, and the bridge path
/// needs it back as the first byte of the raw payload.
struct PrefixedStream<S> {
    first: Option<u8>,
    inner: S,
}

impl<S> PrefixedStream<S> {
    fn new(first: u8, inner: S) -> Self {
        Self { first: Some(first), inner }
    }
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if let Some(b) = self.first.take() {
            buf.put_slice(&[b]);
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {    #[error("identity: {0}")]
    Identity(String),
    #[error("mesh: {0}")]
    Mesh(String),
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Tunnel(#[from] tunnel::TunnelError),
}

struct Inner {
    rt: tokio::runtime::Runtime,
    identity: Identity,
    npub: String,
    psk: Option<[u8; 32]>,
    device_name: Option<String>,
    /// Mesh device directory, when scoped to one. Read on every tunnel:
    /// the epoch PSK changes when members join or are removed, and long
    /// running peers must pick up the new secret without a restart.
    mesh_dir: Option<PathBuf>,
    relays: Vec<String>,
    listen: SocketAddr,
    ttl: u64,
    events: std_mpsc::Sender<Event>,
    /// Liveness of mesh-mates, fed by the advert watcher `up` starts.
    /// Shared and never reset: relay reconnects only pause the feed.
    presence: std::sync::Arc<noscat_core::relay::Presence>,
    /// In-flight sends keyed by (peer, path string): their cancel flags.
    /// Concurrent sends of the same file to the same peer all live here:
    /// a cancel fans out to all of them, and each task removes only its
    /// own flag, so a finishing send never orphans a running one.
    cancels: std::sync::Mutex<
        std::collections::HashMap<
            (String, String),
            Vec<std::sync::Arc<std::sync::atomic::AtomicBool>>,
        >,
    >,
    /// Receive-side disk cap per transfer (the client config's
    /// `max_incoming_bytes`).
    max_incoming: u64,
    /// Active forwards: id -> entry. `cancel_forward` wakes the accept
    /// loop; the forward's own task removes the entry when it ends.
    forwards: std::sync::Mutex<std::collections::HashMap<u64, ForwardEntry>>,
    next_forward_id: std::sync::atomic::AtomicU64,
}

/// A running forward: what it dials, where it listens, and the wake that
/// stops its accept loop.
struct ForwardEntry {
    target: String,
    local: SocketAddr,
    cancel: std::sync::Arc<tokio::sync::Notify>,
}

/// A forward as the UI's list shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardInfo {
    pub id: u64,
    /// The npub the forward dials per connection.
    pub target: String,
    /// The local TCP address it listens on.
    pub local: SocketAddr,
}

impl Inner {
    /// Emit an event; a dropped receiver just means nobody is listening.
    fn emit(&self, ev: Event) {
        let _ = self.events.send(ev);
    }

    /// Bind the serve-side UDP listener and publish the advert: the shared
    /// first step of [`Client::listen`], [`Client::up`],
    /// [`Client::serve_stdio`], and [`Client::expose`]. Returns the
    /// configured listener and its local address, emitting
    /// [`Event::Listening`].
    fn bind_and_announce(&self) -> Result<(tunnel::TunnelListener, SocketAddr), ClientError> {
        let mut listener = self.rt.block_on(tunnel::bind_listener(
            &self.identity,
            self.listen,
            &self.relays,
            self.ttl,
            self.psk.as_ref(),
            self.device_name.as_deref(),
        ))?;
        if let Some(dir) = &self.mesh_dir {
            listener.set_mesh_dir(dir.clone());
        }
        let addr = listener.local_addr();
        self.emit(Event::Listening {
            npub: self.identity.npub(),
            addr,
        });
        Ok((listener, addr))
    }

    /// The mesh PSK as of *now*: re-derived from the device directory so
    /// an epoch change (a join or removal elsewhere) applies to the next
    /// tunnel without a client restart. Falls back to the cached secret
    /// when the directory cannot be read.
    fn fresh_psk(&self) -> Option<[u8; 32]> {
        match &self.mesh_dir {
            Some(dir) => {
                // Opening the MLS group (SQLite + crypto export) is
                // blocking work; keep it off the async workers. A failure
                // falls back to the session's PSK: a stale epoch beats no
                // tunnel.
                let dir = dir.clone();
                let fallback = self.psk;
                tokio::task::block_in_place(|| {
                    noscat_core::mesh::Device::open(&dir)
                        .and_then(|d| d.tunnel_psk())
                        .ok()
                        .and_then(|psk| <[u8; 32]>::try_from(psk).ok())
                        .or(fallback)
                })
            }
            None => self.psk,
        }
    }

    /// Dial a peer and finish the session into a byte stream (async half of
    /// [`Client::connect`], reused by the forward loop).
    async fn dial(&self, target: &str) -> Result<(TunnelStream, SocketAddr), tunnel::TunnelError> {
        let psk = self.fresh_psk();
        let session = tunnel::dial_session(&self.identity, target, &self.relays, psk.as_ref()).await?;
        let (socket, peer, hs, who) = session.finish().await;
        let stream = TunnelStream::new(socket, peer, hs, TunnelInlet::Exclusive, who);
        Ok((stream, peer))
    }

    /// Bridge a tunnel stream to this process's stdio with netcat
    /// half-close semantics: local EOF sends a FIN, a peer FIN surfaces as
    /// EOF on stdout.
    async fn bridge_stdio(stream: TunnelStream) -> Result<(), tunnel::TunnelError> {
        let (mut rd, mut wr) = tokio::io::split(stream);
        let up = tokio::spawn(async move {
            let mut sin = tokio::io::stdin();
            let n = tokio::io::copy(&mut sin, &mut wr).await?;
            // stdin EOF: send the FIN so the peer sees a clean half-close.
            wr.shutdown().await?;
            io::Result::Ok(n)
        });
        let mut sout = tokio::io::stdout();
        let down = tokio::spawn(async move {
            let n = tokio::io::copy(&mut rd, &mut sout).await?;
            io::Result::Ok(n)
        });
        // Either direction ending is progress; both ending is the session.
        let up = up.await.map_err(|e| io::Error::other(e))??;
        let down = down.await.map_err(|e| io::Error::other(e))??;
        let _ = (up, down);
        Ok(())
    }
}

/// A running noscat client. Cloneable handle; dropping the last handle stops
/// the background runtime and all its tasks. Only the first clone holds the
/// event receiver (see [`Client::events`]).
pub struct Client {
    inner: Arc<Inner>,
    events_rx: Option<std_mpsc::Receiver<Event>>,
}

impl Clone for Client {
    fn clone(&self) -> Self {
        Client {
            inner: self.inner.clone(),
            events_rx: None,
        }
    }
}

/// Join two spliced copy tasks: surface whichever task's own io error
/// (a JoinError means the runtime is dying - same treatment).
async fn flatten_join<T: Send + 'static>(
    h: tokio::task::JoinHandle<io::Result<T>>,
) -> io::Result<T> {
    h.await.map_err(|e| io::Error::other(e))?
}

impl Client {
    /// Resolve the config, start the runtime, and publish nothing yet: the
    /// client is idle until a command is issued.
    pub fn start(config: ClientConfig) -> Result<Client, ClientError> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let identity = match &config.identity {
            IdentitySource::Ephemeral => Identity::generate(),
            IdentitySource::Secret(s) => Identity::from_secret(s)
                .map_err(|e| ClientError::Identity(e.to_string()))?,
            IdentitySource::File(path) => {
                if !path.exists() {
                    // First run on this node: generate the identity and store
                    // it, so `--identity <file>` is the whole setup. Durable
                    // and owner-only via the shared fsutil helper; a lost
                    // create race (concurrent first runs) reads the winner
                    // instead of overwriting it - generate() above is
                    // simply discarded.
                    let identity = Identity::generate();
                    let secret = identity.secret_hex();
                    if let Some(dir) = path.parent() {
                        std::fs::create_dir_all(dir).map_err(|e| {
                            ClientError::Identity(format!(
                                "cannot create {}: {e}",
                                dir.display()
                            ))
                        })?;
                    }
                    match noscat_core::fsutil::create_secret_file(path, &secret).map_err(|e| {
                        ClientError::Identity(format!(
                            "cannot write {}: {e}",
                            path.display()
                        ))
                    })? {
                        true => identity,
                        false => {
                            let secret = std::fs::read_to_string(path).map_err(|e| {
                                ClientError::Identity(format!(
                                    "cannot read {}: {e}",
                                    path.display()
                                ))
                            })?;
                            Identity::from_secret(secret.trim())
                                .map_err(|e| ClientError::Identity(e.to_string()))?
                        }
                    }
                } else {
                    let secret = std::fs::read_to_string(path).map_err(|e| {
                        ClientError::Identity(format!("cannot read {}: {e}", path.display()))
                    })?;
                    #[cfg(unix)]
                    {
                        // A pre-existing world-readable identity is a leaked
                        // secret: refuse rather than use it silently (the
                        // mesh device heals its own file the same way).
                        use std::os::unix::fs::PermissionsExt as _;
                        let mode = std::fs::metadata(&path)
                            .map(|m| m.permissions().mode())
                            .unwrap_or(0o600);
                        if mode & 0o077 != 0 {
                            return Err(ClientError::Identity(format!(
                                "{} is readable by other users (mode {:o}); chmod 600 it and retry",
                                path.display(),
                                mode & 0o777
                            )));
                        }
                    }
                    Identity::from_secret(secret.trim())
                        .map_err(|e| ClientError::Identity(e.to_string()))?
                }
            }
        };
        let psk = match &config.mesh_dir {
            Some(dir) => {
                let device = noscat_core::mesh::Device::open(dir)
                    .map_err(|e| ClientError::Mesh(e.to_string()))?;
                let psk = device
                    .tunnel_psk()
                    .map_err(|e| ClientError::Mesh(e.to_string()))?;
                Some(
                    <[u8; 32]>::try_from(psk)
                        .map_err(|_| ClientError::Mesh("unexpected PSK length".into()))?,
                )
            }
            None => None,
        };
        let (tx, rx) = std_mpsc::channel();
        Ok(Client {
            inner: Arc::new(Inner {
                rt,
                npub: identity.npub(),
                identity,
                psk,
                device_name: config.device_name,
                mesh_dir: config.mesh_dir,
                relays: config.relays.unwrap_or_else(|| {
                    DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect()
                }),
                listen: config.listen.unwrap_or_else(|| {
                    std::net::SocketAddr::from(([0, 0, 0, 0], noscat_core::relay::DEFAULT_LISTEN_PORT))
                }),
                ttl: config.advert_ttl_secs,
                max_incoming: config
                    .max_incoming_bytes
                    .unwrap_or(noscat_core::tunnel::MAX_INCOMING_BYTES),
                events: tx,
                presence: std::sync::Arc::new(noscat_core::relay::Presence::new()),
                cancels: std::sync::Mutex::new(std::collections::HashMap::new()),
                forwards: std::sync::Mutex::new(std::collections::HashMap::new()),
                next_forward_id: std::sync::atomic::AtomicU64::new(1),
            }),
            events_rx: Some(rx),
        })
    }

    /// This client's npub (the mesh address UIs display).
    pub fn npub(&self) -> &str {
        &self.inner.npub
    }

    /// Seconds since this mesh-mate's advert was last received by the
    /// presence watcher [`Client::up`] starts; `None` = never seen. `npub`
    /// is the hex form the mesh roster uses. Never errors: a member with
    /// no recent advert just reads as offline.
    pub fn member_age_secs(&self, npub_hex: &str) -> Option<u64> {
        self.inner.presence.age_secs(npub_hex)
    }

    /// Online = the member's advert arrived within the advert TTL. Only
    /// meaningful once [`Client::up`] is running (the watcher's lifetime).
    pub fn member_online(&self, npub_hex: &str) -> bool {
        self.inner.presence.is_online(npub_hex)
    }

    /// Take the event stream (once). Events arrive for every background
    /// operation; blocking operations also return their own errors directly.
    pub fn events(&mut self) -> Option<std_mpsc::Receiver<Event>> {
        self.events_rx.take()
    }

    /// Dial a peer by npub: the tunnel as a byte stream. Blocking for the
    /// advert fetch, punch, and handshake (seconds); call from a worker
    /// thread in UIs.
    pub fn connect(&self, target: &str) -> Result<TunnelStream, ClientError> {
        let inner = self.inner.clone();
        let target = target.to_string();
        let (stream, _peer) = inner.rt.block_on(async {
            let (stream, peer) = inner.dial(&target).await?;
            inner.emit(Event::TunnelUp { peer: target.clone(), addr: peer });
            Ok::<(TunnelStream, SocketAddr), tunnel::TunnelError>((stream, peer))
        })?;
        Ok(stream)
    }

    /// Publish the advert and accept tunnels in the background: each one
    /// arrives as [`Event::Incoming`]. Returns the advertised UDP address.
    /// Concurrent sessions are first-class (one shared socket, a router
    /// demuxing flows per peer).
    pub fn listen(&self) -> Result<SocketAddr, ClientError> {
        let inner = self.inner.clone();
        let (listener, addr) = inner.bind_and_announce()?;
        let rt = inner.rt.handle().clone();
        rt.spawn(async move {
            let mut listener = listener;
            loop {
                let session = match listener.accept().await {
                    Ok(s) => s,
                    Err(e) => {
                        inner.emit(Event::Stopped {
                            what: "listener",
                            error: Some(e.to_string()),
                        });
                        return;
                    }
                };
                let (socket, peer, hs, who, data_rx) = session.finish().await;
                let stream =
                    TunnelStream::new(socket, peer, hs, TunnelInlet::Routed(data_rx), who.clone());
                inner.emit(Event::Incoming { peer: who, addr: peer, stream });
            }
        });
        Ok(addr)
    }

    /// Mesh node mode: listen for any number of inbound peers and
    /// dispatch each one by what it sends. A file transfer (the sender's
    /// TAG_HEADER first frame) is received into `out_dir`; any other stream
    /// is bridged to `bridge_to` when configured, dropped otherwise.
    /// Returns the advertised UDP address; the node runs until the client
    /// is dropped.
    ///
    /// Requires a mesh-scoped client (a `mesh_dir` in the config) and
    /// errors otherwise: membership is the authorization for everything
    /// inbound - the advert is public, so without the group's epoch PSK
    /// anyone who learns the npub could complete a handshake.
    pub fn up(&self, out_dir: PathBuf, bridge_to: Option<SocketAddr>) -> Result<SocketAddr, ClientError> {
        let inner = self.inner.clone();
        // Mesh scoping is the authorization for a node that accepts inbound
        // tunnels and writes received files to disk: without the group's
        // epoch PSK, anyone who learns the (public) npub can complete a
        // handshake. Enforced here so every surface (CLI, FFI) inherits it.
        if inner.mesh_dir.is_none() {
            return Err(ClientError::Mesh(
                "up requires a mesh-scoped client: membership is the authorization".into(),
            ));
        }
        let (listener, addr) = inner.bind_and_announce()?;
        // Presence feed: watch advert refreshes for the whole of the mesh so
        // the roster and chat REPL can show liveness. Arrivals land in a
        // shared map that relay reconnects never wipe; members that never
        // advertise simply read as offline. Membership is checked at query
        // time, so devices joining mid-run appear without a resubscribe.
        {
            let presence = inner.presence.clone();
            let relays = inner.relays.clone();
            inner.rt.handle().spawn(async move {
                if let Ok(mut rx) = noscat_core::relay::watch_adverts_presence(&relays).await {
                    while let Some(npub_hex) = rx.recv().await {
                        presence.note(&npub_hex);
                    }
                }
            });
        }
        let rt = inner.rt.handle().clone();
        rt.spawn(async move {
            let mut listener = listener;
            loop {
                let session = match listener.accept().await {
                    Ok(s) => s,
                    Err(e) => {
                        inner.emit(Event::Stopped {
                            what: "node",
                            error: Some(e.to_string()),
                        });
                        return;
                    }
                };
                let inner = inner.clone();
                let out_dir = out_dir.clone();
                tokio::spawn(async move {
                    let (socket, peer, hs, who, data_rx) = session.finish().await;
                    let mut stream =
                        TunnelStream::new(socket, peer, hs, TunnelInlet::Routed(data_rx), who.clone());
                    inner.emit(Event::TunnelUp { peer: who.clone(), addr: peer });
                    use tokio::io::AsyncReadExt as _;
                    let mut tag = [0u8; 1];
                    if stream.read_exact(&mut tag).await.is_err() {
                        // The peer vanished before even tagging its stream:
                        // TunnelUp already went out, so close it out or the
                        // UI hangs on a peer that is never heard from again.
                        inner.emit(Event::TunnelClosed { peer: who, error: None });
                        return;
                    }
                    if tag[0] == tunnel::TAG_HEADER {
                        // Hand the sniffed byte back so the receiver reads
                        // the same TAG_HEADER framing the sender wrote.
                        let mut prefixed = PrefixedStream::new(tag[0], stream);
                        match tunnel::receive_routed_file(&who, &mut prefixed, &out_dir, inner.max_incoming).await {
                            Ok((who, path, true)) => {
                                inner.emit(Event::TransferDone { peer: who, path })
                            }
                            // A partial is NOT a done transfer: the part
                            // file is a resume seed only.
                            Ok((who, path, false)) => {
                                inner.emit(Event::TransferPartial { peer: who, path })
                            }
                            Err(e) => inner.emit(Event::TransferFailed {
                                peer: who,
                                path: None,
                                error: e.to_string(),
                            }),
                        }
                    } else if tag[0] == tunnel::TAG_CHAT {
                        // One-shot chat: the rest of the stream is the
                        // message, read to the sender's FIN. Echo a FIN so
                        // the sender's read-to-EOF confirms delivery.
                        // Capped: a mesh peer (or a bug) streaming
                        // gigabytes must not OOM the long-running node.
                        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
                        let mut text = Vec::new();
                        let mut limited = tokio::io::AsyncReadExt::take(&mut stream, (MAX_TEXT_BYTES + 1) as u64);
                        let read_ok = limited.read_to_end(&mut text).await.is_ok();
                        let ok = read_ok
                            && text.len() <= MAX_TEXT_BYTES
                            && std::str::from_utf8(&text)
                                .map(|t| {
                                    inner.emit(Event::ChatMessage { peer: who.clone(), text: t.to_string() });
                                    true
                                })
                                .unwrap_or(false);
                        if !ok {
                            let error = if read_ok && text.len() > MAX_TEXT_BYTES {
                                format!("chat message exceeds {MAX_TEXT_BYTES} bytes")
                            } else {
                                "malformed chat message".into()
                            };
                            inner.emit(Event::ChatFailed {
                                peer: who,
                                error,
                            });
                        }
                        drop(limited); // release the &mut stream borrow
                        let _ = stream.shutdown().await;
                    } else if tag[0] == tunnel::TAG_CLIP {
                        // One-shot clipboard share: same wire shape as chat
                        // (text to the sender's FIN, FIN echo confirms).
                        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
                        let mut text = Vec::new();
                        let mut limited = tokio::io::AsyncReadExt::take(&mut stream, (MAX_TEXT_BYTES + 1) as u64);
                        let read_ok = limited.read_to_end(&mut text).await.is_ok();
                        let ok = read_ok
                            && text.len() <= MAX_TEXT_BYTES
                            && std::str::from_utf8(&text)
                                .map(|t| {
                                    inner.emit(Event::Clipboard { peer: who.clone(), text: t.to_string() });
                                    true
                                })
                                .unwrap_or(false);
                        if !ok {
                            // Not ChatFailed: nothing the *user* sent
                            // failed - a remote peer sent garbage. A
                            // generic stop keeps the receiver's UI out of
                            // it (a remote cannot fabricate local
                            // "message failed" bubbles).
                            let error = if read_ok && text.len() > MAX_TEXT_BYTES {
                                format!("clipboard share exceeds {MAX_TEXT_BYTES} bytes")
                            } else {
                                format!("malformed clipboard share from {who}")
                            };
                            inner.emit(Event::Stopped {
                                what: "clipboard",
                                error: Some(error),
                            });
                        }
                        drop(limited); // release the &mut stream borrow
                        let _ = stream.shutdown().await;
                    } else if let Some(to) = bridge_to {
                        let mut prefixed = PrefixedStream::new(tag[0], stream);
                        match tokio::net::TcpStream::connect(to).await {
                            Ok(mut tcp) => {
                                // Bridge ends are routine (peer closed, target
                                // closed); failures carry no event.
                                let _ =
                                    tokio::io::copy_bidirectional(&mut prefixed, &mut tcp).await;
                            }
                            Err(e) => inner.emit(Event::Stopped {
                                what: "bridge",
                                error: Some(format!("{to}: {e}")),
                            }),
                        }
                    }
                    // No bridge target: raw streams are dropped silently;
                });
            }
        });
        Ok(addr)
    }

    /// Netcat mode, dial side: bridge this process's stdio over a tunnel to
    /// `target`. Blocks until the session closes.
    pub fn pipe_stdio(&self, target: &str) -> Result<(), ClientError> {        let inner = self.inner.clone();
        let target = target.to_string();
        inner.rt.block_on(async {
            let (stream, peer) = inner.dial(&target).await?;
            inner.emit(Event::TunnelUp { peer: target.clone(), addr: peer });
            let res = Inner::bridge_stdio(stream).await;
            inner.emit(Event::TunnelClosed {
                peer: target,
                error: res.as_ref().err().map(|e| e.to_string()),
            });
            res
        })?;
        Ok(())
    }

    /// Netcat mode, serve side: advertise, take the first peer, bridge stdio.
    /// Blocks until the session closes.
    pub fn serve_stdio(&self) -> Result<(), ClientError> {
        let inner = self.inner.clone();
        // Bind, advertise, and report readiness FIRST: the caller must see
        // the npub before the possibly long wait for the first peer.
        let (listener, _addr) = inner.bind_and_announce()?;
        let inner2 = inner.clone();
        inner.rt.block_on(async move {
            let mut listener = listener;
            let session = listener.accept().await?;
            let (socket, peer, hs, who, _data_rx) = session.finish().await;
            let stream = TunnelStream::new(socket, peer, hs, TunnelInlet::Exclusive, who.clone());
            inner2.emit(Event::TunnelUp { peer: who.clone(), addr: peer });
            let res = Inner::bridge_stdio(stream).await;
            inner2.emit(Event::TunnelClosed {
                peer: who,
                error: res.as_ref().err().map(|e| e.to_string()),
            });
            res
        })?;
        Ok(())
    }

    /// Expose a local TCP service to inbound tunnels: every accepted tunnel
    /// is spliced to `to` on its own task, so concurrent peers just work.
    /// Returns immediately with the advertised UDP address; the listener
    /// runs until the client is dropped.
    pub fn expose(&self, to: SocketAddr) -> Result<SocketAddr, ClientError> {
        let inner = self.inner.clone();
        let (listener, addr) = inner.bind_and_announce()?;
        let rt = inner.rt.handle().clone();
        rt.spawn(async move {
            let mut listener = listener;
            loop {
                let session = match listener.accept().await {
                    Ok(s) => s,
                    Err(e) => {
                        inner.emit(Event::Stopped {
                            what: "expose",
                            error: Some(e.to_string()),
                        });
                        return;
                    }
                };
                let inner = inner.clone();
                tokio::spawn(async move {
                    let (socket, peer, hs, who, data_rx) = session.finish().await;
                    let stream =
                        TunnelStream::new(socket, peer, hs, TunnelInlet::Routed(data_rx), who.clone());                    inner.emit(Event::TunnelUp { peer: who.clone(), addr: peer });
                    let res = match tokio::net::TcpStream::connect(to).await {
                        Ok(conn) => {
                            let (mut crd, mut cwr) = tokio::io::split(conn);
                            let (mut srd, mut swr) = tokio::io::split(stream);
                            let up = tokio::spawn(async move {
                                tokio::io::copy(&mut crd, &mut swr).await?;
                                swr.shutdown().await
                            });
                            let down = tokio::spawn(async move {
                                tokio::io::copy(&mut srd, &mut cwr).await?;
                                cwr.shutdown().await
                            });
                            tokio::try_join!(flatten_join(up), flatten_join(down)).map(|_| ())
                        }
                        Err(e) => Err(io::Error::other(format!("cannot reach tcp/{to}: {e}"))),
                    };
                    inner.emit(Event::TunnelClosed {
                        peer: who,
                        error: res.as_ref().err().map(|e| e.to_string()),
                    });
                });
            }
        });
        Ok(addr)
    }

    /// Send a one-shot chat message to `target`: dial a tunnel, write the
    /// text, and wait for the peer's delivery FIN. Returns immediately; a
    /// failure surfaces as [`Event::ChatFailed`] (the caller keeps its
    /// optimistic copy of the message).
    pub fn send_chat(&self, target: &str, text: &str) {
        self.send_tagged_text(tunnel::TAG_CHAT, target, text);
    }

    /// Share the local clipboard with `target`: dial a tunnel, write the
    /// text tagged as a clipboard share, and wait for the peer's delivery
    /// FIN. The receiver puts the text on its system clipboard. Wire shape
    /// and failure reporting mirror [`Self::send_chat`].
    pub fn send_clipboard(&self, target: &str, text: &str) {
        self.send_tagged_text(tunnel::TAG_CLIP, target, text);
    }

    /// The one-shot text send both [`Self::send_chat`] and
    /// [`Self::send_clipboard`] are: dial, write `tag` + text, half-close,
    /// and wait for the receiver's FIN echo - that echo is the delivery
    /// confirmation (`ChatDelivered`); anything else is `ChatFailed`.
    fn send_tagged_text(&self, tag: u8, target: &str, text: &str) {
        let inner = self.inner.clone();
        let target = target.to_string();
        let text = text.to_string();
        let rt = inner.rt.handle().clone();
        rt.spawn(async move {
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
            let res = match inner.dial(&target).await {
                Ok((mut stream, _)) => {
                    let mut payload = vec![tag];
                    payload.extend_from_slice(text.as_bytes());
                    let sent = stream.write_all(&payload).await.is_ok()
                        && stream.flush().await.is_ok()
                        && stream.shutdown().await.is_ok();
                    if !sent {
                        Err("could not send".to_string())
                    } else {
                        // The peer echoes a FIN once the text is in hand.
                        let mut sink = Vec::new();
                        match stream.read_to_end(&mut sink).await {
                            Ok(_) => Ok(()),
                            Err(e) => Err(e.to_string()),
                        }
                    }
                }
                Err(e) => Err(e.to_string()),
            };
            if let Err(error) = res {
                inner.emit(Event::ChatFailed { peer: target, error });
            } else {
                inner.emit(Event::ChatDelivered { peer: target });
            }
        });
    }

    /// Forward a local TCP port over tunnels to `target`: every connection
    /// to `local` dials a fresh tunnel and splices through. Returns
    /// immediately with the forward's id (for [`Client::list_forwards`] /
    /// [`Client::cancel_forward`]); runs until cancelled or the client is
    /// dropped. A bind or accept failure arrives as
    /// [`Event::ForwardStopped`] with the error set.
    pub fn forward(&self, target: &str, local: SocketAddr) -> u64 {
        let inner = self.inner.clone();
        let id = inner
            .next_forward_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let cancel = std::sync::Arc::new(tokio::sync::Notify::new());
        inner.forwards.lock().unwrap_or_else(|p| p.into_inner()).insert(
            id,
            ForwardEntry {
                target: target.to_string(),
                local,
                cancel: cancel.clone(),
            },
        );
        let target = target.to_string();
        let rt = inner.rt.handle().clone();
        rt.spawn(async move {
            let tcp = match tokio::net::TcpListener::bind(local).await {
                Ok(t) => t,
                Err(e) => {
                    inner
                        .forwards
                        .lock().unwrap_or_else(|p| p.into_inner())
                        .remove(&id);
                    inner.emit(Event::ForwardStopped {
                        id,
                        error: Some(format!("{local}: {e}")),
                    });
                    return;
                }
            };
            loop {
                let accepted = tokio::select! {
                    _ = cancel.notified() => {
                        inner.forwards.lock().unwrap_or_else(|p| p.into_inner()).remove(&id);
                        inner.emit(Event::ForwardStopped { id, error: None });
                        return;
                    }
                    accepted = tcp.accept() => accepted,
                };
                let (conn, client) = match accepted {
                    Ok(c) => c,
                    Err(e) => {
                        inner
                            .forwards
                            .lock().unwrap_or_else(|p| p.into_inner())
                            .remove(&id);
                        inner.emit(Event::ForwardStopped {
                            id,
                            error: Some(e.to_string()),
                        });
                        return;
                    }
                };
                let inner = inner.clone();
                let target = target.clone();
                tokio::spawn(async move {
                    // Bound concurrent dials per forward: a loopback
                    // client piling up connections must not exhaust the
                    // dial path (each dial is a whole tunnel handshake).
                    let _dial_slot = match FORWARD_DIAL_PERMITS.acquire().await {
                        Ok(permit) => permit,
                        Err(_) => return,
                    };
                    let (stream, peer) = match inner.dial(&target).await {
                        Ok(s) => s,
                        Err(e) => {
                            inner.emit(Event::Stopped {
                                what: "forward",
                                error: Some(format!("{client}: {e}")),
                            });
                            return;
                        }
                    };
                    inner.emit(Event::TunnelUp { peer: target.clone(), addr: peer });
                    let (mut crd, mut cwr) = tokio::io::split(conn);
                    let (mut srd, mut swr) = tokio::io::split(stream);
                    let up = tokio::spawn(async move {
                        tokio::io::copy(&mut crd, &mut swr).await?;
                        swr.shutdown().await
                    });
                    let down = tokio::spawn(async move {
                        tokio::io::copy(&mut srd, &mut cwr).await?;
                        cwr.shutdown().await
                    });
                    let res = tokio::try_join!(flatten_join(up), flatten_join(down));
                    inner.emit(Event::TunnelClosed {
                        peer: target,
                        error: res.as_ref().err().map(|e| e.to_string()),
                    });
                });
            }
        });
        id
    }

    /// The forwards currently running: id, dial target, local listen
    /// address. A forward that just failed may linger here until its task
    /// cleans up; its [`Event::ForwardStopped`] reconciles the UI.
    pub fn list_forwards(&self) -> Vec<ForwardInfo> {
        self.inner
            .forwards
            .lock().unwrap_or_else(|p| p.into_inner())
            .iter()
            .map(|(id, e)| ForwardInfo {
                id: *id,
                target: e.target.clone(),
                local: e.local,
            })
            .collect()
    }

    /// Stop a forward: its accept loop ends (the listener closes; live
    /// tunnel connections finish naturally). Returns false when no
    /// forward with that id is running. A confirming
    /// [`Event::ForwardStopped`] (with no error) follows.
    pub fn cancel_forward(&self, id: u64) -> bool {
        match self
            .inner
            .forwards
            .lock().unwrap_or_else(|p| p.into_inner())
            .get(&id)
        {
            Some(entry) => {
                entry.cancel.notify_one();
                true
            }
            None => false,
        }
    }

    /// Send a file to a peer (resume-aware, sha256-verified at the peer).
    /// Returns immediately; [`Event::TransferDone`]/[`Event::TransferFailed`]
    /// report the outcome, [`Event::TransferCancelled`] a cancel (see
    /// [`Client::cancel_transfer`]).
    pub fn send_file(&self, path: PathBuf, target: &str) {
        let inner = self.inner.clone();
        let target = target.to_string();
        let source = path.clone();
        let key = (target.clone(), source.display().to_string());
        let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut flags = inner
            .cancels
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        flags.entry(key.clone()).or_default().push(flag.clone());
        drop(flags);
        let rt = inner.rt.handle().clone();
        rt.spawn(async move {
            // One event per percent change: per-ack would cross the FFI
            // (or flood a terminal) far too often.
            let last_percent = std::sync::atomic::AtomicU8::new(0);
            let progress = |sent: u64, total: u64| {
                if total == 0 {
                    return;
                }
                let percent = (sent * 100 / total).min(100) as u8;
                if last_percent.swap(percent, std::sync::atomic::Ordering::Relaxed) != percent {
                    inner.emit(Event::TransferProgress {
                        peer: target.clone(),
                        path: source.clone(),
                        sent,
                        total,
                    });
                }
            };
            let psk = inner.fresh_psk();
            let outcome = tunnel::send_file(
                &inner.identity,
                &target,
                &source,
                &inner.relays,
                psk.as_ref(),
                Some(&progress),
                Some(flag.as_ref()),
            )
            .await;
            // Remove only this send's flag: a concurrent same-key send
            // stays cancellable.
            let mut flags = inner
                .cancels
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if let Some(list) = flags.get_mut(&key) {
                list.retain(|f| !std::sync::Arc::ptr_eq(f, &flag));
                if list.is_empty() {
                    flags.remove(&key);
                }
            }
            match outcome {
                Ok(()) => inner.emit(Event::TransferDone { peer: target, path: source }),
                Err(tunnel::TunnelError::TransferCancelled) => {
                    inner.emit(Event::TransferCancelled { peer: target, path: source })
                }
                Err(e) => inner.emit(Event::TransferFailed {
                    peer: target,
                    path: Some(source),
                    error: e.to_string(),
                }),
            }
        });
    }

    /// Receive one file into `out_dir`. Returns immediately; the outcome
    /// arrives as [`Event::TransferDone`] (path = the verified final file) or
    /// Cancel in-flight sends to `target` of the file at `path` (all of
    /// them, if several are running): each stops between chunks (within
    /// one retry round), [`Event::TransferCancelled`] fires, and the
    /// receiver keeps its resumable partial for a later send of the same
    /// file. Returns false when no send to that peer with that path is in
    /// flight (it may have already finished). The receive side has no
    /// cancel: it ends when the sender stops.
    pub fn cancel_transfer(&self, target: &str, path: &std::path::Path) -> bool {
        let key = (target.to_string(), path.display().to_string());
        let mut flags = self
            .inner
            .cancels
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        match flags.get_mut(&key) {
            Some(list) if !list.is_empty() => {
                for flag in list {
                    flag.store(true, std::sync::atomic::Ordering::Relaxed);
                }
                true
            }
            _ => false,
        }
    }

    /// Receive one file into `out_dir`. Returns immediately; the outcome
    /// arrives as [`Event::TransferDone`] (with the verified final path) or
    /// [`Event::TransferFailed`].
    pub fn receive_file(&self, out_dir: PathBuf) {
        let inner = self.inner.clone();
        let rt = inner.rt.handle().clone();
        rt.spawn(async move {
            let psk = inner.fresh_psk();
            let name = inner.device_name.clone();
            match tunnel::receive_file(
                &inner.identity,
                inner.listen,
                &inner.relays,
                inner.ttl,
                &out_dir,
                psk.as_ref(),
                name.as_deref(),
                inner.max_incoming,
            )
            .await
            {
                Ok((who, path, true)) => inner.emit(Event::TransferDone { peer: who, path }),
                Ok((who, path, false)) => {
                    inner.emit(Event::TransferPartial { peer: who, path })
                }
                Err(e) => inner.emit(Event::TransferFailed {
                    peer: String::new(),
                    path: None,
                    error: e.to_string(),
                }),
            }
        });
    }
}
