//! noscat-client: the UI-facing layer of the noscat stack.
//!
//! Everything a graphical client needs and a terminal does not: an owned
//! async runtime, identity/relay/tailnet configuration resolved once, and an
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
#[derive(Debug, Clone)]
pub enum IdentitySource {
    /// A fresh ephemeral keypair (the netcat default).
    Ephemeral,
    /// An existing identity, hex secret or `nsec1...`.
    Secret(String),
    /// A file holding the secret; generated and written on first use if missing.
    File(PathBuf),
}

/// Everything a client session needs, resolved once at [`Client::start`].
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub identity: IdentitySource,
    /// Relay URLs. `None` uses the core's default public set.
    pub relays: Option<Vec<String>>,
    /// The UDP listen address for serve-side tunnels.
    pub listen: Option<SocketAddr>,
    /// A tailnet device directory: tunnels are scoped to the group's epoch
    /// PSK, so only members can connect or be dialed.
    pub tailnet_dir: Option<PathBuf>,
    /// Advert lifetime in seconds.
    pub advert_ttl_secs: u64,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            identity: IdentitySource::Ephemeral,
            relays: None,
            listen: None,
            tailnet_dir: None,
            advert_ttl_secs: 3600,
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
    /// A one-shot chat message arrived over the node dispatcher.
    ChatMessage {
        peer: String,
        text: String,
    },
    /// Sending a chat message failed (the UI keeps its optimistic copy and
    /// can mark it undelivered).
    ChatFailed {
        peer: String,
        error: String,
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
    #[error("tailnet: {0}")]
    Tailnet(String),
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
    /// Tailnet device directory, when scoped to one. Read on every tunnel:
    /// the epoch PSK changes when members join or are removed, and long
    /// running peers must pick up the new secret without a restart.
    tailnet_dir: Option<PathBuf>,
    relays: Vec<String>,
    listen: SocketAddr,
    ttl: u64,
    events: std_mpsc::Sender<Event>,
}

impl Inner {
    /// Emit an event; a dropped receiver just means nobody is listening.
    fn emit(&self, ev: Event) {
        let _ = self.events.send(ev);
    }

    /// The tailnet PSK as of *now*: re-derived from the device directory so
    /// an epoch change (a join or removal elsewhere) applies to the next
    /// tunnel without a client restart. Falls back to the cached secret
    /// when the directory cannot be read.
    fn fresh_psk(&self) -> Option<[u8; 32]> {
        match &self.tailnet_dir {
            Some(dir) => match noscat_core::tailnet::Device::open(dir)
                .and_then(|d| d.tunnel_psk())
            {
                Ok(psk) => <[u8; 32]>::try_from(psk).ok().or(self.psk),
                Err(_) => self.psk,
            },
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
                    // it, so `--identity <file>` is the whole setup.
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
                    #[cfg(unix)]
                    {
                        use std::io::Write as _;
                        use std::os::unix::fs::OpenOptionsExt as _;
                        let mut f = std::fs::OpenOptions::new()
                            .mode(0o600)
                            .write(true)
                            .create_new(true)
                            .open(path)
                            .map_err(|e| {
                                ClientError::Identity(format!(
                                    "cannot write {}: {e}",
                                    path.display()
                                ))
                            })?;
                        f.write_all(secret.as_bytes()).map_err(|e| {
                            ClientError::Identity(format!(
                                "cannot write {}: {e}",
                                path.display()
                            ))
                        })?;
                    }
                    #[cfg(not(unix))]
                    std::fs::write(path, secret.as_bytes()).map_err(|e| {
                        ClientError::Identity(format!(
                            "cannot write {}: {e}",
                            path.display()
                        ))
                    })?;
                    identity
                } else {
                    let secret = std::fs::read_to_string(path).map_err(|e| {
                        ClientError::Identity(format!("cannot read {}: {e}", path.display()))
                    })?;
                    Identity::from_secret(secret.trim())
                        .map_err(|e| ClientError::Identity(e.to_string()))?
                }
            }
        };
        let psk = match &config.tailnet_dir {
            Some(dir) => {
                let device = noscat_core::tailnet::Device::open(dir)
                    .map_err(|e| ClientError::Tailnet(e.to_string()))?;
                let psk = device
                    .tunnel_psk()
                    .map_err(|e| ClientError::Tailnet(e.to_string()))?;
                Some(
                    <[u8; 32]>::try_from(psk)
                        .map_err(|_| ClientError::Tailnet("unexpected PSK length".into()))?,
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
                tailnet_dir: config.tailnet_dir,
                relays: config.relays.unwrap_or_else(|| {
                    DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect()
                }),
                listen: config.listen.unwrap_or_else(|| "0.0.0.0:41641".parse().unwrap()),
                ttl: config.advert_ttl_secs,
                events: tx,
            }),
            events_rx: Some(rx),
        })
    }

    /// This client's npub (the mesh address UIs display).
    pub fn npub(&self) -> &str {
        &self.inner.npub
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
        let mut listener = inner.rt.block_on(tunnel::bind_listener(
            &inner.identity,
            inner.listen,
            &inner.relays,
            inner.ttl,
            inner.psk.as_ref(),
        ))?;
        if let Some(dir) = &inner.tailnet_dir {
            listener.set_tailnet_dir(dir.clone());
        }
        let addr = listener.local_addr();
        inner.emit(Event::Listening {
            npub: inner.identity.npub(),
            addr,
        });
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

    /// Tailnet node mode: listen for any number of inbound peers and
    /// dispatch each one by what it sends. A file transfer (the sender's
    /// TAG_HEADER first frame) is received into `out_dir`; any other stream
    /// is bridged to `bridge_to` when configured, dropped otherwise.
    /// Returns the advertised UDP address; the node runs until the client
    /// is dropped. Call this on a tailnet-scoped client: membership is the
    /// authorization for everything inbound.
    pub fn up(&self, out_dir: PathBuf, bridge_to: Option<SocketAddr>) -> Result<SocketAddr, ClientError> {
        let inner = self.inner.clone();
        let mut listener = inner.rt.block_on(tunnel::bind_listener(
            &inner.identity,
            inner.listen,
            &inner.relays,
            inner.ttl,
            inner.psk.as_ref(),
        ))?;
        if let Some(dir) = &inner.tailnet_dir {
            listener.set_tailnet_dir(dir.clone());
        }
        let addr = listener.local_addr();
        inner.emit(Event::Listening {
            npub: inner.identity.npub(),
            addr,
        });
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
                        return;
                    }
                    if tag[0] == tunnel::TAG_HEADER {
                        // Hand the sniffed byte back so the receiver reads
                        // the same TAG_HEADER framing the sender wrote.
                        let mut prefixed = PrefixedStream::new(tag[0], stream);
                        match tunnel::receive_routed_file(&who, &mut prefixed, &out_dir).await {
                            Ok((who, path)) => {
                                inner.emit(Event::TransferDone { peer: who, path })
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
                        use tokio::io::AsyncWriteExt as _;
                        let mut text = Vec::new();
                        let ok = stream.read_to_end(&mut text).await.is_ok()
                            && std::str::from_utf8(&text)
                                .map(|t| {
                                    inner.emit(Event::ChatMessage { peer: who.clone(), text: t.to_string() });
                                    true
                                })
                                .unwrap_or(false);
                        if !ok {
                            inner.emit(Event::ChatFailed {
                                peer: who,
                                error: "malformed chat message".into(),
                            });
                        }
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
        let mut listener = inner.rt.block_on(tunnel::bind_listener(
            &inner.identity,
            inner.listen,
            &inner.relays,
            inner.ttl,
            inner.psk.as_ref(),
        ))?;
        if let Some(dir) = &inner.tailnet_dir {
            listener.set_tailnet_dir(dir.clone());
        }
        let addr = listener.local_addr();
        inner.emit(Event::Listening { npub: inner.identity.npub(), addr });
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
        let mut listener = inner.rt.block_on(tunnel::bind_listener(
            &inner.identity,
            inner.listen,
            &inner.relays,
            inner.ttl,
            inner.psk.as_ref(),
        ))?;
        if let Some(dir) = &inner.tailnet_dir {
            listener.set_tailnet_dir(dir.clone());
        }
        let addr = listener.local_addr();
        inner.emit(Event::Listening {
            npub: inner.identity.npub(),
            addr,
        });
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
                            tokio::try_join!(flatten(up), flatten(down)).map(|_| ())
                        }
                        Err(e) => Err(io::Error::other(format!("cannot reach tcp/{to}: {e}"))),
                    };
                    inner.emit(Event::TunnelClosed {
                        peer: who,
                        error: res.as_ref().err().map(|e| e.to_string()),
                    });
                });
            }

            async fn flatten<T: Send + 'static>(
                h: tokio::task::JoinHandle<io::Result<T>>,
            ) -> io::Result<T> {
                h.await.map_err(|e| io::Error::other(e))?
            }
        });
        Ok(addr)
    }

    /// Send a one-shot chat message to `target`: dial a tunnel, write the
    /// text, and wait for the peer's delivery FIN. Returns immediately; a
    /// failure surfaces as [`Event::ChatFailed`] (the caller keeps its
    /// optimistic copy of the message).
    pub fn send_chat(&self, target: &str, text: &str) {
        let inner = self.inner.clone();
        let target = target.to_string();
        let text = text.to_string();
        let rt = inner.rt.handle().clone();
        rt.spawn(async move {
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
            let res = match inner.dial(&target).await {
                Ok((mut stream, _)) => {
                    let mut payload = vec![tunnel::TAG_CHAT];
                    payload.extend_from_slice(text.as_bytes());
                    let sent = stream.write_all(&payload).await.is_ok()
                        && stream.flush().await.is_ok()
                        && stream.shutdown().await.is_ok();
                    if !sent {
                        Err("could not send".to_string())
                    } else {
                        // The peer echoes a FIN once the message is in hand.
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
            }
        });
    }

    /// Forward a local TCP port over tunnels to `target`: every connection
    /// to `local` dials a fresh tunnel and splices through. Returns
    /// immediately; runs until the client is dropped.
    pub fn forward(&self, target: &str, local: SocketAddr) -> Result<(), ClientError> {
        let inner = self.inner.clone();
        let target = target.to_string();
        let rt = inner.rt.handle().clone();
        rt.spawn(async move {
            let tcp = match tokio::net::TcpListener::bind(local).await {
                Ok(t) => t,
                Err(e) => {
                    inner.emit(Event::Stopped {
                        what: "forward",
                        error: Some(e.to_string()),
                    });
                    return;
                }
            };
            loop {
                let (conn, client) = match tcp.accept().await {
                    Ok(c) => c,
                    Err(e) => {
                        inner.emit(Event::Stopped {
                            what: "forward",
                            error: Some(e.to_string()),
                        });
                        return;
                    }
                };
                let inner = inner.clone();
                let target = target.clone();
                tokio::spawn(async move {
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
                    let res = tokio::try_join!(flatten(up), flatten(down));
                    inner.emit(Event::TunnelClosed {
                        peer: target,
                        error: res.as_ref().err().map(|e| e.to_string()),
                    });
                });
            }

            async fn flatten<T: Send + 'static>(
                h: tokio::task::JoinHandle<io::Result<T>>,
            ) -> io::Result<T> {
                h.await.map_err(|e| io::Error::other(e))?
            }
        });
        Ok(())
    }

    /// Send a file to a peer (resume-aware, sha256-verified at the peer).
    /// Returns immediately; [`Event::TransferDone`]/[`TransferFailed`] report
    /// the outcome.
    pub fn send_file(&self, path: PathBuf, target: &str) {
        let inner = self.inner.clone();
        let target = target.to_string();
        let source = path.clone();
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
            match tunnel::send_file(
                &inner.identity,
                &target,
                &source,
                &inner.relays,
                psk.as_ref(),
                Some(&progress),
            )
            .await
            {
                Ok(()) => inner.emit(Event::TransferDone { peer: target, path: source }),
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
    /// [`Event::TransferFailed`].
    pub fn receive_file(&self, out_dir: PathBuf) {
        let inner = self.inner.clone();
        let rt = inner.rt.handle().clone();
        rt.spawn(async move {
            let psk = inner.fresh_psk();
            match tunnel::receive_file(
                &inner.identity,
                inner.listen,
                &inner.relays,
                inner.ttl,
                &out_dir,
                psk.as_ref(),
            )
            .await
            {
                Ok((who, path)) => inner.emit(Event::TransferDone { peer: who, path }),
                Err(e) => inner.emit(Event::TransferFailed {
                    peer: String::new(),
                    path: None,
                    error: e.to_string(),
                }),
            }
        });
    }
}
