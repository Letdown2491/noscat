//! noscat-client: the UI-facing layer of the noscat stack.
//!
//! A [`Client`] is one running device: it owns an async runtime, the
//! device's identity and state directory, its mesh membership, and an
//! event stream instead of stderr prints. Every method is blocking or
//! fire-and-forget, so UIs call it from a worker thread and pump
//! [`Client::events`] on another.
//!
//! - Mesh: [`Client::create_mesh`], [`Client::invite`], [`Client::join`],
//!   [`Client::remove`], [`Client::leave`], [`Client::members`].
//! - Receiving: [`Client::up`] (files into a directory, other streams to a
//!   local TCP service), [`Client::expose`] (every stream to a TCP service),
//!   [`Client::serve_port`] (members may reach one local port by number).
//! - Sending: [`Client::send_file`], [`Client::send_chat`],
//!   [`Client::send_clipboard`], [`Client::forward`], [`Client::connect`],
//!   [`Client::pipe_stdio`].
//!
//! Only members of this device's mesh can reach it or be reached: the
//! roster is the admission list for the data plane (ADR 0005).
//!
//! The CLI (`crates/noscat`) is built on this crate too, which keeps the
//! layer honest.

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

use noscat_core::Identity;
use noscat_core::apps::{self, Incoming, Received, TextKind};
use noscat_core::dataplane::{DataplaneConfig, Reachability};
use noscat_core::device::{Device, DeviceConfig, DeviceEvent};
use noscat_core::streams::Connection;
use nostr::nips::nip19::ToBech32 as _;
use nostr::prelude::PublicKey;
use quinn::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite};

pub use noscat_core::parse_pairing_target;
pub use noscat_core::relay::{DEFAULT_RELAYS, default_relays};

/// How long a dial waits for a member to become reachable.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Default receive cap per file transfer: 64 GiB.
pub const MAX_INCOMING_BYTES: u64 = 64 << 30;
/// Default UDP port for a reachable device.
pub const DEFAULT_LISTEN_PORT: u16 = 41641;

/// Where the client's identity comes from.
#[derive(Clone)]
pub enum IdentitySource {
    /// A fresh keypair for this process only.
    Ephemeral,
    /// An existing identity, hex secret or `nsec1...`.
    Secret(String),
    /// A file holding the secret; created owner-only on first use.
    File(PathBuf),
}

impl std::fmt::Debug for IdentitySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // ClientConfig derives Debug and UIs log it; never the secret.
        match self {
            Self::Ephemeral => write!(f, "Ephemeral"),
            Self::Secret(_) => write!(f, "Secret(<redacted>)"),
            Self::File(path) => write!(f, "File({path:?})"),
        }
    }
}

/// Everything a client needs, resolved once at [`Client::start`].
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub identity: IdentitySource,
    /// Relay URLs for this device's key package, inbox and new meshes.
    /// `None` uses [`DEFAULT_RELAYS`].
    pub relays: Option<Vec<String>>,
    /// UDP bind address of the data plane. `None` picks a free port, or
    /// [`DEFAULT_LISTEN_PORT`] when `reachable` is set.
    pub listen: Option<SocketAddr>,
    /// Device state directory (mesh membership, group keys). `None` keeps
    /// state in a temporary directory for this process only.
    pub mesh_dir: Option<PathBuf>,
    /// Friendly name other members see.
    pub device_name: Option<String>,
    /// This device is directly reachable (port forward, VPS, public IPv6).
    /// `Some(None)` learns the public address by STUN; `Some(Some(addr))`
    /// advertises `addr`. Every mesh needs at least one reachable member.
    pub reachable: Option<Option<SocketAddr>>,
    /// Find members on the same LAN by mDNS.
    pub lan_discovery: bool,
    /// Receive cap per transfer. `None` uses [`MAX_INCOMING_BYTES`].
    pub max_incoming_bytes: Option<u64>,
    /// Known UDP addresses of devices (npub or hex), tried before discovery.
    pub static_peers: Vec<(String, SocketAddr)>,
    /// STUN servers for learning the public address. `None` uses the
    /// data plane's defaults.
    pub stun_servers: Option<Vec<String>>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            identity: IdentitySource::Ephemeral,
            relays: None,
            listen: None,
            mesh_dir: None,
            device_name: None,
            reachable: None,
            lan_discovery: true,
            max_incoming_bytes: None,
            static_peers: Vec::new(),
            stun_servers: None,
        }
    }
}

/// A member of this device's mesh, as UIs show it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    /// bech32 npub: the target for every send, forward and connect.
    pub npub: String,
    /// Name from the member's latest advert.
    pub name: Option<String>,
    pub admin: bool,
    pub this_device: bool,
    pub online: bool,
    /// Seconds since its last advert; `None` = never seen.
    pub last_seen_secs: Option<u64>,
}

/// What the client does on its own, surfaced for UIs. Peers are bech32
/// npubs.
#[derive(Debug, Clone)]
pub enum Event {
    /// Receiving is set up ([`Client::up`], [`Client::expose`]).
    Listening { npub: String, addr: SocketAddr },
    /// A connection with a member is up (dialed or accepted).
    TunnelUp { peer: String },
    /// A connection with a member ended; `error` is set when not clean.
    TunnelClosed { peer: String, error: Option<String> },
    /// A transfer finished and verified (source path on send, final path
    /// on receive).
    TransferDone { peer: String, path: PathBuf },
    /// A receive ended without a whole file; the `.noscat-part` resumes
    /// when the same file is sent again.
    TransferPartial { peer: String, path: PathBuf },
    /// Sends only, one event per percent.
    TransferProgress { peer: String, path: PathBuf, sent: u64, total: u64 },
    TransferFailed { peer: String, path: Option<PathBuf>, error: String },
    /// Cancelled by this side.
    TransferCancelled { peer: String, path: PathBuf },
    /// A forward ended (cancelled, or `error` set).
    ForwardStopped { id: u64, error: Option<String> },
    ChatMessage { peer: String, text: String },
    /// A member shared its clipboard.
    Clipboard { peer: String, text: String },
    ChatFailed { peer: String, error: String },
    /// The member confirmed it has the chat message or clipboard text.
    ChatDelivered { peer: String },
    /// A background operation stopped.
    Stopped { what: &'static str, error: Option<String> },
    /// This device is now in a mesh (created or joined).
    MeshJoined { name: String },
    /// The member list changed.
    Roster { members: Vec<Member> },
    /// A member's advert arrived (presence and name).
    MemberSeen { peer: String, name: Option<String> },
    /// One of this device's membership changes lost a race with another
    /// member's and did not happen; it may be retried.
    MeshChangeUndone,
    /// This device is no longer in a mesh.
    MeshLeft,
    /// A device asks to be invited: it scanned this device's QR and is
    /// waiting in [`Client::join`]. Show a prompt; [`Client::invite`]
    /// with `peer` adds it.
    JoinRequest { peer: String, name: Option<String> },
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("identity: {0}")]
    Identity(String),
    #[error("mesh: {0}")]
    Mesh(String),
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    Stream(String),
    /// Another process is running a device on this state directory.
    #[error("another noscat process is using {}", .0.display())]
    Busy(PathBuf),
}

impl From<noscat_core::device::DeviceError> for ClientError {
    fn from(e: noscat_core::device::DeviceError) -> Self {
        Self::Mesh(e.to_string())
    }
}

impl From<apps::AppError> for ClientError {
    fn from(e: apps::AppError) -> Self {
        Self::Stream(e.to_string())
    }
}

/// A forward as the UI's list shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardInfo {
    pub id: u64,
    /// The member it reaches.
    pub target: String,
    /// The local TCP address it listens on.
    pub local: SocketAddr,
    /// Port on the member (0 = its default service).
    pub remote_port: u16,
}

struct ForwardEntry {
    info: ForwardInfo,
    cancel: Arc<tokio::sync::Notify>,
}

/// A byte stream to a member ([`Client::connect`]).
pub struct MeshStream {
    send: SendStream,
    recv: RecvStream,
}

impl AsyncRead for MeshStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for MeshStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        AsyncWrite::poll_write(std::pin::Pin::new(&mut self.send), cx, buf)
    }
    fn poll_flush(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
        AsyncWrite::poll_flush(std::pin::Pin::new(&mut self.send), cx)
    }
    fn poll_shutdown(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(std::pin::Pin::new(&mut self.send), cx)
    }
}

/// Where incoming streams go.
#[derive(Default)]
struct Serving {
    /// Receive files here (`up`).
    inbox: Option<PathBuf>,
    /// Port-0 forwards go to this TCP service (`up`'s bridge, `expose`).
    bridge: Option<SocketAddr>,
    /// Local ports members may forward to by number.
    ports: HashSet<u16>,
    /// `serve_stdio` waiting for its first stream.
    stdio: Option<tokio::sync::oneshot::Sender<(String, SendStream, RecvStream)>>,
}

/// The client's shared state. Background tasks hold it, so it must not own
/// anything whose drop stops the device: that is [`Owner`]'s job.
struct Inner {
    rt: tokio::runtime::Handle,
    device: Device,
    npub: String,
    events: std_mpsc::Sender<Event>,
    max_incoming: u64,
    serving: Mutex<Serving>,
    conns: Mutex<HashMap<PublicKey, Connection>>,
    /// In-flight sends keyed by (peer, path): abort handles.
    sends: Mutex<HashMap<(String, PathBuf), Vec<tokio::task::AbortHandle>>>,
    forwards: Mutex<HashMap<u64, ForwardEntry>>,
    next_forward_id: AtomicU64,
}

/// What only [`Client`] handles hold: the runtime, the directory lock and
/// shutdown. Background tasks hold [`Inner`] and run on this runtime, so
/// if they owned it the device could never stop. Dropping the last
/// `Client` drops this, which stops the device, ends the tasks and
/// releases the directory.
struct Owner {
    /// Always `Some` until drop.
    rt: Option<tokio::runtime::Runtime>,
    inner: Arc<Inner>,
    dir: PathBuf,
    /// Removed on drop when the state was temporary.
    temp_dir: bool,
    /// Held for the client's life: one process per state directory.
    /// Declared after `rt` so it is released after the device stopped.
    _lock: std::fs::File,
}

impl Drop for Owner {
    fn drop(&mut self) {
        let device = self.inner.device.clone();
        let rt = self.rt.take();
        let stop = move || {
            if let Some(rt) = rt {
                rt.block_on(device.shutdown());
            }
        };
        // Blocking on (or dropping) a runtime inside another one panics; a
        // UI or CLI may drop its last clone from async code.
        if tokio::runtime::Handle::try_current().is_ok() {
            let _ = std::thread::spawn(stop).join();
        } else {
            stop();
        }
        if self.temp_dir {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

impl Inner {
    fn rt(&self) -> &tokio::runtime::Handle {
        &self.rt
    }
}

/// Running clients by state directory, so helpers that only know a
/// directory (the FFI's mesh functions) use the running device instead
/// of opening its state a second time.
fn registry() -> &'static Mutex<HashMap<PathBuf, Weak<Owner>>> {
    static R: OnceLock<Mutex<HashMap<PathBuf, Weak<Owner>>>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(HashMap::new()))
}

fn canonical(dir: &Path) -> PathBuf {
    std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf())
}

fn npub_of(pk: &PublicKey) -> String {
    pk.to_bech32().unwrap_or_else(|_| pk.to_hex())
}

fn load_identity(src: &IdentitySource) -> Result<Identity, ClientError> {
    let id = |e: &dyn std::fmt::Display| ClientError::Identity(e.to_string());
    match src {
        IdentitySource::Ephemeral => Ok(Identity::generate()),
        IdentitySource::Secret(s) => Identity::from_secret(s).map_err(|e| id(&e)),
        IdentitySource::File(path) => {
            if !path.exists() {
                let fresh = Identity::generate();
                if let Some(dir) = path.parent() {
                    std::fs::create_dir_all(dir)
                        .map_err(|e| ClientError::Identity(format!("cannot create {}: {e}", dir.display())))?;
                }
                // A lost create race reads the winner instead of
                // overwriting it.
                let created = noscat_core::fsutil::create_secret_file(path, &fresh.secret_hex())
                    .map_err(|e| ClientError::Identity(format!("cannot write {}: {e}", path.display())))?;
                if created {
                    return Ok(fresh);
                }
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let mode = std::fs::metadata(path).map(|m| m.permissions().mode()).unwrap_or(0o600);
                if mode & 0o077 != 0 {
                    return Err(ClientError::Identity(format!(
                        "{} is readable by other users (mode {:o}); chmod 600 it and retry",
                        path.display(),
                        mode & 0o777
                    )));
                }
            }
            let secret = std::fs::read_to_string(path)
                .map_err(|e| ClientError::Identity(format!("cannot read {}: {e}", path.display())))?;
            Identity::from_secret(secret.trim()).map_err(|e| id(&e))
        }
    }
}

/// The npub an identity source resolves to, creating the identity file
/// (owner-only) if it does not exist yet. Starts nothing.
pub fn identity_npub(src: &IdentitySource) -> Result<String, ClientError> {
    Ok(load_identity(src)?.npub())
}

fn parse_target(target: &str) -> Result<PublicKey, ClientError> {
    parse_pairing_target(target).map_err(ClientError::Mesh)
}

impl Inner {
    fn emit(&self, ev: Event) {
        let _ = self.events.send(ev);
    }

    async fn members(&self) -> Vec<Member> {
        self.device
            .members()
            .await
            .into_iter()
            .map(|m| Member {
                npub: npub_of(&m.device),
                name: m.name,
                admin: m.admin,
                this_device: m.this_device,
                online: m.online,
                last_seen_secs: m.last_seen_secs,
            })
            .collect()
    }

    /// A live connection to `peer`, reusing one if it is open.
    async fn conn(self: &Arc<Self>, peer: PublicKey) -> Result<Connection, ClientError> {
        if let Some(c) = self.conns.lock().ok().and_then(|m| m.get(&peer).cloned()) {
            if c.inner.close_reason().is_none() {
                return Ok(c);
            }
        }
        let c = self
            .device
            .streams()
            .connect(peer, CONNECT_TIMEOUT)
            .await
            .map_err(|e| ClientError::Stream(e.to_string()))?;
        self.adopt(c.clone());
        Ok(c)
    }

    /// Track a connection: events on open and close, and serve the
    /// streams the member opens on it.
    fn adopt(self: &Arc<Self>, c: Connection) {
        if let Ok(mut m) = self.conns.lock() {
            m.insert(c.peer, c.clone());
        }
        let peer = npub_of(&c.peer);
        self.emit(Event::TunnelUp { peer: peer.clone() });
        let me = self.clone();
        self.rt().spawn(async move {
            loop {
                match apps::accept(&c).await {
                    Ok(Some(incoming)) => {
                        let me = me.clone();
                        let peer = peer.clone();
                        tokio::spawn(async move { me.handle(peer, incoming).await });
                    }
                    Ok(None) => break,
                    Err(e) => tracing::debug!(%peer, "bad stream: {e}"),
                }
            }
            let reason = c.inner.close_reason();
            if let Ok(mut m) = me.conns.lock() {
                if m.get(&c.peer).is_some_and(|x| x.inner.stable_id() == c.inner.stable_id()) {
                    m.remove(&c.peer);
                }
            }
            let error = match reason {
                Some(quinn::ConnectionError::LocallyClosed | quinn::ConnectionError::ApplicationClosed(_)) | None => None,
                Some(e) => Some(e.to_string()),
            };
            me.emit(Event::TunnelClosed { peer, error });
        });
    }

    async fn handle(self: Arc<Self>, peer: String, incoming: Incoming) {
        match incoming {
            Incoming::Text { kind: TextKind::Chat, text } => self.emit(Event::ChatMessage { peer, text }),
            Incoming::Text { kind: TextKind::Clipboard, text } => self.emit(Event::Clipboard { peer, text }),
            Incoming::File(f) => {
                let inbox = self.serving.lock().ok().and_then(|s| s.inbox.clone());
                let Some(dir) = inbox else {
                    f.refuse().await;
                    return;
                };
                if f.size > self.max_incoming {
                    self.emit(Event::TransferFailed {
                        peer,
                        path: None,
                        error: format!("{} is larger than the receive limit", f.name),
                    });
                    f.refuse().await;
                    return;
                }
                match f.receive(&dir, |_, _| {}).await {
                    Ok(Received::Done(path)) => self.emit(Event::TransferDone { peer, path }),
                    Ok(Received::Partial(path)) => self.emit(Event::TransferPartial { peer, path }),
                    Err(e) => self.emit(Event::TransferFailed { peer, path: None, error: e.to_string() }),
                }
            }
            Incoming::Forward(fw) => {
                let (stdio, to) = {
                    let Ok(mut s) = self.serving.lock() else { return };
                    if fw.port == 0 {
                        match s.stdio.take() {
                            Some(tx) => (Some(tx), None),
                            None => (None, s.bridge),
                        }
                    } else if s.ports.contains(&fw.port) {
                        (None, Some(SocketAddr::from(([127, 0, 0, 1], fw.port))))
                    } else {
                        (None, None)
                    }
                };
                if let Some(tx) = stdio {
                    if let Ok((s, r)) = fw.accept_raw().await {
                        let _ = tx.send((peer, s, r));
                    }
                } else if let Some(to) = to {
                    if let Err(e) = fw.accept(to).await {
                        tracing::debug!(%peer, "forward to {to} ended: {e}");
                    }
                } else {
                    fw.refuse().await;
                }
            }
        }
    }

    async fn send_text(self: Arc<Self>, target: String, kind: TextKind, text: String) {
        let res = async {
            let pk = parse_target(&target)?;
            let c = self.conn(pk).await?;
            apps::send_text(&c, kind, &text).await?;
            Ok::<_, ClientError>(npub_of(&pk))
        }
        .await;
        match res {
            Ok(peer) => self.emit(Event::ChatDelivered { peer }),
            Err(e) => self.emit(Event::ChatFailed { peer: target, error: e.to_string() }),
        }
    }

    async fn open_forward(self: &Arc<Self>, target: &str, port: u16) -> Result<(String, SendStream, RecvStream), ClientError> {
        let pk = parse_target(target)?;
        let c = self.conn(pk).await?;
        let (s, r) = apps::open_forward(&c, port).await?;
        Ok((npub_of(&pk), s, r))
    }

    fn pump(self: &Arc<Self>) {
        let me = self.clone();
        let mut rx = self.device.subscribe();
        self.rt().spawn(async move {
            loop {
                let ev = match rx.recv().await {
                    Ok(ev) => ev,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => return,
                };
                match ev {
                    DeviceEvent::Joined => {
                        let name = me.device.mesh_name().await.unwrap_or_default();
                        me.emit(Event::MeshJoined { name });
                    }
                    DeviceEvent::Roster(_) => {
                        let members = me.members().await;
                        me.emit(Event::Roster { members });
                    }
                    DeviceEvent::Advert { device, name } => me.emit(Event::MemberSeen { peer: npub_of(&device), name }),
                    DeviceEvent::Superseded => me.emit(Event::MeshChangeUndone),
                    DeviceEvent::Removed => me.emit(Event::MeshLeft),
                    DeviceEvent::JoinRequest { device, name } => {
                        me.emit(Event::JoinRequest { peer: npub_of(&device), name });
                    }
                    DeviceEvent::App(_) => {}
                }
            }
        });
        let me = self.clone();
        self.rt().spawn(async move {
            while let Some(c) = me.device.streams().accept().await {
                me.adopt(c);
            }
        });
    }
}

/// One running device. Cloning shares it; dropping the last clone stops
/// it.
pub struct Client {
    inner: Arc<Inner>,
    owner: Arc<Owner>,
    /// Behind a mutex so `Client` is `Sync` (`Receiver` is not).
    events_rx: Mutex<Option<std_mpsc::Receiver<Event>>>,
}

impl Clone for Client {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            owner: self.owner.clone(),
            events_rx: Mutex::new(None),
        }
    }
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client").field("npub", &self.inner.npub).finish_non_exhaustive()
    }
}

impl Client {
    /// Start the device: identity, state, relays and data plane. Blocks
    /// for a few seconds (relay connections); call from a worker thread.
    /// Must not be called from inside an async runtime.
    pub fn start(config: ClientConfig) -> Result<Client, ClientError> {
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
        let identity = load_identity(&config.identity)?;
        let (dir, temp_dir) = match &config.mesh_dir {
            Some(d) => (d.clone(), false),
            None => (
                std::env::temp_dir().join(format!("noscat-{}-{}", std::process::id(), rand::random::<u32>())),
                true,
            ),
        };
        std::fs::create_dir_all(&dir)?;
        let key = canonical(&dir);
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join("lock"))?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => return Err(ClientError::Busy(dir)),
            Err(std::fs::TryLockError::Error(e)) => return Err(e.into()),
        }
        if registry().lock().ok().and_then(|r| r.get(&key).and_then(Weak::upgrade)).is_some() {
            return Err(ClientError::Mesh(format!("a client is already running for {}", dir.display())));
        }
        let bind = config.listen.unwrap_or_else(|| {
            let port = if config.reachable.is_some() { DEFAULT_LISTEN_PORT } else { 0 };
            SocketAddr::from(([0, 0, 0, 0], port))
        });
        let mut dataplane = DataplaneConfig {
            bind,
            lan_discovery: config.lan_discovery,
            ..DataplaneConfig::default()
        };
        if let Some(stun) = config.stun_servers.clone() {
            dataplane.stun_servers = stun;
        }
        let mut peer_addresses: HashMap<PublicKey, Vec<SocketAddr>> = HashMap::new();
        for (who, addr) in &config.static_peers {
            peer_addresses.entry(parse_target(who)?).or_default().push(*addr);
        }
        if let Some(external_addr) = config.reachable {
            dataplane.reachability = Reachability::Public { external_addr };
        }
        let cfg = DeviceConfig {
            dir: dir.clone(),
            name: config.device_name.clone().unwrap_or_else(noscat_core::default_device_name),
            relays: config.relays.clone().unwrap_or_else(default_relays),
            dataplane,
            peer_addresses,
        };
        let npub = identity.npub();
        let device = rt.block_on(Device::start(identity, cfg))?;
        let (tx, rx) = std_mpsc::channel();
        let inner = Arc::new(Inner {
            rt: rt.handle().clone(),
            device,
            npub,
            events: tx,
            max_incoming: config.max_incoming_bytes.unwrap_or(MAX_INCOMING_BYTES),
            serving: Mutex::new(Serving::default()),
            conns: Mutex::new(HashMap::new()),
            sends: Mutex::new(HashMap::new()),
            forwards: Mutex::new(HashMap::new()),
            next_forward_id: AtomicU64::new(1),
        });
        inner.pump();
        let owner = Arc::new(Owner { rt: Some(rt), inner: inner.clone(), dir, temp_dir, _lock: lock });
        if let Ok(mut r) = registry().lock() {
            r.retain(|_, w| w.strong_count() > 0);
            r.insert(key, Arc::downgrade(&owner));
        }
        Ok(Client { inner, owner, events_rx: Mutex::new(Some(rx)) })
    }

    /// The running client for a state directory, if any in this process.
    #[must_use]
    pub fn running(dir: &Path) -> Option<Client> {
        let owner = registry().lock().ok()?.get(&canonical(dir))?.upgrade()?;
        Some(Client { inner: owner.inner.clone(), owner, events_rx: Mutex::new(None) })
    }

    /// This device's npub (bech32).
    #[must_use]
    pub fn npub(&self) -> &str {
        &self.inner.npub
    }

    /// Take the event stream (once per client). Events arrive on a
    /// client-owned thread; drain it continuously.
    pub fn events(&mut self) -> Option<std_mpsc::Receiver<Event>> {
        self.events_rx.get_mut().ok()?.take()
    }

    // ---- mesh ------------------------------------------------------------

    /// Whether this device is in a mesh.
    #[must_use]
    pub fn in_mesh(&self) -> bool {
        self.inner.rt().block_on(self.inner.device.in_mesh())
    }

    /// The mesh name, if in a mesh.
    #[must_use]
    pub fn mesh_name(&self) -> Option<String> {
        self.inner.rt().block_on(self.inner.device.mesh_name())
    }

    /// Start a new mesh with this device as its only member.
    pub fn create_mesh(&self, name: &str) -> Result<(), ClientError> {
        self.inner.rt().block_on(self.inner.device.create(name))?;
        Ok(())
    }

    /// Add a device (npub or `noscat:` URI) to the mesh. It must be
    /// running, or waiting in [`Client::join`].
    pub fn invite(&self, target: &str) -> Result<(), ClientError> {
        let pk = parse_target(target)?;
        self.inner.rt().block_on(self.inner.device.invite(pk))?;
        Ok(())
    }

    /// Wait up to `timeout` for an invitation from `inviter` (npub or
    /// `noscat:` URI; the scanned QR is the trust anchor) and join.
    pub fn join(&self, inviter: &str, timeout: Duration) -> Result<(), ClientError> {
        let pk = parse_target(inviter)?;
        self.inner.rt().block_on(self.inner.device.join(pk, timeout))?;
        Ok(())
    }

    /// Remove a member from the mesh.
    pub fn remove(&self, target: &str) -> Result<(), ClientError> {
        let pk = parse_target(target)?;
        self.inner.rt().block_on(self.inner.device.remove(&[pk]))?;
        Ok(())
    }

    /// Leave the mesh, waiting up to `timeout` for a member to confirm.
    pub fn leave(&self, timeout: Duration) -> Result<(), ClientError> {
        self.inner.rt().block_on(self.inner.device.leave(timeout))?;
        Ok(())
    }

    /// The members with names and presence.
    #[must_use]
    pub fn members(&self) -> Vec<Member> {
        self.inner.rt().block_on(self.inner.members())
    }

    /// Seconds since a member's last advert (npub or hex); `None` = never
    /// seen.
    #[must_use]
    pub fn member_age_secs(&self, npub: &str) -> Option<u64> {
        let pk = parse_target(npub).ok()?;
        self.members().into_iter().find(|m| m.npub == npub_of(&pk)).and_then(|m| m.last_seen_secs)
    }

    /// Whether a member's advert is fresh.
    #[must_use]
    pub fn member_online(&self, npub: &str) -> bool {
        let Ok(pk) = parse_target(npub) else { return false };
        self.members().into_iter().any(|m| m.npub == npub_of(&pk) && m.online)
    }

    /// Re-check network paths after a network change (Wi-Fi to mobile).
    pub fn network_changed(&self) {
        let dp = self.inner.device.dataplane().clone();
        self.inner.rt().spawn(async move {
            let _ = dp.network_changed().await;
        });
    }

    // ---- receiving -------------------------------------------------------

    fn local_addr(&self) -> SocketAddr {
        self.inner
            .rt()
            .block_on(self.inner.device.dataplane().local_addrs())
            .ok()
            .and_then(|a| a.first().copied())
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)))
    }

    /// Receive files into `out_dir`, and bridge members' other streams to
    /// `bridge_to` when set. Returns the data plane's UDP address.
    pub fn up(&self, out_dir: PathBuf, bridge_to: Option<SocketAddr>) -> Result<SocketAddr, ClientError> {
        std::fs::create_dir_all(&out_dir)?;
        if let Ok(mut s) = self.inner.serving.lock() {
            s.inbox = Some(out_dir);
            s.bridge = bridge_to;
        }
        let addr = self.local_addr();
        self.inner.emit(Event::Listening { npub: self.inner.npub.clone(), addr });
        Ok(addr)
    }

    /// Accept files into `out_dir` (without changing the bridge).
    pub fn receive_file(&self, out_dir: PathBuf) {
        if let Ok(mut s) = self.inner.serving.lock() {
            s.inbox = Some(out_dir);
        }
    }

    /// Bridge every member stream to the TCP service at `to`.
    pub fn expose(&self, to: SocketAddr) -> Result<SocketAddr, ClientError> {
        if let Ok(mut s) = self.inner.serving.lock() {
            s.bridge = Some(to);
        }
        let addr = self.local_addr();
        self.inner.emit(Event::Listening { npub: self.inner.npub.clone(), addr });
        Ok(addr)
    }

    /// Let members forward to `127.0.0.1:port` on this device by number
    /// ([`Client::forward_port`]); `false` withdraws it.
    pub fn serve_port(&self, port: u16, enabled: bool) {
        if let Ok(mut s) = self.inner.serving.lock() {
            if enabled {
                s.ports.insert(port);
            } else {
                s.ports.remove(&port);
            }
        }
    }

    // ---- sending ---------------------------------------------------------

    /// A byte stream to the member's default service.
    pub fn connect(&self, target: &str) -> Result<MeshStream, ClientError> {
        let (_, send, recv) = self.inner.rt().block_on(self.inner.open_forward(target, 0))?;
        Ok(MeshStream { send, recv })
    }

    /// Netcat mode, dial side: bridge this process's stdio to the member.
    /// Blocks until the stream closes.
    pub fn pipe_stdio(&self, target: &str) -> Result<(), ClientError> {
        let inner = self.inner.clone();
        inner.rt().block_on(async {
            let (peer, s, r) = inner.open_forward(target, 0).await?;
            let res = bridge_stdio(s, r).await;
            if let Err(e) = &res {
                inner.emit(Event::Stopped { what: "stdio", error: Some(format!("{peer}: {e}")) });
            }
            res
        })?;
        Ok(())
    }

    /// Netcat mode, serve side: bridge the first member stream (default
    /// service) to stdio. Blocks until it closes.
    pub fn serve_stdio(&self) -> Result<(), ClientError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        if let Ok(mut s) = self.inner.serving.lock() {
            s.stdio = Some(tx);
        }
        self.inner.emit(Event::Listening { npub: self.inner.npub.clone(), addr: self.local_addr() });
        self.inner.rt().block_on(async {
            let (_peer, s, r) = rx.await.map_err(|_| ClientError::Stream("stopped".into()))?;
            bridge_stdio(s, r).await
        })?;
        Ok(())
    }

    /// Send a chat message; delivery arrives as `ChatDelivered` or
    /// `ChatFailed`.
    pub fn send_chat(&self, target: &str, text: &str) {
        let inner = self.inner.clone();
        self.inner.rt().spawn(inner.send_text(target.to_string(), TextKind::Chat, text.to_string()));
    }

    /// Share text for the member's clipboard; same delivery events as chat.
    pub fn send_clipboard(&self, target: &str, text: &str) {
        let inner = self.inner.clone();
        self.inner.rt().spawn(inner.send_text(target.to_string(), TextKind::Clipboard, text.to_string()));
    }

    /// Send a file; progress and the outcome arrive as events.
    pub fn send_file(&self, path: PathBuf, target: &str) {
        let inner = self.inner.clone();
        let target = target.to_string();
        let key = (target.clone(), path.clone());
        let task = self.inner.rt().spawn({
            let inner = inner.clone();
            let key = key.clone();
            async move {
                let res = async {
                    let pk = parse_target(&target)?;
                    let peer = npub_of(&pk);
                    let c = inner.conn(pk).await?;
                    let mut last_pct = u64::MAX;
                    apps::send_file(&c, &path, |sent, total| {
                        let pct = if total == 0 { 100 } else { sent * 100 / total };
                        if pct != last_pct {
                            last_pct = pct;
                            inner.emit(Event::TransferProgress { peer: peer.clone(), path: path.clone(), sent, total });
                        }
                    })
                    .await?;
                    Ok::<_, ClientError>(peer)
                }
                .await;
                match res {
                    Ok(peer) => inner.emit(Event::TransferDone { peer, path: path.clone() }),
                    Err(e) => inner.emit(Event::TransferFailed { peer: target.clone(), path: Some(path.clone()), error: e.to_string() }),
                }
                if let Ok(mut m) = inner.sends.lock() {
                    m.remove(&key);
                }
            }
        });
        if let Ok(mut m) = self.inner.sends.lock() {
            m.entry(key).or_default().push(task.abort_handle());
        }
    }

    /// Cancel sends of `path` to `target`; the receiver keeps its partial
    /// for a later resume. Returns whether any send was running.
    pub fn cancel_transfer(&self, target: &str, path: &Path) -> bool {
        let handles = self
            .inner
            .sends
            .lock()
            .ok()
            .and_then(|mut m| m.remove(&(target.to_string(), path.to_path_buf())))
            .unwrap_or_default();
        let any = !handles.is_empty();
        for h in handles {
            h.abort();
        }
        if any {
            self.inner.emit(Event::TransferCancelled { peer: target.to_string(), path: path.to_path_buf() });
        }
        any
    }

    /// Listen on `local` and carry each TCP connection to the member's
    /// default service. Returns the forward id.
    pub fn forward(&self, target: &str, local: SocketAddr) -> u64 {
        self.forward_port(target, local, 0)
    }

    /// Like [`Client::forward`], to a port the member serves
    /// ([`Client::serve_port`]).
    pub fn forward_port(&self, target: &str, local: SocketAddr, remote_port: u16) -> u64 {
        let id = self.inner.next_forward_id.fetch_add(1, Ordering::Relaxed);
        let cancel = Arc::new(tokio::sync::Notify::new());
        if let Ok(mut m) = self.inner.forwards.lock() {
            m.insert(
                id,
                ForwardEntry {
                    info: ForwardInfo { id, target: target.to_string(), local, remote_port },
                    cancel: cancel.clone(),
                },
            );
        }
        let inner = self.inner.clone();
        let target = target.to_string();
        self.inner.rt().spawn(async move {
            let error = async {
                let listener = tokio::net::TcpListener::bind(local).await?;
                loop {
                    let (tcp, _) = tokio::select! {
                        a = listener.accept() => a?,
                        () = cancel.notified() => return Ok::<(), io::Error>(()),
                    };
                    let inner = inner.clone();
                    let target = target.clone();
                    tokio::spawn(async move {
                        match inner.open_forward(&target, remote_port).await {
                            Ok((_, s, r)) => {
                                let _ = apps::bridge(tcp, s, r).await;
                            }
                            Err(e) => tracing::info!(%target, "forward connection failed: {e}"),
                        }
                    });
                }
            }
            .await
            .err()
            .map(|e| e.to_string());
            if let Ok(mut m) = inner.forwards.lock() {
                m.remove(&id);
            }
            inner.emit(Event::ForwardStopped { id, error });
        });
        id
    }

    /// Running forwards.
    #[must_use]
    pub fn list_forwards(&self) -> Vec<ForwardInfo> {
        let mut v: Vec<ForwardInfo> =
            self.inner.forwards.lock().map(|m| m.values().map(|e| e.info.clone()).collect()).unwrap_or_default();
        v.sort_by_key(|f| f.id);
        v
    }

    /// Stop a forward; `ForwardStopped` confirms it.
    pub fn cancel_forward(&self, id: u64) -> bool {
        let entry = self.inner.forwards.lock().ok().and_then(|m| m.get(&id).map(|e| e.cancel.clone()));
        match entry {
            Some(c) => {
                c.notify_one();
                true
            }
            None => false,
        }
    }
}

async fn bridge_stdio(mut s: SendStream, mut r: RecvStream) -> Result<(), ClientError> {
    let up = async {
        let mut stdin = tokio::io::stdin();
        let res = tokio::io::copy(&mut stdin, &mut s).await;
        let _ = s.finish();
        res
    };
    let down = async {
        let mut stdout = tokio::io::stdout();
        let res = tokio::io::copy(&mut r, &mut stdout).await;
        let _ = tokio::io::AsyncWriteExt::flush(&mut stdout).await;
        res
    };
    let (a, b) = tokio::join!(up, down);
    b?;
    a?;
    Ok(())
}
