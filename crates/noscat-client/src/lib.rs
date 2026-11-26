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
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use noscat_core::Identity;
use noscat_core::access::Access;
use noscat_core::apps::{self, Incoming, Received, TextKind};
use noscat_core::dataplane::{DataplaneConfig, Reachability};
use noscat_core::device::{Device, DeviceConfig, DeviceEvent};
use noscat_core::streams::Connection;
use nostr::nips::nip19::ToBech32 as _;
use nostr::prelude::PublicKey;
use quinn::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite};

pub use noscat_core::{pairing_uri, parse_pairing_relays, parse_pairing_target};
mod terminal;

pub use noscat_core::access::{Group as AccessGroup, Rule as AccessRule};
pub use noscat_core::apps::TermFrame;
pub use noscat_core::relay::{DEFAULT_RELAYS, default_relays};

/// How long a dial waits for a member to become reachable.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// How often the prober (`start_probing`) dials online members it has no
/// connection to.
const PROBE_INTERVAL: Duration = Duration::from_secs(30);
/// Default receive cap per file transfer: 64 GiB.
pub const MAX_INCOMING_BYTES: u64 = 64 << 30;
/// Default UDP port for a reachable device.
pub const DEFAULT_LISTEN_PORT: u16 = 41641;
/// How long an asked access request waits for an answer before it counts
/// as denied.
pub const ACCESS_ASK_TIMEOUT: Duration = Duration::from_secs(60);
/// Access requests kept for [`Client::access_requests`].
const ACCESS_RECENT: usize = 50;

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
    /// The relays a pairing code names ([`parse_pairing_relays`]), when
    /// this client starts in order to join through them: until the join
    /// ends it uses only these, so nothing (not even its key package)
    /// reaches `relays` or the defaults. Ignored once in a mesh.
    pub join_relays: Vec<String>,
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
            join_relays: Vec::new(),
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

/// A device that asked to join (scanned this device's QR) and is not a
/// member yet. Its name is its own claim: compare the npub with the
/// joining device's screen before inviting it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinRequest {
    pub npub: String,
    pub name: Option<String>,
    /// Seconds since it asked.
    pub age_secs: u64,
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
    /// Reachable from the internet, per its latest advert (this device:
    /// per its own config). Every mesh needs one.
    pub reachable: bool,
    /// It offers a terminal (per its latest advert; this device: its own
    /// offer). Show the terminal action only for these; the member still
    /// decides per request.
    pub control: bool,
    /// Data can flow to it right now: a direct link, or a live connection
    /// (possibly relayed through another member). `online` only says its
    /// advert arrived over the relays; a member can be online and still
    /// unreachable (different network, no reachable member).
    pub connected: bool,
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
    /// A transfer began, in either direction. `id` names it in every later
    /// transfer event. `path` is the source file of a send; `None` on a
    /// receive (the final name is only known at the end).
    TransferStarted { id: u64, peer: String, name: String, size: u64, incoming: bool, path: Option<PathBuf> },
    /// A transfer finished and verified (source path on send, final path
    /// on receive, which may differ from the sent name when it was taken).
    TransferDone { id: u64, peer: String, path: PathBuf },
    /// A receive ended without a whole file; the `.noscat-part` resumes
    /// when the same file is sent again.
    TransferPartial { id: u64, peer: String, path: PathBuf },
    /// Both directions, at most one event per percent. `path` is the source
    /// on a send and the `.noscat-part` file on a receive.
    TransferProgress { id: u64, peer: String, path: PathBuf, sent: u64, total: u64 },
    TransferFailed { id: u64, peer: String, path: Option<PathBuf>, error: String },
    /// A send cancelled by this side; the receiver keeps its partial.
    TransferCancelled { id: u64, peer: String, path: PathBuf },
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
    /// A member asks for a group set to ask (Control). Show a prompt and
    /// answer with [`Client::answer_access`] within
    /// [`ACCESS_ASK_TIMEOUT`]; raised only after
    /// [`Client::set_access_prompts`]`(true)`.
    AccessRequest { id: u64, peer: String, group: AccessGroup },
    /// An asked request ended (answered, or timed out as denied). Close
    /// its prompt.
    AccessResolved { id: u64, peer: String, group: AccessGroup, outcome: AccessOutcome },
    /// Viewer: [`Client::open_terminal`] waits while the member asks its
    /// user. Show "waiting for <member> to approve".
    TerminalWaiting { peer: String },
    /// Host: a member's terminal session started here. Show it (the apps
    /// keep a banner up while any session is open).
    TerminalOpened { id: u64, peer: String },
    /// Host: a session ended (`error` set when the shell could not run).
    TerminalClosed { id: u64, peer: String, secs: u64, error: Option<String> },
}

/// A terminal session open on this device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalSession {
    pub id: u64,
    pub peer: String,
    pub secs: u64,
}

struct TerminalEntry {
    peer: PublicKey,
    started: Instant,
    end: Option<tokio::sync::oneshot::Sender<()>>,
}

/// How an access request ended, or that it still waits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessOutcome {
    /// Asked; no answer yet.
    Waiting,
    Allowed,
    Denied,
    /// Asked, and nobody answered in time.
    TimedOut,
    /// The group asks, but no app was there to ask (a headless host).
    NoOneToAsk,
}

/// An incoming request the access rules acted on, for a host's review.
/// Allowed requests by an allow rule are not listed; refused ones and
/// every asked one are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessRequest {
    pub id: u64,
    pub peer: String,
    pub group: AccessGroup,
    pub age_secs: u64,
    pub outcome: AccessOutcome,
}

/// The answer to an asked request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessAnswer {
    /// Allow this request only.
    Once,
    /// Allow it and every later one from this member (saves an allow rule).
    Always,
    /// Refuse this request.
    Deny,
}

/// The rule for each access group, as it applies to one member (or the
/// defaults).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessRules {
    pub send: AccessRule,
    pub services: AccessRule,
    pub control: AccessRule,
}

impl AccessRules {
    fn from_fn(f: impl Fn(AccessGroup) -> AccessRule) -> Self {
        Self { send: f(AccessGroup::Send), services: f(AccessGroup::Services), control: f(AccessGroup::Control) }
    }
}

struct PendingAsk {
    peer: PublicKey,
    group: AccessGroup,
    at: Instant,
    answer: tokio::sync::oneshot::Sender<bool>,
}

struct RecentAsk {
    id: u64,
    peer: PublicKey,
    group: AccessGroup,
    at: Instant,
    outcome: AccessOutcome,
}

/// Access state that lives only while the client runs.
#[derive(Default)]
struct Asks {
    next_id: u64,
    pending: HashMap<u64, PendingAsk>,
    recent: VecDeque<RecentAsk>,
    /// One-time passes (`noscat allow --once` with nothing pending).
    once: HashSet<(PublicKey, AccessGroup)>,
}

impl Asks {
    fn next_id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }

    /// Log an outcome. A refusal repeating the previous entry within a
    /// minute refreshes it, so a member retrying in a loop takes one line.
    fn record(&mut self, id: Option<u64>, peer: PublicKey, group: AccessGroup, outcome: AccessOutcome) -> u64 {
        if id.is_none() {
            if let Some(last) = self.recent.back_mut() {
                if last.peer == peer
                    && last.group == group
                    && last.outcome == outcome
                    && last.at.elapsed() < Duration::from_secs(60)
                {
                    last.at = Instant::now();
                    return last.id;
                }
            }
        }
        let id = id.unwrap_or_else(|| self.next_id());
        self.recent.push_back(RecentAsk { id, peer, group, at: Instant::now(), outcome });
        while self.recent.len() > ACCESS_RECENT {
            self.recent.pop_front();
        }
        id
    }
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
    #[error("another noscat client is using {} (in this process or another)", .0.display())]
    Busy(PathBuf),
}

impl From<noscat_core::device::DeviceError> for ClientError {
    fn from(e: noscat_core::device::DeviceError) -> Self {
        Self::Mesh(e.to_string())
    }
}

impl From<noscat_core::access::AccessError> for ClientError {
    fn from(e: noscat_core::access::AccessError) -> Self {
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
    sends: Mutex<HashMap<(String, PathBuf), Vec<(u64, tokio::task::AbortHandle)>>>,
    next_transfer_id: AtomicU64,
    forwards: Mutex<HashMap<u64, ForwardEntry>>,
    next_forward_id: AtomicU64,
    /// The connection prober runs (started by `up`/`expose`).
    probing: std::sync::atomic::AtomicBool,
    /// Members a probe is connecting to right now.
    probes: Mutex<std::collections::HashSet<PublicKey>>,
    /// Who may do what to this device (saved in the state directory).
    access: Mutex<Access>,
    asks: Mutex<Asks>,
    /// An app answers access prompts; without one, asking means denying.
    prompts: AtomicBool,
    /// Terminal sessions members have open here.
    terminals: Mutex<HashMap<u64, TerminalEntry>>,
    next_terminal_id: AtomicU64,
    /// The state directory (the terminal session log).
    dir: PathBuf,
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

/// Now as `YYYY-MM-DDTHH:MM:SSZ` (for the terminal log).
fn utc_now() -> String {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days.cast_signed() + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem / 60 % 60, rem % 60)
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
            let raw = std::fs::read(path)
                .map_err(|e| ClientError::Identity(format!("cannot read {}: {e}", path.display())))?;
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("identity.nsec");
            let plain = noscat_core::fsutil::unseal(name, &raw).map_err(|e| ClientError::Identity(e.to_string()))?;
            let secret = String::from_utf8(plain).map_err(|_| ClientError::Identity(format!("{} is not text", path.display())))?;
            let identity = Identity::from_secret(secret.trim()).map_err(|e| id(&e))?;
            // A plain file from before the storage key was set: seal it now.
            if !noscat_core::fsutil::is_sealed(&raw) && noscat_core::fsutil::has_storage_key() {
                if let Err(e) = noscat_core::fsutil::write_secret(path, &raw) {
                    tracing::warn!("could not seal {}: {e}", path.display());
                }
            }
            Ok(identity)
        }
    }
}

/// Seal the device's secret files (identity, mesh state) at rest with
/// `key` from now on; plain files migrate on their next write. Call once
/// at start, before any client or device-directory helper. The key lives
/// in the platform's keystore; this crate never stores it. `None` writes
/// plain files (the CLI's default).
pub fn set_storage_key(key: Option<[u8; 32]>) {
    noscat_core::fsutil::set_storage_key(key);
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
        let direct: std::collections::HashSet<PublicKey> = self
            .device
            .peers()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|p| p.direct)
            .map(|p| p.device)
            .collect();
        let live: std::collections::HashSet<PublicKey> = self
            .conns
            .lock()
            .map(|m| m.iter().filter(|(_, c)| c.inner.close_reason().is_none()).map(|(k, _)| *k).collect())
            .unwrap_or_default();
        let mut members: Vec<Member> = self
            .device
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
                reachable: m.reachable,
                control: m.control,
                connected: !m.this_device && (direct.contains(&m.device) || live.contains(&m.device)),
            })
            .collect();
        sort_members(&mut members);
        members
    }

    /// While serving, keep a connection to every member whose advert is
    /// fresh, so `connected` tells "reachable now" from "seen on the
    /// relays". Each round dials the online members without a live
    /// connection; keep-alives hold the rest open and their close shows.
    fn start_probing(self: &Arc<Self>) {
        if self.probing.swap(true, Ordering::SeqCst) {
            return;
        }
        let me = self.clone();
        self.rt().spawn(async move {
            loop {
                for m in me.device.members().await {
                    if m.this_device || !m.online {
                        continue;
                    }
                    let open = me
                        .conns
                        .lock()
                        .is_ok_and(|c| c.get(&m.device).is_some_and(|c| c.inner.close_reason().is_none()));
                    // Skip members with a live connection or a probe already
                    // under way.
                    if open || !me.probes.lock().is_ok_and(|mut p| p.insert(m.device)) {
                        continue;
                    }
                    let me2 = me.clone();
                    tokio::spawn(async move {
                        let ok = me2.conn(m.device).await.is_ok();
                        if let Ok(mut p) = me2.probes.lock() {
                            p.remove(&m.device);
                        }
                        if !ok {
                            tracing::debug!(peer = %npub_of(&m.device), "probe: no connection");
                        }
                    });
                }
                tokio::time::sleep(PROBE_INTERVAL).await;
            }
        });
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
            // `connected` changed: refresh the roster for UIs.
            let members = me.members().await;
            me.emit(Event::Roster { members });
            loop {
                match apps::accept(&c).await {
                    Ok(Some(incoming)) => {
                        let me = me.clone();
                        let peer = peer.clone();
                        let pk = c.peer;
                        tokio::spawn(async move { me.handle(pk, peer, incoming).await });
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
            let members = me.members().await;
            me.emit(Event::Roster { members });
        });
    }

    async fn handle(self: Arc<Self>, pk: PublicKey, peer: String, incoming: Incoming) {
        // The opener is the QUIC peer, authenticated by the handshake: it
        // cannot claim to be another member.
        let mut incoming = incoming;
        if let Incoming::Terminal(_) = incoming {
            if !terminal::SUPPORTED {
                if let Incoming::Terminal(t) = incoming {
                    t.refuse().await;
                }
                return;
            }
        }
        let group = incoming.group();
        let allowed = match &mut incoming {
            Incoming::Terminal(t) => self.authorize(pk, group, t.waiting()).await,
            _ => self.authorize(pk, group, std::future::ready(())).await,
        };
        if !allowed {
            incoming.not_permitted().await;
            return;
        }
        match incoming {
            Incoming::Text(t) => match t.ack().await {
                (TextKind::Chat, text) => self.emit(Event::ChatMessage { peer, text }),
                (TextKind::Clipboard, text) => self.emit(Event::Clipboard { peer, text }),
            },
            Incoming::File(f) => {
                let inbox = self.serving.lock().ok().and_then(|s| s.inbox.clone());
                let Some(dir) = inbox else {
                    f.refuse().await;
                    return;
                };
                let id = self.next_transfer_id.fetch_add(1, Ordering::Relaxed);
                self.emit(Event::TransferStarted {
                    id,
                    peer: peer.clone(),
                    name: f.name.clone(),
                    size: f.size,
                    incoming: true,
                    path: None,
                });
                if f.size > self.max_incoming {
                    self.emit(Event::TransferFailed {
                        id,
                        peer,
                        path: None,
                        error: format!("{} is larger than the receive limit", f.name),
                    });
                    f.refuse().await;
                    return;
                }
                let part = dir.join(format!("{}{}", f.name, apps::PART_SUFFIX));
                let mut last_pct = u64::MAX;
                let progress = |got: u64, total: u64| {
                    let pct = if total == 0 { 100 } else { got * 100 / total };
                    if pct != last_pct {
                        last_pct = pct;
                        self.emit(Event::TransferProgress { id, peer: peer.clone(), path: part.clone(), sent: got, total });
                    }
                };
                match f.receive(&dir, progress).await {
                    Ok(Received::Done(path)) => self.emit(Event::TransferDone { id, peer, path }),
                    Ok(Received::Partial(path)) => self.emit(Event::TransferPartial { id, peer, path }),
                    Err(e) => self.emit(Event::TransferFailed { id, peer, path: None, error: e.to_string() }),
                }
            }
            Incoming::Terminal(t) => self.host_terminal(pk, peer, t).await,
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

    async fn host_terminal(self: &Arc<Self>, pk: PublicKey, peer: String, t: apps::IncomingTerminal) {
        let id = self.next_terminal_id.fetch_add(1, Ordering::Relaxed);
        let (end_tx, end_rx) = tokio::sync::oneshot::channel();
        if let Ok(mut m) = self.terminals.lock() {
            m.insert(id, TerminalEntry { peer: pk, started: Instant::now(), end: Some(end_tx) });
        }
        self.log_terminal(&format!("{peer} opened session {id}"));
        self.emit(Event::TerminalOpened { id, peer: peer.clone() });
        let res = terminal::host(t, end_rx).await;
        let secs = self.terminals.lock().ok().and_then(|mut m| m.remove(&id)).map_or(0, |e| e.started.elapsed().as_secs());
        match &res {
            Ok(code) => self.log_terminal(&format!("{peer} session {id} ended after {secs} s, exit {code}")),
            Err(e) => self.log_terminal(&format!("{peer} session {id} failed: {e}")),
        }
        self.emit(Event::TerminalClosed { id, peer, secs, error: res.err() });
    }

    /// Append to `<dir>/terminal.log`: who opened a session, when, and for
    /// how long.
    fn log_terminal(&self, what: &str) {
        use std::io::Write as _;
        tracing::info!("terminal: {what}");
        let line = format!("{} {what}\n", utc_now());
        let path = self.dir.join("terminal.log");
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
        if let Ok(mut f) = opts.open(path) {
            let _ = f.write_all(line.as_bytes());
        }
    }

    /// Offer control in adverts when some member could get in: a member or
    /// the default allows it, or asks and an app is here to answer.
    async fn refresh_control_offer(&self) {
        let prompts = self.prompts.load(Ordering::Relaxed);
        let opens = |r: AccessRule| r == AccessRule::Allow || (r == AccessRule::Ask && prompts);
        let offered = terminal::SUPPORTED
            && self.access.lock().is_ok_and(|a| {
                opens(a.default_rule(AccessGroup::Control))
                    || a.devices().iter().any(|d| a.own_rule(d, AccessGroup::Control).is_some_and(opens))
            });
        self.device.set_control_offered(offered).await;
    }

    /// Whether `peer` may do what `group` covers. Allow and deny rules
    /// answer at once; ask raises [`Event::AccessRequest`], awaits
    /// `waiting` (the protocol tells the opener it waits), and holds the
    /// request until an answer or [`ACCESS_ASK_TIMEOUT`].
    async fn authorize(
        self: &Arc<Self>,
        peer: PublicKey,
        group: AccessGroup,
        waiting: impl std::future::Future<Output = ()>,
    ) -> bool {
        // A poisoned lock refuses: never allow what the rules might deny.
        let rule = self.access.lock().map_or(AccessRule::Deny, |a| a.rule(&peer, group));
        let record = |outcome| {
            if let Ok(mut a) = self.asks.lock() {
                a.record(None, peer, group, outcome);
            }
        };
        match rule {
            AccessRule::Allow => true,
            AccessRule::Deny => {
                record(AccessOutcome::Denied);
                false
            }
            AccessRule::Ask => {
                if self.asks.lock().is_ok_and(|mut a| a.once.remove(&(peer, group))) {
                    record(AccessOutcome::Allowed);
                    return true;
                }
                if !self.prompts.load(Ordering::Relaxed) {
                    record(AccessOutcome::NoOneToAsk);
                    return false;
                }
                let (tx, rx) = tokio::sync::oneshot::channel();
                let Ok(id) = self.asks.lock().map(|mut a| {
                    let id = a.next_id();
                    a.pending.insert(id, PendingAsk { peer, group, at: Instant::now(), answer: tx });
                    id
                }) else {
                    return false;
                };
                self.emit(Event::AccessRequest { id, peer: npub_of(&peer), group });
                waiting.await;
                let outcome = match tokio::time::timeout(ACCESS_ASK_TIMEOUT, rx).await {
                    Ok(Ok(true)) => AccessOutcome::Allowed,
                    Ok(Ok(false)) => AccessOutcome::Denied,
                    Ok(Err(_)) | Err(_) => AccessOutcome::TimedOut,
                };
                if let Ok(mut a) = self.asks.lock() {
                    a.pending.remove(&id);
                    a.record(Some(id), peer, group, outcome);
                }
                self.emit(Event::AccessResolved { id, peer: npub_of(&peer), group, outcome });
                outcome == AccessOutcome::Allowed
            }
        }
    }

    async fn send_text(self: Arc<Self>, target: String, kind: TextKind, text: String) {
        let res = async {
            let pk = parse_target(&target)?;
            let c = self.conn(pk).await?;
            match apps::send_text(&c, kind, &text).await {
                Ok(()) => {}
                // The member answered: retrying cannot change its mind.
                Err(e @ (apps::AppError::NotPermitted | apps::AppError::Refused)) => return Err(e.into()),
                Err(first) => {
                // The connection may be stale (the network changed under
                // it): drop it and try once more on a fresh one.
                tracing::debug!(peer = %npub_of(&pk), "text send failed, retrying on a new connection: {first}");
                c.inner.close(0u32.into(), b"retry");
                if let Ok(mut m) = self.conns.lock() {
                    m.remove(&pk);
                }
                let c = self.conn(pk).await?;
                apps::send_text(&c, kind, &text).await?;
                }
            }
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
        dataplane.stun_servers = config.stun_servers.clone();
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
            join_relays: config.join_relays.clone(),
            dataplane,
            peer_addresses,
        };
        let access = Access::load(&dir)?;
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
            next_transfer_id: AtomicU64::new(1),
            forwards: Mutex::new(HashMap::new()),
            next_forward_id: AtomicU64::new(1),
            probing: std::sync::atomic::AtomicBool::new(false),
            probes: Mutex::new(std::collections::HashSet::new()),
            access: Mutex::new(access),
            asks: Mutex::new(Asks::default()),
            prompts: AtomicBool::new(false),
            terminals: Mutex::new(HashMap::new()),
            next_terminal_id: AtomicU64::new(1),
            dir: dir.clone(),
        });
        inner.rt().block_on(inner.refresh_control_offer());
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

    /// The state directory (identity, mesh, access rules, terminal log).
    #[must_use]
    pub fn state_dir(&self) -> &Path {
        &self.inner.dir
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

    /// This device's name, as members see it.
    #[must_use]
    pub fn device_name(&self) -> String {
        self.inner.device.name()
    }

    /// Rename this device. Members see the new name within seconds: an
    /// advert goes out now, and this returns once it is published (or
    /// failed). Blocking. The caller persists the name for the next start.
    pub fn set_device_name(&self, name: &str) {
        self.inner.rt().block_on(self.inner.device.set_name(name));
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

    /// Devices that asked to join in the last 15 minutes and are not
    /// members yet, oldest first. Read from the relays, so a process
    /// started after the request (a CLI next to a service) sees it too.
    /// Invite one with [`Client::invite`].
    pub fn join_requests(&self) -> Vec<JoinRequest> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        self.inner
            .rt()
            .block_on(self.inner.device.pending_joins())
            .into_iter()
            .map(|p| JoinRequest { npub: npub_of(&p.device), name: p.name, age_secs: now.saturating_sub(p.asked_at) })
            .collect()
    }

    /// Wait up to `timeout` for an invitation from `inviter` (npub or
    /// `noscat:` URI; the scanned QR is the trust anchor) and join. A URI
    /// that names relays (a private mesh's) joins through those alone.
    pub fn join(&self, inviter: &str, timeout: Duration) -> Result<(), ClientError> {
        let pk = parse_target(inviter)?;
        let relays = parse_pairing_relays(inviter);
        self.inner.rt().block_on(self.inner.device.join(pk, &relays, timeout))?;
        Ok(())
    }

    /// The mesh's relays (empty outside a mesh).
    #[must_use]
    pub fn mesh_relays(&self) -> Vec<String> {
        self.inner.rt().block_on(self.inner.device.mesh_relays())
    }

    /// Whether the mesh is private: its devices use only its relays, log
    /// in to them (NIP-42) and stay off the public ones.
    #[must_use]
    pub fn is_private(&self) -> bool {
        self.inner.rt().block_on(self.inner.device.is_private())
    }

    /// Replace the mesh's relays (1 to 16 `wss://` URLs).
    pub fn set_mesh_relays(&self, relays: &[String]) -> Result<(), ClientError> {
        self.inner.rt().block_on(self.inner.device.set_mesh_relays(relays))?;
        Ok(())
    }

    /// The mesh's STUN servers (`ip:port`); empty when it lists none.
    #[must_use]
    pub fn mesh_stun(&self) -> Vec<String> {
        self.inner.rt().block_on(self.inner.device.mesh_stun())
    }

    /// Replace the mesh's STUN servers (`ip:port`, no hostnames, at most
    /// 8; empty removes them). Members use the new list from their next
    /// start.
    pub fn set_mesh_stun(&self, servers: &[String]) -> Result<(), ClientError> {
        self.inner.rt().block_on(self.inner.device.set_mesh_stun(servers))?;
        Ok(())
    }

    /// Make the mesh private, or shared again.
    pub fn set_private(&self, private: bool) -> Result<(), ClientError> {
        self.inner.rt().block_on(self.inner.device.set_private(private))?;
        Ok(())
    }

    /// This device's pairing URI for QR codes: `noscat:<npub>`, with the
    /// mesh's relays when it is private.
    #[must_use]
    pub fn pairing_uri(&self) -> String {
        let relays = if self.is_private() { self.mesh_relays() } else { Vec::new() };
        pairing_uri(self.npub(), &relays)
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

    // ---- access ----------------------------------------------------------

    /// The rules for members without rules of their own.
    #[must_use]
    pub fn access_defaults(&self) -> AccessRules {
        let a = self.inner.access.lock();
        AccessRules::from_fn(|g| a.as_ref().map_or(g.default_rule(), |a| a.default_rule(g)))
    }

    /// The rules that apply to `device` (its own, else the defaults).
    pub fn access_of(&self, device: &str) -> Result<AccessRules, ClientError> {
        let pk = parse_target(device)?;
        let a = self.inner.access.lock().map_err(|_| ClientError::Mesh("access settings unavailable".into()))?;
        Ok(AccessRules::from_fn(|g| a.rule(&pk, g)))
    }

    /// Members with rules of their own, and those rules.
    #[must_use]
    pub fn access_devices(&self) -> Vec<(String, Vec<(AccessGroup, AccessRule)>)> {
        let Ok(a) = self.inner.access.lock() else { return Vec::new() };
        a.devices()
            .into_iter()
            .map(|pk| {
                let own = AccessGroup::ALL.into_iter().filter_map(|g| a.own_rule(&pk, g).map(|r| (g, r))).collect();
                (npub_of(&pk), own)
            })
            .collect()
    }

    /// Set `device`'s rule for `group` (`None` device: the default for
    /// every member; `None` rule: back to the default). `Ask` is for
    /// Control only. Saved at once.
    pub fn set_access(&self, device: Option<&str>, group: AccessGroup, rule: Option<AccessRule>) -> Result<(), ClientError> {
        let pk = device.map(parse_target).transpose()?;
        self.inner.access.lock().map_err(|_| ClientError::Mesh("access settings unavailable".into()))?.set(pk.as_ref(), group, rule)?;
        self.inner.rt().block_on(self.inner.refresh_control_offer());
        Ok(())
    }

    /// Drop all of `device`'s own rules: the defaults apply to it again.
    pub fn reset_access(&self, device: &str) -> Result<(), ClientError> {
        let pk = parse_target(device)?;
        self.inner.access.lock().map_err(|_| ClientError::Mesh("access settings unavailable".into()))?.reset(&pk)?;
        self.inner.rt().block_on(self.inner.refresh_control_offer());
        Ok(())
    }

    /// Whether an app is here to answer [`Event::AccessRequest`]. Off (the
    /// default, a headless host), a group set to ask refuses at once.
    pub fn set_access_prompts(&self, on: bool) {
        self.inner.prompts.store(on, Ordering::Relaxed);
        self.inner.rt().block_on(self.inner.refresh_control_offer());
    }

    /// Answer an asked request. Errors if it is no longer waiting.
    pub fn answer_access(&self, id: u64, answer: AccessAnswer) -> Result<(), ClientError> {
        let pending = self
            .inner
            .asks
            .lock()
            .ok()
            .and_then(|mut a| a.pending.remove(&id))
            .ok_or_else(|| ClientError::Mesh("that request is no longer waiting".into()))?;
        if answer == AccessAnswer::Always {
            self.inner
                .access
                .lock()
                .map_err(|_| ClientError::Mesh("access settings unavailable".into()))?
                .set(Some(&pending.peer), pending.group, Some(AccessRule::Allow))?;
        }
        let _ = pending.answer.send(answer != AccessAnswer::Deny);
        Ok(())
    }

    /// Answer `device`'s waiting `group` requests, if any. Returns whether
    /// one was waiting.
    pub fn answer_waiting(&self, device: &str, group: AccessGroup, allow: bool) -> Result<bool, ClientError> {
        let pk = parse_target(device)?;
        let mut a = self.inner.asks.lock().map_err(|_| ClientError::Mesh("access state unavailable".into()))?;
        let waiting: Vec<u64> = a.pending.iter().filter(|(_, p)| p.peer == pk && p.group == group).map(|(id, _)| *id).collect();
        for id in &waiting {
            if let Some(p) = a.pending.remove(id) {
                let _ = p.answer.send(allow);
            }
        }
        if !allow {
            a.once.remove(&(pk, group));
        }
        Ok(!waiting.is_empty())
    }

    /// Allow `device` one `group` request: the waiting one if there is
    /// one, else its next (until this client stops). For hosts without an
    /// app, e.g. `noscat allow <device> control --once`.
    pub fn allow_once(&self, device: &str, group: AccessGroup) -> Result<(), ClientError> {
        if !self.answer_waiting(device, group, true)? {
            let pk = parse_target(device)?;
            if let Ok(mut a) = self.inner.asks.lock() {
                a.once.insert((pk, group));
            }
        }
        Ok(())
    }

    /// Waiting requests, then recent refusals and asked requests, newest
    /// first.
    #[must_use]
    pub fn access_requests(&self) -> Vec<AccessRequest> {
        let Ok(a) = self.inner.asks.lock() else { return Vec::new() };
        let mut out: Vec<AccessRequest> = a
            .pending
            .iter()
            .map(|(id, p)| AccessRequest {
                id: *id,
                peer: npub_of(&p.peer),
                group: p.group,
                age_secs: p.at.elapsed().as_secs(),
                outcome: AccessOutcome::Waiting,
            })
            .collect();
        out.sort_by_key(|r| r.age_secs);
        out.extend(a.recent.iter().rev().map(|r| AccessRequest {
            id: r.id,
            peer: npub_of(&r.peer),
            group: r.group,
            age_secs: r.at.elapsed().as_secs(),
            outcome: r.outcome,
        }));
        out
    }

    // ---- terminal --------------------------------------------------------

    /// Open a terminal on a member (`cols` x `rows`, the viewer's `TERM`).
    /// Blocks until its shell started; while the member asks its user,
    /// [`Event::TerminalWaiting`] fires and this keeps waiting (up to
    /// [`ACCESS_ASK_TIMEOUT`] on the member's side). The stream then
    /// carries [`TermFrame`]s: write `Input` and `Resize`, read `Output`
    /// until `Exit`. Refusals are `ClientError::Stream` ("not permitted",
    /// or "does not offer this").
    pub fn open_terminal(&self, target: &str, cols: u16, rows: u16, term: &str) -> Result<MeshStream, ClientError> {
        let pk = parse_target(target)?;
        let inner = self.inner.clone();
        let term = term.to_string();
        self.inner.rt().block_on(async move {
            let c = inner.conn(pk).await?;
            let peer = npub_of(&pk);
            let (send, recv) = apps::open_terminal(&c, cols, rows, &term, || {
                inner.emit(Event::TerminalWaiting { peer: peer.clone() });
            })
            .await?;
            Ok(MeshStream { send, recv })
        })
    }

    /// Terminal sessions members have open on this device.
    #[must_use]
    pub fn terminal_sessions(&self) -> Vec<TerminalSession> {
        let Ok(m) = self.inner.terminals.lock() else { return Vec::new() };
        let mut v: Vec<TerminalSession> = m
            .iter()
            .map(|(id, e)| TerminalSession { id: *id, peer: npub_of(&e.peer), secs: e.started.elapsed().as_secs() })
            .collect();
        v.sort_by_key(|t| t.id);
        v
    }

    /// End a session open on this device (its shell is killed). Whether it
    /// was open.
    pub fn end_terminal(&self, id: u64) -> bool {
        self.inner.terminals.lock().ok().and_then(|mut m| m.get_mut(&id).and_then(|e| e.end.take())).is_some_and(|tx| tx.send(()).is_ok())
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
        self.inner.start_probing();
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
        self.inner.start_probing();
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

    /// Send a file. Returns the transfer id; `TransferStarted`, progress
    /// and the outcome arrive as events carrying it.
    pub fn send_file(&self, path: PathBuf, target: &str) -> u64 {
        let inner = self.inner.clone();
        let target = target.to_string();
        let key = (target.clone(), path.clone());
        let id = self.inner.next_transfer_id.fetch_add(1, Ordering::Relaxed);
        let task = self.inner.rt().spawn({
            let inner = inner.clone();
            let key = key.clone();
            async move {
                let res = async {
                    let pk = parse_target(&target)?;
                    let peer = npub_of(&pk);
                    let size = tokio::fs::metadata(&path).await?.len();
                    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                    inner.emit(Event::TransferStarted { id, peer: peer.clone(), name, size, incoming: false, path: Some(path.clone()) });
                    let c = inner.conn(pk).await?;
                    let mut last_pct = u64::MAX;
                    apps::send_file(&c, &path, |sent, total| {
                        let pct = if total == 0 { 100 } else { sent * 100 / total };
                        if pct != last_pct {
                            last_pct = pct;
                            inner.emit(Event::TransferProgress { id, peer: peer.clone(), path: path.clone(), sent, total });
                        }
                    })
                    .await?;
                    Ok::<_, ClientError>(peer)
                }
                .await;
                match res {
                    Ok(peer) => inner.emit(Event::TransferDone { id, peer, path: path.clone() }),
                    Err(e) => inner.emit(Event::TransferFailed { id, peer: target.clone(), path: Some(path.clone()), error: e.to_string() }),
                }
                if let Ok(mut m) = inner.sends.lock() {
                    m.remove(&key);
                }
            }
        });
        if let Ok(mut m) = self.inner.sends.lock() {
            m.entry(key).or_default().push((id, task.abort_handle()));
        }
        id
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
        for (id, h) in handles {
            h.abort();
            self.inner.emit(Event::TransferCancelled { id, peer: target.to_string(), path: path.to_path_buf() });
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

/// The order every UI shows members in: this device first, then by name
/// (case-insensitive), then devices with no name yet, each group by npub
/// for a stable order. Presence never reorders the list.
fn sort_members(members: &mut [Member]) {
    members.sort_by(|a, b| {
        let key = |m: &Member| {
            let name = m.name.as_deref().map(str::trim).filter(|n| !n.is_empty()).map(str::to_lowercase);
            (!m.this_device, name.is_none(), name, m.npub.clone())
        };
        key(a).cmp(&key(b))
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(npub: &str, name: Option<&str>, this_device: bool, online: bool) -> Member {
        Member {
            npub: npub.into(),
            name: name.map(str::to_string),
            admin: true,
            this_device,
            online,
            last_seen_secs: None,
            reachable: false,
            control: false,
            connected: online,
        }
    }

    #[test]
    fn utc_now_is_a_plausible_timestamp() {
        let t = super::utc_now();
        assert_eq!(t.len(), 20, "{t}");
        assert!(t.starts_with("20") && t.ends_with('Z') && &t[10..11] == "T", "{t}");
    }

    #[test]
    fn members_sort_self_first_then_names_then_unnamed() {
        let mut v = vec![
            m("npub1d", None, false, true),
            m("npub1c", Some("vps"), false, false),
            m("npub1b", Some("Motherbox"), false, true),
            m("npub1a", None, false, false),
            m("npub1z", Some("zed"), true, true),
            m("npub1e", Some("alpha"), false, false),
        ];
        sort_members(&mut v);
        let order: Vec<&str> = v.iter().map(|m| m.npub.as_str()).collect();
        assert_eq!(order, ["npub1z", "npub1e", "npub1b", "npub1c", "npub1a", "npub1d"]);
    }
}
