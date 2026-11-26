//! UniFFI bindings over `noscat-client` for mobile apps.
//!
//! The protocol lives in Rust. Kotlin (and later Swift) sees identities,
//! plain commands and an event callback, never MLS, FIPS or Nostr details.
//!
//! A device directory holds one device (`identity.nsec`, mesh state). At
//! most one device runs per directory: the `mesh_*` functions use the
//! app's running [`NoscatClient`] for that directory when there is one,
//! and otherwise run the device just for the call.

use std::sync::Arc;
use std::path::{Path, PathBuf};
use std::time::Duration;

uniffi::setup_scaffolding!();

/// The one FFI error: every fallible call surfaces its message here.
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum NoscatError {
    #[error("{0}")]
    Failed(String),
}

impl NoscatError {
    fn fail<E: ToString>(e: E) -> Self {
        NoscatError::Failed(e.to_string())
    }
}

/// A noscat identity: the npub is the device's address, the secret hex
/// its credential (keep it in the platform keystore).
#[derive(uniffi::Record)]
pub struct Identity {
    pub npub: String,
    pub secret_hex: String,
}

/// Client configuration.
#[derive(uniffi::Record)]
pub struct ClientConfig {
    /// The identity secret (hex or nsec). None = the device dir's
    /// `identity.nsec` (created if missing, sealed under a storage key), or
    /// an ephemeral one without a device dir.
    pub identity_secret: Option<String>,
    /// Relay URLs; None uses the defaults.
    pub relays: Option<Vec<String>>,
    /// The device directory (mesh state). None = no mesh, state in a
    /// temporary directory.
    pub mesh_dir: Option<String>,
    /// Name other members see. None = the hostname.
    pub device_name: Option<String>,
    /// UDP port of the data plane. None = any free port.
    pub listen_port: Option<u16>,
}

/// A member of the mesh, as the device list shows it.
#[derive(uniffi::Record, Clone)]
pub struct MeshMember {
    /// bech32 npub: the target for sends and forwards.
    pub npub: String,
    /// Name from the member's latest advert; None = show a generic label.
    pub name: Option<String>,
    /// Seconds since its last advert; None = not seen since this device
    /// started.
    pub last_seen_secs: Option<u64>,
    /// Its advert is fresh (seen within 10 minutes).
    pub online: bool,
    /// May add and remove members (every noscat device is an admin).
    pub admin: bool,
    /// This device.
    pub this_device: bool,
    /// Reachable from the internet, per its latest advert. Every mesh
    /// needs one such member for devices on different networks to meet.
    pub reachable: bool,
    /// It offers a terminal: show the Terminal action for it.
    pub control: bool,
    /// Data can flow to it right now (a direct link or a live, possibly
    /// relayed, connection). `online` only means its advert arrived.
    pub connected: bool,
}

fn member(m: noscat_client::Member) -> MeshMember {
    MeshMember {
        npub: m.npub,
        name: m.name,
        last_seen_secs: m.last_seen_secs,
        online: m.online,
        admin: m.admin,
        this_device: m.this_device,
        reachable: m.reachable,
        control: m.control,
        connected: m.connected,
    }
}

/// An access group: what an incoming request asks to do.
#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessGroup {
    /// Files, chat, clipboard.
    Send,
    /// Forwards.
    Services,
    /// Terminal.
    Control,
}

impl From<noscat_client::AccessGroup> for AccessGroup {
    fn from(g: noscat_client::AccessGroup) -> Self {
        match g {
            noscat_client::AccessGroup::Send => Self::Send,
            noscat_client::AccessGroup::Services => Self::Services,
            noscat_client::AccessGroup::Control => Self::Control,
        }
    }
}

impl From<AccessGroup> for noscat_client::AccessGroup {
    fn from(g: AccessGroup) -> Self {
        match g {
            AccessGroup::Send => Self::Send,
            AccessGroup::Services => Self::Services,
            AccessGroup::Control => Self::Control,
        }
    }
}

/// A member's rule for one group. `Ask` is for Control only.
#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessRule {
    Allow,
    Deny,
    Ask,
}

impl From<noscat_client::AccessRule> for AccessRule {
    fn from(r: noscat_client::AccessRule) -> Self {
        match r {
            noscat_client::AccessRule::Allow => Self::Allow,
            noscat_client::AccessRule::Deny => Self::Deny,
            noscat_client::AccessRule::Ask => Self::Ask,
        }
    }
}

impl From<AccessRule> for noscat_client::AccessRule {
    fn from(r: AccessRule) -> Self {
        match r {
            AccessRule::Allow => Self::Allow,
            AccessRule::Deny => Self::Deny,
            AccessRule::Ask => Self::Ask,
        }
    }
}

/// The rule per group for one member (or the defaults).
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct AccessRules {
    pub send: AccessRule,
    pub services: AccessRule,
    pub control: AccessRule,
}

impl From<noscat_client::AccessRules> for AccessRules {
    fn from(r: noscat_client::AccessRules) -> Self {
        Self { send: r.send.into(), services: r.services.into(), control: r.control.into() }
    }
}

/// How an access request ended, or that it waits.
#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessOutcome {
    Waiting,
    Allowed,
    Denied,
    TimedOut,
    NoOneToAsk,
}

impl From<noscat_client::AccessOutcome> for AccessOutcome {
    fn from(o: noscat_client::AccessOutcome) -> Self {
        use noscat_client::AccessOutcome as O;
        match o {
            O::Waiting => Self::Waiting,
            O::Allowed => Self::Allowed,
            O::Denied => Self::Denied,
            O::TimedOut => Self::TimedOut,
            O::NoOneToAsk => Self::NoOneToAsk,
        }
    }
}

/// The answer to an asked request.
#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessAnswer {
    Once,
    Always,
    Deny,
}

/// A refused or asked request, for review.
#[derive(uniffi::Record, Clone, Debug)]
pub struct AccessRequest {
    pub id: u64,
    pub peer: String,
    pub group: AccessGroup,
    pub age_secs: u64,
    pub outcome: AccessOutcome,
}

/// A terminal session a member has open on this device.
#[derive(uniffi::Record, Clone, Debug)]
pub struct TerminalSessionInfo {
    pub id: u64,
    pub peer: String,
    pub secs: u64,
}

/// What the client does on its own, delivered to the listener.
#[derive(uniffi::Enum)]
pub enum Event {
    /// Receiving is set up: npub and the data plane's UDP port.
    Listening { npub: String, port: u16 },
    /// A connection with a member is up.
    TunnelUp { peer: String },
    /// It ended; `error` is set when not clean.
    TunnelClosed { peer: String, error: Option<String> },
    /// A transfer began, either direction. `id` names it in every later
    /// transfer event; `path` is the source of a send, None on a receive.
    TransferStarted { id: u64, peer: String, name: String, size: u64, incoming: bool, path: Option<String> },
    /// A transfer finished: on receive the final verified path (it may
    /// differ from the sent name), on send the source.
    TransferDone { id: u64, peer: String, path: String },
    /// A receive ended without a whole file; the `.noscat-part` resumes
    /// when the same file is sent again.
    TransferPartial { id: u64, peer: String, path: String },
    /// Both directions, at most one event per percent.
    TransferProgress { id: u64, peer: String, path: String, sent: u64, total: u64 },
    TransferFailed { id: u64, peer: String, error: String },
    /// A send cancelled by this side; the receiver keeps its partial.
    TransferCancelled { id: u64, peer: String, path: String },
    /// A forward ended (cancelled: error None).
    ForwardStopped { id: u64, error: Option<String> },
    ChatMessage { peer: String, text: String },
    /// A member shared its clipboard.
    Clipboard { peer: String, text: String },
    /// The member acknowledged the chat message or clipboard text.
    ChatDelivered { peer: String },
    ChatFailed { peer: String, error: String },
    /// A background operation stopped.
    Stopped { what: String, error: Option<String> },
    /// This device is in a mesh now (created or joined).
    MeshJoined { name: String },
    /// The member list changed.
    Roster { members: Vec<MeshMember> },
    /// A member's advert arrived (presence, name).
    MemberSeen { peer: String, name: Option<String> },
    /// A membership change of ours lost a race with another member's and
    /// did not happen; it may be retried.
    MeshChangeUndone,
    /// This device is no longer in a mesh.
    MeshLeft,
    /// A device that scanned this device's QR asks to be invited; call
    /// `invite(peer)` to add it.
    JoinRequest { peer: String, name: Option<String> },
    /// A member asks for a group set to ask; answer with
    /// `answerAccess(id, ..)` within 60 s. Only after
    /// `setAccessPrompts(true)`.
    AccessRequest { id: u64, peer: String, group: AccessGroup },
    /// An asked request ended: close its prompt.
    AccessResolved { id: u64, peer: String, group: AccessGroup, outcome: AccessOutcome },
    /// `openTerminal` waits while the member asks its user.
    TerminalWaiting { peer: String },
    /// Host: a member's terminal session started here.
    TerminalOpened { id: u64, peer: String },
    /// Host: a session ended.
    TerminalClosed { id: u64, peer: String, secs: u64, error: Option<String> },
    /// Viewer: output of a terminal this device opened (raw bytes).
    TerminalOutput { session: u64, data: Vec<u8> },
    /// Viewer: that terminal ended; the last event of the session.
    TerminalExited { session: u64, code: Option<i32>, error: Option<String> },
}

/// The FFI form of a client event; `None` for events the apps do not
/// take yet.
fn event(ev: noscat_client::Event) -> Option<Event> {
    use noscat_client::Event as E;
    Some(match ev {
        E::Listening { npub, addr } => Event::Listening { npub, port: addr.port() },
        E::TunnelUp { peer } => Event::TunnelUp { peer },
        E::TunnelClosed { peer, error } => Event::TunnelClosed { peer, error },
        E::TransferStarted { id, peer, name, size, incoming, path } => Event::TransferStarted {
            id,
            peer,
            name,
            size,
            incoming,
            path: path.map(|p| p.display().to_string()),
        },
        E::TransferDone { id, peer, path } => Event::TransferDone { id, peer, path: path.display().to_string() },
        E::TransferPartial { id, peer, path } => Event::TransferPartial { id, peer, path: path.display().to_string() },
        E::TransferProgress { id, peer, path, sent, total } => {
            Event::TransferProgress { id, peer, path: path.display().to_string(), sent, total }
        }
        E::TransferFailed { id, peer, error, .. } => Event::TransferFailed { id, peer, error },
        E::TransferCancelled { id, peer, path } => Event::TransferCancelled { id, peer, path: path.display().to_string() },
        E::ForwardStopped { id, error } => Event::ForwardStopped { id, error },
        E::ChatMessage { peer, text } => Event::ChatMessage { peer, text },
        E::Clipboard { peer, text } => Event::Clipboard { peer, text },
        E::ChatDelivered { peer } => Event::ChatDelivered { peer },
        E::ChatFailed { peer, error } => Event::ChatFailed { peer, error },
        E::Stopped { what, error } => Event::Stopped { what: what.to_string(), error },
        E::MeshJoined { name } => Event::MeshJoined { name },
        E::Roster { members } => Event::Roster { members: members.into_iter().map(member).collect() },
        E::MemberSeen { peer, name } => Event::MemberSeen { peer, name },
        E::MeshChangeUndone => Event::MeshChangeUndone,
        E::MeshLeft => Event::MeshLeft,
        E::JoinRequest { peer, name } => Event::JoinRequest { peer, name },
        E::AccessRequest { id, peer, group } => Event::AccessRequest { id, peer, group: group.into() },
        E::AccessResolved { id, peer, group, outcome } => {
            Event::AccessResolved { id, peer, group: group.into(), outcome: outcome.into() }
        }
        E::TerminalWaiting { peer } => Event::TerminalWaiting { peer },
        E::TerminalOpened { id, peer } => Event::TerminalOpened { id, peer },
        E::TerminalClosed { id, peer, secs, error } => Event::TerminalClosed { id, peer, secs, error },
        E::TerminalOutput { session, data } => Event::TerminalOutput { session, data },
        E::TerminalExited { session, code, error } => Event::TerminalExited { session, code, error },
    })
}

/// The event sink the app registers; called from a background thread.
#[uniffi::export(callback_interface)]
pub trait EventListener: Send + Sync {
    fn on_event(&self, event: Event);
}

/// Generate a fresh identity.
#[uniffi::export]
pub fn generate_identity() -> Identity {
    let id = noscat_core::Identity::generate();
    Identity { npub: id.npub(), secret_hex: id.secret_hex() }
}

/// Restore an identity from its secret (hex or nsec).
#[uniffi::export]
pub fn identity_from_secret(secret: String) -> Result<Identity, NoscatError> {
    let id = noscat_core::Identity::from_secret(&secret).map_err(NoscatError::fail)?;
    Ok(Identity { npub: id.npub(), secret_hex: id.secret_hex() })
}

/// A running forward.
#[derive(uniffi::Record)]
pub struct ForwardInfo {
    /// The id from `forward()`; the key for `cancelForward`.
    pub id: u64,
    /// The member every connection goes to.
    pub target: String,
    /// The local TCP listen address (e.g. "127.0.0.1:8080").
    pub local: String,
}

// ---- device directory functions ---------------------------------------------

/// Seal this device's secret files (identity, mesh state) with a 32-byte
/// key from now on; existing plain files migrate on their next write. Call
/// once at app start, before anything else. Keep the key in the Android
/// Write noscat's logs at `filter` (a RUST_LOG filter, e.g.
/// `noscat_core=debug`) to the file at `path`, appending, for diagnosing a
/// start or a connection; phones have no stderr. The first call wins; the
/// later ones do nothing. Call before the client starts to see its start.
#[uniffi::export]
pub fn start_debug_log(path: String, filter: String) -> Result<(), NoscatError> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| NoscatError::Failed(format!("{path}: {e}")))?;
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .with_ansi(false)
        .with_writer(std::sync::Mutex::new(file))
        .try_init();
    Ok(())
}

/// Keystore (wrapped); losing it makes the device unreadable, and only
/// Forget mesh recovers. None: plain files.
#[uniffi::export]
pub fn set_storage_key(key: Option<Vec<u8>>) -> Result<(), NoscatError> {
    let key = match key {
        None => None,
        Some(k) => Some(
            <[u8; 32]>::try_from(k.as_slice())
                .map_err(|_| NoscatError::Failed(format!("storage key must be 32 bytes, got {}", k.len())))?,
        ),
    };
    noscat_client::set_storage_key(key);
    Ok(())
}

fn identity_file(dir: &Path) -> PathBuf {
    dir.join("identity.nsec")
}

/// Run `f` on the device of `dir`: the running client, or one started for
/// this call (identity `<dir>/identity.nsec`, created if missing).
fn with_device<T>(
    dir: &str,
    relays: Option<Vec<String>>,
    f: impl FnOnce(&noscat_client::Client) -> Result<T, NoscatError>,
) -> Result<T, NoscatError> {
    with_device_joining(dir, relays, Vec::new(), f)
}

/// As [`with_device`], a device started here using only `join_relays`
/// (a pairing code's) until its join ends.
fn with_device_joining<T>(
    dir: &str,
    relays: Option<Vec<String>>,
    join_relays: Vec<String>,
    f: impl FnOnce(&noscat_client::Client) -> Result<T, NoscatError>,
) -> Result<T, NoscatError> {
    let dir = PathBuf::from(dir);
    if let Some(c) = noscat_client::Client::running(&dir) {
        return f(&c);
    }
    let c = noscat_client::Client::start(noscat_client::ClientConfig {
        identity: noscat_client::IdentitySource::File(identity_file(&dir)),
        relays,
        join_relays,
        mesh_dir: Some(dir),
        ..noscat_client::ClientConfig::default()
    })
    .map_err(NoscatError::fail)?;
    f(&c)
}

fn members_of(c: &noscat_client::Client) -> Vec<MeshMember> {
    c.members().into_iter().map(member).collect()
}

/// The members of the device directory's mesh, with names and presence.
/// Presence is only known while the app's client runs for `dir`.
#[uniffi::export]
pub fn mesh_members(dir: String, relays: Option<Vec<String>>) -> Result<Vec<MeshMember>, NoscatError> {
    with_device(&dir, relays, |c| Ok(members_of(c)))
}

/// This device directory's npub (creating its identity if needed): the
/// address the inviting device adds. `owner_npub` is unused and kept for
/// call compatibility; `mesh_join` names the inviter.
#[uniffi::export]
pub fn mesh_prepare(dir: String, owner_npub: Option<String>, relays: Option<Vec<String>>) -> Result<String, NoscatError> {
    let _ = (owner_npub, relays);
    std::fs::create_dir_all(&dir).map_err(NoscatError::fail)?;
    if let Some(c) = noscat_client::Client::running(Path::new(&dir)) {
        return Ok(c.npub().to_string());
    }
    noscat_client::identity_npub(&noscat_client::IdentitySource::File(identity_file(Path::new(&dir))))
        .map_err(NoscatError::fail)
}

/// Wait up to `timeout_secs` for an invitation from `owner_npub` (a bare
/// npub or the `noscat:` URI a QR scan gives) and join. The inviting
/// device is asked to invite this one (`JoinRequest` there). Invitations
/// from anyone else are ignored. Returns the members.
#[uniffi::export]
pub fn mesh_join(
    dir: String,
    timeout_secs: u64,
    owner_npub: String,
    relays: Option<Vec<String>>,
) -> Result<Vec<MeshMember>, NoscatError> {
    // A code naming a private mesh's relays: the device started for the
    // join uses only those, so its key package never reaches the public
    // relays.
    let join_relays = noscat_client::parse_pairing_relays(&owner_npub);
    with_device_joining(&dir, relays, join_relays, |c| {
        c.join(&owner_npub, Duration::from_secs(timeout_secs)).map_err(|e| match e {
            noscat_client::ClientError::Mesh(m) if m.contains("timed out") => {
                NoscatError::Failed("no invitation arrived in time".into())
            }
            e => NoscatError::fail(e),
        })?;
        Ok(members_of(c))
    })
}

/// The members after catching up. A running client is always caught up;
/// otherwise the device runs for `wait_secs` first.
#[uniffi::export]
pub fn mesh_sync(dir: String, wait_secs: u64, relays: Option<Vec<String>>) -> Result<Vec<MeshMember>, NoscatError> {
    if let Some(c) = noscat_client::Client::running(Path::new(&dir)) {
        return Ok(members_of(&c));
    }
    with_device(&dir, relays, |c| {
        std::thread::sleep(Duration::from_secs(wait_secs));
        Ok(members_of(c))
    })
}

/// Start a new mesh with this device as its only member.
#[uniffi::export]
pub fn mesh_create(dir: String, name: String, relays: Option<Vec<String>>) -> Result<(), NoscatError> {
    with_device(&dir, relays, |c| c.create_mesh(&name).map_err(NoscatError::fail))
}

/// Add a device (npub or `noscat:` URI); it must be running or joining.
#[uniffi::export]
pub fn mesh_invite(dir: String, npub: String, relays: Option<Vec<String>>) -> Result<(), NoscatError> {
    with_device(&dir, relays, |c| c.invite(&npub).map_err(NoscatError::fail))
}

/// Remove a member.
#[uniffi::export]
pub fn mesh_remove(dir: String, npub: String, relays: Option<Vec<String>>) -> Result<(), NoscatError> {
    with_device(&dir, relays, |c| c.remove(&npub).map_err(NoscatError::fail))
}

/// Leave the mesh, waiting up to `timeout_secs` for a member to complete it.
#[uniffi::export]
pub fn mesh_leave(dir: String, timeout_secs: u64, relays: Option<Vec<String>>) -> Result<(), NoscatError> {
    with_device(&dir, relays, |c| c.leave(Duration::from_secs(timeout_secs)).map_err(NoscatError::fail))
}

// ---- the running client -------------------------------------------------------

/// A running device. Dropping the last reference stops it.
#[derive(uniffi::Object)]
pub struct NoscatClient {
    client: noscat_client::Client,
}

#[uniffi::export]
impl NoscatClient {
    /// Start the device. Blocks for a few seconds (relays); never call it
    /// on the main thread. `listener` gets every event from a background
    /// thread.
    #[uniffi::constructor]
    pub fn new(config: ClientConfig, listener: Box<dyn EventListener>) -> Result<Self, NoscatError> {
        let mut client = noscat_client::Client::start(noscat_client::ClientConfig {
            // No secret with a device dir: the dir's own identity.nsec
            // (sealed when a storage key is set), never read by the app.
            identity: match (&config.identity_secret, &config.mesh_dir) {
                (Some(s), _) => noscat_client::IdentitySource::Secret(s.trim().to_string()),
                (None, Some(dir)) => noscat_client::IdentitySource::File(identity_file(Path::new(dir))),
                (None, None) => noscat_client::IdentitySource::Ephemeral,
            },
            relays: config.relays.clone(),
            listen: config.listen_port.map(|p| std::net::SocketAddr::from(([0, 0, 0, 0], p))),
            mesh_dir: config.mesh_dir.as_ref().map(PathBuf::from),
            device_name: config.device_name,
            ..noscat_client::ClientConfig::default()
        })
        .map_err(NoscatError::fail)?;
        let rx = client.events().ok_or_else(|| NoscatError::Failed("event receiver already taken".into()))?;
        std::thread::spawn(move || {
            for ev in rx {
                let Some(ev) = event(ev) else { continue };
                // A throwing callback must not end event delivery.
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| listener.on_event(ev)));
            }
        });
        Ok(Self { client })
    }

    /// This device's npub.
    pub fn npub(&self) -> String {
        self.client.npub().to_string()
    }

    /// The mesh name, if in a mesh.
    pub fn mesh_name(&self) -> Option<String> {
        self.client.mesh_name()
    }

    /// What this device's pairing QR shows: `noscat:<npub>`, plus
    /// `?relay=` for each of a private mesh's relays, so a device that
    /// scans it joins through them. Blocking (reads the mesh state): call
    /// it off the main thread and cache it.
    pub fn pairing_uri(&self) -> String {
        self.client.pairing_uri()
    }

    /// This device's name, as members see it.
    pub fn device_name(&self) -> String {
        self.client.device_name()
    }

    /// Rename this device; members see it within seconds. Blocking (it
    /// publishes an advert). Persist the name yourself and pass it as the
    /// config's name on the next start.
    pub fn set_device_name(&self, name: String) {
        self.client.set_device_name(&name);
    }

    /// The members with names and presence.
    pub fn members(&self) -> Vec<MeshMember> {
        members_of(&self.client)
    }

    /// Add a device (npub or `noscat:` URI), e.g. after a `JoinRequest`.
    pub fn invite(&self, npub: String) -> Result<(), NoscatError> {
        self.client.invite(&npub).map_err(NoscatError::fail)
    }

    /// Remove a member.
    pub fn remove(&self, npub: String) -> Result<(), NoscatError> {
        self.client.remove(&npub).map_err(NoscatError::fail)
    }

    /// Re-check network paths after a network change (Wi-Fi to mobile).
    pub fn network_changed(&self) {
        self.client.network_changed();
    }

    /// Listen on 127.0.0.1:local_port; each connection goes to the
    /// member's default service. Returns the forward id.
    pub fn forward(&self, target_npub: String, local_port: u16) -> Result<u64, NoscatError> {
        Ok(self.client.forward(&target_npub, std::net::SocketAddr::from(([127, 0, 0, 1], local_port))))
    }

    /// The running forwards.
    pub fn list_forwards(&self) -> Vec<ForwardInfo> {
        self.client
            .list_forwards()
            .into_iter()
            .map(|f| ForwardInfo { id: f.id, target: f.target, local: f.local.to_string() })
            .collect()
    }

    /// Stop a forward; `ForwardStopped` confirms it. False if no such forward.
    pub fn cancel_forward(&self, id: u64) -> bool {
        self.client.cancel_forward(id)
    }

    /// Make the TCP service host:port this device's default service for
    /// members. Returns the data plane's UDP port.
    pub fn expose(&self, to_host: String, to_port: u16) -> Result<u16, NoscatError> {
        let to: std::net::SocketAddr = format!("{to_host}:{to_port}").parse().map_err(NoscatError::fail)?;
        self.client.expose(to).map(|a| a.port()).map_err(NoscatError::fail)
    }

    /// Let members forward to 127.0.0.1:port here by number.
    pub fn serve_port(&self, port: u16, enabled: bool) {
        self.client.serve_port(port, enabled);
    }

    /// Send a file; the outcome arrives as events. Resumes a partial the
    /// member kept.
    /// Send a file; returns the transfer id the events carry.
    pub fn send_file(&self, path: String, target_npub: String) -> u64 {
        self.client.send_file(PathBuf::from(path), &target_npub)
    }

    /// Cancel a send (same path and member it started with).
    pub fn cancel_transfer(&self, path: String, target_npub: String) -> bool {
        self.client.cancel_transfer(&target_npub, Path::new(&path))
    }

    /// Accept files from members into out_dir.
    pub fn receive_file(&self, out_dir: String) {
        self.client.receive_file(PathBuf::from(out_dir));
    }

    /// Send a chat message; delivery arrives as ChatDelivered or ChatFailed.
    pub fn send_chat(&self, target_npub: String, text: String) {
        self.client.send_chat(&target_npub, &text);
    }

    /// Share text for the member's clipboard; same delivery events as chat.
    pub fn send_clipboard(&self, target_npub: String, text: String) {
        self.client.send_clipboard(&target_npub, &text);
    }

    /// The mesh's STUN servers (`ip:port`); empty when it lists none.
    /// Blocking.
    pub fn mesh_stun(&self) -> Vec<String> {
        self.client.mesh_stun()
    }

    /// Replace the mesh's STUN servers (`ip:port`, no hostnames, at most
    /// 8; empty removes them). Members use the new list from their next
    /// start. Blocking.
    pub fn set_mesh_stun(&self, servers: Vec<String>) -> Result<(), NoscatError> {
        self.client.set_mesh_stun(&servers).map_err(NoscatError::fail)
    }

    /// The rules for members without their own.
    pub fn access_defaults(&self) -> AccessRules {
        self.client.access_defaults().into()
    }

    /// The rules that apply to a member.
    pub fn access_of(&self, npub: String) -> Result<AccessRules, NoscatError> {
        self.client.access_of(&npub).map(Into::into).map_err(NoscatError::fail)
    }

    /// Members with rules of their own (npubs).
    pub fn access_custom(&self) -> Vec<String> {
        self.client.access_devices().into_iter().map(|(n, _)| n).collect()
    }

    /// Set a member's rule (None npub: the default; None rule: back to the
    /// default). Saved at once.
    pub fn set_access(&self, npub: Option<String>, group: AccessGroup, rule: Option<AccessRule>) -> Result<(), NoscatError> {
        self.client.set_access(npub.as_deref(), group.into(), rule.map(Into::into)).map_err(NoscatError::fail)
    }

    /// Drop a member's own rules.
    pub fn reset_access(&self, npub: String) -> Result<(), NoscatError> {
        self.client.reset_access(&npub).map_err(NoscatError::fail)
    }

    /// An app is here to answer access prompts.
    pub fn set_access_prompts(&self, on: bool) {
        self.client.set_access_prompts(on);
    }

    /// Answer an AccessRequest event.
    pub fn answer_access(&self, id: u64, answer: AccessAnswer) -> Result<(), NoscatError> {
        let answer = match answer {
            AccessAnswer::Once => noscat_client::AccessAnswer::Once,
            AccessAnswer::Always => noscat_client::AccessAnswer::Always,
            AccessAnswer::Deny => noscat_client::AccessAnswer::Deny,
        };
        self.client.answer_access(id, answer).map_err(NoscatError::fail)
    }

    /// Waiting, then recent refused or asked requests, newest first.
    pub fn access_requests(&self) -> Vec<AccessRequest> {
        self.client
            .access_requests()
            .into_iter()
            .map(|r| AccessRequest { id: r.id, peer: r.peer, group: r.group.into(), age_secs: r.age_secs, outcome: r.outcome.into() })
            .collect()
    }

    /// Terminal sessions members have open on this device.
    pub fn terminal_sessions(&self) -> Vec<TerminalSessionInfo> {
        self.client
            .terminal_sessions()
            .into_iter()
            .map(|t| TerminalSessionInfo { id: t.id, peer: t.peer, secs: t.secs })
            .collect()
    }

    /// End a session open on this device.
    pub fn end_terminal(&self, id: u64) -> bool {
        self.client.end_terminal(id)
    }

    /// Open a terminal on a member. Blocks until its shell started (a
    /// TerminalWaiting event fires while the member asks its user; up to a
    /// minute); never on the main thread. Output and the end arrive as
    /// TerminalOutput and TerminalExited events with the handle's id.
    pub fn open_terminal(&self, target_npub: String, cols: u16, rows: u16) -> Result<Arc<Terminal>, NoscatError> {
        let h = self.client.start_terminal(&target_npub, cols, rows, "xterm-256color").map_err(NoscatError::fail)?;
        Ok(Arc::new(Terminal { handle: h }))
    }

    /// Receive files into out_dir and bridge members' default-service
    /// streams to 127.0.0.1:bridge_port when given. Returns the data
    /// plane's UDP port.
    pub fn up(&self, out_dir: String, bridge_port: Option<u16>) -> Result<u16, NoscatError> {
        let bridge_to = bridge_port.map(|p| std::net::SocketAddr::from(([127, 0, 0, 1], p)));
        self.client.up(PathBuf::from(out_dir), bridge_to).map(|a| a.port()).map_err(NoscatError::fail)
    }
}

/// A terminal this device opened on a member.
#[derive(uniffi::Object)]
pub struct Terminal {
    handle: noscat_client::TerminalHandle,
}

#[uniffi::export]
impl Terminal {
    /// The id its events carry.
    pub fn id(&self) -> u64 {
        self.handle.id()
    }

    /// Keystrokes or a paste, as raw terminal bytes.
    pub fn write(&self, data: Vec<u8>) {
        self.handle.write(&data);
    }

    /// The view changed size.
    pub fn resize(&self, cols: u16, rows: u16) {
        self.handle.resize(cols, rows);
    }

    /// End the session. (Not `close`: that releases the Kotlin object,
    /// which ends the session too.)
    pub fn end(&self) {
        self.handle.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_round_trip() {
        let fresh = generate_identity();
        let restored = identity_from_secret(fresh.secret_hex.clone()).unwrap();
        assert_eq!(fresh.npub, restored.npub);
        assert!(restored.npub.starts_with("npub1"));
    }

    #[test]
    fn bad_secret_is_an_error() {
        assert!(identity_from_secret("not-a-key".into()).is_err());
    }

    #[test]
    fn prepare_creates_a_stable_identity() {
        let dir = std::env::temp_dir().join(format!("noscat-ffi-{}", std::process::id()));
        let a = mesh_prepare(dir.display().to_string(), None, None).unwrap();
        let b = mesh_prepare(dir.display().to_string(), None, None).unwrap();
        assert_eq!(a, b);
        assert!(a.starts_with("npub1"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
