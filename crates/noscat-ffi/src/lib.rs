//! UniFFI bindings over the noscat client stack for mobile apps.
//!
//! The rule this crate enforces: the protocol lives in Rust. Kotlin (and,
//! later, Swift via the same scaffolding) sees identities, plain commands
//! (dial, forward, expose, send, receive, up), and an event callback - never
//! Noise, UDP, or Nostr details. The Rust side is the `noscat-core` /
//! `noscat-client` crates, wrapped here with FFI-safe types only (records,
//! enums, callback interfaces).

use std::sync::Arc;

uniffi::setup_scaffolding!();

/// The one FFI error: every exported fallible call surfaces its message
/// through `Failed` (uniFFI needs a real error enum, not bare strings).
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

/// A noscat identity: the npub is the public mesh address, the secret hex is
/// the credential (store it in the platform keystore, never in plain files if
/// avoidable).
#[derive(uniffi::Record)]
pub struct Identity {
    pub npub: String,
    pub secret_hex: String,
}

/// Client configuration. `relays` defaults to the core's public relay set.
#[derive(uniffi::Record)]
pub struct ClientConfig {
    /// The identity secret (hex or nsec). None = generate an ephemeral one.
    pub identity_secret: Option<String>,
    /// Relay URLs; None uses the defaults.
    pub relays: Option<Vec<String>>,
    /// The mesh device directory to scope tunnels to, if any.
    pub mesh_dir: Option<String>,
    /// Friendly device name shown to peers (published in the advert).
    /// None = no name (UIs fall back to generic labels).
    pub device_name: Option<String>,
    /// The UDP port to listen on for inbound tunnels. None = 41641.
    pub listen_port: Option<u16>,
}

/// What the client does on its own, delivered to the registered listener.
#[derive(uniffi::Enum)]
pub enum Event {
    /// The serve side is up (advert published): npub + local UDP port.
    Listening { npub: String, port: u16 },
    /// A tunnel is ready for traffic: peer npub (or noise key fallback).
    TunnelUp { peer: String },
    /// A tunnel ended; error is set when it was not a clean close.
    TunnelClosed { peer: String, error: Option<String> },
    /// A file transfer finished: the final verified path.
    TransferDone { peer: String, path: String },
    /// A receive ended WITHOUT a verified whole file: the kept
    /// `.noscat-part` path is a resume seed only, not a usable file.
    TransferPartial { peer: String, path: String },
    /// A file transfer is under way (sends only, one event per percent).
    TransferProgress {
        peer: String,
        path: String,
        sent: u64,
        total: u64,
    },
    /// A file transfer failed.
    TransferFailed { peer: String, error: String },
    /// A file transfer was cancelled by this side (cancelTransfer): the
    /// receiver keeps its resumable partial.
    TransferCancelled { peer: String, path: String },
    /// A forward ended: cancelled (error None) or failed (error set).
    /// The id lets the UI drop it from its forward list.
    ForwardStopped { id: u64, error: Option<String> },
    /// A one-shot chat message arrived over the node dispatcher.
    ChatMessage { peer: String, text: String },
    /// A peer shared their clipboard: put `text` on the system clipboard.
    Clipboard { peer: String, text: String },
    /// A chat message or clipboard share was delivered: the peer echoed
    /// the tunnel's FIN. The "delivered" tick.
    ChatDelivered { peer: String },
    /// Sending a chat message failed.
    ChatFailed { peer: String, error: String },
    /// A background operation stopped (the listener, a forward, ...).
    Stopped { what: String, error: Option<String> },
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
    Identity {
        npub: id.npub(),
        secret_hex: id.secret_hex(),
    }
}

/// Restore an identity from its secret (hex or nsec).
#[uniffi::export]
pub fn identity_from_secret(secret: String) -> Result<Identity, NoscatError> {
    let id = noscat_core::Identity::from_secret(&secret).map_err(NoscatError::fail)?;
    Ok(Identity {
        npub: id.npub(),
        secret_hex: id.secret_hex(),
    })
}

/// A forward the device is running: one local TCP listener whose
/// connections each dial a tunnel to the target.
#[derive(uniffi::Record)]
pub struct ForwardInfo {
    /// The id from `forward()`; the key for `cancelForward`.
    pub id: u64,
    /// The npub every connection dials.
    pub target: String,
    /// The local TCP address the listener is on (e.g. "127.0.0.1:8080").
    pub local: String,
}

/// A member device of a mesh group: how the UI's device list shows it.
#[derive(uniffi::Record)]
pub struct MeshMember {
    /// The device's npub (bech32), the dial target for tunnels.
    pub npub: String,
    /// True for the device that owns (created) the mesh.
    pub is_owner: bool,
    /// The device's friendly name from its advert, when it is serving and
    /// published one. None = show a generic label.
    pub name: Option<String>,
    /// Seconds since the device's advert was last seen (published or
    /// received), when one is known. Online = within the advert TTL;
    /// None = no advert on the relays, treat as offline.
    pub last_seen_secs: Option<u64>,
}

/// One shared runtime for the standalone mesh helpers: each would
/// otherwise open a full multi-thread runtime per call (thread-pool
/// spin-up per roster view on a phone).
fn mesh_runtime() -> Result<&'static tokio::runtime::Runtime, NoscatError> {
    static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    let rt = RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime cannot fail to build")
    });
    Ok(rt)
}

/// List the member devices of a mesh device directory, with each
/// member's friendly name resolved from its current advert (concurrently;
/// members that are offline simply come back unnamed). The directory is
/// an enrolled mesh device (identity.nsec + MLS state), imported onto the
/// device; membership is what authorizes mesh-scoped tunnels.
#[uniffi::export]
pub fn mesh_members(dir: String, relays: Option<Vec<String>>) -> Result<Vec<MeshMember>, NoscatError> {
    let rt = mesh_runtime()?;
    let device = noscat_core::mesh::Device::open(std::path::Path::new(&dir))
        .map_err(NoscatError::fail)?;
    let relays = relays.unwrap_or_else(noscat_core::relay::default_relays);
    rt.block_on(async move {
        let members = members_of(device)?;
        let relays = &relays;
        let now = nostr::prelude::Timestamp::now().as_secs();
        let infos = members.iter().map(|m| async move {
            let Ok(pk) = nostr::prelude::PublicKey::parse(&m.npub) else {
                return None;
            };
            noscat_core::relay::fetch_advert_for(relays, None, Some(pk))
                .await
                .ok()
                .flatten()
                .map(|a| (a.name, now.saturating_sub(a.created_at)))
        });
        let infos = futures_util::future::join_all(infos).await;
        Ok(members
            .into_iter()
            .zip(infos)
            .map(|(m, info)| {
                let (name, last_seen_secs) = info
                    .map(|(n, s)| (n, Some(s)))
                    .unwrap_or((None, None));
                MeshMember { name, last_seen_secs, ..m }
            })
            .collect())
    })
}

/// Prepare to join a mesh over the relays: open (creating if needed) this
/// device's mesh device directory and publish its MLS key package. With
/// `owner_npub`, the request is addressed to that owner alone (the one whose
/// QR the user scanned); the returned npub is this device's address.
#[uniffi::export]
pub fn mesh_prepare(
    dir: String,
    owner_npub: Option<String>,
    relays: Option<Vec<String>>,
) -> Result<String, NoscatError> {
    let rt = mesh_runtime()?;
    let device = noscat_core::mesh::Device::open(std::path::Path::new(&dir))
        .map_err(NoscatError::fail)?;
    let relays = relays.unwrap_or_else(noscat_core::relay::default_relays);
    let target = match owner_npub {
        Some(npub) => Some(
            nostr::prelude::PublicKey::parse(&npub)
                .map_err(NoscatError::fail)?,
        ),
        None => None,
    };
    rt.block_on(device.publish_key_package(&relays, target))
        .map_err(NoscatError::fail)?;
    Ok(device.identity.npub())
}

/// Join the mesh: wait up to `timeout_secs` for the owner's gift-wrapped
/// invitation on the relays and process it. `owner_npub` is the mesh
/// owner's npub (from the QR the phone scanned): invitations from anyone
/// else, or a mesh owned by anyone else, are refused. Returns the member
/// list on success; a timeout error means the owner has not invited this
/// npub yet.
#[uniffi::export]
pub fn mesh_join(
    dir: String,
    timeout_secs: u64,
    owner_npub: String,
    relays: Option<Vec<String>>,
) -> Result<Vec<MeshMember>, NoscatError> {
    let rt = mesh_runtime()?;
    let mut device = noscat_core::mesh::Device::open(std::path::Path::new(&dir))
        .map_err(NoscatError::fail)?;
    let relays = relays.unwrap_or_else(noscat_core::relay::default_relays);
    // Accept a bare npub or the full noscat: URI a QR scan hands over.
    let expected = noscat_core::parse_pairing_target(&owner_npub).map_err(NoscatError::fail)?;
    rt.block_on(async move {
        tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs),
            device.join_mesh(&relays, expected),
        )
        .await
        .map_err(|_| NoscatError::Failed("no invitation arrived in time".into()))?
        .map_err(NoscatError::fail)?;
        members_of(device)
    })
}

/// Keep the membership current: merge the owner's epoch commits (invites,
/// removals) that arrive while we listen, then return the member list.
#[uniffi::export]
pub fn mesh_sync(
    dir: String,
    wait_secs: u64,
    relays: Option<Vec<String>>,
) -> Result<Vec<MeshMember>, NoscatError> {
    let rt = mesh_runtime()?;
    let mut device = noscat_core::mesh::Device::open(std::path::Path::new(&dir))
        .map_err(NoscatError::fail)?;
    let relays = relays.unwrap_or_else(noscat_core::relay::default_relays);
    rt.block_on(async move {
        device
            .sync_mesh(&relays, std::time::Duration::from_secs(wait_secs))
            .await
            .map_err(NoscatError::fail)?;
        members_of(device)
    })
}

/// Re-publish the mesh owner's recorded commit chain (see `mesh_sync`)
/// so a member stranded at a stale epoch can catch up. `to_npub` limits
/// the resend to one member; `None` resends to every member. Run this on
/// the OWNER's device: only the owner commits, so only the owner has the
/// journal. Up-to-date members skip the replays by epoch.
/// Returns how many gift wraps were sent.
#[uniffi::export]
pub fn mesh_resend(
    dir: String,
    to_npub: Option<String>,
    relays: Option<Vec<String>>,
) -> Result<u32, NoscatError> {
    let rt = mesh_runtime()?;
    let mut device = noscat_core::mesh::Device::open(std::path::Path::new(&dir))
        .map_err(NoscatError::fail)?;
    let relays = relays.unwrap_or_else(noscat_core::relay::default_relays);
    let target = match &to_npub {
        Some(npub) => Some(
            nostr::prelude::PublicKey::parse(npub).map_err(NoscatError::fail)?,
        ),
        None => None,
    };
    let sent = rt
        .block_on(device.resend_commits(target, &relays))
        .map_err(NoscatError::fail)?;
    Ok(sent as u32)
}

fn members_of(device: noscat_core::mesh::Device) -> Result<Vec<MeshMember>, NoscatError> {
    use nostr::nips::nip19::ToBech32;
    let mut out = Vec::new();
    for m in device.list_members().map_err(NoscatError::fail)? {
        let npub = nostr::prelude::PublicKey::from_hex(&m.npub)
            .map_err(NoscatError::fail)?
            .to_bech32()
            .map_err(NoscatError::fail)?;
        out.push(MeshMember {
            npub,
            is_owner: m.is_owner,
            name: None,
            last_seen_secs: None,
        });
    }
    Ok(out)
}

/// A running noscat client. Dropping the last reference stops the runtime
/// and every background operation it owns.
#[derive(uniffi::Object)]
pub struct NoscatClient {
    inner: Arc<ClientInner>,
}

struct ClientInner {
    // noscat_client::Client is Send but not Sync (it carries a std mpsc
    // receiver), and uniffi objects must be Sync: pin it behind a mutex.
    // Every method on it is blocking anyway, so the lock never awaits.
    client: std::sync::Mutex<noscat_client::Client>,
}

#[uniffi::export]
impl NoscatClient {
    /// Start the client: resolve the identity and config, spin the runtime.
    /// `listener` receives every subsequent event from a background thread.
    #[uniffi::constructor]
    pub fn new(config: ClientConfig, listener: Box<dyn EventListener>) -> Result<Self, NoscatError> {
        let mut client = noscat_client::Client::start(noscat_client::ClientConfig {
            identity: match &config.identity_secret {
                Some(s) => noscat_client::IdentitySource::Secret(s.trim().to_string()),
                None => noscat_client::IdentitySource::Ephemeral,
            },
            relays: config.relays.clone(),
            listen: Some(
                std::net::SocketAddr::from((
                    [0, 0, 0, 0],
                    config
                        .listen_port
                        .unwrap_or(noscat_core::relay::DEFAULT_LISTEN_PORT),
                )),
            ),
            mesh_dir: config.mesh_dir.as_ref().map(std::path::PathBuf::from),
            device_name: config.device_name,
            advert_ttl_secs: noscat_core::advert::ADVERT_TTL_SECS,
            max_incoming_bytes: None,
        })
        .map_err(NoscatError::fail)?;

        // Pump client events into the app's callback. The channel dies with
        // the client; the thread ends with it.
        let rx = client
            .events()
            .ok_or_else(|| NoscatError::Failed("event receiver already taken".into()))?;
        let pump = std::thread::spawn(move || {
            for ev in rx {
                let event = match ev {
                    noscat_client::Event::Listening { npub, addr } => Event::Listening {
                        npub,
                        port: addr.port(),
                    },
                    noscat_client::Event::TunnelUp { peer, .. } => Event::TunnelUp { peer },
                    noscat_client::Event::TunnelClosed { peer, error } => {
                        Event::TunnelClosed { peer, error }
                    }
                    noscat_client::Event::TransferDone { peer, path } => {
                        Event::TransferDone { peer, path: path.display().to_string() }
                    }
                    noscat_client::Event::TransferPartial { peer, path } => {
                        Event::TransferPartial { peer, path: path.display().to_string() }
                    }
                    noscat_client::Event::TransferProgress { peer, path, sent, total } => {
                        Event::TransferProgress {
                            peer,
                            path: path.display().to_string(),
                            sent,
                            total,
                        }
                    }
                    noscat_client::Event::TransferFailed { peer, error, .. } => {
                        Event::TransferFailed { peer, error }
                    }
                    noscat_client::Event::TransferCancelled { peer, path } => {
                        Event::TransferCancelled { peer, path: path.display().to_string() }
                    }
                    noscat_client::Event::ForwardStopped { id, error } => {
                        Event::ForwardStopped { id, error }
                    }
                    noscat_client::Event::ChatMessage { peer, text } => {
                        Event::ChatMessage { peer, text }
                    }
                    noscat_client::Event::Clipboard { peer, text } => {
                        Event::Clipboard { peer, text }
                    }
                    noscat_client::Event::ChatFailed { peer, error } => {
                        Event::ChatFailed { peer, error }
                    }
                    noscat_client::Event::ChatDelivered { peer } => {
                        Event::ChatDelivered { peer }
                    }
                    noscat_client::Event::Stopped { what, error } => {
                        Event::Stopped { what: what.to_string(), error }
                    }
                    // Phase 1 does not surface raw streams: listeners are
                    // consumed internally by expose/listen/up operations.
                    noscat_client::Event::Incoming { .. } => continue,
                };
                // A throwing app callback must not kill event delivery
                // permanently (the client keeps running; the UI would go
                // deaf): unwind at the loop, keep pumping.
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    listener.on_event(event);
                }));
            }
        });
        std::mem::forget(pump); // detach: runs until the channel closes

        Ok(Self {
            inner: Arc::new(ClientInner {
                client: std::sync::Mutex::new(client),
            }),
        })
    }

    /// This device's npub (the mesh address to share with peers).
    pub fn npub(&self) -> String {
        self.lock().npub().to_string()
    }

    /// Forward a local port over a tunnel to a peer running `expose`:
    /// localhost:port on this device becomes the peer's service. Returns
    /// immediately; progress arrives as events.
    pub fn forward(&self, target_npub: String, local_port: u16) -> Result<u64, NoscatError> {
        Ok(self.lock().forward(
            &target_npub,
            std::net::SocketAddr::from(([127, 0, 0, 1], local_port)),
        ))
    }

    /// The forwards currently running (id, dial target, local listen
    /// address): the UI's per-device forwards list.
    pub fn list_forwards(&self) -> Vec<ForwardInfo> {
        self.lock()
            .list_forwards()
            .into_iter()
            .map(|f| ForwardInfo {
                id: f.id,
                target: f.target,
                local: f.local.to_string(),
            })
            .collect()
    }

    /// Stop a forward by id (listener closes; live connections finish
    /// naturally). Returns false when no such forward is running. A
    /// confirming Event::ForwardStopped (error None) follows.
    pub fn cancel_forward(&self, id: u64) -> bool {
        self.lock().cancel_forward(id)
    }

    /// Expose a peer-reachable TCP service of this device (host:port) over
    /// tunnels. Returns immediately; progress arrives as events.
    pub fn expose(&self, to_host: String, to_port: u16) -> Result<u16, NoscatError> {
        let to: std::net::SocketAddr = format!("{to_host}:{to_port}")
            .parse()
            .map_err(NoscatError::fail)?;
        self.lock()
            .expose(to)
            .map(|addr| addr.port())
            .map_err(NoscatError::fail)
    }

    /// Send a file to a peer. Returns immediately; the outcome arrives as
    /// TransferDone / TransferFailed. Resume-aware, sha256-verified at the peer.
    pub fn send_file(&self, path: String, target_npub: String) {
        self.lock().send_file(std::path::PathBuf::from(path), &target_npub);
    }

    /// Cancel an in-flight send (same path and peer the send was started
    /// with). The transfer stops between chunks, TransferCancelled fires,
    /// and the receiver keeps its resumable partial. Returns false when no
    /// such send is in flight (it may have already finished).
    pub fn cancel_transfer(&self, path: String, target_npub: String) -> bool {
        self.lock()
            .cancel_transfer(&target_npub, std::path::Path::new(&path))
    }

    /// Receive one file into out_dir. Returns immediately; the outcome
    /// arrives as TransferDone (with the verified final path) / TransferFailed.
    pub fn receive_file(&self, out_dir: String) {
        self.lock().receive_file(std::path::PathBuf::from(out_dir));
    }

    /// Send a one-shot chat message to a peer. Returns immediately; a
    /// failure arrives as ChatFailed (delivery is FIN-confirmed otherwise).
    pub fn send_chat(&self, target_npub: String, text: String) {
        self.lock().send_chat(&target_npub, &text);
    }

    /// Share this device's clipboard text with a peer: it becomes the
    /// clipboard on the receiving device. Returns immediately; a failure
    /// arrives as ChatFailed, delivery is FIN-confirmed otherwise.
    pub fn send_clipboard(&self, target_npub: String, text: String) {
        self.lock().send_clipboard(&target_npub, &text);
    }

    /// Node mode (requires a mesh-scoped client: membership is the
    /// authorization). Advertises and accepts any number of inbound peers
    /// until the client is dropped: files are saved into out_dir, and raw
    /// inbound tunnels are bridged to 127.0.0.1:bridge_port when given.
    /// Returns the advertised UDP port.
    pub fn up(&self, out_dir: String, bridge_port: Option<u16>) -> Result<u16, NoscatError> {
        let bridge_to = bridge_port
            .map(|p| std::net::SocketAddr::from(([127, 0, 0, 1], p)));
        self.lock()
            .up(std::path::PathBuf::from(out_dir), bridge_to)
            .map(|addr| addr.port())
            .map_err(NoscatError::fail)
    }
}

// Not exported: a plain private helper (MutexGuard cannot cross the FFI).
impl NoscatClient {
    fn lock(&self) -> std::sync::MutexGuard<'_, noscat_client::Client> {
        self.inner.client.lock().unwrap_or_else(|p| p.into_inner())
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
}
