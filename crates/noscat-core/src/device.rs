//! A running device: the mesh group on relays, wired to the data plane.
//!
//! [`Device`] owns one [`MeshGroup`], one relay connection, one
//! [`Dataplane`] and one [`Streams`]. It keeps them in step:
//! - group events (kind 445) and Welcomes (kind 1059) from relays go into
//!   the group; every roster change goes to [`Streams::retain_members`]
//!   then [`Dataplane::set_members`], so only members can reach this
//!   device;
//! - this device's FIPS advert and name go to the group as an app event
//!   on every roster change and every [`ADVERT_INTERVAL`]; members'
//!   adverts go into the data plane and the presence map;
//! - own commits are published before they are applied, and Welcomes are
//!   sent only after their commit is acknowledged (Marmot "publish before
//!   apply").
//!
//! Membership flows: [`Device::create`] starts a mesh, [`Device::invite`]
//! adds a device by its key (it must be running or have published a key
//! package), [`Device::join`] waits for an invitation from a named device,
//! [`Device::remove`] and [`Device::leave`] shrink the mesh.

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use futures_util::StreamExt as _;
use nostr::prelude::{Event, Filter, Kind, PublicKey, SingleLetterTag, Timestamp};
use nostr_sdk::prelude::{Client, ClientNotification, RelayStatus, SubscriptionId};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, broadcast};

use crate::dataplane::{Dataplane, DataplaneConfig, DataplaneError, Member, PeerLink};
use crate::identity::Identity;
use crate::marmot::transport::AppEvent;
use crate::marmot::{
    self, ADVERT_KIND, Change, GROUP_KIND, INBOX_RELAYS_KIND, KEY_PACKAGE_KIND, MeshError, MeshGroup,
    Outgoing, RELAY_LIST_KIND,
};
use crate::relay::{self, Presence};
use crate::streams::{Streams, StreamsError};

/// How often a device re-sends its advert to the group. Well inside
/// [`relay::PRESENCE_TTL_SECS`].
pub const ADVERT_INTERVAL: Duration = Duration::from_secs(120);
/// How long a publish waits for relay acknowledgements per attempt.
/// How long a publish waits for the first relay to accept.
const PUBLISH_WAIT: Duration = Duration::from_secs(15);
/// Sends per relay when it is not connected (never when it is slow).
const PUBLISH_ATTEMPTS: u32 = 3;
/// How long relay setup waits for the first relay to connect.
const RELAY_CONNECT_WAIT: Duration = Duration::from_secs(10);
/// Relay lists are republished after this even when unchanged.
const RELAY_LIST_REFRESH_SECS: u64 = 7 * 24 * 3600;
/// Gift wraps carry a created_at randomized up to two days into the past.
const GIFT_WRAP_LOOKBACK_SECS: u64 = 3 * 24 * 60 * 60;
/// Overlap when resuming the group subscription after a restart.
/// Join requests older than this are stale (the asker stopped waiting).
const JOIN_REQUEST_TTL_SECS: u64 = 15 * 60;
/// Least time between adverts sent in answer to a returning member.
const ADVERT_REPLY_DEBOUNCE: Duration = Duration::from_secs(10);
const RESUME_OVERLAP_SECS: u64 = 15 * 60;
const SYNC_FILE: &str = "relay-sync.json";
const SUB_GROUP: &str = "noscat-group";
const SUB_INBOX: &str = "noscat-inbox";

/// Errors from the device runtime.
#[derive(Debug, thiserror::Error)]
pub enum DeviceError {
    #[error(transparent)]
    Mesh(#[from] MeshError),
    #[error(transparent)]
    Dataplane(#[from] DataplaneError),
    #[error(transparent)]
    Streams(#[from] StreamsError),
    #[error(transparent)]
    Relay(#[from] relay::RelayError),
    #[error("no relay accepted the event: {0}")]
    Publish(String),
    #[error("no key package found for {0}; is the device running or prepared to join?")]
    NoKeyPackage(String),
    #[error("timed out waiting for {0}")]
    Timeout(&'static str),
    #[error("{0}")]
    Other(String),
}

/// Device settings.
#[derive(Debug, Clone)]
pub struct DeviceConfig {
    /// State directory (identity lives elsewhere; see the client).
    pub dir: PathBuf,
    /// Friendly name shown to other members.
    pub name: String,
    /// This device's relays: where its key package and inbox live, and the
    /// mesh's relays when it creates one.
    pub relays: Vec<String>,
    pub dataplane: DataplaneConfig,
    /// Known UDP addresses for some members (a home server with a fixed
    /// address). Tried directly in addition to what adverts say.
    pub peer_addresses: HashMap<PublicKey, Vec<std::net::SocketAddr>>,
}

/// What a member looks like from this device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberStatus {
    pub device: PublicKey,
    /// Name from the member's latest advert.
    pub name: Option<String>,
    pub admin: bool,
    pub this_device: bool,
    /// An advert arrived within [`relay::PRESENCE_TTL_SECS`].
    pub online: bool,
    pub last_seen_secs: Option<u64>,
}

/// Something that happened on the mesh.
#[derive(Debug, Clone)]
pub enum DeviceEvent {
    /// This device joined a mesh (by invitation or by creating one).
    Joined,
    /// The member list changed.
    Roster(Vec<PublicKey>),
    /// A member's advert arrived (presence and name).
    Advert { device: PublicKey, name: Option<String> },
    /// An app event of another kind from a member.
    App(AppEvent),
    /// One of this device's own commits lost a race and was undone; the
    /// add or remove it carried did not happen.
    Superseded,
    /// This device is no longer in a mesh.
    Removed,
    /// A device that is not a member asks to be invited (it scanned this
    /// device's QR and is waiting in [`Device::join`]). Only a prompt:
    /// nothing happens unless someone calls [`Device::invite`].
    JoinRequest { device: PublicKey, name: Option<String> },
}

#[derive(Serialize, Deserialize, Default)]
struct SyncState {
    /// Newest group event created_at processed.
    since: u64,
    /// Relay lists last published, by kind: the relays and when. They are
    /// republished only when the relays change or the copy gets old, not on
    /// every start (each one-shot CLI command starts the device).
    #[serde(default)]
    relay_lists: HashMap<u16, (Vec<String>, u64)>,
}

struct Inner {
    identity: Identity,
    cfg: DeviceConfig,
    group: Mutex<MeshGroup>,
    client: Client,
    dp: Arc<Dataplane>,
    streams: Arc<Streams>,
    events: broadcast::Sender<DeviceEvent>,
    presence: Presence,
    names: StdMutex<HashMap<PublicKey, String>>,
    /// Accept a Welcome only from this device (set by [`Device::join`]).
    expected_inviter: StdMutex<Option<PublicKey>>,
    subscribed: StdMutex<Vec<[u8; 32]>>,
    sync: StdMutex<SyncState>,
    /// When this device last answered a returning member with its advert.
    last_reply: StdMutex<Option<std::time::Instant>>,
    /// Newest join request time per device, so relays replaying the inbox
    /// do not repeat a prompt.
    join_requests: StdMutex<HashMap<PublicKey, u64>>,
}

/// A running device. Cheap to clone; stops when [`Device::shutdown`] is
/// called.
#[derive(Clone)]
pub struct Device {
    inner: Arc<Inner>,
    tasks: Arc<StdMutex<Vec<tokio::task::JoinHandle<()>>>>,
}

impl std::fmt::Debug for Device {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Device").field("device", &self.inner.identity.public_key().to_hex()).finish_non_exhaustive()
    }
}

fn now() -> u64 {
    Timestamp::now().as_secs()
}

fn save_sync(dir: &std::path::Path, s: &SyncState) {
    if let Ok(b) = serde_json::to_vec(s) {
        let _ = crate::fsutil::write_atomic(&dir.join(SYNC_FILE), &b);
    }
}

/// Send `event` to one relay. Re-sends only when the relay was not
/// connected (its connection task is retrying), with a growing pause.
async fn publish_one(client: &Client, event: &Event, relay_url: &str) -> Result<(), String> {
    let mut last = String::new();
    for attempt in 0..PUBLISH_ATTEMPTS {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_secs(2 << attempt)).await;
        }
        let err = match client.send_event(event).to([relay_url]).await {
            Ok(out) if !out.success.is_empty() => {
                relay::note_relay_success(relay_url);
                return Ok(());
            }
            Ok(out) => out.failed.into_values().next().unwrap_or_default(),
            Err(e) => e.to_string(),
        };
        relay::note_relay_failure(relay_url, &err);
        let lower = err.to_lowercase();
        let unconnected = ["not connected", "disconnected", "terminated", "not ready", "connection", "closed"]
            .iter()
            .any(|w| lower.contains(w));
        if !unconnected {
            return Err(err);
        }
        last = err;
    }
    Err(last)
}

fn union(a: &[String], b: &[String]) -> Vec<String> {
    let mut v: Vec<String> = a.iter().chain(b).cloned().collect::<BTreeSet<_>>().into_iter().collect();
    v.retain(|r| marmot::codec::valid_relay_url(r));
    v
}

impl Device {
    /// Start the device: open its mesh state, bring up the data plane and
    /// streams, connect to relays and catch up.
    pub async fn start(identity: Identity, cfg: DeviceConfig) -> Result<Self, DeviceError> {
        std::fs::create_dir_all(&cfg.dir).map_err(|e| DeviceError::Other(e.to_string()))?;
        let group = MeshGroup::open(&cfg.dir, &identity)?;
        let dp = Arc::new(Dataplane::start(&identity, cfg.dataplane.clone()).await?);
        let streams = Arc::new(Streams::start(dp.clone()).await?);
        let sync: SyncState = std::fs::read(cfg.dir.join(SYNC_FILE))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let (events, _) = broadcast::channel(256);
        let inner = Arc::new(Inner {
            identity,
            cfg,
            group: Mutex::new(group),
            client: Client::new(),
            dp,
            streams,
            events,
            presence: Presence::new(),
            names: StdMutex::new(HashMap::new()),
            expected_inviter: StdMutex::new(None),
            subscribed: StdMutex::new(Vec::new()),
            sync: StdMutex::new(sync),
            last_reply: StdMutex::new(None),
            join_requests: StdMutex::new(HashMap::new()),
        });
        let dev = Self {
            inner,
            tasks: Arc::new(StdMutex::new(Vec::new())),
        };
        let relays = dev.all_relays().await;
        dev.ensure_relays(&relays).await;
        dev.spawn_loop();
        dev.subscribe_inbox().await;
        dev.apply_roster().await?;
        dev.resubscribe_group(true).await;
        // In the background: a slow relay must not hold up the start.
        let d = dev.clone();
        let h = tokio::spawn(async move { d.publish_profile().await });
        dev.tasks.lock().unwrap_or_else(|p| p.into_inner()).push(h);
        dev.spawn_advert_ticker();
        Ok(dev)
    }

    /// This device's key.
    #[must_use]
    pub fn device(&self) -> PublicKey {
        self.inner.identity.public_key()
    }

    /// The data plane (link state, network changes).
    #[must_use]
    pub fn dataplane(&self) -> &Arc<Dataplane> {
        &self.inner.dp
    }

    /// QUIC streams to members.
    #[must_use]
    pub fn streams(&self) -> &Arc<Streams> {
        &self.inner.streams
    }

    /// Mesh events from now on.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<DeviceEvent> {
        self.inner.events.subscribe()
    }

    pub async fn in_mesh(&self) -> bool {
        self.inner.group.lock().await.in_mesh()
    }

    /// The mesh name, if in a mesh.
    pub async fn mesh_name(&self) -> Option<String> {
        self.inner.group.lock().await.name().ok()
    }

    /// The members with presence.
    pub async fn members(&self) -> Vec<MemberStatus> {
        let infos = self.inner.group.lock().await.members().unwrap_or_default();
        let names = self.inner.names.lock().map(|n| n.clone()).unwrap_or_default();
        infos
            .into_iter()
            .map(|m| {
                let hex = m.device.to_hex();
                let name = if m.this_device {
                    Some(self.inner.cfg.name.clone())
                } else {
                    names.get(&m.device).cloned()
                };
                MemberStatus {
                    device: m.device,
                    name,
                    admin: m.admin,
                    this_device: m.this_device,
                    online: m.this_device || self.inner.presence.is_online(&hex),
                    last_seen_secs: if m.this_device { Some(0) } else { self.inner.presence.age_secs(&hex) },
                }
            })
            .collect()
    }

    /// Link state for members.
    pub async fn peers(&self) -> Result<Vec<PeerLink>, DeviceError> {
        Ok(self.inner.dp.peers().await?)
    }

    // ---- relays --------------------------------------------------------

    async fn all_relays(&self) -> Vec<String> {
        let group = self.inner.group.lock().await.relays().unwrap_or_default();
        union(&self.inner.cfg.relays, &group)
    }

    /// Add the relays this device does not have yet and wait (up to
    /// [`RELAY_CONNECT_WAIT`]) until one of `relays` is connected. Each relay
    /// gets nostr-sdk's connection task, which keeps retrying for the life of
    /// the device (10 seconds, backing off to a minute), so a relay that is
    /// down at start joins later and a dropped one comes back.
    async fn ensure_relays(&self, relays: &[String]) {
        let have: BTreeSet<String> =
            self.inner.client.relays().await.keys().map(|u| u.as_str().trim_end_matches('/').to_string()).collect();
        for r in relays {
            if have.contains(r.trim_end_matches('/')) {
                continue;
            }
            if let Err(e) = self.inner.client.add_relay(r.as_str()).await {
                tracing::warn!(relay = %r, "cannot add relay: {e}");
                continue;
            }
            if let Err(e) = self.inner.client.connect_relay(r.as_str()).await {
                tracing::warn!(relay = %r, "relay connect failed: {e}");
            }
        }
        let wanted: BTreeSet<&str> = relays.iter().map(|r| r.trim_end_matches('/')).collect();
        let deadline = tokio::time::Instant::now() + RELAY_CONNECT_WAIT;
        loop {
            let up = self.inner.client.relays().await.iter().any(|(u, r)| {
                wanted.contains(u.as_str().trim_end_matches('/')) && r.status() == RelayStatus::Connected
            });
            if up || tokio::time::Instant::now() >= deadline {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Publish to `relays`; succeeds on the first relay that accepts it.
    /// Each relay is sent to on its own task: the call returns as soon as one
    /// accepts (or every relay has answered, or [`PUBLISH_WAIT`] passes),
    /// and slower relays finish in the background. A relay is sent the event
    /// again only when it was not connected; one that is merely slow to
    /// answer is never re-sent to, and a rejection is final.
    async fn publish(&self, event: &Event, relays: &[String]) -> Result<(), DeviceError> {
        let relays = relay::healthy_relays(&union(relays, &[]));
        if relays.is_empty() {
            return Err(DeviceError::Publish("no relays".into()));
        }
        self.ensure_relays(&relays).await;
        let (tx, mut rx) = tokio::sync::mpsc::channel(relays.len());
        for r in relays {
            let client = self.inner.client.clone();
            let event = event.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                let res = publish_one(&client, &event, &r).await;
                let _ = tx.send((r, res)).await;
            });
        }
        drop(tx);
        let first = async {
            let mut errors = Vec::new();
            while let Some((r, res)) = rx.recv().await {
                match res {
                    Ok(()) => return Ok(()),
                    Err(e) => errors.push(format!("{r}: {e}")),
                }
            }
            Err(errors.join("; "))
        };
        match tokio::time::timeout(PUBLISH_WAIT, first).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(DeviceError::Publish(e)),
            Err(_) => Err(DeviceError::Publish("no relay answered in time".into())),
        }
    }

    async fn fetch(&self, filter: Filter, relays: &[String]) -> Vec<Event> {
        let relays = union(relays, &[]);
        self.ensure_relays(&relays).await;
        match self.inner.client.fetch_events(filter).timeout(relay::FETCH_WAIT).await {
            Ok(evs) => evs.into_iter().collect(),
            Err(e) => {
                tracing::warn!("fetch failed: {e}");
                Vec::new()
            }
        }
    }

    /// Relay lists (when they changed or got old) and, outside a mesh, a
    /// key package, so others can invite this device.
    async fn publish_profile(&self) {
        let keys = self.inner.identity.keys();
        let relays = self.inner.cfg.relays.clone();
        let mut sorted = relays.clone();
        sorted.sort();
        for kind in [INBOX_RELAYS_KIND, RELAY_LIST_KIND] {
            let fresh = {
                let s = self.inner.sync.lock().unwrap_or_else(|p| p.into_inner());
                s.relay_lists
                    .get(&kind)
                    .is_some_and(|(r, at)| *r == sorted && now().saturating_sub(*at) < RELAY_LIST_REFRESH_SECS)
            };
            if fresh {
                continue;
            }
            match marmot::transport::relay_list_event(keys, kind, &relays) {
                Ok(ev) => match self.publish(&ev, &relays).await {
                    Ok(()) => {
                        let mut s = self.inner.sync.lock().unwrap_or_else(|p| p.into_inner());
                        s.relay_lists.insert(kind, (sorted.clone(), now()));
                        save_sync(&self.inner.cfg.dir, &s);
                    }
                    Err(e) => tracing::warn!(kind, "relay list not published: {e}"),
                },
                Err(e) => tracing::warn!("relay list: {e}"),
            }
        }
        if !self.in_mesh().await {
            if let Err(e) = self.publish_key_package().await {
                tracing::warn!("key package not published: {e}");
            }
        }
    }

    /// Publish a fresh key package (done automatically while not in a
    /// mesh; exposed so a joiner can refresh it).
    pub async fn publish_key_package(&self) -> Result<(), DeviceError> {
        let ev = self.inner.group.lock().await.key_package_event()?;
        self.publish(&ev, &self.inner.cfg.relays).await
    }

    // ---- subscriptions -------------------------------------------------

    async fn subscribe_inbox(&self) {
        let filter = Filter::new()
            .kind(Kind::GiftWrap)
            .pubkey(self.device())
            .since(Timestamp::from_secs(now().saturating_sub(GIFT_WRAP_LOOKBACK_SECS)));
        if let Err(e) = self
            .inner
            .client
            .subscribe(filter)
            .with_id(SubscriptionId::new(SUB_INBOX))
            .await
        {
            tracing::warn!("inbox subscription failed: {e}");
        }
    }

    /// (Re)subscribe to group events when the routing ids change.
    async fn resubscribe_group(&self, force: bool) {
        let ids = self.inner.group.lock().await.routing_ids();
        {
            let mut cur = self.inner.subscribed.lock().unwrap_or_else(|p| p.into_inner());
            if !force && *cur == ids {
                return;
            }
            cur.clone_from(&ids);
        }
        let id = SubscriptionId::new(SUB_GROUP);
        if ids.is_empty() {
            let _ = self.inner.client.unsubscribe(&id).await;
            return;
        }
        let relays = self.all_relays().await;
        self.ensure_relays(&relays).await;
        let since = {
            let s = self.inner.sync.lock().unwrap_or_else(|p| p.into_inner());
            if s.since == 0 { now().saturating_sub(RESUME_OVERLAP_SECS) } else { s.since.saturating_sub(RESUME_OVERLAP_SECS) }
        };
        let filter = Filter::new()
            .kind(Kind::Custom(GROUP_KIND))
            .custom_tags(SingleLetterTag::from_char('h').expect("h is a single-letter tag"), ids.iter().map(hex::encode))
            .since(Timestamp::from_secs(since));
        if let Err(e) = self.inner.client.subscribe(filter).with_id(id).await {
            tracing::warn!("group subscription failed: {e}");
        }
    }

    fn note_synced(&self, created_at: u64) {
        let mut s = self.inner.sync.lock().unwrap_or_else(|p| p.into_inner());
        let capped = created_at.min(now());
        if capped > s.since {
            s.since = capped;
            save_sync(&self.inner.cfg.dir, &s);
        }
    }

    fn spawn_loop(&self) {
        let dev = self.clone();
        let mut notes = self.inner.client.notifications();
        let h = tokio::spawn(async move {
            while let Some(n) = notes.next().await {
                let ClientNotification::Event { event, .. } = n else { continue };
                if let Err(e) = dev.on_event(&event).await {
                    tracing::warn!("event handling: {e}");
                }
            }
        });
        self.tasks.lock().unwrap_or_else(|p| p.into_inner()).push(h);
    }

    fn spawn_advert_ticker(&self) {
        let dev = self.clone();
        let h = tokio::spawn(async move {
            // The first tick fires at once: members learn a restarted
            // device's endpoints now, not one interval later.
            let mut tick = tokio::time::interval(ADVERT_INTERVAL);
            loop {
                tick.tick().await;
                dev.send_advert().await;
            }
        });
        self.tasks.lock().unwrap_or_else(|p| p.into_inner()).push(h);
    }

    async fn on_event(&self, event: &Event) -> Result<(), DeviceError> {
        if event.kind == Kind::Custom(GROUP_KIND) {
            let changes = self.inner.group.lock().await.process(event)?;
            self.note_synced(event.created_at.as_secs());
            self.handle(changes).await;
        } else if event.kind == Kind::GiftWrap {
            let expected = *self.inner.expected_inviter.lock().unwrap_or_else(|p| p.into_inner());
            let Some(inviter) = expected else {
                self.on_join_request(event).await;
                return Ok(());
            };
            let joined = {
                let mut g = self.inner.group.lock().await;
                if g.in_mesh() {
                    return Ok(());
                }
                match g.join(event, Some(inviter)) {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::info!("invitation ignored: {e}");
                        None
                    }
                }
            };
            if let Some(changes) = joined {
                *self.inner.expected_inviter.lock().unwrap_or_else(|p| p.into_inner()) = None;
                self.note_synced(now().saturating_sub(RESUME_OVERLAP_SECS));
                let _ = self.inner.events.send(DeviceEvent::Joined);
                self.handle(changes).await;
            }
        }
        Ok(())
    }

    async fn on_join_request(&self, event: &Event) {
        if !self.in_mesh().await {
            return;
        }
        let req = match marmot::transport::unwrap_join_request(self.inner.identity.keys(), event) {
            Ok(Some(r)) => r,
            Ok(None) => return,
            Err(e) => {
                tracing::debug!("gift wrap ignored: {e}");
                return;
            }
        };
        if now().saturating_sub(req.created_at) > JOIN_REQUEST_TTL_SECS {
            return;
        }
        let member = self
            .inner
            .group
            .lock()
            .await
            .members()
            .unwrap_or_default()
            .iter()
            .any(|m| m.device == req.sender);
        if member {
            return;
        }
        {
            let mut seen = self.inner.join_requests.lock().unwrap_or_else(|p| p.into_inner());
            if seen.get(&req.sender).is_some_and(|t| *t >= req.created_at) {
                return;
            }
            seen.insert(req.sender, req.created_at);
        }
        let _ = self.inner.events.send(DeviceEvent::JoinRequest { device: req.sender, name: req.name });
    }

    /// Act on group changes. Boxed: committing a leave from here re-enters
    /// it through [`Self::commit`].
    fn handle(&self, changes: Vec<Change>) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(self.handle_inner(changes))
    }

    async fn handle_inner(&self, changes: Vec<Change>) {
        let mut roster = false;
        for c in changes {
            match c {
                Change::Roster(r) => {
                    roster = true;
                    let _ = self.inner.events.send(DeviceEvent::Roster(r));
                }
                Change::App(ev) if ev.kind == ADVERT_KIND => self.on_advert(ev).await,
                Change::App(ev) => {
                    let _ = self.inner.events.send(DeviceEvent::App(ev));
                }
                Change::Removed => {
                    roster = true;
                    let _ = self.inner.events.send(DeviceEvent::Removed);
                }
                Change::Superseded { own, .. } => {
                    if own {
                        let _ = self.inner.events.send(DeviceEvent::Superseded);
                    }
                }
                Change::LeaveRequested(who) => {
                    tracing::info!(device = %who.to_hex(), "member asked to leave");
                    let dev = self.clone();
                    tokio::spawn(async move {
                        // Spread out so members rarely commit it at once.
                        let jitter = rand::random::<u64>() % 3000;
                        tokio::time::sleep(Duration::from_millis(jitter)).await;
                        if let Err(e) = dev.commit_pending().await {
                            tracing::warn!("committing a leave: {e}");
                        }
                    });
                }
            }
        }
        if roster {
            if let Err(e) = self.apply_roster().await {
                tracing::warn!("applying roster: {e}");
            }
            self.resubscribe_group(false).await;
            if self.in_mesh().await {
                self.send_advert().await;
            } else {
                self.publish_profile().await;
            }
        }
    }

    async fn on_advert(&self, ev: AppEvent) {
        let device = ev.pubkey;
        let name = ev.tag("name").map(str::to_string);
        if let Some(n) = &name {
            if let Ok(mut names) = self.inner.names.lock() {
                names.insert(device, n.clone());
            }
        }
        // A member we have not heard from lately (just started, or back
        // from offline) needs our endpoints too: answer with our advert
        // instead of making it wait for the next tick. Debounced so a
        // mesh full of restarts does not echo.
        let stale = self
            .inner
            .presence
            .age_secs(&device.to_hex())
            .is_none_or(|age| age > ADVERT_INTERVAL.as_secs() + 30);
        self.inner.presence.note(&device.to_hex());
        if stale && device != self.device() {
            let due = {
                let mut last = self.inner.last_reply.lock().unwrap_or_else(|p| p.into_inner());
                let due = last.is_none_or(|t| t.elapsed() > ADVERT_REPLY_DEBOUNCE);
                if due {
                    *last = Some(std::time::Instant::now());
                }
                due
            };
            if due {
                let dev = self.clone();
                tokio::spawn(async move { dev.send_advert().await });
            }
        }
        if !ev.content.is_empty() {
            if let Err(e) = self.inner.dp.ingest_advert(&ev.content).await {
                tracing::debug!("advert not used: {e}");
            }
        }
        let _ = self.inner.events.send(DeviceEvent::Advert { device, name });
    }

    /// Admit exactly the current members to streams and the data plane.
    async fn apply_roster(&self) -> Result<(), DeviceError> {
        let me = self.device();
        let others: Vec<PublicKey> = self
            .inner
            .group
            .lock()
            .await
            .members()
            .unwrap_or_default()
            .into_iter()
            .map(|m| m.device)
            .filter(|d| *d != me)
            .collect();
        self.inner.streams.retain_members(&others).await;
        let members: Vec<Member> = others
            .into_iter()
            .map(|device| Member {
                device,
                addresses: self.inner.cfg.peer_addresses.get(&device).cloned().unwrap_or_default(),
            })
            .collect();
        self.inner.dp.set_members(&members).await?;
        Ok(())
    }

    /// Send this device's advert to the group now.
    pub async fn send_advert(&self) {
        let advert = match self.inner.dp.local_advert().await {
            Ok(a) => a,
            Err(e) => {
                tracing::debug!("no local advert: {e}");
                None
            }
        };
        let ev = {
            let mut g = self.inner.group.lock().await;
            if !g.in_mesh() {
                return;
            }
            g.send_advert(advert.as_deref(), &self.inner.cfg.name)
        };
        match ev {
            Ok(ev) => {
                let relays = self.all_relays().await;
                if let Err(e) = self.publish(&ev, &relays).await {
                    tracing::warn!("advert not published: {e}");
                }
            }
            Err(e) => tracing::warn!("advert: {e}"),
        }
    }

    /// Send an app event of `kind` to every member.
    pub async fn send_app(&self, kind: u16, tags: Vec<Vec<String>>, content: String) -> Result<(), DeviceError> {
        let ev = self.inner.group.lock().await.send_app(kind, tags, content)?;
        let relays = self.all_relays().await;
        self.publish(&ev, &relays).await
    }

    // ---- membership ----------------------------------------------------

    /// Publish a staged commit, then apply it (or drop it on failure), then
    /// deliver its Welcomes.
    async fn commit(&self, out: Outgoing) -> Result<(), DeviceError> {
        let relays = self.all_relays().await;
        if let Err(e) = self.publish(&out.commit, &relays).await {
            self.inner.group.lock().await.abandon()?;
            return Err(e);
        }
        let changes = self.inner.group.lock().await.confirm()?;
        self.handle(changes).await;
        for w in &out.welcomes {
            let inbox = self.inbox_relays(&w.invitee).await;
            let gw = self.inner.group.lock().await.wrap_welcome(w)?;
            if let Err(e) = self.publish(&gw, &inbox).await {
                tracing::warn!(device = %w.invitee.to_hex(), "invitation not delivered: {e}");
            }
        }
        Ok(())
    }

    async fn commit_pending(&self) -> Result<(), DeviceError> {
        let out = self.inner.group.lock().await.commit_pending()?;
        match out {
            Some(out) => self.commit(out).await,
            None => Ok(()),
        }
    }

    /// A device's inbox relays (kind 10050), or ours when it has none.
    async fn inbox_relays(&self, device: &PublicKey) -> Vec<String> {
        let mine = self.all_relays().await;
        let lists = self
            .fetch(Filter::new().kind(Kind::Custom(INBOX_RELAYS_KIND)).author(*device).limit(1), &mine)
            .await;
        let theirs: Vec<String> = lists
            .iter()
            .max_by_key(|e| e.created_at)
            .map(|e| {
                e.tags
                    .iter()
                    .filter_map(|t| match t.as_slice() {
                        [n, v, ..] if n == "relay" => Some(v.clone()),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        if theirs.is_empty() { mine } else { union(&theirs, &[]) }
    }

    /// Create a mesh named `name` on this device's relays.
    pub async fn create(&self, name: &str) -> Result<(), DeviceError> {
        self.inner.group.lock().await.create(name, &self.inner.cfg.relays)?;
        let _ = self.inner.events.send(DeviceEvent::Joined);
        self.resubscribe_group(true).await;
        self.send_advert().await;
        Ok(())
    }

    /// Add a device to the mesh by its key. Its newest key package is
    /// fetched from this device's relays and the ones it lists.
    pub async fn invite(&self, device: PublicKey) -> Result<(), DeviceError> {
        let mine = self.all_relays().await;
        let mut relays = mine.clone();
        let lists = self
            .fetch(Filter::new().kind(Kind::Custom(RELAY_LIST_KIND)).author(device).limit(1), &mine)
            .await;
        if let Some(l) = lists.iter().max_by_key(|e| e.created_at) {
            let theirs: Vec<String> = l
                .tags
                .iter()
                .filter_map(|t| match t.as_slice() {
                    [n, v] if n == "r" => Some(v.clone()),
                    [n, v, m] if n == "r" && m == "write" => Some(v.clone()),
                    _ => None,
                })
                .collect();
            relays = union(&relays, &theirs);
        }
        let mut kps = self
            .fetch(Filter::new().kind(Kind::Custom(KEY_PACKAGE_KIND)).author(device).limit(10), &relays)
            .await;
        kps.sort_by_key(|e| std::cmp::Reverse(e.created_at));
        let mut last = None;
        for kp in kps {
            let staged = self.inner.group.lock().await.add(std::slice::from_ref(&kp));
            match staged {
                Ok(out) => return self.commit(out).await,
                Err(MeshError::KeyPackage(e)) => last = Some(e),
                Err(e) => return Err(e.into()),
            }
        }
        Err(DeviceError::NoKeyPackage(match last {
            Some(e) => format!("{} ({e})", device.to_hex()),
            None => device.to_hex(),
        }))
    }

    /// Remove devices from the mesh.
    pub async fn remove(&self, devices: &[PublicKey]) -> Result<(), DeviceError> {
        let out = self.inner.group.lock().await.remove(devices)?;
        self.commit(out).await
    }

    /// Wait for an invitation from `inviter` and join its mesh. The key
    /// package is (re)published first so the inviter can find it.
    pub async fn join(&self, inviter: PublicKey, timeout: Duration) -> Result<(), DeviceError> {
        if self.in_mesh().await {
            return Err(MeshError::AlreadyInMesh.into());
        }
        let mut rx = self.subscribe();
        *self.inner.expected_inviter.lock().unwrap_or_else(|p| p.into_inner()) = Some(inviter);
        self.publish_key_package().await?;
        // Ask the inviter's device to prompt its user. Best effort: an
        // invite by npub works without it.
        match marmot::transport::wrap_join_request(self.inner.identity.keys(), &inviter, &self.inner.cfg.name) {
            Ok(wrap) => {
                let relays = self.inbox_relays(&inviter).await;
                if let Err(e) = self.publish(&wrap, &relays).await {
                    tracing::warn!("join request not delivered: {e}");
                }
            }
            Err(e) => tracing::warn!("join request: {e}"),
        }
        // An invitation that arrived before now is still on the relays.
        let relays = self.all_relays().await;
        let stored = self
            .fetch(
                Filter::new()
                    .kind(Kind::GiftWrap)
                    .pubkey(self.device())
                    .since(Timestamp::from_secs(now().saturating_sub(GIFT_WRAP_LOOKBACK_SECS))),
                &relays,
            )
            .await;
        for ev in stored {
            self.on_event(&ev).await?;
            if self.in_mesh().await {
                return Ok(());
            }
        }
        let wait = async {
            loop {
                match rx.recv().await {
                    Ok(DeviceEvent::Joined) => return Ok(()),
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => {
                        return Err(DeviceError::Other("device stopped".into()));
                    }
                }
            }
        };
        let r = tokio::time::timeout(timeout, wait).await;
        if !matches!(r, Ok(Ok(()))) {
            *self.inner.expected_inviter.lock().unwrap_or_else(|p| p.into_inner()) = None;
        }
        r.map_err(|_| DeviceError::Timeout("an invitation"))?
    }

    /// Leave the mesh: step down as admin, ask the others to remove this
    /// device, and wait up to `timeout` for it. The last device of a mesh
    /// (or one no member answers) forgets the mesh locally.
    pub async fn leave(&self, timeout: Duration) -> Result<(), DeviceError> {
        let (alone, admin) = {
            let g = self.inner.group.lock().await;
            if !g.in_mesh() {
                return Err(MeshError::NoMesh.into());
            }
            (g.members()?.len() <= 1, g.is_admin())
        };
        if alone {
            self.forget().await?;
            return Ok(());
        }
        if admin {
            let out = self.inner.group.lock().await.step_down()?;
            self.commit(out).await?;
        }
        let mut rx = self.subscribe();
        let req = self.inner.group.lock().await.leave_request()?;
        let relays = self.all_relays().await;
        self.publish(&req, &relays).await?;
        let wait = async {
            loop {
                match rx.recv().await {
                    Ok(DeviceEvent::Removed) | Err(broadcast::error::RecvError::Closed) => return,
                    _ => {}
                }
            }
        };
        if tokio::time::timeout(timeout, wait).await.is_err() {
            tracing::warn!("no member committed the leave in time; forgetting the mesh locally");
            self.forget().await?;
        }
        Ok(())
    }

    async fn forget(&self) -> Result<(), DeviceError> {
        self.inner.group.lock().await.forget()?;
        let _ = self.inner.events.send(DeviceEvent::Removed);
        self.handle(Vec::new()).await;
        self.apply_roster().await?;
        self.resubscribe_group(false).await;
        self.publish_profile().await;
        Ok(())
    }

    /// Stop everything.
    pub async fn shutdown(&self) {
        for h in self.tasks.lock().unwrap_or_else(|p| p.into_inner()).drain(..) {
            h.abort();
        }
        self.inner.streams.close();
        let _ = self.inner.dp.shutdown().await;
        self.inner.client.shutdown().await;
    }
}
