//! Relay plumbing: publish and watch overlay adverts over real Nostr relays.
//!
//! Relays are the discovery channel only - they carry signed, public advert
//! events (kind 37195 pattern). Tunnel traffic never touches them.

use std::time::Duration;

use nostr::prelude::*;
use nostr_sdk::prelude::*;
use tokio::time::timeout;

use crate::advert::{Advert, AdvertError, Endpoint, ADVERT_IDENTIFIER, ADVERT_KIND};
use crate::identity::Identity;

/// Relays used when the operator does not configure any. Overridable with
/// `--relay`. Chosen for uptime: three operators so no single relay is
/// load-bearing, and a relay that rate-limits us is backed off (see
/// [`note_relay_failure`]) rather than hammering.
pub const DEFAULT_RELAYS: &[&str] = &[
    "wss://relay.primal.net",
    "wss://relay.nostr.com",
    "wss://nostr.mom",
];

/// How long to wait for relay connections before giving up.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long to wait for a matching advert before giving up.
pub(crate) const FETCH_WAIT: Duration = Duration::from_secs(15);

/// A connected client over `relays` - the one place relay plumbing is set
/// up. Callers that publish/fetch shut the client down when done; the
/// long-lived `watch_*` streams just drop it.
pub(crate) type RelayClient = Client;

pub(crate) async fn connect_client(relays: &[String]) -> Result<Client, RelayError> {
    if relays.is_empty() {
        return Err(RelayError::NoRelays);
    }
    // Skip relays in a rate-limit cool-down; healthy_relays never returns
    // an empty list, so this never takes the only relay out.
    let relays = healthy_relays(relays);
    let client = Client::new();
    for relay in &relays {
        client.add_relay(relay).await?;
    }
    let _ = timeout(CONNECT_TIMEOUT, client.connect().and_wait(CONNECT_TIMEOUT))
        .await
        .map_err(|_| {
            for relay in &relays {
                note_relay_failure(relay, "connect timeout");
            }
            RelayError::ConnectTimeout
        })?;
    for relay in &relays {
        note_relay_success(relay);
    }
    Ok(client)
}

/// The default relay set as owned strings: for surfaces (FFI mesh helpers,
/// CLI defaults) that resolve relays without a config in hand.
pub fn default_relays() -> Vec<String> {
    DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect()
}

/// The default UDP port serve-side tunnels listen on (one place; the CLI
/// defaults, the client's default listen addr, and the FFI agree on it).
pub const DEFAULT_LISTEN_PORT: u16 = 41641;

#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("no relays configured")]
    NoRelays,    #[error("timed out connecting to relays")]
    ConnectTimeout,
    #[error(transparent)]
    Sdk(#[from] nostr_sdk::error::Error),
    #[error(transparent)]
    Advert(#[from] AdvertError),
    #[error(transparent)]
    Sign(#[from] nostr::error::Error),
}

/// The cool-down for a relay that failed once: doubled per consecutive
/// failure, capped, so a persistently rate-limiting relay is retried
/// rarely instead of being hammered.
const BACKOFF_BASE: Duration = Duration::from_secs(30);
const BACKOFF_CAP: u32 = 5;

/// A relay's health: consecutive failures and the cool-down that started
/// at the last one. Global state: relays are process-wide endpoints, and
/// every call path (fetch, publish, the watchers) should agree on who is
/// currently worth dialing.
#[derive(Default)]
struct RelayHealth {
    failures: u32,
    cooling_until: Option<std::time::Instant>,
}

fn relay_health() -> &'static std::sync::Mutex<std::collections::HashMap<String, RelayHealth>> {
    static HEALTH: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, RelayHealth>>,
    > = std::sync::OnceLock::new();
    HEALTH.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// True when an error string is a relay rate-limiting us (HTTP 429 on the
/// websocket, or a relay-protocol notice saying the same). Errors from
/// different stacks arrive as flattened strings; the markers are stable.
fn is_rate_limit(text: &str) -> bool {
    let t = text.to_ascii_lowercase();
    t.contains("429") || t.contains("rate limit") || t.contains("too many requests")
}

/// Record a relay failure; rate limits start (or extend) that relay's
/// cool-down: `BACKOFF_BASE` doubled per consecutive failure, capped.
/// Non-rate-limit failures only count toward the consecutive streak.
pub fn note_relay_failure(url: &str, err: &str) {
    let mut health = relay_health().lock().expect("relay health");
    let h = health.entry(url.to_string()).or_default();
    h.failures = h.failures.saturating_add(1);
    if is_rate_limit(err) {
        let shift = h.failures.saturating_sub(1).min(BACKOFF_CAP);
        h.cooling_until =
            Some(std::time::Instant::now() + BACKOFF_BASE * 2u32.saturating_pow(shift));
        tracing::info!(%url, failures = h.failures, "relay backing off: {err}");
    }
}

/// Record a relay working again: clears the failure streak and any
/// cool-down.
pub fn note_relay_success(url: &str) {
    let mut health = relay_health().lock().expect("relay health");
    if let Some(h) = health.get_mut(url) {
        h.failures = 0;
        h.cooling_until = None;
    }
}

/// The relays worth dialing right now: those not in a rate-limit
/// cool-down. Never returns an empty list - if every relay is cooling
/// down, all of them come back (a backed-off relay is still better than
/// going dark; the worst it does is hit a 429 again).
pub fn healthy_relays(relays: &[String]) -> Vec<String> {
    let now = std::time::Instant::now();
    let health = relay_health().lock().expect("relay health");
    let usable: Vec<String> = relays
        .iter()
        .filter(|url| {
            !matches!(
                health.get(*url),
                Some(RelayHealth {
                    cooling_until: Some(until),
                    ..
                }) if *until > now
            )
        })
        .cloned()
        .collect();
    if usable.is_empty() {
        relays.to_vec()
    } else {
        usable
    }
}

/// Sign and publish an advert event to the given relays.
pub async fn publish_advert(
    identity: &Identity,
    endpoints: Vec<Endpoint>,
    noise_pub: [u8; 32],
    name: Option<String>,
    ttl_secs: u64,
    relays: &[String],
) -> Result<(), RelayError> {
    if relays.is_empty() {
        return Err(RelayError::NoRelays);
    }
    let event =
        Advert::event(identity, endpoints, noise_pub, name, ttl_secs, Timestamp::now())?;

    let client = connect_client(relays).await?;
    let output = client.send_event(&event).await?;
    for (url, status) in &output.success {
        tracing::info!(%url, ?status, "advert published");
    }
    for (url, err) in &output.failed {
        tracing::warn!(%url, %err, "relay rejected advert");
        if is_rate_limit(err) {
            note_relay_failure(&url.to_string(), err);
        }
    }
    client.shutdown().await;
    Ok(())
}

/// Fetch the freshest advert matching a Noise key and/or npub from the relays.
///
/// Subscribes, waits up to [`FETCH_WAIT`] for a valid, unexpired advert, then
/// disconnects. `None` means "nothing valid arrived in time". Results are
/// cached briefly ([`ADVERT_CACHE_TTL`]): lookups repeat constantly (accept-
/// time peer display, roster names, dials) and relays rate-limit the churn.
pub async fn fetch_advert_for(
    relays: &[String],
    noise_key: Option<[u8; 32]>,
    npub: Option<PublicKey>,
) -> Result<Option<Advert>, RelayError> {
    const ADVERT_CACHE_TTL: Duration = Duration::from_secs(30);
    // A miss must expire faster than the dialer's retry cadence (5s): a
    // miss cached for the full 30s answers every retry from the cache, so
    // a dial against a peer whose advert just landed performs exactly one
    // real query and then fails against our own memory of the miss.
    const ADVERT_MISS_TTL: Duration = Duration::from_secs(4);
    static CACHE: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, (std::time::Instant, Option<Advert>)>>,
    > = std::sync::OnceLock::new();
    let cache = CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let cache_key = match (noise_key, npub) {
        (Some(k), _) => format!("k:{}", hex::encode(k)),
        (_, Some(p)) => format!("n:{p}"),
        (None, None) => String::new(),
    };
    if let Some((at, advert)) = cache.lock().expect("advert cache").get(&cache_key) {
        let ttl = if advert.is_some() {
            ADVERT_CACHE_TTL
        } else {
            ADVERT_MISS_TTL
        };
        if at.elapsed() < ttl {
            return Ok(advert.clone());
        }
    }

    let mut filter = Filter::new()
        .kind(Kind::Custom(ADVERT_KIND))
        .identifier(ADVERT_IDENTIFIER);
    if let Some(pk) = npub {
        filter = filter.author(pk);
    }

    let client = connect_client(relays).await?;
    client.subscribe(filter).await?;

    let mut notifications = client.notifications();
    let found = timeout(
        FETCH_WAIT,
        async {
            let cache_key = cache_key.clone();
            while let Some(notification) = notifications.next().await {
                let ClientNotification::Event { event, .. } = notification else {
                    continue;
                };
                let advert = match Advert::from_event(&event, Timestamp::now()) {
                    Ok(a) => a,
                    Err(e) => {
                        tracing::debug!(%e, "ignoring invalid advert");
                        continue;
                    }
                };
                if let Some(want_noise) = noise_key {
                    if advert.noise_pub != want_noise {
                        continue;
                    }
                }
                cache
                    .lock()
                    .expect("advert cache")
                    .insert(cache_key, (std::time::Instant::now(), Some(advert.clone())));
                return Some(advert);
            }
            None
        },
    )
    .await
    .unwrap_or(None);

    client.shutdown().await;
    cache
        .lock()
        .expect("advert cache")
        .insert(cache_key, (std::time::Instant::now(), found.clone()));
    Ok(found)
}

/// Fetch a device's published MLS key package (mesh kind 30443) by author.
///
/// `None` means "nothing arrived in time" - usually the device has not run
/// `noscat mesh publish` yet.
pub async fn fetch_key_package(
    relays: &[String],
    device: PublicKey,
) -> Result<Option<Event>, RelayError> {
    use crate::mesh::{KEY_PACKAGE_IDENTIFIER, KEY_PACKAGE_KIND};

    let filter = Filter::new()
        .kind(Kind::Custom(KEY_PACKAGE_KIND))
        .identifier(KEY_PACKAGE_IDENTIFIER)
        .author(device);

    let client = connect_client(relays).await?;
    client.subscribe(filter).await?;

    let mut notifications = client.notifications();
    let found = timeout(
        FETCH_WAIT,
        async {
            while let Some(notification) = notifications.next().await {
                let ClientNotification::Event { event, .. } = notification else {
                    continue;
                };
                if event.pubkey == device {
                    return Some(event.as_ref().clone());
                }
            }
            None
        },
    )
    .await
    .unwrap_or(None);

    client.shutdown().await;
    Ok(found)
}

/// Subscribe to noscat adverts on the given relays and print them as they
/// arrive, until the task is cancelled. Returns when the stream ends.
pub async fn watch_adverts(relays: &[String]) -> Result<(), RelayError> {
    let client = connect_client(relays).await?;

    let filter = Filter::new()
        .kind(Kind::Custom(ADVERT_KIND))
        .identifier(ADVERT_IDENTIFIER);
    client.subscribe(filter).await?;

    let mut notifications = client.notifications();
    while let Some(notification) = notifications.next().await {
        if let ClientNotification::Event { relay_url, event, .. } = notification {
            match Advert::from_event(&event, Timestamp::now()) {
                Ok(advert) => {
                    let npub = advert.npub.to_string();
                    println!(
                        "# advert from {npub} via {relay_url}: {:?} (expires {})",
                        advert.endpoints, advert.expires_at
                    );
                }
                Err(e) => eprintln!("# ignoring invalid advert from {relay_url}: {e}"),
            }
        }
    }
    Ok(())
}

/// Subscribe to mesh key packages (kind 30443) on the relays and forward
/// each event's author to the returned channel; the stream lives until the
/// receiver is dropped. This is how the mesh owner notices a device asking
/// to join: the device publishes its key package tagged to the owner's npub,
/// and this subscription only surfaces events addressed to `target` - a
/// device that scanned a different owner's QR never reaches us.
pub async fn watch_key_packages(
    relays: &[String],
    target: PublicKey,
) -> Result<tokio::sync::mpsc::Receiver<PublicKey>, RelayError> {
    use crate::mesh::{KEY_PACKAGE_IDENTIFIER, KEY_PACKAGE_KIND};

    let client = connect_client(relays).await?;
    let filter = Filter::new()
        .kind(Kind::Custom(KEY_PACKAGE_KIND))
        .identifier(KEY_PACKAGE_IDENTIFIER)
        .pubkey(target);
    client.subscribe(filter).await?;

    let (tx, rx) = tokio::sync::mpsc::channel(16);
    tokio::spawn(async move {
        let mut notifications = client.notifications();
        while let Some(notification) = notifications.next().await {
            if let ClientNotification::Event { event, .. } = notification {
                // Bounded channel: a slow confirmer drops duplicates rather
                // than buffering unbounded; the phone republishes on retry.
                let _ = tx.try_send(event.pubkey);
            }
        }
    });
    Ok(rx)
}

/// Presence tracking for mesh-mates: when each member's advert was last
/// received. Keyed by hex npub (the mesh roster's native form), so the
/// client and UIs never need the nostr types to query it. Held by the
/// caller (the node's client), so relay reconnects never wipe it - only
/// fresh arrivals update it, and a member with no recent advert simply
/// reads as offline rather than erroring.
pub struct Presence {
    last_seen: std::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>,
}

impl Presence {
    pub fn new() -> Self {
        Self {
            last_seen: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Record an advert arrival for `npub` (hex) as of `at`.
    pub fn note_at(&self, npub: &str, at: std::time::Instant) {
        self.last_seen
            .lock()
            .expect("presence map")
            .insert(npub.to_string(), at);
    }

    /// Record an advert arrival for `npub` (hex) as of now.
    pub fn note(&self, npub: &str) {
        self.note_at(npub, std::time::Instant::now());
    }

    /// Seconds since `npub`'s (hex) last advert arrival; `None` = never seen.
    pub fn age_secs(&self, npub: &str) -> Option<u64> {
        self.last_seen
            .lock()
            .expect("presence map")
            .get(npub)
            .map(|t| t.elapsed().as_secs())
    }

    /// Online = an advert arrived within the advert TTL
    /// ([`crate::advert::ADVERT_TTL_SECS`]). A member with no recent advert is
    /// offline, never an error.
    pub fn is_online(&self, npub: &str) -> bool {
        matches!(self.age_secs(npub), Some(age) if age < crate::advert::ADVERT_TTL_SECS)
    }
}

impl Default for Presence {
    fn default() -> Self {
        Self::new()
    }
}

/// Subscribe to noscat adverts (kind 37195) on the relays and forward each
/// valid advert's author (hex npub) to the returned channel; the stream
/// lives until the receiver is dropped. This is the node's presence feed:
/// every arrival is recorded in the caller's [`Presence`] map, and callers
/// filter to mesh-mates at query time, so devices that join mid-run show up
/// without resubscribing. Reconnects are handled inside (a dropped relay
/// stream or an unreachable relay just restarts the subscription after a
/// short back off), so the caller's last-seen map survives relay churn
/// untouched.
pub async fn watch_adverts_presence(
    relays: &[String],
) -> Result<tokio::sync::mpsc::Receiver<String>, RelayError> {
    if relays.is_empty() {
        return Err(RelayError::NoRelays);
    }
    let filter = Filter::new()
        .kind(Kind::Custom(ADVERT_KIND))
        .identifier(ADVERT_IDENTIFIER);
    let relays = relays.to_vec();
    let (tx, rx) = tokio::sync::mpsc::channel(64);
    tokio::spawn(async move {
        while !tx.is_closed() {
            let client = match connect_client(&relays).await {
                Ok(c) => c,
                Err(e) => {
                    for r in &relays {
                        note_relay_failure(r, &e.to_string());
                    }
                    tracing::warn!(%e, "presence: relays unreachable; retrying");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
            };
            if let Err(e) = client.subscribe(filter.clone()).await {
                for r in &relays {
                    note_relay_failure(r, &e.to_string());
                }
                tracing::warn!(%e, "presence: subscribe failed; retrying");
                client.shutdown().await;
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
            let mut notifications = client.notifications();
            loop {
                match notifications.next().await {
                    Some(ClientNotification::Event { event, .. }) => {
                        match Advert::from_event(&event, Timestamp::now()) {
                            Ok(a) => {
                                if tx.try_send(a.npub.to_string()).is_err() {
                                    return; // receiver gone: stop watching
                                }
                            }
                            Err(e) => {
                                tracing::debug!(%e, "presence: ignoring invalid advert")
                            }
                        }
                    }
                    Some(_) => {}
                    None => break, // relay stream ended: resubscribe
                }
            }
            client.shutdown().await;
            if tx.is_closed() {
                return;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
    Ok(rx)
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
    const B: &str = "d5b9b0b6c3d9a4b0c1f2e3d4c5b6a79881726354435261728394a5b6c7d8e9f0";

    #[test]
    fn presence_tracks_arrivals() {
        let p = Presence::new();
        assert!(!p.is_online(A));
        assert_eq!(p.age_secs(A), None);
        p.note(A);
        assert_eq!(p.age_secs(A), Some(0));
        assert!(p.is_online(A));
    }

    #[test]
    fn presence_ages_out_after_the_advert_ttl() {
        let p = Presence::new();
        // Arrived just past the TTL window: offline, but still remembered.
        p.note_at(
            A,
            std::time::Instant::now() - Duration::from_secs(crate::advert::ADVERT_TTL_SECS + 5),
        );
        assert!(!p.is_online(A));
        assert!(p.age_secs(A).is_some());
        // Still inside the window: online.
        p.note_at(
            A,
            std::time::Instant::now() - Duration::from_secs(crate::advert::ADVERT_TTL_SECS - 5),
        );
        assert!(p.is_online(A));
    }

    #[test]
    fn presence_never_errors_on_unknown_members() {
        let p = Presence::new();
        p.note(A);
        // An unknown member reads as offline with no age, no panic.
        assert_eq!(p.age_secs(B), None);
        assert!(!p.is_online(B));
        // And the known member is unaffected.
        assert!(p.is_online(A));
    }

    #[test]
    fn presence_survives_reconnect_shaped_updates() {        // The watcher re-sends the same author after every resubscribe;
        // recording it again must refresh, not corrupt, the entry.
        let p = Presence::new();
        p.note(A);
        p.note_at(
            A,
            std::time::Instant::now() - Duration::from_secs(1200),
        );
        assert_eq!(p.age_secs(A), Some(1200));
        p.note(A);
        assert_eq!(p.age_secs(A), Some(0));
        assert!(p.is_online(A));
    }

    /// A rate-limited relay cools down exponentially and healthy_relays
    /// skips it while it cools; success resets everything; and the filter
    /// never empties the list (going dark is worse than a re-hit 429).
    #[test]
    fn rate_limited_relays_back_off_and_recover() {
        let r = "wss://backoff.test";
        let ok = "wss://healthy.test".to_string();
        let relays = vec![r.to_string(), ok.clone()];

        assert_eq!(healthy_relays(&relays), relays, "no history: nothing filtered");

        // One 429: 30s cool-down, the healthy relay is preferred.
        note_relay_failure(r, "HTTP 429 Too Many Requests");
        assert_eq!(healthy_relays(&relays), vec![ok.clone()]);

        // Repeated 429s double the cool-down (30s, 60s, 120s...), capped.
        note_relay_failure(r, "429");
        note_relay_failure(r, "429");
        assert_eq!(healthy_relays(&relays), vec![ok.clone()]);

        // A rate-limit-free failure keeps the streak but starts no
        // cool-down.
        note_relay_success(r);
        note_relay_failure(r, "connection reset");
        assert_eq!(healthy_relays(&relays), relays);

        // Success clears the streak: a later 429 backs off from base.
        note_relay_success(r);
        note_relay_failure(r, "429");
        assert_eq!(healthy_relays(&relays), vec![ok.clone()]);

        // All relays cooling down: never go dark, return them all.
        note_relay_failure(&ok, "429");
        assert_eq!(healthy_relays(&relays), relays);
    }
}
