//! Relay plumbing shared by the control plane: connecting to relays with
//! per-relay timeouts, rate-limit back-off, and presence bookkeeping.
//!
//! Relays carry only the Marmot group traffic (kind 445 group events, 1059
//! gift-wrapped Welcomes, 30443 key packages, 10050 and 10002 relay lists).
//! Endpoint adverts travel inside the group, never in public (ADR 0006).

use std::time::Duration;

use nostr_sdk::prelude::*;


/// Relays used when the operator does not configure any. Overridable with
/// `--relay`. Currently ONE relay: two of the three defaults have proven
/// unreachable from real phone networks (a black-holed path fails every
/// relay op - see issue #16 - and with one healthy relay left the fan-out
/// buys nothing). A relay that rate-limits us is backed off (see
/// [`note_relay_failure`]) rather than hammered. Re-broaden this list only
/// with relays verified reachable from mobile paths.
pub const DEFAULT_RELAYS: &[&str] = &["wss://relay.primal.net"];

/// How long to wait for a fetch (key packages, relay lists) to finish.
pub(crate) const FETCH_WAIT: Duration = Duration::from_secs(15);

/// A member reads as online while its last advert is younger than this.
/// Devices re-send their advert well inside it.
pub const PRESENCE_TTL_SECS: u64 = 600;

/// The default relay set as owned strings: for surfaces (FFI mesh helpers,
/// CLI defaults) that resolve relays without a config in hand.
pub fn default_relays() -> Vec<String> {
    DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect()
}

#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("no relays configured")]
    NoRelays,    #[error("timed out connecting to relays")]
    ConnectTimeout,
    #[error(transparent)]
    Sdk(#[from] nostr_sdk::error::Error),
    #[error(transparent)]
    Sign(#[from] nostr::error::Error),
}

/// The cool-down for a relay that failed once: doubled per consecutive
/// failure, capped, so a persistently rate-limiting relay is retried
/// rarely instead of being hammered.
const BACKOFF_BASE: Duration = Duration::from_secs(30);
const BACKOFF_CAP: u32 = 5;

/// Ceiling on the node's presence map (distinct npubs tracked): adversarial
/// advert floods must not grow it without end on a long-running `up`.
const PRESENCE_CAP: usize = 4096;

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
    let mut health = relay_health().lock().unwrap_or_else(|p| p.into_inner());
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
    let mut health = relay_health().lock().unwrap_or_else(|p| p.into_inner());
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
    let health = relay_health().lock().unwrap_or_else(|p| p.into_inner());
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

    /// Record an advert arrival for `npub` (hex) as of `at`. Bounded: the
    /// node feeds every valid advert on the relays, so a flood of
    /// distinct npubs must not grow the map without end on a long-running
    /// process. Entries older than the advert TTL already read as
    /// offline - expired ones are dropped; past that, the oldest evicts.
    pub fn note_at(&self, npub: &str, at: std::time::Instant) {
        let mut map = self.last_seen.lock().unwrap_or_else(|p| p.into_inner());
        if !map.contains_key(npub) && map.len() >= PRESENCE_CAP {
            let ttl = std::time::Duration::from_secs(PRESENCE_TTL_SECS);
            map.retain(|_, t| t.elapsed() < ttl);
            if map.len() >= PRESENCE_CAP {
                let oldest = map
                    .iter()
                    .min_by_key(|(_, t)| *t)
                    .map(|(k, _)| k.clone());
                if let Some(k) = oldest {
                    map.remove(&k);
                }
            }
        }
        map.insert(npub.to_string(), at);
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
    /// ([`PRESENCE_TTL_SECS`]). A member with no recent advert is
    /// offline, never an error.
    pub fn is_online(&self, npub: &str) -> bool {
        matches!(self.age_secs(npub), Some(age) if age < PRESENCE_TTL_SECS)
    }
}

impl Default for Presence {
    fn default() -> Self {
        Self::new()
    }
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
            std::time::Instant::now() - Duration::from_secs(PRESENCE_TTL_SECS + 5),
        );
        assert!(!p.is_online(A));
        assert!(p.age_secs(A).is_some());
        // Still inside the window: online.
        p.note_at(
            A,
            std::time::Instant::now() - Duration::from_secs(PRESENCE_TTL_SECS - 5),
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
