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
/// `--relay`. Chosen for uptime.
pub const DEFAULT_RELAYS: &[&str] = &["wss://relay.primal.net", "wss://nostr.mom"];

/// How long to wait for relay connections before giving up.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long to wait for a matching advert before giving up.
const FETCH_WAIT: Duration = Duration::from_secs(15);

/// A connected client over `relays` - the one place relay plumbing is set
/// up. Callers that publish/fetch shut the client down when done; the
/// long-lived `watch_*` streams just drop it.
pub(crate) async fn connect_client(relays: &[String]) -> Result<Client, RelayError> {
    if relays.is_empty() {
        return Err(RelayError::NoRelays);
    }
    let client = Client::new();
    for relay in relays {
        client.add_relay(relay).await?;
    }
    let _ = timeout(CONNECT_TIMEOUT, client.connect().and_wait(CONNECT_TIMEOUT))
        .await
        .map_err(|_| RelayError::ConnectTimeout)?;
    Ok(client)
}

#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("no relays configured")]
    NoRelays,
    #[error("timed out connecting to relays")]
    ConnectTimeout,
    #[error(transparent)]
    Sdk(#[from] nostr_sdk::error::Error),
    #[error(transparent)]
    Advert(#[from] AdvertError),
    #[error(transparent)]
    Sign(#[from] nostr::error::Error),
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
        if at.elapsed() < ADVERT_CACHE_TTL {
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
