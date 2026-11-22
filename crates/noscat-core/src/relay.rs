//! Relay plumbing: publish and watch overlay adverts over real Nostr relays.
//!
//! Relays are the discovery channel only — they carry signed, public advert
//! events (kind 37195 pattern). Tunnel traffic never touches them.

use std::time::Duration;

use nostr::prelude::*;
use nostr_sdk::prelude::*;
use tokio::time::timeout;

use crate::advert::{Advert, AdvertError, Endpoint, ADVERT_IDENTIFIER, ADVERT_KIND};
use crate::identity::Identity;

/// Relays used when the operator does not configure any. Overridable with
/// `--relay`. Chosen for uptime; nos.lol carried every message in testing
/// while others flaked.
pub const DEFAULT_RELAYS: &[&str] = &["wss://nos.lol", "wss://relay.primal.net", "wss://nostr.mom"];

/// How long to wait for relay connections before giving up.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long to wait for a matching advert before giving up.
const FETCH_WAIT: Duration = Duration::from_secs(15);

/// A connected client over `relays` — the one place relay plumbing is set
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
    ttl_secs: u64,
    relays: &[String],
) -> Result<(), RelayError> {
    if relays.is_empty() {
        return Err(RelayError::NoRelays);
    }
    let event = Advert::event(identity, endpoints, noise_pub, ttl_secs, Timestamp::now())?;

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
/// disconnects. `None` means "nothing valid arrived in time".
pub async fn fetch_advert_for(
    relays: &[String],
    noise_key: Option<[u8; 32]>,
    npub: Option<PublicKey>,
) -> Result<Option<Advert>, RelayError> {
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
                return Some(advert);
            }
            None
        },
    )
    .await
    .unwrap_or(None);

    client.shutdown().await;
    Ok(found)
}

/// Fetch a device's published MLS key package (tailnet kind 30443) by author.
///
/// `None` means "nothing arrived in time" — usually the device has not run
/// `noscat tailnet publish` yet.
pub async fn fetch_key_package(
    relays: &[String],
    device: PublicKey,
) -> Result<Option<Event>, RelayError> {
    use crate::tailnet::{KEY_PACKAGE_IDENTIFIER, KEY_PACKAGE_KIND};

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
