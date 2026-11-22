//! Traversal signaling: gift-wrapped (NIP-59) endpoint exchange, following
//! the FIPS design's kind-21059 pattern.
//!
//! The public advert carries a node's *stationary* addresses. The ephemeral
//! half — the port mappings each side just opened for this specific session —
//! travels through sealed (kind 21059 rumor) gift wraps addressed to the
//! peer's npub, so relays see only opaque envelopes and nobody else learns
//! where either node is reachable.

use std::time::Duration;

use nostr::nips::nip59::{extract_rumor, GiftWrapBuilder};
use nostr::prelude::*;
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::advert::Endpoint;
use crate::identity::Identity;

/// Kind of the *rumor* inside the gift wrap: a FIPS-style traversal request.
pub const TRAVERSAL_KIND: u16 = 21059;

/// Gift wraps live a week; they are session-scoped in practice.
const GIFT_WRAP_TTL: Duration = Duration::from_secs(7 * 24 * 3600);

#[derive(Debug, thiserror::Error)]
pub enum TraversalError {
    #[error("no relays configured")]
    NoRelays,
    #[error(transparent)]
    Sdk(#[from] nostr_sdk::error::Error),
    #[error(transparent)]
    Nostr(#[from] nostr::error::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// Payload sealed inside the gift wrap: "here is who I am on the data plane
/// and where I am (currently) reachable — punch me".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraversalPayload {
    /// Sender's Noise static public key, hex.
    pub noise_pub: String,
    /// Sender's candidate endpoints, best first (LAN, then reflexive).
    pub endpoints: Vec<Endpoint>,
}

/// Seal and publish our traversal request to `target`'s npub.
pub async fn send_traversal(
    identity: &Identity,
    target: PublicKey,
    noise_pub: [u8; 32],
    endpoints: Vec<Endpoint>,
    relays: &[String],
) -> Result<(), TraversalError> {
    if relays.is_empty() {
        return Err(TraversalError::NoRelays);
    }
    let payload = serde_json::to_string(&TraversalPayload {
        noise_pub: hex::encode(noise_pub),
        endpoints,
    })?;
    let rumor = UnsignedEvent::new(
        identity.public_key(),
        Timestamp::now(),
        Kind::Custom(TRAVERSAL_KIND),
        [],
        payload,
    );
    let gift_wrap = GiftWrapBuilder::new(target, rumor)
        .expiration(GIFT_WRAP_TTL)
        .finalize(identity.keys())?;

    let client = Client::new();
    for relay in relays {
        client.add_relay(relay).await?;
    }
    client.connect().and_wait(Duration::from_secs(8)).await;
    client.send_event(&gift_wrap).await?;
    client.shutdown().await;
    Ok(())
}

/// Watch for gift wraps addressed to us whose rumor is a traversal request.
///
/// For each valid one, delivers (sender's npub, payload) on `tx` and keeps
/// running until the channel closes or the client shuts down.
pub async fn watch_traversal(
    identity: Identity,
    relays: Vec<String>,
    tx: mpsc::Sender<(PublicKey, TraversalPayload)>,
) -> Result<(), TraversalError> {
    if relays.is_empty() {
        return Err(TraversalError::NoRelays);
    }
    let client = Client::new();
    for relay in relays {
        client.add_relay(relay).await?;
    }
    client.connect().and_wait(Duration::from_secs(8)).await;
    let filter = Filter::new().kind(Kind::GiftWrap).pubkey(identity.public_key());
    client.subscribe(filter).await?;

    let mut notifications = client.notifications();
    while let Some(notification) = notifications.next().await {
        let ClientNotification::Event { event, .. } = notification else {
            continue;
        };
        let Ok(unwrapped) = extract_rumor(identity.keys(), &event) else {
            tracing::debug!("ignoring undecryptable gift wrap");
            continue;
        };
        if u16::from(unwrapped.rumor.kind) != TRAVERSAL_KIND {
            continue;
        }
        let Ok(payload) = serde_json::from_str::<TraversalPayload>(&unwrapped.rumor.content) else {
            tracing::debug!("gift wrap rumor is not a traversal payload");
            continue;
        };
        if tx.send((unwrapped.sender, payload)).await.is_err() {
            break; // consumer gone; shut down
        }
    }
    Ok(())
}

/// Watch for gift-wrapped tailnet messages (kind 30444 rumors: MLS commits
/// and Welcomes). Delivers (sender, rumor content) on `tx`.
pub async fn watch_tailnet(
    identity: Identity,
    relays: Vec<String>,
    tx: mpsc::Sender<(PublicKey, String)>,
) -> Result<(), TraversalError> {
    use crate::tailnet::TAILNET_KIND;

    if relays.is_empty() {
        return Err(TraversalError::NoRelays);
    }
    let client = Client::new();
    for relay in relays {
        client.add_relay(relay).await?;
    }
    client.connect().and_wait(Duration::from_secs(8)).await;
    let filter = Filter::new().kind(Kind::GiftWrap).pubkey(identity.public_key());
    client.subscribe(filter).await?;

    let mut notifications = client.notifications();
    while let Some(notification) = notifications.next().await {
        let ClientNotification::Event { event, .. } = notification else {
            continue;
        };
        let Ok(unwrapped) = extract_rumor(identity.keys(), &event) else {
            tracing::debug!("ignoring undecryptable gift wrap");
            continue;
        };
        if u16::from(unwrapped.rumor.kind) != TAILNET_KIND {
            continue;
        }
        if tx.send((unwrapped.sender, unwrapped.rumor.content)).await.is_err() {
            break; // consumer gone; shut down
        }
    }
    Ok(())
}
