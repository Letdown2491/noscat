//! Overlay adverts: signed, expiring endpoint advertisements published to Nostr
//! relays so peers can discover where a node is reachable.
//!
//! This mirrors FIPS's kind-37195 overlay advert (research/fips.md §3): a
//! parameterized replaceable event with a fixed `d` tag, JSON payload, and a
//! NIP-40 expiration. Relays see *that* a node advertises, not who talks to it —
//! traversal signaling (the sensitive part) is a separate, gift-wrapped channel.

use nostr::prelude::*;
use serde::{Deserialize, Serialize};

use crate::identity::Identity;

/// Kind for noscat overlay adverts: parameterized replaceable (30000–39999),
/// following the FIPS advert convention (kind 37195).
pub const ADVERT_KIND: u16 = 37195;

/// Fixed `d` tag value scoping all noscat adverts to one replaceable slot per node.
pub const ADVERT_IDENTIFIER: &str = "noscat-overlay-v1";

/// How a node is reachable. Mirrors the FIPS `OverlayAdvert` endpoint shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Udp,
    Tcp,
}

/// A reachable endpoint: transport plus a socket address string (`ip:port` or host:port).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    pub transport: Transport,
    pub addr: String,
}

/// JSON payload carried in the advert event content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdvertPayload {
    pub endpoints: Vec<Endpoint>,
}

/// A parsed overlay advert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advert {
    /// The advertising node (event author).
    pub npub: PublicKey,
    pub endpoints: Vec<Endpoint>,
    /// Unix seconds after which this advert should be considered stale.
    pub expires_at: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum AdvertError {
    #[error("event is not a noscat advert (kind {0})")]
    WrongKind(u16),
    #[error("event is not signed by its author")]
    InvalidSignature,
    #[error("missing or wrong `d` identifier tag")]
    BadIdentifier,
    #[error("missing expiration tag")]
    MissingExpiration,
    #[error("advert is expired (unix {0})")]
    Expired(u64),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Sign(#[from] nostr::error::Error),
}

impl Advert {
    /// Build and sign a replaceable advert event for these endpoints.
    pub fn event(
        identity: &Identity,
        endpoints: Vec<Endpoint>,
        ttl_secs: u64,
        now: Timestamp,
    ) -> Result<Event, AdvertError> {
        let payload = AdvertPayload { endpoints };
        let expires_at = now.as_secs().saturating_add(ttl_secs);
        let json = serde_json::to_string(&payload)?;
        EventBuilder::new(Kind::Custom(ADVERT_KIND), json)
            .tags([
                Tag::identifier(ADVERT_IDENTIFIER),
                Tag::expiration(Timestamp::from(expires_at)),
            ])
            .finalize(identity.keys())
            .map_err(AdvertError::Sign)
    }

    /// Parse and validate an advert from a relay event.
    pub fn from_event(event: &Event, now: Timestamp) -> Result<Self, AdvertError> {
        let kind_u16 = u16::from(event.kind);
        if kind_u16 != ADVERT_KIND {
            return Err(AdvertError::WrongKind(kind_u16));
        }
        if event.verify().is_err() {
            return Err(AdvertError::InvalidSignature);
        }
        // Fixed replaceable slot: exactly one `d` tag with our identifier.
        let identifier = event
            .tags
            .iter()
            .find(|t| t.kind() == "d")
            .and_then(|t| t.content());
        if identifier != Some(ADVERT_IDENTIFIER) {
            return Err(AdvertError::BadIdentifier);
        }
        let expires_at = event
            .tags
            .iter()
            .find(|t| t.kind() == "expiration")
            .and_then(|t| t.content())
            .and_then(|v| v.parse::<u64>().ok())
            .ok_or(AdvertError::MissingExpiration)?;
        if expires_at <= now.as_secs() {
            return Err(AdvertError::Expired(expires_at));
        }
        let payload: AdvertPayload = serde_json::from_str(&event.content)?;
        Ok(Self {
            npub: event.pubkey,
            endpoints: payload.endpoints,
            expires_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(transport: Transport, addr: &str) -> Endpoint {
        Endpoint {
            transport,
            addr: addr.to_string(),
        }
    }

    #[test]
    fn advert_round_trips_through_event() {
        let id = Identity::generate();
        let now = Timestamp::now();
        let event = Advert::event(
            &id,
            vec![endpoint(Transport::Udp, "203.0.113.7:41641")],
            3600,
            now,
        )
        .expect("sign advert");

        let parsed = Advert::from_event(&event, now).expect("parse advert");
        assert_eq!(parsed.npub, id.public_key());
        assert_eq!(
            parsed.endpoints,
            vec![endpoint(Transport::Udp, "203.0.113.7:41641")]
        );
        assert_eq!(parsed.expires_at, now.as_secs() + 3600);
    }

    #[test]
    fn rejects_wrong_kind() {
        let id = Identity::generate();
        let event = EventBuilder::new(Kind::TextNote, "not an advert")
            .finalize(id.keys())
            .expect("sign");
        assert!(matches!(
            Advert::from_event(&event, Timestamp::now()),
            Err(AdvertError::WrongKind(_))
        ));
    }

    #[test]
    fn rejects_expired_advert() {
        let id = Identity::generate();
        let now = Timestamp::now();
        // TTL of 1 second, but claim "now" is far in the future.
        let event = Advert::event(&id, vec![], 1, now).expect("sign advert");
        let later = Timestamp::from(now.as_secs() + 120);
        assert!(matches!(
            Advert::from_event(&event, later),
            Err(AdvertError::Expired(_))
        ));
    }
}
