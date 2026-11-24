//! The Marmot Nostr transport shapes (transports/nostr.md) that a noscat
//! mesh uses: kind 445 group events, kind 30443 key packages, kind 444
//! Welcome rumors in NIP-59 gift wraps, kind 10050 inbox lists, and the
//! unsigned inner app event (foundation/application-messages.md).
//!
//! Pure functions over bytes and events; MLS types stay in the parent
//! module.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use nostr::prelude::*;
use rand::RngCore as _;

/// Kind 445: an MLS message encrypted under the epoch's group-event key.
pub const GROUP_KIND: u16 = 445;
/// Kind 444: the Welcome rumor inside a gift wrap.
pub const WELCOME_KIND: u16 = 444;
/// Kind 30443: a device's published key package.
pub const KEY_PACKAGE_KIND: u16 = 30443;
/// Kind 10050: NIP-17 inbox relays, where Welcomes are delivered.
pub const INBOX_RELAYS_KIND: u16 = 10050;
/// Kind 10002: NIP-65 relay list, where key packages are published.
pub const RELAY_LIST_KIND: u16 = 10002;

/// A malformed transport object. Never carries input bytes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("transport: {0}")]
pub struct TransportError(pub String);

fn bad<T>(msg: impl Into<String>) -> Result<T, TransportError> {
    Err(TransportError(msg.into()))
}

/// All tags named `name`, as value lists.
fn tags_named<'a>(event: &'a Event, name: &str) -> Vec<&'a [String]> {
    event
        .tags
        .iter()
        .map(Tag::as_slice)
        .filter(|t| t.first().is_some_and(|n| n == name))
        .map(|t| &t[1..])
        .collect()
}

/// The single value of a required singleton tag.
fn singleton<'a>(event: &'a Event, name: &str) -> Result<&'a str, TransportError> {
    match tags_named(event, name).as_slice() {
        [[v]] => Ok(v.as_str()),
        _ => bad(format!("tag {name} must appear once with one value")),
    }
}

// ---- kind 445 ----------------------------------------------------------

/// Seal MLS bytes into a kind 445 event signed by a fresh ephemeral key.
pub fn seal_group_event(
    group_event_key: &[u8; 32],
    nostr_group_id: &[u8; 32],
    mls_bytes: &[u8],
) -> Result<Event, TransportError> {
    let cipher = ChaCha20Poly1305::new(group_event_key.into());
    let mut nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), mls_bytes)
        .map_err(|_| TransportError("encrypt failed".into()))?;
    let mut payload = Vec::with_capacity(12 + ct.len());
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&ct);
    let ephemeral = Keys::generate();
    EventBuilder::new(Kind::Custom(GROUP_KIND), B64.encode(payload))
        .tag(Tag::parse(["h", &hex::encode(nostr_group_id)]).map_err(|e| TransportError(e.to_string()))?)
        .finalize(&ephemeral)
        .map_err(|e| TransportError(e.to_string()))
}

/// Validate a kind 445 envelope and return its routing id and the raw
/// `nonce || ciphertext` payload. Checks signature, kind, and the exact tag
/// set (one `h`, optionally one `expiration`, nothing else).
pub fn open_group_envelope(event: &Event) -> Result<([u8; 32], Vec<u8>), TransportError> {
    if event.kind != Kind::Custom(GROUP_KIND) {
        return bad("not kind 445");
    }
    event.verify().map_err(|_| TransportError("bad event signature".into()))?;
    for t in event.tags.iter() {
        match t.as_slice().first().map(String::as_str) {
            Some("h" | "expiration") => {}
            _ => return bad("kind 445 carries an unexpected tag"),
        }
    }
    let h = singleton(event, "h")?;
    let mut id = [0u8; 32];
    if h.len() != 64 || h != h.to_lowercase() || hex::decode_to_slice(h, &mut id).is_err() {
        return bad("h tag is not 64 lowercase hex");
    }
    let payload = B64
        .decode(event.content.as_bytes())
        .map_err(|_| TransportError("content is not base64".into()))?;
    if payload.len() < 28 {
        return bad("content shorter than nonce plus tag");
    }
    Ok((id, payload))
}

/// Try to decrypt a 445 payload with one group-event key.
#[must_use]
pub fn decrypt_group_payload(group_event_key: &[u8; 32], payload: &[u8]) -> Option<Vec<u8>> {
    if payload.len() < 28 {
        return None;
    }
    let cipher = ChaCha20Poly1305::new(group_event_key.into());
    cipher.decrypt(Nonce::from_slice(&payload[..12]), &payload[12..]).ok()
}

// ---- kind 30443 --------------------------------------------------------

/// Everything needed to sign a key package event.
pub struct KeyPackageTags<'a> {
    /// The device's publication slot id (32 random bytes, kept for life).
    pub slot: &'a [u8; 32],
    /// The KeyPackageRef.
    pub key_package_ref: &'a [u8],
    pub ciphersuite: u16,
    pub extensions: &'a [u16],
    pub proposals: &'a [u16],
    pub components: &'a [u16],
}

fn id_list(name: &str, ids: &[u16]) -> Result<Tag, TransportError> {
    let mut v = vec![name.to_string()];
    v.extend(ids.iter().map(|i| format!("0x{i:04x}")));
    Tag::parse(v).map_err(|e| TransportError(e.to_string()))
}

/// Build and sign a kind 30443 key package event.
pub fn key_package_event(
    keys: &Keys,
    mls_message_bytes: &[u8],
    t: &KeyPackageTags<'_>,
) -> Result<Event, TransportError> {
    let p = |v: &[&str]| Tag::parse(v.iter().copied()).map_err(|e| TransportError(e.to_string()));
    EventBuilder::new(Kind::Custom(KEY_PACKAGE_KIND), B64.encode(mls_message_bytes))
        .tag(p(&["d", &hex::encode(t.slot)])?)
        .tag(p(&["mls_protocol_version", "1.0"])?)
        .tag(p(&["i", &hex::encode(t.key_package_ref)])?)
        .tag(id_list("mls_ciphersuite", &[t.ciphersuite])?)
        .tag(id_list("mls_extensions", t.extensions)?)
        .tag(id_list("mls_proposals", t.proposals)?)
        .tag(id_list("app_components", t.components)?)
        .tag(p(&["client", "noscat"])?)
        .finalize(keys)
        .map_err(|e| TransportError(e.to_string()))
}

/// A key package event that passed the transport checks.
pub struct KeyPackageEnvelope {
    /// Decoded `MLSMessage` bytes (`mls_key_package` wire format).
    pub mls_bytes: Vec<u8>,
    /// The claimed KeyPackageRef from the `i` tag; the caller checks it
    /// against the decoded package.
    pub key_package_ref: Vec<u8>,
    /// The publication slot.
    pub slot: [u8; 32],
}

/// Validate a kind 30443 event's signature, tag cardinality and encodings.
pub fn open_key_package_event(event: &Event) -> Result<KeyPackageEnvelope, TransportError> {
    if event.kind != Kind::Custom(KEY_PACKAGE_KIND) {
        return bad("not kind 30443");
    }
    event.verify().map_err(|_| TransportError("bad event signature".into()))?;
    let d = singleton(event, "d")?;
    let mut slot = [0u8; 32];
    if d.len() != 64 || d != d.to_lowercase() || hex::decode_to_slice(d, &mut slot).is_err() {
        return bad("d tag is not 64 lowercase hex");
    }
    if singleton(event, "mls_protocol_version")? != "1.0" {
        return bad("unsupported mls_protocol_version");
    }
    let i = singleton(event, "i")?;
    let key_package_ref = hex::decode(i).map_err(|_| TransportError("i tag is not hex".into()))?;
    for name in ["mls_ciphersuite", "mls_extensions", "mls_proposals", "app_components"] {
        let lists = tags_named(event, name);
        let [list] = lists.as_slice() else {
            return bad(format!("{name} must appear exactly once"));
        };
        if list.is_empty() {
            return bad(format!("{name} is empty"));
        }
        let mut seen = std::collections::BTreeSet::new();
        for v in *list {
            let ok = v.len() == 6
                && v.starts_with("0x")
                && v[2..].chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c));
            if !ok || !seen.insert(v) {
                return bad(format!("{name} has a malformed or repeated id"));
            }
        }
    }
    if !tags_named(event, "app_components")[0].iter().any(|v| v == "0x8009") {
        return bad("app_components does not list 0x8009");
    }
    let mls_bytes = B64
        .decode(event.content.as_bytes())
        .map_err(|_| TransportError("content is not base64".into()))?;
    Ok(KeyPackageEnvelope {
        mls_bytes,
        key_package_ref,
        slot,
    })
}

// ---- Welcomes ----------------------------------------------------------

/// Gift-wrap a Welcome for one consumed key package.
pub fn wrap_welcome(
    inviter: &Keys,
    invitee: &PublicKey,
    welcome_bytes: &[u8],
    key_package_event_id: &EventId,
    relays: &[String],
) -> Result<Event, TransportError> {
    let mut relays_tag = vec!["relays".to_string()];
    relays_tag.extend(relays.iter().cloned());
    let rumor = EventBuilder::new(Kind::Custom(WELCOME_KIND), B64.encode(welcome_bytes))
        .tag(Tag::parse(["e", &key_package_event_id.to_hex()]).map_err(|e| TransportError(e.to_string()))?)
        .tag(Tag::parse(relays_tag).map_err(|e| TransportError(e.to_string()))?)
        .finalize_unsigned(inviter.public_key());
    nostr::nips::nip59::GiftWrapBuilder::new(*invitee, rumor)
        .finalize(inviter)
        .map_err(|e| TransportError(e.to_string()))
}

/// An unwrapped Welcome, not yet processed by MLS.
#[derive(Debug, Clone)]
pub struct WelcomeEnvelope {
    /// The inviter's account as authenticated by the NIP-59 seal.
    pub sender: PublicKey,
    /// `MLSMessage` bytes with `mls_welcome` wire format.
    pub mls_bytes: Vec<u8>,
    /// The key package event the Welcome claims to consume.
    pub key_package_event_id: EventId,
    /// Relays where the new member should fetch group messages.
    pub relays: Vec<String>,
}

/// Unwrap a kind 1059 gift wrap addressed to `keys` and check the kind 444
/// rumor's shape. Returns `Ok(None)` for a gift wrap that holds something
/// other than a Welcome.
pub fn unwrap_welcome(keys: &Keys, gift_wrap: &Event) -> Result<Option<WelcomeEnvelope>, TransportError> {
    if gift_wrap.kind != Kind::GiftWrap {
        return bad("not a gift wrap");
    }
    let to_me = gift_wrap
        .tags
        .iter()
        .filter_map(|t| match t.as_slice() {
            [n, v] if n == "p" => Some(v.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    if to_me != [keys.public_key().to_hex().as_str()] {
        return bad("gift wrap is not addressed to this device");
    }
    let unwrapped = nostr::nips::nip59::extract_rumor(keys, gift_wrap)
        .map_err(|e| TransportError(format!("unwrap failed: {e}")))?;
    let rumor = unwrapped.rumor;
    if rumor.kind != Kind::Custom(WELCOME_KIND) {
        return Ok(None);
    }
    if rumor.pubkey != unwrapped.sender {
        return bad("rumor author is not the seal signer");
    }
    let es: Vec<&[String]> = rumor
        .tags
        .iter()
        .map(Tag::as_slice)
        .filter(|t| t.first().is_some_and(|n| n == "e"))
        .collect();
    let [[_, e]] = es.as_slice() else {
        return bad("welcome needs exactly one e tag with one value");
    };
    let key_package_event_id = EventId::from_hex(e).map_err(|_| TransportError("e tag is not an event id".into()))?;
    let rs: Vec<&[String]> = rumor
        .tags
        .iter()
        .map(Tag::as_slice)
        .filter(|t| t.first().is_some_and(|n| n == "relays"))
        .collect();
    let [r] = rs.as_slice() else {
        return bad("welcome needs exactly one relays tag");
    };
    let relays: Vec<String> = r[1..].to_vec();
    if relays.is_empty() || relays.iter().any(|u| !super::codec::valid_relay_url(u)) {
        return bad("welcome relays tag is empty or malformed");
    }
    let mls_bytes = B64
        .decode(rumor.content.as_bytes())
        .map_err(|_| TransportError("welcome content is not base64".into()))?;
    Ok(Some(WelcomeEnvelope {
        sender: unwrapped.sender,
        mls_bytes,
        key_package_event_id,
        relays,
    }))
}

/// A NIP-17 inbox relay list (kind 10050) or NIP-65 relay list (kind 10002)
/// for this device.
pub fn relay_list_event(keys: &Keys, kind: u16, relays: &[String]) -> Result<Event, TransportError> {
    let tag_name = if kind == INBOX_RELAYS_KIND { "relay" } else { "r" };
    let mut b = EventBuilder::new(Kind::Custom(kind), "");
    for r in relays {
        b = b.tag(Tag::parse([tag_name, r.as_str()]).map_err(|e| TransportError(e.to_string()))?);
    }
    b.finalize(keys).map_err(|e| TransportError(e.to_string()))
}

// ---- inner app events --------------------------------------------------

/// A Marmot app event: an unsigned Nostr-shaped payload inside MLS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppEvent {
    pub id: EventId,
    pub pubkey: PublicKey,
    pub created_at: u64,
    pub kind: u16,
    pub tags: Vec<Vec<String>>,
    pub content: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AppEventWire {
    id: String,
    pubkey: String,
    created_at: u64,
    kind: u16,
    tags: Vec<Vec<String>>,
    content: String,
}

fn tags_of(tags: &[Vec<String>]) -> Result<Tags, TransportError> {
    let mut out = Vec::with_capacity(tags.len());
    for t in tags {
        if t.is_empty() {
            return bad("empty tag");
        }
        out.push(Tag::parse(t.iter().map(String::as_str)).map_err(|e| TransportError(e.to_string()))?);
    }
    Ok(Tags::from_list(out))
}

impl AppEvent {
    /// Build an app event and compute its id.
    pub fn new(author: PublicKey, kind: u16, tags: Vec<Vec<String>>, content: String) -> Result<Self, TransportError> {
        let created_at = Timestamp::now().as_secs();
        let id = EventId::compute(
            &author,
            &Timestamp::from_secs(created_at),
            &Kind::Custom(kind),
            &tags_of(&tags)?,
            &content,
        );
        Ok(Self {
            id,
            pubkey: author,
            created_at,
            kind,
            tags,
            content,
        })
    }

    /// Serialize as the exact JSON object the spec requires (no `sig`).
    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(&AppEventWire {
            id: self.id.to_hex(),
            pubkey: self.pubkey.to_hex(),
            created_at: self.created_at,
            kind: self.kind,
            tags: self.tags.clone(),
            content: self.content.clone(),
        })
        .expect("serializable")
    }

    /// Strict decode: exactly the six members, no duplicates, lowercase
    /// hex, and an `id` that matches the canonical serialization.
    pub fn from_json(bytes: &[u8]) -> Result<Self, TransportError> {
        let w: AppEventWire =
            serde_json::from_slice(bytes).map_err(|_| TransportError("malformed app event".into()))?;
        let lower_hex64 = |s: &str| s.len() == 64 && s.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c));
        if !lower_hex64(&w.pubkey) || !lower_hex64(&w.id) {
            return bad("app event id or pubkey is not 64 lowercase hex");
        }
        let pubkey = PublicKey::from_hex(&w.pubkey).map_err(|_| TransportError("bad pubkey".into()))?;
        let id = EventId::compute(
            &pubkey,
            &Timestamp::from_secs(w.created_at),
            &Kind::Custom(w.kind),
            &tags_of(&w.tags)?,
            &w.content,
        );
        if id.to_hex() != w.id {
            return bad("app event id does not match its contents");
        }
        Ok(Self {
            id,
            pubkey,
            created_at: w.created_at,
            kind: w.kind,
            tags: w.tags,
            content: w.content,
        })
    }

    /// First value of the first tag named `name`.
    #[must_use]
    pub fn tag(&self, name: &str) -> Option<&str> {
        self.tags
            .iter()
            .find(|t| t.first().is_some_and(|n| n == name))
            .and_then(|t| t.get(1))
            .map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_event_round_trip_and_tag_rules() {
        let key = [7u8; 32];
        let gid = [3u8; 32];
        let ev = seal_group_event(&key, &gid, b"mls bytes").unwrap();
        let (h, payload) = open_group_envelope(&ev).unwrap();
        assert_eq!(h, gid);
        assert_eq!(decrypt_group_payload(&key, &payload).unwrap(), b"mls bytes");
        assert!(decrypt_group_payload(&[8u8; 32], &payload).is_none());
        // Two events never share an author.
        let ev2 = seal_group_event(&key, &gid, b"x").unwrap();
        assert_ne!(ev.pubkey, ev2.pubkey);
        // An extra tag makes it malformed.
        let extra = EventBuilder::new(Kind::Custom(GROUP_KIND), ev.content.clone())
            .tag(Tag::parse(["h", &hex::encode(gid)]).unwrap())
            .tag(Tag::parse(["p", "x"]).unwrap())
            .finalize(&Keys::generate())
            .unwrap();
        assert!(open_group_envelope(&extra).is_err());
    }

    #[test]
    fn app_event_strict_decoding() {
        let k = Keys::generate();
        let ev = AppEvent::new(k.public_key(), 9, vec![vec!["name".into(), "x".into()]], "hi".into()).unwrap();
        let json = ev.to_json();
        assert_eq!(AppEvent::from_json(&json).unwrap(), ev);
        let s = String::from_utf8(json).unwrap();
        let with_sig = s.replacen('{', "{\"sig\":\"00\",", 1);
        assert!(AppEvent::from_json(with_sig.as_bytes()).is_err());
        let dup = s.replacen('{', &format!("{{\"kind\":{},", 9), 1);
        assert!(AppEvent::from_json(dup.as_bytes()).is_err(), "duplicate keys are rejected");
        let tampered = s.replace("\"hi\"", "\"ho\"");
        assert!(AppEvent::from_json(tampered.as_bytes()).is_err());
    }

    #[test]
    fn welcome_wrap_round_trip() {
        let (a, b) = (Keys::generate(), Keys::generate());
        let kp_id = EventId::from_byte_array([0u8; 32]);
        let gw = wrap_welcome(&a, &b.public_key(), b"welcome", &kp_id, &["wss://r.example".into()]).unwrap();
        let w = unwrap_welcome(&b, &gw).unwrap().unwrap();
        assert_eq!(w.sender, a.public_key());
        assert_eq!(w.mls_bytes, b"welcome");
        assert_eq!(w.relays, ["wss://r.example"]);
        assert!(unwrap_welcome(&Keys::generate(), &gw).is_err());
    }
}
