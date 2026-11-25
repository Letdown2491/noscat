//! Marmot binary profile (foundation/canonical-encoding.md) and the bytes of
//! the components a noscat mesh carries.
//!
//! Every decoder here is canonical: it rejects anything that does not
//! re-encode to the same bytes (non-minimal length prefixes, unsorted or
//! duplicate lists, trailing bytes).

use std::collections::BTreeSet;

/// MLS extensions draft `app_components` (support and required lists).
pub const APP_COMPONENTS: u16 = 0x0001;
/// MLS extensions draft `safe_aad`. Leaves advertise an empty list.
pub const SAFE_AAD: u16 = 0x0002;
/// `marmot.group.profile.v1` (name and description). MDK requires it in the
/// groups it creates, so noscat supports it; noscat groups do not require it.
pub const GROUP_PROFILE: u16 = 0x8001;
/// `marmot.group.admin-policy.v1`.
pub const ADMIN_POLICY: u16 = 0x8003;
/// `marmot.transport.nostr.routing.v1`.
pub const NOSTR_ROUTING: u16 = 0x8004;
/// `marmot.member.account-identity-proof.v2` (LeafNode only).
pub const IDENTITY_PROOF: u16 = 0x8009;
/// `marmot.group.lifecycle.v1`.
pub const LIFECYCLE: u16 = 0x800c;
/// `noscat.mesh.v1`: marks a Marmot group as a noscat mesh and carries its
/// name. Private-use id, never required, so other Marmot clients keep it
/// byte for byte as unknown data (see docs/nip-noscat.md).
pub const NOSCAT_MESH: u16 = 0xf3a0;
/// `noscat.private.v1`: present (with empty state) when the mesh is
/// private: devices use only the routing component's relays, log in to
/// them (NIP-42), and leave the public default relays. Not required, so
/// other Marmot clients ignore it.
pub const NOSCAT_PRIVATE: u16 = 0xf3a1;
/// Marmot encrypted media policy v2. White Noise requires it in every new
/// group. noscat never sends media; it supports the component in the sense
/// Marmot means (it can be a member of a group that carries the policy and
/// leaves the policy as it is).
pub const ENCRYPTED_MEDIA_V2: u16 = 0x800b;

/// Components a noscat group requires: the Marmot mandatory set plus Nostr
/// routing and lifecycle.
pub const REQUIRED_COMPONENTS: [u16; 4] = [ADMIN_POLICY, NOSTR_ROUTING, IDENTITY_PROOF, LIFECYCLE];
/// Components noscat advertises in its leaves: the `app_components` list
/// itself plus every app component it supports. The key package's
/// `app_components` tag carries only the app components (ids from
/// [`FIRST_APP_COMPONENT`]), as MDK checks.
pub const SUPPORTED_COMPONENTS: [u16; 9] = [
    APP_COMPONENTS,
    GROUP_PROFILE,
    ADMIN_POLICY,
    NOSTR_ROUTING,
    IDENTITY_PROOF,
    LIFECYCLE,
    NOSCAT_MESH,
    NOSCAT_PRIVATE,
    ENCRYPTED_MEDIA_V2,
];

/// First app-component id; lower ids are dictionary framework entries.
pub const FIRST_APP_COMPONENT: u16 = 0x8000;

/// Most relays a routing component may list.
pub const MAX_RELAYS: usize = 16;
/// Longest mesh name noscat writes.
pub const MAX_MESH_NAME: usize = 64;

/// A decode failure. The string says what was wrong; it never carries input
/// bytes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct CodecError(pub String);

fn err<T>(msg: impl Into<String>) -> Result<T, CodecError> {
    Err(CodecError(msg.into()))
}

/// Append a canonical (shortest) QUIC variable-length integer.
pub fn put_varint(value: u64, out: &mut Vec<u8>) {
    if value < 64 {
        out.push(value as u8);
    } else if value < 16_384 {
        out.extend_from_slice(&(0x4000 | value as u16).to_be_bytes());
    } else if value < 1_073_741_824 {
        out.extend_from_slice(&(0x8000_0000 | value as u32).to_be_bytes());
    } else {
        out.extend_from_slice(&(0xC000_0000_0000_0000 | value).to_be_bytes());
    }
}

/// Read a QUIC varint, rejecting a longer-than-needed prefix.
/// Returns (value, bytes consumed).
pub fn get_varint(bytes: &[u8]) -> Result<(u64, usize), CodecError> {
    let Some(&first) = bytes.first() else {
        return err("truncated length");
    };
    let len = 1usize << (first >> 6);
    if bytes.len() < len {
        return err("truncated length");
    }
    let mut v = u64::from(first & 0x3f);
    for b in &bytes[1..len] {
        v = (v << 8) | u64::from(*b);
    }
    let minimal = match len {
        1 => true,
        2 => v >= 64,
        4 => v >= 16_384,
        _ => v >= 1_073_741_824,
    };
    if !minimal {
        return err("non-canonical length prefix");
    }
    Ok((v, len))
}

/// Split one length-prefixed vector off the front of `bytes`.
fn take_vec(bytes: &[u8]) -> Result<(&[u8], &[u8]), CodecError> {
    let (len, n) = get_varint(bytes)?;
    let len = usize::try_from(len).map_err(|_| CodecError("length too large".into()))?;
    let end = n.checked_add(len).ok_or_else(|| CodecError("length overflow".into()))?;
    if bytes.len() < end {
        return err("truncated vector");
    }
    Ok((&bytes[n..end], &bytes[end..]))
}

fn put_vec(data: &[u8], out: &mut Vec<u8>) {
    put_varint(data.len() as u64, out);
    out.extend_from_slice(data);
}

/// `ComponentsList`: a sorted, duplicate-free vector of big-endian u16 ids.
#[must_use]
pub fn encode_components(ids: &BTreeSet<u16>) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + ids.len() * 2);
    put_varint((ids.len() * 2) as u64, &mut out);
    for id in ids {
        out.extend_from_slice(&id.to_be_bytes());
    }
    out
}

/// Decode a `ComponentsList` exactly.
pub fn decode_components(bytes: &[u8]) -> Result<BTreeSet<u16>, CodecError> {
    let (body, rest) = take_vec(bytes)?;
    if !rest.is_empty() {
        return err("component list has trailing bytes");
    }
    if body.len() % 2 != 0 {
        return err("component list length is odd");
    }
    let mut ids = BTreeSet::new();
    let mut prev: Option<u16> = None;
    for c in body.chunks_exact(2) {
        let id = u16::from_be_bytes([c[0], c[1]]);
        if prev.is_some_and(|p| id <= p) {
            return err("component list is not sorted and unique");
        }
        prev = Some(id);
        ids.insert(id);
    }
    Ok(ids)
}

/// `MarmotAdminPolicyV1`: a sorted, unique, non-empty list of 32-byte keys.
#[must_use]
pub fn encode_admins(admins: &BTreeSet<[u8; 32]>) -> Vec<u8> {
    let mut body = Vec::with_capacity(admins.len() * 32);
    for a in admins {
        body.extend_from_slice(a);
    }
    let mut out = Vec::with_capacity(body.len() + 2);
    put_vec(&body, &mut out);
    out
}

/// Decode an admin policy exactly (sorted, unique, non-empty).
pub fn decode_admins(bytes: &[u8]) -> Result<BTreeSet<[u8; 32]>, CodecError> {
    let (body, rest) = take_vec(bytes)?;
    if !rest.is_empty() {
        return err("admin policy has trailing bytes");
    }
    if body.is_empty() || body.len() % 32 != 0 {
        return err("admin policy is empty or not a list of 32-byte keys");
    }
    let mut out = BTreeSet::new();
    let mut prev: Option<[u8; 32]> = None;
    for c in body.chunks_exact(32) {
        let mut k = [0u8; 32];
        k.copy_from_slice(c);
        if prev.is_some_and(|p| k <= p) {
            return err("admin policy is not sorted and unique");
        }
        prev = Some(k);
        out.insert(k);
    }
    Ok(out)
}

/// `MarmotNostrRoutingV1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Routing {
    /// Random 32-byte routing id, the `h` tag of kind 445 events.
    pub nostr_group_id: [u8; 32],
    /// Sorted, unique relay URLs (1 to 16).
    pub relays: Vec<String>,
}

/// Check one relay URL against the transport's relay URL profile.
pub fn valid_relay_url(url: &str) -> bool {
    if url.is_empty() || url.len() > 512 {
        return false;
    }
    let Some(rest) = url.strip_prefix("wss://").or_else(|| url.strip_prefix("ws://")) else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    !authority.is_empty() && !authority.contains('@') && !url.contains('#')
}

/// Encode routing state. Relays are sorted and deduplicated by the caller
/// (see [`Routing::new`]).
#[must_use]
pub fn encode_routing(r: &Routing) -> Vec<u8> {
    let mut body = Vec::new();
    for url in &r.relays {
        put_vec(url.as_bytes(), &mut body);
    }
    let mut out = Vec::with_capacity(32 + body.len() + 2);
    out.extend_from_slice(&r.nostr_group_id);
    put_vec(&body, &mut out);
    out
}

/// Decode routing state exactly, enforcing the validation rules of
/// nostr-routing-v1.md.
pub fn decode_routing(bytes: &[u8]) -> Result<Routing, CodecError> {
    if bytes.len() < 32 {
        return err("routing state is truncated");
    }
    let mut nostr_group_id = [0u8; 32];
    nostr_group_id.copy_from_slice(&bytes[..32]);
    let (mut body, rest) = take_vec(&bytes[32..])?;
    if !rest.is_empty() {
        return err("routing state has trailing bytes");
    }
    let mut relays: Vec<String> = Vec::new();
    while !body.is_empty() {
        let (url, more) = take_vec(body)?;
        body = more;
        if url.is_empty() || url.len() > 512 {
            return err("relay url length out of range");
        }
        let url = std::str::from_utf8(url).map_err(|_| CodecError("relay url is not UTF-8".into()))?;
        if !valid_relay_url(url) {
            return err("relay url does not match the relay URL profile");
        }
        if relays.last().is_some_and(|p| p.as_bytes() >= url.as_bytes()) {
            return err("relay list is not sorted and unique");
        }
        relays.push(url.to_string());
    }
    if relays.is_empty() || relays.len() > MAX_RELAYS {
        return err("relay list must hold 1 to 16 relays");
    }
    Ok(Routing {
        nostr_group_id,
        relays,
    })
}

impl Routing {
    /// Build routing state from a fresh random id and any relay list: keeps
    /// valid URLs, sorts and deduplicates them, caps at 16.
    pub fn new(nostr_group_id: [u8; 32], relays: &[String]) -> Result<Self, CodecError> {
        let mut set: BTreeSet<&str> = BTreeSet::new();
        for r in relays {
            let r = r.trim();
            if valid_relay_url(r) {
                set.insert(r);
            }
        }
        let relays: Vec<String> = set.into_iter().take(MAX_RELAYS).map(String::from).collect();
        if relays.is_empty() {
            return err("no valid relay url (wss://host)");
        }
        Ok(Self {
            nostr_group_id,
            relays,
        })
    }
}

/// `MarmotGroupLifecycleV1`: one byte.
pub const LIFECYCLE_ACTIVE: [u8; 1] = [0x00];

/// Decode lifecycle state: `Ok(true)` is active, `Ok(false)` disbanded.
pub fn decode_lifecycle(bytes: &[u8]) -> Result<bool, CodecError> {
    match bytes {
        [0x00] => Ok(true),
        [0x01] => Ok(false),
        _ => err("invalid lifecycle state"),
    }
}

/// `noscat.mesh.v1` state: `opaque name<V>`, UTF-8, at most 64 bytes.
pub fn encode_mesh(name: &str) -> Result<Vec<u8>, CodecError> {
    if name.len() > MAX_MESH_NAME {
        return err("mesh name is longer than 64 bytes");
    }
    let mut out = Vec::with_capacity(name.len() + 1);
    put_vec(name.as_bytes(), &mut out);
    Ok(out)
}

/// Decode `noscat.mesh.v1` state exactly.
pub fn decode_mesh(bytes: &[u8]) -> Result<String, CodecError> {
    let (body, rest) = take_vec(bytes)?;
    if !rest.is_empty() {
        return err("mesh state has trailing bytes");
    }
    if body.len() > MAX_MESH_NAME {
        return err("mesh name is longer than 64 bytes");
    }
    String::from_utf8(body.to_vec()).map_err(|_| CodecError("mesh name is not UTF-8".into()))
}

/// Check `noscat.private.v1` state: always empty.
pub fn validate_private(bytes: &[u8]) -> Result<(), CodecError> {
    if bytes.is_empty() { Ok(()) } else { err("private state must be empty") }
}

/// Structural check of `marmot.group.profile.v1` (two var-bytes fields:
/// name and description). noscat only preserves this component; it never
/// writes it.
pub fn validate_group_profile(bytes: &[u8]) -> Result<(), CodecError> {
    let (name, rest) = take_vec(bytes)?;
    let (desc, rest) = take_vec(rest)?;
    if !rest.is_empty() {
        return err("group profile has trailing bytes");
    }
    if name.len() > 256 || desc.len() > 4096 {
        return err("group profile field too long");
    }
    if std::str::from_utf8(name).is_err() || std::str::from_utf8(desc).is_err() {
        return err("group profile is not UTF-8");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_examples_from_the_spec() {
        let mut out = Vec::new();
        put_varint(7, &mut out);
        assert_eq!(out, [0x07]);
        for (len, prefix) in [(64u64, vec![0x40, 0x40]), (16383, vec![0x7f, 0xff]), (16384, vec![0x80, 0x00, 0x40, 0x00])] {
            let mut out = Vec::new();
            put_varint(len, &mut out);
            assert_eq!(out, prefix);
            assert_eq!(get_varint(&out).unwrap(), (len, out.len()));
        }
        // 5 written with a 2-byte prefix is not canonical.
        assert!(get_varint(&[0x40, 0x05]).is_err());
    }

    #[test]
    fn component_lists_round_trip_and_reject_unsorted() {
        let ids: BTreeSet<u16> = [0x8009, 0x0001, 0x8003].into();
        let bytes = encode_components(&ids);
        assert_eq!(bytes, [6, 0x00, 0x01, 0x80, 0x03, 0x80, 0x09]);
        assert_eq!(decode_components(&bytes).unwrap(), ids);
        assert!(decode_components(&[4, 0x80, 0x09, 0x80, 0x03]).is_err());
        assert!(decode_components(&[4, 0x80, 0x09, 0x80, 0x09]).is_err());
        assert!(decode_components(&[2, 0x80, 0x09, 0x00]).is_err());
    }

    #[test]
    fn admins_and_routing_round_trip() {
        let admins: BTreeSet<[u8; 32]> = [[2u8; 32], [1u8; 32]].into();
        assert_eq!(decode_admins(&encode_admins(&admins)).unwrap(), admins);
        assert!(decode_admins(&encode_admins(&BTreeSet::new())).is_err());

        let r = Routing::new(
            [9u8; 32],
            &[
                "wss://b.example".into(),
                "wss://a.example".into(),
                "wss://a.example".into(),
                "https://nope".into(),
            ],
        )
        .unwrap();
        assert_eq!(r.relays, ["wss://a.example", "wss://b.example"]);
        assert_eq!(decode_routing(&encode_routing(&r)).unwrap(), r);
        let unsorted = Routing {
            nostr_group_id: [0; 32],
            relays: vec!["wss://b.example".into(), "wss://a.example".into()],
        };
        assert!(decode_routing(&encode_routing(&unsorted)).is_err());
    }

    #[test]
    fn mesh_and_lifecycle() {
        assert_eq!(decode_mesh(&encode_mesh("home").unwrap()).unwrap(), "home");
        assert!(encode_mesh(&"x".repeat(65)).is_err());
        assert_eq!(decode_lifecycle(&LIFECYCLE_ACTIVE), Ok(true));
        assert!(decode_lifecycle(&[0, 0]).is_err());
    }
}
