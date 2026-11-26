//! noscat-core: a decentralized mesh of devices over Nostr.
//!
//! Layering (ADR 0001 to 0007):
//! - `identity`: one secp256k1 keypair per device: its Nostr identity,
//!   its FIPS node address, and its Marmot account.
//! - `marmot`: the control plane: the mesh is a Marmot group on OpenMLS;
//!   membership, admin policy and endpoint adverts live there.
//! - `dataplane`: the FIPS data plane: encrypted, NAT-traversing links to
//!   member devices, gated to the current roster.
//! - `streams`: QUIC over FIPS: reliable streams between members.
//! - `relay`: relay connections, back-off and presence bookkeeping.
//! - `device`: the runtime: keeps relays, group, data plane and streams
//!   in step for one device.
//! - `apps`: the app protocols over streams: file transfer, chat and
//!   clipboard text, TCP forwarding.
//! - `access`: who may do what to this device (access groups).

pub mod access;
pub mod apps;
pub mod dataplane;
pub mod device;
pub mod fsutil;
pub mod identity;
pub mod marmot;
pub mod relay;
pub mod streams;

pub use identity::Identity;

/// Parse a pairing target into the peer's public key. Accepts a bare npub
/// (hex or bech32) or a full pairing URI as shown in QR codes and deep
/// links: `noscat:<npub>` optionally followed by query
/// parameters (`noscat:<npub>?relay=...`). The `noscat:` prefix and any
/// query string are stripped, then the remainder is validated as a key -
/// so callers never hand a whole URI into the dial path and fail there
/// with a confusing error.
pub fn parse_pairing_target(target: &str) -> Result<nostr::prelude::PublicKey, String> {
    let t = target.trim();
    let t = t
        .strip_prefix("noscat:")
        .or_else(|| t.strip_prefix("NOSCAT:"))
        .unwrap_or(t);
    // Cut the query string, if any (?relay=... etc).
    let t = t.split('?').next().unwrap_or(t);
    let t = t.trim_end_matches('/');
    if t.is_empty() {
        return Err("empty pairing target".to_string());
    }
    nostr::prelude::PublicKey::parse(t).map_err(|e| format!("bad pairing target {target:?}: {e}"))
}

/// Relays named in a pairing URI (`noscat:<npub>?relay=<url>&relay=...`,
/// percent-encoded): a private mesh's own relays, which a joining device
/// uses instead of its own. Empty for a bare npub or a URI without them.
pub fn parse_pairing_relays(target: &str) -> Vec<String> {
    let Some((_, query)) = target.trim().split_once('?') else {
        return Vec::new();
    };
    query
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .filter(|(k, _)| *k == "relay")
        .filter_map(|(_, v)| percent_decode(v))
        .filter(|r| r.starts_with("wss://") || r.starts_with("ws://"))
        .collect()
}

/// The pairing URI for a device: `noscat:<npub>`, plus `?relay=` hints
/// when its mesh is private (so a joining device knows where to find it).
pub fn pairing_uri(npub: &str, relays: &[String]) -> String {
    let mut uri = format!("noscat:{npub}");
    for (i, r) in relays.iter().enumerate() {
        uri.push(if i == 0 { '?' } else { '&' });
        uri.push_str("relay=");
        for b in r.bytes() {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                uri.push(b as char);
            } else {
                uri.push_str(&format!("%{b:02X}"));
            }
        }
    }
    uri
}

fn percent_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// A sensible default friendly name for this device: the hostname on unix
/// systems (Android reports "localhost"; apps should pass something better,
/// e.g. the device model). Falls back to "noscat".
pub fn default_device_name() -> String {
    #[cfg(unix)]
    {
        // gethostname(3) works on every unix (Linux, macOS, the BSDs);
        // the /proc file this used to read is Linux-only.
        let mut buf = [0u8; 256];
        let len = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
        if len == 0 {
            let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            let h = String::from_utf8_lossy(&buf[..end]).trim().to_string();
            if !h.is_empty() && h != "localhost" {
                return h;
            }
        }
    }
    "noscat".to_string()
}

#[cfg(test)]
mod pairing_target_tests {
    use super::*;

    fn ok(s: &str) -> String {
        parse_pairing_target(s).unwrap().to_string()
    }

    #[test]
    fn pairing_target_accepts_bare_and_uris() {
        let hex_key = "4f95c6e4a7a6c6d5a2d34a8cb3e5e4e5a1b2c3d4e5f60718293a4b5c6d7e8f90";
        let parsed = parse_pairing_target(hex_key).unwrap().to_string();
        assert_eq!(parsed, parsed.to_lowercase());

        // The QR/deep-link forms all resolve to the same key.
        let base = ok(hex_key);
        assert_eq!(ok(&format!("noscat:{hex_key}")), base);
        assert_eq!(ok(&format!("NOSCAT:{hex_key}")), base);
        assert_eq!(ok(&format!("noscat:{hex_key}?relay=wss%3A%2F%2Frelay.example")), base);
        assert_eq!(ok(&format!("noscat:{hex_key}/")), base);
        assert_eq!(ok(&format!("  {hex_key}  ")), base);

        assert!(parse_pairing_target("noscat:").is_err());
        let relays = vec!["wss://relay.example/mesh".to_string(), "wss://b.example".to_string()];
        let uri = pairing_uri(hex_key, &relays);
        assert_eq!(uri, format!("noscat:{hex_key}?relay=wss%3A%2F%2Frelay.example%2Fmesh&relay=wss%3A%2F%2Fb.example"));
        assert_eq!(ok(&uri), base);
        assert_eq!(parse_pairing_relays(&uri), relays);
        assert!(parse_pairing_relays(&format!("noscat:{hex_key}")).is_empty());
        assert!(parse_pairing_relays(&format!("noscat:{hex_key}?relay=https%3A%2F%2Fx&relay=%zz")).is_empty());
        assert_eq!(pairing_uri("npub1x", &[]), "noscat:npub1x");
        assert!(parse_pairing_target("not-a-key").is_err());
        assert!(parse_pairing_target("noscat:not-a-key").is_err());
    }
}
