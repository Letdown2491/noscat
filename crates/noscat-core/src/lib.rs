//! noscat-core: a decentralized mesh of devices over Nostr.
//!
//! Layering (ADR 0001 to 0007):
//! - `identity` - one secp256k1 keypair per device: its Nostr identity,
//!   its FIPS node address, and its Marmot account.
//! - `marmot` - the control plane: the mesh is a Marmot group on OpenMLS;
//!   membership, admin policy and endpoint adverts live there.
//! - `dataplane` - the FIPS data plane: encrypted, NAT-traversing links to
//!   member devices, gated to the current roster.
//! - `streams` - QUIC over FIPS: reliable streams between members.
//! - `relay` - relay connections, back-off and presence bookkeeping.

pub mod dataplane;
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

/// A sensible default friendly name for this device: the hostname on unix
/// systems (Android reports "localhost" - apps should pass something better,
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
        assert!(parse_pairing_target("not-a-key").is_err());
        assert!(parse_pairing_target("noscat:not-a-key").is_err());
    }
}
