//! noscat-core: the Nostr-native userspace tunnel and mesh library.
//!
//! Layering:
//! - `identity` - one secp256k1 keypair is the Nostr identity, the mesh identity,
//!   and the Noise static key (the FIPS pattern).
//! - `advert` - signed, expiring endpoint advertisements on Nostr (FIPS kind-37195 pattern).
//! - `tunnel` - the data plane (Noise XK over UDP): session primitives
//!   (`dial_session`/`serve_session`/`bind_listener`) for API consumers, plus
//!   [`TunnelStream`] for the tunnel as a plain byte stream, and the
//!   netcat/file-transfer operations on top.
//! - `tailnet` - MLS group control plane per tailnet (Marmot component model).

pub mod advert;
pub mod identity;
pub mod noise;
pub mod relay;
pub mod stun;
pub mod tailnet;
pub mod traversal;
pub mod tunnel;

pub use advert::Advert;
pub use identity::Identity;

/// A sensible default friendly name for this device: the hostname on unix
/// systems (Android reports "localhost" - apps should pass something better,
/// e.g. the device model). Falls back to "noscat".
pub fn default_device_name() -> String {
    #[cfg(unix)]
    {
        if let Ok(h) = std::fs::read_to_string("/proc/sys/kernel/hostname") {
            let h = h.trim();
            if !h.is_empty() && h != "localhost" {
                return h.to_string();
            }
        }
    }
    "noscat".to_string()
}
