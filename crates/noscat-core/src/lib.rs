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
//! - `mesh` - MLS group control plane per mesh (Marmot component model).

pub mod advert;
pub mod fsutil;
pub mod identity;
pub mod noise;
pub mod relay;
pub mod stun;
pub mod mesh;
pub mod traversal;
pub mod tunnel;

pub use advert::Advert;
pub use identity::Identity;

/// A sensible default friendly name for this device: the hostname on unix
/// systems (Android reports "localhost" - apps should pass something better,
/// e.g. the device model). Falls back to "noscat".
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
