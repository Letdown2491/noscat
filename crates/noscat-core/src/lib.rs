//! noscat-core: the Nostr-native userspace tunnel and mesh library.
//!
//! Layering:
//! - `identity` - one secp256k1 keypair is the Nostr identity, the mesh identity,
//!   and the Noise static key (the FIPS pattern).
//! - `advert` - signed, expiring endpoint advertisements on Nostr (FIPS kind-37195 pattern).
//! - later: data plane (Noise XK over UDP), traversal signaling (kind-21059 pattern),
//!   tailnet control plane (MLS group per tailnet, Marmot component model).

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
