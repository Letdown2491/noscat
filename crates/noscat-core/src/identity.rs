//! Node identity: one secp256k1 keypair serves as the Nostr identity, the mesh
//! identity, and (later) the Noise static key — the same pattern FIPS uses
//! ("there is no separate Nostr key", research/fips.md §4).

use nostr::key::Error as KeyError;
use nostr::nips::nip19::ToBech32;
use nostr::prelude::*;

/// Errors from identity operations.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error(transparent)]
    Secret(#[from] KeyError),
}

/// A noscat node identity. Wraps a Nostr keypair.
///
/// The public half (npub) is the node's address on the mesh; the secret half
/// must be treated with the same care as a WireGuard private key.
#[derive(Debug, Clone)]
pub struct Identity {
    keys: Keys,
}

impl Identity {
    /// Generate a fresh ephemeral identity (the tailcat "ephemeral key" default:
    /// nobody has ever seen the address it produces, and it dies with the process).
    pub fn generate() -> Self {
        Self {
            keys: Keys::generate(),
        }
    }

    /// Restore an identity from a secret key given as hex or `nsec...` bech32.
    pub fn from_secret(secret: &str) -> Result<Self, IdentityError> {
        Ok(Self {
            keys: Keys::parse(secret)?,
        })
    }

    /// The node's public key (npub). This is what peers address.
    pub fn public_key(&self) -> PublicKey {
        self.keys.public_key()
    }

    /// The node's public key as `npub...` bech32.
    ///
    /// The `ToBech32` impl for `PublicKey` is infallible.
    pub fn npub(&self) -> String {
        self.keys.public_key().to_bech32().unwrap()
    }

    /// The secret key as hex, for persisting a stable identity.
    ///
    /// Callers are responsible for storage hygiene (0600, keyring, etc.).
    pub fn secret_hex(&self) -> String {
        self.keys.secret_key().to_secret_hex()
    }

    /// Borrow the underlying Nostr keys for event signing.
    pub fn keys(&self) -> &Keys {
        &self.keys
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_identity_round_trips_through_secret() {
        let id = Identity::generate();
        let restored = Identity::from_secret(&id.secret_hex()).expect("parse own secret");
        assert_eq!(id.public_key(), restored.public_key());
    }

    #[test]
    fn npub_is_bech32_with_npub_hrp() {
        let id = Identity::generate();
        let npub = id.npub();
        assert!(npub.starts_with("npub1"), "got {npub}");
    }

    #[test]
    fn parses_nsec_form() {
        let id = Identity::generate();
        let nsec = id.keys().secret_key().to_bech32().expect("nsec");
        let restored = Identity::from_secret(&nsec).expect("parse nsec");
        assert_eq!(id.public_key(), restored.public_key());
    }
}
