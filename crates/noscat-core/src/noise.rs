//! Noise sessions for the data plane.
//!
//! Design note (deliberate deviation from FIPS, research/fips.md §4): FIPS uses
//! the Nostr keypair directly as a Noise secp256k1 static key. snow does not
//! speak secp256k1, and mislabeling a custom DH as "25519" would be worse than
//! the trade, so the MVP derives a curve25519 static key from the identity
//! secret via HKDF and publishes it in the signed advert. The advert signature
//! cryptographically binds the Noise key to the npub, so identity semantics are
//! preserved: anyone can verify the tunnel terminates at the advertised node.
//! Moving to secp256k1 DH natively is the long-term plan.

use snow::{Builder, HandshakeState, TransportState};

/// The Noise pattern the data plane speaks. Both ends are noscat.
pub const NOISE_PATTERN: &str = "Noise_XK_25519_ChaChaPoly_SHA256";

/// Domain separation for deriving the Noise static key from the identity secret.
const DERIVE_SALT: &[u8] = b"noscat";
const DERIVE_INFO: &[u8] = b"noscat/noise-static-v1";

/// Handshake prologue, binding the handshake transcript to this protocol.
const PROLOGUE: &[u8] = b"noscat/tunnel-v1";

#[derive(Debug, thiserror::Error)]
pub enum NoiseError {
    #[error(transparent)]
    Snow(#[from] snow::Error),
    #[error("bad derived key length")]
    KeyLen,
}

/// Derive the curve25519 Noise static private key from the identity secret
/// (the nsec bytes, 32 bytes). Deterministic: same identity, same Noise key.
pub fn noise_static_from_identity(secret: &[u8; 32]) -> Result<[u8; 32], NoiseError> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(Some(DERIVE_SALT), secret);
    let mut out = [0u8; 32];
    hk.expand(DERIVE_INFO, &mut out)
        .map_err(|_| NoiseError::KeyLen)?;
    Ok(out)
}

/// Derive the curve25519 public half of a Noise static private key.
/// Same primitive (and crate version) snow uses for its "25519" DH, with the
/// same RFC 7748 clamping snow applies — private key and published public key
/// must agree byte-for-byte or the XK transcript diverges.
pub fn noise_public(privkey: &[u8; 32]) -> [u8; 32] {
    use curve25519_dalek::montgomery::MontgomeryPoint;
    use curve25519_dalek::scalar::Scalar;
    let mut clamped = *privkey;
    clamped[0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;
    let scalar = Scalar::from_bytes_mod_order(clamped);
    MontgomeryPoint::mul_base(&scalar).to_bytes()
}

/// Base builder with the pattern, prologue, and optional keys set.
fn builder<'a>(
    local_static: Option<&'a [u8; 32]>,
    remote_static: Option<&'a [u8; 32]>,
) -> Result<Builder<'a>, NoiseError> {
    let params: snow::params::NoiseParams = NOISE_PATTERN.parse()?;
    let mut b = Builder::with_resolver(
        params,
        std::boxed::Box::new(snow::resolvers::DefaultResolver),
    );
    b = b.prologue(PROLOGUE)?;
    if let Some(local) = local_static {
        b = b.local_private_key(local)?;
    }
    if let Some(remote) = remote_static {
        b = b.remote_public_key(remote)?;
    }
    Ok(b)
}

/// Start an initiator handshake: we know the server's npub, it does not know us
/// until msg 3 (XK's identity-hiding for the initiator).
pub fn initiator(
    local_static: &[u8; 32],
    remote_static: &[u8; 32],
) -> Result<HandshakeState, NoiseError> {
    Ok(builder(Some(local_static), Some(remote_static))?.build_initiator()?)
}

/// Start a responder handshake: we know our own static key only.
pub fn responder(local_static: &[u8; 32]) -> Result<HandshakeState, NoiseError> {
    Ok(builder(Some(local_static), None)?.build_responder()?)
}

/// Split a finished handshake into the transport session.
pub fn into_transport(state: HandshakeState) -> Result<TransportState, NoiseError> {
    Ok(state.into_transport_mode()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic_and_distinct() {
        let secret = [7u8; 32];
        let a = noise_static_from_identity(&secret).expect("derive");
        let b = noise_static_from_identity(&secret).expect("derive");
        assert_eq!(a, b);
        let other = noise_static_from_identity(&[8u8; 32]).expect("derive");
        assert_ne!(a, other);
    }

    #[test]
    fn xk_handshake_completes_and_transports() {
        let server_secret = [1u8; 32];
        let client_secret = [2u8; 32];
        let server_static = noise_static_from_identity(&server_secret).expect("derive");
        let client_static = noise_static_from_identity(&client_secret).expect("derive");

        // The client uses the server's *public* Noise key, exactly like it
        // would from a fetched advert (the advert publishes noise_public()).
        let server_noise_pub = noise_public(&server_static);
        let mut hs_c = initiator(&client_static, &server_noise_pub).expect("initiator");
        let mut hs_s = responder(&server_static).expect("responder");

        let mut buf_c = [0u8; 65535];
        let mut buf_s = [0u8; 65535];

        // -> e
        let n = hs_c.write_message(b"", &mut buf_c).expect("msg1");
        hs_s.read_message(&buf_c[..n], &mut buf_s).expect("read1");

        // <- e, ee, s, er
        let n = hs_s.write_message(b"", &mut buf_c).expect("msg2");
        hs_c.read_message(&buf_c[..n], &mut buf_s).expect("read2");

        // -> s, se
        let n = hs_c.write_message(b"hello", &mut buf_c).expect("msg3");
        let (n, payload) = {
            let n = hs_s.read_message(&buf_c[..n], &mut buf_s).expect("read3");
            (n, &buf_s[..n])
        };
        assert_eq!(payload, b"hello");
        assert!(hs_c.is_handshake_finished() && hs_s.is_handshake_finished());

        // The responder learns the initiator's static key (advert binding check
        // would verify it equals the initiator's published noise key).
        assert_eq!(
            hs_s.get_remote_static().expect("remote"),
            &noise_public(&client_static)
        );

        let mut t_c = into_transport(hs_c).expect("transport");
        let mut t_s = into_transport(hs_s).expect("transport");

        let n = t_c.write_message(b"ping", &mut buf_c).expect("write");
        let n = t_s.read_message(&buf_c[..n], &mut buf_s).expect("read");
        assert_eq!(&buf_s[..n], b"ping");

        let n = t_s.write_message(b"pong", &mut buf_c).expect("write");
        let n = t_c.read_message(&buf_c[..n], &mut buf_s).expect("read");
        assert_eq!(&buf_s[..n], b"pong");
    }
}
