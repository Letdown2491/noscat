//! `marmot.member.account-identity-proof.v2` (component 0x8009): the
//! device's Nostr key authorizes its MLS leaf signature key through a
//! local-only kind 450 event (app-components/account-identity-proof-v2.md,
//! foundation/authorization-proofs.md).

use nostr::prelude::*;
use secp256k1::schnorr::Signature;
use secp256k1::{Secp256k1, XOnlyPublicKey};

/// Kind of the local signing event. Never published.
pub const PROOF_KIND: u16 = 450;
const PROOF_D: &str = "marmot.account-identity-proof.v2";
const PROOF_CONTENT: &str = "Authorize this MLS leaf key for my Marmot account";
/// Encoded proof length: signer (32) + created_at (8) + signature (64).
pub const PROOF_LEN: usize = 104;

/// A proof that failed to decode or verify. Never carries input bytes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("account identity proof: {0}")]
pub struct ProofError(pub &'static str);

fn proof_event_id(
    signer: &PublicKey,
    created_at: u64,
    ciphersuite: u16,
    signature_scheme: u16,
    mls_signature_key: &[u8],
) -> EventId {
    let tags = Tags::from_list(vec![
        Tag::parse(["d", PROOF_D]).expect("static tag"),
        Tag::parse(["component", "0x8009"]).expect("static tag"),
        Tag::parse(["ciphersuite", &format!("0x{ciphersuite:04x}")]).expect("tag"),
        Tag::parse(["signature_scheme", &format!("0x{signature_scheme:04x}")]).expect("tag"),
        Tag::parse(["mls_signature_key", &hex::encode(mls_signature_key)]).expect("tag"),
    ]);
    EventId::compute(
        signer,
        &Timestamp::from_secs(created_at),
        &Kind::Custom(PROOF_KIND),
        &tags,
        PROOF_CONTENT,
    )
}

/// Sign a proof for `mls_signature_key` with the device's Nostr keys.
#[must_use]
pub fn sign(
    keys: &Keys,
    created_at: u64,
    ciphersuite: u16,
    signature_scheme: u16,
    mls_signature_key: &[u8],
) -> [u8; PROOF_LEN] {
    let signer = keys.public_key();
    let id = proof_event_id(&signer, created_at.max(1), ciphersuite, signature_scheme, mls_signature_key);
    let sig = keys.sign_schnorr(id.to_bytes());
    let mut out = [0u8; PROOF_LEN];
    out[..32].copy_from_slice(&signer.to_bytes());
    out[32..40].copy_from_slice(&created_at.max(1).to_be_bytes());
    out[40..].copy_from_slice(sig.as_ref());
    out
}

/// Verify a proof against the leaf's credential identity, ciphersuite,
/// signature scheme and signature key.
pub fn verify(
    proof: &[u8],
    credential_identity: &[u8],
    ciphersuite: u16,
    signature_scheme: u16,
    mls_signature_key: &[u8],
) -> Result<(), ProofError> {
    if proof.len() != PROOF_LEN {
        return Err(ProofError("wrong length"));
    }
    let signer_bytes = &proof[..32];
    if signer_bytes != credential_identity {
        return Err(ProofError("signer is not the credential identity"));
    }
    let xonly = XOnlyPublicKey::from_slice(signer_bytes).map_err(|_| ProofError("signer is not an x-only key"))?;
    let signer = PublicKey::from_slice(signer_bytes).map_err(|_| ProofError("signer is not an x-only key"))?;
    let mut ts = [0u8; 8];
    ts.copy_from_slice(&proof[32..40]);
    let created_at = u64::from_be_bytes(ts);
    if created_at == 0 || created_at > (1u64 << 53) - 1 {
        return Err(ProofError("created_at out of range"));
    }
    let sig = Signature::from_slice(&proof[40..]).map_err(|_| ProofError("malformed signature"))?;
    let id = proof_event_id(&signer, created_at, ciphersuite, signature_scheme, mls_signature_key);
    Secp256k1::verification_only()
        .verify_schnorr(&sig, &id.to_bytes(), &xonly)
        .map_err(|_| ProofError("signature does not verify"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The signing test vector in account-identity-proof-v2.md.
    #[test]
    fn spec_vector_verifies() {
        let component = hex::decode(
            "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9000000006553f100\
             c5315d3c85b9d4907cb03395a2a97b3ba2eab393f8e45b13a5d5233acedac60a51d2a295e1b1b5ee\
             372d18a49bdb8041a7dba9dedce722c7c6f712f78bbdfb5d",
        )
        .unwrap();
        let signer = &component[..32];
        let key: Vec<u8> = (0u8..32).collect();
        let id = proof_event_id(&PublicKey::from_slice(signer).unwrap(), 1_700_000_000, 1, 0x0807, &key);
        assert_eq!(id.to_hex(), "b7e9a15dd85990fb0f49c33db3cc9875f73986207b038404ceb6b7fec4e0af6b");
        verify(&component, signer, 1, 0x0807, &key).unwrap();
        // Any change to the signed inputs breaks it.
        assert!(verify(&component, signer, 1, 0x0807, &[0u8; 32]).is_err());
        assert!(verify(&component, signer, 2, 0x0807, &key).is_err());
    }

    #[test]
    fn own_proofs_verify() {
        let keys = Keys::generate();
        let proof = sign(&keys, 1_800_000_000, 1, 0x0807, b"leafkey");
        let me = keys.public_key().to_bytes();
        verify(&proof, &me, 1, 0x0807, b"leafkey").unwrap();
        assert!(verify(&proof, &Keys::generate().public_key().to_bytes(), 1, 0x0807, b"leafkey").is_err());
    }
}
