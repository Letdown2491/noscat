//! The tailnet: one MLS group per owner's set of devices, built on OpenMLS.
//!
//! Design (Marmot-shaped, OpenMLS-native):
//! - Every device is a Nostr identity (npub) plus an MLS Ed25519 signing key
//!   derived from the same secret (HKDF, same pattern as `crate::noise`).
//! - A device advertises its ability to join by publishing an MLS *key
//!   package* as a kind-30443 event (Marmot's key-package slot).
//! - The owner invites a device by fetching its key package, committing an
//!   MLS Add, and gift-wrapping (NIP-59) the Welcome to the device.
//! - Membership is authorization: `export_secret` derives the tunnel PSK, so
//!   the Noise handshake in `crate::tunnel` only completes for group members
//!   of the same epoch. Removing a device ratchets the epoch — it is out.
//!
//! Storage caveat (spike): OpenMLS state is persisted through the memory
//! storage's own file serialization (`openmls_memory_storage::persistence`),
//! which upstream marks test-only. The NIP will require a real storage
//! profile (SQLite) before this leaves spike status.

use std::path::PathBuf;
use std::time::Duration;

use nostr::nips::nip59::GiftWrapBuilder;
use nostr::prelude::*;
use nostr_sdk::prelude::*;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};

use crate::identity::Identity;

/// Marmot-compatible key-package slot: a device publishes its MLS key package
/// here so the tailnet owner can add it.
pub const KEY_PACKAGE_KIND: u16 = 30443;
/// Draft slot for gift-wrapped tailnet messages (Welcomes, later commits).
pub const TAILNET_KIND: u16 = 30444;
/// Replaceable `d` tag scoping a device's key package to one slot.
pub const KEY_PACKAGE_IDENTIFIER: &str = "noscat-tailnet-kp-v1";
/// Exporter label for the tunnel PSK (see `crate::tunnel`).
pub const EXPORTER_LABEL: &str = "noscat/tunnel-psk-v1";
/// Domain separation for deriving the MLS Ed25519 key from the identity secret.
const MLS_DERIVE_INFO: &[u8] = b"noscat/mls-ed25519-v1";

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

#[derive(Debug, thiserror::Error)]
pub enum TailnetError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Nostr(#[from] nostr::error::Error),
    #[error(transparent)]
    Sdk(#[from] nostr_sdk::error::Error),
    #[error(transparent)]
    Relay(#[from] crate::relay::RelayError),
    #[error(transparent)]
    Identity(#[from] crate::identity::IdentityError),
    #[error("bad hex encoding: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("mls: {0}")]
    Mls(String),
    #[error("device directory {0} does not hold a tailnet (run `tailnet create` first)")]
    NoTailnet(PathBuf),
    #[error("timed out waiting for a tailnet invitation")]
    JoinTimeout,
}

impl From<tls_codec::Error> for TailnetError {
    fn from(e: tls_codec::Error) -> Self {
        TailnetError::Mls(e.to_string())
    }
}

/// A device: nostr identity + MLS state, persisted to a directory.
pub struct Device {
    pub dir: PathBuf,
    pub identity: Identity,
    provider: Provider,
    signer: SignatureKeyPair,
    /// None until the device creates or joins a tailnet.
    group_id: Option<GroupId>,
}

/// OpenMLS provider with *our* storage handle: OpenMlsRustCrypto bundles a
/// private memory storage with no mutable accessor, and we need `&mut` to
/// load persisted state.
pub struct Provider {
    crypto: openmls_rust_crypto::RustCrypto,
    storage: openmls_memory_storage::MemoryStorage,
}

impl Default for Provider {
    fn default() -> Self {
        Self {
            crypto: openmls_rust_crypto::RustCrypto::default(),
            storage: openmls_memory_storage::MemoryStorage::default(),
        }
    }
}

impl openmls_traits::OpenMlsProvider for Provider {
    type CryptoProvider = openmls_rust_crypto::RustCrypto;
    type RandProvider = openmls_rust_crypto::RustCrypto;
    type StorageProvider = openmls_memory_storage::MemoryStorage;

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }
    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }
}

impl Device {
    /// Open (or initialize) a device directory.
    pub fn open(dir: &std::path::Path) -> Result<Self, TailnetError> {
        std::fs::create_dir_all(dir)?;
        let secret_path = dir.join("identity.nsec");
        let identity = if secret_path.exists() {
            Identity::from_secret(std::fs::read_to_string(&secret_path)?.trim())?
        } else {
            let id = Identity::generate();
            std::fs::write(&secret_path, format!("{}\n", id.secret_hex()))?;
            id
        };

        // Load MLS state if this device already has one.
        let mut provider = Provider::default();
        let mls_path = dir.join("mls.json");
        if mls_path.exists() {
            let file = std::fs::File::open(&mls_path)?;
            provider
                .storage
                .load_from_file(&file)
                .map_err(|e| {
                    TailnetError::Mls(format!(
                        "cannot load MLS state from {}: {e}",
                        mls_path.display()
                    ))
                })?;
        }

        let signer = mls_signer(&identity)?;
        signer
            .store(&provider.storage)
            .map_err(|e| TailnetError::Mls(format!("cannot store signer: {e}")))?;

        // Group id is tracked in a small sidecar (storage holds the state).
        let group_id = match std::fs::read_to_string(dir.join("tailnet.json")) {
            Ok(json) => {
                let gid: Vec<u8> = hex::decode(json.trim())?;
                Some(GroupId::from_slice(&gid))
            }
            Err(_) => None,
        };

        Ok(Self {
            dir: dir.to_path_buf(),
            identity,
            provider,
            signer,
            group_id,
        })
    }

    /// Persist MLS state to the device directory.
    fn persist(&self) -> Result<(), TailnetError> {
        let mls_path = self.dir.join("mls.json");
        let file = std::fs::File::create(&mls_path).map_err(|e| {
            TailnetError::Mls(format!("create {}: {e}", mls_path.display()))
        })?;
        self.provider
            .storage
            .save_to_file(&file)
            .map_err(|e| TailnetError::Mls(format!("cannot save MLS state: {e}")))?;
        if let Some(gid) = &self.group_id {
            let gid_path = self.dir.join("tailnet.json");
            std::fs::write(&gid_path, format!("{}\n", hex::encode(gid.as_slice())))
                .map_err(|e| TailnetError::Mls(format!("write {}: {e}", gid_path.display())))?;
        }
        Ok(())
    }

    /// The group's current epoch tunnel PSK. Membership is authorization.
    pub fn tunnel_psk(&self) -> Result<Vec<u8>, TailnetError> {
        let group = self.group()?;
        let psk = group
            .export_secret(self.provider.crypto(), EXPORTER_LABEL, &[], 32)
            .map_err(|e| TailnetError::Mls(e.to_string()))?;
        Ok(psk)
    }

    fn group(&self) -> Result<MlsGroup, TailnetError> {
        let gid = self
            .group_id
            .as_ref()
            .ok_or_else(|| TailnetError::NoTailnet(self.dir.clone()))?;
        MlsGroup::load(self.provider.storage(), gid)
            .map_err(|e| TailnetError::Mls(e.to_string()))?
            .ok_or_else(|| TailnetError::Mls("group state missing from storage".into()))
    }

    /// Create a tailnet owned by this device.
    pub fn create_tailnet(&mut self) -> Result<(), TailnetError> {
        if self.group_id.is_some() {
            return Err(TailnetError::Mls(format!(
                "{} already has a tailnet; use a fresh device directory to own another",
                self.identity.npub()
            )));
        }
        let group_id = GroupId::from_slice(&self.identity.public_key().to_bytes());
        let _group = MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            &group_config(),
            group_id.clone(),
            self.credential_with_key()?,
        )
        .map_err(|e| TailnetError::Mls(e.to_string()))?;
        self.group_id = Some(group_id);
        self.persist()
    }

    fn credential_with_key(&self) -> Result<CredentialWithKey, TailnetError> {
        let identity = self.identity.public_key().to_bytes().to_vec();
        let credential = Credential::new(CredentialType::Basic, identity);
        Ok(CredentialWithKey {
            credential,
            signature_key: self.signer.public().into(),
        })
    }

    /// Publish our MLS key package (kind 30443) so the owner can invite us.
    pub async fn publish_key_package(&self, relays: &[String]) -> Result<(), TailnetError> {
        let bundle = KeyPackage::builder()
            .build(
                CIPHERSUITE,
                &self.provider,
                &self.signer,
                self.credential_with_key()?,
            )
            .map_err(|e| TailnetError::Mls(e.to_string()))?;
        let bytes = bundle.key_package().tls_serialize_detached()?;

        // The bundle's private init/encryption keys just went into storage;
        // they are what will decrypt the owner's Welcome, so persist now.
        self.persist()?;

        let event = EventBuilder::new(Kind::Custom(KEY_PACKAGE_KIND), hex::encode(bytes))
            .tag(Tag::identifier(KEY_PACKAGE_IDENTIFIER))
            .finalize(self.identity.keys())
            .map_err(|e| TailnetError::Nostr(e))?;

        let client = Client::new();
        for relay in relays {
            client.add_relay(relay).await?;
        }
        client.connect().and_wait(Duration::from_secs(8)).await;
        client.send_event(&event).await?;
        client.shutdown().await;
        Ok(())
    }

    /// Invite a device (by npub) into the tailnet: fetch its key package,
    /// commit the Add, gift-wrap the Welcome to it, and persist our new epoch.
    pub async fn invite(
        &mut self,
        device: PublicKey,
        relays: &[String],
    ) -> Result<(), TailnetError> {
        let mut group = self.group()?;

        let kp_event = crate::relay::fetch_key_package(relays, device)
            .await?
            .ok_or_else(|| TailnetError::Mls(format!("no key package found for {device}")))?;
        let kp_bytes = hex::decode(&kp_event.content)
            .map_err(|e| TailnetError::Mls(format!("bad key package hex: {e}")))?;
        let key_package_in = KeyPackageIn::tls_deserialize_exact(&mut kp_bytes.as_slice())
            .map_err(|e| TailnetError::Mls(e.to_string()))?;
        let key_package = key_package_in
            .validate(self.provider.crypto(), ProtocolVersion::default())
            .map_err(|e| TailnetError::Mls(e.to_string()))?;

        let (commit, welcome, _info) = group
            .add_members(&self.provider, &self.signer, &[key_package])
            .map_err(|e| TailnetError::Mls(e.to_string()))?;
        group
            .merge_pending_commit(&self.provider)
            .map_err(|e| TailnetError::Mls(e.to_string()))?;
        self.persist()?;

        // Gift-wrap both messages to the invitee; the commit matters once the
        // tailnet has more than one existing member.
        let MlsMessageBodyOut::Welcome(welcome) = welcome.body() else {
            return Err(TailnetError::Mls("expected a Welcome from add_members".into()));
        };
        let payload = serde_json::to_string(&TailnetMessage {
            commit: hex::encode(commit.tls_serialize_detached()?),
            welcome: hex::encode(welcome.tls_serialize_detached()?),
        })?;
        let rumor = UnsignedEvent::new(
            self.identity.public_key(),
            Timestamp::now(),
            Kind::Custom(TAILNET_KIND),
            [],
            payload,
        );
        let gift_wrap = GiftWrapBuilder::new(device, rumor)
            .expiration(Duration::from_secs(7 * 24 * 3600))
            .finalize(self.identity.keys())
            .map_err(|e| TailnetError::Nostr(e))?;

        let client = Client::new();
        for relay in relays {
            client.add_relay(relay).await?;
        }
        client.connect().and_wait(Duration::from_secs(8)).await;
        client.send_event(&gift_wrap).await?;
        client.shutdown().await;
        Ok(())
    }

    /// Wait for a gift-wrapped tailnet invitation and join it.
    pub async fn join_tailnet(&mut self, relays: &[String]) -> Result<(), TailnetError> {
        if self.group_id.is_some() {
            return Err(TailnetError::Mls(format!(
                "{} is already in a tailnet",
                self.identity.npub()
            )));
        }
        let (tx, mut rx) = tokio::sync::mpsc::channel::<(PublicKey, String)>(16);
        let watch = tokio::spawn(crate::traversal::watch_tailnet(
            self.identity.clone(),
            relays.to_vec(),
            tx,
        ));
        eprintln!("# ⏳ waiting for a tailnet invitation (Ctrl-C to give up)…");
        let (sender, payload) = rx.recv().await.ok_or(TailnetError::JoinTimeout)?;
        watch.abort();

        let msg: TailnetMessage = serde_json::from_str(&payload)?;
        eprintln!("# ✉️  invitation received from {sender} — joining…");

        let welcome_bytes = hex::decode(&msg.welcome)?;
        let welcome =
            Welcome::tls_deserialize_exact(&mut welcome_bytes.as_slice())
                .map_err(|e| TailnetError::Mls(e.to_string()))?;
        let staged = StagedWelcome::new_from_welcome(
            &self.provider,
            &group_config().join_config().clone(),
            welcome,
            None,
        )
        .map_err(|e| TailnetError::Mls(e.to_string()))?;
        let group = staged
            .into_group(&self.provider)
            .map_err(|e| TailnetError::Mls(e.to_string()))?;
        let group_id = group.group_id().clone();
        self.group_id = Some(group_id);
        self.persist()?;

        eprintln!("# ✅ joined tailnet of {}", sender);
        Ok(())
    }
}

/// Wire format of a gift-wrapped tailnet message.
#[derive(serde::Serialize, serde::Deserialize)]
struct TailnetMessage {
    /// MLS commit (needed by other members; the invitee ignores it).
    commit: String,
    /// MLS Welcome carrying the group secrets for the invitee.
    welcome: String,
}

fn group_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .use_ratchet_tree_extension(true)
        .build()
}

/// The device's MLS Ed25519 signing key, derived from its nostr secret — one
/// secret governs the whole device, same pattern as the Noise key.
fn mls_signer(identity: &Identity) -> Result<SignatureKeyPair, TailnetError> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let secret: [u8; 32] = identity
        .keys()
        .secret_key()
        .as_secret_bytes()
        .try_into()
        .map_err(|_| TailnetError::Mls("bad secret length".into()))?;
    let hk = Hkdf::<Sha256>::new(Some(b"noscat"), &secret);
    let mut seed = [0u8; 32];
    hk.expand(MLS_DERIVE_INFO, &mut seed)
        .map_err(|_| TailnetError::Mls("key derivation failed".into()))?;
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    Ok(SignatureKeyPair::from_raw(
        SignatureScheme::ED25519,
        signing.to_bytes().to_vec(),
        signing.verifying_key().to_bytes().to_vec(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The heart of the tailnet: the owner adds a device from its published
    /// key package, the device joins from the Welcome, and both independently
    /// derive the *same* tunnel PSK from the group's exporter. This is the
    /// exact flow `create_tailnet` / `invite` / `join_tailnet` implement,
    /// minus the relay transport.
    #[test]
    fn mls_add_join_derives_shared_psk() -> Result<(), TailnetError> {
        let owner = Identity::generate();
        let invitee = Identity::generate();
        let owner_provider = Provider::default();
        let invitee_provider = Provider::default();
        let owner_signer = mls_signer(&owner)?;
        let invitee_signer = mls_signer(&invitee)?;

        // Owner creates the tailnet.
        let group_id = GroupId::from_slice(&owner.public_key().to_bytes());
        let mut group = MlsGroup::new_with_group_id(
            &owner_provider,
            &owner_signer,
            &group_config(),
            group_id,
            CredentialWithKey {
                credential: Credential::new(
                    CredentialType::Basic,
                    owner.public_key().to_bytes().to_vec(),
                ),
                signature_key: owner_signer.public().into(),
            },
        )
        .map_err(|e| TailnetError::Mls(e.to_string()))?;

        // Invitee publishes a key package (stored in its own provider, which
        // is what lets it later decrypt the Welcome).
        let invitee_credential = CredentialWithKey {
            credential: Credential::new(
                CredentialType::Basic,
                invitee.public_key().to_bytes().to_vec(),
            ),
            signature_key: invitee_signer.public().into(),
        };
        let invitee_bundle = KeyPackage::builder()
            .build(CIPHERSUITE, &invitee_provider, &invitee_signer, invitee_credential)
            .map_err(|e| TailnetError::Mls(e.to_string()))?;

        // Owner commits the Add and produces the Welcome.
        let (commit, welcome_msg, _info) = group
            .add_members(&owner_provider, &owner_signer, &[invitee_bundle.key_package().clone()])
            .map_err(|e| TailnetError::Mls(e.to_string()))?;
        group
            .merge_pending_commit(&owner_provider)
            .map_err(|e| TailnetError::Mls(e.to_string()))?;
        let MlsMessageBodyOut::Welcome(welcome) = welcome_msg.body() else {
            return Err(TailnetError::Mls("expected a Welcome from add_members".into()));
        };
        let welcome = welcome.clone();

        // Invitee joins from the Welcome.
        let staged = StagedWelcome::new_from_welcome(
            &invitee_provider,
            &group_config().join_config().clone(),
            welcome,
            None,
        )
        .map_err(|e| TailnetError::Mls(e.to_string()))?;
        let joined = staged
            .into_group(&invitee_provider)
            .map_err(|e| TailnetError::Mls(e.to_string()))?;

        // Both sides derive the same exporter secret -> same tunnel PSK.
        let psk_owner = group
            .export_secret(owner_provider.crypto(), EXPORTER_LABEL, &[], 32)
            .map_err(|e| TailnetError::Mls(e.to_string()))?;
        let psk_invitee = joined
            .export_secret(invitee_provider.crypto(), EXPORTER_LABEL, &[], 32)
            .map_err(|e| TailnetError::Mls(e.to_string()))?;
        assert_eq!(psk_owner, psk_invitee, "members must derive the same PSK");
        assert_eq!(psk_owner.len(), 32);
        Ok(())
    }

    /// A device directory is the unit of persistence: same directory, same
    /// identity, same group, same PSK — across processes.
    #[test]
    fn device_state_survives_reopen() -> Result<(), TailnetError> {
        let dir = std::env::temp_dir().join(format!(
            "noscat-tailnet-test-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));

        let npub;
        let psk;
        {
            let mut device = Device::open(&dir)?;
            npub = device.identity.npub();
            device.create_tailnet()?;
            psk = device.tunnel_psk()?;
        }

        let reopened = Device::open(&dir)?;
        assert_eq!(reopened.identity.npub(), npub);
        assert_eq!(reopened.tunnel_psk()?, psk);

        std::fs::remove_dir_all(&dir).ok();
        Ok(())
    }
}
