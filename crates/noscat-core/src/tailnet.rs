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
//!   of the same epoch. Removing a device ratchets the epoch - it is out.
//!
//! Storage: OpenMLS state (key packages, trees, secrets) lives in a SQLite
//! storage profile (`openmls_sqlite_storage`, serde-JSON codec) at
//! `<device>/mls.sqlite3`, migrated on open. The group id rides in a
//! `tailnet.json` sidecar so `Device::open` knows which group to load.

use std::path::PathBuf;
use std::time::Duration;

use nostr::nips::nip59::GiftWrapBuilder;
use nostr::prelude::*;
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
/// GroupContext extension type carrying the tailnet policy. RFC 9420
/// reserves 0xffa0..=0xffff for private use; OpenMLS passes unknown types
/// through, which is exactly the Marmot-shaped hook for group policy.
const POLICY_EXTENSION_TYPE: u16 = 0xffa0;
/// Domain separation for deriving the MLS Ed25519 key from the identity secret.
const MLS_DERIVE_INFO: &[u8] = b"noscat/mls-ed25519-v1";

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

#[derive(Debug, thiserror::Error)]
pub enum TailnetError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
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
    #[error("commit rejected: {0} is not authorized to change the tailnet (policy is owner-only)")]
    PolicyViolation(String),
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

/// A serde-JSON codec for the SQLite MLS store: OpenMLS 0.8 derives
/// `Serialize`/`Deserialize` on all stored entity types.
#[derive(Default)]
pub struct JsonCodec;

impl openmls_sqlite_storage::Codec for JsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}

/// The concrete store type: serde-JSON codec over an owned rusqlite handle.
type SqliteStore =
    openmls_sqlite_storage::SqliteStorageProvider<JsonCodec, openmls_sqlite_storage::Connection>;

/// OpenMLS provider with a SQLite storage profile: all MLS state (key
/// packages, trees, secrets, groups) survives process restarts through
/// `<device>/mls.sqlite3`. `Default` builds an in-memory store (tests).
pub struct Provider {
    crypto: openmls_rust_crypto::RustCrypto,
    storage: SqliteStore,
}

impl Provider {
    /// Open (creating and migrating if necessary) an on-disk MLS store.
    pub fn open(path: &std::path::Path) -> Result<Self, TailnetError> {
        Self::from_connection(openmls_sqlite_storage::Connection::open(path)?)
    }

    fn from_connection(connection: openmls_sqlite_storage::Connection) -> Result<Self, TailnetError> {
        let mut storage = SqliteStore::new(connection);
        storage
            .run_migrations()
            .map_err(|e| TailnetError::Mls(format!("mls store migration failed: {e}")))?;
        Ok(Self {
            crypto: openmls_rust_crypto::RustCrypto::default(),
            storage,
        })
    }
}

impl Default for Provider {
    fn default() -> Self {
        Self::from_connection(
            openmls_sqlite_storage::Connection::open_in_memory()
                .expect("in-memory sqlite always opens"),
        )
        .expect("in-memory sqlite migration cannot fail")
    }
}

impl openmls_traits::OpenMlsProvider for Provider {
    type CryptoProvider = openmls_rust_crypto::RustCrypto;
    type RandProvider = openmls_rust_crypto::RustCrypto;
    type StorageProvider = SqliteStore;

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
            let identity = Identity::from_secret(std::fs::read_to_string(&secret_path)?.trim())?;
            // Heal secrets written by older versions with default (loose)
            // permissions: only the owner should ever read this file.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(
                    &secret_path,
                    std::fs::Permissions::from_mode(0o600),
                );
            }
            identity
        } else {
            let id = Identity::generate();
            // Created owner-only from the start: the nsec is the device's
            // master secret (Nostr, Noise, and MLS all derive from it).
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                use std::io::Write as _;
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&secret_path)?
                    .write_all(format!("{}\n", id.secret_hex()).as_bytes())?;
            }
            #[cfg(not(unix))]
            std::fs::write(&secret_path, format!("{}\n", id.secret_hex()))?;
            id
        };

        // Load MLS state (SQLite storage profile) if this device has one.
        let provider = Provider::open(&dir.join("mls.sqlite3"))?;

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

    /// Persist device state. MLS state is written to SQLite by OpenMLS itself
    /// as operations run; this only refreshes the group-id sidecar.
    fn persist(&self) -> Result<(), TailnetError> {
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
        let policy = TailnetPolicy {
            owner: self.identity.public_key().to_bytes().to_vec(),
        };
        let _group = MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            &group_config(&policy)?,
            group_id.clone(),
            self.credential_with_key()?,
        )
        .map_err(|e| TailnetError::Mls(e.to_string()))?;
        self.group_id = Some(group_id);
        self.persist()
    }

    /// The tailnet's membership and epoch (for `tailnet members`).
    pub fn list_members(&self) -> Result<Vec<MemberInfo>, TailnetError> {
        let group = self.group()?;
        let owner = group.group_id().as_slice().to_vec();
        let epoch = group.epoch().as_u64();
        let mut out = Vec::new();
        for m in group.members() {
            let npub = hex::encode(m.credential.serialized_content());
            out.push(MemberInfo {
                is_owner: m.credential.serialized_content() == owner.as_slice(),
                npub,
                epoch,
            });
        }
        Ok(out)
    }

    /// The member matching `npub` bytes, if it is in the tailnet.
    fn leaf_index_of(group: &MlsGroup, npub: &[u8]) -> Option<LeafNodeIndex> {
        group
            .members()
            .find(|m| m.credential.serialized_content() == npub)
            .map(|m| m.index)
    }

    fn credential_with_key(&self) -> Result<CredentialWithKey, TailnetError> {
        let identity = self.identity.public_key().to_bytes().to_vec();
        let credential = Credential::new(CredentialType::Basic, identity);
        Ok(CredentialWithKey {
            credential,
            signature_key: self.signer.public().into(),
        })
    }

    /// A key package for this device. It advertises the policy extension:
    /// a leaf node must cover every group-context extension of the tailnet
    /// it may join (add proposals and key updates validate this).
    fn key_package(
        &self,
        provider: &Provider,
        signer: &SignatureKeyPair,
    ) -> Result<KeyPackageBundle, TailnetError> {
        let capabilities = Capabilities::builder()
            .extensions(vec![ExtensionType::Unknown(POLICY_EXTENSION_TYPE)])
            .build();
        KeyPackage::builder()
            .leaf_node_capabilities(capabilities)
            .build(
                CIPHERSUITE,
                provider,
                signer,
                self.credential_with_key()?,
            )
            .map_err(|e| TailnetError::Mls(e.to_string()))
    }

    /// Publish our MLS key package (kind 30443) so an owner can invite us.
    /// With `target`, the package is tagged to that owner's npub: only they
    /// see the join request, and their invitation is the one we accept.
    pub async fn publish_key_package(
        &self,
        relays: &[String],
        target: Option<PublicKey>,
    ) -> Result<(), TailnetError> {
        let bundle = self.key_package(&self.provider, &self.signer)?;
        let bytes = bundle.key_package().tls_serialize_detached()?;

        // The bundle's private init/encryption keys just went into storage;
        // they are what will decrypt the owner's Welcome, so persist now.
        self.persist()?;

        let mut builder = EventBuilder::new(Kind::Custom(KEY_PACKAGE_KIND), hex::encode(bytes))
            .tag(Tag::identifier(KEY_PACKAGE_IDENTIFIER));
        if let Some(owner) = target {
            builder = builder.tag(Tag::public_key(owner));
        }
        let event = builder
            .finalize(self.identity.keys())
            .map_err(|e| TailnetError::Nostr(e))?;

        let client = crate::relay::connect_client(relays).await?;
        client.send_event(&event).await?;
        client.shutdown().await;
        Ok(())
    }

    /// Invite a device (by npub) into the tailnet: fetch its key package,
    /// commit the Add, gift-wrap the Welcome to it, and the commit to every
    /// other member (they must merge it to reach the new epoch), then persist
    /// our new epoch.
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

        let MlsMessageBodyOut::Welcome(welcome) = welcome.body() else {
            return Err(TailnetError::Mls("expected a Welcome from add_members".into()));
        };
        let commit_hex = hex::encode(commit.tls_serialize_detached()?);
        let invitee_payload = serde_json::to_string(&TailnetMessage {
            commit: commit_hex.clone(),
            welcome: Some(hex::encode(welcome.tls_serialize_detached()?)),
        })?;
        let member_payload = serde_json::to_string(&TailnetMessage {
            commit: commit_hex,
            welcome: None,
        })?;

        // Welcome to the invitee; commit to every other existing member so
        // the whole tailnet lands in the same epoch (and derives the same PSK).
        let mut targets: Vec<PublicKey> = Vec::new();
        for m in group.members() {
            if m.credential.serialized_content() == self.identity.public_key().to_bytes() {
                continue; // ourselves
            }
            if m.credential.serialized_content() == device.to_bytes() {
                continue; // the invitee gets the combined payload above
            }
            targets.push(PublicKey::from_slice(m.credential.serialized_content())?);
        }
        self.send_gift_wrap(&invitee_payload, device, relays).await?;
        for member in targets {
            self.send_gift_wrap(&member_payload, member, relays).await?;
        }
        Ok(())
    }

    /// Remove a device (by npub) from the tailnet: commit the Remove, deliver
    /// the commit to the remaining members so the epoch ratchets past the
    /// removed device, and persist. The removed device is deliberately left
    /// behind: its PSK stops matching, locking it out of every tunnel.
    pub async fn remove_member(
        &mut self,
        device: PublicKey,
        relays: &[String],
    ) -> Result<(), TailnetError> {
        let mut group = self.group()?;
        let leaf = Self::leaf_index_of(&group, &device.to_bytes())
            .ok_or_else(|| TailnetError::Mls(format!("{device} is not in this tailnet")))?;

        let (commit, _welcome, _info) = group
            .remove_members(&self.provider, &self.signer, &[leaf])
            .map_err(|e| TailnetError::Mls(e.to_string()))?;
        group
            .merge_pending_commit(&self.provider)
            .map_err(|e| TailnetError::Mls(e.to_string()))?;
        self.persist()?;

        let payload = serde_json::to_string(&TailnetMessage {
            commit: hex::encode(commit.tls_serialize_detached()?),
            welcome: None,
        })?;
        let remaining: Vec<PublicKey> = group
            .members()
            .filter(|m| m.credential.serialized_content() != self.identity.public_key().to_bytes())
            .map(|m| PublicKey::from_slice(m.credential.serialized_content()))
            .collect::<Result<_, _>>()?;
        for member in remaining {
            self.send_gift_wrap(&payload, member, relays).await?;
        }
        Ok(())
    }

    /// Receive gift-wrapped tailnet messages for up to `wait` and merge any
    /// commits addressed to us, enforcing the group's policy. This is how
    /// non-owner members follow the owner's epoch advances (invites,
    /// removals) and keep deriving the current tunnel PSK.
    pub async fn sync_tailnet(
        &mut self,
        relays: &[String],
        wait: Duration,
    ) -> Result<usize, TailnetError> {
        if self.group_id.is_none() {
            return Err(TailnetError::NoTailnet(self.dir.clone()));
        }
        let (tx, mut rx) = tokio::sync::mpsc::channel::<(PublicKey, String)>(16);
        let watch = tokio::spawn(crate::traversal::watch_tailnet(
            self.identity.clone(),
            relays.to_vec(),
            tx,
        ));
        let mut merged = 0usize;
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let msg = match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Some((sender, payload))) => (sender, payload),
                Ok(None) | Err(_) => break,
            };
            let payload: TailnetMessage = match serde_json::from_str(&msg.1) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("# ⚠️  undecodable tailnet message from {}: {e}", msg.0);
                    continue;
                }
            };
            if payload.welcome.is_some() {
                eprintln!("# ⚠️  got an unexpected invitation from {} (already in a tailnet)", msg.0);
                continue;
            }
            match self.process_commit(&payload.commit) {
                Ok(()) => {
                    merged += 1;
                    eprintln!("# ⬇️  merged commit from {} (epoch {})", msg.0, self.epoch()?);
                }
                Err(TailnetError::PolicyViolation(e)) => {
                    eprintln!("# 🚫 commit from {} rejected: {e}", msg.0);
                }
                Err(e) => eprintln!("# ⚠️  commit from {} not merged: {e}", msg.0),
            }
        }
        watch.abort();
        Ok(merged)
    }

    /// Merge one serialized commit into our group after checking the group's
    /// policy: MLS authenticates the commit, the policy decides if the
    /// committer may change the membership.
    fn process_commit(&mut self, commit_hex: &str) -> Result<(), TailnetError> {
        let mut group = self.group()?;
        let bytes = hex::decode(commit_hex)
            .map_err(|e| TailnetError::Mls(format!("bad commit hex: {e}")))?;
        let message = MlsMessageIn::tls_deserialize_exact(&mut bytes.as_slice())
            .map_err(|e| TailnetError::Mls(e.to_string()))?;
        let protocol: ProtocolMessage = match message.try_into() {
            Ok(p) => p,
            Err(_) => return Err(TailnetError::Mls("not a public MLS message".into())),
        };
        let processed = group
            .process_message(&self.provider, protocol)
            .map_err(|e| TailnetError::Mls(e.to_string()))?;
        let committer = processed.credential().serialized_content().to_vec();
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            return Err(TailnetError::Mls("expected a commit".into()));
        };
        // MLS authenticated the commit; the group's policy decides whether
        // this committer may change the membership. The commit carries the
        // (possibly new) group context with the policy extension.
        let policy = TailnetPolicy::from_context(staged.group_context())?;
        if !policy.authorizes(&committer) {
            return Err(TailnetError::PolicyViolation(hex::encode(committer)));
        }
        group
            .merge_staged_commit(&self.provider, *staged)
            .map_err(|e| TailnetError::Mls(e.to_string()))?;
        self.persist()
    }

    /// The group's current epoch (display).
    fn epoch(&self) -> Result<u64, TailnetError> {
        Ok(self.group()?.epoch().as_u64())
    }

    /// Gift-wrap `payload` (NIP-59) to `to`.
    async fn send_gift_wrap(
        &self,
        payload: &str,
        to: PublicKey,
        relays: &[String],
    ) -> Result<(), TailnetError> {
        let rumor = UnsignedEvent::new(
            self.identity.public_key(),
            Timestamp::now(),
            Kind::Custom(TAILNET_KIND),
            [],
            payload.to_string(),
        );
        let gift_wrap = GiftWrapBuilder::new(to, rumor)
            .expiration(Duration::from_secs(7 * 24 * 3600))
            .finalize(self.identity.keys())
            .map_err(|e| TailnetError::Nostr(e))?;

        let client = crate::relay::connect_client(relays).await?;
        client.send_event(&gift_wrap).await?;
        client.shutdown().await;
        Ok(())
    }

    /// Wait for a gift-wrapped tailnet invitation and join it.
    /// Wait for a gift-wrapped invitation and join the tailnet. With
    /// `expected_owner`, invitations from anyone else are ignored: the phone
    /// scanned a specific owner's QR, and only that tailnet may adopt it.
    pub async fn join_tailnet(
        &mut self,
        relays: &[String],
        expected_owner: Option<PublicKey>,
    ) -> Result<(), TailnetError> {
        if self.group_id.is_some() {
            // Local state says this device is already a member. Forgetting a
            // tailnet on the device (the mobile "disconnect") does not remove
            // it from the group, so this is the normal path when rejoining
            // after a disconnect: the existing membership is still valid.
            eprintln!("# ✅ already a member of a tailnet - nothing to join");
            return Ok(());
        }
        let (tx, mut rx) = tokio::sync::mpsc::channel::<(PublicKey, String)>(16);
        let watch = tokio::spawn(crate::traversal::watch_tailnet(
            self.identity.clone(),
            relays.to_vec(),
            tx,
        ));
        eprintln!("# ⏳ waiting for a tailnet invitation (Ctrl-C to give up)…");
        // Gift wraps are signed, so the sender cannot be spoofed: an
        // invitation from anyone but the expected owner is dropped unheard.
        let (sender, payload) = loop {
            let (sender, payload) = rx.recv().await.ok_or(TailnetError::JoinTimeout)?;
            if expected_owner.is_some() && expected_owner != Some(sender) {
                eprintln!("# ignoring an invitation from {sender} (not the expected owner)");
                continue;
            }
            break (sender, payload);
        };
        watch.abort();

        let msg: TailnetMessage = serde_json::from_str(&payload)?;
        eprintln!("# ✉️  invitation received from {sender} - joining…");

        let welcome_bytes = hex::decode(&msg.welcome.ok_or_else(|| {
            TailnetError::Mls("invitation carries no Welcome".into())
        })?)?;
        let welcome =
            Welcome::tls_deserialize_exact(&mut welcome_bytes.as_slice())
                .map_err(|e| TailnetError::Mls(e.to_string()))?;
        let staged = StagedWelcome::new_from_welcome(
            &self.provider,
            &join_config(),
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
    /// MLS Welcome carrying the group secrets for the invitee. Absent in
    /// commits fanned out to existing members (epoch propagation).
    welcome: Option<String>,
}

/// The tailnet's access policy, carried as a GroupContext extension so it is
/// authenticated by the group itself and inherited by every joiner.
///
/// Single-owner tailnets: only the owner may add or remove devices. Members
/// enforce this at commit-merge time (see `process_commit`) - an MLS commit
/// is signed, so the committer's credential is checked against the policy.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct TailnetPolicy {
    /// npub bytes of the tailnet's owner.
    pub owner: Vec<u8>,
}

impl TailnetPolicy {
    /// The policy extension for a tailnet owned by `owner` (npub bytes).
    fn extension(owner: &[u8]) -> Result<Extension, TailnetError> {
        let policy = TailnetPolicy {
            owner: owner.to_vec(),
        };
        Ok(Extension::Unknown(
            POLICY_EXTENSION_TYPE,
            UnknownExtension(serde_json::to_vec(&policy)?),
        ))
    }

    /// Read the policy out of a group context (the one a commit or Welcome
    /// carries - MlsGroup keeps its current context private).
    fn from_context(context: &GroupContext) -> Result<Self, TailnetError> {
        for ext in context.extensions().iter() {
            if let Extension::Unknown(POLICY_EXTENSION_TYPE, UnknownExtension(bytes)) = ext {
                return Ok(serde_json::from_slice(bytes)?);
            }
        }
        Err(TailnetError::Mls("tailnet policy extension missing".into()))
    }

    /// Is `identity` (credential bytes) allowed to add/remove members?
    fn authorizes(&self, identity: &[u8]) -> bool {
        identity == self.owner
    }
}

/// The tailnet's current membership: npub + MLS leaf index per device.
pub struct MemberInfo {
    /// x-only npub hex, for display and CLI round-trips.
    pub npub: String,
    pub epoch: u64,
    pub is_owner: bool,
}

fn group_config(policy: &TailnetPolicy) -> Result<MlsGroupCreateConfig, TailnetError> {
    let owner_ext = TailnetPolicy::extension(&policy.owner)?;
    let extensions = Extensions::single(owner_ext)
        .map_err(|e| TailnetError::Mls(e.to_string()))?;
    // The owner's leaf must advertise the policy extension too: its commits
    // carry an update path that has to support every group-context extension.
    let capabilities = Capabilities::builder()
        .extensions(vec![ExtensionType::Unknown(POLICY_EXTENSION_TYPE)])
        .build();
    Ok(MlsGroupCreateConfig::builder()
        .use_ratchet_tree_extension(true)
        .capabilities(capabilities)
        .with_group_context_extensions(extensions)
        .build())
}

/// Join-side half of the config (the policy extension arrives with the group
/// context; a joiner only needs the framing parameters).
fn join_config() -> MlsGroupJoinConfig {
    MlsGroupCreateConfig::builder()
        .use_ratchet_tree_extension(true)
        .build()
        .join_config()
        .clone()
}

/// The device's MLS Ed25519 signing key, derived from its nostr secret - one
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
        let policy = TailnetPolicy {
            owner: owner.public_key().to_bytes().to_vec(),
        };
        let mut group = MlsGroup::new_with_group_id(
            &owner_provider,
            &owner_signer,
            &group_config(&policy)?,
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
        let invitee_bundle = key_package_with_policy_capability(
            &invitee_provider,
            &invitee_signer,
            invitee_credential,
        )?;

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
        let _ = commit;

        // Invitee joins from the Welcome.
        let staged = StagedWelcome::new_from_welcome(
            &invitee_provider,
            &join_config(),
            welcome,
            None,
        )
        .map_err(|e| TailnetError::Mls(e.to_string()))?;
        let joined_staged_context = staged.group_context().clone();
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

        // The policy extension made it into the joiner's group context.
        let read_policy = TailnetPolicy::from_context(&joined_staged_context)?;
        assert_eq!(read_policy.owner, owner.public_key().to_bytes());
        assert!(read_policy.authorizes(&owner.public_key().to_bytes()));
        assert!(!read_policy.authorizes(&invitee.public_key().to_bytes()));
        Ok(())
    }

    /// A device directory is the unit of persistence: same directory, same
    /// identity, same group, same PSK - across processes.
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

    /// Build an owner + two members, all in the same epoch: the second Add's
    /// commit is processed by the first member through `process_message` (the
    /// `sync_tailnet` path, minus the transport).
    struct TailnetFixture {
        owner_provider: Provider,
        owner_signer: SignatureKeyPair,
        owner_group: MlsGroup,
        a: Identity,
        b: Identity,
        a_group: MlsGroup,
        a_provider: Provider,
        a_signer: SignatureKeyPair,
        b_group: MlsGroup,
        b_provider: Provider,
    }

    fn cred(id: &Identity, signer: &SignatureKeyPair) -> CredentialWithKey {
        CredentialWithKey {
            credential: Credential::new(CredentialType::Basic, id.public_key().to_bytes().to_vec()),
            signature_key: signer.public().into(),
        }
    }

    fn fixture_two_members() -> Result<TailnetFixture, TailnetError> {
        let owner = Identity::generate();
        let a = Identity::generate();
        let b = Identity::generate();
        let owner_provider = Provider::default();
        let a_provider = Provider::default();
        let b_provider = Provider::default();
        let owner_signer = mls_signer(&owner)?;
        let a_signer = mls_signer(&a)?;
        let b_signer = mls_signer(&b)?;
        let policy = TailnetPolicy {
            owner: owner.public_key().to_bytes().to_vec(),
        };

        let mut owner_group = MlsGroup::new_with_group_id(
            &owner_provider,
            &owner_signer,
            &group_config(&policy)?,
            GroupId::from_slice(&owner.public_key().to_bytes()),
            cred(&owner, &owner_signer),
        )
        .map_err(|e| TailnetError::Mls(e.to_string()))?;

        let bundle_for = |provider: &Provider, signer: &SignatureKeyPair, id: &Identity| {
            key_package_with_policy_capability(
                provider,
                signer,
                cred(id, signer),
            )
        };

        // Owner adds A, which joins from the Welcome (already in the new
        // epoch - it must not merge its own Add commit).
        let kp_a = bundle_for(&a_provider, &a_signer, &a)?;
        let (_commit_a, welcome_a, _) = owner_group
            .add_members(&owner_provider, &owner_signer, &[kp_a.key_package().clone()])
            .map_err(|e| TailnetError::Mls(e.to_string()))?;
        owner_group
            .merge_pending_commit(&owner_provider)
            .map_err(|e| TailnetError::Mls(e.to_string()))?;
        let a_group = join_from_welcome(&a_provider, &welcome_a, &a_signer)?;

        // Owner adds B; A follows via the commit (the `sync_tailnet` path).
        let kp_b = bundle_for(&b_provider, &b_signer, &b)?;
        let (commit_b, welcome_b, _) = owner_group
            .add_members(&owner_provider, &owner_signer, &[kp_b.key_package().clone()])
            .map_err(|e| TailnetError::Mls(e.to_string()))?;
        owner_group
            .merge_pending_commit(&owner_provider)
            .map_err(|e| TailnetError::Mls(e.to_string()))?;
        let mut a_group = a_group;
        let staged = stage_commit(&mut a_group, &a_provider, &commit_b)?;
        a_group
            .merge_staged_commit(&a_provider, *staged)
            .map_err(|e| TailnetError::Mls(e.to_string()))?;
        let b_group = join_from_welcome(&b_provider, &welcome_b, &b_signer)?;

        Ok(TailnetFixture {
            owner_provider,
            owner_signer,
            owner_group,
            a,
            b,
            a_group,
            a_provider,
            a_signer,
            b_group,
            b_provider,
        })
    }

    /// All three members derive the same PSK, and a removal ratchets the
    /// epoch so the removed device's PSK stops matching.
    #[test]
    fn removal_ratchets_epoch_and_locks_out_device() -> Result<(), TailnetError> {
        let mut fx = fixture_two_members()?;

        let psk_of = |group: &MlsGroup, provider: &Provider| -> Result<Vec<u8>, TailnetError> {
            group
                .export_secret(provider.crypto(), EXPORTER_LABEL, &[], 32)
                .map_err(|e| TailnetError::Mls(e.to_string()))
        };
        let psk_before = psk_of(&fx.owner_group, &fx.owner_provider)?;
        assert_eq!(psk_before, psk_of(&fx.a_group, &fx.a_provider)?);
        assert_eq!(psk_before, psk_of(&fx.b_group, &fx.b_provider)?);

        // Owner removes A; the commit is fanned out to the remaining members.
        let leaf = fx
            .owner_group
            .members()
            .find(|m| m.credential.serialized_content() == fx.a.public_key().to_bytes())
            .map(|m| m.index)
            .ok_or_else(|| TailnetError::Mls("member A missing".into()))?;
        let (commit, _w, _) = fx
            .owner_group
            .remove_members(&fx.owner_provider, &fx.owner_signer, &[leaf])
            .map_err(|e| TailnetError::Mls(e.to_string()))?;
        fx.owner_group
            .merge_pending_commit(&fx.owner_provider)
            .map_err(|e| TailnetError::Mls(e.to_string()))?;

        // The removed device never sees the commit: its PSK is now stale.
        assert_ne!(psk_before, psk_of(&fx.owner_group, &fx.owner_provider)?);

        // A remaining member (B) merges the commit and ratchets to the new
        // epoch - locked out together with A is nobody but A.
        let mut b_group = fx.b_group;
        let staged = stage_commit(&mut b_group, &fx.b_provider, &commit)?;
        b_group
            .merge_staged_commit(&fx.b_provider, *staged)
            .map_err(|e| TailnetError::Mls(e.to_string()))?;
        assert_eq!(
            psk_of(&fx.owner_group, &fx.owner_provider)?,
            psk_of(&b_group, &fx.b_provider)?,
            "a synced member must follow the ratchet"
        );
        Ok(())
    }

    /// The policy is the law: a commit from a non-owner member (even a valid,
    /// correctly signed one) must be rejected by the receiving member.
    #[test]
    fn acl_rejects_non_owner_commit() -> Result<(), TailnetError> {
        let mut fx = fixture_two_members()?;

        // Member A (not the owner) commits the removal of B - legal MLS, but
        // the tailnet's policy says only the owner may change membership.
        let leaf_b = fx
            .a_group
            .members()
            .find(|m| m.credential.serialized_content() == fx.b.public_key().to_bytes())
            .map(|m| m.index)
            .ok_or_else(|| TailnetError::Mls("member B missing".into()))?;
        let (commit, _w, _) = fx
            .a_group
            .remove_members(&fx.a_provider, &fx.a_signer, &[leaf_b])
            .map_err(|e| TailnetError::Mls(e.to_string()))?;

        // The receiver (playing the owner's tailnet device) stages it fine -
        // MLS authenticates A - but the policy forbids the merge.
        let mut owner_group = fx.owner_group;
        let message = commit_a_into_in(&commit)?;
        let protocol: ProtocolMessage = match message.try_into() {
            Ok(p) => p,
            Err(_) => return Err(TailnetError::Mls("not a public MLS message".into())),
        };
        let processed = owner_group
            .process_message(&fx.owner_provider, protocol)
            .map_err(|e| TailnetError::Mls(e.to_string()))?;
        let policy = match processed.content() {
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                TailnetPolicy::from_context(staged.group_context())?
            }
            _ => return Err(TailnetError::Mls("expected a commit".into())),
        };
        assert!(
            !policy.authorizes(processed.credential().serialized_content()),
            "fixture broken: committer should not be the owner"
        );
        assert!(matches!(
            processed.content(),
            ProcessedMessageContent::StagedCommitMessage(_)
        ));
        // Refusing to merge leaves the epoch unchanged: the ratchet moves
        // only when `merge_staged_commit` runs.
        assert_eq!(owner_group.epoch(), fx.a_group.epoch());
        Ok(())
    }
}

/// Deserialize an owner's serialized commit into a message a member can
/// process.
#[cfg(test)]
fn commit_a_into_in(commit: &MlsMessageOut) -> Result<MlsMessageIn, TailnetError> {
    let bytes = commit.tls_serialize_detached()?;
    Ok(MlsMessageIn::tls_deserialize_exact(&mut bytes.as_slice())
        .map_err(|e| TailnetError::Mls(e.to_string()))?)
}

/// A test key package that advertises the policy extension, matching what
/// `publish_key_package` puts on the relays.
#[cfg(test)]
fn key_package_with_policy_capability(
    provider: &Provider,
    signer: &SignatureKeyPair,
    credential: CredentialWithKey,
) -> Result<KeyPackageBundle, TailnetError> {
    let capabilities = Capabilities::builder()
        .extensions(vec![ExtensionType::Unknown(POLICY_EXTENSION_TYPE)])
        .build();
    KeyPackage::builder()
        .leaf_node_capabilities(capabilities)
        .build(CIPHERSUITE, provider, signer, credential)
        .map_err(|e| TailnetError::Mls(e.to_string()))
}

/// Process a serialized commit into a staged commit for authorization checks.
#[cfg(test)]
fn stage_commit(
    group: &mut MlsGroup,
    provider: &Provider,
    commit: &MlsMessageOut,
) -> Result<Box<StagedCommit>, TailnetError> {
    let message = commit_a_into_in(commit)?;
    let protocol: ProtocolMessage = match message.try_into() {
        Ok(p) => p,
        Err(_) => return Err(TailnetError::Mls("not a public MLS message".into())),
    };
    match group
        .process_message(provider, protocol)
        .map_err(|e| TailnetError::Mls(e.to_string()))?
        .into_content()
    {
        ProcessedMessageContent::StagedCommitMessage(staged) => Ok(staged),
        _ => Err(TailnetError::Mls("expected a commit".into())),
    }
}

/// Join a fresh member from a Welcome (the `join_tailnet` path).
#[cfg(test)]
fn join_from_welcome(
    provider: &Provider,
    welcome: &MlsMessageOut,
    _signer: &SignatureKeyPair,
) -> Result<MlsGroup, TailnetError> {
    let MlsMessageBodyOut::Welcome(welcome) = welcome.body() else {
        return Err(TailnetError::Mls("expected a Welcome".into()));
    };
    let staged = StagedWelcome::new_from_welcome(
        provider,
        &join_config(),
        welcome.clone(),
        None,
    )
    .map_err(|e| TailnetError::Mls(e.to_string()))?;
    staged
        .into_group(provider)
        .map_err(|e| TailnetError::Mls(e.to_string()))
}
