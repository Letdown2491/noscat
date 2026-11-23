//! The mesh: one MLS group per owner's set of devices, built on OpenMLS.
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
//! `mesh.json` sidecar so `Device::open` knows which group to load.

use std::path::PathBuf;
use std::time::Duration;

use nostr::nips::nip59::{extract_rumor, GiftWrapBuilder};
use nostr::prelude::*;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};

use crate::identity::Identity;

/// Marmot-compatible key-package slot: a device publishes its MLS key package
/// here so the mesh owner can add it.
pub const KEY_PACKAGE_KIND: u16 = 30443;
/// Draft slot for gift-wrapped mesh messages (Welcomes, later commits).
pub const MESH_KIND: u16 = 30444;

/// How many merged commits the owner keeps in `commits.json` for
/// `mesh resend`. Small by design: each resend re-publishes the whole
/// chain oldest first (a straggler must merge them in order), and eight
/// covers any realistic straggle window between membership changes.
const COMMIT_JOURNAL_KEEP: usize = 8;
/// Replaceable `d` tag scoping a device's key package to one slot.
pub const KEY_PACKAGE_IDENTIFIER: &str = "noscat-mesh-kp-v1";
/// Exporter label for the tunnel PSK (see `crate::tunnel`).
pub const EXPORTER_LABEL: &str = "noscat/tunnel-psk-v1";
/// GroupContext extension type carrying the mesh policy. RFC 9420
/// reserves 0xffa0..=0xffff for private use; OpenMLS passes unknown types
/// through, which is exactly the Marmot-shaped hook for group policy.
const POLICY_EXTENSION_TYPE: u16 = 0xffa0;
/// Domain separation for deriving the MLS Ed25519 key from the identity secret.
const MLS_DERIVE_INFO: &[u8] = b"noscat/mls-ed25519-v1";

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

#[derive(Debug, thiserror::Error)]
pub enum MeshError {
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
    #[error("device directory {0} does not hold a mesh (run `mesh create` first)")]
    NoMesh(PathBuf),
    #[error("timed out waiting for a mesh invitation")]
    JoinTimeout,
    #[error("not stored by any relay for: {0} (run `mesh resend` on the owner once the relays answer again)")]
    Delivery(String),
    #[error("commit rejected: {0} is not authorized to change the mesh (policy is owner-only)")]
    PolicyViolation(String),
}

impl From<tls_codec::Error> for MeshError {
    fn from(e: tls_codec::Error) -> Self {
        MeshError::Mls(e.to_string())
    }
}

/// A device: nostr identity + MLS state, persisted to a directory.
pub struct Device {
    pub dir: PathBuf,
    pub identity: Identity,
    provider: Provider,
    signer: SignatureKeyPair,
    /// None until the device creates or joins a mesh.
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
    pub fn open(path: &std::path::Path) -> Result<Self, MeshError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // The store holds signature keys, encryption keys, and the epoch
        // PSKs: create it owner-only from the start (chmod-after-open
        // leaves a window) and heal loose modes written by older versions.
        #[cfg(unix)]
        {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
            {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        let connection = openmls_sqlite_storage::Connection::open(path)?;
        // Concurrent connections are routine (the node's accept loop, the
        // dial-side PSK derivation, mesh sync): with stock defaults a
        // reader/writer collision is SQLITE_BUSY, which callers then
        // degrade into a silently stale-epoch PSK. WAL plus a busy
        // timeout turn those into waits instead.
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| MeshError::Sqlite(e))?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(|e| MeshError::Sqlite(e))?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        Self::from_connection(connection)
    }

    fn from_connection(connection: openmls_sqlite_storage::Connection) -> Result<Self, MeshError> {
        let mut storage = SqliteStore::new(connection);
        storage
            .run_migrations()
            .map_err(|e| MeshError::Mls(format!("mls store migration failed: {e}")))?;
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
    pub fn open(dir: &std::path::Path) -> Result<Self, MeshError> {
        std::fs::create_dir_all(dir)?;
        let secret_path = dir.join("identity.nsec");
        let identity = if secret_path.exists() {
            let identity = Identity::from_secret(std::fs::read_to_string(&secret_path)?.trim())?;
            // Heal secrets written by older versions with default (loose)
            // permissions: only the owner should ever read this file.
            crate::fsutil::heal_secret_mode(&secret_path);
            identity
        } else {
            let id = Identity::generate();
            // Created owner-only from the start: the nsec is the device's
            // master secret (Nostr, Noise, and MLS all derive from it). A
            // lost create race (two concurrent opens of a fresh dir) reads
            // the winner instead of overwriting it - overwriting would
            // fork this device's key from what its MLS store will hold.
            let secret = format!("{}\n", id.secret_hex());
            match crate::fsutil::create_secret_file(&secret_path, &secret)? {
                true => id,
                false => {
                    Identity::from_secret(std::fs::read_to_string(&secret_path)?.trim())?
                }
            }
        };

        // Load MLS state (SQLite storage profile) if this device has one.
        let provider = Provider::open(&dir.join("mls.sqlite3"))?;

        let signer = mls_signer(&identity)?;
        signer
            .store(&provider.storage)
            .map_err(|e| MeshError::Mls(format!("cannot store signer: {e}")))?;

        // Group id is tracked in a small sidecar (storage holds the state).
        // Migrate the pre-rename sidecar name once (tailnet -> mesh).
        let gid_path = dir.join("mesh.json");
        let legacy_path = dir.join("tailnet.json");
        if !gid_path.exists() && legacy_path.exists() {
            std::fs::rename(&legacy_path, &gid_path)?;
        }
        let group_id = match std::fs::read_to_string(&gid_path) {
            Ok(json) => match hex::decode(json.trim()) {
                Ok(gid) => Some(GroupId::from_slice(&gid)),
                // A torn sidecar (a crash mid-write in older versions;
                // the atomic writer prevents new ones) must not brick the
                // device: fail loud, continue mesh-less.
                Err(e) => {
                    eprintln!("# ⚠️  {} is corrupt, ignoring: {e}", gid_path.display());
                    None
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            // EACCES or the like is a real problem, not "no mesh".
            Err(e) => return Err(e.into()),
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
    /// as operations run; this only refreshes the group-id sidecar. The
    /// sidecar is written atomically (a torn mesh.json used to brick the
    /// device dir: open hard-fails on undecodable hex) and skipped when
    /// it already agrees - the group id never changes after create/join,
    /// so this is normally a no-op per merged commit.
    fn persist(&self) -> Result<(), MeshError> {
        if let Some(gid) = &self.group_id {
            let gid_path = self.dir.join("mesh.json");
            let json = format!("{}\n", hex::encode(gid.as_slice()));
            if std::fs::read_to_string(&gid_path).is_ok_and(|s| s == json) {
                return Ok(());
            }
            crate::fsutil::write_atomic(&gid_path, json.as_bytes())?;
        }
        Ok(())
    }

    /// Append a merged commit to the owner's journal (`commits.json` in
    /// the device dir, oldest first, last [`COMMIT_JOURNAL_KEEP`] kept).
    /// This is the healing store for `mesh resend`: a member that missed
    /// the live fan-out (the wrap was never stored by any relay) can only
    /// be fixed by the owner re-publishing the commit - backfill fetches
    /// what relays stored, and this never was. Written atomically: a torn
    /// journal must not fail invite/remove after the commit is merged.
    fn record_commit(&self, commit_hex: &str) -> Result<(), MeshError> {
        let mut journal = self.commit_journal()?;
        journal.push(commit_hex.to_string());
        let len = journal.len();
        if len > COMMIT_JOURNAL_KEEP {
            journal.drain(..len - COMMIT_JOURNAL_KEEP);
        }
        let path = self.dir.join("commits.json");
        crate::fsutil::write_atomic(&path, &serde_json::to_vec(&journal)?)?;
        Ok(())
    }

    /// The owner's merged-commit journal, oldest first. An empty, absent,
    /// or corrupt journal just means "nothing to resend" (or this device
    /// is not the owner - only owners commit, so only owners have
    /// entries): the journal only weakens healing, it must never fail a
    /// membership operation.
    fn commit_journal(&self) -> Result<Vec<String>, MeshError> {
        let path = self.dir.join("commits.json");
        match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice(&bytes) {
                Ok(journal) => Ok(journal),
                Err(e) => {
                    tracing::warn!(
                        file = %path.display(),
                        "commit journal unreadable, treating as empty: {e}"
                    );
                    Ok(Vec::new())
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e.into()),
        }
    }

    /// The group's current epoch tunnel PSK. Membership is authorization.
    pub fn tunnel_psk(&self) -> Result<Vec<u8>, MeshError> {
        let group = self.group()?;
        let psk = group
            .export_secret(self.provider.crypto(), EXPORTER_LABEL, &[], 32)
            .map_err(|e| MeshError::Mls(e.to_string()))?;
        Ok(psk)
    }

    fn group(&self) -> Result<MlsGroup, MeshError> {
        let gid = self
            .group_id
            .as_ref()
            .ok_or_else(|| MeshError::NoMesh(self.dir.clone()))?;
        MlsGroup::load(self.provider.storage(), gid)
            .map_err(|e| MeshError::Mls(e.to_string()))?
            .ok_or_else(|| MeshError::Mls("group state missing from storage".into()))
    }

    /// Create a mesh owned by this device.
    pub fn create_mesh(&mut self) -> Result<(), MeshError> {
        if self.group_id.is_some() {
            return Err(MeshError::Mls(format!(
                "{} already has a mesh; use a fresh device directory to own another",
                self.identity.npub()
            )));
        }
        let group_id = GroupId::from_slice(&self.identity.public_key().to_bytes());
        let policy = MeshPolicy {
            owner: self.identity.public_key().to_bytes().to_vec(),
        };
        let _group = MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            &group_config(&policy)?,
            group_id.clone(),
            self.credential_with_key()?,
        )
        .map_err(|e| MeshError::Mls(e.to_string()))?;
        self.group_id = Some(group_id);
        self.persist()
    }

    /// The mesh's membership and epoch (for `mesh members`).
    pub fn list_members(&self) -> Result<Vec<MemberInfo>, MeshError> {
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

    /// The member matching `npub` bytes, if it is in the mesh.
    fn leaf_index_of(group: &MlsGroup, npub: &[u8]) -> Option<LeafNodeIndex> {
        group
            .members()
            .find(|m| m.credential.serialized_content() == npub)
            .map(|m| m.index)
    }

    fn credential_with_key(&self) -> Result<CredentialWithKey, MeshError> {
        let identity = self.identity.public_key().to_bytes().to_vec();
        let credential = Credential::new(CredentialType::Basic, identity);
        Ok(CredentialWithKey {
            credential,
            signature_key: self.signer.public().into(),
        })
    }

    /// A key package for this device. It advertises the policy extension:
    /// a leaf node must cover every group-context extension of the mesh
    /// it may join (add proposals and key updates validate this).
    fn key_package(
        &self,
        provider: &Provider,
        signer: &SignatureKeyPair,
    ) -> Result<KeyPackageBundle, MeshError> {
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
            .map_err(|e| MeshError::Mls(e.to_string()))
    }

    /// Publish our MLS key package (kind 30443) so an owner can invite us.
    /// With `target`, the package is tagged to that owner's npub: only they
    /// see the join request, and their invitation is the one we accept.
    pub async fn publish_key_package(
        &self,
        relays: &[String],
        target: Option<PublicKey>,
    ) -> Result<(), MeshError> {
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
            .map_err(|e| MeshError::Nostr(e))?;

        let client = crate::relay::connect_client(relays).await?;
        client.send_event(&event).await?;
        client.shutdown().await;
        Ok(())
    }

    /// Invite a device (by npub) into the mesh: fetch its key package,
    /// commit the Add, gift-wrap the Welcome to it, and the commit to every
    /// other member (they must merge it to reach the new epoch), then persist
    /// our new epoch.
    pub async fn invite(
        &mut self,
        device: PublicKey,
        relays: &[String],
    ) -> Result<(), MeshError> {
        let mut group = self.group()?;

        let kp_event = crate::relay::fetch_key_package(relays, device)
            .await?
            .ok_or_else(|| MeshError::Mls(format!("no key package found for {device}")))?;
        let kp_bytes = hex::decode(&kp_event.content)
            .map_err(|e| MeshError::Mls(format!("bad key package hex: {e}")))?;
        let key_package_in = KeyPackageIn::tls_deserialize_exact(&mut kp_bytes.as_slice())
            .map_err(|e| MeshError::Mls(e.to_string()))?;
        let key_package = key_package_in
            .validate(self.provider.crypto(), ProtocolVersion::default())
            .map_err(|e| MeshError::Mls(e.to_string()))?;
        // The key package must belong to the device we are inviting: a
        // malicious device can publish a package carrying someone else's
        // credential (its own MLS signature still validates), which would
        // seat it in the group under the victim's identity.
        if key_package.leaf_node().credential().serialized_content() != device.to_bytes().to_vec()
        {
            return Err(MeshError::Mls(format!(
                "key package of {device} carries a different credential"
            )));
        }

        let (commit, welcome, _info) = group
            .add_members(&self.provider, &self.signer, &[key_package])
            .map_err(|e| MeshError::Mls(e.to_string()))?;
        group
            .merge_pending_commit(&self.provider)
            .map_err(|e| MeshError::Mls(e.to_string()))?;
        let commit_hex = hex::encode(commit.tls_serialize_detached()?);
        // Journal before the sidecar persist: a crash between the two
        // advances the epoch but must not lose the commit from the
        // resend journal (a replayed entry is idempotent on the
        // receiving side - epoch-skip).
        self.record_commit(&commit_hex)?;
        self.persist()?;

        let MlsMessageBodyOut::Welcome(welcome) = welcome.body() else {
            return Err(MeshError::Mls("expected a Welcome from add_members".into()));
        };
        let invitee_payload = serde_json::to_string(&MeshMessage {
            commit: commit_hex.clone(),
            welcome: Some(hex::encode(welcome.tls_serialize_detached()?)),
        })?;
        let member_payload = serde_json::to_string(&MeshMessage {
            commit: commit_hex,
            welcome: None,
        })?;

        // Welcome to the invitee; commit to every other existing member so
        // the whole mesh lands in the same epoch (and derives the same PSK).
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
        // One relay session carries the whole fan-out: the invitee's
        // combined payload plus the commit to every other member.
        let mut items: Vec<(PublicKey, &str)> = vec![(device, invitee_payload.as_str())];
        for member in targets {
            items.push((member, member_payload.as_str()));
        }
        self.send_gift_waps(relays, &items).await
    }

    /// Remove a device (by npub) from the mesh: commit the Remove, deliver
    /// the commit to the remaining members so the epoch ratchets past the
    /// removed device, and persist. The removed device is deliberately left
    /// behind: its PSK stops matching, locking it out of every tunnel.
    pub async fn remove_member(
        &mut self,
        device: PublicKey,
        relays: &[String],
    ) -> Result<(), MeshError> {
        let mut group = self.group()?;
        let leaf = Self::leaf_index_of(&group, &device.to_bytes())
            .ok_or_else(|| MeshError::Mls(format!("{device} is not in this mesh")))?;

        let (commit, _welcome, _info) = group
            .remove_members(&self.provider, &self.signer, &[leaf])
            .map_err(|e| MeshError::Mls(e.to_string()))?;
        group
            .merge_pending_commit(&self.provider)
            .map_err(|e| MeshError::Mls(e.to_string()))?;
        let commit_hex = hex::encode(commit.tls_serialize_detached()?);
        // Journal before the sidecar persist (see invite).
        self.record_commit(&commit_hex)?;
        self.persist()?;

        let payload = serde_json::to_string(&MeshMessage {
            commit: commit_hex,
            welcome: None,
        })?;
        let remaining: Vec<PublicKey> = group
            .members()
            .filter(|m| m.credential.serialized_content() != self.identity.public_key().to_bytes())
            .map(|m| PublicKey::from_slice(m.credential.serialized_content()))
            .collect::<Result<_, _>>()?;
        let items: Vec<(PublicKey, &str)> = remaining
            .iter()
            .map(|m| (*m, payload.as_str()))
            .collect();
        self.send_gift_waps(relays, &items).await
    }

    /// Re-publish the owner's recorded commit chain (the `commits.json`
    /// journal, oldest first) to every other member, or to the one named
    /// by `to`. The healing path for a member stranded at a stale epoch:
    /// its own `mesh sync` cannot help when the original wrap was never
    /// stored by any relay - this re-gift-wraps the commits so the next
    /// sync (live or backfill) delivers them. Already-current members
    /// skip the replays by epoch, so resending is safe mid-flight.
    /// Returns how many gift wraps went out. Only the owner has a journal
    /// (only the owner commits), so anywhere else this is an error.
    pub async fn resend_commits(
        &mut self,
        to: Option<PublicKey>,
        relays: &[String],
    ) -> Result<usize, MeshError> {
        if self.group_id.is_none() {
            return Err(MeshError::NoMesh(self.dir.clone()));
        }
        let journal = self.commit_journal()?;
        if journal.is_empty() {
            return Err(MeshError::Mls(
                "no recorded commits to resend (only the mesh owner commits; \
                 run this on the owner's device)"
                    .into(),
            ));
        }
        let group = self.group()?;
        let targets: Vec<PublicKey> = match to {
            Some(pk) => vec![pk],
            None => group
                .members()
                .filter(|m| m.credential.serialized_content() != self.identity.public_key().to_bytes())
                .map(|m| PublicKey::from_slice(m.credential.serialized_content()))
                .collect::<Result<_, _>>()?,
        };
        if targets.is_empty() {
            return Err(MeshError::Mls("no other members to resend to".into()));
        }
        let mut items: Vec<(PublicKey, &str)> = Vec::new();
        let mut owned = Vec::new();
        for commit_hex in &journal {
            owned.push(serde_json::to_string(&MeshMessage {
                commit: commit_hex.clone(),
                welcome: None,
            })?);
        }
        for target in &targets {
            for payload in &owned {
                items.push((*target, payload.as_str()));
            }
        }
        let sent = items.len();
        self.send_gift_waps(relays, &items).await?;
        Ok(sent)
    }

    /// Receive gift-wrapped mesh messages for up to `wait` and merge any
    /// commits addressed to us, enforcing the group's policy. This is how
    /// non-owner members follow the owner's epoch advances (invites,
    /// removals) and keep deriving the current tunnel PSK.
    ///
    /// Backfill first, then live: gift wraps are stored on the relays for
    /// their 7-day expiry, and a member that was offline at commit time
    /// (app closed, network switch, relay blip) would otherwise never see
    /// that commit - its group stays at the old epoch and it derives a
    /// stale tunnel PSK. The one-shot fetch (oldest first) closes that
    /// gap; the live listen keeps today's semantics for messages published
    /// while we wait.
    pub async fn sync_mesh(
        &mut self,
        relays: &[String],
        wait: Duration,
    ) -> Result<usize, MeshError> {
        if self.group_id.is_none() {
            return Err(MeshError::NoMesh(self.dir.clone()));
        }
        let mut merged = self.backfill_commits(relays).await;
        let (tx, mut rx) = tokio::sync::mpsc::channel::<(PublicKey, String)>(16);
        let watch = tokio::spawn(crate::traversal::watch_mesh(
            self.identity.clone(),
            relays.to_vec(),
            tx,
        ));
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let msg = match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Some((sender, payload))) => (sender, payload),
                Ok(None) | Err(_) => break,
            };
            let payload: MeshMessage = match serde_json::from_str(&msg.1) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("# ⚠️  undecodable mesh message from {}: {e}", msg.0);
                    continue;
                }
            };
            merged += self.accept_mesh_message(msg.0, &payload);
        }
        watch.abort();
        Ok(merged)
    }

    /// One-shot fetch of stored gift-wrapped mesh messages addressed to us
    /// (the backfill for commits missed while offline), each merged oldest
    /// first through the same enforcement as the live path. Relay fetch
    /// failures degrade to "no backfill": the live listen still runs.
    async fn backfill_commits(&mut self, relays: &[String]) -> usize {
        let filter = Filter::new()
            .kind(Kind::GiftWrap)
            .pubkey(self.identity.public_key());
        let client = match crate::relay::connect_client(relays).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("# ⚠️  mesh backfill skipped (relays unreachable): {e}");
                return 0;
            }
        };
        let events = match client
            .fetch_events(filter)
            .timeout(crate::relay::FETCH_WAIT)
            .await
        {
            Ok(events) => events,
            Err(e) => {
                eprintln!("# ⚠️  mesh backfill fetch failed: {e}");
                client.shutdown().await;
                return 0;
            }
        };
        client.shutdown().await;

        // Unwrap and order by epoch: MLS commits chain, so replaying
        // newest-first (relay ordering is arbitrary) would fail each one
        // against a group context it predates. Messages whose commit does
        // not parse sort first and fail to merge loudly - same as before.
        let mut msgs: Vec<(u64, PublicKey, MeshMessage)> = Vec::new();
        for event in events {
            let Ok(unwrapped) = extract_rumor(self.identity.keys(), &event) else {
                tracing::debug!("backfill: ignoring undecryptable gift wrap");
                continue;
            };
            if u16::from(unwrapped.rumor.kind) != MESH_KIND {
                continue;
            }
            let Ok(msg) = serde_json::from_str::<MeshMessage>(&unwrapped.rumor.content) else {
                tracing::debug!("backfill: gift wrap rumor is not a mesh message");
                continue;
            };
            let epoch = Self::commit_epoch(&msg.commit).unwrap_or(0);
            msgs.push((epoch, unwrapped.sender, msg));
        }
        msgs.sort_by_key(|(epoch, _, _)| *epoch);

        let mut merged = 0usize;
        for (_, sender, msg) in msgs {
            merged += self.accept_mesh_message(sender, &msg);
        }
        merged
    }

    /// Decode, policy-check, and merge one mesh message (live or
    /// backfilled); returns 1 when a commit merged. All failures are
    /// logged and contained - one bad or stale commit never aborts the
    /// sync of the rest.
    fn accept_mesh_message(&mut self, sender: PublicKey, payload: &MeshMessage) -> usize {
        if payload.welcome.is_some() {
            eprintln!("# ⚠️  got an unexpected invitation from {sender} (already in a mesh)");
            return 0;
        }
        // Already merged (or older than us - relays deliver stored events
        // to the live subscription too): skip silently, this is normal
        // backfill-versus-live overlap.
        match (Self::commit_epoch(&payload.commit), self.epoch()) {
            (Ok(epoch), Ok(ours)) if epoch <= ours => return 0,
            _ => {}
        }
        let mut group = match self.group() {
            Ok(g) => g,
            Err(e) => {
                eprintln!("# ⚠️  cannot open our mesh group: {e}");
                return 0;
            }
        };
        match Self::accept_commit_on(&mut group, &self.provider, &sender, &payload.commit) {
            Ok(merged) => {
                if merged == 0 {
                    return 0; // already merged: normal backfill-live overlap
                }
                if let Err(e) = self.persist() {
                    eprintln!("# ⚠️  merged commit from {sender} but persist failed: {e}");
                    return 0;
                }
                eprintln!("# ⬇️  merged commit from {sender} (epoch {})", self.epoch().unwrap_or(0));
                1
            }
            Err(MeshError::PolicyViolation(e)) => {
                eprintln!("# 🚫 commit from {sender} rejected: {e}");
                0
            }
            Err(e) => {
                eprintln!("# ⚠️  commit from {sender} not merged: {e}");
                0
            }
        }
    }

    /// The epoch a serialized commit advances the group to: backfill orders
    /// commits by it (they must merge oldest-first) and skips ones already
    /// merged into our group.
    fn commit_epoch(commit_hex: &str) -> Result<u64, MeshError> {
        let bytes = hex::decode(commit_hex)
            .map_err(|e| MeshError::Mls(format!("bad commit hex: {e}")))?;
        let message = MlsMessageIn::tls_deserialize_exact(&mut bytes.as_slice())
            .map_err(|e| MeshError::Mls(e.to_string()))?;
        let protocol: ProtocolMessage = match message.try_into() {
            Ok(p) => p,
            Err(_) => return Err(MeshError::Mls("not a public MLS message".into())),
        };
        Ok(protocol.epoch().as_u64())
    }

    /// Merge one serialized commit into an explicit group after checking
    /// the group's policy: MLS authenticates the commit, the policy
    /// decides if the committer may change the membership. Commits whose
    /// epoch is not ahead of the group's are skipped (0): relays deliver
    /// stored events to the live subscription too, so replaying an
    /// already-merged commit is the normal overlap of backfill and live,
    /// not an error.
    fn accept_commit_on(
        group: &mut MlsGroup,
        provider: &Provider,
        sender: &PublicKey,
        commit_hex: &str,
    ) -> Result<usize, MeshError> {
        // A commit's message epoch is the one it APPLIES to (the group
        // ratchets on merge), so ours+1 is a pending commit and anything
        // strictly older is already behind us. Already-merged replays are
        // not detectable from the message alone - MLS rejects them at
        // staging (the proposal queue was consumed by the first merge),
        // which the caller logs and moves past.
        match Self::commit_epoch(commit_hex) {
            Ok(epoch) if epoch < group.epoch().as_u64() => {
                tracing::debug!(%sender, epoch, "mesh commit is older than our group; skipping");
                return Ok(0);
            }
            _ => {}
        }
        let bytes = hex::decode(commit_hex)
            .map_err(|e| MeshError::Mls(format!("bad commit hex: {e}")))?;
        let message = MlsMessageIn::tls_deserialize_exact(&mut bytes.as_slice())
            .map_err(|e| MeshError::Mls(e.to_string()))?;
        let protocol: ProtocolMessage = match message.try_into() {
            Ok(p) => p,
            Err(_) => return Err(MeshError::Mls("not a public MLS message".into())),
        };
        let processed = group
            .process_message(provider, protocol)
            .map_err(|e| MeshError::Mls(e.to_string()))?;
        let committer = processed.credential().serialized_content().to_vec();
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            return Err(MeshError::Mls("expected a commit".into()));
        };
        // MLS authenticated the commit; the group's policy decides whether
        // this committer may change the membership. See `authorize_commit`:
        // the policy comes from OUR context, never the commit's.
        Self::authorize_commit(group, &staged, &committer)?;
        group
            .merge_staged_commit(provider, *staged)
            .map_err(|e| MeshError::Mls(e.to_string()))?;
        Ok(1)
    }


    /// Authorization for a staged commit: the policy is read from OUR
    /// current context, never from the commit's own - the committer could
    /// rewrite it with a GCE proposal and then satisfy it. A commit whose
    /// context carries a different policy is rejected outright, so the
    /// policy cannot be mutated after creation.
    fn authorize_commit(
        group: &MlsGroup,
        staged: &StagedCommit,
        committer: &[u8],
    ) -> Result<(), MeshError> {
        let local = MeshPolicy::from_extensions(group.extensions())?;
        if MeshPolicy::from_context(staged.group_context())?.owner != local.owner {
            return Err(MeshError::PolicyViolation(
                "commit attempts to change the mesh policy".into(),
            ));
        }
        if !local.authorizes(committer) {
            return Err(MeshError::PolicyViolation(hex::encode(committer)));
        }
        Ok(())
    }

    /// The group's current epoch (display).
    fn epoch(&self) -> Result<u64, MeshError> {
        Ok(self.group()?.epoch().as_u64())
    }

    /// Gift-wrap `payload` (NIP-59) to `to` over a shared relay session:
    /// fan-out to several members opens ONE connection set, not one per
    /// member (relay connects are the expensive, rate-limit-earning part).
    /// Single-recipient sends are the `(to, payload)` list of length one.
    ///
    /// A send counts as delivered only when at least one relay ACKs the
    /// event with `OK` (the `success` map of the send output); a bare
    /// absence of error means nothing. Undelivered recipients are retried
    /// (fresh gift wraps, since the timestamp must move) before the caller
    /// hears about it: an unacknowledged commit fan-out is how members get
    /// stranded at a stale epoch - the owner has merged and persisted, and
    /// a wrap that no relay stored is unrecoverable by backfill. What
    /// still fails after the retries comes back as [`MeshError::Delivery`]
    /// naming the npubs; the commit itself is safely merged on the owner
    /// and recoverable via `mesh resend`.
    async fn send_gift_waps(&self, relays: &[String], items: &[(PublicKey, &str)]) -> Result<(), MeshError> {
        const ATTEMPTS: usize = 3;
        const RETRY_PAUSE: Duration = Duration::from_secs(2);

        // A wrap that fails to BUILD is a bug in our payload, not a relay
        // problem: it aborts immediately, before any send.
        let mut wraps: Vec<(PublicKey, Event)> = Vec::with_capacity(items.len());
        for (to, payload) in items {
            let rumor = UnsignedEvent::new(
                self.identity.public_key(),
                Timestamp::now(),
                Kind::Custom(MESH_KIND),
                [],
                (*payload).to_string(),
            );
            let gift_wrap = GiftWrapBuilder::new(*to, rumor)
                .expiration(Duration::from_secs(7 * 24 * 3600))
                .finalize(self.identity.keys())
                .map_err(|e| MeshError::Nostr(e))?;
            wraps.push((*to, gift_wrap));
        }

        let mut client: Option<crate::relay::RelayClient> = None;
        let mut undelivered: Vec<PublicKey> = Vec::new();
        for attempt in 0..ATTEMPTS {
            if attempt > 0 {
                if undelivered.is_empty() {
                    break;
                }
                tracing::info!(n = undelivered.len(), "retrying undelivered gift wraps");
                tokio::time::sleep(RETRY_PAUSE).await;
            }
            // Connect lazily: a single-recipient send is the common case
            // (sync_mesh commits go to N-1, invites to N). Reconnect on a
            // retry: the previous session may be the thing that died.
            if client.is_none() {
                client = Some(crate::relay::connect_client(relays).await?);
            }
            let pending = std::mem::take(&mut undelivered);
            for (i, (to, gift_wrap)) in wraps.iter().enumerate() {
                // After the first attempt only the stragglers go out.
                if attempt > 0 && !pending.contains(to) {
                    continue;
                }
                match client
                    .as_ref()
                    .expect("connected or just connected above")
                    .send_event(gift_wrap)
                    .await
                {
                    Ok(output) if !output.success.is_empty() => {}
                    Ok(output) => {
                        for (url, err) in &output.failed {
                            tracing::warn!(%url, %err, %to, "relay rejected gift wrap");
                        }
                        undelivered.push(*to);
                    }
                    Err(e) => {
                        tracing::warn!(%to, %e, "gift wrap send failed");
                        undelivered.push(*to);
                        // Everything later in the list was not attempted
                        // this round: carry it into the next retry.
                        for (rest, _) in &wraps[i + 1..] {
                            if !undelivered.contains(rest) {
                                undelivered.push(*rest);
                            }
                        }
                        // The session itself may be the thing that died:
                        // force the next attempt to reconnect.
                        if let Some(c) = client.take() {
                            c.shutdown().await;
                        }
                        break;
                    }
                }
            }
        }
        if let Some(c) = client.as_ref() {
            c.shutdown().await;
        }
        match undelivered.is_empty() {
            true => Ok(()),
            false => {
                let list = undelivered
                    .iter()
                    .map(|k| k.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                Err(MeshError::Delivery(list))
            }
        }
    }

    /// Wait for a gift-wrapped invitation and join the mesh. Invitations
    /// from anyone else are ignored, and the group's own policy must name
    /// `expected_owner` as owner before the join is accepted: the phone
    /// scanned a specific owner's QR, and only that mesh may adopt it.
    /// (An attacker who knows the victim's npub can build their own MLS
    /// group and send a valid Welcome - the expected owner is the anchor
    /// that makes such an invitation refusable.)
    pub async fn join_mesh(
        &mut self,
        relays: &[String],
        expected_owner: PublicKey,
    ) -> Result<(), MeshError> {
        if self.group_id.is_some() {
            // Local state says this device is already a member. Forgetting a
            // mesh on the device (the mobile "disconnect") does not remove
            // it from the group, so this is the normal path when rejoining
            // after a disconnect: the existing membership is still valid.
            eprintln!("# ✅ already a member of a mesh - nothing to join");
            return Ok(());
        }
        let (tx, mut rx) = tokio::sync::mpsc::channel::<(PublicKey, String)>(16);
        let watch = tokio::spawn(crate::traversal::watch_mesh(
            self.identity.clone(),
            relays.to_vec(),
            tx,
        ));
        eprintln!("# ⏳ waiting for a mesh invitation (Ctrl-C to give up)…");
        // Gift wraps are signed, so the sender cannot be spoofed: an
        // invitation from anyone but the expected owner is dropped unheard.
        let (sender, payload) = loop {
            let (sender, payload) = rx.recv().await.ok_or(MeshError::JoinTimeout)?;
            if sender != expected_owner {
                eprintln!("# ignoring an invitation from {sender} (not the expected owner)");
                continue;
            }
            break (sender, payload);
        };
        watch.abort();

        let msg: MeshMessage = serde_json::from_str(&payload)?;
        eprintln!("# ✉️  invitation received from {sender} - joining…");

        let welcome_bytes = hex::decode(&msg.welcome.ok_or_else(|| {
            MeshError::Mls("invitation carries no Welcome".into())
        })?)?;
        let welcome =
            Welcome::tls_deserialize_exact(&mut welcome_bytes.as_slice())
                .map_err(|e| MeshError::Mls(e.to_string()))?;
        let staged = StagedWelcome::new_from_welcome(
            &self.provider,
            &join_config(),
            welcome,
            None,
        )
        .map_err(|e| MeshError::Mls(e.to_string()))?;
        // The group itself must agree the expected owner is in charge: a
        // sender can only gift-wrap, not change who owns the mesh they
        // claim. A policy mismatch here means the invitation is for a mesh
        // we did not ask to join.
        let policy = MeshPolicy::from_context(staged.group_context())?;
        if policy.owner != expected_owner.to_bytes().to_vec() {
            return Err(MeshError::PolicyViolation(
                "invitation is not from the expected owner's mesh".into(),
            ));
        }
        let group = staged
            .into_group(&self.provider)
            .map_err(|e| MeshError::Mls(e.to_string()))?;
        let group_id = group.group_id().clone();
        self.group_id = Some(group_id);
        self.persist()?;

        eprintln!("# ✅ joined mesh of {}", sender);
        Ok(())
    }
}

/// Wire format of a gift-wrapped mesh message.
#[derive(serde::Serialize, serde::Deserialize)]
struct MeshMessage {
    /// MLS commit (needed by other members; the invitee ignores it).
    commit: String,
    /// MLS Welcome carrying the group secrets for the invitee. Absent in
    /// commits fanned out to existing members (epoch propagation).
    welcome: Option<String>,
}

/// The mesh's access policy, carried as a GroupContext extension so it is
/// authenticated by the group itself and inherited by every joiner.
///
/// Single-owner meshs: only the owner may add or remove devices. Members
/// enforce this at commit-merge time (see `accept_commit_on`) - an MLS
/// commit is signed, so the committer's credential is checked against the policy.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct MeshPolicy {
    /// npub bytes of the mesh's owner.
    pub owner: Vec<u8>,
}

impl MeshPolicy {
    /// The policy extension for a mesh owned by `owner` (npub bytes).
    fn extension(owner: &[u8]) -> Result<Extension, MeshError> {
        let policy = MeshPolicy {
            owner: owner.to_vec(),
        };
        Ok(Extension::Unknown(
            POLICY_EXTENSION_TYPE,
            UnknownExtension(serde_json::to_vec(&policy)?),
        ))
    }

    /// Read the policy out of a group context (the one a commit or Welcome
    /// carries - MlsGroup keeps its current context private).
    fn from_context(context: &GroupContext) -> Result<Self, MeshError> {
        Self::from_extensions(context.extensions())
    }

    /// Read the policy out of a context's extension set.
    fn from_extensions(extensions: &Extensions<GroupContext>) -> Result<Self, MeshError> {
        for ext in extensions.iter() {
            if let Extension::Unknown(POLICY_EXTENSION_TYPE, UnknownExtension(bytes)) = ext {
                return Ok(serde_json::from_slice(bytes)?);
            }
        }
        Err(MeshError::Mls("mesh policy extension missing".into()))
    }

    /// Is `identity` (credential bytes) allowed to add/remove members?
    fn authorizes(&self, identity: &[u8]) -> bool {
        identity == self.owner
    }
}

/// The mesh's current membership: npub + MLS leaf index per device.
pub struct MemberInfo {
    /// x-only npub hex, for display and CLI round-trips.
    pub npub: String,
    pub epoch: u64,
    pub is_owner: bool,
}

fn group_config(policy: &MeshPolicy) -> Result<MlsGroupCreateConfig, MeshError> {
    let owner_ext = MeshPolicy::extension(&policy.owner)?;
    let extensions = Extensions::single(owner_ext)
        .map_err(|e| MeshError::Mls(e.to_string()))?;
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
fn mls_signer(identity: &Identity) -> Result<SignatureKeyPair, MeshError> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let secret: [u8; 32] = identity
        .keys()
        .secret_key()
        .as_secret_bytes()
        .try_into()
        .map_err(|_| MeshError::Mls("bad secret length".into()))?;
    let hk = Hkdf::<Sha256>::new(Some(b"noscat"), &secret);
    let mut seed = [0u8; 32];
    hk.expand(MLS_DERIVE_INFO, &mut seed)
        .map_err(|_| MeshError::Mls("key derivation failed".into()))?;
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

    /// The heart of the mesh: the owner adds a device from its published
    /// key package, the device joins from the Welcome, and both independently
    /// derive the *same* tunnel PSK from the group's exporter. This is the
    /// exact flow `create_mesh` / `invite` / `join_mesh` implement,
    /// minus the relay transport.
    #[test]
    fn mls_add_join_derives_shared_psk() -> Result<(), MeshError> {
        let owner = Identity::generate();
        let invitee = Identity::generate();
        let owner_provider = Provider::default();
        let invitee_provider = Provider::default();
        let owner_signer = mls_signer(&owner)?;
        let invitee_signer = mls_signer(&invitee)?;

        // Owner creates the mesh.
        let group_id = GroupId::from_slice(&owner.public_key().to_bytes());
        let policy = MeshPolicy {
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
        .map_err(|e| MeshError::Mls(e.to_string()))?;

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
            .map_err(|e| MeshError::Mls(e.to_string()))?;
        group
            .merge_pending_commit(&owner_provider)
            .map_err(|e| MeshError::Mls(e.to_string()))?;
        let MlsMessageBodyOut::Welcome(welcome) = welcome_msg.body() else {
            return Err(MeshError::Mls("expected a Welcome from add_members".into()));
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
        .map_err(|e| MeshError::Mls(e.to_string()))?;
        let joined_staged_context = staged.group_context().clone();
        let joined = staged
            .into_group(&invitee_provider)
            .map_err(|e| MeshError::Mls(e.to_string()))?;

        // Both sides derive the same exporter secret -> same tunnel PSK.
        let psk_owner = group
            .export_secret(owner_provider.crypto(), EXPORTER_LABEL, &[], 32)
            .map_err(|e| MeshError::Mls(e.to_string()))?;
        let psk_invitee = joined
            .export_secret(invitee_provider.crypto(), EXPORTER_LABEL, &[], 32)
            .map_err(|e| MeshError::Mls(e.to_string()))?;
        assert_eq!(psk_owner, psk_invitee, "members must derive the same PSK");
        assert_eq!(psk_owner.len(), 32);

        // The policy extension made it into the joiner's group context.
        let read_policy = MeshPolicy::from_context(&joined_staged_context)?;
        assert_eq!(read_policy.owner, owner.public_key().to_bytes());
        assert!(read_policy.authorizes(&owner.public_key().to_bytes()));
        assert!(!read_policy.authorizes(&invitee.public_key().to_bytes()));
        Ok(())
    }

    /// A device directory is the unit of persistence: same directory, same
    /// identity, same group, same PSK - across processes.
    #[test]
    fn device_state_survives_reopen() -> Result<(), MeshError> {
        let dir = std::env::temp_dir().join(format!(
            "noscat-mesh-test-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));

        let npub;
        let psk;
        {
            let mut device = Device::open(&dir)?;
            npub = device.identity.npub();
            device.create_mesh()?;
            psk = device.tunnel_psk()?;
        }

        let reopened = Device::open(&dir)?;
        assert_eq!(reopened.identity.npub(), npub);
        assert_eq!(reopened.tunnel_psk()?, psk);

        std::fs::remove_dir_all(&dir).ok();
        Ok(())
    }

    /// The owner's commit journal (the `mesh resend` healing store):
    /// round-trips oldest first, and keeps only the most recent entries.
    #[test]
    fn commit_journal_roundtrips_and_caps() -> Result<(), MeshError> {
        let dir = std::env::temp_dir().join(format!(
            "noscat-mesh-test-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let device = Device::open(&dir)?;

        for i in 0..10 {
            device.record_commit(&format!("{i:064}"))?;
        }
        let journal = device.commit_journal()?;
        assert_eq!(journal.len(), COMMIT_JOURNAL_KEEP, "journal is capped");
        assert_eq!(
            journal.first().map(String::as_str),
            Some(format!("{:064}", 2).as_str())
        );
        assert_eq!(
            journal.last().map(String::as_str),
            Some(format!("{:064}", 9).as_str()),
            "oldest first: the newest commit is last"
        );
        // Appends survive a reopen: the journal lives in the device dir.
        let reopened = Device::open(&dir)?;
        assert_eq!(reopened.commit_journal()?, journal);

        std::fs::remove_dir_all(&dir).ok();
        Ok(())
    }

    /// `resend_commits` refuses to run outside a mesh, and on an owner
    /// device that has committed nothing (an empty journal - e.g. a member
    /// device, which never commits). Both are local checks: no network.
    #[test]
    fn resend_refuses_no_mesh_or_empty_journal() -> Result<(), MeshError> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let dir = std::env::temp_dir().join(format!(
            "noscat-mesh-test-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let mut device = Device::open(&dir)?;

        let no_mesh = rt.block_on(device.resend_commits(None, &[]));
        assert!(matches!(no_mesh, Err(MeshError::NoMesh(_))));

        device.create_mesh()?;
        let empty = rt.block_on(device.resend_commits(None, &[]));
        assert!(
            matches!(&empty, Err(MeshError::Mls(m)) if m.contains("no recorded commits")),
            "an empty journal must read as 'nothing to resend': {empty:?}"
        );

        std::fs::remove_dir_all(&dir).ok();
        Ok(())
    }

    /// Build an owner + two members, all in the same epoch: the second Add's
    /// commit is processed by the first member through `process_message` (the
    /// `sync_mesh` path, minus the transport).
    struct MeshFixture {
        owner: Identity,
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
        /// The raw "member B joins" commit: the one A has not merged.
        commit_b: MlsMessageOut,
    }

    impl MeshFixture {
        /// Catch A up with the missed commit (the path `sync_mesh`'s
        /// backfill now provides): stage and merge it into A's group.
        fn catch_up_a(&mut self) -> Result<(), MeshError> {
            let staged = stage_commit(&mut self.a_group, &self.a_provider, &self.commit_b)?;
            self.a_group
                .merge_staged_commit(&self.a_provider, *staged)
                .map_err(|e| MeshError::Mls(e.to_string()))?;
            Ok(())
        }
    }

    fn cred(id: &Identity, signer: &SignatureKeyPair) -> CredentialWithKey {
        CredentialWithKey {
            credential: Credential::new(CredentialType::Basic, id.public_key().to_bytes().to_vec()),
            signature_key: signer.public().into(),
        }
    }

    fn fixture_two_members() -> Result<MeshFixture, MeshError> {
        let owner = Identity::generate();
        let a = Identity::generate();
        let b = Identity::generate();
        let owner_provider = Provider::default();
        let a_provider = Provider::default();
        let b_provider = Provider::default();
        let owner_signer = mls_signer(&owner)?;
        let a_signer = mls_signer(&a)?;
        let b_signer = mls_signer(&b)?;
        let policy = MeshPolicy {
            owner: owner.public_key().to_bytes().to_vec(),
        };

        let mut owner_group = MlsGroup::new_with_group_id(
            &owner_provider,
            &owner_signer,
            &group_config(&policy)?,
            GroupId::from_slice(&owner.public_key().to_bytes()),
            cred(&owner, &owner_signer),
        )
        .map_err(|e| MeshError::Mls(e.to_string()))?;

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
            .map_err(|e| MeshError::Mls(e.to_string()))?;
        owner_group
            .merge_pending_commit(&owner_provider)
            .map_err(|e| MeshError::Mls(e.to_string()))?;
        let a_group = join_from_welcome(&a_provider, &welcome_a, &a_signer)?;

        // Owner adds B; the commit is published but A (playing the member
        // that was offline) has NOT merged it: A stays one epoch behind.
        // `catch_up_a` is the sync/backfill path.
        let kp_b = bundle_for(&b_provider, &b_signer, &b)?;
        let (commit_b, welcome_b, _) = owner_group
            .add_members(&owner_provider, &owner_signer, &[kp_b.key_package().clone()])
            .map_err(|e| MeshError::Mls(e.to_string()))?;
        owner_group
            .merge_pending_commit(&owner_provider)
            .map_err(|e| MeshError::Mls(e.to_string()))?;
        let b_group = join_from_welcome(&b_provider, &welcome_b, &b_signer)?;

        Ok(MeshFixture {
            owner,
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
            commit_b,
        })
    }

    /// All three members derive the same PSK, and a removal ratchets the
    /// epoch so the removed device's PSK stops matching.
    #[test]
    fn removal_ratchets_epoch_and_locks_out_device() -> Result<(), MeshError> {
        let mut fx = fixture_two_members()?;
        fx.catch_up_a()?;

        let psk_of = |group: &MlsGroup, provider: &Provider| -> Result<Vec<u8>, MeshError> {
            group
                .export_secret(provider.crypto(), EXPORTER_LABEL, &[], 32)
                .map_err(|e| MeshError::Mls(e.to_string()))
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
            .ok_or_else(|| MeshError::Mls("member A missing".into()))?;
        let (commit, _w, _) = fx
            .owner_group
            .remove_members(&fx.owner_provider, &fx.owner_signer, &[leaf])
            .map_err(|e| MeshError::Mls(e.to_string()))?;
        fx.owner_group
            .merge_pending_commit(&fx.owner_provider)
            .map_err(|e| MeshError::Mls(e.to_string()))?;

        // The removed device never sees the commit: its PSK is now stale.
        assert_ne!(psk_before, psk_of(&fx.owner_group, &fx.owner_provider)?);

        // A remaining member (B) merges the commit and ratchets to the new
        // epoch - locked out together with A is nobody but A.
        let mut b_group = fx.b_group;
        let staged = stage_commit(&mut b_group, &fx.b_provider, &commit)?;
        b_group
            .merge_staged_commit(&fx.b_provider, *staged)
            .map_err(|e| MeshError::Mls(e.to_string()))?;
        assert_eq!(
            psk_of(&fx.owner_group, &fx.owner_provider)?,
            psk_of(&b_group, &fx.b_provider)?,
            "a synced member must follow the ratchet"
        );
        Ok(())
    }

    /// A member that missed a live commit catches up from backfill: the
    /// owner invited a third device while the member was not on its relay
    /// subscription, and the stored commit replays into the member's
    /// group - same epoch, same tunnel PSK as the owner (issue #11).
    /// Replays of an already-merged commit (backfill and live overlap, or
    /// a second sync) are skipped, never errors, and the epoch does not
    /// move.
    #[test]
    fn backfill_merges_missed_commit_replays_are_noops() -> Result<(), MeshError> {
        let fx = fixture_two_members()?;
        let psk_of = |group: &MlsGroup, provider: &Provider| -> Result<Vec<u8>, MeshError> {
            group
                .export_secret(provider.crypto(), EXPORTER_LABEL, &[], 32)
                .map_err(|e| MeshError::Mls(e.to_string()))
        };

        // A is one epoch behind: it never received the B-add commit.
        let owner_epoch = fx.owner_group.epoch().as_u64();
        assert_eq!(
            owner_epoch,
            fx.a_group.epoch().as_u64() + 1,
            "fixture: A missed exactly one commit"
        );

        // Backfill into A's group.
        let mut a_group = fx.a_group;
        let sender = fx.owner.public_key();
        let missed = hex::encode(fx.commit_b.tls_serialize_detached()?);
        let merged =
            Device::accept_commit_on(&mut a_group, &fx.a_provider, &sender, &missed)?;
        assert_eq!(merged, 1, "the missed commit must merge");
        assert_eq!(a_group.epoch().as_u64(), owner_epoch);
        assert_eq!(
            psk_of(&a_group, &fx.a_provider)?,
            psk_of(&fx.owner_group, &fx.owner_provider)?,
            "backfilled member derives the owner's tunnel PSK"
        );

        // Replay the same commit (the live subscription also hands stored
        // events over): skipped or MLS-rejected, never merged, and epoch
        // and PSK are untouched.
        let replay =
            Device::accept_commit_on(&mut a_group, &fx.a_provider, &sender, &missed);
        assert!(
            matches!(replay, Ok(0) | Err(_)),
            "an already-merged commit must not merge again: {replay:?}"
        );
        assert_eq!(a_group.epoch().as_u64(), owner_epoch);
        assert_eq!(
            psk_of(&a_group, &fx.a_provider)?,
            psk_of(&fx.owner_group, &fx.owner_provider)?
        );
        Ok(())
    }

    /// Backfill still enforces the mesh policy: a stored commit from a
    /// non-owner member is rejected with the policy violation, not merged.
    #[test]
    fn backfill_rejects_non_owner_commit() -> Result<(), MeshError> {
        let mut fx = fixture_two_members()?;
        fx.catch_up_a()?;

        // Member A (current, so its commit passes the epoch guard) commits
        // the removal of B - legal MLS, forbidden by the policy.
        let leaf_b = fx
            .a_group
            .members()
            .find(|m| m.credential.serialized_content() == fx.b.public_key().to_bytes())
            .map(|m| m.index)
            .ok_or_else(|| MeshError::Mls("member B missing".into()))?;
        let (commit, _w, _) = fx
            .a_group
            .remove_members(&fx.a_provider, &fx.a_signer, &[leaf_b])
            .map_err(|e| MeshError::Mls(e.to_string()))?;
        let commit_hex = hex::encode(commit.tls_serialize_detached()?);

        let mut owner_group = fx.owner_group;
        let sender = fx.a.public_key();
        let res =
            Device::accept_commit_on(&mut owner_group, &fx.owner_provider, &sender, &commit_hex);
        assert!(
            matches!(res, Err(MeshError::PolicyViolation(_))),
            "a backfilled non-owner commit must be rejected: {res:?}"
        );
        assert_eq!(owner_group.epoch(), fx.a_group.epoch(), "nothing merged");
        Ok(())
    }

    /// A member commit that rewrites the policy via a GCE proposal must be
    /// rejected: the authorization policy is read from OUR group's context,
    /// not the committer's document. Without this, a non-owner could name
    /// themselves owner in the commit and pass their own check.
    #[test]
    fn acl_rejects_non_owner_commit() -> Result<(), MeshError> {
        let mut fx = fixture_two_members()?;
        fx.catch_up_a()?;

        // Member A (not the owner) commits the removal of B - legal MLS, but
        // the mesh's policy says only the owner may change membership.
        let leaf_b = fx
            .a_group
            .members()
            .find(|m| m.credential.serialized_content() == fx.b.public_key().to_bytes())
            .map(|m| m.index)
            .ok_or_else(|| MeshError::Mls("member B missing".into()))?;
        let (commit, _w, _) = fx
            .a_group
            .remove_members(&fx.a_provider, &fx.a_signer, &[leaf_b])
            .map_err(|e| MeshError::Mls(e.to_string()))?;

        // The receiver (playing the owner's mesh device) stages it fine -
        // MLS authenticates A - but the policy forbids the merge.
        let mut owner_group = fx.owner_group;
        let message = commit_a_into_in(&commit)?;
        let protocol: ProtocolMessage = match message.try_into() {
            Ok(p) => p,
            Err(_) => return Err(MeshError::Mls("not a public MLS message".into())),
        };
        let processed = owner_group
            .process_message(&fx.owner_provider, protocol)
            .map_err(|e| MeshError::Mls(e.to_string()))?;
        let policy = match processed.content() {
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                MeshPolicy::from_context(staged.group_context())?
            }
            _ => return Err(MeshError::Mls("expected a commit".into())),
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

    /// A member commit that rewrites the policy via a GCE proposal must be
    /// rejected: the authorization policy is read from OUR group's context,
    /// not the committer's document. Without this, a non-owner could name
    /// themselves owner in the commit and pass their own check.
    #[test]
    fn acl_rejects_policy_rewriting_commit() -> Result<(), MeshError> {
        let mut fx = fixture_two_members()?;
        fx.catch_up_a()?;

        // Member A (not the owner) proposes a GCE that renames A owner and
        // commits it - legal MLS, and self-authorizing only if the receiver
        // trusts the commit's context.
        let attacker_owner = fx.a.public_key().to_bytes().to_vec();
        let required = RequiredCapabilitiesExtension::new(
            &[ExtensionType::Unknown(POLICY_EXTENSION_TYPE)],
            &[],
            &[],
        );
        let attacker_ext = Extensions::from_vec(vec![
            Extension::RequiredCapabilities(required),
            MeshPolicy::extension(&attacker_owner)?,
        ])
        .map_err(|e| MeshError::Mls(e.to_string()))?;
        let commit = fx
            .a_group
            .commit_builder()
            .propose_group_context_extensions(attacker_ext)
            .map_err(|e| MeshError::Mls(e.to_string()))?
            .load_psks(fx.a_provider.storage())
            .map_err(|e| MeshError::Mls(e.to_string()))?
            .build(fx.a_provider.rand(), fx.a_provider.crypto(), &fx.a_signer, |_| true)
            .map_err(|e| MeshError::Mls(e.to_string()))?
            .stage_commit(&fx.a_provider)
            .map_err(|e| MeshError::Mls(e.to_string()))?
            .commit()
            .clone();

        // The receiver stages it (MLS authenticates A as a member), then
        // authorization must fail - on the policy rewrite and, belt and
        // braces, the non-owner committer.
        let mut owner_group = fx.owner_group;
        let message = commit_a_into_in(&commit)?;
        let protocol: ProtocolMessage = match message.try_into() {
            Ok(p) => p,
            Err(_) => return Err(MeshError::Mls("not a public MLS message".into())),
        };
        let processed = owner_group
            .process_message(&fx.owner_provider, protocol)
            .map_err(|e| MeshError::Mls(e.to_string()))?;
        let staged = match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged) => staged,
            ProcessedMessageContent::ApplicationMessage(_) => {
                return Err(MeshError::Mls("expected a commit".into()))
            }
            _ => return Err(MeshError::Mls("expected a commit".into())),
        };
        let committer = fx.a.public_key().to_bytes().to_vec();
        assert!(matches!(
            Device::authorize_commit(&owner_group, &staged, &committer),
            Err(MeshError::PolicyViolation(_))
        ));
        // And the local policy still names the original owner, not A.
        let local = MeshPolicy::from_extensions(owner_group.extensions())?;
        assert_ne!(local.owner, attacker_owner, "the local policy must be untouchable by commit");
        Ok(())
    }
}

/// Deserialize an owner's serialized commit into a message a member can
/// process.
#[cfg(test)]
fn commit_a_into_in(commit: &MlsMessageOut) -> Result<MlsMessageIn, MeshError> {
    let bytes = commit.tls_serialize_detached()?;
    Ok(MlsMessageIn::tls_deserialize_exact(&mut bytes.as_slice())
        .map_err(|e| MeshError::Mls(e.to_string()))?)
}

/// A test key package that advertises the policy extension, matching what
/// `publish_key_package` puts on the relays.
#[cfg(test)]
fn key_package_with_policy_capability(
    provider: &Provider,
    signer: &SignatureKeyPair,
    credential: CredentialWithKey,
) -> Result<KeyPackageBundle, MeshError> {
    let capabilities = Capabilities::builder()
        .extensions(vec![ExtensionType::Unknown(POLICY_EXTENSION_TYPE)])
        .build();
    KeyPackage::builder()
        .leaf_node_capabilities(capabilities)
        .build(CIPHERSUITE, provider, signer, credential)
        .map_err(|e| MeshError::Mls(e.to_string()))
}

/// Process a serialized commit into a staged commit for authorization checks.
#[cfg(test)]
fn stage_commit(
    group: &mut MlsGroup,
    provider: &Provider,
    commit: &MlsMessageOut,
) -> Result<Box<StagedCommit>, MeshError> {
    let message = commit_a_into_in(commit)?;
    let protocol: ProtocolMessage = match message.try_into() {
        Ok(p) => p,
        Err(_) => return Err(MeshError::Mls("not a public MLS message".into())),
    };
    match group
        .process_message(provider, protocol)
        .map_err(|e| MeshError::Mls(e.to_string()))?
        .into_content()
    {
        ProcessedMessageContent::StagedCommitMessage(staged) => Ok(staged),
        _ => Err(MeshError::Mls("expected a commit".into())),
    }
}

/// Join a fresh member from a Welcome (the `join_mesh` path).
#[cfg(test)]
fn join_from_welcome(
    provider: &Provider,
    welcome: &MlsMessageOut,
    _signer: &SignatureKeyPair,
) -> Result<MlsGroup, MeshError> {
    let MlsMessageBodyOut::Welcome(welcome) = welcome.body() else {
        return Err(MeshError::Mls("expected a Welcome".into()));
    };
    let staged = StagedWelcome::new_from_welcome(
        provider,
        &join_config(),
        welcome.clone(),
        None,
    )
    .map_err(|e| MeshError::Mls(e.to_string()))?;
    staged
        .into_group(provider)
        .map_err(|e| MeshError::Mls(e.to_string()))
}
