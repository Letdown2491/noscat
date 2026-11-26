//! The mesh as a Marmot group (ADR 0004, 0007): the noscat subset of the
//! Marmot protocol on published OpenMLS.
//!
//! [`MeshGroup`] is a state machine with no I/O. Callers hand it Nostr
//! events (kind 445 group events, kind 1059 Welcome gift wraps, kind 30443
//! key packages) and get back events to publish plus [`Change`]s to act on.
//! The relay side lives in `crate::device`.
//!
//! What a noscat mesh is, in Marmot terms:
//! - Every device is its own Marmot account (unique npub) and an admin, so
//!   any device can add or remove members and no single device is a point
//!   of failure.
//! - The group requires admin policy, Nostr routing, identity proofs and
//!   lifecycle; it carries the non-required `noscat.mesh.v1` component
//!   with the mesh name, which other Marmot clients keep as unknown data.
//! - Endpoint adverts and device names travel as app events of kind
//!   [`ADVERT_KIND`], never on public relays (ADR 0006).
//!
//! Convergence (ADR 0007): commits are applied as they arrive, and the last
//! [`MAX_REWIND`] parent states are kept. When a valid commit arrives for an
//! older epoch, the two branches are compared with Marmot's branch order
//! (depth with the witness boost, witness score, privileged before
//! ordinary, lower committer, lower digest) and the loser is rolled back.
//! The result after input settles matches Marmot's; noscat does not delay
//! linear commits behind a settlement window.

pub mod codec;
pub mod proof;
pub mod transport;

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use nostr::prelude::{Event, EventId, Keys, PublicKey, Timestamp};
use openmls::component::ComponentData;
use openmls::prelude::*;
use openmls_traits::storage::StorageProvider as _;
use openmls_basic_credential::SignatureKeyPair;
use openmls_memory_storage::MemoryStorage;
use openmls_rust_crypto::RustCrypto;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ::tls_codec::{Deserialize as _, Serialize as _};

use crate::identity::Identity;
use codec::Routing;
use transport::{AppEvent, KeyPackageTags};

pub use transport::{GROUP_KIND, INBOX_RELAYS_KIND, KEY_PACKAGE_KIND, RELAY_LIST_KIND, WELCOME_KIND};

/// The one ciphersuite Marmot requires (0x0001).
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
/// Inner app event kind for a device's advert: content is the FIPS advert
/// JSON (or empty when the device has none yet), a `name` tag carries the
/// device name.
pub const ADVERT_KIND: u16 = 21195;
/// Marmot convergence policy v1: how many commits a branch may rewind.
pub const MAX_REWIND: u64 = 5;
/// Key package lifetime (30 days; OpenMLS adds an hour of skew margin).
const KEY_PACKAGE_LIFETIME_SECS: u64 = 30 * 24 * 60 * 60;
/// Longest key package lifetime range a receiver accepts (84 days + 1 h).
const MAX_KEY_PACKAGE_RANGE_SECS: u64 = 7_261_200;
/// Exporter label and context for the kind 445 outer key.
const EXPORTER_LABEL: &str = "marmot";
const EXPORTER_CONTEXT: &[u8] = b"group-event";
/// How many message ids to remember for duplicate detection.
const SEEN_KEEP: usize = 4096;
/// How many undecryptable or future-epoch inputs to keep for retry.
const DEFERRED_KEEP: usize = 512;
/// Domain separation for the leaf signing key (same scheme as 0.4).
const MLS_DERIVE_INFO: &[u8] = b"noscat/mls-ed25519-v1";
/// State file inside the device directory.
const STATE_FILE: &str = "mesh-state.json";
const STATE_VERSION: u32 = 1;

/// Errors from the mesh group.
#[derive(Debug, thiserror::Error)]
pub enum MeshError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("state file: {0}")]
    State(String),
    #[error("mls: {0}")]
    Mls(String),
    #[error(transparent)]
    Codec(#[from] codec::CodecError),
    #[error(transparent)]
    Transport(#[from] transport::TransportError),
    #[error(transparent)]
    Proof(#[from] proof::ProofError),
    #[error("this device is not in a mesh")]
    NoMesh,
    #[error("this device is already in a mesh")]
    AlreadyInMesh,
    #[error("a membership change is waiting to be published")]
    Pending,
    #[error("invalid key package: {0}")]
    KeyPackage(String),
    #[error("invalid invitation: {0}")]
    Welcome(String),
    #[error("not allowed: {0}")]
    NotAllowed(String),
}

fn mls<E: std::fmt::Debug>(context: &'static str) -> impl FnOnce(E) -> MeshError {
    move |e| MeshError::Mls(format!("{context}: {e:?}"))
}

/// Something the caller should act on after processing input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// The roster changed. Holds the full member list (devices other than
    /// this one included, this one included too).
    Roster(Vec<PublicKey>),
    /// An app event from a member, already authenticated against the MLS
    /// sender.
    App(AppEvent),
    /// This device was removed from the mesh; its group state is gone.
    Removed,
    /// A commit this device had applied lost a convergence race and was
    /// rolled back (named by its commit digest). If it was ours, the change
    /// it made (an add or remove) did not happen and may be retried.
    Superseded { digest: [u8; 32], own: bool },
    /// A member asked to leave; committing it is pending (see
    /// [`MeshGroup::commit_pending`]).
    LeaveRequested(PublicKey),
}

/// A commit waiting for its publication to be acknowledged.
#[derive(Debug, Clone)]
pub struct Outgoing {
    /// The kind 445 event to publish to every group relay.
    pub commit: Event,
    /// Welcomes to send once the commit is acknowledged.
    pub welcomes: Vec<PendingWelcome>,
}

/// One Welcome to gift-wrap and deliver after its commit is acknowledged.
#[derive(Debug, Clone)]
pub struct PendingWelcome {
    pub invitee: PublicKey,
    pub key_package_event: EventId,
    pub welcome: Vec<u8>,
    pub relays: Vec<String>,
}

/// A member as the roster shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberInfo {
    pub device: PublicKey,
    pub admin: bool,
    pub this_device: bool,
}

// ---- provider ----------------------------------------------------------

#[derive(Default)]
struct Provider {
    crypto: RustCrypto,
    storage: MemoryStorage,
}

impl OpenMlsProvider for Provider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MemoryStorage;
    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }
    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }
    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

type Dump = BTreeMap<String, String>;

fn dump(storage: &MemoryStorage) -> Dump {
    storage
        .values
        .read()
        .expect("storage lock")
        .iter()
        .map(|(k, v)| (B64.encode(k), B64.encode(v)))
        .collect()
}

fn restore(d: &Dump) -> Result<MemoryStorage, MeshError> {
    let s = MemoryStorage::default();
    {
        let mut map = s.values.write().expect("storage lock");
        for (k, v) in d {
            let k = B64.decode(k).map_err(|_| MeshError::State("bad storage key".into()))?;
            let v = B64.decode(v).map_err(|_| MeshError::State("bad storage value".into()))?;
            map.insert(k, v);
        }
    }
    Ok(s)
}

// ---- persisted state ---------------------------------------------------

/// One applied commit, kept while it is inside the rewind horizon.
#[derive(Serialize, Deserialize, Clone)]
struct Applied {
    /// Epoch the commit was applied on top of.
    parent_epoch: u64,
    /// Full storage before applying it.
    snapshot: Dump,
    /// SHA-256 of the commit's MLSMessage bytes.
    digest: [u8; 32],
    committer: [u8; 32],
    privileged: bool,
    own: bool,
}

/// A device's own published key package.
#[derive(Serialize, Deserialize, Clone)]
struct OwnKeyPackage {
    event_id: String,
    key_package_ref: String,
}

#[derive(Serialize, Deserialize, Default)]
struct Meta {
    /// The device's key package publication slot, random, kept for life.
    slot: String,
    /// MLS group id (private, never published).
    group_id: Option<String>,
    /// Published key packages whose private keys are still held.
    key_packages: Vec<OwnKeyPackage>,
    /// Group-event keys by epoch, oldest first (current included).
    epoch_keys: Vec<(u64, String)>,
    /// Routing ids this group has used, newest last.
    routing_ids: Vec<String>,
    /// Commits inside the rewind horizon, oldest first.
    history: Vec<Applied>,
    /// Distinct app-event senders per epoch on the current branch.
    witnesses: BTreeMap<u64, BTreeSet<String>>,
    /// Recently seen MLS message ids.
    seen: VecDeque<String>,
    /// 445 payloads no retained key could open, and MLS messages for a
    /// future epoch: both retried after the epoch changes.
    deferred_payloads: VecDeque<String>,
    deferred_messages: VecDeque<String>,
    /// created_at of the newest key package event built. The next one is
    /// stamped later even within the same second: relays keep one key
    /// package per slot and reject a replacement that is not newer.
    #[serde(default)]
    last_key_package_at: u64,
}

#[derive(Serialize, Deserialize)]
struct Persisted {
    version: u32,
    meta: Meta,
    storage: Dump,
}

// ---- the group ---------------------------------------------------------

/// One device's view of its mesh. See the module docs.
pub struct MeshGroup {
    path: PathBuf,
    keys: Keys,
    signer: SignatureKeyPair,
    provider: Provider,
    meta: Meta,
    group: Option<MlsGroup>,
    /// Snapshot taken before staging an own commit, until it is confirmed.
    pending: Option<(Dump, [u8; 32])>,
}

impl std::fmt::Debug for MeshGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeshGroup")
            .field("device", &self.keys.public_key().to_hex())
            .field("epoch", &self.epoch())
            .finish_non_exhaustive()
    }
}

fn leaf_signer(identity: &Identity) -> SignatureKeyPair {
    use hkdf::Hkdf;
    let secret = identity.keys().secret_key().secret_bytes();
    let hk = Hkdf::<Sha256>::new(Some(b"noscat"), &secret);
    let mut seed = [0u8; 32];
    hk.expand(MLS_DERIVE_INFO, &mut seed).expect("32 bytes is a valid length");
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    SignatureKeyPair::from_raw(
        SignatureScheme::ED25519,
        signing.to_bytes().to_vec(),
        signing.verifying_key().to_bytes().to_vec(),
    )
}

fn cs_id() -> u16 {
    CIPHERSUITE as u16
}

fn scheme_id() -> u16 {
    CIPHERSUITE.signature_algorithm() as u16
}

fn capabilities() -> Capabilities {
    Capabilities::new(
        None,
        Some(&[CIPHERSUITE]),
        Some(&[ExtensionType::AppDataDictionary]),
        Some(&[ProposalType::AppDataUpdate, ProposalType::SelfRemove]),
        Some(&[CredentialType::Basic]),
    )
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

fn xonly(pk: &PublicKey) -> [u8; 32] {
    pk.to_bytes()
}

fn identity_of(credential: &Credential) -> Option<[u8; 32]> {
    let basic = BasicCredential::try_from(credential.clone()).ok()?;
    let id: [u8; 32] = basic.identity().try_into().ok()?;
    PublicKey::from_slice(&id).ok()?;
    Some(id)
}

fn dict_of_leaf(leaf: &LeafNode) -> Option<&AppDataDictionary> {
    leaf.extensions().app_data_dictionary().map(AppDataDictionaryExtension::dictionary)
}

/// Check one member leaf: valid Marmot identity, a valid proof for its
/// signature key, support for every component the group requires.
fn check_leaf(leaf: &LeafNode, required: &BTreeSet<u16>) -> Result<[u8; 32], String> {
    let id = identity_of(leaf.credential()).ok_or("credential is not a 32-byte x-only key")?;
    let dict = dict_of_leaf(leaf).ok_or("leaf has no app_data_dictionary")?;
    let supported = dict
        .get(&codec::APP_COMPONENTS)
        .ok_or("leaf has no app_components list")
        .and_then(|b| codec::decode_components(b).map_err(|_| "bad app_components list"))?;
    if !supported.contains(&codec::IDENTITY_PROOF) {
        return Err("leaf does not advertise 0x8009".into());
    }
    if let Some(missing) = required.iter().find(|c| !supported.contains(c)) {
        return Err(format!("leaf does not support required component {missing:#06x}"));
    }
    let p = dict.get(&codec::IDENTITY_PROOF).ok_or("leaf has no identity proof")?;
    proof::verify(p, &id, cs_id(), scheme_id(), leaf.signature_key().as_slice()).map_err(|e| e.to_string())?;
    Ok(id)
}

/// Group-level state decoded from the GroupContext.
struct GroupState {
    required: BTreeSet<u16>,
    admins: BTreeSet<[u8; 32]>,
    routing: Routing,
    name: String,
    private: bool,
    /// `noscat.stun.v1`, empty when absent.
    stun: Vec<String>,
}

fn group_state(group: &MlsGroup) -> Result<GroupState, String> {
    let dict = group
        .extensions()
        .app_data_dictionary()
        .map(AppDataDictionaryExtension::dictionary)
        .ok_or("group has no app_data_dictionary")?;
    let get = |id: u16| dict.get(&id).ok_or(format!("group has no {id:#06x} state"));
    let required = codec::decode_components(get(codec::APP_COMPONENTS)?).map_err(|e| e.to_string())?;
    for c in [codec::ADMIN_POLICY, codec::IDENTITY_PROOF] {
        if !required.contains(&c) {
            return Err(format!("group does not require {c:#06x}"));
        }
    }
    let admins = codec::decode_admins(get(codec::ADMIN_POLICY)?).map_err(|e| e.to_string())?;
    let routing = codec::decode_routing(get(codec::NOSTR_ROUTING)?).map_err(|e| e.to_string())?;
    if let Some(l) = dict.get(&codec::LIFECYCLE) {
        if !codec::decode_lifecycle(l).map_err(|e| e.to_string())? {
            return Err("group is disbanded".into());
        }
    }
    let name = match dict.get(&codec::NOSCAT_MESH) {
        Some(b) => codec::decode_mesh(b).map_err(|e| e.to_string())?,
        None => String::new(),
    };
    Ok(GroupState {
        required,
        admins,
        routing,
        name,
        private: dict.get(&codec::NOSCAT_PRIVATE).is_some(),
        stun: match dict.get(&codec::NOSCAT_STUN) {
            Some(b) => codec::decode_stun(b).map_err(|e| e.to_string())?,
            None => Vec::new(),
        },
    })
}

/// Validate a resulting epoch: group state decodes, every leaf is valid,
/// every admin still has a leaf.
fn check_group(group: &MlsGroup) -> Result<GroupState, String> {
    let st = group_state(group)?;
    let mut accounts = BTreeSet::new();
    for m in group.members() {
        let leaf = group
            .public_group()
            .leaf(m.index)
            .ok_or("member without a leaf")?;
        accounts.insert(check_leaf(leaf, &st.required)?);
    }
    if let Some(a) = st.admins.iter().find(|a| !accounts.contains(*a)) {
        return Err(format!("admin {} has no leaf", hex::encode(a)));
    }
    Ok(st)
}

/// Validate one AppDataUpdate against the parent state: the bytes of every
/// component noscat understands must decode, and required components can
/// not be removed. Unknown components are opaque data.
fn check_app_data_update(update: &AppDataUpdateProposal, required: &BTreeSet<u16>) -> Result<(), String> {
    let id = update.component_id();
    let data = match update.operation() {
        AppDataUpdateOperation::Update(b) => b.as_slice(),
        AppDataUpdateOperation::Remove => {
            if required.contains(&id) || id == codec::ADMIN_POLICY || id == codec::LIFECYCLE || id == codec::APP_COMPONENTS {
                return Err(format!("cannot remove {id:#06x}"));
            }
            return Ok(());
        }
    };
    let r = match id {
        codec::APP_COMPONENTS => codec::decode_components(data).map(|ids| {
            if ids.contains(&codec::ADMIN_POLICY) && ids.contains(&codec::IDENTITY_PROOF) {
                Ok(())
            } else {
                Err(codec::CodecError("mandatory components dropped".into()))
            }
        }).and_then(|r| r),
        codec::ADMIN_POLICY => codec::decode_admins(data).map(|_| ()),
        codec::NOSTR_ROUTING => codec::decode_routing(data).map(|_| ()),
        codec::LIFECYCLE => match codec::decode_lifecycle(data) {
            Ok(true) => Ok(()),
            Ok(false) => Err(codec::CodecError("noscat does not support disbanding".into())),
            Err(e) => Err(e),
        },
        codec::NOSCAT_MESH => codec::decode_mesh(data).map(|_| ()),
        codec::NOSCAT_PRIVATE => codec::validate_private(data),
        codec::NOSCAT_STUN => codec::decode_stun(data).map(|_| ()),
        codec::GROUP_PROFILE => codec::validate_group_profile(data),
        codec::IDENTITY_PROOF | codec::SAFE_AAD => Err(codec::CodecError("not a GroupContext component".into())),
        _ => Ok(()),
    };
    r.map_err(|e| e.to_string())
}

/// Classify a commit: `Ok(false)` ordinary (a pure self-update, or only
/// SelfRemove proposals), `Ok(true)` privileged (needs an admin).
fn is_privileged(staged: &StagedCommit) -> bool {
    let mut any = false;
    for p in staged.queued_proposals() {
        any = true;
        if !matches!(p.proposal(), Proposal::SelfRemove) {
            return true;
        }
    }
    let _ = any;
    false
}

impl MeshGroup {
    /// Open (or create) the mesh state for `identity` in `dir`.
    pub fn open(dir: &Path, identity: &Identity) -> Result<Self, MeshError> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join(STATE_FILE);
        let (meta, storage) = if path.exists() {
            let p: Persisted = serde_json::from_slice(&crate::fsutil::read_secret(&path)?)
                .map_err(|e| MeshError::State(e.to_string()))?;
            if p.version != STATE_VERSION {
                return Err(MeshError::State(format!("unsupported state version {}", p.version)));
            }
            (p.meta, restore(&p.storage)?)
        } else {
            let mut slot = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rng(), &mut slot);
            (
                Meta {
                    slot: hex::encode(slot),
                    ..Meta::default()
                },
                MemoryStorage::default(),
            )
        };
        let provider = Provider {
            crypto: RustCrypto::default(),
            storage,
        };
        let group = match &meta.group_id {
            Some(gid) => MlsGroup::load(
                provider.storage(),
                &GroupId::from_slice(&hex::decode(gid).map_err(|_| MeshError::State("bad group id".into()))?),
            )
            .map_err(mls("load group"))?,
            None => None,
        };
        let me = Self {
            path,
            keys: identity.keys().clone(),
            signer: leaf_signer(identity),
            provider,
            meta,
            group,
            pending: None,
        };
        me.save()?;
        Ok(me)
    }

    fn save(&self) -> Result<(), MeshError> {
        let p = Persisted {
            version: STATE_VERSION,
            meta: serde_json::from_value(serde_json::to_value(&self.meta).map_err(|e| MeshError::State(e.to_string()))?)
                .map_err(|e| MeshError::State(e.to_string()))?,
            storage: dump(&self.provider.storage),
        };
        let bytes = serde_json::to_vec(&p).map_err(|e| MeshError::State(e.to_string()))?;
        crate::fsutil::write_secret(&self.path, &bytes)?;
        Ok(())
    }

    /// This device.
    #[must_use]
    pub fn device(&self) -> PublicKey {
        self.keys.public_key()
    }

    /// Whether this device is in a mesh.
    #[must_use]
    pub fn in_mesh(&self) -> bool {
        self.group.is_some()
    }

    /// Current epoch, if in a mesh.
    #[must_use]
    pub fn epoch(&self) -> Option<u64> {
        self.group.as_ref().map(|g| g.epoch().as_u64())
    }

    fn group(&self) -> Result<&MlsGroup, MeshError> {
        self.group.as_ref().ok_or(MeshError::NoMesh)
    }

    /// The mesh name ("" when unnamed).
    pub fn name(&self) -> Result<String, MeshError> {
        group_state(self.group()?).map(|s| s.name).map_err(MeshError::Mls)
    }

    /// Relays the group publishes to.
    pub fn relays(&self) -> Result<Vec<String>, MeshError> {
        group_state(self.group()?).map(|s| s.routing.relays).map_err(MeshError::Mls)
    }

    /// Whether the mesh is private (`noscat.private.v1`). False outside a
    /// mesh.
    #[must_use]
    pub fn is_private(&self) -> bool {
        self.group().ok().and_then(|g| group_state(g).ok()).is_some_and(|s| s.private)
    }

    /// The mesh's STUN servers (`noscat.stun.v1`); empty when it lists none
    /// or outside a mesh.
    #[must_use]
    pub fn stun(&self) -> Vec<String> {
        self.group().ok().and_then(|g| group_state(g).ok()).map(|s| s.stun).unwrap_or_default()
    }

    /// Replace the mesh's STUN servers (admins only): `ip:port` entries, no
    /// hostnames, at most 8. An empty list removes them (shared meshes then
    /// use public STUN servers, private meshes none).
    pub fn set_stun(&mut self, servers: &[String]) -> Result<Outgoing, MeshError> {
        let st = self.require_admin()?;
        let servers = codec::stun_list(servers)?;
        if servers == st.stun {
            return Err(MeshError::NotAllowed("the mesh already uses exactly these STUN servers".into()));
        }
        let update = if servers.is_empty() {
            AppDataUpdateProposal::remove(codec::NOSCAT_STUN)
        } else {
            AppDataUpdateProposal::update(codec::NOSCAT_STUN, codec::encode_stun(&servers))
        };
        let (commit, _) = self.stage_own(Vec::new(), Vec::new(), vec![Proposal::AppDataUpdate(Box::new(update))])?;
        Ok(Outgoing {
            commit,
            welcomes: Vec::new(),
        })
    }

    /// Replace the mesh's relays (admins only). The routing id stays, so
    /// members keep their subscriptions; they pick up the new relays when
    /// they apply the commit. Publish the commit to the old and new relays
    /// both, then [`Self::confirm`].
    pub fn set_relays(&mut self, relays: &[String]) -> Result<Outgoing, MeshError> {
        let st = self.require_admin()?;
        let routing = Routing::new(st.routing.nostr_group_id, relays)?;
        if routing.relays == st.routing.relays {
            return Err(MeshError::NotAllowed("the mesh already uses exactly these relays".into()));
        }
        let updates = vec![Proposal::AppDataUpdate(Box::new(AppDataUpdateProposal::update(
            codec::NOSTR_ROUTING,
            codec::encode_routing(&routing),
        )))];
        let (commit, _) = self.stage_own(Vec::new(), Vec::new(), updates)?;
        Ok(Outgoing {
            commit,
            welcomes: Vec::new(),
        })
    }

    /// Make the mesh private or shared (admins only).
    pub fn set_private(&mut self, private: bool) -> Result<Outgoing, MeshError> {
        let st = self.require_admin()?;
        if st.private == private {
            return Err(MeshError::NotAllowed(
                if private { "the mesh is already private" } else { "the mesh is already shared" }.into(),
            ));
        }
        let update = if private {
            AppDataUpdateProposal::update(codec::NOSCAT_PRIVATE, Vec::new())
        } else {
            AppDataUpdateProposal::remove(codec::NOSCAT_PRIVATE)
        };
        let (commit, _) = self.stage_own(Vec::new(), Vec::new(), vec![Proposal::AppDataUpdate(Box::new(update))])?;
        Ok(Outgoing {
            commit,
            welcomes: Vec::new(),
        })
    }

    /// Routing ids to subscribe to (`#h`), newest last. Older ones stay
    /// while their epochs may still produce traffic.
    #[must_use]
    pub fn routing_ids(&self) -> Vec<[u8; 32]> {
        self.meta
            .routing_ids
            .iter()
            .filter_map(|h| hex::decode(h).ok()?.try_into().ok())
            .collect()
    }

    /// The roster: every member device, with admin flags.
    pub fn members(&self) -> Result<Vec<MemberInfo>, MeshError> {
        let g = self.group()?;
        let st = group_state(g).map_err(MeshError::Mls)?;
        let me = xonly(&self.device());
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        for m in g.members() {
            let Some(id) = identity_of(&m.credential) else { continue };
            if !seen.insert(id) {
                continue;
            }
            let Ok(device) = PublicKey::from_slice(&id) else { continue };
            out.push(MemberInfo {
                device,
                admin: st.admins.contains(&id),
                this_device: id == me,
            });
        }
        Ok(out)
    }

    fn roster(&self) -> Vec<PublicKey> {
        self.members().map(|m| m.into_iter().map(|m| m.device).collect()).unwrap_or_default()
    }

    fn leaf_extensions(&self) -> Result<Extensions<LeafNode>, MeshError> {
        let mut dict = AppDataDictionary::new();
        dict.insert(
            codec::APP_COMPONENTS,
            codec::encode_components(&codec::SUPPORTED_COMPONENTS.into_iter().collect()),
        );
        dict.insert(codec::SAFE_AAD, codec::encode_components(&BTreeSet::new()));
        let p = proof::sign(&self.keys, now_secs(), cs_id(), scheme_id(), self.signer.public());
        dict.insert(codec::IDENTITY_PROOF, p.to_vec());
        Extensions::from_vec(vec![Extension::AppDataDictionary(AppDataDictionaryExtension::new(dict))])
            .map_err(mls("leaf extensions"))
    }

    fn credential(&self) -> CredentialWithKey {
        CredentialWithKey {
            credential: BasicCredential::new(xonly(&self.device()).to_vec()).into(),
            signature_key: self.signer.public().into(),
        }
    }

    fn group_event_key(group: &MlsGroup, crypto: &RustCrypto) -> Result<[u8; 32], MeshError> {
        let s = group
            .export_secret(crypto, EXPORTER_LABEL, EXPORTER_CONTEXT, 32)
            .map_err(mls("exporter"))?;
        s.as_slice().try_into().map_err(|_| MeshError::Mls("exporter length".into()))
    }

    /// Record the current epoch's key and routing id after any epoch change.
    fn note_epoch(&mut self) -> Result<(), MeshError> {
        let g = self.group()?;
        let epoch = g.epoch().as_u64();
        let key = Self::group_event_key(g, &self.provider.crypto)?;
        let routing = group_state(g).map_err(MeshError::Mls)?.routing;
        self.meta.epoch_keys.retain(|(e, _)| *e < epoch && epoch - *e <= MAX_REWIND);
        self.meta.epoch_keys.push((epoch, hex::encode(key)));
        let h = hex::encode(routing.nostr_group_id);
        if self.meta.routing_ids.last() != Some(&h) {
            self.meta.routing_ids.retain(|x| *x != h);
            self.meta.routing_ids.push(h);
            let keep = self.meta.routing_ids.len().saturating_sub(4);
            self.meta.routing_ids.drain(..keep);
        }
        let floor = epoch.saturating_sub(MAX_REWIND);
        self.meta.witnesses.retain(|e, _| *e >= floor);
        self.meta.history.retain(|a| a.parent_epoch + MAX_REWIND >= epoch);
        Ok(())
    }

    fn current_key(&self) -> Result<[u8; 32], MeshError> {
        let (_, k) = self.meta.epoch_keys.last().ok_or(MeshError::NoMesh)?;
        let mut out = [0u8; 32];
        hex::decode_to_slice(k, &mut out).map_err(|_| MeshError::State("bad epoch key".into()))?;
        Ok(out)
    }

    fn current_routing_id(&self) -> Result<[u8; 32], MeshError> {
        Ok(group_state(self.group()?).map_err(MeshError::Mls)?.routing.nostr_group_id)
    }

    // ---- creating and joining ------------------------------------------

    /// Create a one-device mesh named `name`, routed over `relays`.
    pub fn create(&mut self, name: &str, relays: &[String]) -> Result<(), MeshError> {
        if self.group.is_some() {
            return Err(MeshError::AlreadyInMesh);
        }
        let mut rid = [0u8; 32];
        let mut gid = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut rid);
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut gid);
        let routing = Routing::new(rid, relays)?;
        let mut dict = AppDataDictionary::new();
        dict.insert(
            codec::APP_COMPONENTS,
            codec::encode_components(&codec::REQUIRED_COMPONENTS.into_iter().collect()),
        );
        dict.insert(codec::ADMIN_POLICY, codec::encode_admins(&[xonly(&self.device())].into()));
        dict.insert(codec::NOSTR_ROUTING, codec::encode_routing(&routing));
        dict.insert(codec::LIFECYCLE, codec::LIFECYCLE_ACTIVE.to_vec());
        dict.insert(codec::NOSCAT_MESH, codec::encode_mesh(name)?);
        let ctx = Extensions::from_vec(vec![
            Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
                &[ExtensionType::AppDataDictionary],
                &[ProposalType::AppDataUpdate],
                &[],
            )),
            Extension::AppDataDictionary(AppDataDictionaryExtension::new(dict)),
        ])
        .map_err(mls("group extensions"))?;
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .capabilities(capabilities())
            .with_leaf_node_extensions(self.leaf_extensions()?)
            .map_err(mls("leaf extensions"))?
            .with_group_context_extensions(ctx)
            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .max_past_epochs(MAX_REWIND as usize)
            .build();
        let group = MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            &config,
            GroupId::from_slice(&gid),
            self.credential(),
        )
        .map_err(mls("create group"))?;
        check_group(&group).map_err(MeshError::Mls)?;
        self.meta.group_id = Some(hex::encode(gid));
        self.group = Some(group);
        self.note_epoch()?;
        self.save()
    }

    /// A fresh signed kind 30443 key package event for this device's slot.
    /// The private key stays in local state until a Welcome consumes it or
    /// it is replaced.
    pub fn key_package_event(&mut self) -> Result<Event, MeshError> {
        let bundle = KeyPackage::builder()
            .key_package_lifetime(Lifetime::new(KEY_PACKAGE_LIFETIME_SECS))
            .leaf_node_capabilities(capabilities())
            .leaf_node_extensions(self.leaf_extensions()?)
            .mark_as_last_resort()
            .build(CIPHERSUITE, &self.provider, &self.signer, self.credential())
            .map_err(mls("key package"))?;
        let kp = bundle.key_package().clone();
        let kp_ref = kp.hash_ref(&self.provider.crypto).map_err(mls("key package ref"))?;
        let msg: MlsMessageOut = kp.into();
        let bytes = msg.tls_serialize_detached().map_err(mls("serialize key package"))?;
        let mut slot = [0u8; 32];
        hex::decode_to_slice(&self.meta.slot, &mut slot).map_err(|_| MeshError::State("bad slot".into()))?;
        let mut components: Vec<u16> = codec::SUPPORTED_COMPONENTS
            .into_iter()
            .filter(|c| *c >= codec::FIRST_APP_COMPONENT)
            .collect();
        components.sort_unstable();
        let at = Timestamp::now().as_secs().max(self.meta.last_key_package_at + 1);
        self.meta.last_key_package_at = at;
        let ev = transport::key_package_event(
            &self.keys,
            &bytes,
            &KeyPackageTags {
                slot: &slot,
                key_package_ref: kp_ref.as_slice(),
                ciphersuite: cs_id(),
                extensions: &[u16::from(ExtensionType::AppDataDictionary)],
                proposals: &[u16::from(ProposalType::AppDataUpdate), u16::from(ProposalType::SelfRemove)],
                components: &components,
            },
            Timestamp::from_secs(at),
        )?;
        // Keep the newest two: an inviter may still hold the previous one.
        self.meta.key_packages.push(OwnKeyPackage {
            event_id: ev.id.to_hex(),
            key_package_ref: hex::encode(kp_ref.as_slice()),
        });
        while self.meta.key_packages.len() > 2 {
            let old = self.meta.key_packages.remove(0);
            if let Some(r) = key_package_ref(&old.key_package_ref) {
                let _ = self.provider.storage.delete_key_package(&r);
            }
        }
        self.save()?;
        Ok(ev)
    }

    /// Validate a member-to-be's key package event; returns the device and
    /// the decoded package.
    fn validate_key_package(&self, event: &Event) -> Result<(PublicKey, KeyPackage), MeshError> {
        let env = transport::open_key_package_event(event)?;
        let msg = MlsMessageIn::tls_deserialize_exact(&env.mls_bytes)
            .map_err(|_| MeshError::KeyPackage("content is not an MLSMessage".into()))?;
        let MlsMessageBodyIn::KeyPackage(kp_in) = msg.extract() else {
            return Err(MeshError::KeyPackage("not a key package message".into()));
        };
        let kp = kp_in
            .validate(&self.provider.crypto, ProtocolVersion::Mls10)
            .map_err(|e| MeshError::KeyPackage(format!("{e:?}")))?;
        if kp.ciphersuite() != CIPHERSUITE {
            return Err(MeshError::KeyPackage("unsupported ciphersuite".into()));
        }
        let r = kp.hash_ref(&self.provider.crypto).map_err(mls("key package ref"))?;
        if r.as_slice() != env.key_package_ref.as_slice() {
            return Err(MeshError::KeyPackage("i tag does not match the package".into()));
        }
        let lt = kp.life_time();
        if lt.not_after().saturating_sub(lt.not_before()) > MAX_KEY_PACKAGE_RANGE_SECS {
            return Err(MeshError::KeyPackage("lifetime range too long".into()));
        }
        let required = match &self.group {
            Some(g) => group_state(g).map_err(MeshError::Mls)?.required,
            None => codec::REQUIRED_COMPONENTS.into_iter().collect(),
        };
        let id = check_leaf(kp.leaf_node(), &required).map_err(MeshError::KeyPackage)?;
        if id != xonly(&event.pubkey) {
            return Err(MeshError::KeyPackage("author is not the credential identity".into()));
        }
        Ok((event.pubkey, kp))
    }

    // ---- membership changes (admin) ------------------------------------

    fn require_admin(&self) -> Result<GroupState, MeshError> {
        let st = group_state(self.group()?).map_err(MeshError::Mls)?;
        if !st.admins.contains(&xonly(&self.device())) {
            return Err(MeshError::NotAllowed("this device is not an admin of the mesh".into()));
        }
        if self.pending.is_some() {
            return Err(MeshError::Pending);
        }
        Ok(st)
    }

    /// Add devices from their key package events. Every added device
    /// becomes an admin. Publish `commit`, then call [`Self::confirm`].
    pub fn add(&mut self, key_packages: &[Event]) -> Result<Outgoing, MeshError> {
        let st = self.require_admin()?;
        let mut kps = Vec::new();
        let mut added = Vec::new();
        let mut admins = st.admins.clone();
        for ev in key_packages {
            let (device, kp) = self.validate_key_package(ev)?;
            if self.roster().contains(&device) {
                return Err(MeshError::NotAllowed(format!("{} is already a member", device.to_hex())));
            }
            admins.insert(xonly(&device));
            added.push((device, ev.id));
            kps.push(kp);
        }
        if kps.is_empty() {
            return Err(MeshError::NotAllowed("nothing to add".into()));
        }
        let updates = vec![Proposal::AppDataUpdate(Box::new(AppDataUpdateProposal::update(
            codec::ADMIN_POLICY,
            codec::encode_admins(&admins),
        )))];
        let (commit, welcome) = self.stage_own(kps, Vec::new(), updates)?;
        let welcome = welcome.ok_or_else(|| MeshError::Mls("add produced no Welcome".into()))?;
        let wbytes = welcome.tls_serialize_detached().map_err(mls("serialize welcome"))?;
        Ok(Outgoing {
            commit,
            welcomes: added
                .into_iter()
                .map(|(invitee, kp_event)| PendingWelcome {
                    invitee,
                    key_package_event: kp_event,
                    welcome: wbytes.clone(),
                    relays: st.routing.relays.clone(),
                })
                .collect(),
        })
    }

    /// Remove devices (and their admin entries).
    pub fn remove(&mut self, devices: &[PublicKey]) -> Result<Outgoing, MeshError> {
        let st = self.require_admin()?;
        let g = self.group()?;
        let gone: BTreeSet<[u8; 32]> = devices.iter().map(xonly).collect();
        if gone.contains(&xonly(&self.device())) {
            return Err(MeshError::NotAllowed("use leave to remove this device".into()));
        }
        let leaves: Vec<LeafNodeIndex> = g
            .members()
            .filter(|m| identity_of(&m.credential).is_some_and(|id| gone.contains(&id)))
            .map(|m| m.index)
            .collect();
        if leaves.is_empty() {
            return Err(MeshError::NotAllowed("not a member".into()));
        }
        let admins: BTreeSet<[u8; 32]> = st.admins.difference(&gone).copied().collect();
        let updates = if admins == st.admins {
            Vec::new()
        } else {
            vec![Proposal::AppDataUpdate(Box::new(AppDataUpdateProposal::update(
                codec::ADMIN_POLICY,
                codec::encode_admins(&admins),
            )))]
        };
        let (commit, _) = self.stage_own(Vec::new(), leaves, updates)?;
        Ok(Outgoing {
            commit,
            welcomes: Vec::new(),
        })
    }

    /// First step of leaving: drop this device from the admin list (valid
    /// only while another admin remains). Publish and [`Self::confirm`],
    /// then call [`Self::leave_request`].
    pub fn step_down(&mut self) -> Result<Outgoing, MeshError> {
        let st = self.require_admin()?;
        let mut admins = st.admins.clone();
        admins.remove(&xonly(&self.device()));
        if admins.is_empty() {
            return Err(MeshError::NotAllowed(
                "this is the only admin; remove the other devices or keep the mesh".into(),
            ));
        }
        let updates = vec![Proposal::AppDataUpdate(Box::new(AppDataUpdateProposal::update(
            codec::ADMIN_POLICY,
            codec::encode_admins(&admins),
        )))];
        let (commit, _) = self.stage_own(Vec::new(), Vec::new(), updates)?;
        Ok(Outgoing {
            commit,
            welcomes: Vec::new(),
        })
    }

    /// Second step of leaving: a SelfRemove proposal for another member to
    /// commit. Returns the kind 445 event to publish.
    pub fn leave_request(&mut self) -> Result<Event, MeshError> {
        let st = group_state(self.group()?).map_err(MeshError::Mls)?;
        if st.admins.contains(&xonly(&self.device())) {
            return Err(MeshError::NotAllowed("step down as admin first".into()));
        }
        let key = self.current_key()?;
        let rid = self.current_routing_id()?;
        let g = self.group.as_mut().ok_or(MeshError::NoMesh)?;
        let msg = g
            .leave_group_via_self_remove(&self.provider, &self.signer)
            .map_err(mls("self remove"))?;
        let bytes = msg.tls_serialize_detached().map_err(mls("serialize"))?;
        self.save()?;
        Ok(transport::seal_group_event(&key, &rid, &bytes)?)
    }

    /// Commit pending SelfRemove proposals from members who asked to leave.
    /// Returns `None` when there is nothing to commit.
    pub fn commit_pending(&mut self) -> Result<Option<Outgoing>, MeshError> {
        let g = self.group()?;
        if self.pending.is_some() || g.pending_proposals().next().is_none() {
            return Ok(None);
        }
        let (commit, _) = self.stage_own(Vec::new(), Vec::new(), Vec::new())?;
        Ok(Some(Outgoing {
            commit,
            welcomes: Vec::new(),
        }))
    }

    /// Build and stage an own commit; the group stays at its epoch until
    /// [`Self::confirm`].
    fn stage_own(
        &mut self,
        adds: Vec<KeyPackage>,
        removals: Vec<LeafNodeIndex>,
        proposals: Vec<Proposal>,
    ) -> Result<(Event, Option<MlsMessageOut>), MeshError> {
        let key = self.current_key()?;
        let rid = self.current_routing_id()?;
        let required = group_state(self.group()?).map_err(MeshError::Mls)?.required;
        let snapshot = dump(&self.provider.storage);
        let g = self.group.as_mut().ok_or(MeshError::NoMesh)?;
        for p in &proposals {
            if let Proposal::AppDataUpdate(u) = p {
                check_app_data_update(u, &required).map_err(MeshError::NotAllowed)?;
            }
        }
        let mut builder = g
            .commit_builder()
            .consume_proposal_store(true)
            .propose_adds(adds)
            .propose_removals(removals)
            .add_proposals(proposals)
            .load_psks(self.provider.storage())
            .map_err(mls("load psks"))?;
        let updates: Vec<AppDataUpdateProposal> = builder.app_data_update_proposals().cloned().collect();
        let mut updater = builder.app_data_dictionary_updater();
        for u in &updates {
            match u.operation() {
                AppDataUpdateOperation::Update(d) => {
                    updater.set(ComponentData::from_parts(u.component_id(), d.clone()));
                }
                AppDataUpdateOperation::Remove => updater.remove(&u.component_id()),
            }
        }
        let changes = updater.changes();
        builder.with_app_data_dictionary_updates(changes);
        let bundle = builder
            .build(self.provider.rand(), self.provider.crypto(), &self.signer, |_| true)
            .map_err(mls("build commit"))?
            .stage_commit(&self.provider)
            .map_err(mls("stage commit"))?;
        let (commit, welcome, _) = bundle.into_messages();
        let bytes = commit.tls_serialize_detached().map_err(mls("serialize commit"))?;
        self.pending = Some((snapshot, sha256(&bytes)));
        let ev = transport::seal_group_event(&key, &rid, &bytes)?;
        Ok((ev, welcome))
    }

    /// The staged commit was acknowledged by a relay: apply it.
    pub fn confirm(&mut self) -> Result<Vec<Change>, MeshError> {
        let Some((snapshot, digest)) = self.pending.take() else {
            return Ok(Vec::new());
        };
        let parent_epoch = self.epoch().ok_or(MeshError::NoMesh)?;
        let g = self.group.as_mut().ok_or(MeshError::NoMesh)?;
        g.merge_pending_commit(&self.provider).map_err(mls("merge own commit"))?;
        self.meta.history.push(Applied {
            parent_epoch,
            snapshot,
            digest,
            committer: xonly(&self.device()),
            privileged: true,
            own: true,
        });
        self.note_epoch()?;
        let mut changes = vec![Change::Roster(self.roster())];
        changes.extend(self.retry_deferred()?);
        self.save()?;
        Ok(changes)
    }

    /// Publication failed for good: drop the staged commit.
    pub fn abandon(&mut self) -> Result<(), MeshError> {
        if self.pending.take().is_some() {
            if let Some(g) = self.group.as_mut() {
                g.clear_pending_commit(self.provider.storage()).map_err(mls("clear pending"))?;
            }
            self.save()?;
        }
        Ok(())
    }

    /// Gift-wrap one Welcome for delivery to the invitee's inbox relays.
    pub fn wrap_welcome(&self, w: &PendingWelcome) -> Result<Event, MeshError> {
        Ok(transport::wrap_welcome(&self.keys, &w.invitee, &w.welcome, &w.key_package_event, &w.relays)?)
    }

    /// Join a mesh from a Welcome gift wrap. With `inviter`, only that
    /// device's invitation is accepted (the scanned QR is the trust
    /// anchor). Returns `Ok(None)` for gift wraps that are not for this
    /// device's key packages; they may be another device's.
    pub fn join(&mut self, gift_wrap: &Event, inviter: Option<PublicKey>) -> Result<Option<Vec<Change>>, MeshError> {
        if self.group.is_some() {
            return Err(MeshError::AlreadyInMesh);
        }
        let Some(env) = transport::unwrap_welcome(&self.keys, gift_wrap)? else {
            return Ok(None);
        };
        if !self.meta.key_packages.iter().any(|k| k.event_id == env.key_package_event_id.to_hex()) {
            return Ok(None);
        }
        if inviter.is_some_and(|i| i != env.sender) {
            return Err(MeshError::Welcome("the invitation is not from the expected device".into()));
        }
        let msg = MlsMessageIn::tls_deserialize_exact(&env.mls_bytes)
            .map_err(|_| MeshError::Welcome("not an MLSMessage".into()))?;
        let MlsMessageBodyIn::Welcome(welcome) = msg.extract() else {
            return Err(MeshError::Welcome("not a Welcome".into()));
        };
        // Stage on a copy so a rejected Welcome leaves the key package as
        // it was.
        let trial = Provider {
            crypto: RustCrypto::default(),
            storage: restore(&dump(&self.provider.storage))?,
        };
        let config = MlsGroupJoinConfig::builder()
            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .max_past_epochs(MAX_REWIND as usize)
            .build();
        let staged = StagedWelcome::new_from_welcome(&trial, &config, welcome, None)
            .map_err(|e| MeshError::Welcome(format!("{e:?}")))?;
        let sender = staged.welcome_sender().map_err(mls("welcome sender"))?;
        let author = identity_of(sender.credential())
            .ok_or_else(|| MeshError::Welcome("author has no Marmot identity".into()))?;
        if author != xonly(&env.sender) {
            return Err(MeshError::Welcome("gift wrap sender is not the Welcome author".into()));
        }
        let group = staged.into_group(&trial).map_err(|e| MeshError::Welcome(format!("{e:?}")))?;
        let st = check_group(&group).map_err(MeshError::Welcome)?;
        if !st.admins.contains(&author) {
            return Err(MeshError::Welcome("the inviter is not an admin of the mesh".into()));
        }
        self.provider = trial;
        self.meta.group_id = Some(hex::encode(group.group_id().as_slice()));
        self.group = Some(group);
        self.note_epoch()?;
        self.save()?;
        Ok(Some(vec![Change::Roster(self.roster())]))
    }

    // ---- inbound group traffic -----------------------------------------

    /// Process one kind 445 event. Malformed or foreign events are dropped
    /// without error; an `Err` means local state could not be written.
    pub fn process(&mut self, event: &Event) -> Result<Vec<Change>, MeshError> {
        if self.group.is_none() {
            return Ok(Vec::new());
        }
        let Ok((h, payload)) = transport::open_group_envelope(event) else {
            return Ok(Vec::new());
        };
        if !self.routing_ids().contains(&h) {
            return Ok(Vec::new());
        }
        let changes = self.process_payload(&payload, true)?;
        self.save()?;
        Ok(changes)
    }

    fn keys_newest_first(&self) -> Vec<(u64, [u8; 32])> {
        self.meta
            .epoch_keys
            .iter()
            .rev()
            .filter_map(|(e, k)| {
                let mut out = [0u8; 32];
                hex::decode_to_slice(k, &mut out).ok()?;
                Some((*e, out))
            })
            .collect()
    }

    fn process_payload(&mut self, payload: &[u8], defer: bool) -> Result<Vec<Change>, MeshError> {
        let opened = self
            .keys_newest_first()
            .into_iter()
            .find_map(|(_, k)| transport::decrypt_group_payload(&k, payload));
        let Some(mls_bytes) = opened else {
            if defer {
                push_bounded(&mut self.meta.deferred_payloads, B64.encode(payload));
            }
            return Ok(Vec::new());
        };
        self.process_mls(&mls_bytes)
    }

    fn mark_seen(&mut self, id: &[u8; 32]) -> bool {
        let h = hex::encode(id);
        if self.meta.seen.contains(&h) {
            return false;
        }
        self.meta.seen.push_back(h);
        while self.meta.seen.len() > SEEN_KEEP {
            self.meta.seen.pop_front();
        }
        true
    }

    fn process_mls(&mut self, mls_bytes: &[u8]) -> Result<Vec<Change>, MeshError> {
        let digest = sha256(mls_bytes);
        if self.meta.seen.contains(&hex::encode(digest)) {
            return Ok(Vec::new());
        }
        let Ok(msg) = MlsMessageIn::tls_deserialize_exact(mls_bytes) else {
            self.mark_seen(&digest);
            return Ok(Vec::new());
        };
        let Ok(proto) = ProtocolMessage::try_from(msg) else {
            self.mark_seen(&digest);
            return Ok(Vec::new());
        };
        let current = self.epoch().ok_or(MeshError::NoMesh)?;
        let epoch = proto.epoch().as_u64();
        let is_commit = proto.content_type() == ContentType::Commit;
        if epoch > current || (self.pending.is_some() && is_commit) {
            push_bounded(&mut self.meta.deferred_messages, B64.encode(mls_bytes));
            return Ok(Vec::new());
        }
        if is_commit && epoch < current {
            self.mark_seen(&digest);
            return self.race(mls_bytes, epoch, digest);
        }
        self.mark_seen(&digest);
        self.apply(proto, digest)
    }

    /// Process a message at the current epoch (or an app message from a
    /// retained past epoch).
    fn apply(&mut self, proto: ProtocolMessage, digest: [u8; 32]) -> Result<Vec<Change>, MeshError> {
        let parent_epoch = self.epoch().ok_or(MeshError::NoMesh)?;
        let parent_state = group_state(self.group()?).map_err(MeshError::Mls)?;
        let snapshot = dump(&self.provider.storage);
        let g = self.group.as_mut().ok_or(MeshError::NoMesh)?;
        let Ok(processed) = g.process_message(&self.provider, proto) else {
            return Ok(Vec::new());
        };
        let sender_id = identity_of(processed.credential());
        let msg_epoch = processed.epoch().as_u64();
        let processed = match processed.content() {
            ProcessedMessageContent::UnresolvedAppDataCommit(u) => {
                let updates: Vec<AppDataUpdateProposal> = u.app_data_update_proposals().cloned().collect();
                if updates.iter().any(|u| check_app_data_update(u, &parent_state.required).is_err())
                    || !sender_id.is_some_and(|s| parent_state.admins.contains(&s))
                {
                    self.rollback(snapshot)?;
                    return Ok(Vec::new());
                }
                let mut updater = g.app_data_dictionary_updater();
                for u in &updates {
                    match u.operation() {
                        AppDataUpdateOperation::Update(d) => {
                            updater.set(ComponentData::from_parts(u.component_id(), d.clone()));
                        }
                        AppDataUpdateOperation::Remove => updater.remove(&u.component_id()),
                    }
                }
                let changes = updater.changes();
                match g.resolve_app_data_commit(&self.provider, processed, changes) {
                    Ok(p) => p,
                    Err(_) => {
                        self.rollback(snapshot)?;
                        return Ok(Vec::new());
                    }
                }
            }
            _ => processed,
        };
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(m) => {
                let Some(sender) = sender_id else { return Ok(Vec::new()) };
                let Ok(ev) = AppEvent::from_json(&m.into_bytes()) else {
                    return Ok(Vec::new());
                };
                if xonly(&ev.pubkey) != sender {
                    return Ok(Vec::new());
                }
                self.meta.witnesses.entry(msg_epoch).or_default().insert(hex::encode(sender));
                Ok(vec![Change::App(ev)])
            }
            ProcessedMessageContent::ProposalMessage(qp) => {
                // Only SelfRemove from a non-admin is accepted standalone.
                let ok = matches!(qp.proposal(), Proposal::SelfRemove)
                    && sender_id.is_some_and(|s| !parent_state.admins.contains(&s));
                if !ok {
                    return Ok(Vec::new());
                }
                let who = sender_id.and_then(|s| PublicKey::from_slice(&s).ok());
                g.store_pending_proposal(self.provider.storage(), *qp)
                    .map_err(mls("store proposal"))?;
                Ok(who.map(Change::LeaveRequested).into_iter().collect())
            }
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                let privileged = is_privileged(&staged);
                let Some(committer) = sender_id else {
                    self.rollback(snapshot)?;
                    return Ok(Vec::new());
                };
                if privileged && !parent_state.admins.contains(&committer) {
                    self.rollback(snapshot)?;
                    return Ok(Vec::new());
                }
                let removed_me = staged.self_removed();
                if g.merge_staged_commit(&self.provider, *staged).is_err() {
                    self.rollback(snapshot)?;
                    return Ok(Vec::new());
                }
                if removed_me {
                    return self.forget_group();
                }
                if check_group(self.group()?).is_err() {
                    self.rollback(snapshot)?;
                    return Ok(Vec::new());
                }
                self.meta.history.push(Applied {
                    parent_epoch,
                    snapshot,
                    digest,
                    committer,
                    privileged,
                    own: false,
                });
                self.note_epoch()?;
                let mut changes = vec![Change::Roster(self.roster())];
                changes.extend(self.retry_deferred()?);
                Ok(changes)
            }
            _ => Ok(Vec::new()),
        }
    }

    fn rollback(&mut self, snapshot: Dump) -> Result<(), MeshError> {
        self.provider.storage = restore(&snapshot)?;
        self.reload()
    }

    fn reload(&mut self) -> Result<(), MeshError> {
        let gid = self.meta.group_id.as_ref().ok_or(MeshError::NoMesh)?;
        let gid = GroupId::from_slice(&hex::decode(gid).map_err(|_| MeshError::State("bad group id".into()))?);
        self.group = MlsGroup::load(self.provider.storage(), &gid).map_err(mls("load group"))?;
        Ok(())
    }

    /// Drop this device's mesh state without telling anyone: for the last
    /// device of a mesh, or after a leave that no member committed. The
    /// key package slot is kept.
    pub fn forget(&mut self) -> Result<(), MeshError> {
        self.pending = None;
        self.forget_group()?;
        self.save()
    }

    /// Whether this device is an admin of its mesh.
    #[must_use]
    pub fn is_admin(&self) -> bool {
        self.group
            .as_ref()
            .and_then(|g| group_state(g).ok())
            .is_some_and(|st| st.admins.contains(&xonly(&self.device())))
    }

    fn forget_group(&mut self) -> Result<Vec<Change>, MeshError> {
        if let Some(g) = self.group.as_mut() {
            let _ = g.delete(self.provider.storage());
        }
        self.group = None;
        let slot = std::mem::take(&mut self.meta.slot);
        self.meta = Meta {
            slot,
            ..Meta::default()
        };
        self.provider.storage = MemoryStorage::default();
        Ok(vec![Change::Removed])
    }

    /// After an epoch change, retry inputs that could not be used before.
    fn retry_deferred(&mut self) -> Result<Vec<Change>, MeshError> {
        let mut out = Vec::new();
        for _ in 0..4 {
            let before = self.epoch();
            let messages: Vec<String> = self.meta.deferred_messages.drain(..).collect();
            for m in messages {
                if let Ok(b) = B64.decode(&m) {
                    out.extend(self.process_mls(&b)?);
                }
            }
            let payloads: Vec<String> = self.meta.deferred_payloads.drain(..).collect();
            for p in payloads {
                if let Ok(b) = B64.decode(&p) {
                    out.extend(self.process_payload(&b, true)?);
                }
            }
            if self.epoch() == before || self.group.is_none() {
                break;
            }
        }
        Ok(out)
    }

    // ---- convergence ---------------------------------------------------

    /// A valid-looking commit for an older epoch: compare branches.
    fn race(&mut self, mls_bytes: &[u8], parent: u64, digest: [u8; 32]) -> Result<Vec<Change>, MeshError> {
        let current = self.epoch().ok_or(MeshError::NoMesh)?;
        if current - parent > MAX_REWIND {
            return Ok(Vec::new());
        }
        let Some(pos) = self.meta.history.iter().position(|a| a.parent_epoch == parent) else {
            return Ok(Vec::new());
        };
        let fork = self.meta.history[pos].clone();
        if fork.digest == digest {
            return Ok(Vec::new());
        }

        // Replay the competitor on a copy of the fork state.
        let mut trial = MeshGroup {
            path: self.path.clone(),
            keys: self.keys.clone(),
            signer: self.signer.clone(),
            provider: Provider {
                crypto: RustCrypto::default(),
                storage: restore(&fork.snapshot)?,
            },
            meta: Meta {
                group_id: self.meta.group_id.clone(),
                slot: self.meta.slot.clone(),
                ..Meta::default()
            },
            group: None,
            pending: None,
        };
        trial.reload()?;
        trial.note_epoch()?;
        let Ok(msg) = MlsMessageIn::tls_deserialize_exact(mls_bytes) else { return Ok(Vec::new()) };
        let Ok(proto) = ProtocolMessage::try_from(msg) else { return Ok(Vec::new()) };
        let mut trial_changes = trial.apply(proto, digest)?;
        if trial.epoch() != Some(parent + 1) {
            return Ok(Vec::new()); // invalid against its parent
        }
        let Some(their_tip) = trial.meta.history.last().cloned() else {
            return Ok(Vec::new());
        };
        // Witnesses for the competitor: app messages we could not open.
        let payloads: Vec<String> = self.meta.deferred_payloads.iter().cloned().collect();
        for p in payloads {
            if let Ok(b) = B64.decode(&p) {
                trial_changes.extend(trial.process_payload(&b, false)?);
            }
        }

        let ours = Branch {
            depth: current - parent,
            witnesses: (parent + 1..=current)
                .map(|e| self.meta.witnesses.get(&e).map_or(0, BTreeSet::len))
                .collect(),
            tip: self.meta.history.last().cloned().unwrap_or(fork.clone()),
        };
        let theirs = Branch {
            depth: 1,
            witnesses: vec![trial.meta.witnesses.get(&(parent + 1)).map_or(0, BTreeSet::len)],
            tip: their_tip.clone(),
        };
        if !theirs.beats(&ours) {
            return Ok(Vec::new());
        }

        // The competitor wins: adopt the trial state.
        let superseded: Vec<Change> = self.meta.history[pos..]
            .iter()
            .map(|a| Change::Superseded {
                digest: a.digest,
                own: a.own,
            })
            .collect();
        let mut history: Vec<Applied> = self.meta.history[..pos].to_vec();
        history.push(Applied {
            snapshot: fork.snapshot.clone(),
            ..their_tip
        });
        self.provider = trial.provider;
        self.group = trial.group;
        self.meta.history = history;
        self.meta.witnesses.retain(|e, _| *e <= parent);
        for (e, s) in trial.meta.witnesses {
            self.meta.witnesses.insert(e, s);
        }
        self.meta.epoch_keys.retain(|(e, _)| *e <= parent);
        self.note_epoch()?;
        let mut changes = superseded;
        changes.push(Change::Roster(self.roster()));
        changes.extend(trial_changes.into_iter().filter(|c| matches!(c, Change::App(_))));
        changes.extend(self.retry_deferred()?);
        Ok(changes)
    }

    // ---- app events ----------------------------------------------------

    /// Encrypt an app event of `kind` into a kind 445 event.
    pub fn send_app(&mut self, kind: u16, tags: Vec<Vec<String>>, content: String) -> Result<Event, MeshError> {
        let key = self.current_key()?;
        let rid = self.current_routing_id()?;
        let ev = AppEvent::new(self.device(), kind, tags, content)?;
        let g = self.group.as_mut().ok_or(MeshError::NoMesh)?;
        let msg = g
            .create_message(&self.provider, &self.signer, &ev.to_json())
            .map_err(mls("create message"))?;
        let bytes = msg.tls_serialize_detached().map_err(mls("serialize"))?;
        let epoch = g.epoch().as_u64();
        self.mark_seen(&sha256(&bytes));
        let me = hex::encode(xonly(&self.device()));
        self.meta.witnesses.entry(epoch).or_default().insert(me);
        self.save()?;
        Ok(transport::seal_group_event(&key, &rid, &bytes)?)
    }

    /// This device's advert as an app event (see [`ADVERT_KIND`]).
    pub fn send_advert(&mut self, fips_advert_json: Option<&str>, name: &str, reachable: bool) -> Result<Event, MeshError> {
        let mut tags = Vec::new();
        if !name.is_empty() {
            tags.push(vec!["name".to_string(), name.to_string()]);
        }
        if reachable {
            tags.push(vec!["reachable".to_string(), "1".to_string()]);
        }
        self.send_app(ADVERT_KIND, tags, fips_advert_json.unwrap_or_default().to_string())
    }
}

/// A stored hex key package ref back as an OpenMLS `KeyPackageRef`.
fn key_package_ref(hex_ref: &str) -> Option<KeyPackageRef> {
    let raw = hex::decode(hex_ref).ok()?;
    let encoded = ::tls_codec::VLBytes::new(raw).tls_serialize_detached().ok()?;
    KeyPackageRef::tls_deserialize_exact(&encoded).ok()
}

fn push_bounded(q: &mut VecDeque<String>, v: String) {
    if q.contains(&v) {
        return;
    }
    q.push_back(v);
    while q.len() > DEFERRED_KEEP {
        q.pop_front();
    }
}

/// A candidate branch from a shared fork epoch, for Marmot branch order.
struct Branch {
    depth: u64,
    /// Distinct app senders at each branch epoch.
    witnesses: Vec<usize>,
    tip: Applied,
}

impl Branch {
    fn quorum(&self) -> bool {
        self.witnesses.iter().any(|n| *n >= 2)
    }
    fn effective_depth(&self) -> u64 {
        self.depth + u64::from(self.quorum())
    }
    fn score(&self) -> usize {
        self.witnesses.iter().map(|n| (*n).min(2)).sum()
    }
    /// Whether `self` wins over `other` (convergence.md, "Branch selection").
    fn beats(&self, other: &Branch) -> bool {
        use std::cmp::Ordering::{Equal, Greater, Less};
        let key = |b: &Branch| (b.effective_depth(), b.quorum(), b.score());
        match key(self).cmp(&key(other)) {
            Greater => return true,
            Less => return false,
            Equal => {}
        }
        // privileged before ordinary, then lower committer, then lower digest
        match (self.tip.privileged, other.tip.privileged) {
            (true, false) => return true,
            (false, true) => return false,
            _ => {}
        }
        (self.tip.committer, self.tip.digest) < (other.tip.committer, other.tip.digest)
    }
}
