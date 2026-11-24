//! The data plane: one FIPS endpoint per device (ADR 0002).
//!
//! This is the only module that touches the `fips_core` crate. Everything
//! above it speaks in devices (`nostr::PublicKey`), adverts (signed event
//! JSON) and service datagrams.
//!
//! Membership is admission (ADR 0005): FIPS runs with `configured_only`, and
//! [`Dataplane::set_members`] replaces the configured peer list, so a device
//! that is not a member cannot form a link or a session, and removing a
//! member cuts it off before the call returns.
//!
//! Adverts never touch public relays (ADR 0006): FIPS runs with External
//! peerfinding, the caller carries [`Dataplane::local_advert`] to the other
//! members (inside the Marmot group) and feeds theirs to
//! [`Dataplane::ingest_advert`].

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use fips_core::config::{NostrPeerfindingSource, PeerAddress, PeerConfig, TransportInstances};
use fips_core::{
    Config, FipsEndpoint, FipsEndpointServiceDatagram, FipsEndpointServiceReceiver, PeerIdentity,
    UdpConfig,
};
use futures_util::FutureExt;
use nostr::nips::nip19::ToBech32;
use nostr::prelude::PublicKey;

use crate::identity::Identity;

/// FIPS UDP link MTU. A relayed (transit) path carries service datagrams of
/// at most this minus 110 bytes, and QUIC needs 1200, so FIPS's own default
/// (1280, relayed limit 1170) would break every relayed stream. 1320 leaves
/// 1210 and keeps outer packets at 1348 (IPv4) / 1368 (IPv6) bytes, which
/// fits behind `PPPoE` and most tunnels. Measured in `tests/netrig`; ADR 0003.
pub const FIPS_UDP_MTU: u16 = 1320;

/// Largest service datagram every path (direct or relayed) delivers.
pub const MAX_DATAGRAM: usize = FIPS_UDP_MTU as usize - 110;

/// Nostr kind of a FIPS overlay advert.
pub const ADVERT_KIND: u16 = 37195;

/// Errors from the data plane.
#[derive(Debug, thiserror::Error)]
pub enum DataplaneError {
    #[error("fips: {0}")]
    Fips(String),
    #[error("advert: {0}")]
    Advert(String),
    #[error("config: {0}")]
    Config(String),
}

fn fips_err(e: impl std::fmt::Display) -> DataplaneError {
    DataplaneError::Fips(e.to_string())
}

/// How other devices can reach this one.
#[derive(Debug, Clone, Default)]
pub enum Reachability {
    /// Behind NAT (the usual case for phones and laptops). The advert says
    /// "nat" and FIPS punches holes or relays through a reachable member.
    #[default]
    BehindNat,
    /// Directly reachable (a home server with a port forward, a VPS, public
    /// IPv6). With no `external_addr`, FIPS learns the public IP by STUN and
    /// advertises it with the bound port.
    Public { external_addr: Option<SocketAddr> },
}

/// Data plane settings. `Default` suits a device behind NAT.
#[derive(Debug, Clone)]
pub struct DataplaneConfig {
    /// UDP bind address. Port 0 picks one; a reachable member should use a
    /// fixed, forwarded port.
    pub bind: SocketAddr,
    pub reachability: Reachability,
    /// STUN servers (`stun:host:port`) for learning the public address.
    pub stun_servers: Vec<String>,
    /// Find members on the same LAN by mDNS. FIPS ignores private and
    /// loopback addresses in adverts, so without this two devices on one
    /// home network only meet through NAT traversal.
    pub lan_discovery: bool,
}

impl Default for DataplaneConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::from(([0, 0, 0, 0], 0)),
            reachability: Reachability::BehindNat,
            stun_servers: vec![
                "stun:stun.l.google.com:19302".into(),
                "stun:stun.cloudflare.com:3478".into(),
            ],
            lan_discovery: true,
        }
    }
}

/// A mesh member as the data plane sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub device: PublicKey,
    /// Known UDP addresses to try directly (a home server's static address,
    /// or loopback in tests). Usually empty: addresses come from adverts.
    pub addresses: Vec<SocketAddr>,
}

impl Member {
    #[must_use]
    pub fn new(device: PublicKey) -> Self {
        Self {
            device,
            addresses: Vec::new(),
        }
    }
}

/// Link state for one member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerLink {
    pub device: PublicKey,
    /// A direct FIPS link exists. Traffic may still flow without one, relayed
    /// through another member.
    pub direct: bool,
    /// Remote transport address of the direct link.
    pub remote: Option<String>,
    pub rtt_ms: Option<u64>,
}

/// A datagram received on a service port.
#[derive(Debug)]
pub(crate) struct Datagram {
    pub from: PublicKey,
    pub data: Vec<u8>,
}

/// Receiver for one service port.
pub(crate) struct PortReceiver {
    inner: FipsEndpointServiceReceiver,
    batch: Vec<FipsEndpointServiceDatagram>,
}

impl PortReceiver {
    /// Wait for at least one datagram and append up to `max` to `out`.
    /// `None` when the data plane has shut down.
    pub(crate) async fn recv_batch(&mut self, out: &mut Vec<Datagram>, max: usize) -> Option<()> {
        self.batch.clear();
        self.inner.recv_batch_into(&mut self.batch, max).await?;
        for d in self.batch.drain(..) {
            if let Some(from) = to_device(&d.source_peer) {
                out.push(Datagram {
                    from,
                    data: d.data.as_slice().to_vec(),
                });
            }
        }
        Some(())
    }
}

/// One device's FIPS endpoint.
pub struct Dataplane {
    ep: Arc<FipsEndpoint>,
    device: PublicKey,
    members: RwLock<HashSet<PublicKey>>,
}

impl std::fmt::Debug for Dataplane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dataplane")
            .field("device", &self.device)
            .finish_non_exhaustive()
    }
}

fn to_device(p: &PeerIdentity) -> Option<PublicKey> {
    PublicKey::from_slice(&p.pubkey().serialize()).ok()
}

fn to_peer(device: &PublicKey) -> Option<PeerIdentity> {
    let x = secp256k1::XOnlyPublicKey::from_slice(&device.to_bytes()).ok()?;
    Some(PeerIdentity::from_pubkey(x))
}

fn npub(device: &PublicKey) -> String {
    // ToBech32 for PublicKey is infallible.
    device.to_bech32().unwrap_or_default()
}

impl Dataplane {
    /// Start the endpoint. No member can connect until [`Self::set_members`].
    pub async fn start(identity: &Identity, cfg: DataplaneConfig) -> Result<Self, DataplaneError> {
        if matches!(cfg.reachability, Reachability::Public { .. }) && cfg.bind.port() == 0 {
            // FIPS advertises the bound port; with port 0 it silently
            // advertises nothing.
            return Err(DataplaneError::Config(
                "a reachable device needs a fixed UDP port (bind port is 0)".into(),
            ));
        }
        // ToBech32 for SecretKey is infallible.
        let Ok(nsec) = identity.keys().secret_key().to_bech32();
        let mut config = Config::new();
        config.node.identity.nsec = Some(nsec);
        config.node.control.enabled = false;
        config.node.peer_admission.configured_only = true;
        config.node.discovery.lan.enabled = cfg.lan_discovery;
        config.node.discovery.local.enabled = false;
        let nd = &mut config.node.discovery.nostr;
        nd.enabled = true;
        nd.advertise = true;
        nd.peerfinding_source = NostrPeerfindingSource::External;
        nd.advert_relays = Vec::new();
        nd.stun_servers.clone_from(&cfg.stun_servers);
        let (public, external_addr) = match cfg.reachability {
            Reachability::BehindNat => (false, None),
            Reachability::Public { external_addr } => (true, external_addr.map(|a| a.to_string())),
        };
        config.transports.udp = TransportInstances::Single(UdpConfig {
            bind_addr: Some(cfg.bind.to_string()),
            mtu: Some(FIPS_UDP_MTU),
            advertise_on_nostr: Some(true),
            public: Some(public),
            external_addr,
            ..UdpConfig::default()
        });
        // The bind future is large (about 32 KB); box it off the caller's stack.
        let ep = Box::pin(
            FipsEndpoint::builder()
                .config(config)
                .without_system_tun()
                .bind(),
        )
        .await
        .map_err(fips_err)?;
        Ok(Self {
            ep: Arc::new(ep),
            device: identity.public_key(),
            members: RwLock::new(HashSet::new()),
        })
    }

    /// This device.
    pub fn device(&self) -> PublicKey {
        self.device
    }

    /// Bound UDP addresses (useful when binding port 0).
    pub async fn local_addrs(&self) -> Result<Vec<SocketAddr>, DataplaneError> {
        self.ep.bound_udp_listen_addrs().await.map_err(fips_err)
    }

    /// Replace the member set. Devices not in it (and this device, if
    /// listed) are dropped and can no longer connect; links to removed
    /// members are torn down before this returns.
    pub async fn set_members(&self, members: &[Member]) -> Result<(), DataplaneError> {
        let mut configs = Vec::new();
        let mut set = HashSet::new();
        for m in members.iter().filter(|m| m.device != self.device) {
            if !set.insert(m.device) {
                continue;
            }
            let mut c = PeerConfig::new(npub(&m.device), "udp", "0.0.0.0:1");
            c.addresses.clear(); // the constructor requires one; we may have none
            for a in &m.addresses {
                c = c.with_address(PeerAddress::new("udp", a.to_string()));
            }
            configs.push(c);
        }
        // Shrink the set first so adverts from removed members are refused
        // while FIPS applies the change.
        self.members
            .write()
            .map_err(|_| DataplaneError::Fips("member lock poisoned".into()))?
            .retain(|d| set.contains(d));
        self.ep.update_peers(configs).await.map_err(fips_err)?;
        *self
            .members
            .write()
            .map_err(|_| DataplaneError::Fips("member lock poisoned".into()))? = set;
        Ok(())
    }

    fn is_member(&self, device: &PublicKey) -> bool {
        self.members.read().is_ok_and(|m| m.contains(device))
    }

    /// This device's current signed advert (kind 37195) as event JSON, for
    /// delivery to the other members. `None` until FIPS has something to
    /// advertise (for a public device, until STUN has answered).
    pub async fn local_advert(&self) -> Result<Option<String>, DataplaneError> {
        use fips_nostr::JsonUtil;
        Ok(self
            .ep
            .local_nostr_discovery_advert_event()
            .await
            .map_err(fips_err)?
            .map(|e| e.as_json()))
    }

    /// Feed a member's advert (event JSON). Refuses anything that is not a
    /// kind 37195 event signed by a current member. Returns whether FIPS
    /// accepted it (an older or duplicate advert is not an error).
    pub async fn ingest_advert(&self, json: &str) -> Result<bool, DataplaneError> {
        use fips_nostr::JsonUtil;
        let event = fips_nostr::Event::from_json(json)
            .map_err(|e| DataplaneError::Advert(e.to_string()))?;
        if event.kind.as_u16() != ADVERT_KIND {
            return Err(DataplaneError::Advert(format!(
                "kind {} is not an advert",
                event.kind.as_u16()
            )));
        }
        event
            .verify()
            .map_err(|e| DataplaneError::Advert(e.to_string()))?;
        let author = PublicKey::from_slice(&event.pubkey.to_bytes())
            .map_err(|e| DataplaneError::Advert(e.to_string()))?;
        if !self.is_member(&author) {
            return Err(DataplaneError::Advert("author is not a member".into()));
        }
        self.ep.ingest_nostr_event(event).await.map_err(fips_err)
    }

    /// Direct-link state for every member FIPS knows about.
    pub async fn peers(&self) -> Result<Vec<PeerLink>, DataplaneError> {
        let peers = self.ep.peers().await.map_err(fips_err)?;
        Ok(peers
            .into_iter()
            .filter_map(|p| {
                let device = PublicKey::parse(&p.npub).ok()?;
                Some(PeerLink {
                    device,
                    direct: p.connected,
                    remote: p.transport_addr,
                    rtt_ms: p.srtt_ms,
                })
            })
            .collect())
    }

    /// Tell FIPS the network changed (Wi-Fi to cellular, sleep and wake):
    /// rebind sockets and re-probe paths to every member.
    pub async fn network_changed(&self) -> Result<(), DataplaneError> {
        self.ep
            .rebind_network_transports(None)
            .await
            .map_err(fips_err)?;
        let peers: Vec<PeerIdentity> = self
            .members
            .read()
            .map_err(|_| DataplaneError::Fips("member lock poisoned".into()))?
            .iter()
            .filter_map(to_peer)
            .collect();
        self.ep.refresh_peer_paths(peers).await.map_err(fips_err)?;
        Ok(())
    }

    /// Stop the endpoint.
    pub async fn shutdown(&self) -> Result<(), DataplaneError> {
        self.ep.shutdown().await.map_err(fips_err)
    }

    /// Register a service port.
    pub(crate) async fn bind_port(&self, port: u16) -> Result<PortReceiver, DataplaneError> {
        Ok(PortReceiver {
            inner: self
                .ep
                .register_service_receiver(port)
                .await
                .map_err(fips_err)?,
            batch: Vec::new(),
        })
    }

    /// Send one datagram without waiting. `false` if it could not be queued
    /// (no session yet, too large, shut down): callers treat that as loss.
    pub(crate) fn send_now(&self, to: &PublicKey, port: u16, data: Vec<u8>) -> bool {
        let Some(peer) = to_peer(to) else {
            return false;
        };
        // send_datagram has no await points inside, so it completes on the
        // first poll.
        matches!(
            self.ep.send_datagram(peer, port, port, data).now_or_never(),
            Some(Ok(()))
        )
    }
}
