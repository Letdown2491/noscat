//! The data plane: a Noise-XK session over one UDP socket pair.
//!
//! MVP topology ("netcat mode"): `serve` binds a UDP port, advertises its
//! candidates (LAN + STUN reflexive) over Nostr relays, and pipes the first
//! peer that completes the handshake to its stdio. `pipe` gathers the target's
//! candidates from the advert and from a NIP-59 gift-wrapped traversal
//! exchange ([`crate::traversal`]), punches UDP holes toward them, handshakes,
//! and pipes its stdio into the tunnel. One datagram = one Noise message.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nostr::prelude::*;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};

use crate::advert::{Endpoint, Transport};
use crate::identity::Identity;
use crate::noise::{self, NoiseError};

/// How long `pipe` waits for the target's advert to show up on the relays.
const ADVERT_WAIT: Duration = Duration::from_secs(30);
/// Total budget for punching + handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);
/// One punch/handshake round: blast candidates, then listen for a reply.
const ROUND: Duration = Duration::from_secs(4);
/// UDP read buffer: Noise caps messages well below the 65535 IP limit.
const BUF: usize = 65535;
/// Punch marker: junk to the peer, ignorable noise to us.
const PUNCH: &[u8] = b"noscat/punch/v1";

#[derive(Debug, thiserror::Error)]
pub enum TunnelError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Noise(#[from] NoiseError),
    #[error(transparent)]
    Snow(#[from] snow::Error),
    #[error(transparent)]
    Relay(#[from] crate::relay::RelayError),
    #[error(transparent)]
    Traversal(#[from] crate::traversal::TraversalError),
    #[error("no advert for {0} found on the relays within {1:?}")]
    AdvertTimeout(String, Duration),
    #[error("handshake timed out (NAT or firewall is not letting the peers through)")]
    HandshakeTimeout,
    #[error("peer did not complete the handshake")]
    NoHandshake,
    #[error("advert does not carry a usable noise key or endpoint")]
    BadAdvert,
}

/// The identity's Noise keypair (public, private), derived from its secret —
/// see [`crate::noise`] for why this is a derivation, not the raw key.
pub fn noise_keypair(identity: &Identity) -> Result<([u8; 32], [u8; 32]), TunnelError> {
    let secret: [u8; 32] = identity
        .keys()
        .secret_key()
        .as_secret_bytes()
        .try_into()
        .map_err(|_| NoiseError::KeyLen)?;
    let privkey = noise::noise_static_from_identity(&secret)?;
    Ok((noise::noise_public(&privkey), privkey))
}

/// Candidate endpoints for a socket: the concrete LAN/interface address plus
/// the STUN server-reflexive mapping, deduplicated (LAN first — it is usually
/// the better path when both peers share a network).
async fn discover_endpoints(socket: &UdpSocket) -> Result<Vec<Endpoint>, TunnelError> {
    let local = socket.local_addr()?;
    let mut addrs: Vec<SocketAddr> = Vec::new();
    if !local.ip().is_unspecified() {
        addrs.push(local);
    } else {
        // Resolve the concrete interface IP the OS would pick to leave the box
        // (routing probe; no packets are sent).
        if let Ok(probe) = UdpSocket::bind(if local.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).await
        {
            if probe.connect("8.8.8.8:80").await.is_ok() {
                if let Ok(src) = probe.local_addr() {
                    if !src.ip().is_unspecified() {
                        addrs.push(SocketAddr::new(src.ip(), local.port()));
                    }
                }
            }
        }
    }
    match crate::stun::discover(socket).await {
        Ok(reflexive) => addrs.push(reflexive),
        Err(e) => tracing::warn!("STUN discovery failed: {e}; advert will carry LAN only"),
    }
    addrs.dedup();
    Ok(addrs
        .into_iter()
        .map(|addr| Endpoint {
            transport: Transport::Udp,
            addr: addr.to_string(),
        })
        .collect())
}

/// Candidates as dialable addresses.
fn parse_endpoints(endpoints: &[Endpoint]) -> Vec<SocketAddr> {
    endpoints
        .iter()
        .filter_map(|e| e.addr.parse().ok())
        .collect()
}

/// Keep blasting punch markers at the candidate list. To everyone else this is
/// junk; to the peer it opens (and keeps open) the NAT mapping we handshake on.
async fn punch_loop(socket: Arc<UdpSocket>, candidates: Arc<Mutex<Vec<SocketAddr>>>) {
    loop {
        let targets = candidates.lock().expect("candidates lock").clone();
        for addr in targets {
            let _ = socket.send_to(PUNCH, addr).await;
        }
        sleep(Duration::from_secs(2)).await;
    }
}

/// Bridge stdio over the encrypted session until both sides close.
///
/// Local stdin EOF sends a FIN (an authenticated empty Noise payload); a FIN
/// from the peer ends the receive side; the session ends when both happened.
async fn pump<R, W>(
    mut reader: R,
    mut writer: W,
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    mut session: snow::TransportState,
) -> Result<(), TunnelError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut plain = [0u8; BUF];
    let mut wire = [0u8; BUF];

    let mut stdin_open = true;
    loop {
        tokio::select! {
            n = reader.read(&mut plain), if stdin_open => {
                match n {
                    Ok(0) => {
                        let n = session.write_message(b"", &mut wire)?;
                        socket.send_to(&wire[..n], peer).await?;
                        stdin_open = false;
                    }
                    Ok(n) => {
                        let n = session.write_message(&plain[..n], &mut wire)?;
                        socket.send_to(&wire[..n], peer).await?;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            r = socket.recv_from(&mut wire) => {
                let (n, from) = r?;
                if from != peer {
                    tracing::debug!(%from, "ignoring packet from stranger");
                    continue;
                }
                match session.read_message(&wire[..n], &mut plain) {
                    Ok(0) if !stdin_open => return Ok(()), // mutual close
                    Ok(0) => {}                            // peer FIN; keep draining
                    Ok(m) => {
                        writer.write_all(&plain[..m]).await?;
                        writer.flush().await?;
                    }
                    Err(snow::Error::Decrypt) => {
                        tracing::warn!("dropping undecryptable datagram");
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        }
    }
}

/// Serve one tunnel: bind, advertise candidates, exchange traversal signaling,
/// handshake with the first peer, then bridge stdio over the encrypted
/// channel. Resolves when the session closes, reporting the peer's identity.
///
/// With a `psk` (the tailnet's epoch secret), the handshake is bound to the
/// group: only members of the same tailnet can complete it.
pub async fn serve(
    identity: &Identity,
    listen: SocketAddr,
    relays: &[String],
    ttl_secs: u64,
    psk: Option<&[u8; 32]>,
) -> Result<String, TunnelError> {
    let (noise_pub, noise_priv) = noise_keypair(identity)?;

    let socket = Arc::new(UdpSocket::bind(listen).await?);
    let local = socket.local_addr()?;
    let mut hs = noise::responder(&noise_priv, psk)?;

    let endpoints = discover_endpoints(&socket).await?;
    crate::relay::publish_advert(identity, endpoints.clone(), noise_pub, ttl_secs, relays).await?;
    eprintln!(
        "# 🐈 serving as {} on udp/{local} (candidates: {}) — waiting for a peer… (Ctrl-C to quit)",
        identity.npub(),
        endpoints
            .iter()
            .map(|e| e.addr.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );

    // Traversal signaling: when the peer gift-wraps us its live candidates,
    // record them (so we punch toward it) and answer with ours, so both NAT
    // mappings get opened from the inside.
    let (tx, mut rx) = mpsc::channel::<(PublicKey, crate::traversal::TraversalPayload)>(16);
    let watch = tokio::spawn(crate::traversal::watch_traversal(
        identity.clone(),
        relays.to_vec(),
        tx,
    ));
    let peer_candidates: Arc<Mutex<Vec<SocketAddr>>> = Arc::new(Mutex::new(Vec::new()));
    let reply_candidates = peer_candidates.clone();
    let reply_identity = identity.clone();
    let reply_noise = noise_pub;
    let reply_endpoints = endpoints.clone();
    let reply_relays: Vec<String> = relays.to_vec();
    let replier = tokio::spawn(async move {
        while let Some((sender, payload)) = rx.recv().await {
            tracing::info!(%sender, ?payload.endpoints, "traversal request received");
            *reply_candidates.lock().expect("candidates lock") =
                parse_endpoints(&payload.endpoints);
            let _ = crate::traversal::send_traversal(
                &reply_identity,
                sender,
                reply_noise,
                reply_endpoints.clone(),
                &reply_relays,
            )
            .await;
        }
    });
    let puncher = tokio::spawn(punch_loop(socket.clone(), peer_candidates));

    // First valid handshake datagram is XK message 1 (-> e); punches and
    // strangers' noise are dropped along the way (snow restores its state on
    // every failed read).
    let mut wire = [0u8; BUF];
    let mut plain = [0u8; BUF];
    let peer = loop {
        let (n, from) = socket.recv_from(&mut wire).await?;
        match hs.read_message(&wire[..n], &mut plain) {
            Ok(_) => break from,
            Err(e) => tracing::debug!(%from, %e, "not a handshake opener; ignoring"),
        }
    };

    // <- e, ee, s, er
    let n = hs.write_message(b"", &mut wire)?;
    socket.send_to(&wire[..n], peer).await?;

    // -> s, se
    match timeout(HANDSHAKE_TIMEOUT, socket.recv_from(&mut wire)).await {
        Ok(Ok((n, from))) if from == peer => {
            hs.read_message(&wire[..n], &mut plain)?;
        }
        Ok(Ok((_, from))) => {
            tracing::debug!(%from, "handshake finished with a different source address");
            return Err(TunnelError::NoHandshake);
        }
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Err(TunnelError::HandshakeTimeout),
    }

    let initiator_noise: [u8; 32] = hs
        .get_remote_static()
        .ok_or(TunnelError::NoHandshake)?
        .try_into()
        .map_err(|_| TunnelError::NoHandshake)?;
    let session = noise::into_transport(hs)?;

    // The initiator's Noise key binds to its npub through its signed advert.
    let who = match crate::relay::fetch_advert_for(relays, Some(initiator_noise), None).await? {
        Some(advert) => advert.npub.to_string(),
        None => format!("noise key {}", hex::encode(initiator_noise)),
    };
    eprintln!("# 🔗 tunnel up with {who} — bridging stdio");

    puncher.abort();
    replier.abort();
    watch.abort();
    pump(tokio::io::stdin(), tokio::io::stdout(), socket, peer, session).await?;
    Ok(who)
}

/// Dial a peer by npub: gather candidates (advert + gift-wrapped traversal
/// exchange), punch UDP holes, handshake, and bridge stdio. With a `psk` (the
/// tailnet's epoch secret), only members of the same tailnet can complete the
/// handshake.
pub async fn pipe(
    identity: &Identity,
    target: &str,
    relays: &[String],
    psk: Option<&[u8; 32]>,
) -> Result<(), TunnelError> {
    let target_pubkey = PublicKey::parse(target).map_err(|_| TunnelError::BadAdvert)?;
    let (noise_pub, noise_priv) = noise_keypair(identity)?;

    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    let my_endpoints = discover_endpoints(&socket).await?;
    eprintln!(
        "# 🐈 dialing {target} (my candidates: {})…",
        my_endpoints
            .iter()
            .map(|e| e.addr.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );

    // The advert carries the server's static candidates. Each fetch waits its
    // own budget, so two misses exhaust ADVERT_WAIT.
    let advert = loop {
        if let Some(a) = crate::relay::fetch_advert_for(relays, None, Some(target_pubkey)).await? {
            break a;
        }
        sleep(ADVERT_WAIT).await; // relays may have been slow; try once more
        if let Some(a) = crate::relay::fetch_advert_for(relays, None, Some(target_pubkey)).await? {
            break a;
        }
        return Err(TunnelError::AdvertTimeout(target.to_string(), ADVERT_WAIT));
    };
    let mut candidates: Vec<SocketAddr> = parse_endpoints(&advert.endpoints);
    tracing::info!(?candidates, "advert candidates");

    // Tell the peer where we are reachable so it can punch back at us, then
    // listen for its reply for any candidate the advert could not carry
    // (e.g. a freshly opened reflexive mapping).
    crate::traversal::send_traversal(identity, target_pubkey, noise_pub, my_endpoints, relays)
        .await?;
    let (tx, mut rx) = mpsc::channel::<(PublicKey, crate::traversal::TraversalPayload)>(16);
    let watch = tokio::spawn(crate::traversal::watch_traversal(
        identity.clone(),
        relays.to_vec(),
        tx,
    ));

    // Punch + handshake rounds: blast msg1 at every known candidate, listen
    // for msg2 from anywhere (its source is the mapping that got us through).
    // Between rounds, fold in candidates the peer signaled gift-wrapped.
    let mut hs = noise::initiator(&noise_priv, &advert.noise_pub, psk)?;
    let mut wire = [0u8; BUF];
    let mut plain = [0u8; BUF];
    let n = hs.write_message(b"", &mut wire)?;
    let msg1: Vec<u8> = wire[..n].to_vec();

    let deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;
    let peer = loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(TunnelError::HandshakeTimeout);
        }
        for addr in &candidates {
            let _ = socket.send_to(&msg1, addr).await;
        }
        match timeout(ROUND, socket.recv_from(&mut wire)).await {
            Ok(Ok((n, from))) => {
                if wire[..n.min(PUNCH.len())] == *PUNCH {
                    continue; // our own punch echoed back? ignore and keep waiting
                }
                match hs.read_message(&wire[..n], &mut plain) {
                    Ok(_) => break from,
                    Err(e) => tracing::debug!(%from, %e, "stray datagram during handshake"),
                }
            }
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {}
        }
        while let Ok((sender, payload)) = rx.try_recv() {
            if sender != target_pubkey {
                continue; // only the dialed peer's signals count
            }
            for addr in parse_endpoints(&payload.endpoints) {
                if !candidates.contains(&addr) {
                    tracing::info!(%addr, "learned candidate via traversal");
                    candidates.push(addr);
                }
            }
        }
    };
    watch.abort();

    // -> s, se
    let n = hs.write_message(b"", &mut wire)?;
    socket.send_to(&wire[..n], peer).await?;
    let session = noise::into_transport(hs)?;

    eprintln!("# 🔗 tunnel up with {target} at udp/{peer} — bridging stdio");
    pump(tokio::io::stdin(), tokio::io::stdout(), socket, peer, session).await
}
