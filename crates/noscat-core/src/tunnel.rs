//! The data plane: a Noise-XK session over one UDP socket pair.
//!
//! MVP topology ("netcat mode"): `serve` binds a UDP port, advertises its
//! candidates (LAN + STUN reflexive) over Nostr relays, and pipes the first
//! peer that completes the handshake to its stdio. `pipe` gathers the target's
//! candidates from the advert and from a NIP-59 gift-wrapped traversal
//! exchange ([`crate::traversal`]), punches UDP holes toward them, handshakes,
//! and pipes its stdio into the tunnel. One datagram = one Noise message.
//!
//! File transfer (`send_file`/`receive_file`) rides the same tunnels: a tiny
//! tagged protocol — JSON header, ACK'd 16 KiB chunks, FIN — so a clean
//! return means the whole file was received and flushed. The ACK layer exists
//! because blasting back-to-back datagrams overflows kernel socket buffers;
//! without it the tail of every large transfer would be silently lost.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nostr::prelude::*;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout, timeout_at};

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
/// File-transfer chunk: comfortably inside one Noise message + UDP datagram.
const CHUNK: usize = 16 * 1024;
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
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("no advert for {0} found on the relays within {1:?}")]
    AdvertTimeout(String, Duration),
    #[error("handshake timed out (NAT or firewall is not letting the peers through)")]
    HandshakeTimeout,
    #[error("peer did not complete the handshake")]
    NoHandshake,
    #[error("advert does not carry a usable noise key or endpoint")]
    BadAdvert,
    #[error("refusing unsafe transfer path {0:?}")]
    UnsafePath(PathBuf),
    #[error("transfer stalled: the path keeps dropping data or the peer stopped responding")]
    TransferStalled,
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

/// An established, tailnet-scoped (when a PSK was used) session with a peer,
/// from either side of the handshake. `finish` aborts the signaling tasks and
/// hands back the transport parts for whichever pump consumes them.
struct Session {
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    session: snow::TransportState,
    who: String,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Session {
    /// Abort signaling tasks and deconstruct into the transport parts.
    fn finish(mut self) -> (Arc<UdpSocket>, SocketAddr, snow::TransportState, String) {
        for task in self.tasks.drain(..) {
            task.abort();
        }
        (self.socket, self.peer, self.session, self.who)
    }
}

/// Await the first valid handshake opener (XK msg 1) and finish the responder
/// side. Punches and strangers' noise are dropped along the way (snow restores
/// its state on every failed read).
async fn accept_handshake(
    mut hs: snow::HandshakeState,
    socket: &Arc<UdpSocket>,
    relays: &[String],
) -> Result<Session, TunnelError> {
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

    Ok(Session {
        socket: socket.clone(),
        peer,
        session,
        who,
        tasks: Vec::new(),
    })
}

/// Serve one session: bind, advertise candidates, watch for traversal
/// signaling, and return when the first peer completes the handshake.
///
/// With a `psk` (the tailnet's epoch secret), the handshake is bound to the
/// group: only members of the same tailnet can complete it.
async fn serve_session(
    identity: &Identity,
    listen: SocketAddr,
    relays: &[String],
    ttl_secs: u64,
    psk: Option<&[u8; 32]>,
) -> Result<Session, TunnelError> {
    let (noise_pub, noise_priv) = noise_keypair(identity)?;

    let socket = Arc::new(UdpSocket::bind(listen).await?);
    let local = socket.local_addr()?;

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
    let watch_identity = identity.clone();
    let watch_relays = relays.to_vec();
    let watch = tokio::spawn(async move {
        let _ = crate::traversal::watch_traversal(watch_identity, watch_relays, tx).await;
    });
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

    let hs = noise::responder(&noise_priv, psk)?;
    let mut session = accept_handshake(hs, &socket, relays).await?;
    session.tasks = vec![watch, replier, puncher];
    Ok(session)
}

/// Dial a peer by npub: gather candidates (advert + gift-wrapped traversal
/// exchange), punch UDP holes, and complete the handshake. With a `psk` (the
/// tailnet's epoch secret), only members of the same tailnet can connect.
async fn dial_session(
    identity: &Identity,
    target: &str,
    relays: &[String],
    psk: Option<&[u8; 32]>,
) -> Result<Session, TunnelError> {
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
    let watch_identity = identity.clone();
    let watch_relays = relays.to_vec();
    let watch = tokio::spawn(async move {
        let _ = crate::traversal::watch_traversal(watch_identity, watch_relays, tx).await;
    });

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

    Ok(Session {
        socket,
        peer,
        session,
        who: target.to_string(),
        tasks: Vec::new(),
    })
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

/// Serve one tunnel and bridge stdio over it.
pub async fn serve(
    identity: &Identity,
    listen: SocketAddr,
    relays: &[String],
    ttl_secs: u64,
    psk: Option<&[u8; 32]>,
) -> Result<String, TunnelError> {
    let session = serve_session(identity, listen, relays, ttl_secs, psk).await?;
    let (socket, peer, hs, who) = session.finish();
    eprintln!("# 🔗 tunnel up with {who} — bridging stdio");
    pump(tokio::io::stdin(), tokio::io::stdout(), socket, peer, hs).await?;
    Ok(who)
}

/// Dial a peer by npub and bridge stdio over the tunnel.
pub async fn pipe(
    identity: &Identity,
    target: &str,
    relays: &[String],
    psk: Option<&[u8; 32]>,
) -> Result<(), TunnelError> {
    let session = dial_session(identity, target, relays, psk).await?;
    let (socket, peer, hs, _) = session.finish();
    eprintln!("# 🔗 tunnel up with {target} at udp/{peer} — bridging stdio");
    pump(tokio::io::stdin(), tokio::io::stdout(), socket, peer, hs).await
}

/// Wire format of a transfer: a JSON header naming the file, then raw chunks.
#[derive(serde::Serialize, serde::Deserialize)]
struct TransferHeader {
    name: String,
    len: u64,
}

/// Transfer message tags: first byte of every plaintext payload.
const TAG_HEADER: u8 = 1;
const TAG_CHUNK: u8 = 2;
const TAG_ACK: u8 = 3;
const TAG_FIN: u8 = 4;
/// Per-chunk ACK wait before retransmitting.
const ACK_TIMEOUT: Duration = Duration::from_secs(1);
/// Retransmission budget per chunk before declaring the path too lossy.
const MAX_RETRIES: u32 = 60;
/// Receiver-side inactivity bound: the sender stopped answering.
const IDLE_TIMEOUT: Duration = Duration::from_secs(90);

/// One encrypted send + the ack round-trip for it. `payload` carries the tag
/// and (for chunks) sequence number; `want_ack` is the ack we are waiting on
/// (`None` for header/fin, which complete on *any* authenticated reply).
async fn send_and_ack(
    socket: &UdpSocket,
    peer: SocketAddr,
    hs: &mut snow::TransportState,
    payload: &[u8],
    want_ack: Option<u32>,
    plain: &mut [u8],
    wire: &mut [u8],
) -> Result<(), TunnelError> {
    for _ in 0..MAX_RETRIES {
        let n = hs.write_message(payload, wire)?;
        socket.send_to(&wire[..n], peer).await?;
        let wait = tokio::time::Instant::now() + ACK_TIMEOUT;
        loop {
            let recv = timeout_at(wait, socket.recv_from(wire)).await;
            match recv {
                Err(_) => break, // ack timeout -> retransmit
                Ok(Err(e)) => return Err(e.into()),
                Ok(Ok((n, from))) => {
                    if from != peer {
                        continue;
                    }
                    match hs.read_message(&wire[..n], plain) {
                        // Any authenticated reply completes header/fin waits;
                        // a chunk ack completes only on a matching seq; a FIN
                        // means the receiver is already done — complete too.
                        Ok(m) if m >= 5 && plain[0] == TAG_ACK => {
                            let seq = u32::from_be_bytes(plain[1..5].try_into().unwrap());
                            match want_ack {
                                Some(w) if seq >= w => return Ok(()),
                                Some(_) => continue, // older ack: keep waiting
                                None => return Ok(()),
                            }
                        }
                        Ok(m) if m >= 1 && plain[0] == TAG_FIN => return Ok(()),
                        Ok(_) => {} // unexpected payload; keep waiting
                        Err(snow::Error::Decrypt) => {}
                        Err(e) => return Err(e.into()),
                    }
                }
            }
        }
    }
    Err(TunnelError::TransferStalled)
}

/// Receive one authenticated datagram into `plain`, skipping strangers,
/// undecryptables, and empties. `Err` maps straight through.
async fn recv_plain(
    socket: &UdpSocket,
    peer: SocketAddr,
    hs: &mut snow::TransportState,
    plain: &mut [u8],
    wire: &mut [u8],
) -> Result<usize, TunnelError> {
    let deadline = tokio::time::Instant::now() + IDLE_TIMEOUT;
    loop {
        let (n, from) = timeout_at(deadline, socket.recv_from(wire))
            .await
            .map_err(|_| TunnelError::TransferStalled)??;
        if from != peer {
            continue;
        }
        match hs.read_message(&wire[..n], plain) {
            Ok(0) => continue,
            Ok(m) => return Ok(m),
            Err(snow::Error::Decrypt) => {}
            Err(e) => return Err(e.into()),
        }
    }
}

/// Strip any path components from a peer-supplied filename.
fn sanitize_name(name: &str) -> Result<PathBuf, TunnelError> {
    let name = Path::new(name)
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| TunnelError::UnsafePath(PathBuf::from(name)))?;
    if name.is_empty() || name == "." || name == ".." {
        return Err(TunnelError::UnsafePath(PathBuf::from(name)));
    }
    Ok(PathBuf::from(name))
}

/// Send a file over a tunnel to `target`.
///
/// Protocol (every message Noise-encrypted): TAG_HEADER (JSON name+len) ->
/// TAG_CHUNK (seq + data), each retransmitted until ACKed -> TAG_FIN, held
/// until the receiver confirms the file is on disk. A clean return means the
/// receiving side wrote and flushed the entire file.
pub async fn send_file(
    identity: &Identity,
    target: &str,
    path: &Path,
    relays: &[String],
    psk: Option<&[u8; 32]>,
) -> Result<(), TunnelError> {
    let mut file = tokio::fs::File::open(path).await?;
    let len = file.metadata().await?.len();
    let name = sanitize_name(
        path.file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| TunnelError::UnsafePath(path.to_path_buf()))?
            .as_ref(),
    )?;

    let session = dial_session(identity, target, relays, psk).await?;
    let (socket, peer, mut hs, _) = session.finish();
    eprintln!(
        "# 🔗 tunnel up with {target} at udp/{peer} — sending {} ({len} bytes)",
        name.display()
    );

    let mut wire = [0u8; BUF];
    let mut plain = [0u8; BUF];

    // -> header; the receiver acks it, so we know it is listening.
    let mut msg = vec![TAG_HEADER];
    msg.extend(serde_json::to_string(&TransferHeader {
        name: name.to_string_lossy().to_string(),
        len,
    })?.into_bytes());
    send_and_ack(&socket, peer, &mut hs, &msg, None, &mut plain, &mut wire).await?;

    // -> chunks, each held until its ack (or a later ack) arrives.
    let total_chunks = len.div_ceil(CHUNK as u64) as u32;
    let mut buf = [0u8; CHUNK];
    for seq in 0..total_chunks {
        let offset = (seq as u64) * (CHUNK as u64);
        let want = CHUNK.min((len - offset) as usize);
        let m = file.read(&mut buf[..want]).await?;
        let mut msg = Vec::with_capacity(5 + m);
        msg.push(TAG_CHUNK);
        msg.extend_from_slice(&seq.to_be_bytes());
        msg.extend_from_slice(&buf[..m]);
        send_and_ack(&socket, peer, &mut hs, &msg, Some(seq), &mut plain, &mut wire).await?;
    }

    // -> FIN; the receiver's reply means the whole file is on disk.
    send_and_ack(&socket, peer, &mut hs, &[TAG_FIN], None, &mut plain, &mut wire).await?;
    eprintln!("# ✅ {} received by peer ({len} bytes sent)", name.display());
    Ok(())
}

/// Receive one file over a tunnel: serve until a peer completes the
/// handshake, read the transfer header, and stream the bytes into
/// `<out_dir>/<name>`. Resolves when the transfer completes, reporting
/// (peer, path).
pub async fn receive_file(
    identity: &Identity,
    listen: SocketAddr,
    relays: &[String],
    ttl_secs: u64,
    out_dir: &Path,
    psk: Option<&[u8; 32]>,
) -> Result<(String, PathBuf), TunnelError> {
    let session = serve_session(identity, listen, relays, ttl_secs, psk).await?;
    let (socket, peer, mut hs, who) = session.finish();

    let mut wire = [0u8; BUF];
    let mut plain = [0u8; BUF];

    async fn send_ack(
        socket: &UdpSocket,
        peer: SocketAddr,
        hs: &mut snow::TransportState,
        seq: u32,
        wire: &mut [u8],
    ) -> Result<(), TunnelError> {
        let mut msg = vec![TAG_ACK];
        msg.extend_from_slice(&seq.to_be_bytes());
        let n = hs.write_message(&msg, wire)?;
        socket.send_to(&wire[..n], peer).await?;
        Ok(())
    }

    // <- header; ack it so the sender can start streaming.
    let m = recv_plain(&socket, peer, &mut hs, &mut plain, &mut wire).await?;
    if m < 1 || plain[0] != TAG_HEADER {
        return Err(TunnelError::BadAdvert);
    }
    let header: TransferHeader = serde_json::from_slice(&plain[1..m])?;
    let name = sanitize_name(&header.name)?;
    let out_path = out_dir.join(&name);
    eprintln!("# 📥 {who} is sending {} ({} bytes)…", name.display(), header.len);
    send_ack(&socket, peer, &mut hs, u32::MAX, &mut wire).await?;

    let mut file = tokio::fs::File::create(&out_path).await?;
    let mut expected: u32 = 0;
    let mut received = 0u64;
    'receive: loop {
        let m = recv_plain(&socket, peer, &mut hs, &mut plain, &mut wire).await?;
        match plain[0] {
            TAG_CHUNK if m >= 5 => {
                let seq = u32::from_be_bytes(plain[1..5].try_into().unwrap());
                if seq == expected {
                    file.write_all(&plain[5..m]).await?;
                    received += (m - 5) as u64;
                    expected += 1;
                }
                send_ack(&socket, peer, &mut hs, seq, &mut wire).await?;
                if header.len > 0 && received >= header.len {
                    break 'receive;
                }
            }
            TAG_FIN => break 'receive,
            _ => {}
        }
    }
    file.flush().await?;
    drop(file);

    // -> FIN, then linger for the sender's FIN (it retransmits until it hears
    // from us), so the sender returns only after the file is truly on disk.
    let n = hs.write_message(&[TAG_FIN], &mut wire)?;
    socket.send_to(&wire[..n], peer).await?;
    loop {
        match recv_plain(&socket, peer, &mut hs, &mut plain, &mut wire).await {
            Ok(m) if m >= 1 && plain[0] == TAG_FIN => break,
            Ok(_) => {
                let n = hs.write_message(&[TAG_FIN], &mut wire)?;
                socket.send_to(&wire[..n], peer).await?;
            }
            Err(TunnelError::TransferStalled) => break, // sender gone; we are done
            Err(e) => return Err(e),
        }
    }

    if received != header.len {
        eprintln!(
            "# ⚠️  transfer incomplete: {received}/{} bytes (path too lossy)",
            header.len
        );
    } else {
        eprintln!("# ✅ {who} -> {out_path:?} ({received} bytes)");
    }
    Ok((who, out_path))
}

