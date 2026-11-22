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
//! tagged protocol — JSON header, ACK'd MTU-sized chunks, FIN — so a clean
//! return means the whole file was received, flushed, and sha256-verified.
//! The ACK layer exists because blasting back-to-back datagrams overflows
//! kernel socket buffers; without it the tail of every large transfer would
//! be silently lost. An interrupted transfer leaves a partial file plus a
//! meta sidecar; the next attempt resumes from the receiver's acked point.

use std::collections::{HashMap, VecDeque};
use std::io::SeekFrom;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nostr::prelude::*;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt};
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
/// Cadence of the listener's punch loop.
const PUNCH_EVERY: Duration = Duration::from_secs(2);
/// UDP read buffer: Noise caps messages well below the 65535 IP limit.
const BUF: usize = 65535;
/// Largest payload a single Noise message can carry, so it still fits in one
/// UDP datagram: 65507 = IP(20) + UDP(8) max datagram, minus the 16-byte
/// Poly1305 tag. A full 64 KiB TCP read would blow both snow's message cap
/// and the kernel's, so the pump reads at most this much per turn.
const MAX_PAYLOAD: usize = 65_507 - 16;
/// File-transfer chunk: MTU-sized so a frame never fragments into multiple
/// IP packets — one datagram, one loss unit. Throughput comes from the
/// sliding window (many small in-flight frames), not from huge datagrams.
const CHUNK: usize = 1200;
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

/// Fat kernel buffers for a test socket (production sockets get theirs in
/// `bind_udp` via socket2): defaults (~212 KB) are smaller than one window
/// burst (32 × 16 KiB), so bursts would overflow the peer's receive queue
/// and every burst would need replay rounds to land.
#[cfg_attr(not(test), allow(dead_code))]
#[cfg(unix)]
fn tune_buffers(sock: &std::net::UdpSocket) {
    use std::os::fd::AsRawFd;

    // Best effort: if the sysctl caps these, we still work — just burstier.
    let buf: libc::c_int = 4 * 1024 * 1024;
    unsafe {
        for opt in [libc::SO_SNDBUF, libc::SO_RCVBUF] {
            libc::setsockopt(
                sock.as_raw_fd(),
                libc::SOL_SOCKET,
                opt,
                &buf as *const libc::c_int as *const libc::c_void,
                std::mem::size_of_val(&buf) as libc::socklen_t,
            );
        }
    }
}

#[cfg(not(unix))]
#[cfg_attr(not(test), allow(dead_code))]
fn tune_buffers(_sock: &std::net::UdpSocket) {}

/// Bind a UDP socket with fat kernel buffers.
fn bind_udp(addr: SocketAddr) -> Result<Arc<UdpSocket>, TunnelError> {
    let sock = std::net::UdpSocket::bind(addr)?;
    tune_buffers(&sock);
    sock.set_nonblocking(true)?;
    Ok(Arc::new(UdpSocket::from_std(sock)?))
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
        sleep(PUNCH_EVERY).await;
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
    /// Background lookup of the peer's npub (relay round-trip). Display only —
    /// the data path must never wait on it.
    who_lookup: Option<tokio::task::JoinHandle<String>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Session {
    /// Abort signaling tasks and deconstruct into the transport parts. The
    /// peer name resolves to the advert lookup only if it already finished —
    /// awaiting it here would stall the data path by up to FETCH_WAIT.
    async fn finish(mut self) -> (Arc<UdpSocket>, SocketAddr, snow::TransportState, String) {
        for task in self.tasks.drain(..) {
            task.abort();
        }
        let who = match self.who_lookup.take() {
            Some(h) if h.is_finished() => h.await.unwrap_or_else(|_| self.who.clone()),
            Some(h) => {
                h.abort();
                self.who
            }
            None => self.who,
        };
        (self.socket, self.peer, self.session, who)
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

    // -> s, se. A punch marker can land in this slot (the initiator's punch
    // loop is still running) — snow restores its state on failed reads, so
    // junk is skipped until the real msg3 arrives.
    let deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;
    loop {
        let (n, from) = match timeout_at(deadline, socket.recv_from(&mut wire)).await {
            Err(_) => return Err(TunnelError::HandshakeTimeout),
            Ok(r) => r?,
        };
        if from != peer {
            continue;
        }
        match hs.read_message(&wire[..n], &mut plain) {
            Ok(_) => break,
            Err(snow::Error::Decrypt) => continue,
            Err(e) => return Err(e.into()),
        }
    }

    let initiator_noise: [u8; 32] = hs
        .get_remote_static()
        .ok_or(TunnelError::NoHandshake)?
        .try_into()
        .map_err(|_| TunnelError::NoHandshake)?;
    let session = noise::into_transport(hs)?;

    // The initiator's Noise key binds to its npub through its signed advert.
    // Resolve it in the background: a relay round-trip can burn the whole
    // FETCH_WAIT, and the data path must never wait on a display name.
    let who = format!("noise key {}", hex::encode(initiator_noise));
    let lookup_relays: Vec<String> = relays.to_vec();
    let fallback = who.clone();
    let who_lookup = tokio::spawn(async move {
        match crate::relay::fetch_advert_for(&lookup_relays, Some(initiator_noise), None).await {
            Ok(Some(advert)) => advert.npub.to_string(),
            _ => fallback,
        }
    });

    Ok(Session {
        socket: socket.clone(),
        peer,
        session,
        who,
        who_lookup: Some(who_lookup),
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

    let socket = bind_udp(listen)?;
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

    let socket = bind_udp("0.0.0.0:0".parse().unwrap())?;
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
        who_lookup: None,
        tasks: Vec::new(),
    })
}

/// Bridge stdio over the encrypted session until both sides close.
///
/// Local stdin EOF sends a FIN (an authenticated empty Noise payload); a FIN
/// from the peer ends the receive side; the session ends when both happened.
/// Where a pump's tunnel datagrams come from: an exclusive socket (the
/// single-session paths) or the per-session channel a router demuxes into
/// (the shared-socket listener).
enum Datagrams<'a> {
    Socket(Arc<UdpSocket>, SocketAddr),
    Channel(&'a mut mpsc::UnboundedReceiver<Vec<u8>>),
}

impl Datagrams<'_> {
    /// Next tunnel datagram, written into `wire`; `None` = the source closed.
    async fn recv(&mut self, wire: &mut [u8]) -> Result<Option<usize>, TunnelError> {
        match self {
            Datagrams::Socket(socket, peer) => loop {
                let (n, from) = socket.recv_from(wire).await?;
                if from != *peer {
                    tracing::debug!(%from, "ignoring packet from stranger");
                    continue;
                }
                return Ok(Some(n));
            },
            Datagrams::Channel(rx) => match rx.recv().await {
                None => Ok(None),
                Some(d) => {
                    let n = d.len();
                    wire[..n].copy_from_slice(&d);
                    Ok(Some(n))
                }
            },
        }
    }
}

async fn pump<R, W>(
    mut reader: R,
    mut writer: W,
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    mut session: snow::TransportState,
    datagrams: &mut Datagrams<'_>,
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
            // Cap the read at the largest payload a Noise message can carry:
            // a fast local writer can fill the whole buffer, and an oversized
            // write_message would kill the session with a snow Input error.
            n = reader.read(&mut plain[..MAX_PAYLOAD]), if stdin_open => {
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
            r = datagrams.recv(&mut wire) => {
                let n = match r? {
                    None => return Ok(()), // source closed
                    Some(n) => n,
                };
                match session.read_message(&wire[..n], &mut plain) {
                    Ok(0) if !stdin_open => return Ok(()), // mutual close
                    Ok(0) => {
                        // Peer FIN: propagate the half-close downstream so
                        // TCP-backed transports see EOF properly.
                        stdin_open = false;
                        let _ = writer.shutdown().await;
                    }
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
    let (socket, peer, hs, who) = session.finish().await;
    eprintln!("# 🔗 tunnel up with {who} — bridging stdio");
    let mut src = Datagrams::Socket(socket.clone(), peer);
    pump(tokio::io::stdin(), tokio::io::stdout(), socket, peer, hs, &mut src).await?;
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
    let (socket, peer, hs, _) = session.finish().await;
    eprintln!("# 🔗 tunnel up with {target} at udp/{peer} — bridging stdio");
    let mut src = Datagrams::Socket(socket.clone(), peer);
    pump(tokio::io::stdin(), tokio::io::stdout(), socket, peer, hs, &mut src).await
}

/// Expose a local TCP service to tailnet peers: each tunnel is spliced to a
/// fresh connection to `to`. Runs forever; with a `psk`, only tailnet
/// members can connect at all.
///
/// Concurrent sessions are first-class: one shared UDP socket on `listen`
/// carries every session, with a router demuxing datagrams by source address
/// (see [`TunnelListener`]). Each accepted tunnel is bridged to `to` on its
/// own task, and the accept loop immediately waits for the next peer.
pub async fn expose_tcp(
    identity: &Identity,
    listen: SocketAddr,
    to: SocketAddr,
    relays: &[String],
    ttl_secs: u64,
    psk: Option<&[u8; 32]>,
) -> Result<(), TunnelError> {
    let mut listener = bind_listener(identity, listen, relays, ttl_secs, psk).await?;
    loop {
        let session = listener.accept().await?;
        let (socket, peer, hs, who, mut datagrams) = session.finish().await;
        eprintln!("# 🔗 tunnel up with {who} — forwarding to tcp/{to}");
        let sessions = listener.sessions.clone();
        tokio::spawn(async move {
            let mut src = Datagrams::Channel(&mut datagrams);
            match tokio::net::TcpStream::connect(to).await {
                Ok(conn) => {
                    let (rd, wr) = tokio::io::split(conn);
                    if let Err(e) = pump(rd, wr, socket, peer, hs, &mut src).await {
                        tracing::warn!(%e, "tunnel session ended with error");
                    }
                }
                Err(e) => tracing::warn!("cannot reach local service tcp/{to}: {e}"),
            }
            sessions.lock().expect("sessions lock").remove(&peer);
            eprintln!("# 🔁 session with {who} closed");
        });
    }
}

/// A long-lived listener for many concurrent sessions: one UDP socket on the
/// listen port, one advert, and a router task that owns the socket's receive
/// side and demuxes every datagram by source address. Established sessions
/// get their flows on dedicated channels; an unknown source (a new dialer's
/// Noise msg1) surfaces from [`TunnelListener::accept`]. This is the shape
/// WireGuard uses too — per-session sockets on a shared port cannot work,
/// because the kernel's flow hash would pin a dialer's datagrams to one
/// arbitrary session socket forever.
struct TunnelListener {
    socket: Arc<UdpSocket>,
    noise_priv: [u8; 32],
    psk: Option<[u8; 32]>,
    relays: Vec<String>,
    accept_rx: mpsc::UnboundedReceiver<(SocketAddr, Vec<u8>)>,
    /// Established sessions: source addr -> that session's tunnel datagrams.
    sessions: Arc<Mutex<HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>>>>,
    /// Handshakes in progress: source addr -> its msg3-era datagrams.
    handshakes: Arc<Mutex<HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>>>>,
}

/// Bind the shared listen socket, publish one advert, and start the router,
/// the shared traversal watcher, and the punch loop.
async fn bind_listener(
    identity: &Identity,
    listen: SocketAddr,
    relays: &[String],
    ttl_secs: u64,
    psk: Option<&[u8; 32]>,
) -> Result<TunnelListener, TunnelError> {
    let (noise_pub, noise_priv) = noise_keypair(identity)?;
    let socket = bind_udp(listen)?;
    let local = socket.local_addr()?;

    let endpoints = discover_endpoints(&socket).await?;
    crate::relay::publish_advert(identity, endpoints.clone(), noise_pub, ttl_secs, relays).await?;
    eprintln!(
        "# 🐈 serving as {} on udp/{local} (candidates: {}) — concurrent sessions welcome (Ctrl-C to quit)",
        identity.npub(),
        endpoints
            .iter()
            .map(|e| e.addr.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );

    let sessions: Arc<Mutex<HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let handshakes: Arc<Mutex<HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let (accept_tx, accept_rx) = mpsc::unbounded_channel();

    // Router: demux every datagram by source address. Punch markers and
    // other sub-frame junk are dropped here — they carry no state.
    let r_socket = socket.clone();
    let r_sessions = sessions.clone();
    let r_handshakes = handshakes.clone();
    tokio::spawn(async move {
        let mut wire = [0u8; BUF];
        loop {
            let (n, from) = match r_socket.recv_from(&mut wire).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(%e, "router recv failed");
                    continue;
                }
            };
            if n < MIN_FRAME {
                continue;
            }
            route_datagram(from, &wire[..n], &r_sessions, &r_handshakes, &accept_tx);
        }
    });

    // Traversal: one shared watcher for all sessions. A dialer's gift-wrapped
    // candidate list is recorded under the addrs it points at (the punch loop
    // needs a target), and answered with ours, so both NAT mappings get
    // opened from the inside.
    let candidates: Arc<Mutex<HashMap<SocketAddr, Vec<SocketAddr>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let (tx, mut rx) = mpsc::channel::<(PublicKey, crate::traversal::TraversalPayload)>(16);
    let watch_identity = identity.clone();
    let watch_relays = relays.to_vec();
    tokio::spawn(async move {
        let _ = crate::traversal::watch_traversal(watch_identity, watch_relays, tx).await;
    });
    let c_candidates = candidates.clone();
    let reply_identity = identity.clone();
    let reply_noise = noise_pub;
    let reply_endpoints = endpoints.clone();
    let reply_relays = relays.to_vec();
    tokio::spawn(async move {
        while let Some((sender, payload)) = rx.recv().await {
            let eps = parse_endpoints(&payload.endpoints);
            tracing::info!(%sender, ?eps, "traversal request received");
            c_candidates
                .lock()
                .expect("candidates lock")
                .extend(eps.iter().map(|a| (*a, eps.clone())));
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

    // Punch loop: keep the serve-side NAT mappings open toward every
    // candidate that has not grown into an established session yet. The
    // dialer's own punch + msg1 opened the mapping in one direction; this
    // opens it in ours, which stricter NATs need before msg2 can land.
    let p_socket = socket.clone();
    let p_sessions = sessions.clone();
    tokio::spawn(async move {
        loop {
            sleep(PUNCH_EVERY).await;
            let targets: Vec<SocketAddr> = {
                let established = p_sessions.lock().expect("sessions lock");
                candidates
                    .lock()
                    .expect("candidates lock")
                    .keys()
                    .filter(|a| !established.contains_key(a))
                    .cloned()
                    .collect()
            };
            for addr in targets {
                let _ = p_socket.send_to(PUNCH, addr).await;
            }
        }
    });

    Ok(TunnelListener {
        socket,
        noise_priv,
        psk: psk.cloned(),
        relays: relays.to_vec(),
        accept_rx,
        sessions,
        handshakes,
    })
}

/// Send one datagram to its session (by source address), to the handshake
/// currently being accepted from that source, or — an unknown source — to
/// the accept queue as a candidate handshake opener.
fn route_datagram(
    from: SocketAddr,
    datagram: &[u8],
    sessions: &Mutex<HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>>>,
    handshakes: &Mutex<HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>>>,
    accept: &mpsc::UnboundedSender<(SocketAddr, Vec<u8>)>,
) {
    if let Some(tx) = sessions.lock().expect("sessions lock").get(&from) {
        let _ = tx.send(datagram.to_vec());
        return;
    }
    if let Some(tx) = handshakes.lock().expect("handshakes lock").get(&from) {
        let _ = tx.send(datagram.to_vec());
        return;
    }
    let _ = accept.send((from, datagram.to_vec()));
}

/// One accepted tunnel: the shared socket for egress, a dedicated channel
/// for ingress, and its own Noise transport. The channel is dropped when the
/// session's pump ends; the listener's session map entry goes with it.
struct ListenerSession {
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    session: snow::TransportState,
    who: String,
    data_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    /// Background lookup of the dialer's npub (relay round-trip). Display
    /// only — the data path must never wait on it.
    who_lookup: Option<tokio::task::JoinHandle<String>>,
}

impl ListenerSession {
    /// Abort the display-name lookup and deconstruct into the transport
    /// parts for the pump.
    async fn finish(
        mut self,
    ) -> (
        Arc<UdpSocket>,
        SocketAddr,
        snow::TransportState,
        String,
        mpsc::UnboundedReceiver<Vec<u8>>,
    ) {
        let who = match self.who_lookup.take() {
            Some(h) if h.is_finished() => h.await.unwrap_or_else(|_| self.who.clone()),
            Some(h) => {
                h.abort();
                self.who
            }
            None => self.who,
        };
        (self.socket, self.peer, self.session, who, self.data_rx)
    }
}

impl TunnelListener {
    /// Serve the next dialer that completes the handshake: take its msg1 off
    /// the accept queue, answer msg2, and wait for msg3 — all routed through
    /// the shared socket's demux. Returns with the session registered in the
    /// router's map, so its pump starts receiving flows immediately.
    async fn accept(&mut self) -> Result<ListenerSession, TunnelError> {
        let mut plain = [0u8; BUF];
        let mut wire = [0u8; BUF];
        loop {
            let (from, msg1) = match self.accept_rx.recv().await {
                Some(m) => m,
                None => return Err(TunnelError::NoHandshake),
            };
            let mut hs = noise::responder(&self.noise_priv, self.psk.as_ref())?;
            if hs.read_message(&msg1, &mut plain).is_err() {
                continue; // not a handshake opener for us
            }

            // Register before msg2 goes out: the dialer's msg3 can only
            // follow it, and must land in our channel, not the accept queue.
            let (tx, mut rx) = mpsc::unbounded_channel();
            self.handshakes.lock().expect("handshakes lock").insert(from, tx);
            let n = hs.write_message(b"", &mut wire)?;
            self.socket.send_to(&wire[..n], from).await?;

            let deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;
            let ok = loop {
                match timeout_at(deadline, rx.recv()).await {
                    Err(_) | Ok(None) => break false,
                    Ok(Some(dgram)) => match hs.read_message(&dgram, &mut plain) {
                        Ok(_) => break true,
                        Err(snow::Error::Decrypt) => continue, // punch echo or msg1 replay
                        Err(_) => break false,
                    },
                }
            };
            self.handshakes.lock().expect("handshakes lock").remove(&from);
            if !ok {
                continue; // dialer vanished mid-handshake; serve the next
            }

            let initiator_noise: [u8; 32] = hs
                .get_remote_static()
                .ok_or(TunnelError::NoHandshake)?
                .try_into()
                .map_err(|_| TunnelError::NoHandshake)?;
            let session = noise::into_transport(hs)?;
            let who = format!("noise key {}", hex::encode(initiator_noise));
            let lookup_relays = self.relays.clone();
            let fallback = who.clone();
            let who_lookup = tokio::spawn(async move {
                match crate::relay::fetch_advert_for(&lookup_relays, Some(initiator_noise), None)
                    .await
                {
                    Ok(Some(advert)) => advert.npub.to_string(),
                    _ => fallback,
                }
            });

            let (data_tx, data_rx) = mpsc::unbounded_channel();
            self.sessions.lock().expect("sessions lock").insert(from, data_tx);
            return Ok(ListenerSession {
                socket: self.socket.clone(),
                peer: from,
                session,
                who,
                data_rx,
                who_lookup: Some(who_lookup),
            });
        }
    }
}

/// Forward a local TCP port over tunnels to `target`: every connection to
/// `127.0.0.1:<port>` dials `target` (a fresh tunnel per connection) and
/// splices the traffic through, encrypted. With a `psk`, only tailnet
/// members of the same group can be dialed.
pub async fn forward_tcp(
    identity: &Identity,
    target: &str,
    port: u16,
    relays: &[String],
    psk: Option<&[u8; 32]>,
) -> Result<(), TunnelError> {
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await?;
    eprintln!("# 🐈 forwarding tcp/0.0.0.0:{port} over tunnels to {target}");
    let psk = psk.copied();
    loop {
        let (conn, client) = listener.accept().await?;
        eprintln!("# 🔈 connection from {client} — dialing {target}…");
        // Each connection gets its own tunnel on its own task; the accept
        // loop is free for the next one.
        let identity = identity.clone();
        let target = target.to_string();
        let relays = relays.to_vec();
        tokio::spawn(async move {
            match dial_session(&identity, &target, &relays, psk.as_ref()).await {
                Ok(session) => {
                    let (socket, peer, hs, _) = session.finish().await;
                    let (rd, wr) = tokio::io::split(conn);
                    let mut src = Datagrams::Socket(socket.clone(), peer);
                    if let Err(e) = pump(rd, wr, socket, peer, hs, &mut src).await {
                        tracing::warn!(%e, "tunnel session ended with error");
                    }
                }
                Err(e) => eprintln!("# ⚠️  cannot establish tunnel for {client}: {e}"),
            }
        });
    }
}

/// Wire format of a transfer: a JSON header naming the file, then raw chunks.
/// `sha256` is the whole-file digest from the sender's side; it is the
/// transfer's identity (a partial file is only resumed when it matches) and
/// the end-to-end integrity check for the finished file.
#[derive(serde::Serialize, serde::Deserialize)]
struct TransferHeader {
    name: String,
    len: u64,
    sha256: String,
}

/// Resume sidecar, persisted next to the partial file: how many chunks the
/// receiver durably holds of the transfer identified by (len, sha256).
#[derive(serde::Serialize, serde::Deserialize)]
struct ResumeMeta {
    len: u64,
    sha256: String,
    chunks: u64,
}

/// Transfer message tags: first byte of every plaintext payload.
const TAG_HEADER: u8 = 1;
const TAG_CHUNK: u8 = 2;
const TAG_ACK: u8 = 3;
const TAG_FIN: u8 = 4;
/// Header reply carrying the receiver's resume point: tag + u32 "next
/// expected seq" (how many complete chunks it already holds on disk).
const TAG_RESUME: u8 = 5;
/// Smallest authenticated frame (a 5-byte payload + the 16-byte Poly1305
/// tag). Anything decrypt-failing below this is a punch marker, not a replay.
const MIN_FRAME: usize = 5 + 16;
/// Per-chunk ACK wait before retransmitting.
const ACK_TIMEOUT: Duration = Duration::from_secs(1);
/// Sliding window: chunks in flight before an ack is required. Kept small
/// on purpose: the receiver can only ack in order, so under loss the sender
/// replays the *whole* window each sweep — the burst must fit in the peer's
/// socket queue or the same frames keep dropping every round (32 × 1232 B
/// ≈ 39 KiB; comfortably inside even default kernel buffers).
const WINDOW: u32 = 32;
/// Ack history depth. The sender must consume every ack the receiver writes
/// *in order* (snow nonces), so a lost ack makes every later one undecryptable
/// until a replay reaches the missed nonce. The receiver only acks at window
/// boundaries (see `receive_chunks`), so the total ack count — and therefore
/// the worst-case nonce gap — stays far below this for any realistic file.
const ACK_HISTORY: usize = 4 * WINDOW as usize;
/// Retransmit an unacked chunk after this long without progress.
const RTO: Duration = Duration::from_millis(400);
/// After the file is on disk, the receiver answers the sender's replays with
/// its FIN until the sender goes quiet for this long — enough for the
/// sender's retransmit loop (1 s cadence) to hear the confirmation, with
/// headroom for a short path flap.
const FIN_LINGER: Duration = Duration::from_secs(10);
/// Retransmission budget per chunk before declaring the path too lossy.
const MAX_RETRIES: u32 = 120;
/// Receiver-side inactivity bound: the sender stopped answering.
const IDLE_TIMEOUT: Duration = Duration::from_secs(90);

/// One encrypted send + the ack round-trip for it (header and FIN frames).
///
/// Retransmission replays the *same ciphertext*: snow nonces are sequential
/// and never on the wire, so a re-encrypted retry would carry a fresh nonce
/// the peer cannot decrypt after missing the original. Replay is safe — the
/// peer either consumes it (it never got it) or fails Decrypt and skips it
/// (it already did).
///
/// `want_seq` completes the wait on a cumulative ack reaching that many
/// chunks (the FIN handshake — the receiver must have *everything*), or on a
/// TAG_FIN from the peer. `None` completes on any authenticated reply (the
/// header wait — any ack proves the receiver is listening).
///
/// Returns the value carried by the completing frame: the ack's cumulative
/// seq (or the header reply's resume point), or `u32::MAX` when a peer FIN
/// completed the wait.
///
/// `retries` bounds the replay budget; the header passes a small one because
/// a lost header ack self-heals (chunk acks replay the whole ack history).
async fn send_and_ack(
    socket: &UdpSocket,
    peer: SocketAddr,
    hs: &mut snow::TransportState,
    payload: &[u8],
    want_seq: Option<u32>,
    retries: u32,
    plain: &mut [u8],
    wire: &mut [u8],
) -> Result<u32, TunnelError> {
    let n = hs.write_message(payload, wire)?;
    let ct = wire[..n].to_vec();
    socket.send_to(&ct, peer).await?;
    for _ in 0..retries {
        let wait = tokio::time::Instant::now() + ACK_TIMEOUT;
        loop {
            match timeout_at(wait, socket.recv_from(wire)).await {
                Err(_) => break, // ack timeout -> replay
                Ok(Err(e)) => return Err(e.into()),
                Ok(Ok((n, from))) => {
                    if from != peer {
                        continue;
                    }
                    match hs.read_message(&wire[..n], plain) {
                        Ok(m) if m >= 5 && (plain[0] == TAG_ACK || plain[0] == TAG_RESUME) => {
                            let seq = u32::from_be_bytes(plain[1..5].try_into().unwrap());
                            match want_seq {
                                Some(w) if seq >= w => return Ok(seq),
                                Some(_) => {} // stale replayed ack; keep waiting
                                None => return Ok(seq),
                            }
                        }
                        Ok(m) if m >= 1 && plain[0] == TAG_FIN => return Ok(u32::MAX),
                        Ok(_) => {}
                        Err(snow::Error::Decrypt) => {} // already-consumed replay
                        Err(e) => return Err(e.into()),
                    }
                }
            }
        }
        socket.send_to(&ct, peer).await?;
    }
    Err(TunnelError::TransferStalled)
}

/// Emit one encrypted chunk frame (tag + seq + data) and hand back the
/// ciphertext — retransmissions must replay these exact bytes, because a
/// re-encrypted retry would carry a new snow nonce the receiver can't decrypt.
async fn emit_chunk(
    socket: &UdpSocket,
    peer: SocketAddr,
    hs: &mut snow::TransportState,
    seq: u32,
    data: &[u8],
    wire: &mut [u8],
) -> Result<Vec<u8>, TunnelError> {
    let mut msg = Vec::with_capacity(5 + data.len());
    msg.push(TAG_CHUNK);
    msg.extend_from_slice(&seq.to_be_bytes());
    msg.extend_from_slice(data);
    let n = hs.write_message(&msg, wire)?;
    socket.send_to(&wire[..n], peer).await?;
    Ok(wire[..n].to_vec())
}

/// Fold one datagram into the ack state: consume the ack nonce stream
/// sequentially (replays of already-consumed acks fail Decrypt and are
/// skipped), advancing `base` by the newest cumulative value heard.
fn fold_ack(
    hs: &mut snow::TransportState,
    frames: &mut VecDeque<(Vec<u8>, Instant, u32)>,
    base: &mut u32,
    datagram: &[u8],
    plain: &mut [u8],
) -> Result<(), TunnelError> {
    match hs.read_message(datagram, plain) {
        Ok(m) if m >= 5 && plain[0] == TAG_ACK => {
            let ack = u32::from_be_bytes(plain[1..5].try_into().unwrap());
            tracing::debug!(ack, base = *base, "ack decrypted");
            let advance = (ack.saturating_sub(*base) as usize).min(frames.len());
            for _ in 0..advance {
                frames.pop_front();
            }
            *base += advance as u32;
            Ok(())
        }
        Ok(_) => Ok(()),
        Err(snow::Error::Decrypt) => {
            tracing::trace!(len = datagram.len(), "ack replay skipped (already consumed)");
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

/// Stream chunks `first..` of `file` (`len` bytes) through a sliding window:
/// up to [`WINDOW`] frames in flight, each retransmitted on [`RTO`] until the
/// receiver's cumulative ack ("next expected seq") covers it. Because snow
/// nonces are strictly sequential, retransmission *replays* cached
/// ciphertexts — a replay burst lets the receiver catch up across every gap
/// at once, and lost acks resync the same way (the receiver replays its ack
/// history; see `ack_and_replay`). Acks are drained in batches — the
/// receiver's replays make them arrive many-at-once.
async fn stream_chunks(
    socket: &UdpSocket,
    peer: SocketAddr,
    hs: &mut snow::TransportState,
    total: u32,
    len: u64,
    file: &mut tokio::fs::File,
    first: u32,
) -> Result<(), TunnelError> {
    let mut wire = [0u8; BUF];
    let mut plain = [0u8; BUF];
    let mut buf = [0u8; CHUNK];

    // In-flight frames (seqs base..next): cached ciphertext, last-sent time,
    // retransmission count.
    let mut frames: VecDeque<(Vec<u8>, Instant, u32)> = VecDeque::new();
    let mut base: u32 = first; // next seq the receiver wants
    let mut next: u32 = first; // next unsent chunk
    let mut sweep_round: usize = 0;

    async fn read_chunk_at(
        file: &mut tokio::fs::File,
        seq: u32,
        len: u64,
        buf: &mut [u8],
    ) -> Result<usize, TunnelError> {
        let offset = seq as u64 * CHUNK as u64;
        let want = CHUNK.min((len - offset) as usize);
        file.seek(SeekFrom::Start(offset)).await?;
        Ok(file.read(&mut buf[..want]).await?)
    }

    loop {
        if base >= total {
            return Ok(());
        }
        // Fill the window with fresh frames.
        while next < total && next - base < WINDOW {
            let m = read_chunk_at(file, next, len, &mut buf).await?;
            let ct = emit_chunk(socket, peer, hs, next, &buf[..m], &mut wire).await?;
            frames.push_back((ct, Instant::now(), 0));
            next += 1;
        }
        // Replay anything whose ack is late — starting the sweep at a
        // rotating offset each round: a burst whose tail always lands past
        // the peer's receive queue would otherwise drop the *same* frames
        // every round and never recover them.
        let mut replayed = 0usize;
        let start = sweep_round % frames.len().max(1);
        let len = frames.len();
        for offset in 0..len {
            let (ct, at, retries) = &mut frames[(start + offset) % len];
            if at.elapsed() >= RTO {
                *retries += 1;
                if *retries > MAX_RETRIES {
                    return Err(TunnelError::TransferStalled);
                }
                socket.send_to(ct, peer).await?;
                replayed += 1;
                *at = Instant::now();
            }
        }
        sweep_round = sweep_round.wrapping_add(1);
        if replayed > 0 {
            tracing::debug!(%replayed, base, next, "replay sweep");
        }
        // Wait for the next ack, then drain the queue dry (the receiver's
        // replays arrive many-at-once; per-datagram loop overhead would
        // throttle throughput).
        let deadline = tokio::time::Instant::now() + RTO;
        let (n, from) = match timeout_at(deadline, socket.recv_from(&mut wire)).await {
            Err(_) => continue, // no acks in time -> replay sweep runs again
            Ok(r) => r?,
        };
        tracing::debug!(%from, n, "sender got datagram");
        if from == peer {
            fold_ack(hs, &mut frames, &mut base, &wire[..n], &mut plain)?;
            tracing::trace!(base, next, "ack folded");
        }
        let mut drained = 0usize;
        loop {
            match socket.try_recv_from(&mut wire) {
                Ok((n, from)) if from == peer => {
                    drained += 1;
                    fold_ack(hs, &mut frames, &mut base, &wire[..n], &mut plain)?;
                }
                Ok(_) => continue, // stranger; keep draining
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e.into()),
            }
        }
        if drained > 0 {
            tracing::debug!(drained, base, "drained queued acks");
        }
    }
}

/// Send one control frame — a cumulative ack (`TAG_ACK`, "I expect `seq`
/// next") or a header reply (`TAG_RESUME`, the receiver's resume point) —
/// and, on `full`, replay the whole recent ack history. The replay is the
/// resync mechanism: the sender's nonce stream only advances when it hears
/// *an* ack it can decrypt, so if acks were lost, the replays (old nonces
/// fail Decrypt and are skipped; un-consumed ones decrypt in order) walk it
/// forward to the newest cumulative value. Replaying on *every* chunk would
/// flood the sender with quadratic ack traffic, so it is time-budgeted.
async fn ack_and_replay(
    socket: &UdpSocket,
    peer: SocketAddr,
    hs: &mut snow::TransportState,
    tag: u8,
    seq: u32,
    history: &mut VecDeque<Vec<u8>>,
    wire: &mut [u8],
    full: bool,
) -> Result<(), TunnelError> {
    let mut msg = vec![tag];
    msg.extend_from_slice(&seq.to_be_bytes());
    let n = hs.write_message(&msg, wire)?;
    let ct = wire[..n].to_vec();
    history.push_back(ct.clone());
    if history.len() > ACK_HISTORY {
        history.pop_front();
    }
    tracing::debug!(seq, full, history = history.len(), %peer, "acking");
    if full {
        for old in history.iter() {
            socket.send_to(old, peer).await?;
        }
    } else {
        socket.send_to(&ct, peer).await?;
    }
    Ok(())
}

/// The receive side of [`stream_chunks`]: write chunks in order and ack
/// cumulatively with history replay. Snow only decrypts frames in nonce
/// order, and the sender emits seqs in nonce order — so every frame that
/// decrypts IS the next one (frames behind a gap are undecryptable and
/// skipped; the sender's replay bursts refill the gap). Returns bytes on
/// disk (including `already`, the prefix a resumed partial had); stops once
/// `len` have been, or the sender FINs.
///
/// `hasher` folds every written byte into the file's sha256 as it lands.
/// When `meta` is given, each window-boundary ack — after a flush, so the
/// acked prefix is in the OS — refreshes the resume sidecar with the acked
/// chunk count: a crash right after leaves a part file + meta consistent
/// with every ack the sender heard.
async fn receive_chunks<W>(
    socket: &UdpSocket,
    peer: SocketAddr,
    hs: &mut snow::TransportState,
    len: u64,
    file: &mut W,
    history: &mut VecDeque<Vec<u8>>,
    hasher: &mut sha2::Sha256,
    mut meta: Option<(&Path, ResumeMeta)>,
    already: u64,
) -> Result<u64, TunnelError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut wire = [0u8; BUF];
    let mut plain = [0u8; BUF];
    let mut received = already;
    loop {
        let (n, from) = timeout_at(
            tokio::time::Instant::now() + IDLE_TIMEOUT,
            socket.recv_from(&mut wire),
        )
        .await
        .map_err(|_| TunnelError::TransferStalled)??;
        if from != peer {
            continue;
        }
        let m = match hs.read_message(&wire[..n], &mut plain) {
            Ok(m) => m,
            Err(snow::Error::Decrypt) => {
                // A failed decrypt on a noise-sized datagram is an old chunk
                // (or header) replay: the sender is retransmitting *because
                // it missed our acks*. Its nonces can never move backward, so
                // the only way it advances is hearing our already-written ack
                // history — replay it all, right now. Smaller junk is punch
                // markers; ignore those.
                if n >= MIN_FRAME {
                    for ct in history.iter() {
                        socket.send_to(ct, peer).await?;
                    }
                    tracing::debug!(n, history = history.len(), "stuck sender; replayed acks");
                }
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        match plain[0] {
            TAG_CHUNK if m >= 5 => {
                let seq = u32::from_be_bytes(plain[1..5].try_into().unwrap());
                use sha2::Digest as _;
                hasher.update(&plain[5..m]);
                file.write_all(&plain[5..m]).await?;
                received += (m - 5) as u64;
                // Delayed-ack style: ack only at window boundaries (and the
                // final chunk). Every ack is a fresh snow nonce the sender
                // must consume *in order*, so a burst of per-chunk acks would
                // let the ack stream outrun the sender's consumption under
                // timing skew and the nonce gap would outgrow the replay
                // history — one ack per window keeps the gap trivially small.
                if (seq + 1) % WINDOW == 0 || (len > 0 && received >= len) {
                    file.flush().await?;
                    if let Some((meta_path, meta)) = meta.as_mut() {
                        meta.chunks = seq as u64 + 1;
                        let _ = std::fs::write(meta_path, serde_json::to_string(meta)?);
                    }
                    ack_and_replay(socket, peer, hs, TAG_ACK, seq + 1, history, &mut wire, false)
                        .await?;
                }
                if len > 0 && received >= len {
                    break;
                }
            }
            TAG_FIN => break,
            _ => {}
        }
    }
    Ok(received)
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
/// Protocol (every message Noise-encrypted): TAG_HEADER (JSON name+len+sha256)
/// -> TAG_CHUNK (seq + MTU-sized data) through a sliding window with
/// cumulative acks and RTO retransmits -> TAG_FIN, held until the receiver
/// confirms the file is on disk. A clean return means the receiving side
/// wrote, flushed, and verified the entire file. If the receiver holds a
/// partial file from an interrupted attempt, it resumes from there.
pub async fn send_file(
    identity: &Identity,
    target: &str,
    path: &Path,
    relays: &[String],
    psk: Option<&[u8; 32]>,
) -> Result<(), TunnelError> {
    let name = sanitize_name(
        path.file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| TunnelError::UnsafePath(path.to_path_buf()))?
            .as_ref(),
    )?;

    // Whole-file sha256 off-thread, overlapped with the tunnel setup: the
    // header cannot go out without it (it is the resume identity).
    let hash_task = {
        let path = path.to_path_buf();
        tokio::task::spawn_blocking(move || -> Result<[u8; 32], std::io::Error> {
            use sha2::Digest;
            let mut f = std::fs::File::open(&path)?;
            let mut h = sha2::Sha256::new();
            std::io::copy(&mut f, &mut h)?;
            Ok(h.finalize().into())
        })
    };
    let session = dial_session(identity, target, relays, psk).await?;
    let (socket, peer, mut hs, _) = session.finish().await;
    let file_sha = match hash_task.await {
        Ok(Ok(sha)) => sha,
        Ok(Err(e)) => return Err(e.into()),
        Err(e) => return Err(TunnelError::Io(std::io::Error::other(e))),
    };
    eprintln!(
        "# 🔗 tunnel up with {target} at udp/{peer} — sending {}",
        name.display()
    );

    send_stream(&socket, peer, &mut hs, path, &name, &file_sha).await
}

/// The sender half of a file transfer over an established Noise session
/// (everything after `dial_session`).
async fn send_stream(
    socket: &UdpSocket,
    peer: SocketAddr,
    hs: &mut snow::TransportState,
    path: &Path,
    name: &Path,
    file_sha: &[u8; 32],
) -> Result<(), TunnelError> {
    let mut file = tokio::fs::File::open(path).await?;
    let len = file.metadata().await?.len();
    let mut wire = [0u8; BUF];
    let mut plain = [0u8; BUF];

    // -> header; a small ack budget: a lost header ack self-heals once the
    // chunks flow (their acks replay the header ack too). The reply carries
    // the receiver's resume point (chunks already on disk from an
    // interrupted attempt) or u32::MAX if a FIN completed the wait.
    let mut msg = vec![TAG_HEADER];
    msg.extend(serde_json::to_string(&TransferHeader {
        name: name.to_string_lossy().to_string(),
        len,
        sha256: hex::encode(file_sha),
    })?.into_bytes());
    let reply = match send_and_ack(socket, peer, hs, &msg, None, 3, &mut plain, &mut wire).await {
        Ok(reply) => reply,
        Err(e) => {
            tracing::debug!("header ack not heard ({e}); streaming anyway");
            0
        }
    };

    // -> chunks through the sliding window, starting at the resume point.
    let started = Instant::now();
    let total_chunks = len.div_ceil(CHUNK as u64) as u32;
    let resumed = reply != u32::MAX && reply > 0;
    let first = reply.min(total_chunks);
    if resumed {
        eprintln!(
            "# ↩️  resuming {} at chunk {first}/{total_chunks} (receiver kept a partial copy)",
            name.display()
        );
    }
    if first < total_chunks {
        stream_chunks(socket, peer, hs, total_chunks, len, &mut file, first).await?;
    }

    // -> FIN; completes when the receiver's cumulative ack reaches the
    // transfer total, or it FINs — either way the whole file is on disk.
    send_and_ack(socket, peer, hs, &[TAG_FIN], Some(total_chunks), MAX_RETRIES, &mut plain, &mut wire)
        .await?;
    let dt = started.elapsed().as_secs_f64();
    eprintln!(
        "# ✅ {} received by peer ({len} bytes in {dt:.1}s, {:.1} MB/s)",
        name.display(),
        len as f64 / dt / (1024.0 * 1024.0)
    );
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
    let (socket, peer, mut hs, who) = session.finish().await;
    receive_stream(&who, &socket, peer, &mut hs, out_dir).await
}

/// The receiver half of a file transfer over an established Noise session
/// (everything after `serve_session`): header, resume decision, chunk
/// streaming, finalize.
async fn receive_stream(
    who: &str,
    socket: &UdpSocket,
    peer: SocketAddr,
    hs: &mut snow::TransportState,
    out_dir: &Path,
) -> Result<(String, PathBuf), TunnelError> {
    let mut wire = [0u8; BUF];
    let mut plain = [0u8; BUF];
    let mut history: VecDeque<Vec<u8>> = VecDeque::new();

    // <- header; ack it (seeding the ack history) so the sender can stream.
    // A decrypt failure here is the sender replaying the header — it missed
    // our ack — so answer with the whole history immediately.
    let m = loop {
        let (n, from) = timeout_at(
            tokio::time::Instant::now() + IDLE_TIMEOUT,
            socket.recv_from(&mut wire),
        )
        .await
        .map_err(|_| TunnelError::TransferStalled)??;
        if from != peer {
            continue;
        }
        match hs.read_message(&wire[..n], &mut plain) {
            Ok(m) if m >= 1 && plain[0] == TAG_HEADER => break m,
            Ok(0) => continue,
            Ok(_) => continue,
            Err(snow::Error::Decrypt) if n >= MIN_FRAME => {
                for ct in history.iter() {
                    socket.send_to(ct, peer).await?;
                }
            }
            Err(snow::Error::Decrypt) => {} // punch marker
            Err(e) => return Err(e.into()),
        }
    };
    let header: TransferHeader = serde_json::from_slice(&plain[1..m])?;
    let name = sanitize_name(&header.name)?;
    let final_path = out_dir.join(&name);
    let part_path = out_dir.join(format!("{}.noscat-part", name.display()));
    let meta_path = out_dir.join(format!("{}.noscat-part.meta", name.display()));
    let total_chunks = header.len.div_ceil(CHUNK as u64) as u32;
    eprintln!("# 📥 {who} is sending {} ({} bytes)…", name.display(), header.len);

    // Resume decision: a partial file from an interrupted attempt continues
    // only when its recorded identity — len and whole-file sha256, both from
    // the previous header — matches this transfer's header.
    use sha2::Digest as _;
    let mut resume_chunks = 0u32;
    let mut hasher = sha2::Sha256::new();
    let saved_meta = std::fs::read(&meta_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<ResumeMeta>(&bytes).ok());
    if let Some(meta) = &saved_meta {
        let prefix_len = meta.chunks.min(total_chunks as u64) * CHUNK as u64;
        if meta.len == header.len
            && meta.sha256 == header.sha256
            && prefix_len > 0
            && prefix_len <= header.len
            && tokio::fs::metadata(&part_path).await.map(|m| m.len() >= prefix_len).unwrap_or(false)
        {
            // Seed the hash with the durable prefix; the part file is
            // appended from there.
            use tokio::io::AsyncReadExt;
            let mut part = tokio::fs::File::open(&part_path).await?;
            let mut prefix = vec![0u8; prefix_len as usize];
            part.read_exact(&mut prefix).await?;
            hasher.update(&prefix);
            resume_chunks = (prefix_len / CHUNK as u64) as u32;
        }
    }
    ack_and_replay(socket, peer, hs, TAG_RESUME, resume_chunks, &mut history, &mut wire, true).await?;
    if resume_chunks > 0 {
        eprintln!(
            "# ↩️  resuming {name:?} at chunk {resume_chunks}/{total_chunks} — asking the sender to skip ahead"
        );
    }

    // Cumulative acks with history replay keep the sender's nonce stream
    // moving across lost acks; see receive_chunks.
    let mut file = if resume_chunks > 0 {
        tokio::io::BufWriter::with_capacity(
            64 * 1024,
            tokio::fs::OpenOptions::new()
                .append(true)
                .open(&part_path)
                .await?,
        )
    } else {
        tokio::io::BufWriter::with_capacity(64 * 1024, tokio::fs::File::create(&part_path).await?)
    };
    let meta_state = ResumeMeta {
        len: header.len,
        sha256: header.sha256.clone(),
        chunks: resume_chunks as u64,
    };
    let received = receive_chunks(
        socket,
        peer,
        hs,
        header.len,
        &mut file,
        &mut history,
        &mut hasher,
        Some((&meta_path, meta_state)),
        resume_chunks as u64 * CHUNK as u64,
    )
    .await?;
    file.flush().await?;
    let inner = file.into_inner();
    inner.sync_all().await?;
    drop(inner);

    if received != header.len {
        // Leave the part file + sidecar: the next attempt picks up here.
        eprintln!(
            "# ⚠️  transfer incomplete: {received}/{} bytes (path too lossy); partial kept for resume",
            header.len
        );
        return Ok((who.to_string(), part_path));
    }

    // Whole-file integrity: the streamed bytes plus (on resume) the seeded
    // prefix must hash to the header's digest.
    let digest = hex::encode(hasher.finalize());
    if digest != header.sha256 {
        eprintln!("# ⚠️  sha256 mismatch ({digest} != {}); keeping the partial", header.sha256);
        return Ok((who.to_string(), part_path));
    }
    tokio::fs::rename(&part_path, &final_path).await?;
    tokio::fs::remove_file(&meta_path).await.ok();
    eprintln!("# ✅ {who} -> {final_path:?} ({received} bytes)");

    // -> FIN, then linger: answer every datagram the sender replays with
    // (ack history + FIN) until it goes quiet, so its FIN wait always
    // resyncs and returns only after the file is truly on disk.
    let n = hs.write_message(&[TAG_FIN], &mut wire)?;
    let fin = wire[..n].to_vec();
    socket.send_to(&fin, peer).await?;
    tracing::debug!("file complete; FIN sent, lingering for the sender");
    let mut quiet = tokio::time::Instant::now() + FIN_LINGER;
    loop {
        match timeout_at(quiet, socket.recv_from(&mut wire)).await {
            Err(_) => break, // sender gone quiet: it has our confirmation
            Ok(r) => {
                let (_, from) = r?;
                if from != peer {
                    continue;
                }
                socket.send_to(&fin, peer).await?;
                for ct in history.iter() {
                    socket.send_to(ct, peer).await?;
                }
                quiet = tokio::time::Instant::now() + FIN_LINGER;
            }
        }
    }
    Ok((who.to_string(), final_path))
}


#[cfg(test)]
mod tests {
    use super::*;

    /// The listener's router demuxes datagrams strictly by source address:
    /// an established session's flow goes only to its channel, a handshake
    /// in progress gets its own, and anything unknown surfaces from the
    /// accept queue. This is what lets concurrent sessions share one UDP
    /// port without the kernel pinning a flow to the wrong socket.
    #[test]
    fn router_demuxes_by_source() {
        let (accept_tx, mut accept_rx) = mpsc::unbounded_channel();
        let sessions: Arc<Mutex<HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let handshakes: Arc<Mutex<HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>>>> =
            Arc::new(Mutex::new(HashMap::new()));

        let established: SocketAddr = "10.0.0.1:1111".parse().unwrap();
        let (est_tx, mut est_rx) = mpsc::unbounded_channel();
        sessions.lock().unwrap().insert(established, est_tx);
        let handshaking: SocketAddr = "10.0.0.2:2222".parse().unwrap();
        let (hs_tx, mut hs_rx) = mpsc::unbounded_channel();
        handshakes.lock().unwrap().insert(handshaking, hs_tx);
        let unknown: SocketAddr = "10.0.0.3:3333".parse().unwrap();

        route_datagram(established, b"flow", &sessions, &handshakes, &accept_tx);
        route_datagram(handshaking, b"msg3", &sessions, &handshakes, &accept_tx);
        route_datagram(unknown, b"msg1", &sessions, &handshakes, &accept_tx);

        assert_eq!(est_rx.try_recv().unwrap(), b"flow");
        assert_eq!(hs_rx.try_recv().unwrap(), b"msg3");
        let (from, msg1) = accept_rx.try_recv().unwrap();
        assert_eq!(from, unknown);
        assert_eq!(msg1, b"msg1");
        // Nothing spilled across channels.
        assert!(est_rx.try_recv().is_err());
        assert!(hs_rx.try_recv().is_err());
        assert!(accept_rx.try_recv().is_err());
    }

    /// Full transfer roundtrip over real UDP loopback — through a proxy that
    /// drops every 7th data-plane frame (~14% loss). Proves the sliding
    /// window + cumulative acks recover loss: stop-and-wait would still pass
    /// this, but only at 1 RTT per chunk; the window finishes in a handful.
    #[tokio::test]
    async fn transfer_survives_heavy_frame_loss() {
        use crate::noise;

        let mut wi = [0u8; BUF];
        let mut pi = [0u8; BUF];

        // Two parties, real UDP sockets (with production kernel buffers —
        // defaults would overflow mid-burst and turn the loss test into a
        // buffer-overflow test), and a lossy middlebox between them.
        let send_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let recv_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let proxy_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        for s in [&send_sock, &recv_sock, &proxy_sock] {
            tune_buffers(s);
            s.set_nonblocking(true).unwrap();
        }
        let send_sock = UdpSocket::from_std(send_sock).unwrap();
        let recv_sock = UdpSocket::from_std(recv_sock).unwrap();
        let proxy_sock = UdpSocket::from_std(proxy_sock).unwrap();
        let (sender_addr, recv_addr, proxy_addr) = (
            send_sock.local_addr().unwrap(),
            recv_sock.local_addr().unwrap(),
            proxy_sock.local_addr().unwrap(),
        );
        let proxy = tokio::spawn(async move {
            let mut buf = [0u8; BUF];
            let mut from_sender = 0u32;
            loop {
                let (n, from) = proxy_sock.recv_from(&mut buf).await.unwrap();
                let target = if from == sender_addr {
                    from_sender += 1;
                    // The first two sender datagrams are the XK initiator's
                    // handshake messages — let them through; drop every 7th
                    // data-plane frame after that.
                    if from_sender > 2 && (from_sender - 2) % 7 == 0 {
                        continue;
                    }
                    recv_addr
                } else {
                    sender_addr
                };
                proxy_sock.send_to(&buf[..n], target).await.unwrap();
            }
        });

        // Noise XK handshake (both peers see the proxy as their counterpart).
        let ipriv = [7u8; 32];
        let rpriv = [9u8; 32];
        let rpub = noise::noise_public(&rpriv);
        let mut hi = noise::initiator(&ipriv, &rpub, None).unwrap();
        let mut hr = noise::responder(&rpriv, None).unwrap();
        // -> e
        let n = hi.write_message(b"", &mut wi).unwrap();
        send_sock.send_to(&wi[..n], proxy_addr).await.unwrap();
        let (n, _) = recv_sock.recv_from(&mut wi).await.unwrap();
        hr.read_message(&wi[..n], &mut pi).unwrap();
        // <- e, ee, s, er
        let n = hr.write_message(b"", &mut wi).unwrap();
        recv_sock.send_to(&wi[..n], proxy_addr).await.unwrap();
        let (n, _) = send_sock.recv_from(&mut wi).await.unwrap();
        hi.read_message(&wi[..n], &mut pi).unwrap();
        // -> s, se
        let n = hi.write_message(b"", &mut wi).unwrap();
        send_sock.send_to(&wi[..n], proxy_addr).await.unwrap();
        let (n, _) = recv_sock.recv_from(&mut wi).await.unwrap();
        hr.read_message(&wi[..n], &mut pi).unwrap();
        let mut ti = noise::into_transport(hi).unwrap();
        let mut tr = noise::into_transport(hr).unwrap();

        // 1 MiB + tail: 65 chunks — one window and a bit, with an odd tail.
        let mut data = vec![0u8; 1024 * 1024 + 123];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let dir = std::env::temp_dir();
        let src_path = dir.join("noscat-xfer-src.bin");
        let dst_path = dir.join("noscat-xfer-dst.bin");
        tokio::fs::write(&src_path, &data).await.unwrap();
        let len = data.len() as u64;
        let total = len.div_ceil(CHUNK as u64) as u32;

        let mut src = tokio::fs::File::open(&src_path).await.unwrap();
        let mut dst = tokio::fs::File::create(&dst_path).await.unwrap();
        let sender = tokio::spawn(async move {
            stream_chunks(&send_sock, proxy_addr, &mut ti, total, len, &mut src, 0)
                .await
                .unwrap();
        });
        let mut history: VecDeque<Vec<u8>> = VecDeque::new();
        let mut hasher = {
            use sha2::Digest as _;
            sha2::Sha256::new()
        };
        let got = receive_chunks(
            &recv_sock,
            proxy_addr,
            &mut tr,
            len,
            &mut dst,
            &mut history,
            &mut hasher,
            None,
            0,
        )
        .await
        .unwrap();
        sender.await.unwrap();
        proxy.abort();

        assert_eq!(got, len);
        let written = tokio::fs::read(&dst_path).await.unwrap();
        assert_eq!(written, data);
        let _ = tokio::fs::remove_file(&src_path).await;
        let _ = tokio::fs::remove_file(&dst_path).await;
    }

    /// Handshake two sockets directly (no relay, no traversal) and return
    /// them plus their transport states and addresses, ready for
    /// `send_stream`/`receive_stream`.
    async fn handshake_pair() -> (
        UdpSocket,
        UdpSocket,
        snow::TransportState,
        snow::TransportState,
        SocketAddr,
        SocketAddr,
    ) {
        let send_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let recv_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        for s in [&send_sock, &recv_sock] {
            tune_buffers(s);
            s.set_nonblocking(true).unwrap();
        }
        let send_sock = UdpSocket::from_std(send_sock).unwrap();
        let recv_sock = UdpSocket::from_std(recv_sock).unwrap();
        let saddr = send_sock.local_addr().unwrap();
        let raddr = recv_sock.local_addr().unwrap();

        let ipriv = [7u8; 32];
        let rpriv = [9u8; 32];
        let mut hi = noise::initiator(&ipriv, &noise::noise_public(&rpriv), None).unwrap();
        let mut hr = noise::responder(&rpriv, None).unwrap();
        let mut wi = [0u8; BUF];
        let mut pi = [0u8; BUF];
        // -> e
        let n = hi.write_message(b"", &mut wi).unwrap();
        send_sock.send_to(&wi[..n], raddr).await.unwrap();
        let (n, _) = recv_sock.recv_from(&mut wi).await.unwrap();
        hr.read_message(&wi[..n], &mut pi).unwrap();
        // <- e, ee, s, er
        let n = hr.write_message(b"", &mut wi).unwrap();
        recv_sock.send_to(&wi[..n], saddr).await.unwrap();
        let (n, _) = send_sock.recv_from(&mut wi).await.unwrap();
        hi.read_message(&wi[..n], &mut pi).unwrap();
        // -> s, se
        let n = hi.write_message(b"", &mut wi).unwrap();
        send_sock.send_to(&wi[..n], raddr).await.unwrap();
        let (n, _) = recv_sock.recv_from(&mut wi).await.unwrap();
        hr.read_message(&wi[..n], &mut pi).unwrap();
        let ti = noise::into_transport(hi).unwrap();
        let tr = noise::into_transport(hr).unwrap();
        (send_sock, recv_sock, ti, tr, saddr, raddr)
    }

    fn sha256_hex(data: &[u8]) -> String {
        use sha2::Digest;
        hex::encode(sha2::Sha256::digest(data))
    }

    /// An interrupted transfer's receiver state — a partial file plus a
    /// sidecar naming the transfer identity (len + sha256) and the acked
    /// chunk count — makes the next attempt start where the last one
    /// stopped: the sender is told to skip the acked chunks, the prefix is
    /// folded into the hash, and the finished file is byte-identical. A
    /// sidecar from a *different* file must not be resumed onto.
    #[tokio::test]
    async fn transfer_resumes_from_receiver_partial() {
        // 3 windows + a tail: enough for the partial to cover several
        // window-boundary acks.
        let mut data = vec![0u8; 3 * 32 * CHUNK + 777];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let len = data.len() as u64;
        let total = len.div_ceil(CHUNK as u64) as u32;
        let dir = std::env::temp_dir();
        let src_path = dir.join("noscat-resume-src.bin");
        let out_dir = dir.join("noscat-resume-out");
        let _ = tokio::fs::remove_dir_all(&out_dir).await;
        tokio::fs::create_dir_all(&out_dir).await.unwrap();
        tokio::fs::write(&src_path, &data).await.unwrap();
        let name = sanitize_name("resume-target.bin").unwrap();
        let part_path = out_dir.join(format!("{}.noscat-part", name.display()));
        let meta_path = out_dir.join(format!("{}.noscat-part.meta", name.display()));
        use sha2::Digest;
        let sha_bytes: [u8; 32] = sha2::Sha256::digest(&data).into();
        let sha = hex::encode(sha_bytes);

        // Receiver state from the interrupted attempt: a bit past two window
        // boundaries are on disk and acked.
        let cut = (2 * WINDOW as usize + 17) * CHUNK;
        tokio::fs::write(&part_path, &data[..cut]).await.unwrap();
        tokio::fs::write(
            &meta_path,
            serde_json::to_vec(&ResumeMeta {
                len,
                sha256: sha.clone(),
                chunks: cut as u64 / CHUNK as u64,
            })
            .unwrap(),
        )
        .await
        .unwrap();

        let (send_sock, recv_sock, mut ti, mut tr, saddr, raddr) = handshake_pair().await;

        let src_path2 = src_path.clone();
        let name2 = name.clone();
        let sender = tokio::spawn(async move {
            send_stream(&send_sock, raddr, &mut ti, &src_path2, &name2, &sha_bytes).await
        });
        let out_dir2 = out_dir.clone();
        let receiver =
            tokio::spawn(async move { receive_stream("peer", &recv_sock, saddr, &mut tr, &out_dir2).await });
        let (sent, got) = tokio::join!(sender, receiver);
        sent.unwrap().unwrap();
        let (_, path) = got.unwrap().unwrap();
        assert_eq!(path, out_dir.join(&name), "completed transfer must be at the final name");
        let finished = tokio::fs::read(&path).await.unwrap();
        assert_eq!(finished, data, "resumed file must be byte-identical");
        assert!(!part_path.exists(), "partial must be renamed away");
        assert!(!meta_path.exists(), "sidecar must be removed on completion");
        let _ = tokio::fs::remove_file(&src_path).await;
        let _ = tokio::fs::remove_dir_all(&out_dir).await;
        let _ = total;
    }

    /// A sidecar recording a *different* file (stale sha256 — e.g. the source
    /// changed between attempts) must be discarded, not resumed onto: the
    /// transfer starts from scratch and still produces the correct file.
    #[tokio::test]
    async fn resume_rejects_mismatched_sidecar() {
        let mut data = vec![0u8; 2 * 32 * CHUNK + 5];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i % 253) as u8;
        }
        let len = data.len() as u64;
        let dir = std::env::temp_dir();
        let src_path = dir.join("noscat-resume2-src.bin");
        let out_dir = dir.join("noscat-resume2-out");
        let _ = tokio::fs::remove_dir_all(&out_dir).await;
        tokio::fs::create_dir_all(&out_dir).await.unwrap();
        tokio::fs::write(&src_path, &data).await.unwrap();
        let name = sanitize_name("resume2-target.bin").unwrap();
        let part_path = out_dir.join(format!("{}.noscat-part", name.display()));
        let meta_path = out_dir.join(format!("{}.noscat-part.meta", name.display()));

        // The stale attempt: same length, wrong content (half zeros).
        let stale = {
            let mut d = data.clone();
            let half = d.len() / 2;
            d[..half].fill(0);
            d
        };
        let cut = (WINDOW as usize) * CHUNK;
        tokio::fs::write(&part_path, &stale[..cut]).await.unwrap();
        tokio::fs::write(
            &meta_path,
            serde_json::to_vec(&ResumeMeta {
                len,
                sha256: sha256_hex(&stale),
                chunks: cut as u64 / CHUNK as u64,
            })
            .unwrap(),
        )
        .await
        .unwrap();

        let (send_sock, recv_sock, mut ti, mut tr, saddr, raddr) = handshake_pair().await;
        let sha_bytes: [u8; 32] = {
            use sha2::Digest;
            sha2::Sha256::digest(&data).into()
        };

        let src_path2 = src_path.clone();
        let name2 = name.clone();
        let sender = tokio::spawn(async move {
            send_stream(&send_sock, raddr, &mut ti, &src_path2, &name2, &sha_bytes).await
        });
        let out_dir2 = out_dir.clone();
        let receiver =
            tokio::spawn(async move { receive_stream("peer", &recv_sock, saddr, &mut tr, &out_dir2).await });
        let (sent, got) = tokio::join!(sender, receiver);
        sent.unwrap().unwrap();
        let (_, path) = got.unwrap().unwrap();
        assert_eq!(path, out_dir.join(&name));
        let finished = tokio::fs::read(&path).await.unwrap();
        assert_eq!(finished, data, "a mismatched sidecar must trigger a fresh transfer");
        let _ = tokio::fs::remove_file(&src_path).await;
        let _ = tokio::fs::remove_dir_all(&out_dir).await;
        let _ = len;
    }
}
