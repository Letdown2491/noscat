//! Reliable streams: QUIC (quinn) over FIPS service datagrams (ADR 0003).
//!
//! One quinn endpoint per device serves and dials on a single FIPS service
//! port. quinn sees each member as a synthetic `fd00::` socket address; this
//! module maps those back to devices.
//!
//! Peer identity comes from FIPS, not from TLS: every datagram's source is
//! the member whose FIPS session (Noise XK, end to end) carried it, and the
//! data plane only admits members. A QUIC connection is therefore with the
//! device its address maps to. TLS adds per-connection keys; its certificate
//! names the device (checked by the dialer) only as a guard against
//! mis-routing, not as the authentication.
//!
//! Before dialing, `connect` pings the member on a probe port until it
//! answers. That waits out FIPS session setup, which drops the first
//! datagram to a new peer (it would otherwise cost QUIC a 1 s retransmit),
//! and turns "member offline" into a prompt error.

use nostr::nips::nip19::ToBech32 as _;
use std::collections::HashMap;
use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::{Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use nostr::prelude::PublicKey;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::sync::{Notify, mpsc};

use crate::dataplane::{Datagram, Dataplane, DataplaneError};

/// FIPS service port carrying QUIC.
pub const QUIC_PORT: u16 = 4433;
/// FIPS service port for readiness probes.
pub const PROBE_PORT: u16 = 4434;
/// QUIC UDP payload: QUIC's floor, which every FIPS path carries at
/// `dataplane::FIPS_UDP_MTU`.
const QUIC_MTU: u16 = 1200;
const _: () = assert!(QUIC_MTU as usize <= crate::dataplane::MAX_DATAGRAM);
const PSEUDO_PORT: u16 = 443;
const SERVER_NAME: &str = "noscat";

/// A device's TLS name: its 64-char hex key as two 32-char DNS labels
/// (a single label may not exceed 63).
fn device_name(device: &PublicKey) -> String {
    let hex = device.to_hex();
    format!("{}.{}", &hex[..32], &hex[32..])
}

/// Errors from the stream layer.
#[derive(Debug, thiserror::Error)]
pub enum StreamsError {
    #[error(transparent)]
    Dataplane(#[from] DataplaneError),
    #[error("{0} did not answer (offline, unreachable, or not a member)")]
    Unreachable(String),
    #[error("quic: {0}")]
    Quic(String),
    #[error("tls: {0}")]
    Tls(String),
}

fn quic_err(e: impl fmt::Display) -> StreamsError {
    StreamsError::Quic(e.to_string())
}

/// Device <-> synthetic socket address, stable for the process lifetime.
#[derive(Default)]
struct Book {
    by_device: HashMap<PublicKey, SocketAddr>,
    by_addr: HashMap<SocketAddr, PublicKey>,
}

impl Book {
    fn addr(&mut self, device: PublicKey) -> SocketAddr {
        if let Some(a) = self.by_device.get(&device) {
            return *a;
        }
        let n = u32::try_from(self.by_device.len() + 1).unwrap_or(u32::MAX);
        #[allow(clippy::cast_possible_truncation)]
        let ip = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, (n >> 16) as u16, n as u16);
        let a = SocketAddr::new(ip.into(), PSEUDO_PORT);
        self.by_device.insert(device, a);
        self.by_addr.insert(a, device);
        a
    }
}

/// quinn socket backed by a FIPS service port.
struct FipsSocket {
    dp: Arc<Dataplane>,
    book: Arc<Mutex<Book>>,
    rx: Mutex<mpsc::Receiver<(SocketAddr, Vec<u8>)>>,
}

impl fmt::Debug for FipsSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FipsSocket")
    }
}

#[derive(Debug)]
struct AlwaysWritable;

impl UdpPoller for AlwaysWritable {
    fn poll_writable(self: Pin<&mut Self>, _: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncUdpSocket for FipsSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(AlwaysWritable)
    }

    // quinn calls this holding its connection lock: the book lock taken
    // here must never be held by anyone calling into quinn.
    fn try_send(&self, t: &Transmit) -> io::Result<()> {
        let to = self
            .book
            .lock()
            .ok()
            .and_then(|b| b.by_addr.get(&t.destination).copied());
        let Some(to) = to else {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "unknown member",
            ));
        };
        // A datagram FIPS cannot take is a lost packet; QUIC recovers.
        let _ = self.dp.send_now(&to, QUIC_PORT, t.contents.to_vec());
        Ok(())
    }

    #[allow(clippy::field_reassign_with_default)] // RecvMeta is #[non_exhaustive]
    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let Ok(mut rx) = self.rx.lock() else {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        };
        let mut n = 0;
        while n < bufs.len().min(meta.len()) {
            let (from, data) = if n == 0 {
                match rx.poll_recv(cx) {
                    Poll::Ready(Some(x)) => x,
                    Poll::Ready(None) => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
                    Poll::Pending => return Poll::Pending,
                }
            } else {
                match rx.try_recv() {
                    Ok(x) => x,
                    Err(_) => break,
                }
            };
            let len = data.len().min(bufs[n].len());
            bufs[n][..len].copy_from_slice(&data[..len]);
            // RecvMeta is #[non_exhaustive]: start from Default, then fill.
            let mut m = RecvMeta::default();
            m.addr = from;
            m.len = len;
            m.stride = len;
            meta[n] = m;
            n += 1;
        }
        Poll::Ready(Ok(n))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(SocketAddr::new(
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0xffff, 0xffff).into(),
            PSEUDO_PORT,
        ))
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

fn transport_config() -> Arc<quinn::TransportConfig> {
    let mut t = quinn::TransportConfig::default();
    t.initial_mtu(QUIC_MTU)
        .min_mtu(QUIC_MTU)
        .mtu_discovery_config(None);
    t.stream_receive_window((16u32 << 20).into());
    t.receive_window((32u32 << 20).into());
    t.send_window(32 << 20);
    t.keep_alive_interval(Some(Duration::from_secs(10)));
    // BBR: Cubic on 1200-byte packets is bounded by random loss (ADR 0003).
    t.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    Arc::new(t)
}

/// Accepts the certificate if it names the expected device. See the module
/// docs: authentication is FIPS's job; this only catches mis-routing.
#[derive(Debug)]
struct NamesDevice {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for NamesDevice {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // The dialer puts the device's name (`device_name`) in the SNI, and
        // every device's certificate carries its own name as its only SAN. A
        // byte search is enough for a mis-routing guard (65 bytes of hex and
        // a dot cannot appear in the DER by accident) and avoids an X.509
        // parser.
        let rustls::pki_types::ServerName::DnsName(name) = server_name else {
            return Err(rustls::Error::General("unexpected server name".into()));
        };
        let name = name.as_ref().as_bytes();
        if name.len() == 65 && end_entity.as_ref().windows(65).any(|w| w == name) {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "certificate names another device".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            m,
            c,
            d,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            m,
            c,
            d,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A QUIC connection with a member.
#[derive(Debug, Clone)]
pub struct Connection {
    pub peer: PublicKey,
    pub inner: quinn::Connection,
}

/// Counts an incoming handshake for its member while alive.
struct HandshakeGuard<'a> {
    map: &'a Mutex<HashMap<PublicKey, usize>>,
    peer: PublicKey,
}

impl<'a> HandshakeGuard<'a> {
    fn new(map: &'a Mutex<HashMap<PublicKey, usize>>, peer: PublicKey) -> Self {
        if let Ok(mut m) = map.lock() {
            *m.entry(peer).or_default() += 1;
        }
        Self { map, peer }
    }
}

impl Drop for HandshakeGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut m) = self.map.lock()
            && let Some(n) = m.get_mut(&self.peer)
        {
            *n = n.saturating_sub(1);
        }
    }
}

/// Probe replies: device -> waiters.
type ProbeWaiters = Arc<Mutex<HashMap<PublicKey, Arc<Notify>>>>;

/// The stream layer for one device.
pub struct Streams {
    dp: Arc<Dataplane>,
    endpoint: quinn::Endpoint,
    book: Arc<Mutex<Book>>,
    probes: ProbeWaiters,
    live: Mutex<HashMap<PublicKey, Vec<quinn::Connection>>>,
    /// Members allowed to hold connections; `None` until first set.
    allowed: Mutex<Option<std::collections::HashSet<PublicKey>>>,
    /// Incoming handshakes in progress, per member.
    handshaking: Mutex<HashMap<PublicKey, usize>>,
    /// `accept` closed a connection from a non-member since the last
    /// `retain_members` (its close frame may still be leaving).
    refused: std::sync::atomic::AtomicBool,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl fmt::Debug for Streams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Streams")
            .field("device", &self.dp.device())
            .finish_non_exhaustive()
    }
}

impl Drop for Streams {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

const PROBE_REQ: u8 = b'?';
const PROBE_ACK: u8 = b'!';

impl Streams {
    /// Bind the QUIC and probe ports on `dp`.
    pub async fn start(dp: Arc<Dataplane>) -> Result<Self, StreamsError> {
        let book = Arc::new(Mutex::new(Book::default()));
        let mut tasks = Vec::new();

        // QUIC port pump: FIPS receiver -> channel polled by quinn.
        let mut quic_rx = dp.bind_port(QUIC_PORT).await?;
        let (tx, rx) = mpsc::channel(8192);
        {
            let book = book.clone();
            tasks.push(tokio::spawn(async move {
                let mut batch: Vec<Datagram> = Vec::new();
                while quic_rx.recv_batch(&mut batch, 128).await.is_some() {
                    for d in batch.drain(..) {
                        let Ok(mut b) = book.lock() else { return };
                        let from = b.addr(d.from);
                        drop(b);
                        // Full queue: drop, as a full socket buffer would.
                        let _ = tx.try_send((from, d.data));
                    }
                }
            }));
        }

        // Probe port: answer requests, wake waiters on acks.
        let probes: ProbeWaiters = Arc::default();
        let mut probe_rx = dp.bind_port(PROBE_PORT).await?;
        {
            let (dp, probes) = (dp.clone(), probes.clone());
            tasks.push(tokio::spawn(async move {
                let mut batch: Vec<Datagram> = Vec::new();
                while probe_rx.recv_batch(&mut batch, 64).await.is_some() {
                    for d in batch.drain(..) {
                        match d.data.first() {
                            Some(&PROBE_REQ) => {
                                let _ = dp.send_now(&d.from, PROBE_PORT, vec![PROBE_ACK]);
                            }
                            Some(&PROBE_ACK) => {
                                if let Some(n) =
                                    probes.lock().ok().and_then(|p| p.get(&d.from).cloned())
                                {
                                    n.notify_waiters();
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }));
        }

        let socket = Arc::new(FipsSocket {
            dp: dp.clone(),
            book: book.clone(),
            rx: Mutex::new(rx),
        });
        let endpoint = Self::endpoint(&dp, socket)?;
        Ok(Self {
            dp,
            endpoint,
            book,
            probes,
            live: Mutex::new(HashMap::new()),
            allowed: Mutex::new(None),
            handshaking: Mutex::new(HashMap::new()),
            refused: std::sync::atomic::AtomicBool::new(false),
            tasks,
        })
    }

    fn endpoint(dp: &Dataplane, socket: Arc<FipsSocket>) -> Result<quinn::Endpoint, StreamsError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let me = device_name(&dp.device());

        let ck = rcgen::generate_simple_self_signed(vec![me.clone()])
            .map_err(|e| StreamsError::Tls(e.to_string()))?;
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der());
        let mut server_tls = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| StreamsError::Tls(e.to_string()))?
            .with_no_client_auth()
            .with_single_cert(vec![ck.cert.der().clone()], key.into())
            .map_err(|e| StreamsError::Tls(e.to_string()))?;
        server_tls.alpn_protocols = vec![SERVER_NAME.as_bytes().to_vec()];
        let server_crypto =
            quinn::crypto::rustls::QuicServerConfig::try_from(server_tls).map_err(quic_err)?;
        let mut server = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));
        server.transport_config(transport_config());

        let mut client_tls = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| StreamsError::Tls(e.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NamesDevice { provider }))
            .with_no_client_auth();
        client_tls.alpn_protocols = vec![SERVER_NAME.as_bytes().to_vec()];
        let client_crypto =
            quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).map_err(quic_err)?;
        let mut client = quinn::ClientConfig::new(Arc::new(client_crypto));
        client.transport_config(transport_config());

        let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(server),
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(quic_err)?;
        endpoint.set_default_client_config(client);
        Ok(endpoint)
    }

    /// Wait until `peer` answers a probe, retrying every 200 ms.
    pub async fn probe(&self, peer: PublicKey, timeout: Duration) -> Result<(), StreamsError> {
        let notify = {
            let mut p = self
                .probes
                .lock()
                .map_err(|_| StreamsError::Quic("probe lock poisoned".into()))?;
            p.entry(peer)
                .or_insert_with(|| Arc::new(Notify::new()))
                .clone()
        };
        let attempt = async {
            loop {
                let woken = notify.notified();
                tokio::pin!(woken);
                woken.as_mut().enable();
                let _ = self.dp.send_now(&peer, PROBE_PORT, vec![PROBE_REQ]);
                if tokio::time::timeout(Duration::from_millis(200), woken)
                    .await
                    .is_ok()
                {
                    return;
                }
            }
        };
        tokio::time::timeout(timeout, attempt)
            .await
            .map_err(|_| StreamsError::Unreachable(peer.to_bech32().unwrap_or_else(|_| peer.to_hex())))
    }

    /// Open a QUIC connection to a member. Waits up to `timeout` for the
    /// member to become reachable.
    pub async fn connect(
        &self,
        peer: PublicKey,
        timeout: Duration,
    ) -> Result<Connection, StreamsError> {
        if !self.is_allowed(&peer) {
            return Err(StreamsError::Unreachable(peer.to_bech32().unwrap_or_else(|_| peer.to_hex())));
        }
        self.probe(peer, timeout).await?;
        let addr = self
            .book
            .lock()
            .map_err(|_| StreamsError::Quic("book lock poisoned".into()))?
            .addr(peer);
        let inner = self
            .endpoint
            .connect(addr, &device_name(&peer))
            .map_err(quic_err)?
            .await
            .map_err(quic_err)?;
        self.track(peer, &inner);
        Ok(Connection { peer, inner })
    }

    fn track(&self, peer: PublicKey, conn: &quinn::Connection) {
        if let Ok(mut live) = self.live.lock() {
            let v = live.entry(peer).or_default();
            v.retain(|c| c.close_reason().is_none());
            v.push(conn.clone());
        }
    }

    fn refused_since_last_retain(&self) -> bool {
        self.refused
            .swap(false, std::sync::atomic::Ordering::SeqCst)
    }

    fn is_allowed(&self, peer: &PublicKey) -> bool {
        self.allowed
            .lock()
            .is_ok_and(|a| a.as_ref().is_none_or(|set| set.contains(peer)))
    }

    /// Restrict connections to `members`: close every connection with
    /// anyone else, and refuse their late-arriving handshakes in
    /// [`Self::accept`]. When removing a member, call this *before*
    /// [`Dataplane::set_members`]: the close frame needs the member's
    /// session to reach it, and without it the member's side of an open
    /// connection lingers until its idle timeout.
    pub async fn retain_members(&self, members: &[PublicKey]) {
        let set: std::collections::HashSet<PublicKey> = members.iter().copied().collect();
        if let Ok(mut a) = self.allowed.lock() {
            *a = Some(set.clone());
        }
        // A handshake from a removed member that is already under way
        // finishes in about one round trip; `accept` then refuses it and
        // sends the close. Wait for that while the session still exists.
        for _ in 0..100 {
            let busy = self
                .handshaking
                .lock()
                .is_ok_and(|h| h.iter().any(|(p, n)| *n > 0 && !set.contains(p)));
            if !busy {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let mut closed_any = false;
        let removed: Vec<quinn::Connection> = self.live.lock().map_or_else(
            |_| Vec::new(),
            |mut live| {
                let gone: Vec<PublicKey> =
                    live.keys().filter(|p| !set.contains(p)).copied().collect();
                gone.iter()
                    .filter_map(|p| live.remove(p))
                    .flatten()
                    .collect()
            },
        );
        for c in &removed {
            c.close(2u32.into(), b"not a member");
            closed_any = true;
        }
        if !closed_any && !self.refused_since_last_retain() {
            return;
        }
        // quinn sends CONNECTION_CLOSE from its driver task; give it a
        // moment to leave before the caller tears the session down. The
        // frame needs no acknowledgement.
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    /// Next incoming connection, with the member it came from. `None` once
    /// the endpoint is closed.
    pub async fn accept(&self) -> Option<Connection> {
        let me = device_name(&self.dp.device());
        loop {
            let incoming = self.endpoint.accept().await?;
            // Never call into quinn while holding the book: quinn's
            // connection driver holds its connection lock while it calls
            // `try_send`, which takes the book (a lock-order deadlock).
            let addr = incoming.remote_address();
            let from = self.book.lock().ok().and_then(|b| b.by_addr.get(&addr).copied());
            if from.is_some_and(|p| !self.is_allowed(&p)) {
                incoming.refuse();
                continue;
            }
            let _guard = from.map(|p| HandshakeGuard::new(&self.handshaking, p));
            let Ok(conn) = incoming.await else { continue };
            // A dialer that asked for another device's name was mis-routed.
            let sni = conn
                .handshake_data()
                .and_then(|h| h.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
                .and_then(|h| h.server_name);
            if sni.as_deref() != Some(me.as_str()) {
                conn.close(1u32.into(), b"wrong device");
                continue;
            }
            let addr = conn.remote_address();
            let peer = self.book.lock().ok().and_then(|b| b.by_addr.get(&addr).copied());
            let Some(peer) = peer.filter(|p| self.is_allowed(p)) else {
                conn.close(2u32.into(), b"not a member");
                self.refused
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                continue;
            };
            self.track(peer, &conn);
            return Some(Connection { peer, inner: conn });
        }
    }

    /// Close every connection and stop accepting.
    pub fn close(&self) {
        self.endpoint.close(0u32.into(), b"bye");
    }
}
