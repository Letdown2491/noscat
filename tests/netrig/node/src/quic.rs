//! QUIC (quinn) over FIPS service datagrams: the Streams prototype from
//! ADR 0003. quinn sees each FIPS peer as a synthetic fd00:: socket address.
//! Not production code: the client accepts any server certificate (the real
//! design pins it to the peer's npub).

use std::collections::HashMap;
use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::{Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use fips_core::{FipsEndpoint, PeerIdentity};
use futures::FutureExt;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

pub const QUIC_PORT: u16 = 41_443;
const PSEUDO_PORT: u16 = 443;
const MTU: u16 = 1200;

/// FIPS peer <-> synthetic socket address. Process-local; quinn only needs
/// the mapping to be stable.
#[derive(Default)]
pub struct Book {
    by_npub: HashMap<String, SocketAddr>,
    by_addr: HashMap<SocketAddr, PeerIdentity>,
}
impl Book {
    pub fn addr(&mut self, p: PeerIdentity) -> SocketAddr {
        let n = p.npub();
        if let Some(a) = self.by_npub.get(&n) {
            return *a;
        }
        let i = self.by_npub.len() as u16 + 1;
        let a = SocketAddr::new(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, i).into(), PSEUDO_PORT);
        self.by_npub.insert(n, a);
        self.by_addr.insert(a, p);
        a
    }
}

pub struct FipsSocket {
    ep: Arc<FipsEndpoint>,
    book: Arc<Mutex<Book>>,
    rx: Mutex<mpsc::Receiver<(SocketAddr, Vec<u8>)>>,
    pub send_drops: AtomicU64,
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
    fn try_send(&self, t: &Transmit) -> io::Result<()> {
        let peer = self.book.lock().unwrap().by_addr.get(&t.destination).copied();
        let Some(peer) = peer else {
            return Err(io::Error::new(io::ErrorKind::AddrNotAvailable, "unknown peer"));
        };
        // send_datagram has no await points inside, so it completes on first poll.
        let sent = self
            .ep
            .send_datagram(peer, QUIC_PORT, QUIC_PORT, t.contents.to_vec())
            .now_or_never();
        if !matches!(sent, Some(Ok(()))) {
            self.send_drops.fetch_add(1, Ordering::Relaxed);
        }
        Ok(()) // UDP semantics: a drop is a loss, QUIC recovers
    }
    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut rx = self.rx.lock().unwrap();
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
        Ok(SocketAddr::new(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0xffff).into(), PSEUDO_PORT))
    }
    fn may_fragment(&self) -> bool {
        false
    }
}

pub async fn socket(ep: Arc<FipsEndpoint>, book: Arc<Mutex<Book>>) -> Result<Arc<FipsSocket>> {
    let recv = ep.register_service_receiver(QUIC_PORT).await?;
    let (tx, rx) = mpsc::channel(8192);
    let b = book.clone();
    tokio::spawn(async move {
        let mut batch = Vec::new();
        loop {
            batch.clear();
            if recv.recv_batch_into(&mut batch, 128).await.is_none() {
                return;
            }
            for d in batch.drain(..) {
                let from = b.lock().unwrap().addr(d.source_peer);
                let _ = tx.try_send((from, d.data.as_slice().to_vec())); // full: drop, like a socket buffer
            }
        }
    });
    Ok(Arc::new(FipsSocket { ep, book, rx: Mutex::new(rx), send_drops: AtomicU64::new(0) }))
}

fn transport() -> Arc<quinn::TransportConfig> {
    let mut t = quinn::TransportConfig::default();
    t.initial_mtu(MTU).min_mtu(MTU).mtu_discovery_config(None);
    t.stream_receive_window((16u32 << 20).into());
    t.receive_window((32u32 << 20).into());
    t.send_window(32 << 20);
    t.keep_alive_interval(Some(Duration::from_secs(5)));
    if std::env::var("CC").as_deref() != Ok("cubic") {
        t.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    }
    Arc::new(t)
}

#[derive(Debug)]
struct AcceptAny(Arc<rustls::crypto::CryptoProvider>);
impl rustls::client::danger::ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// One quinn endpoint per node, serving and dialing on the same FIPS socket
/// (two endpoints on one socket would steal each other's packets).
pub fn endpoint(sock: Arc<FipsSocket>) -> Result<quinn::Endpoint> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ck = rcgen::generate_simple_self_signed(vec!["noscat".into()])?;
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der());
    let mut server = quinn::ServerConfig::with_single_cert(vec![ck.cert.der().clone()], key.into())?;
    server.transport_config(transport());

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let tls = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny(provider)))
        .with_no_client_auth();
    let mut client = quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(tls)?));
    client.transport_config(transport());

    let mut ep = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(server),
        sock,
        Arc::new(quinn::TokioRuntime),
    )?;
    ep.set_default_client_config(client);
    Ok(ep)
}

/// Accept connections forever; for each bidi stream, read to the end and
/// reply with the sha256 of what arrived.
pub async fn serve(ep: quinn::Endpoint) {
    while let Some(inc) = ep.accept().await {
        tokio::spawn(async move {
            let conn = inc.await?;
            while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                let mut h = Sha256::new();
                let mut buf = vec![0u8; 1 << 16];
                while let Some(n) = recv.read(&mut buf).await? {
                    h.update(&buf[..n]);
                }
                send.write_all(&h.finalize()).await?;
                send.finish()?;
                let _ = send.stopped().await;
            }
            anyhow::Ok(())
        });
    }
}

pub struct Transfer {
    pub handshake_ms: u128,
    pub secs: f64,
    pub mbit: f64,
    pub lost_pct: f64,
    pub rtt_ms: u128,
}

/// Connect to `peer`, send `mib` MiB on one bidi stream, check the sha256 reply.
pub async fn send(ep: quinn::Endpoint, book: Arc<Mutex<Book>>, peer: PeerIdentity, mib: usize) -> Result<Transfer> {
    let to = book.lock().unwrap().addr(peer);
    let hs = Instant::now();
    let conn = ep.connect(to, "noscat")?.await.context("quic connect")?;
    let handshake_ms = hs.elapsed().as_millis();

    let mut data = vec![0u8; mib << 20];
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    for c in data.chunks_mut(8) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        c.copy_from_slice(&x.to_le_bytes()[..c.len()]);
    }
    let want: [u8; 32] = Sha256::digest(&data).into();

    let st = Instant::now();
    let (mut s, mut r) = conn.open_bi().await?;
    s.write_all(&data).await?;
    s.finish()?;
    let got = r.read_to_end(64).await?;
    let secs = st.elapsed().as_secs_f64();
    if got.as_slice() != want {
        bail!("sha256 mismatch");
    }
    let stats = conn.stats();
    conn.close(0u32.into(), b"done");
    Ok(Transfer {
        handshake_ms,
        secs,
        mbit: (mib << 20) as f64 * 8.0 / secs / 1e6,
        lost_pct: stats.path.lost_packets as f64 * 100.0 / stats.udp_tx.datagrams.max(1) as f64,
        rtt_ms: stats.path.rtt.as_millis(),
    })
}
