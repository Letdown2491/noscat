//! First-contact experiment node. One process per network namespace.
//! External peerfinding: signed adverts are exchanged through files in
//! $SHARED (standing in for delivery inside the Marmot group), never relays.
//! Every node echoes pings on a FIPS service port and pings its peers,
//! printing one status line per peer every 2 s.
//!
//! With QUIC_TO=<peer name> and QUIC_MIB, once that peer answers a ping the
//! node sends QUIC_MIB MiB to it over QUIC (quic.rs) and prints a RESULT
//! quic line. Every node serves QUIC.
//!
//! env: NAME, PEERS (comma list of names), SHARED, STUN (optional),
//!      BIND (default 0.0.0.0:2121), DURATION_SECS (default 60), PUBLIC,
//!      QUIC_TO, QUIC_MIB (default 16), QUIC_WAIT_DIRECT (yes: wait for a
//!      direct link first), CC (bbr default, or cubic), FIPS_MTU (UDP link
//!      MTU), PROBE_SIZES (comma list of echo probe sizes)

mod quic;

use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use fips_core::config::{NostrPeerfindingSource, PeerConfig, TransportInstances};
use fips_core::{Config, FipsEndpoint, Identity, PeerIdentity, UdpConfig, encode_nsec};
use nostr::JsonUtil;

const PING_PORT: u16 = 41_000;
const PROBE_SIZES: &str = "256,512,768,1000,1100,1150,1200,1250,1300,1400,2000,8000";

fn env(k: &str, d: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| d.to_string())
}

fn write_atomic(path: &str, data: &str) -> Result<()> {
    let tmp = format!("{path}.tmp");
    std::fs::write(&tmp, data)?;
    std::fs::rename(tmp, path)?;
    Ok(())
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).with_ansi(false).init();
    let name = env("NAME", "x");
    let shared = env("SHARED", "/shared");
    let peers: Vec<String> = env("PEERS", "")
        .split(',')
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();
    let duration = Duration::from_secs(env("DURATION_SECS", "60").parse()?);

    let identity = Identity::generate();
    let mut config = Config::new();
    config.node.identity.nsec = Some(encode_nsec(&identity.keypair().secret_key()));
    config.node.control.enabled = false;
    config.node.discovery.lan.enabled = false;
    config.node.discovery.local.enabled = false;
    config.node.peer_admission.configured_only = true;
    let nd = &mut config.node.discovery.nostr;
    nd.enabled = true;
    nd.advertise = true;
    nd.peerfinding_source = NostrPeerfindingSource::External;
    nd.advert_relays = vec![];
    nd.stun_servers = std::env::var("STUN").ok().into_iter().collect();
    config.transports.udp = TransportInstances::Single(UdpConfig {
        bind_addr: Some(env("BIND", "0.0.0.0:2121")),
        advertise_on_nostr: Some(true),
        public: Some(env("PUBLIC", "no") == "yes"),
        mtu: std::env::var("FIPS_MTU").ok().and_then(|m| m.parse().ok()),
        ..UdpConfig::default()
    });
    let ep = FipsEndpoint::builder()
        .config(config)
        .without_system_tun()
        .bind()
        .await
        .context("bind")?;
    let me = ep.npub().to_string();
    write_atomic(&format!("{shared}/{name}.npub"), &me)?;
    println!("[{name}] up {me}");

    // wait for every peer's npub
    let mut npubs: HashMap<String, String> = HashMap::new();
    while npubs.len() < peers.len() {
        for p in &peers {
            if let Ok(n) = std::fs::read_to_string(format!("{shared}/{p}.npub")) {
                npubs.insert(p.clone(), n.trim().to_string());
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let configs = npubs
        .values()
        .map(|n| {
            let mut c = PeerConfig::new(n.clone(), "udp", "0.0.0.0:1");
            c.addresses.clear(); // resolve from adverts only
            c
        })
        .collect();
    ep.update_peers(configs).await?;

    // ping echo service
    let rx = std::sync::Arc::new(ep.register_service_receiver(PING_PORT).await?);
    let ep = std::sync::Arc::new(ep);
    let pongs: std::sync::Arc<std::sync::Mutex<HashMap<String, (u64, Instant)>>> = Default::default();
    // size probes: 'S' + u32 size + padding, echoed back as 's' + the same size
    let sizes_ok: std::sync::Arc<std::sync::Mutex<HashMap<String, std::collections::BTreeSet<u32>>>> = Default::default();
    {
        let (ep, rx, pongs, sizes_ok) = (ep.clone(), rx.clone(), pongs.clone(), sizes_ok.clone());
        tokio::spawn(async move {
            let mut batch = Vec::new();
            loop {
                batch.clear();
                if rx.recv_batch_into(&mut batch, 64).await.is_none() {
                    return;
                }
                for d in batch.drain(..) {
                    let data = d.data.as_slice().to_vec();
                    if data.first() == Some(&b'S') && data.len() >= 5 {
                        let mut reply = data.clone();
                        reply[0] = b's';
                        let _ = ep.send_datagram(d.source_peer, PING_PORT, PING_PORT, reply).await;
                    } else if data.first() == Some(&b's') && data.len() >= 5 {
                        let size = u32::from_be_bytes(data[1..5].try_into().unwrap());
                        if size as usize == data.len() {
                            sizes_ok.lock().unwrap().entry(d.source_peer.npub()).or_default().insert(size);
                        }
                    } else if data.first() == Some(&b'?') {
                        let mut reply = data.clone();
                        reply[0] = b'!';
                        let _ = ep.send_datagram(d.source_peer, PING_PORT, PING_PORT, reply).await;
                    } else if data.first() == Some(&b'!') && data.len() >= 9 {
                        let sent = u64::from_be_bytes(data[1..9].try_into().unwrap());
                        let rtt = (std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_millis() as u64)
                            .saturating_sub(sent);
                        pongs.lock().unwrap().insert(d.source_peer.npub(), (rtt, Instant::now()));
                    }
                }
            }
        });
    }

    // QUIC: every node serves; QUIC_TO starts a transfer once pings work
    let book = std::sync::Arc::new(std::sync::Mutex::new(quic::Book::default()));
    let qsock = quic::socket(ep.clone(), book.clone()).await?;
    let qep = quic::endpoint(qsock)?;
    tokio::spawn(quic::serve(qep.clone()));
    let quic_to = std::env::var("QUIC_TO").ok().and_then(|p| npubs.get(&p).map(|n| (p, n.clone())));
    let quic_mib: usize = env("QUIC_MIB", "16").parse()?;
    let quic_result: std::sync::Arc<std::sync::Mutex<Option<String>>> = Default::default();
    let mut quic_started = false;
    let quic_wait_direct = env("QUIC_WAIT_DIRECT", "no") == "yes";

    let probe_sizes: Vec<u32> = env("PROBE_SIZES", PROBE_SIZES).split(',').filter_map(|x| x.parse().ok()).collect();
    let start = Instant::now();
    let mut first_ok: HashMap<String, f64> = HashMap::new();
    while start.elapsed() < duration {
        // advert out
        if let Ok(Some(ev)) = ep.local_nostr_discovery_advert_event().await {
            let _ = write_atomic(&format!("{shared}/{name}.advert.json"), &ev.as_json());
        }
        // adverts in
        for p in &peers {
            if let Ok(s) = std::fs::read_to_string(format!("{shared}/{p}.advert.json")) {
                if let Ok(ev) = nostr::Event::from_json(s) {
                    let _ = ep.ingest_nostr_event(ev).await;
                }
            }
        }
        // pings
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis() as u64;
        for (pname, n) in &npubs {
            let mut msg = vec![b'?'];
            msg.extend_from_slice(&now_ms.to_be_bytes());
            if let Ok(id) = PeerIdentity::from_npub(n) {
                let _ = ep.send_datagram(id, PING_PORT, PING_PORT, msg).await;
                if first_ok.contains_key(pname) {
                    for size in &probe_sizes {
                        let size = *size;
                        let mut p = vec![0u8; size as usize];
                        p[0] = b'S';
                        p[1..5].copy_from_slice(&size.to_be_bytes());
                        let _ = ep.send_datagram(id, PING_PORT, PING_PORT, p).await;
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
        let status = ep.peers().await.unwrap_or_default();
        let t = start.elapsed().as_secs_f64();
        for (pname, n) in &npubs {
            let link = status.iter().find(|s| &s.npub == n);
            let pong = pongs.lock().unwrap().get(n).copied();
            let fresh = pong.filter(|(_, at)| at.elapsed() < Duration::from_secs(3));
            if fresh.is_some() {
                first_ok.entry(pname.clone()).or_insert(t);
                let direct_ok = !quic_wait_direct || link.is_some_and(|l| l.connected);
                if !quic_started && direct_ok && quic_to.as_ref().is_some_and(|(p, _)| p == pname) {
                    quic_started = true;
                    let (qep, book, res) = (qep.clone(), book.clone(), quic_result.clone());
                    let peer = PeerIdentity::from_npub(n)?;
                    let (label, mib) = (format!("{name}->{pname}"), quic_mib);
                    tokio::spawn(async move {
                        let line = match quic::send(qep, book, peer, mib).await {
                            Ok(r) => format!(
                                "RESULT quic {label} mib={mib} ok secs={:.2} mbit={:.1} handshake_ms={} rtt_ms={} lost_pct={:.2}",
                                r.secs, r.mbit, r.handshake_ms, r.rtt_ms, r.lost_pct
                            ),
                            Err(e) => format!("RESULT quic {label} mib={mib} failed: {e:#}"),
                        };
                        println!("{line}");
                        *res.lock().unwrap() = Some(line);
                    });
                }
            }
            println!(
                "t={t:5.1} {name}->{pname} ping={} link={} via={} route={}",
                fresh.map(|(r, _)| format!("ok/{r}ms")).unwrap_or_else(|| "--".into()),
                link.map(|l| l.connected).unwrap_or(false),
                link.and_then(|l| l.transport_addr.clone()).unwrap_or_else(|| "-".into()),
                link.and_then(|l| l.last_outbound_route.clone()).unwrap_or_else(|| "-".into()),
            );
        }
    }
    for (p, n) in &npubs {
        let ok = sizes_ok.lock().unwrap().get(n).cloned().unwrap_or_default();
        println!("RESULT size {name}->{p} echoed={ok:?}");
    }
    for p in &peers {
        println!(
            "RESULT {name}->{p} first_ping_ok_at={}",
            first_ok.get(p).map(|t| format!("{t:.1}s")).unwrap_or_else(|| "never".into())
        );
    }
    if let Some((p, _)) = &quic_to {
        if quic_result.lock().unwrap().is_none() {
            println!("RESULT quic {name}->{p} mib={quic_mib} unfinished");
        }
    }
    ep.shutdown().await.ok();
    Ok(())
}
