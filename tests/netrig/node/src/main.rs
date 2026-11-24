//! First-contact experiment node. One process per network namespace.
//! External peerfinding: signed adverts are exchanged through files in
//! $SHARED (standing in for delivery inside the Marmot group), never relays.
//! Every node echoes pings on a FIPS service port and pings its peers,
//! printing one status line per peer every 2 s.
//!
//! env: NAME, PEERS (comma list of names), SHARED, STUN (optional),
//!      BIND (default 0.0.0.0:2121), DURATION_SECS (default 60)

use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use fips_core::config::{NostrPeerfindingSource, PeerConfig, TransportInstances};
use fips_core::{Config, FipsEndpoint, Identity, PeerIdentity, UdpConfig, encode_nsec};
use nostr::JsonUtil;

const PING_PORT: u16 = 41_000;

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
    {
        let (ep, rx, pongs) = (ep.clone(), rx.clone(), pongs.clone());
        tokio::spawn(async move {
            let mut batch = Vec::new();
            loop {
                batch.clear();
                if rx.recv_batch_into(&mut batch, 64).await.is_none() {
                    return;
                }
                for d in batch.drain(..) {
                    let data = d.data.as_slice().to_vec();
                    if data.first() == Some(&b'?') {
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
        for (_, n) in &npubs {
            let mut msg = vec![b'?'];
            msg.extend_from_slice(&now_ms.to_be_bytes());
            if let Ok(id) = PeerIdentity::from_npub(n) {
                let _ = ep.send_datagram(id, PING_PORT, PING_PORT, msg).await;
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
    for p in &peers {
        println!(
            "RESULT {name}->{p} first_ping_ok_at={}",
            first_ok.get(p).map(|t| format!("{t:.1}s")).unwrap_or_else(|| "never".into())
        );
    }
    ep.shutdown().await.ok();
    Ok(())
}
