//! netrig device: noscat-core's Dataplane and Streams, one process per
//! network namespace, so the rig tests the code that ships.
//!
//! Adverts are exchanged through files in $SHARED, standing in for delivery
//! inside the Marmot group (ADR 0006). Every 2 s the node probes each peer
//! (`Streams::probe`, a real end-to-end round trip) and prints one status
//! line per peer. With QUIC_TO=<peer name>, once that peer answers, the
//! node sends QUIC_MIB MiB to it over a QUIC stream and prints a RESULT
//! quic line; every node serves (reads everything, replies with sha256).
//!
//! env: NAME, PEERS (comma list of names), SHARED, STUN (optional),
//!      BIND (default 0.0.0.0:2121), DURATION_SECS (default 60),
//!      PUBLIC (yes: reachable), QUIC_TO, QUIC_MIB (default 16),
//!      QUIC_WAIT_DIRECT (yes: wait for a direct link before sending)

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use noscat_core::Identity;
use noscat_core::dataplane::{Dataplane, DataplaneConfig, Member, Reachability};
use noscat_core::streams::Streams;
use nostr::prelude::PublicKey;
use sha2::{Digest, Sha256};

fn env(k: &str, d: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| d.to_string())
}

fn write_atomic(path: &str, data: &str) -> Result<()> {
    let tmp = format!("{path}.tmp");
    std::fs::write(&tmp, data)?;
    std::fs::rename(tmp, path)?;
    Ok(())
}

async fn serve(streams: Arc<Streams>) {
    while let Some(conn) = streams.accept().await {
        tokio::spawn(async move {
            while let Ok((mut send, mut recv)) = conn.inner.accept_bi().await {
                let mut h = Sha256::new();
                let mut buf = vec![0u8; 1 << 16];
                while let Ok(Some(n)) = recv.read(&mut buf).await {
                    h.update(&buf[..n]);
                }
                let _ = send.write_all(&h.finalize()).await;
                let _ = send.finish();
                let _ = send.stopped().await;
            }
        });
    }
}

async fn transfer(streams: Arc<Streams>, peer: PublicKey, mib: usize) -> Result<String> {
    let hs = Instant::now();
    let conn = streams.connect(peer, Duration::from_secs(20)).await?;
    let handshake_ms = hs.elapsed().as_millis();
    let mut data = vec![0u8; mib << 20];
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    for c in data.chunks_mut(8) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        c.copy_from_slice(&x.to_le_bytes()[..c.len()]);
    }
    let want = Sha256::digest(&data);
    let st = Instant::now();
    let (mut s, mut r) = conn.inner.open_bi().await?;
    s.write_all(&data).await?;
    s.finish()?;
    let got = r.read_to_end(64).await?;
    let secs = st.elapsed().as_secs_f64();
    anyhow::ensure!(got.as_slice() == want.as_slice(), "sha256 mismatch");
    let stats = conn.inner.stats();
    conn.inner.close(0u32.into(), b"done");
    Ok(format!(
        "ok secs={secs:.2} mbit={:.1} handshake_ms={handshake_ms} rtt_ms={} lost_pct={:.2}",
        (mib << 20) as f64 * 8.0 / secs / 1e6,
        stats.path.rtt.as_millis(),
        stats.path.lost_packets as f64 * 100.0 / stats.udp_tx.datagrams.max(1) as f64
    ))
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_ansi(false)
        .init();
    let name = env("NAME", "x");
    let shared = env("SHARED", "/shared");
    let peers: Vec<String> = env("PEERS", "")
        .split(',')
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();
    let duration = Duration::from_secs(env("DURATION_SECS", "60").parse()?);

    let id = Identity::generate();
    let cfg = DataplaneConfig {
        bind: env("BIND", "0.0.0.0:2121").parse()?,
        reachability: if env("PUBLIC", "no") == "yes" {
            Reachability::Public {
                external_addr: None,
            }
        } else {
            Reachability::BehindNat
        },
        stun_servers: Some(std::env::var("STUN").ok().into_iter().collect()),
        lan_discovery: false,
    };
    let dp = Arc::new(Dataplane::start(&id, cfg).await.context("dataplane")?);
    let streams = Arc::new(Streams::start(dp.clone()).await.context("streams")?);
    write_atomic(&format!("{shared}/{name}.npub"), &id.public_key().to_hex())?;
    println!("[{name}] up {}", id.npub());

    // wait for every peer's key, then admit them
    let mut devices: HashMap<String, PublicKey> = HashMap::new();
    while devices.len() < peers.len() {
        for p in &peers {
            if let Ok(k) = std::fs::read_to_string(format!("{shared}/{p}.npub")) {
                if let Ok(k) = PublicKey::parse(k.trim()) {
                    devices.insert(p.clone(), k);
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let members: Vec<Member> = devices.values().map(|d| Member::new(*d)).collect();
    let keys: Vec<PublicKey> = devices.values().copied().collect();
    streams.retain_members(&keys).await;
    dp.set_members(&members).await?;
    tokio::spawn(serve(streams.clone()));

    let quic_to = std::env::var("QUIC_TO")
        .ok()
        .and_then(|p| devices.get(&p).map(|k| (p, *k)));
    let quic_mib: usize = env("QUIC_MIB", "16").parse()?;
    let wait_direct = env("QUIC_WAIT_DIRECT", "no") == "yes";
    let quic_result: Arc<Mutex<Option<String>>> = Arc::default();
    let mut quic_started = false;

    let start = Instant::now();
    let mut first_ok: HashMap<String, f64> = HashMap::new();
    while start.elapsed() < duration {
        let tick = Instant::now();
        // adverts out and in
        if let Ok(Some(json)) = dp.local_advert().await {
            let _ = write_atomic(&format!("{shared}/{name}.advert.json"), &json);
        }
        for p in &peers {
            if let Ok(json) = std::fs::read_to_string(format!("{shared}/{p}.advert.json")) {
                let _ = dp.ingest_advert(&json).await;
            }
        }
        // probe every peer concurrently
        let probes: Vec<_> = devices
            .iter()
            .map(|(pname, k)| {
                let (streams, pname, k) = (streams.clone(), pname.clone(), *k);
                tokio::spawn(async move {
                    let t = Instant::now();
                    let ok = streams.probe(k, Duration::from_millis(1500)).await.is_ok();
                    (pname, ok.then(|| t.elapsed().as_millis()))
                })
            })
            .collect();
        let mut rtts = HashMap::new();
        for p in probes {
            if let Ok((pname, rtt)) = p.await {
                rtts.insert(pname, rtt);
            }
        }
        let links = dp.peers().await.unwrap_or_default();
        let t = start.elapsed().as_secs_f64();
        for (pname, k) in &devices {
            let link = links.iter().find(|l| l.device == *k);
            let rtt = rtts.get(pname).copied().flatten();
            if rtt.is_some() {
                first_ok.entry(pname.clone()).or_insert(t);
                let direct = link.is_some_and(|l| l.direct);
                if !quic_started
                    && (!wait_direct || direct)
                    && quic_to.as_ref().is_some_and(|(p, _)| p == pname)
                {
                    quic_started = true;
                    let (streams, res, peer) = (streams.clone(), quic_result.clone(), *k);
                    let label = format!("{name}->{pname}");
                    tokio::spawn(async move {
                        let line = match transfer(streams, peer, quic_mib).await {
                            Ok(s) => format!("RESULT quic {label} mib={quic_mib} {s}"),
                            Err(e) => format!("RESULT quic {label} mib={quic_mib} failed: {e:#}"),
                        };
                        println!("{line}");
                        *res.lock().unwrap() = Some(line);
                    });
                }
            }
            println!(
                "t={t:5.1} {name}->{pname} ping={} link={} via={}",
                rtt.map_or_else(|| "--".into(), |r| format!("ok/{r}ms")),
                link.is_some_and(|l| l.direct),
                link.and_then(|l| l.remote.clone())
                    .unwrap_or_else(|| "-".into()),
            );
        }
        tokio::time::sleep(Duration::from_secs(2).saturating_sub(tick.elapsed())).await;
    }
    if let Some((p, _)) = &quic_to {
        if quic_result.lock().unwrap().is_none() {
            println!("RESULT quic {name}->{p} mib={quic_mib} unfinished");
        }
    }
    for p in &peers {
        println!(
            "RESULT {name}->{p} first_ping_ok_at={}",
            first_ok
                .get(p)
                .map_or_else(|| "never".into(), |t| format!("{t:.1}s"))
        );
    }
    streams.close();
    dp.shutdown().await.ok();
    Ok(())
}
