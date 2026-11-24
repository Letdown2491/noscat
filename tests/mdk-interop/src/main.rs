//! noscat-core against MDK's White Noise CLI over one in-process relay.
//!
//! 1. White Noise creates a group with a noscat device; the device joins,
//!    and kind 9 messages flow both ways.
//! 2. A noscat device creates a mesh and invites the White Noise account;
//!    it accepts, and messages flow both ways.
//!
//! `WN_BIN` points at the `wn` binary (`wnd` must sit next to it).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use noscat_core::Identity;
use noscat_core::dataplane::{DataplaneConfig, Reachability};
use noscat_core::device::{Device, DeviceConfig, DeviceEvent};
use nostr::prelude::PublicKey;
use serde_json::Value;

const T: Duration = Duration::from_secs(90);
const CHAT: u16 = 9;

struct Wn {
    bin: PathBuf,
    home: PathBuf,
    relay: String,
    account: Option<String>,
}

impl Wn {
    fn run(&self, args: &[&str]) -> Result<Value> {
        let mut cmd = Command::new(&self.bin);
        cmd.env("WN_HOME", &self.home)
            .env("WN_SECRET_STORE", "file")
            .env("WN_ALLOW_LOOPBACK_RELAYS", "1")
            .env("WN_RELAY", &self.relay)
            .env_remove("WN_SOCKET")
            .arg("--json");
        if let Some(a) = &self.account {
            cmd.args(["--account", a]);
        }
        let out = cmd.args(args).output().with_context(|| format!("running wn {args:?}"))?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        if !out.status.success() {
            bail!("wn {args:?} failed: {stdout}{}", String::from_utf8_lossy(&out.stderr));
        }
        serde_json::from_str(stdout.trim()).or_else(|_| Ok(Value::String(stdout.into_owned())))
    }
}

/// First string under `key` anywhere in `v`.
fn find<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    match v {
        Value::Object(m) => m
            .get(key)
            .and_then(Value::as_str)
            .or_else(|| m.values().find_map(|x| find(x, key))),
        Value::Array(a) => a.iter().find_map(|x| find(x, key)),
        _ => None,
    }
}

fn contains_text(v: &Value, text: &str) -> bool {
    match v {
        Value::String(s) => s.contains(text),
        Value::Object(m) => m.values().any(|x| contains_text(x, text)),
        Value::Array(a) => a.iter().any(|x| contains_text(x, text)),
        _ => false,
    }
}

async fn eventually<F: FnMut() -> Result<bool>>(what: &str, mut f: F) -> Result<()> {
    let deadline = Instant::now() + T;
    loop {
        if f()? {
            return Ok(());
        }
        if Instant::now() > deadline {
            bail!("timed out: {what}");
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

async fn noscat(relay: &str, dir: &Path, name: &str) -> Result<Device> {
    let cfg = DeviceConfig {
        dir: dir.to_path_buf(),
        name: name.into(),
        relays: vec![relay.into()],
        dataplane: DataplaneConfig {
            bind: "127.0.0.1:0".parse()?,
            reachability: Reachability::BehindNat,
            stun_servers: vec!["stun:127.0.0.1:9".into()],
            lan_discovery: false,
        },
        peer_addresses: Default::default(),
    };
    Ok(Device::start(Identity::generate(), cfg).await?)
}

async fn next_chat(rx: &mut tokio::sync::broadcast::Receiver<DeviceEvent>) -> Result<String> {
    tokio::time::timeout(T, async {
        loop {
            match rx.recv().await {
                Ok(DeviceEvent::App(ev)) if ev.kind == CHAT => return Ok(ev.content),
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(e) => bail!("event stream: {e}"),
            }
        }
    })
    .await
    .context("waiting for a chat message")?
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
    let bin = PathBuf::from(std::env::var("WN_BIN").context("WN_BIN")?);
    let relay = nostr_relay_builder::MockRelay::run().await?;
    let url = relay.url().await.to_string();
    let base = std::env::temp_dir().join(format!("mdk-interop-{}", rand::random::<u32>()));
    std::fs::create_dir_all(&base)?;

    let mut wn = Wn {
        bin,
        home: base.join("wn"),
        relay: url.clone(),
        account: None,
    };
    wn.run(&["daemon", "start", "--discovery-relays", &url, "--default-account-relays", &url])?;
    let me = wn.run(&["create-identity"])?;
    let wn_npub = find(&me, "npub").context("create-identity npub")?.to_string();
    let wn_pk = PublicKey::parse(&wn_npub)?;
    wn.account = Some(wn_npub.clone());
    println!("wn account {wn_npub}");

    let result = async {
        // 1. White Noise invites a noscat device.
        let a = noscat(&url, &base.join("a"), "noscat-a").await?;
        let joining = {
            let a = a.clone();
            tokio::spawn(async move { a.join(wn_pk, T).await })
        };
        tokio::time::sleep(Duration::from_secs(2)).await;
        let created = wn.run(&["groups", "create", "interop", &a.device().to_hex()])?;
        let gid = find(&created, "group_id").context("groups create group_id")?.to_string();
        joining.await??;
        println!("1. noscat joined the White Noise group {gid}");
        let mut rx = a.subscribe();
        wn.run(&["messages", "send", &gid, "hello from white noise"])?;
        let got = next_chat(&mut rx).await?;
        anyhow::ensure!(got == "hello from white noise", "noscat got {got:?}");
        println!("1. White Noise -> noscat ok");
        a.send_app(CHAT, Vec::new(), "hello from noscat".into()).await?;
        eventually("White Noise sees the noscat message", || {
            Ok(contains_text(&wn.run(&["messages", "list", &gid, "--limit", "20"])?, "hello from noscat"))
        })
        .await?;
        println!("1. noscat -> White Noise ok");
        a.shutdown().await;

        // 2. A noscat mesh invites the White Noise account.
        let b = noscat(&url, &base.join("b"), "noscat-b").await?;
        b.create("noscat-mesh").await?;
        b.invite(wn_pk).await?;
        let mut gid2 = String::new();
        eventually("White Noise sees the invitation", || {
            let inv = wn.run(&["groups", "invites"])?;
            if let Some(g) = find(&inv, "group_id") {
                gid2 = g.to_string();
                return Ok(true);
            }
            Ok(false)
        })
        .await?;
        wn.run(&["groups", "accept", &gid2])?;
        println!("2. White Noise accepted the noscat invitation {gid2}");
        let mut rx = b.subscribe();
        wn.run(&["messages", "send", &gid2, "white noise in a noscat mesh"])?;
        let got = next_chat(&mut rx).await?;
        anyhow::ensure!(got == "white noise in a noscat mesh", "noscat got {got:?}");
        b.send_app(CHAT, Vec::new(), "noscat mesh says hi".into()).await?;
        eventually("White Noise sees the mesh message", || {
            Ok(contains_text(&wn.run(&["messages", "list", &gid2, "--limit", "20"])?, "noscat mesh says hi"))
        })
        .await?;
        anyhow::ensure!(b.members().await.len() == 2, "noscat roster");
        println!("2. both directions ok");
        b.shutdown().await;
        Ok::<_, anyhow::Error>(())
    }
    .await;

    let _ = wn.run(&["daemon", "stop"]);
    if let Err(e) = &result {
        eprintln!("FAIL: {e:#}");
        if let Ok(log) = std::fs::read_to_string(wn.home.join("dev/wnd.log")) {
            eprintln!("--- wnd.log (tail) ---");
            for l in log.lines().rev().take(40).collect::<Vec<_>>().into_iter().rev() {
                eprintln!("{l}");
            }
        }
    }
    let _ = std::fs::remove_dir_all(&base);
    result?;
    println!("mdk-interop: all scenarios passed");
    Ok(())
}
