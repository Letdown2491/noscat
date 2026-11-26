//! The `noscat` binary end to end against an in-process relay: create,
//! join and invite as one-shot commands, then a running `up` that other
//! commands on the same directory go through (members, invite), and
//! chat, send and pipe from the other device.

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_noscat");

fn free_udp() -> SocketAddr {
    std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap()
}

fn tmp(tag: &str) -> PathBuf {
    // The tests run in parallel threads of one process: a counter keeps
    // their directories apart (the clock alone collided).
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let d = std::env::temp_dir().join(format!("noscat-cli-{}-{n}-{}-{tag}", std::process::id(), rand_u32()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn rand_u32() -> u32 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos()
}

struct Dev {
    dir: PathBuf,
    listen: SocketAddr,
    npub: String,
}

struct Rig {
    relay: String,
    peers: Vec<String>,
}

impl Rig {
    fn cmd(&self, d: &Dev, args: &[&str]) -> Command {
        let mut c = Command::new(BIN);
        c.arg("--dir").arg(&d.dir);
        c.args(["--relay", &self.relay, "--listen", &d.listen.to_string(), "--no-lan", "--stun", "stun:127.0.0.1:9"]);
        for p in &self.peers {
            c.args(["--peer", p]);
        }
        // NOSCAT_TEST_LOG sets every device's RUST_LOG (to debug a failure).
        let log = std::env::var("NOSCAT_TEST_LOG").unwrap_or_else(|_| "warn".into());
        c.args(args).env_remove("NOSCAT_IDENTITY").env("RUST_LOG", log);
        c
    }

    fn ok(&self, d: &Dev, args: &[&str]) -> String {
        let out = self.cmd(d, args).output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(
            out.status.success(),
            "noscat {args:?} failed\nstdout: {stdout}\nstderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        stdout + &String::from_utf8_lossy(&out.stderr)
    }
}

fn id(dir: &Path) -> String {
    let out = Command::new(BIN).arg("--dir").arg(dir).arg("id").output().unwrap();
    assert!(out.status.success());
    String::from_utf8_lossy(&out.stdout).lines().last().unwrap().trim().to_string()
}

fn echo() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut s = s;
                let mut buf = [0u8; 4096];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 || s.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

/// Collect a child's stdout and stderr lines into a shared log.
fn capture(child: &mut Child) -> std::sync::Arc<std::sync::Mutex<String>> {
    let log = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    for r in [
        Box::new(child.stdout.take().unwrap()) as Box<dyn std::io::Read + Send>,
        Box::new(child.stderr.take().unwrap()),
    ] {
        let log = log.clone();
        std::thread::spawn(move || {
            for l in BufReader::new(r).lines().map_while(Result::ok) {
                log.lock().unwrap().push_str(&(l + "\n"));
            }
        });
    }
    log
}

/// Prints a running device's log if the test fails while it is held: a
/// failing command shows only its own side.
struct ShowOnFailure(&'static str, std::sync::Arc<std::sync::Mutex<String>>);

impl Drop for ShowOnFailure {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("--- {}'s log:\n{}", self.0, self.1.lock().unwrap_or_else(|p| p.into_inner()));
        }
    }
}

fn wait_for(log: &std::sync::Mutex<String>, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !log.lock().unwrap().contains(what) {
        assert!(Instant::now() < deadline, "never saw {what:?} in:\n{}", log.lock().unwrap());
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn cli_end_to_end() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let relay = rt.block_on(nostr_relay_builder::MockRelay::run()).unwrap();
    let url = rt.block_on(relay.url()).to_string();

    let (da, db) = (tmp("a"), tmp("b"));
    let a = Dev { npub: id(&da), dir: da, listen: free_udp() };
    let b = Dev { npub: id(&db), dir: db, listen: free_udp() };
    let rig = Rig {
        relay: url,
        peers: vec![format!("{}@{}", a.npub, a.listen), format!("{}@{}", b.npub, b.listen)],
    };

    // One-shot mesh commands, each starting and stopping its device.
    rig.ok(&a, &["mesh", "create", "home"]);
    let join = rig.cmd(&b, &["mesh", "join", &a.npub, "--timeout", "60"]).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    // `mesh requests` (not in a terminal, so it only lists) shows B once
    // B has asked; B published its key package before asking.
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let out = rig.cmd(&a, &["mesh", "requests"]).stdin(Stdio::null()).output().unwrap();
        assert!(out.status.success(), "mesh requests failed: {}", String::from_utf8_lossy(&out.stderr));
        if String::from_utf8_lossy(&out.stdout).contains(&b.npub) {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "B's join request never showed in `mesh requests`");
        std::thread::sleep(Duration::from_millis(500));
    }
    rig.ok(&a, &["mesh", "invite", &b.npub]);
    let joined = join.wait_with_output().unwrap();
    assert!(joined.status.success(), "join failed: {}", String::from_utf8_lossy(&joined.stderr));

    // A runs; commands on A's directory go through it.
    let inbox = tmp("inbox");
    let svc = echo();
    let mut up = rig
        .cmd(&a, &["up", "--out", inbox.to_str().unwrap(), "--to", &svc.to_string()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let log = capture(&mut up);
    let _show = ShowOnFailure("A", log.clone());
    wait_for(&log, "up as");
    let members = rig.ok(&a, &["mesh", "members"]);
    assert!(members.contains("2 member(s)"), "{members}");
    assert!(rig.cmd(&a, &["up"]).output().unwrap().status.code() != Some(0), "a second up must fail");

    // B (not running) sends to A.
    let said = rig.ok(&b, &["chat", &a.npub, "hello", "from", "b"]);
    assert!(said.contains("delivered"), "{said}");
    wait_for(&log, "hello from b");

    let src = tmp("src").join("data.bin");
    let body: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&src, &body).unwrap();
    rig.ok(&b, &["send", src.to_str().unwrap(), &a.npub]);
    assert_eq!(std::fs::read(inbox.join("data.bin")).unwrap(), body);

    // Netcat: B's stdio to A's default service (the echo).
    let mut pipe = rig.cmd(&b, &["pipe", &a.npub]).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    pipe.stdin.take().unwrap().write_all(b"ping over noscat\n").unwrap();
    let out = pipe.wait_with_output().unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), "ping over noscat\n", "{}", String::from_utf8_lossy(&out.stderr));

    let _ = up.kill();
    let _ = up.wait();
    drop(relay);
}

#[test]
fn up_accept_joins() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let relay = rt.block_on(nostr_relay_builder::MockRelay::run()).unwrap();
    let url = rt.block_on(relay.url()).to_string();

    let (da, dc) = (tmp("a"), tmp("c"));
    let a = Dev { npub: id(&da), dir: da, listen: free_udp() };
    let c = Dev { npub: id(&dc), dir: dc, listen: free_udp() };
    let rig = Rig {
        relay: url,
        peers: vec![format!("{}@{}", a.npub, a.listen), format!("{}@{}", c.npub, c.listen)],
    };

    rig.ok(&a, &["mesh", "create", "home"]);
    let mut up = rig
        .cmd(&a, &["up", "--accept-joins", "--out", tmp("inbox").to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let log = capture(&mut up);
    wait_for(&log, "accepting joins");

    // C asks; nobody types `invite`.
    let joined = rig.ok(&c, &["mesh", "join", &a.npub, "--timeout", "60"]);
    assert!(joined.contains("home"), "{joined}");
    wait_for(&log, "invited");
    let members = rig.ok(&a, &["mesh", "members"]);
    assert!(members.contains("2 member(s)"), "{members}");

    let _ = up.kill();
    let _ = up.wait();
    drop(relay);
}

/// A device started for one command (here a join nobody answers; at boot,
/// a relay's MEMBERS_COMMAND) holds the directory: `up` waits for it
/// instead of exiting, and a second `up` still fails at once.
#[test]
fn up_waits_for_a_command_holding_the_directory() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let relay = rt.block_on(nostr_relay_builder::MockRelay::run()).unwrap();
    let url = rt.block_on(relay.url()).to_string();
    let (da, dx) = (tmp("a"), tmp("x"));
    let a = Dev { npub: id(&da), dir: da, listen: free_udp() };
    let nobody = id(&dx);
    let rig = Rig { relay: url, peers: vec![] };

    let mut join = rig
        .cmd(&a, &["mesh", "join", &nobody, "--timeout", "8"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // The join's device is up once its control channel is.
    let deadline = Instant::now() + Duration::from_secs(30);
    while !a.dir.join("control.json").exists() {
        assert!(Instant::now() < deadline, "the join never started");
        std::thread::sleep(Duration::from_millis(100));
    }

    let started = Instant::now();
    let mut up = rig
        .cmd(&a, &["up", "--out", tmp("inbox").to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let log = capture(&mut up);
    let _show = ShowOnFailure("up", log.clone());
    wait_for(&log, "waiting for another noscat command");
    wait_for(&log, "not in a mesh yet");
    assert!(started.elapsed() >= Duration::from_secs(2), "up started while the join held the directory");
    let _ = join.wait();
    assert!(up.try_wait().unwrap().is_none(), "up exited");

    // A second long-running device fails at once, not after the wait.
    let t = Instant::now();
    let out = rig.cmd(&a, &["up"]).output().unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("already running"), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(t.elapsed() < Duration::from_secs(15), "took {:?}", t.elapsed());
    // A one-off command goes through the running device.
    let members = rig.ok(&a, &["mesh", "members"]);
    assert!(!members.is_empty());

    let _ = up.kill();
    let _ = up.wait();
    drop(relay);
}
