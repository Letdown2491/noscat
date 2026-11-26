//! Two clients against an in-process relay: create, invite, join, chat,
//! a file transfer, forwards to the default service and to a served port.

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use noscat_client::{Client, ClientConfig, ClientError, Event, IdentitySource};

const T: Duration = Duration::from_secs(30);


/// Ends the test process if `name` runs longer than `secs`. A stalled QUIC
/// transfer otherwise waits forever (keep-alives hold the connection open),
/// which on CI is a job stuck for hours instead of a failure.
fn watchdog(name: &'static str, secs: u64) {
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(secs));
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr(), "\n{name} still running after {secs} s: giving up");
        std::process::exit(101);
    });
}

fn free_udp() -> SocketAddr {
    std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap()
}

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("noscat-client-{}-{}-{tag}", std::process::id(), rand::random::<u32>()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A TCP echo service on loopback.
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

fn wait<T>(rx: &Receiver<Event>, what: &str, mut f: impl FnMut(&Event) -> Option<T>) -> T {
    let deadline = Instant::now() + T;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok(ev) => {
                if let Some(v) = f(&ev) {
                    return v;
                }
            }
            Err(_) => panic!("timed out waiting for {what}"),
        }
    }
}

/// Wait until `a` lists `npub`'s join request. A joiner publishes its key
/// package before it asks, so inviting after this cannot outrun the key
/// package (inviting at once could, on a slow machine).
fn asked(a: &Client, npub: &str) {
    let deadline = Instant::now() + T;
    while !a.join_requests().iter().any(|r| r.npub == npub) {
        assert!(Instant::now() < deadline, "no join request from {npub}");
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn roundtrip(local: SocketAddr, msg: &[u8]) -> Vec<u8> {
    let deadline = Instant::now() + T;
    loop {
        if let Ok(mut s) = TcpStream::connect(local) {
            s.set_read_timeout(Some(T)).unwrap();
            if s.write_all(msg).is_ok() {
                let mut got = vec![0u8; msg.len()];
                if s.read_exact(&mut got).is_ok() {
                    return got;
                }
            }
        }
        assert!(Instant::now() < deadline, "forward to {local} never worked");
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[test]
fn two_clients_end_to_end() {
    watchdog("two_clients_end_to_end", 180);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let relay = rt.block_on(nostr_relay_builder::MockRelay::run()).unwrap();
    let url = rt.block_on(relay.url()).to_string();

    let (ida, idb) = (noscat_core::Identity::generate(), noscat_core::Identity::generate());
    let (pa, pb) = (free_udp(), free_udp());
    let peers = vec![(ida.npub(), pa), (idb.npub(), pb)];
    let dir_b = tmp("bravo");
    let cfg = |id: &noscat_core::Identity, listen, name: &str, dir: PathBuf| ClientConfig {
        identity: IdentitySource::Secret(id.secret_hex()),
        relays: Some(vec![url.clone()]),
        listen: Some(listen),
        mesh_dir: Some(dir),
        device_name: Some(name.into()),
        lan_discovery: false,
        static_peers: peers.clone(),
        stun_servers: Some(vec!["stun:127.0.0.1:9".into()]),
        ..ClientConfig::default()
    };
    let mut a = Client::start(cfg(&ida, pa, "alpha", tmp("alpha"))).unwrap();
    let mut b = Client::start(cfg(&idb, pb, "bravo", dir_b.clone())).unwrap();
    let (ea, eb) = (a.events().unwrap(), b.events().unwrap());

    // Mesh.
    a.create_mesh("home").unwrap();
    assert_eq!(a.mesh_name().as_deref(), Some("home"));
    let joiner = {
        let b = b.clone();
        let inviter = a.npub().to_string();
        std::thread::spawn(move || b.join(&inviter, T))
    };
    asked(&a, b.npub());
    a.invite(b.npub()).unwrap();
    joiner.join().unwrap().unwrap();
    wait(&eb, "b joined", |e| matches!(e, Event::MeshJoined { name } if name == "home").then_some(()));
    assert!(b.in_mesh());
    assert_eq!(a.members().len(), 2);
    assert_eq!(b.members().len(), 2);
    assert!(Client::running(&dir_b).is_some());

    // Receiving: files into an inbox, the default service is an echo.
    let inbox = tmp("inbox");
    let svc = echo();
    b.up(inbox.clone(), Some(svc)).unwrap();

    // Chat.
    a.send_chat(b.npub(), "hi bravo");
    wait(&eb, "chat", |e| match e {
        Event::ChatMessage { text, .. } => Some(text.clone()),
        _ => None,
    });
    wait(&ea, "chat delivered", |e| matches!(e, Event::ChatDelivered { .. }).then_some(()));
    // A live connection counts as connected, both ways.
    let b_npub = b.npub().to_string();
    assert!(a.members().iter().any(|m| m.npub == b_npub && m.connected));
    assert!(b.members().iter().all(|m| !m.this_device || !m.connected));

    // Rename: the other member hears it now, not on the next advert tick.
    a.set_device_name("renamed laptop");
    assert_eq!(a.device_name(), "renamed laptop");
    let a_npub = a.npub().to_string();
    wait(&eb, "rename", |e| match e {
        Event::MemberSeen { peer, name } if *peer == a_npub && name.as_deref() == Some("renamed laptop") => Some(()),
        _ => None,
    });

    // File.
    let src = tmp("src").join("notes.txt");
    let body: Vec<u8> = (0..200_000u32).flat_map(|i| i.to_le_bytes()).collect();
    std::fs::write(&src, &body).unwrap();
    let sid = a.send_file(src.clone(), b.npub());
    // The receiver: started (incoming, name, size), progress up to the
    // whole file, done; one id throughout.
    let mut rid = None;
    let mut received = 0;
    let got = wait(&eb, "file received", |e| match e {
        Event::TransferStarted { id, name, size, incoming, path, .. } => {
            assert!(*incoming && path.is_none());
            assert_eq!((name.as_str(), *size), ("notes.txt", body.len() as u64));
            rid = Some(*id);
            None
        }
        Event::TransferProgress { id, sent, total, .. } => {
            assert_eq!(Some(*id), rid, "progress before started, or another id");
            assert_eq!(*total, body.len() as u64);
            received = *sent;
            None
        }
        Event::TransferDone { id, path, .. } => {
            assert_eq!(Some(*id), rid);
            Some(path.clone())
        }
        Event::TransferFailed { error, .. } => panic!("receive failed: {error}"),
        _ => None,
    });
    assert_eq!(received, body.len() as u64, "receive progress reached the whole file");
    assert_eq!(std::fs::read(&got).unwrap(), body);
    // The sender: the id send_file returned, from started to done.
    let mut started = false;
    wait(&ea, "file sent", |e| match e {
        Event::TransferStarted { id, incoming, path, size, .. } if *id == sid => {
            assert!(!*incoming && path.as_deref() == Some(src.as_path()));
            assert_eq!(*size, body.len() as u64);
            started = true;
            None
        }
        Event::TransferDone { id, path, .. } if *id == sid => {
            assert!(started, "done before started");
            assert_eq!(*path, src);
            Some(())
        }
        Event::TransferFailed { error, .. } => panic!("send failed: {error}"),
        _ => None,
    });

    // Forward to the default service.
    let local = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let id = a.forward(b.npub(), local);
    assert_eq!(roundtrip(local, b"ping"), b"ping");
    assert_eq!(a.list_forwards().len(), 1);
    assert!(a.cancel_forward(id));
    wait(&ea, "forward stopped", |e| matches!(e, Event::ForwardStopped { id: i, .. } if *i == id).then_some(()));

    // Forward to a served port.
    let port_svc = echo();
    b.serve_port(port_svc.port(), true);
    let local2 = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    a.forward_port(b.npub(), local2, port_svc.port());
    assert_eq!(roundtrip(local2, b"served"), b"served");

    // Access: bravo stops taking things from alpha. Alpha is told "not
    // permitted" (not a generic failure), bravo logs the refusal, and the
    // rule is saved in bravo's directory only.
    use noscat_client::{AccessGroup, AccessOutcome, AccessRule};
    assert_eq!(b.access_of(a.npub()).unwrap().control, AccessRule::Ask, "control asks by default");
    b.set_access(Some(a.npub()), AccessGroup::Send, Some(AccessRule::Deny)).unwrap();
    a.send_chat(b.npub(), "let me in");
    let err = wait(&ea, "chat refused", |e| match e {
        Event::ChatFailed { error, .. } => Some(error.clone()),
        Event::ChatDelivered { .. } => panic!("a denied chat was delivered"),
        _ => None,
    });
    assert!(err.contains("not permitted"), "{err}");
    let fid = a.send_file(src.clone(), b.npub());
    let err = wait(&ea, "file refused", |e| match e {
        Event::TransferFailed { id, error, .. } if *id == fid => Some(error.clone()),
        Event::TransferDone { id, .. } if *id == fid => panic!("a denied file arrived"),
        _ => None,
    });
    assert!(err.contains("not permitted"), "{err}");
    let log = b.access_requests();
    assert_eq!(log.len(), 1, "a repeated refusal is one entry: {log:?}");
    assert_eq!((log[0].peer.as_str(), log[0].group, log[0].outcome), (a_npub.as_str(), AccessGroup::Send, AccessOutcome::Denied));
    assert!(dir_b.join("access.json").exists());
    // A forward is "services", untouched by the send rule.
    assert_eq!(roundtrip(local2, b"still served"), b"still served");
    b.reset_access(a.npub()).unwrap();
    a.send_chat(b.npub(), "thanks");
    wait(&ea, "chat delivered again", |e| matches!(e, Event::ChatDelivered { .. }).then_some(()));
    // Ask is for control only.
    assert!(b.set_access(None, AccessGroup::Services, Some(AccessRule::Ask)).is_err());

    drop(a);
    drop(b);
    drop(relay);
}

/// Dropping the last `Client` stops the device and frees its directory,
/// so the next client on it starts (the apps join with one client and
/// then run another). Before 0.5.0's fix the background tasks kept the
/// device alive and the second start failed with `Busy`.
#[test]
fn dropping_the_client_frees_the_directory() {
    watchdog("dropping_the_client_frees_the_directory", 180);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let relay = rt.block_on(nostr_relay_builder::MockRelay::run()).unwrap();
    let url = rt.block_on(relay.url()).to_string();
    let dir = tmp("reuse");
    let cfg = || ClientConfig {
        identity: IdentitySource::File(dir.join("identity.nsec")),
        relays: Some(vec![url.clone()]),
        listen: Some(free_udp()),
        mesh_dir: Some(dir.clone()),
        lan_discovery: false,
        stun_servers: Some(vec!["stun:127.0.0.1:9".into()]),
        ..ClientConfig::default()
    };

    let first = Client::start(cfg()).unwrap();
    first.create_mesh("home").unwrap();
    let helper = Client::running(&dir).expect("registered while running");
    assert!(matches!(Client::start(cfg()), Err(ClientError::Busy(_))), "a second client must not open a running directory");
    drop(helper);
    drop(first);

    assert!(Client::running(&dir).is_none(), "the device stopped with its last handle");
    let again = Client::start(cfg()).expect("the directory is free once the client is dropped");
    assert_eq!(again.mesh_name().as_deref(), Some("home"));
    drop(again);
    drop(relay);
}

fn free_tcp_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// Two devices join a mesh over `url`; `a_relays` are alpha's relays.
fn join_over(rt: &tokio::runtime::Runtime, a_relays: Vec<String>, url: &str) {
    let _ = rt;
    let (ida, idb) = (noscat_core::Identity::generate(), noscat_core::Identity::generate());
    let cfg = |id: &noscat_core::Identity, relays: Vec<String>, name: &str| ClientConfig {
        identity: IdentitySource::Secret(id.secret_hex()),
        relays: Some(relays),
        listen: Some(free_udp()),
        mesh_dir: Some(tmp(name)),
        lan_discovery: false,
        stun_servers: Some(vec!["stun:127.0.0.1:9".into()]),
        ..ClientConfig::default()
    };
    let a = Client::start(cfg(&ida, a_relays, "relay-a")).unwrap();
    let b = Client::start(cfg(&idb, vec![url.to_string()], "relay-b")).unwrap();
    a.create_mesh("home").unwrap();
    let joiner = {
        let b = b.clone();
        let inviter = a.npub().to_string();
        std::thread::spawn(move || b.join(&inviter, T))
    };
    asked(&a, b.npub());
    a.invite(b.npub()).unwrap();
    joiner.join().unwrap().unwrap();
    assert_eq!(a.members().len(), 2);
}

/// A dead relay in the list must neither slow the start down nor stop
/// publishing: the live relay carries everything.
#[test]
fn a_dead_relay_does_not_block() {
    watchdog("a_dead_relay_does_not_block", 180);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let relay = rt.block_on(nostr_relay_builder::MockRelay::run()).unwrap();
    let url = rt.block_on(relay.url()).to_string();
    let dead = format!("ws://127.0.0.1:{}", free_tcp_port());
    let t0 = std::time::Instant::now();
    join_over(&rt, vec![dead, url.clone()], &url);
    assert!(t0.elapsed() < Duration::from_secs(20), "took {:?}", t0.elapsed());
    drop(relay);
}

/// A relay that is down when the device starts is connected once it comes
/// up (nostr-sdk's connection task keeps retrying), and then carries the
/// device's publishes and subscriptions.
#[test]
fn a_relay_that_comes_up_later_is_used() {
    watchdog("a_relay_that_comes_up_later_is_used", 180);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let port = free_tcp_port();
    let url = format!("ws://127.0.0.1:{port}");
    let (ida, idb) = (noscat_core::Identity::generate(), noscat_core::Identity::generate());
    let cfg = |id: &noscat_core::Identity, name: &str| ClientConfig {
        identity: IdentitySource::Secret(id.secret_hex()),
        relays: Some(vec![url.clone()]),
        listen: Some(free_udp()),
        mesh_dir: Some(tmp(name)),
        lan_discovery: false,
        stun_servers: Some(vec!["stun:127.0.0.1:9".into()]),
        ..ClientConfig::default()
    };
    let a = Client::start(cfg(&ida, "late-a")).unwrap();
    let relay = nostr_relay_builder::LocalRelay::new(nostr_relay_builder::RelayBuilder::default().port(port));
    rt.block_on(relay.run()).unwrap();
    let b = Client::start(cfg(&idb, "late-b")).unwrap();
    // alpha's connection task retries every 10 seconds at first.
    let deadline = std::time::Instant::now() + Duration::from_secs(40);
    loop {
        if a.create_mesh("home").is_ok() {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "alpha never reached the relay");
        std::thread::sleep(Duration::from_secs(1));
    }
    let joiner = {
        let b = b.clone();
        let inviter = a.npub().to_string();
        std::thread::spawn(move || b.join(&inviter, T))
    };
    let deadline = std::time::Instant::now() + Duration::from_secs(40);
    while a.invite(b.npub()).is_err() {
        assert!(std::time::Instant::now() < deadline, "alpha could not invite over the late relay");
        std::thread::sleep(Duration::from_secs(1));
    }
    joiner.join().unwrap().unwrap();
    assert_eq!(a.members().len(), 2);
    relay.shutdown();
}

/// A join request is listed by `join_requests` (read from the relays, so
/// a CLI next to a running service sees it), and gone once the device is
/// invited.
#[test]
fn join_requests_are_listed_until_invited() {
    watchdog("join_requests_are_listed_until_invited", 180);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let relay = rt.block_on(nostr_relay_builder::MockRelay::run()).unwrap();
    let url = rt.block_on(relay.url()).to_string();
    let (ida, idb) = (noscat_core::Identity::generate(), noscat_core::Identity::generate());
    let cfg = |id: &noscat_core::Identity, name: &str| ClientConfig {
        identity: IdentitySource::Secret(id.secret_hex()),
        relays: Some(vec![url.clone()]),
        listen: Some(free_udp()),
        mesh_dir: Some(tmp(name)),
        device_name: Some(name.into()),
        lan_discovery: false,
        stun_servers: Some(vec!["stun:127.0.0.1:9".into()]),
        ..ClientConfig::default()
    };
    let a = Client::start(cfg(&ida, "req-a")).unwrap();
    let b = Client::start(cfg(&idb, "req-b")).unwrap();
    a.create_mesh("home").unwrap();
    assert!(a.join_requests().is_empty());

    let joiner = {
        let b = b.clone();
        let inviter = a.npub().to_string();
        std::thread::spawn(move || b.join(&inviter, T))
    };
    let deadline = Instant::now() + T;
    let req = loop {
        if let Some(r) = a.join_requests().into_iter().find(|r| r.npub == b.npub()) {
            break r;
        }
        assert!(Instant::now() < deadline, "the join request never showed up");
        std::thread::sleep(Duration::from_millis(300));
    };
    assert_eq!(req.name.as_deref(), Some("req-b"));
    assert!(req.age_secs < 60);

    a.invite(&req.npub).unwrap();
    joiner.join().unwrap().unwrap();
    assert!(a.join_requests().is_empty(), "a member is no longer a request");
    drop(relay);
}

/// Two clients in one mesh, `b` receiving.
fn mesh_pair(url: &str) -> (Client, Client, Receiver<Event>, Receiver<Event>) {
    let (ida, idb) = (noscat_core::Identity::generate(), noscat_core::Identity::generate());
    let (pa, pb) = (free_udp(), free_udp());
    let peers = vec![(ida.npub(), pa), (idb.npub(), pb)];
    let cfg = |id: &noscat_core::Identity, listen, name: &str| ClientConfig {
        identity: IdentitySource::Secret(id.secret_hex()),
        relays: Some(vec![url.to_string()]),
        listen: Some(listen),
        mesh_dir: Some(tmp(name)),
        device_name: Some(name.into()),
        lan_discovery: false,
        static_peers: peers.clone(),
        stun_servers: Some(vec!["stun:127.0.0.1:9".into()]),
        ..ClientConfig::default()
    };
    let mut a = Client::start(cfg(&ida, pa, "viewer")).unwrap();
    let mut b = Client::start(cfg(&idb, pb, "host")).unwrap();
    let (ea, eb) = (a.events().unwrap(), b.events().unwrap());
    a.create_mesh("home").unwrap();
    let joiner = {
        let b = b.clone();
        let inviter = a.npub().to_string();
        std::thread::spawn(move || b.join(&inviter, T))
    };
    asked(&a, b.npub());
    a.invite(b.npub()).unwrap();
    joiner.join().unwrap().unwrap();
    b.up(tmp("inbox"), None).unwrap();
    (a, b, ea, eb)
}

/// Read terminal output until the exit status.
fn session_output(rt: &tokio::runtime::Runtime, s: &mut noscat_client::MeshStream) -> (String, i32) {
    use noscat_client::TermFrame;
    rt.block_on(async {
        let mut out = Vec::new();
        loop {
            match tokio::time::timeout(T, TermFrame::read(s)).await.expect("terminal output timed out").unwrap() {
                Some(TermFrame::Output(b)) => out.extend(b),
                Some(TermFrame::Exit(code)) => return (String::from_utf8_lossy(&out).into_owned(), code),
                Some(_) => {}
                None => panic!("session ended without an exit status: {}", String::from_utf8_lossy(&out)),
            }
        }
    })
}

fn type_in(rt: &tokio::runtime::Runtime, s: &mut noscat_client::MeshStream, text: &str) {
    use tokio::io::AsyncWriteExt as _;
    rt.block_on(s.write_all(&noscat_client::TermFrame::Input(text.as_bytes().to_vec()).encode())).unwrap();
}

#[test]
#[cfg(unix)]
fn an_unanswered_ask_is_refused_after_the_timeout() {
    use noscat_client::{AccessAnswer, AccessGroup, AccessOutcome, ACCESS_ASK_TIMEOUT};
    watchdog("an_unanswered_ask_is_refused_after_the_timeout", 240);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let relay = rt.block_on(nostr_relay_builder::MockRelay::run()).unwrap();
    let url = rt.block_on(relay.url()).to_string();
    let (a, b, ea, eb) = mesh_pair(&url);
    let (an, bn) = (a.npub().to_string(), b.npub().to_string());
    b.set_access_prompts(true);

    // Asked, and nobody answers: the viewer keeps hearing it waits, then
    // gets "not permitted" once the ask times out, not a hang.
    let started = std::time::Instant::now();
    let opener = {
        let (a, bn) = (a.clone(), bn.clone());
        std::thread::spawn(move || a.open_terminal(&bn, 80, 24, "xterm"))
    };
    let id = wait(&eb, "access request", |e| match e {
        Event::AccessRequest { id, peer, group: AccessGroup::Control } if *peer == an => Some(*id),
        _ => None,
    });
    wait(&ea, "waiting", |e| matches!(e, Event::TerminalWaiting { peer } if *peer == bn).then_some(()));
    let err = opener.join().unwrap().err().expect("an unanswered terminal opened");
    assert!(err.to_string().contains("not permitted"), "{err}");
    assert!(started.elapsed() >= ACCESS_ASK_TIMEOUT, "refused before the timeout: {:?}", started.elapsed());
    wait(&eb, "resolved", |e| match e {
        Event::AccessResolved { id: rid, outcome, .. } if *rid == id => Some(assert_eq!(*outcome, AccessOutcome::TimedOut)),
        _ => None,
    });
    assert_eq!(b.access_requests()[0].outcome, AccessOutcome::TimedOut);
    // A late answer finds nothing waiting, and lets nothing in.
    assert!(b.answer_access(id, AccessAnswer::Once).is_err());
    assert!(b.terminal_sessions().is_empty());
}

/// Windows hosts through ConPTY with `cmd` (portable-pty's default
/// program there): the shell runs, the output and the exit status come
/// through, and ending the session ends the shell.
#[test]
#[cfg(windows)]
fn a_terminal_runs_cmd_on_windows() {
    use noscat_client::{AccessGroup, AccessRule};
    watchdog("a_terminal_runs_cmd_on_windows", 240);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let relay = rt.block_on(nostr_relay_builder::MockRelay::run()).unwrap();
    let url = rt.block_on(relay.url()).to_string();
    let (a, b, _ea, eb) = mesh_pair(&url);
    let (an, bn) = (a.npub().to_string(), b.npub().to_string());
    b.set_access(Some(an.as_str()), AccessGroup::Control, Some(AccessRule::Allow)).unwrap();

    // `set /a` prints the sum: 42 is in the output, not in what was typed.
    let mut s = a.open_terminal(&bn, 100, 30, "xterm-256color").unwrap();
    wait(&eb, "session opened", |e| matches!(e, Event::TerminalOpened { peer, .. } if *peer == an).then_some(()));
    type_in(&rt, &mut s, "set /a 40+2\r");
    std::thread::sleep(Duration::from_millis(500));
    type_in(&rt, &mut s, "exit 3\r");
    let (out, code) = session_output(&rt, &mut s);
    assert!(out.contains("42"), "cmd ran: {out}");
    assert_eq!(code, 3, "the exit status comes through");
    wait(&eb, "session closed", |e| matches!(e, Event::TerminalClosed { error: None, .. }).then_some(()));

    // The host ends a session: the viewer gets an exit status, not a hang.
    let mut s = a.open_terminal(&bn, 80, 24, "xterm").unwrap();
    let sid = wait(&eb, "second session", |e| match e {
        Event::TerminalOpened { id, .. } => Some(*id),
        _ => None,
    });
    std::thread::sleep(Duration::from_millis(1000));
    assert!(b.end_terminal(sid));
    let (_, code) = session_output(&rt, &mut s);
    assert_ne!(code, 0, "an ended shell does not report success");
}

#[test]
#[cfg(unix)]
fn a_terminal_asks_first_then_runs_a_real_shell() {
    use noscat_client::{AccessAnswer, AccessGroup, AccessOutcome};
    watchdog("a_terminal_asks_first_then_runs_a_real_shell", 240);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let relay = rt.block_on(nostr_relay_builder::MockRelay::run()).unwrap();
    let url = rt.block_on(relay.url()).to_string();
    let (a, b, ea, eb) = mesh_pair(&url);
    let (an, bn) = (a.npub().to_string(), b.npub().to_string());

    // Control asks by default, and a host with no app to ask refuses. It
    // offers no terminal in its adverts, since nobody could get in.
    let err = a.open_terminal(&bn, 80, 24, "xterm").err().expect("opened without approval");
    assert!(err.to_string().contains("not permitted"), "{err}");
    assert_eq!(b.access_requests()[0].outcome, AccessOutcome::NoOneToAsk);
    assert!(!b.members().iter().any(|m| m.this_device && m.control));

    // With an app attached it asks; the viewer hears it waits; allow once.
    b.set_access_prompts(true);
    assert!(b.members().iter().any(|m| m.this_device && m.control), "now offered");
    let opener = {
        let (a, bn) = (a.clone(), bn.clone());
        std::thread::spawn(move || a.open_terminal(&bn, 100, 30, "xterm-256color"))
    };
    let id = wait(&eb, "access request", |e| match e {
        Event::AccessRequest { id, peer, group: AccessGroup::Control } if *peer == an => Some(*id),
        _ => None,
    });
    wait(&ea, "waiting", |e| matches!(e, Event::TerminalWaiting { peer } if *peer == bn).then_some(()));
    b.answer_access(id, AccessAnswer::Once).unwrap();
    let mut s = opener.join().unwrap().unwrap();
    wait(&eb, "session opened", |e| matches!(e, Event::TerminalOpened { peer, .. } if *peer == an).then_some(()));
    assert_eq!(b.terminal_sessions().len(), 1);
    type_in(&rt, &mut s, "echo hi-$((40+2)) $(stty size)\nexit 3\n");
    let (out, code) = session_output(&rt, &mut s);
    assert!(out.contains("hi-42 30 100"), "the shell ran at the requested size: {out}");
    assert_eq!(code, 3, "the exit status comes through");
    wait(&eb, "session closed", |e| matches!(e, Event::TerminalClosed { error: None, .. }).then_some(()));
    assert!(b.terminal_sessions().is_empty());
    let log = std::fs::read_to_string(b.state_dir().join("terminal.log")).unwrap();
    assert!(log.contains("opened session") && log.contains("exit 3"), "{log}");

    // Once means once: the next request asks again. Deny it.
    let opener = {
        let (a, bn) = (a.clone(), bn.clone());
        std::thread::spawn(move || a.open_terminal(&bn, 80, 24, "xterm"))
    };
    let id = wait(&eb, "second request", |e| match e {
        Event::AccessRequest { id, .. } => Some(*id),
        _ => None,
    });
    b.answer_access(id, AccessAnswer::Deny).unwrap();
    let err = opener.join().unwrap().err().expect("a denied terminal opened");
    assert!(err.to_string().contains("not permitted"), "{err}");

    // Always: saved as an allow rule. The host ends the session; the
    // viewer gets an exit status, not a hang.
    let opener = {
        let (a, bn) = (a.clone(), bn.clone());
        std::thread::spawn(move || a.open_terminal(&bn, 80, 24, "xterm"))
    };
    let id = wait(&eb, "third request", |e| match e {
        Event::AccessRequest { id, .. } => Some(*id),
        _ => None,
    });
    b.answer_access(id, AccessAnswer::Always).unwrap();
    assert_eq!(b.access_of(&an).unwrap().control, noscat_client::AccessRule::Allow, "always is saved");
    let mut s = opener.join().unwrap().unwrap();
    let sid = wait(&eb, "session opened", |e| match e {
        Event::TerminalOpened { id, .. } => Some(*id),
        _ => None,
    });
    // Wait for the prompt before ending, so the shell is up.
    type_in(&rt, &mut s, "echo ready\n");
    std::thread::sleep(Duration::from_millis(500));
    assert!(b.end_terminal(sid));
    let (_, code) = session_output(&rt, &mut s);
    assert_ne!(code, 0, "an ended shell does not report success");

    // The app-facing handle: output and the end arrive as events.
    let h = a.start_terminal(&bn, 80, 24, "xterm").unwrap();
    h.write(b"echo via-$((1+1))\nexit 7\n");
    let mut out = Vec::new();
    let code = wait(&ea, "handle exit", |e| match e {
        Event::TerminalOutput { session, data } if *session == h.id() => {
            out.extend_from_slice(data);
            None
        }
        Event::TerminalExited { session, code, error } if *session == h.id() => {
            assert!(error.is_none(), "{error:?}");
            Some(*code)
        }
        _ => None,
    });
    assert_eq!(code, Some(7));
    assert!(String::from_utf8_lossy(&out).contains("via-2"));
    // Closing ends the host's session.
    let h = a.start_terminal(&bn, 80, 24, "xterm").unwrap();
    h.close();
    wait(&ea, "closed handle exit", |e| matches!(e, Event::TerminalExited { session, .. } if *session == h.id()).then_some(()));

    drop(a);
    drop(b);
    drop(relay);
}
