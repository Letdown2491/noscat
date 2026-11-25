//! Two clients against an in-process relay: create, invite, join, chat,
//! a file transfer, forwards to the default service and to a served port.

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use noscat_client::{Client, ClientConfig, ClientError, Event, IdentitySource};

const T: Duration = Duration::from_secs(30);

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
    a.invite(b.npub()).unwrap();
    joiner.join().unwrap().unwrap();
    assert_eq!(a.members().len(), 2);
}

/// A dead relay in the list must neither slow the start down nor stop
/// publishing: the live relay carries everything.
#[test]
fn a_dead_relay_does_not_block() {
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
