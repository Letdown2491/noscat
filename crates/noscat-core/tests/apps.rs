//! App protocols between two members on loopback: text with ack, file
//! transfer with resume, and TCP forwarding.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use noscat_core::Identity;
use noscat_core::apps::{self, Incoming, Received, TextKind};
use noscat_core::dataplane::{Dataplane, DataplaneConfig, Member, Reachability};
use noscat_core::streams::{Connection, Streams};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const T: Duration = Duration::from_secs(20);

struct Dev {
    id: Identity,
    streams: Arc<Streams>,
    addr: SocketAddr,
    dp: Arc<Dataplane>,
}

async fn dev() -> Dev {
    let id = Identity::generate();
    let cfg = DataplaneConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        reachability: Reachability::BehindNat,
        stun_servers: Some(vec!["stun:127.0.0.1:9".into()]),
        lan_discovery: false,
    };
    let dp = Arc::new(Dataplane::start(&id, cfg).await.unwrap());
    let addr = dp.local_addrs().await.unwrap()[0];
    let streams = Arc::new(Streams::start(dp.clone()).await.unwrap());
    Dev { id, streams, addr, dp }
}

async fn pair() -> (Dev, Dev, Connection, Connection) {
    let (a, b) = (dev().await, dev().await);
    a.dp.set_members(&[Member { device: b.id.public_key(), addresses: vec![b.addr] }]).await.unwrap();
    b.dp.set_members(&[Member { device: a.id.public_key(), addresses: vec![a.addr] }]).await.unwrap();
    let bs = b.streams.clone();
    let accepted = tokio::spawn(async move { bs.accept().await.unwrap() });
    let ca = a.streams.connect(b.id.public_key(), T).await.unwrap();
    // QUIC only surfaces the connection to the acceptor once data flows.
    let cb = accepted;
    (a, b, ca, cb.await.unwrap_or_else(|_| panic!("accept")))
}

fn tmp(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("noscat-apps-{}-{}-{tag}", std::process::id(), rand::random::<u32>()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[tokio::test(flavor = "multi_thread")]
async fn text_file_resume_and_forward() {
    let (_a, _b, ca, cb) = pair().await;

    // Text is acknowledged once the receiver has it.
    let rx = tokio::spawn({
        let cb = cb.clone();
        async move {
            match apps::accept(&cb).await.unwrap().unwrap() {
                Incoming::Text(t) => t.ack().await,
                other => panic!("{other:?}"),
            }
        }
    });
    apps::send_text(&ca, TextKind::Clipboard, "copied").await.unwrap();
    assert_eq!(rx.await.unwrap(), (TextKind::Clipboard, "copied".to_string()));

    // A receiver whose access rules say no answers "not permitted", and
    // the sender can tell that from a plain refusal.
    let rx = tokio::spawn({
        let cb = cb.clone();
        async move {
            for _ in 0..2 {
                let inc = apps::accept(&cb).await.unwrap().unwrap();
                inc.not_permitted().await;
            }
        }
    });
    assert!(matches!(apps::send_text(&ca, TextKind::Chat, "hi").await, Err(apps::AppError::NotPermitted)));
    assert!(matches!(apps::open_forward(&ca, 22).await, Err(apps::AppError::NotPermitted)));
    rx.await.unwrap();

    // A file arrives verified.
    let src = tmp("src");
    let out = tmp("out");
    let data: Vec<u8> = (0..300_000u32).map(|i| (i * 7 % 251) as u8).collect();
    let path = src.join("data.bin");
    std::fs::write(&path, &data).unwrap();
    let recv = tokio::spawn({
        let cb = cb.clone();
        let out = out.clone();
        async move {
            let Incoming::File(f) = apps::accept(&cb).await.unwrap().unwrap() else { panic!("not a file") };
            f.receive(&out, |_, _| {}).await.unwrap()
        }
    });
    let mut last = (0, 0);
    apps::send_file(&ca, &path, |s, t| last = (s, t)).await.unwrap();
    assert_eq!(last, (data.len() as u64, data.len() as u64));
    let Received::Done(dest) = recv.await.unwrap() else { panic!("partial") };
    assert_eq!(std::fs::read(&dest).unwrap(), data);

    // A matching partial resumes: only the rest is sent.
    let out2 = tmp("out2");
    std::fs::write(out2.join(format!("data.bin{}", apps::PART_SUFFIX)), &data[..100_000]).unwrap();
    let sha = apps::sha256_file(&path).await.unwrap();
    std::fs::write(out2.join("data.bin.noscat-sha"), hex::encode(sha)).unwrap();
    let recv = tokio::spawn({
        let cb = cb.clone();
        let out2 = out2.clone();
        async move {
            let Incoming::File(f) = apps::accept(&cb).await.unwrap().unwrap() else { panic!("not a file") };
            f.receive(&out2, |_, _| {}).await.unwrap()
        }
    });
    let mut first = None;
    apps::send_file(&ca, &path, |s, _| {
        first.get_or_insert(s);
    })
    .await
    .unwrap();
    assert_eq!(first, Some(100_000), "resumed from the partial");
    let Received::Done(dest) = recv.await.unwrap() else { panic!("partial") };
    assert_eq!(std::fs::read(&dest).unwrap(), data);

    // A forward reaches a TCP service on the other side.
    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut s, _) = echo.accept().await.unwrap();
        let mut buf = vec![0u8; 5];
        s.read_exact(&mut buf).await.unwrap();
        s.write_all(&buf).await.unwrap();
    });
    tokio::spawn({
        let cb = cb.clone();
        async move {
            let Incoming::Forward(f) = apps::accept(&cb).await.unwrap().unwrap() else { panic!("not a forward") };
            assert_eq!(f.port, echo_addr.port());
            f.accept(echo_addr).await.unwrap();
        }
    });
    let (mut s, mut r) = apps::open_forward(&ca, echo_addr.port()).await.unwrap();
    s.write_all(b"hello").await.unwrap();
    let mut buf = [0u8; 5];
    r.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello");

    for d in [src, out, out2] {
        std::fs::remove_dir_all(d).ok();
    }
}
