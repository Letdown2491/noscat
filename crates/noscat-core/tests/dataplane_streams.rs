//! Dataplane + Streams on loopback: three devices in one process.
//! NAT traversal and loss are covered by tests/netrig; this checks the
//! module contracts.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use noscat_core::Identity;
use noscat_core::dataplane::{Dataplane, DataplaneConfig, Member, Reachability};
use noscat_core::streams::{Streams, StreamsError};
use sha2::{Digest, Sha256};

struct Device {
    id: Identity,
    dp: Arc<Dataplane>,
    streams: Arc<Streams>,
    addr: SocketAddr,
}

async fn device_with(reachability: Reachability) -> Device {
    let id = Identity::generate();
    // A reachable device needs a fixed port: borrow a free one.
    let bind: SocketAddr = match reachability {
        Reachability::Public { .. } => std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap(),
        Reachability::BehindNat => "127.0.0.1:0".parse().unwrap(),
    };
    let cfg = DataplaneConfig {
        bind,
        reachability,
        // FIPS requires STUN for NAT adverts; nothing listens here.
        stun_servers: vec!["stun:127.0.0.1:9".into()],
        lan_discovery: false,
    };
    let dp = Arc::new(Dataplane::start(&id, cfg).await.unwrap());
    let addr = dp.local_addrs().await.unwrap()[0];
    let streams = Arc::new(Streams::start(dp.clone()).await.unwrap());
    Device {
        id,
        dp,
        streams,
        addr,
    }
}

async fn device() -> Device {
    device_with(Reachability::BehindNat).await
}

fn member(d: &Device) -> Member {
    Member {
        device: d.id.public_key(),
        addresses: vec![d.addr],
    }
}

/// Serve one stream: read everything, reply with its sha256.
fn serve_sha256(d: &Device) -> tokio::task::JoinHandle<nostr::prelude::PublicKey> {
    let streams = d.streams.clone();
    tokio::spawn(async move {
        let conn = streams.accept().await.expect("accept");
        let (mut send, mut recv) = conn.inner.accept_bi().await.unwrap();
        let data = recv.read_to_end(64 << 20).await.unwrap();
        send.write_all(&Sha256::digest(&data)).await.unwrap();
        send.finish().unwrap();
        let _ = send.stopped().await;
        conn.peer
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn members_stream_and_know_who_they_talk_to() {
    let (a, b) = (device().await, device().await);
    a.dp.set_members(&[member(&b)]).await.unwrap();
    b.dp.set_members(&[member(&a)]).await.unwrap();
    let server = serve_sha256(&b);

    let conn = a
        .streams
        .connect(b.id.public_key(), Duration::from_secs(10))
        .await
        .unwrap();
    assert_eq!(conn.peer, b.id.public_key());
    let data: Vec<u8> = (0..4u32 << 20)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13).to_le_bytes()[0])
        .collect();
    let (mut send, mut recv) = conn.inner.open_bi().await.unwrap();
    send.write_all(&data).await.unwrap();
    send.finish().unwrap();
    let digest = recv.read_to_end(64).await.unwrap();

    assert_eq!(digest.as_slice(), Sha256::digest(&data).as_slice());
    assert_eq!(
        server.await.unwrap(),
        a.id.public_key(),
        "server sees the dialer's device"
    );
    let links = a.dp.peers().await.unwrap();
    assert!(
        links
            .iter()
            .any(|l| l.device == b.id.public_key() && l.direct)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn non_members_cannot_reach_each_other() {
    let (a, b, c) = (device().await, device().await, device().await);
    a.dp.set_members(&[member(&b)]).await.unwrap();
    b.dp.set_members(&[member(&a)]).await.unwrap();
    // C lists A, but A does not list C.
    c.dp.set_members(&[member(&a)]).await.unwrap();

    a.streams
        .probe(b.id.public_key(), Duration::from_secs(10))
        .await
        .unwrap();
    let err = c
        .streams
        .probe(a.id.public_key(), Duration::from_secs(3))
        .await
        .unwrap_err();
    assert!(matches!(err, StreamsError::Unreachable(_)), "{err}");
    let err = a
        .streams
        .probe(c.id.public_key(), Duration::from_secs(2))
        .await
        .unwrap_err();
    assert!(matches!(err, StreamsError::Unreachable(_)), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn removing_a_member_cuts_it_off() {
    let (a, b) = (device().await, device().await);
    a.dp.set_members(&[member(&b)]).await.unwrap();
    b.dp.set_members(&[member(&a)]).await.unwrap();
    let _server = serve_sha256(&b);
    let conn = a
        .streams
        .connect(b.id.public_key(), Duration::from_secs(10))
        .await
        .unwrap();
    // No wait here on purpose: B's accept() may not have finished yet, and
    // revocation must still win.

    // B removes A: close the streams first (so the close reaches A), then
    // drop A from the data plane.
    b.streams.retain_members(&[]).await;
    b.dp.set_members(&[]).await.unwrap();

    let closed = tokio::time::timeout(Duration::from_secs(5), conn.inner.closed()).await;
    assert!(closed.is_ok(), "A's connection should close promptly");
    let err = a
        .streams
        .probe(b.id.public_key(), Duration::from_secs(3))
        .await
        .unwrap_err();
    assert!(matches!(err, StreamsError::Unreachable(_)), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn adverts_only_from_members() {
    let a = device_with(Reachability::Public {
        // FIPS withholds adverts whose only address is loopback or private,
        // so advertise a global one (nothing dials it here).
        external_addr: Some("37.120.10.10:2121".parse().unwrap()),
    })
    .await;
    let (b, outsider) = (device().await, device().await);
    b.dp.set_members(&[Member::new(a.id.public_key())])
        .await
        .unwrap();

    let port_zero = Dataplane::start(
        &Identity::generate(),
        DataplaneConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            reachability: Reachability::Public {
                external_addr: None,
            },
            ..DataplaneConfig::default()
        },
    )
    .await;
    assert!(port_zero.is_err(), "public with port 0 is refused");

    let mut advert = None;
    for _ in 0..50 {
        advert = a.dp.local_advert().await.unwrap();
        if advert.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let advert = advert.expect("A produces an advert");
    let v: serde_json::Value = serde_json::from_str(&advert).unwrap();
    assert_eq!(v["kind"], 37195);
    assert_eq!(v["pubkey"], a.id.public_key().to_hex());

    b.dp.ingest_advert(&advert)
        .await
        .expect("member advert accepted");
    assert!(
        outsider.dp.ingest_advert(&advert).await.is_err(),
        "non-member author refused"
    );

    // A tampered advert fails signature verification.
    let tampered = advert.replace("37.120.10.10:2121", "37.120.10.10:2122");
    assert_ne!(tampered, advert);
    assert!(b.dp.ingest_advert(&tampered).await.is_err());
}
