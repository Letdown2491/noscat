//! TunnelStream end to end: complete a real Noise-XK handshake between two
//! loopback UDP sockets, wrap both sides, and echo bytes through the crypto
//! pump - including the half-close (FIN) semantics.

use noscat_client::{Client, ClientConfig, IdentitySource};
use noscat_core::identity::Identity;
use noscat_core::tunnel::{noise_keypair, TunnelInlet, TunnelStream};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

/// Drive the three Noise-XK messages across the two sockets.
async fn handshake(
    a: &UdpSocket,
    b: &UdpSocket,
    mut initiator: snow::HandshakeState,
    mut responder: snow::HandshakeState,
) -> (snow::TransportState, snow::TransportState) {
    let b_addr = b.local_addr().unwrap();
    let a_addr = a.local_addr().unwrap();
    let mut wire = [0u8; 65535];

    // msg1: a -> b
    let n = initiator.write_message(b"", &mut wire).unwrap();
    a.send_to(&wire[..n], b_addr).await.unwrap();
    let n = b.recv_from(&mut wire).await.unwrap().0;
    responder.read_message(&wire[..n], &mut [0u8; 0]).unwrap();

    // msg2: b -> a
    let n = responder.write_message(b"", &mut wire).unwrap();
    b.send_to(&wire[..n], a_addr).await.unwrap();
    let n = a.recv_from(&mut wire).await.unwrap().0;
    initiator.read_message(&wire[..n], &mut [0u8; 0]).unwrap();

    // msg3: a -> b, then both are in transport mode
    let n = initiator.write_message(b"", &mut wire).unwrap();
    a.send_to(&wire[..n], b_addr).await.unwrap();
    let n = b.recv_from(&mut wire).await.unwrap().0;
    responder.read_message(&wire[..n], &mut [0u8; 0]).unwrap();

    (
        noscat_core::noise::into_transport(initiator).unwrap(),
        noscat_core::noise::into_transport(responder).unwrap(),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn tunnel_stream_echo_with_half_close() {
    let id_a = Identity::generate();
    let id_b = Identity::generate();
    let (_pub_a, priv_a) = noise_keypair(&id_a).unwrap();
    let (pub_b, priv_b) = noise_keypair(&id_b).unwrap();

    let a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

    let init = noscat_core::noise::initiator(&priv_a, &pub_b, None).unwrap();
    let resp = noscat_core::noise::responder(&priv_b, None).unwrap();
    let (t_a, t_b) = handshake(&a, &b, init, resp).await;

    let mut stream_a = TunnelStream::new(
        a.clone(),
        b.local_addr().unwrap(),
        t_a,
        TunnelInlet::Exclusive,
        "peer-b",
    );
    let stream_b = TunnelStream::new(
        b.clone(),
        a.local_addr().unwrap(),
        t_b,
        TunnelInlet::Exclusive,
        "peer-a",
    );

    // Echo server: copy everything back until the client's FIN arrives.
    let echo = tokio::spawn(async move {
        let (mut rd, mut wr) = tokio::io::split(stream_b);
        tokio::io::copy(&mut rd, &mut wr).await.unwrap();
        wr.shutdown().await.unwrap();
    });

    let payload = b"hello over the tunnel".repeat(1000); // > one UDP datagram
    stream_a.write_all(&payload).await.unwrap();
    // Half-close: our FIN must reach the echo server, end its copy, and its
    // shutdown must surface as EOF here - after the full echo landed.
    stream_a.shutdown().await.unwrap();
    let mut echoed = Vec::new();
    stream_a.read_to_end(&mut echoed).await.unwrap();
    echo.await.unwrap();

    assert_eq!(echoed, payload);
}

/// The client-level config plumbing: identity from a hex secret, npub
/// reporting, and the one-shot event receiver.
#[test]
fn client_start_resolves_identity_and_events() {
    let id = Identity::generate();
    let mut client = Client::start(ClientConfig {
        identity: noscat_client::IdentitySource::Secret(id.secret_hex()),
        ..ClientConfig::default()
    })
    .unwrap();
    assert_eq!(client.npub(), id.npub());
    assert!(client.events().is_some());
    assert!(client.events().is_none()); // one-shot
}

/// Event emission over a real (local) client pair is covered by the loss
/// tests in noscat-core; here just prove connect() fails fast against empty
/// relays rather than hanging.
#[tokio::test(flavor = "multi_thread")]
async fn connect_fails_fast_without_reachable_advert() {
    let client = Client::start(ClientConfig {
        relays: Some(vec!["wss://127.0.0.1:1".to_string()]),
        ..ClientConfig::default()
    })
    .unwrap();
    let target = Identity::generate().npub();
    let res = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        tokio::task::spawn_blocking(move || client.connect(&target)),
    )
    .await
    .expect("connect should not hang")
    .unwrap();
    assert!(res.is_err()); // no advert anywhere
}

/// `--identity <file>` is the whole setup: a missing file is generated and
/// stored (0600), and later runs reuse the same identity.
#[test]
fn identity_file_is_created_and_stable() {
    let dir = std::env::temp_dir().join(format!(
        "noscat-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let path = dir.join("nested").join("identity.hex");

    let first = Client::start(ClientConfig {
        identity: IdentitySource::File(path.clone()),
        ..ClientConfig::default()
    })
    .expect("a missing identity file should be generated, not an error");

    let stored = std::fs::read_to_string(&path).expect("identity file written");
    assert_eq!(
        Identity::from_secret(stored.trim()).unwrap().npub(),
        first.npub()
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "secret file must be owner-only");
    }

    let second = Client::start(ClientConfig {
        identity: IdentitySource::File(path.clone()),
        ..ClientConfig::default()
    })
    .unwrap();
    assert_eq!(first.npub(), second.npub(), "same file, same identity");

    std::fs::remove_dir_all(&dir).ok();
}
