//! The device runtime end to end against an in-process relay: create,
//! invite, join, adverts, streams between members, remove and leave.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use noscat_core::Identity;
use noscat_core::dataplane::{DataplaneConfig, Reachability};
use noscat_core::device::{Device, DeviceConfig, DeviceEvent};
use nostr::prelude::PublicKey;
use nostr_relay_builder::MockRelay;
use nostr_relay_builder::prelude::{LocalRelay, RelayBuilder, RelayBuilderNip42, RelayBuilderNip42Mode};

const T: Duration = Duration::from_secs(30);

/// With NOSCAT_TEST_LOG set (a RUST_LOG filter), devices log into the
/// test's captured output, which the harness prints when the test fails.
fn logs() {
    if let Ok(filter) = std::env::var("NOSCAT_TEST_LOG") {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
            .with_test_writer()
            .try_init();
    }
}

fn free_port() -> SocketAddr {
    std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap()
}

struct Node {
    id: Identity,
    addr: SocketAddr,
    dir: std::path::PathBuf,
}

fn node(tag: &str) -> Node {
    Node {
        id: Identity::generate(),
        addr: free_port(),
        dir: std::env::temp_dir().join(format!("noscat-device-{}-{}-{tag}", std::process::id(), rand::random::<u32>())),
    }
}

async fn start(n: &Node, name: &str, relay: &str, all: &[&Node]) -> Device {
    start_joining(n, name, relay, &[], all).await
}

/// As [`start`], started to join through `join` (a pairing code's relays).
async fn start_joining(n: &Node, name: &str, relay: &str, join: &[String], all: &[&Node]) -> Device {
    let peer_addresses: HashMap<PublicKey, Vec<SocketAddr>> =
        all.iter().map(|o| (o.id.public_key(), vec![o.addr])).collect();
    let cfg = DeviceConfig {
        dir: n.dir.clone(),
        name: name.into(),
        relays: vec![relay.into()],
        join_relays: join.to_vec(),
        dataplane: DataplaneConfig {
            bind: n.addr,
            reachability: Reachability::BehindNat,
            stun_servers: Some(vec!["stun:127.0.0.1:9".into()]),
            lan_discovery: false,
        },
        peer_addresses,
    };
    Device::start(n.id.clone(), cfg).await.unwrap()
}

async fn until<F, Fut>(what: &str, mut f: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + T;
    while !f().await {
        assert!(tokio::time::Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn invite_and_join(admin: &Device, joiner: &Device) {
    invite_and_join_via(admin, joiner, &[]).await;
}

/// As [`invite_and_join`], the joiner using `relays` (a pairing code's).
async fn invite_and_join_via(admin: &Device, joiner: &Device, relays: &[String]) {
    let mut rx = admin.subscribe();
    let j = joiner.clone();
    let inviter = admin.device();
    let relays = relays.to_vec();
    let waiting = tokio::spawn(async move { j.join(inviter, &relays, T).await });
    // The joiner asks the inviter (the QR it scanned) to invite it.
    let asked = tokio::time::timeout(T, async {
        loop {
            if let Ok(DeviceEvent::JoinRequest { device, .. }) = rx.recv().await {
                if device == joiner.device() {
                    return;
                }
            }
        }
    })
    .await;
    assert!(asked.is_ok(), "no join request from the joiner");
    admin.invite(joiner.device()).await.unwrap();
    waiting.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn mesh_lifecycle_over_a_relay() {
    let relay = MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    let (na, nb, nc) = (node("a"), node("b"), node("c"));
    let all = [&na, &nb, &nc];
    let a = start(&na, "alpha", &url, &all).await;
    let b = start(&nb, "bravo", &url, &all).await;

    a.create("home").await.unwrap();
    assert!(a.in_mesh().await);
    invite_and_join(&a, &b).await;
    assert_eq!(b.mesh_name().await.as_deref(), Some("home"));

    // Both see both, and names and presence arrive through adverts.
    until("a sees bravo online", || async {
        a.members().await.iter().any(|m| m.name.as_deref() == Some("bravo") && m.online)
    })
    .await;
    until("b sees alpha online", || async {
        b.members().await.iter().any(|m| m.name.as_deref() == Some("alpha") && m.online)
    })
    .await;
    assert!(a.members().await.iter().all(|m| m.admin));

    // A stream between members.
    let bs = b.streams().clone();
    let server = tokio::spawn(async move {
        let conn = bs.accept().await.unwrap();
        let (mut s, mut r) = conn.inner.accept_bi().await.unwrap();
        let got = r.read_to_end(1 << 20).await.unwrap();
        s.write_all(&got).await.unwrap();
        s.finish().unwrap();
        let _ = s.stopped().await;
        conn.peer
    });
    let conn = a.streams().connect(b.device(), T).await.unwrap();
    let (mut s, mut r) = conn.inner.open_bi().await.unwrap();
    s.write_all(b"over the mesh").await.unwrap();
    s.finish().unwrap();
    assert_eq!(r.read_to_end(1 << 20).await.unwrap(), b"over the mesh");
    assert_eq!(server.await.unwrap(), a.device());

    // App events reach the other members.
    let mut rx = b.subscribe();
    a.send_app(21196, vec![vec!["t".into(), "x".into()]], "hello".into()).await.unwrap();
    let got = tokio::time::timeout(T, async {
        loop {
            if let Ok(DeviceEvent::App(ev)) = rx.recv().await {
                return ev;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(got.content, "hello");
    assert_eq!(got.pubkey, a.device());

    // A third device, invited by a joiner.
    let c = start(&nc, "charlie", &url, &all).await;
    invite_and_join(&b, &c).await;
    until("a sees three", || async { a.members().await.len() == 3 }).await;
    until("c sees three", || async { c.members().await.len() == 3 }).await;

    // Removal reaches the removed device.
    let mut crx = c.subscribe();
    a.remove(&[c.device()]).await.unwrap();
    tokio::time::timeout(T, async {
        loop {
            if let Ok(DeviceEvent::Removed) = crx.recv().await {
                return;
            }
        }
    })
    .await
    .expect("c learns it was removed");
    assert!(!c.in_mesh().await);
    until("b sees two", || async { b.members().await.len() == 2 }).await;

    // B leaves: it steps down, A commits its SelfRemove.
    b.leave(T).await.unwrap();
    assert!(!b.in_mesh().await);
    until("a is alone", || async { a.members().await.len() == 1 }).await;

    for d in [a, b, c] {
        d.shutdown().await;
    }
    for n in all {
        let _ = std::fs::remove_dir_all(&n.dir);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn state_survives_a_restart() {
    let relay = MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    let (na, nb) = (node("ra"), node("rb"));
    let all = [&na, &nb];
    let a = start(&na, "alpha", &url, &all).await;
    let b = start(&nb, "bravo", &url, &all).await;
    a.create("home").await.unwrap();
    invite_and_join(&a, &b).await;
    b.shutdown().await;
    drop(b);

    // While B is down, a third device joins; B catches up on restart.
    let nc = node("rc");
    let c = start(&nc, "charlie", &url, &[&na, &nb, &nc]).await;
    invite_and_join(&a, &c).await;

    let b = start(&nb, "bravo", &url, &all).await;
    assert!(b.in_mesh().await);
    until("b catches up to three members", || async { b.members().await.len() == 3 }).await;

    for d in [a, b, c] {
        d.shutdown().await;
    }
    for n in [&na, &nb, &nc] {
        let _ = std::fs::remove_dir_all(&n.dir);
    }
}

/// A mesh moves to its own relay and goes private: its devices log in
/// there (the relay serves nobody else) and leave the public relay, and a
/// new device joins through the pairing code's relay alone. The public
/// relay is shut down first, so anything still using it would fail.
#[tokio::test(flavor = "multi_thread")]
async fn private_mesh_on_its_own_relay() {
    logs();
    let public = LocalRelay::new(RelayBuilder::default());
    public.run().await.unwrap();
    let public_url = public.url().await.to_string();
    // Reads need a login, as on noscat-relay. (This relay cannot take
    // writes behind a login: it wants the author logged in, and group
    // events are signed by a fresh key each.)
    let own = LocalRelay::new(RelayBuilder::default().nip42(RelayBuilderNip42 {
        mode: RelayBuilderNip42Mode::Read,
    }));
    own.run().await.unwrap();
    let own_url = own.url().await.to_string().trim_end_matches('/').to_string();

    let (na, nb, nc) = (node("pa"), node("pb"), node("pc"));
    let all = [&na, &nb, &nc];
    let a = start(&na, "alpha", &public_url, &all).await;
    let b = start(&nb, "bravo", &public_url, &all).await;
    a.create("home").await.unwrap();
    invite_and_join(&a, &b).await;

    a.set_mesh_relays(&[own_url.clone()]).await.unwrap();
    until("b sees the new relay", || async { b.mesh_relays().await == [own_url.clone()] }).await;
    a.set_private(true).await.unwrap();
    until("b sees the mesh private", || async { b.is_private().await }).await;
    public.shutdown();

    // Group traffic now flows over the own relay, which answers only
    // logged-in devices.
    let mut rx = b.subscribe();
    a.send_app(21196, vec![vec!["t".into(), "x".into()]], "private".into()).await.unwrap();
    let got = tokio::time::timeout(T, async {
        loop {
            if let Ok(DeviceEvent::App(ev)) = rx.recv().await {
                if ev.content == "private" {
                    return;
                }
            }
        }
    })
    .await;
    assert!(got.is_ok(), "no app event over the private relay");

    // A new device, configured with another public relay (alive), joins
    // through the relay its pairing code names, started for that join:
    // nothing of it, not even its key package, reaches the public relay.
    let decoy = LocalRelay::new(RelayBuilder::default());
    decoy.run().await.unwrap();
    let decoy_url = decoy.url().await.to_string();
    let c = start_joining(&nc, "charlie", &decoy_url, &[own_url.clone()], &all).await;
    invite_and_join_via(&a, &c, &[own_url.clone()]).await;
    assert!(c.is_private().await);
    assert_eq!(c.mesh_relays().await, [own_url.clone()]);
    until("b sees charlie", || async { b.members().await.iter().any(|m| m.device == c.device()) }).await;
    let probe = nostr_sdk::prelude::Client::default();
    probe.add_relay(decoy_url.as_str()).await.unwrap();
    probe.connect().await;
    let leaked = probe
        .fetch_events(nostr::prelude::Filter::new().author(c.device()))
        .timeout(Duration::from_secs(5))
        .await
        .unwrap();
    assert!(leaked.is_empty(), "the joining device published to a public relay: {:?}", leaked.iter().map(|e| e.kind).collect::<Vec<_>>());
    decoy.shutdown();

    for d in [a, b, c] {
        d.shutdown().await;
    }
    for n in all {
        let _ = std::fs::remove_dir_all(&n.dir);
    }
}

/// A member that was offline catches up on everything, even from a relay
/// that returns only the newest few events of a query (public relays cap
/// results, newest first). Before paging, it got the newest slice, missed
/// the commit adding a member and moved its sync point past it.
#[tokio::test(flavor = "multi_thread")]
async fn catch_up_through_a_capped_relay() {
    let relay = LocalRelay::new(RelayBuilder::default().max_filter_limit(8).default_filter_limit(8));
    relay.run().await.unwrap();
    let url = relay.url().await.to_string();
    let (na, nb, nc) = (node("ca"), node("cb"), node("cc"));
    let all = [&na, &nb, &nc];
    let a = start(&na, "alpha", &url, &all).await;
    let b = start(&nb, "bravo", &url, &all).await;
    a.create("home").await.unwrap();
    invite_and_join(&a, &b).await;
    b.shutdown().await;

    // While b is away: a member joins, then plenty of traffic buries the
    // commit under far more than the relay returns at once.
    let c = start(&nc, "charlie", &url, &all).await;
    invite_and_join(&a, &c).await;
    // Spread over seconds like real traffic: Nostr pages by whole seconds.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    for i in 0..24 {
        a.send_app(21196, Vec::new(), format!("filler {i}")).await.unwrap();
        tokio::time::sleep(Duration::from_millis(350)).await;
    }

    let b = start(&nb, "bravo", &url, &all).await;
    until("b sees charlie", || async { b.members().await.iter().any(|m| m.device == c.device()) }).await;
    // And b follows the current epoch: a new message reaches it.
    let mut rx = b.subscribe();
    a.send_app(21196, Vec::new(), "after catch-up".into()).await.unwrap();
    let got = tokio::time::timeout(T, async {
        loop {
            if let Ok(DeviceEvent::App(ev)) = rx.recv().await {
                if ev.content == "after catch-up" {
                    return;
                }
            }
        }
    })
    .await;
    assert!(got.is_ok(), "b is not on the current epoch");

    for d in [a, b, c] {
        d.shutdown().await;
    }
    for n in all {
        let _ = std::fs::remove_dir_all(&n.dir);
    }
}

/// A member restarted moments after its last advert knows nobody's
/// endpoints (the adverts it saw are marked seen, so catching up skips
/// them), and the others still count it as online. Its first advert says
/// `hello`, so they answer at once instead of at their next tick, two
/// minutes away.
#[tokio::test(flavor = "multi_thread")]
async fn a_quick_restart_hears_from_members_at_once() {
    logs();
    let relay = MockRelay::run().await.unwrap();
    let url = relay.url().await.to_string();
    let (na, nb) = (node("qa"), node("qb"));
    let all = [&na, &nb];
    let a = start(&na, "alpha", &url, &all).await;
    let b = start(&nb, "bravo", &url, &all).await;
    a.create("home").await.unwrap();
    invite_and_join(&a, &b).await;
    let online = |d: Device, who: PublicKey| async move { d.members().await.iter().any(|m| m.device == who && m.online) };
    until("a sees b", || online(a.clone(), nb.id.public_key())).await;
    until("b sees a", || online(b.clone(), na.id.public_key())).await;

    b.shutdown().await;
    drop(b);
    let b = start(&nb, "bravo", &url, &all).await;
    let t = std::time::Instant::now();
    until("the restarted b hears from a", || online(b.clone(), na.id.public_key())).await;
    assert!(t.elapsed() < Duration::from_secs(20), "took {:?}", t.elapsed());

    for d in [a, b] {
        d.shutdown().await;
    }
    for n in [&na, &nb] {
        let _ = std::fs::remove_dir_all(&n.dir);
    }
}

/// A relay that refuses gift wraps while the flag is set: it loses
/// invitations (and join requests) until it recovers.
#[derive(Debug)]
struct RefuseGiftWraps(std::sync::Arc<std::sync::atomic::AtomicBool>);

impl nostr_relay_builder::prelude::WritePolicy for RefuseGiftWraps {
    fn admit_event<'a>(
        &'a self,
        event: &'a nostr_relay_builder::prelude::Event,
        _addr: &'a SocketAddr,
    ) -> nostr_relay_builder::prelude::BoxedFuture<'a, nostr_relay_builder::prelude::PolicyResult> {
        use nostr_relay_builder::prelude::{Kind, PolicyResult};
        Box::pin(async move {
            if event.kind == Kind::GiftWrap && self.0.load(std::sync::atomic::Ordering::SeqCst) {
                PolicyResult::Reject("blocked: no gift wraps right now".into())
            } else {
                PolicyResult::Accept
            }
        })
    }
}

/// An invitation no relay accepts: the invite says so, the member shows as
/// joining, and the Welcome is resent (here prompted by the joiner asking
/// again) once the relay takes gift wraps. After the join, the joiner's
/// used key package is deleted from the relay.
#[tokio::test(flavor = "multi_thread")]
async fn a_lost_invitation_is_resent_and_the_used_key_package_deleted() {
    logs();
    use noscat_core::marmot::MemberState;
    let refuse = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let relay = LocalRelay::new(RelayBuilder::default().write_policy(RefuseGiftWraps(refuse.clone())));
    relay.run().await.unwrap();
    let url = relay.url().await.to_string();
    let (na, nb) = (node("a"), node("b"));
    let all = [&na, &nb];
    let a = start(&na, "alpha", &url, &all).await;
    let b = start(&nb, "bravo", &url, &all).await;
    a.create("home").await.unwrap();
    b.publish_key_package().await.unwrap();

    refuse.store(true, std::sync::atomic::Ordering::SeqCst);
    let invited = a.invite(b.device()).await.unwrap();
    assert!(!invited.welcome_accepted, "the relay refused the Welcome");
    let state = |d: &Device, who: PublicKey| {
        let d = d.clone();
        async move { d.members().await.into_iter().find(|m| m.device == who).map(|m| m.state) }
    };
    assert_eq!(state(&a, b.device()).await, Some(MemberState::Pending));

    let j = b.clone();
    let inviter = a.device();
    // Long enough for either resend: the joiner's next request (15 s after
    // its stored-invitation fetch, which is slow on some CI hosts) or the
    // inviter's own retry (30 s after the invite, on a 15 s tick).
    let waiting = tokio::spawn(async move { j.join(inviter, &[], Duration::from_secs(90)).await });
    tokio::time::sleep(Duration::from_secs(1)).await;
    refuse.store(false, std::sync::atomic::Ordering::SeqCst);
    waiting.await.unwrap().expect("the resent Welcome arrives");
    until("a sees bravo active", || async { state(&a, b.device()).await == Some(MemberState::Active) }).await;

    let probe = nostr_sdk::prelude::Client::default();
    probe.add_relay(url.as_str()).await.unwrap();
    probe.connect().await;
    until("b's used key package is gone from the relay", || async {
        probe
            .fetch_events(nostr::prelude::Filter::new().author(b.device()).kind(nostr::prelude::Kind::Custom(30443)))
            .timeout(Duration::from_secs(5))
            .await
            .is_ok_and(|evs| evs.is_empty())
    })
    .await;

    for d in [a, b] {
        d.shutdown().await;
    }
    for n in all {
        let _ = std::fs::remove_dir_all(&n.dir);
    }
}
