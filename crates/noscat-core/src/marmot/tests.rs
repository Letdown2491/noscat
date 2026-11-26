//! Multi-device scenarios for [`MeshGroup`]: every test drives several
//! devices through the same events a relay would carry, in memory.

use super::*;
use nostr::prelude::{EventBuilder, FinalizeEvent as _, Kind};

const RELAY: &str = "wss://relay.example";

struct Dev {
    id: Identity,
    dir: PathBuf,
    g: MeshGroup,
}

impl Dev {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "noscat-marmot-{}-{}-{tag}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let id = Identity::generate();
        let g = MeshGroup::open(&dir, &id).unwrap();
        Self { id, dir, g }
    }

    fn pk(&self) -> PublicKey {
        self.id.public_key()
    }

    fn roster(&self) -> BTreeSet<PublicKey> {
        self.g.members().unwrap().into_iter().map(|m| m.device).collect()
    }

    fn reopen(&mut self) {
        self.g = MeshGroup::open(&self.dir, &self.id).unwrap();
    }
}

impl Drop for Dev {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn set(devs: &[&Dev]) -> BTreeSet<PublicKey> {
    devs.iter().map(|d| d.pk()).collect()
}

/// Admin `a` adds `new`: publish, confirm, deliver the Welcome.
fn invite(a: &mut Dev, new: &mut Dev) -> Event {
    let kp = new.g.key_package_event().unwrap();
    let out = a.g.add(&[kp]).unwrap();
    a.g.confirm().unwrap();
    assert_eq!(out.welcomes.len(), 1);
    let gw = a.g.wrap_welcome(&out.welcomes[0]).unwrap();
    let changes = new.g.join(&gw, Some(a.pk())).unwrap().expect("welcome is for this device");
    assert!(matches!(changes.as_slice(), [Change::Roster(_)]));
    out.commit
}

fn apps(changes: &[Change]) -> Vec<&AppEvent> {
    changes
        .iter()
        .filter_map(|c| match c {
            Change::App(e) => Some(e),
            _ => None,
        })
        .collect()
}

fn mesh_of_two() -> (Dev, Dev) {
    let mut a = Dev::new("a");
    let mut b = Dev::new("b");
    a.g.create("home", &[RELAY.into()]).unwrap();
    invite(&mut a, &mut b);
    (a, b)
}

#[test]
fn create_invite_and_talk() {
    let (mut a, mut b) = mesh_of_two();
    assert_eq!(a.roster(), set(&[&a, &b]));
    assert_eq!(b.roster(), set(&[&a, &b]));
    assert_eq!(b.g.name().unwrap(), "home");
    assert_eq!(b.g.relays().unwrap(), [RELAY]);
    assert_eq!(a.g.epoch(), b.g.epoch());
    assert_eq!(a.g.routing_ids(), b.g.routing_ids());
    // Every device is an admin.
    assert!(b.g.members().unwrap().iter().all(|m| m.admin));

    let ev = b.g.send_advert(Some(r#"{"x":1}"#), "laptop", true, false).unwrap();
    assert_eq!(ev.kind, Kind::Custom(GROUP_KIND));
    let got = a.g.process(&ev).unwrap();
    let got = apps(&got);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].pubkey, b.pk());
    assert_eq!(got[0].kind, ADVERT_KIND);
    assert_eq!(got[0].tag("name"), Some("laptop"));
    assert_eq!(got[0].tag("reachable"), Some("1"));
    // Duplicates are dropped; our own echo is ignored.
    assert!(a.g.process(&ev).unwrap().is_empty());
    assert!(b.g.process(&ev).unwrap().is_empty());
}

#[test]
fn third_device_and_removal() {
    let (mut a, mut b) = mesh_of_two();
    let mut c = Dev::new("c");
    // B (a joiner) can invite too: every device is an admin.
    let commit = invite(&mut b, &mut c);
    let ch = a.g.process(&commit).unwrap();
    assert!(matches!(ch.as_slice(), [Change::Roster(r)] if r.len() == 3));
    assert_eq!(a.roster(), set(&[&a, &b, &c]));
    assert_eq!(c.roster(), set(&[&a, &b, &c]));

    let ev = c.g.send_app(ADVERT_KIND, Vec::new(), String::new()).unwrap();
    assert_eq!(apps(&a.g.process(&ev).unwrap()).len(), 1);
    assert_eq!(apps(&b.g.process(&ev).unwrap()).len(), 1);

    // A removes C.
    let out = a.g.remove(&[c.pk()]).unwrap();
    a.g.confirm().unwrap();
    b.g.process(&out.commit).unwrap();
    let gone = c.g.process(&out.commit).unwrap();
    assert_eq!(gone, [Change::Removed]);
    assert!(!c.g.in_mesh());
    assert_eq!(a.roster(), set(&[&a, &b]));
    assert_eq!(b.roster(), set(&[&a, &b]));
    assert!(b.g.members().unwrap().iter().all(|m| m.admin));

    // C's later messages no longer reach anyone; B and A still talk.
    let ev = b.g.send_app(ADVERT_KIND, Vec::new(), "hi".into()).unwrap();
    assert_eq!(apps(&a.g.process(&ev).unwrap()).len(), 1);
}

#[test]
fn leave_steps_down_then_self_removes() {
    let (mut a, mut b) = mesh_of_two();
    let out = b.g.step_down().unwrap();
    b.g.confirm().unwrap();
    a.g.process(&out.commit).unwrap();
    assert!(!a.g.members().unwrap().iter().find(|m| m.device == b.pk()).unwrap().admin);

    let req = b.g.leave_request().unwrap();
    let ch = a.g.process(&req).unwrap();
    assert_eq!(ch, [Change::LeaveRequested(b.pk())]);
    let out = a.g.commit_pending().unwrap().expect("a SelfRemove to commit");
    a.g.confirm().unwrap();
    assert_eq!(a.roster(), set(&[&a]));
    assert_eq!(b.g.process(&out.commit).unwrap(), [Change::Removed]);
}

#[test]
fn sole_admin_cannot_step_down() {
    let mut a = Dev::new("a");
    a.g.create("solo", &[RELAY.into()]).unwrap();
    assert!(matches!(a.g.step_down(), Err(MeshError::NotAllowed(_))));
}

#[test]
fn abandoned_commit_changes_nothing() {
    let (mut a, mut b) = mesh_of_two();
    let mut c = Dev::new("c");
    let kp = c.g.key_package_event().unwrap();
    let epoch = a.g.epoch();
    a.g.add(&[kp]).unwrap();
    assert!(matches!(a.g.remove(&[b.pk()]), Err(MeshError::Pending)));
    a.g.abandon().unwrap();
    assert_eq!(a.g.epoch(), epoch);
    assert_eq!(a.roster(), set(&[&a, &b]));
    // The mesh still works.
    let ev = a.g.send_app(ADVERT_KIND, Vec::new(), String::new()).unwrap();
    assert_eq!(apps(&b.g.process(&ev).unwrap()).len(), 1);
}

#[test]
fn state_survives_restart() {
    let (mut a, mut b) = mesh_of_two();
    a.reopen();
    b.reopen();
    assert_eq!(a.roster(), set(&[&a, &b]));
    let ev = a.g.send_app(ADVERT_KIND, Vec::new(), "after restart".into()).unwrap();
    let got = b.g.process(&ev).unwrap();
    assert_eq!(apps(&got)[0].content, "after restart");
    // And a membership change after restart.
    let mut c = Dev::new("c");
    let commit = invite(&mut a, &mut c);
    b.g.process(&commit).unwrap();
    assert_eq!(b.roster(), set(&[&a, &b, &c]));
}

#[test]
fn welcome_from_unexpected_inviter_is_refused() {
    let mut a = Dev::new("a");
    let mut b = Dev::new("b");
    a.g.create("home", &[RELAY.into()]).unwrap();
    let kp = b.g.key_package_event().unwrap();
    let out = a.g.add(&[kp]).unwrap();
    a.g.confirm().unwrap();
    let gw = a.g.wrap_welcome(&out.welcomes[0]).unwrap();
    let stranger = Keys::generate().public_key();
    assert!(matches!(b.g.join(&gw, Some(stranger)), Err(MeshError::Welcome(_))));
    assert!(!b.g.in_mesh());
    // The key package is still usable for the right inviter.
    assert!(b.g.join(&gw, Some(a.pk())).unwrap().is_some());
}

#[test]
fn key_package_from_another_author_is_refused() {
    let mut a = Dev::new("a");
    let mut b = Dev::new("b");
    a.g.create("home", &[RELAY.into()]).unwrap();
    let kp = b.g.key_package_event().unwrap();
    // Re-sign B's package content under a different author.
    let forged = EventBuilder::new(kp.kind, kp.content.clone())
        .tags(kp.tags.iter().cloned())
        .finalize(&Keys::generate())
        .unwrap();
    assert!(matches!(a.g.add(&[forged]), Err(MeshError::KeyPackage(_))));
}

#[test]
fn messages_from_a_future_epoch_wait_for_the_commit() {
    let (mut a, mut b) = mesh_of_two();
    let mut c = Dev::new("c");
    let commit = invite(&mut a, &mut c);
    // C speaks at the new epoch before B has seen the commit.
    let ev = c.g.send_app(ADVERT_KIND, Vec::new(), "early".into()).unwrap();
    assert!(b.g.process(&ev).unwrap().is_empty());
    let ch = b.g.process(&commit).unwrap();
    assert_eq!(apps(&ch).len(), 1, "the deferred message is delivered after the commit: {ch:?}");
}

#[test]
fn concurrent_commits_converge() {
    let (mut a, mut b) = mesh_of_two();
    let mut c = Dev::new("c");
    let mut d = Dev::new("d");
    // A and B each add someone at the same epoch.
    let kc = c.g.key_package_event().unwrap();
    let kd = d.g.key_package_event().unwrap();
    let oa = a.g.add(&[kc]).unwrap();
    let ob = b.g.add(&[kd]).unwrap();
    a.g.confirm().unwrap();
    b.g.confirm().unwrap();
    assert_eq!(a.g.epoch(), b.g.epoch());
    // Each now sees the other's competing commit.
    let ca = a.g.process(&ob.commit).unwrap();
    let cb = b.g.process(&oa.commit).unwrap();
    // Exactly one side switched branches, and both agree now.
    let superseded = |ch: &[Change]| ch.iter().any(|c| matches!(c, Change::Superseded { own: true, .. }));
    assert!(superseded(&ca) ^ superseded(&cb), "{ca:?} / {cb:?}");
    assert_eq!(a.roster(), b.roster());
    assert_eq!(a.g.epoch(), b.g.epoch());
    assert_eq!(a.g.current_key().unwrap(), b.g.current_key().unwrap());
    // And they can talk on the converged branch.
    let ev = a.g.send_app(ADVERT_KIND, Vec::new(), "after race".into()).unwrap();
    assert_eq!(apps(&b.g.process(&ev).unwrap()).len(), 1);
}

#[test]
fn group_events_use_fresh_keys_and_one_h_tag() {
    let (mut a, _b) = mesh_of_two();
    let e1 = a.g.send_app(ADVERT_KIND, Vec::new(), String::new()).unwrap();
    let e2 = a.g.send_app(ADVERT_KIND, Vec::new(), String::new()).unwrap();
    assert_ne!(e1.pubkey, e2.pubkey);
    assert_ne!(e1.pubkey, a.pk());
    assert_eq!(e1.tags.iter().filter(|t| t.as_slice()[0] == "h").count(), 1);
}

/// Key packages are addressable (kind 30443, one slot per device): a relay
/// keeps only the newest and rejects a replacement that is not newer. A
/// device publishes one at start and `join` publishes another at once, so
/// two in the same second must still be strictly ordered, and the order
/// must survive a reopen (the next process).
#[test]
fn key_packages_get_strictly_increasing_timestamps() {
    let mut d = Dev::new("kp-ts");
    let a = d.g.key_package_event().unwrap();
    let b = d.g.key_package_event().unwrap();
    assert!(b.created_at > a.created_at, "{} !> {}", b.created_at, a.created_at);
    d.reopen();
    let c = d.g.key_package_event().unwrap();
    assert!(c.created_at > b.created_at, "{} !> {}", c.created_at, b.created_at);
}

#[test]
fn relays_and_private_mode_reach_members() {
    let (mut a, mut b) = mesh_of_two();
    let own = "wss://relay.mesh.example".to_string();
    let out = a.g.set_relays(&[own.clone()]).unwrap();
    a.g.confirm().unwrap();
    b.g.process(&out.commit).unwrap();
    assert_eq!(b.g.relays().unwrap(), [own.clone()]);
    assert!(!b.g.is_private());
    // Same routing id: members keep their subscriptions.
    assert_eq!(a.g.routing_ids(), b.g.routing_ids());

    let out = a.g.set_private(true).unwrap();
    a.g.confirm().unwrap();
    b.g.process(&out.commit).unwrap();
    assert!(a.g.is_private() && b.g.is_private());
    assert!(matches!(b.g.set_private(true), Err(MeshError::NotAllowed(_))));

    // Any admin can make it shared again.
    let out = b.g.set_private(false).unwrap();
    b.g.confirm().unwrap();
    a.g.process(&out.commit).unwrap();
    assert!(!a.g.is_private());
    assert!(matches!(a.g.set_relays(&[own]), Err(MeshError::NotAllowed(_))));
    assert!(a.g.set_relays(&["https://not-a-relay".into()]).is_err());
}
