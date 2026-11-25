//! Secret files sealed at rest with a storage key. Its own test binary:
//! the key is process-wide.

use std::path::PathBuf;

use noscat_client::{Client, ClientConfig, IdentitySource};

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("noscat-sealed-{}-{}-{tag}", std::process::id(), rand::random::<u32>()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn config(dir: &PathBuf, relay: &str) -> ClientConfig {
    ClientConfig {
        identity: IdentitySource::File(dir.join("identity.nsec")),
        relays: Some(vec![relay.to_string()]),
        mesh_dir: Some(dir.clone()),
        lan_discovery: false,
        stun_servers: Some(vec!["stun:127.0.0.1:9".into()]),
        ..ClientConfig::default()
    }
}

fn sealed(path: PathBuf) -> bool {
    noscat_core::fsutil::is_sealed(&std::fs::read(path).unwrap())
}

#[test]
fn a_device_dir_is_sealed_migrates_and_refuses_without_the_key() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let relay = rt.block_on(nostr_relay_builder::MockRelay::run()).unwrap();
    let url = rt.block_on(relay.url()).to_string();
    let dir = tmp("dev");

    // A device made before the key existed: plain files.
    noscat_client::set_storage_key(None);
    let c = Client::start(config(&dir, &url)).unwrap();
    let npub = c.npub().to_string();
    c.create_mesh("home").unwrap();
    drop(c);
    assert!(!sealed(dir.join("identity.nsec")));
    assert!(!sealed(dir.join("mesh-state.json")));

    // With the key: the same device and mesh, both files now sealed.
    noscat_client::set_storage_key(Some([42; 32]));
    let c = Client::start(config(&dir, &url)).unwrap();
    assert_eq!(c.npub(), npub);
    assert_eq!(c.mesh_name().as_deref(), Some("home"));
    drop(c);
    assert!(sealed(dir.join("identity.nsec")));
    assert!(sealed(dir.join("mesh-state.json")));

    // Without it (or with another key) the device refuses to start, and
    // nothing is replaced: no fresh identity over the sealed one.
    let before = std::fs::read(dir.join("identity.nsec")).unwrap();
    for key in [None, Some([1; 32])] {
        noscat_client::set_storage_key(key);
        let err = Client::start(config(&dir, &url)).err().expect("must not start");
        assert!(err.to_string().contains("encrypted"), "{err}");
        assert_eq!(std::fs::read(dir.join("identity.nsec")).unwrap(), before);
    }

    // And back with the right key.
    noscat_client::set_storage_key(Some([42; 32]));
    let c = Client::start(config(&dir, &url)).unwrap();
    assert_eq!(c.npub(), npub);
    drop(c);
    std::fs::remove_dir_all(&dir).ok();
}
