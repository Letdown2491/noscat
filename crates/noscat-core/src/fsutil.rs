//! Durable small-file writes: the crash windows an audit found around
//! the identity, mesh sidecar, and journal files. Three primitives:
//!
//! - [`write_atomic`] - temp file, fsync, rename: a crash mid-write
//!   leaves the previous contents intact instead of a truncated file
//!   that fails to parse on every later start.
//! - [`create_secret_file`] - create-new with owner-only mode on unix;
//!   the create-race loser gets `Ok(false)` and reads the winner, so
//!   two concurrent initializations never clobber each other's key.
//! - [`heal_secret_mode`] - best-effort chmod 0600 for files written
//!   by older versions with default permissions.
//!
//! Secret files (the identity and the mesh state) can also be sealed at
//! rest: after [`set_storage_key`], [`seal`] encrypts them with
//! XChaCha20-Poly1305 under that key (the apps keep it in the Android
//! Keystore or the desktop keyring), and [`unseal`] reads either form, so
//! plain files from before migrate on their next write.

use std::io;
use std::path::Path;
use std::sync::RwLock;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

/// Marks a sealed file: magic, then a 24-byte nonce, then the ciphertext.
const SEAL_MAGIC: &[u8] = b"noscat-sealed-v1\n";

static STORAGE_KEY: RwLock<Option<[u8; 32]>> = RwLock::new(None);

/// Seal secret files with `key` from now on (`None`: write them plain).
/// Process-wide: call it once, before starting a client or using a
/// device directory.
pub fn set_storage_key(key: Option<[u8; 32]>) {
    if let Ok(mut k) = STORAGE_KEY.write() {
        *k = key;
    }
}

fn storage_key() -> Option<[u8; 32]> {
    STORAGE_KEY.read().ok().and_then(|k| *k)
}

/// Whether secret files are being sealed.
#[must_use]
pub fn has_storage_key() -> bool {
    storage_key().is_some()
}

/// Whether `data` is a sealed file.
#[must_use]
pub fn is_sealed(data: &[u8]) -> bool {
    data.starts_with(SEAL_MAGIC)
}

/// `plain` sealed under the storage key, bound to `name` (the file name,
/// so sealed files cannot be swapped for each other); unchanged when no
/// key is set.
pub fn seal(name: &str, plain: &[u8]) -> io::Result<Vec<u8>> {
    seal_with(storage_key(), name, plain)
}

fn seal_with(key: Option<[u8; 32]>, name: &str, plain: &[u8]) -> io::Result<Vec<u8>> {
    let Some(key) = key else {
        return Ok(plain.to_vec());
    };
    let mut nonce = [0u8; 24];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut nonce);
    let ct = XChaCha20Poly1305::new(&key.into())
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plain, aad: name.as_bytes() })
        .map_err(|_| io::Error::other("sealing failed"))?;
    let mut out = Vec::with_capacity(SEAL_MAGIC.len() + nonce.len() + ct.len());
    out.extend_from_slice(SEAL_MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// The plaintext of a file read from disk: sealed files are opened with
/// the storage key, plain ones pass through. A sealed file without the
/// right key is an error, never "missing": the caller must not create a
/// fresh identity over it.
pub fn unseal(name: &str, data: &[u8]) -> io::Result<Vec<u8>> {
    unseal_with(storage_key(), name, data)
}

fn unseal_with(key: Option<[u8; 32]>, name: &str, data: &[u8]) -> io::Result<Vec<u8>> {
    let Some(rest) = data.strip_prefix(SEAL_MAGIC) else {
        return Ok(data.to_vec());
    };
    let key = key.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{name} is encrypted and this process has no storage key (the app that wrote it keeps the key)"),
        )
    })?;
    if rest.len() < 24 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("{name}: truncated sealed file")));
    }
    let (nonce, ct) = rest.split_at(24);
    XChaCha20Poly1305::new(&key.into())
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: name.as_bytes() })
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{name} is encrypted with a different storage key"),
            )
        })
}

fn file_name(path: &Path) -> &str {
    path.file_name().and_then(|n| n.to_str()).unwrap_or("noscat")
}

/// Read a secret file, unsealing it.
pub fn read_secret(path: &Path) -> io::Result<Vec<u8>> {
    unseal(file_name(path), &std::fs::read(path)?)
}

/// Write a secret file atomically and owner-only, sealed when a storage
/// key is set.
pub fn write_secret(path: &Path, plain: &[u8]) -> io::Result<()> {
    write_private_atomic(path, &seal(file_name(path), plain)?)
}

/// Write `contents` to `path` atomically: the data lands in a temp file
/// in the same directory (so the rename is a same-filesystem metadata
/// op), is fsynced, then renamed over `path`. The directory entry is
/// fsynced too (best-effort) so the rename itself survives power loss.
pub fn write_atomic(path: &Path, contents: &[u8]) -> io::Result<()> {
    use std::io::Write as _;

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("noscat");
    let tmp = dir.join(format!("{name}.tmp"));
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(contents)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    #[cfg(unix)]
    {
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

/// [`write_atomic`] for files holding secrets: the temp file is created
/// owner-only on unix before any byte lands in it.
pub fn write_private_atomic(path: &Path, contents: &[u8]) -> io::Result<()> {
    use std::io::Write as _;

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("noscat");
    let tmp = dir.join(format!("{name}.tmp"));
    let _ = std::fs::remove_file(&tmp);
    {
        let mut f = new_secret_options().write(true).create_new(true).open(&tmp)?;
        f.write_all(contents)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    #[cfg(unix)]
    {
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

/// OpenOptions for a secret file: owner-only on unix, plain elsewhere
/// (Windows and the BSDs via cargo install get the default mode).
fn new_secret_options() -> std::fs::OpenOptions {
    let mut o = std::fs::OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o
}

/// Create `path` with `contents` ONLY if it does not already exist.
/// Returns `Ok(true)` when this call created the file, `Ok(false)` when
/// it already existed (a concurrent initialization won the create race:
/// the caller must then READ the file and adopt that identity - it must
/// never overwrite, which would silently fork the device's key).
/// `Err` is a real I/O failure.
pub fn create_secret_file(path: &Path, contents: &str) -> io::Result<bool> {
    use std::io::Write as _;

    let sealed = seal(file_name(path), contents.as_bytes())?;
    match new_secret_options().write(true).create_new(true).open(path) {
        Ok(mut f) => {
            f.write_all(&sealed)?;
            f.sync_all()?;
            Ok(true)
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(e),
    }
}

/// Best-effort chmod 0600 on unix (no-op elsewhere). Logs on failure:
/// a world-readable master secret must never pass silently.
pub fn heal_secret_mode(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
            tracing::warn!(file = %path.display(), "cannot set owner-only permissions: {e}");
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "noscat-fsutil-{}-{}-{tag}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn write_atomic_survives_and_overwrites() {
        let dir = tmpdir("atomic");
        let path = dir.join("state.json");

        write_atomic(&path, b"first").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"first");

        write_atomic(&path, b"second").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second");

        // No temp litter left behind.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn sealing_round_trips_and_refuses_without_the_key() {
        // The key-taking forms: the process-wide key would race the other
        // tests that write mesh state in parallel.
        let k = Some([7; 32]);

        // No key: plain in, plain out; plain files read as is with a key
        // too (they migrate on the next write).
        assert_eq!(seal_with(None, "f", b"plain").unwrap(), b"plain");
        assert_eq!(unseal_with(k, "f", b"plain").unwrap(), b"plain");

        let sealed = seal_with(k, "mesh-state.json", b"secret").unwrap();
        assert!(is_sealed(&sealed));
        assert!(!sealed.windows(6).any(|w| w == b"secret"));
        assert_eq!(unseal_with(k, "mesh-state.json", &sealed).unwrap(), b"secret");
        // Fresh nonce per write.
        assert_ne!(seal_with(k, "mesh-state.json", b"secret").unwrap(), sealed);

        // Bound to its name: swapped files fail.
        assert!(unseal_with(k, "identity.nsec", &sealed).is_err());
        // A wrong key or no key is an error, never empty or "missing".
        let denied = io::ErrorKind::PermissionDenied;
        assert_eq!(unseal_with(Some([8; 32]), "mesh-state.json", &sealed).unwrap_err().kind(), denied);
        assert_eq!(unseal_with(None, "mesh-state.json", &sealed).unwrap_err().kind(), denied);
        assert!(unseal_with(k, "mesh-state.json", SEAL_MAGIC).is_err());
    }

    #[test]
    fn create_secret_file_race_loser_reads_winner() {
        let dir = tmpdir("secret");
        let path = dir.join("identity.nsec");

        assert_eq!(create_secret_file(&path, "winner\n").unwrap(), true);
        // The loser's fresh key must NOT land in the file.
        assert_eq!(create_secret_file(&path, "loser\n").unwrap(), false);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "winner\n");
        std::fs::remove_dir_all(&dir).ok();
    }
}
