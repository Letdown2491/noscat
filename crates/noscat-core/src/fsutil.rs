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

use std::io;
use std::path::Path;

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

    match new_secret_options().write(true).create_new(true).open(path) {
        Ok(mut f) => {
            f.write_all(contents.as_bytes())?;
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
