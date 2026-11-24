//! App protocols on QUIC streams between members: file transfer, text
//! (chat and clipboard) and TCP forwarding.
//!
//! Every stream is bidirectional and starts with a one-byte service tag
//! and a service header from the opener; the accepter answers with a
//! status. Peers are already authenticated: a stream only exists between
//! two current members (see `crate::streams`). The wire format is in
//! `docs/nip-noscat.md`.
//!
//! - File: `[1][u16 name_len][name][u64 size][32 sha256]`. The receiver
//!   answers with the `u64` offset to resume from (`u64::MAX` = refused);
//!   the sender streams the rest; the receiver verifies the whole file and
//!   answers `0` (verified) or `1` (mismatch). A partial receive leaves
//!   `<name>.noscat-part` plus a `.noscat-sha` sidecar, so a resend of the
//!   same file resumes.
//! - Text: `[2][u8 kind][u32 len][utf8]`, answered `0` once received.
//! - Forward: `[3][u16 port]`, answered `0` (bridged) or `1` (refused),
//!   then raw bytes both ways.

use std::path::{Path, PathBuf};

use quinn::{RecvStream, SendStream};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _, AsyncWriteExt as _};

use crate::streams::Connection;

const TAG_FILE: u8 = 1;
const TAG_TEXT: u8 = 2;
const TAG_FORWARD: u8 = 3;
const OK: u8 = 0;
const FAIL: u8 = 1;
const REFUSED_OFFSET: u64 = u64::MAX;
/// Longest text message.
pub const MAX_TEXT: usize = 64 * 1024;
const MAX_NAME: usize = 255;
const CHUNK: usize = 64 * 1024;
/// Suffix of a partial receive and of its sha256 sidecar.
pub const PART_SUFFIX: &str = ".noscat-part";
const SHA_SUFFIX: &str = ".noscat-sha";

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("stream: {0}")]
    Stream(String),
    #[error("protocol: {0}")]
    Protocol(&'static str),
    #[error("the receiver refused the transfer")]
    Refused,
    #[error("the received file did not match its sha256")]
    Mismatch,
}

fn stream_err<E: std::fmt::Display>(e: E) -> AppError {
    AppError::Stream(e.to_string())
}

/// What a text message is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextKind {
    Chat,
    Clipboard,
}

impl TextKind {
    fn byte(self) -> u8 {
        match self {
            Self::Chat => 0,
            Self::Clipboard => 1,
        }
    }
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Chat),
            1 => Some(Self::Clipboard),
            _ => None,
        }
    }
}

async fn read_u8(r: &mut RecvStream) -> Result<u8, AppError> {
    let mut b = [0u8; 1];
    r.read_exact(&mut b).await.map_err(stream_err)?;
    Ok(b[0])
}

async fn read_u16(r: &mut RecvStream) -> Result<u16, AppError> {
    let mut b = [0u8; 2];
    r.read_exact(&mut b).await.map_err(stream_err)?;
    Ok(u16::from_be_bytes(b))
}

async fn read_u32(r: &mut RecvStream) -> Result<u32, AppError> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b).await.map_err(stream_err)?;
    Ok(u32::from_be_bytes(b))
}

async fn read_u64(r: &mut RecvStream) -> Result<u64, AppError> {
    let mut b = [0u8; 8];
    r.read_exact(&mut b).await.map_err(stream_err)?;
    Ok(u64::from_be_bytes(b))
}

async fn write(s: &mut SendStream, b: &[u8]) -> Result<(), AppError> {
    s.write_all(b).await.map_err(stream_err)
}

// ---- sending -----------------------------------------------------------

/// Send a text message and wait for the receiver to confirm it.
pub async fn send_text(conn: &Connection, kind: TextKind, text: &str) -> Result<(), AppError> {
    if text.len() > MAX_TEXT {
        return Err(AppError::Protocol("text too long"));
    }
    let (mut s, mut r) = conn.inner.open_bi().await.map_err(stream_err)?;
    let mut head = vec![TAG_TEXT, kind.byte()];
    head.extend_from_slice(&u32::try_from(text.len()).unwrap_or(u32::MAX).to_be_bytes());
    head.extend_from_slice(text.as_bytes());
    write(&mut s, &head).await?;
    s.finish().map_err(stream_err)?;
    match read_u8(&mut r).await? {
        OK => Ok(()),
        _ => Err(AppError::Refused),
    }
}

/// Hash a file (used before sending, so the receiver can verify and
/// resume).
pub async fn sha256_file(path: &Path) -> Result<[u8; 32], AppError> {
    let mut f = tokio::fs::File::open(path).await?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = f.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().into())
}

/// Send a file. `progress(sent, total)` is called as bytes go out
/// (`sent` counts the resumed prefix too).
pub async fn send_file(
    conn: &Connection,
    path: &Path,
    mut progress: impl FnMut(u64, u64) + Send,
) -> Result<(), AppError> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or(AppError::Protocol("file name is not UTF-8"))?;
    if name.len() > MAX_NAME {
        return Err(AppError::Protocol("file name too long"));
    }
    let size = tokio::fs::metadata(path).await?.len();
    let sha = sha256_file(path).await?;
    let (mut s, mut r) = conn.inner.open_bi().await.map_err(stream_err)?;
    let mut head = vec![TAG_FILE];
    head.extend_from_slice(&u16::try_from(name.len()).unwrap_or(0).to_be_bytes());
    head.extend_from_slice(name.as_bytes());
    head.extend_from_slice(&size.to_be_bytes());
    head.extend_from_slice(&sha);
    write(&mut s, &head).await?;
    let offset = read_u64(&mut r).await?;
    if offset == REFUSED_OFFSET {
        return Err(AppError::Refused);
    }
    if offset > size {
        return Err(AppError::Protocol("resume offset past the end"));
    }
    let mut f = tokio::fs::File::open(path).await?;
    f.seek(std::io::SeekFrom::Start(offset)).await?;
    let mut sent = offset;
    progress(sent, size);
    let mut buf = vec![0u8; CHUNK];
    while sent < size {
        let want = usize::try_from((size - sent).min(CHUNK as u64)).unwrap_or(CHUNK);
        let n = f.read(&mut buf[..want]).await?;
        if n == 0 {
            return Err(AppError::Protocol("file shrank while sending"));
        }
        write(&mut s, &buf[..n]).await?;
        sent += n as u64;
        progress(sent, size);
    }
    s.finish().map_err(stream_err)?;
    match read_u8(&mut r).await? {
        OK => Ok(()),
        _ => Err(AppError::Mismatch),
    }
}

/// Open a forwarded TCP connection to `port` on the member (0 = its
/// default bridge). Returns the raw stream pair once the member accepted.
pub async fn open_forward(conn: &Connection, port: u16) -> Result<(SendStream, RecvStream), AppError> {
    let (mut s, mut r) = conn.inner.open_bi().await.map_err(stream_err)?;
    let mut head = vec![TAG_FORWARD];
    head.extend_from_slice(&port.to_be_bytes());
    write(&mut s, &head).await?;
    match read_u8(&mut r).await? {
        OK => Ok((s, r)),
        _ => Err(AppError::Refused),
    }
}

/// Copy between a TCP connection and a forwarded stream until both sides
/// close.
pub async fn bridge(tcp: tokio::net::TcpStream, mut s: SendStream, mut r: RecvStream) -> Result<(), AppError> {
    let (mut tr, mut tw) = tcp.into_split();
    let up = async {
        let res = tokio::io::copy(&mut tr, &mut s).await;
        let _ = s.finish();
        res
    };
    let down = async {
        let res = tokio::io::copy(&mut r, &mut tw).await;
        let _ = tw.shutdown().await;
        res
    };
    let (a, b) = tokio::join!(up, down);
    a?;
    b?;
    Ok(())
}

// ---- receiving ---------------------------------------------------------

/// An incoming stream, after its header was read.
#[derive(Debug)]
pub enum Incoming {
    File(IncomingFile),
    Text { kind: TextKind, text: String },
    Forward(IncomingForward),
}

/// A file offer. Call [`IncomingFile::receive`] or [`IncomingFile::refuse`].
#[derive(Debug)]
pub struct IncomingFile {
    pub name: String,
    pub size: u64,
    pub sha256: [u8; 32],
    s: SendStream,
    r: RecvStream,
}

/// A forward request. Call [`IncomingForward::accept`] or
/// [`IncomingForward::refuse`].
#[derive(Debug)]
pub struct IncomingForward {
    pub port: u16,
    s: SendStream,
    r: RecvStream,
}

/// How a receive ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Received {
    /// Verified and renamed into place.
    Done(PathBuf),
    /// The stream ended early; the partial file is kept for a resume.
    Partial(PathBuf),
}

/// Read the header of the next stream on `conn`. Text is read and
/// acknowledged here. `Ok(None)` when the connection closed.
pub async fn accept(conn: &Connection) -> Result<Option<Incoming>, AppError> {
    let (mut s, mut r) = match conn.inner.accept_bi().await {
        Ok(p) => p,
        Err(_) => return Ok(None),
    };
    match read_u8(&mut r).await? {
        TAG_TEXT => {
            let kind = TextKind::from_byte(read_u8(&mut r).await?).ok_or(AppError::Protocol("text kind"))?;
            let len = read_u32(&mut r).await? as usize;
            if len > MAX_TEXT {
                return Err(AppError::Protocol("text too long"));
            }
            let mut b = vec![0u8; len];
            r.read_exact(&mut b).await.map_err(stream_err)?;
            let text = String::from_utf8(b).map_err(|_| AppError::Protocol("text is not UTF-8"))?;
            write(&mut s, &[OK]).await?;
            let _ = s.finish();
            Ok(Some(Incoming::Text { kind, text }))
        }
        TAG_FILE => {
            let len = read_u16(&mut r).await? as usize;
            if len == 0 || len > MAX_NAME {
                return Err(AppError::Protocol("file name length"));
            }
            let mut b = vec![0u8; len];
            r.read_exact(&mut b).await.map_err(stream_err)?;
            let name = String::from_utf8(b).map_err(|_| AppError::Protocol("file name is not UTF-8"))?;
            let size = read_u64(&mut r).await?;
            let mut sha256 = [0u8; 32];
            r.read_exact(&mut sha256).await.map_err(stream_err)?;
            Ok(Some(Incoming::File(IncomingFile { name, size, sha256, s, r })))
        }
        TAG_FORWARD => {
            let port = read_u16(&mut r).await?;
            Ok(Some(Incoming::Forward(IncomingForward { port, s, r })))
        }
        _ => Err(AppError::Protocol("unknown service")),
    }
}

/// A file name safe to create in the receive directory: the last path
/// component, without separators or leading dots.
#[must_use]
pub fn safe_name(name: &str) -> Option<String> {
    let base = name.rsplit(['/', '\\']).next()?.trim();
    let base = base.trim_start_matches('.');
    if base.is_empty() || base.contains('\0') || base.len() > MAX_NAME {
        return None;
    }
    Some(base.to_string())
}

/// A path in `dir` for `name` that does not exist yet ("a.txt", then
/// "a (1).txt", ...).
fn unused_path(dir: &Path, name: &str) -> PathBuf {
    let p = dir.join(name);
    if !p.exists() {
        return p;
    }
    let (stem, ext) = match name.rsplit_once('.') {
        Some((s, e)) if !s.is_empty() => (s.to_string(), format!(".{e}")),
        _ => (name.to_string(), String::new()),
    };
    (1..)
        .map(|i| dir.join(format!("{stem} ({i}){ext}")))
        .find(|p| !p.exists())
        .expect("an unused name exists")
}

impl IncomingFile {
    /// Refuse the transfer.
    pub async fn refuse(mut self) {
        let _ = write(&mut self.s, &REFUSED_OFFSET.to_be_bytes()).await;
        let _ = self.s.finish();
    }

    /// Receive into `dir`, resuming a matching partial. `progress(got,
    /// total)` is called as bytes arrive.
    pub async fn receive(mut self, dir: &Path, mut progress: impl FnMut(u64, u64) + Send) -> Result<Received, AppError> {
        let name = safe_name(&self.name).ok_or(AppError::Protocol("unsafe file name"))?;
        tokio::fs::create_dir_all(dir).await?;
        let part = dir.join(format!("{name}{PART_SUFFIX}"));
        let sidecar = dir.join(format!("{name}{SHA_SUFFIX}"));
        let want = hex::encode(self.sha256);
        let resumable = tokio::fs::read_to_string(&sidecar).await.is_ok_and(|s| s.trim() == want);
        let mut offset = if resumable {
            tokio::fs::metadata(&part).await.map(|m| m.len()).unwrap_or(0)
        } else {
            0
        };
        if offset > self.size {
            offset = 0;
        }
        let mut f = tokio::fs::OpenOptions::new().create(true).write(true).truncate(false).open(&part).await?;
        f.set_len(offset).await?;
        f.seek(std::io::SeekFrom::Start(offset)).await?;
        tokio::fs::write(&sidecar, &want).await?;
        write(&mut self.s, &offset.to_be_bytes()).await?;

        let mut got = offset;
        progress(got, self.size);
        let mut buf = vec![0u8; CHUNK];
        while got < self.size {
            let want_n = usize::try_from((self.size - got).min(CHUNK as u64)).unwrap_or(CHUNK);
            match self.r.read(&mut buf[..want_n]).await {
                Ok(Some(n)) => {
                    f.write_all(&buf[..n]).await?;
                    got += n as u64;
                    progress(got, self.size);
                }
                Ok(None) | Err(_) => {
                    f.flush().await?;
                    return Ok(Received::Partial(part));
                }
            }
        }
        f.flush().await?;
        f.sync_all().await?;
        drop(f);
        if sha256_file(&part).await? != self.sha256 {
            let _ = tokio::fs::remove_file(&part).await;
            let _ = tokio::fs::remove_file(&sidecar).await;
            let _ = write(&mut self.s, &[FAIL]).await;
            let _ = self.s.finish();
            return Err(AppError::Mismatch);
        }
        let dest = unused_path(dir, &name);
        tokio::fs::rename(&part, &dest).await?;
        let _ = tokio::fs::remove_file(&sidecar).await;
        write(&mut self.s, &[OK]).await?;
        let _ = self.s.finish();
        let _ = self.s.stopped().await;
        Ok(Received::Done(dest))
    }
}

impl IncomingForward {
    /// Refuse the forward.
    pub async fn refuse(mut self) {
        let _ = write(&mut self.s, &[FAIL]).await;
        let _ = self.s.finish();
    }

    /// Accept and take the raw stream pair (for stdio bridging).
    pub async fn accept_raw(mut self) -> Result<(SendStream, RecvStream), AppError> {
        write(&mut self.s, &[OK]).await?;
        Ok((self.s, self.r))
    }

    /// Accept and bridge to a TCP service at `to`.
    pub async fn accept(mut self, to: std::net::SocketAddr) -> Result<(), AppError> {
        let tcp = match tokio::net::TcpStream::connect(to).await {
            Ok(t) => t,
            Err(e) => {
                let _ = write(&mut self.s, &[FAIL]).await;
                let _ = self.s.finish();
                return Err(e.into());
            }
        };
        write(&mut self.s, &[OK]).await?;
        bridge(tcp, self.s, self.r).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_made_safe() {
        assert_eq!(safe_name("a.txt").as_deref(), Some("a.txt"));
        assert_eq!(safe_name("../../etc/passwd").as_deref(), Some("passwd"));
        assert_eq!(safe_name("C:\\x\\y.doc").as_deref(), Some("y.doc"));
        assert_eq!(safe_name(".bashrc").as_deref(), Some("bashrc"));
        assert_eq!(safe_name("..").as_deref(), None);
        assert_eq!(safe_name("dir/").as_deref(), None);
    }

    #[test]
    fn unused_paths_do_not_overwrite() {
        let dir = std::env::temp_dir().join(format!("noscat-apps-{}", rand::random::<u32>()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(unused_path(&dir, "a.txt"), dir.join("a.txt"));
        std::fs::write(dir.join("a.txt"), b"x").unwrap();
        assert_eq!(unused_path(&dir, "a.txt"), dir.join("a (1).txt"));
        std::fs::write(dir.join("noext"), b"x").unwrap();
        assert_eq!(unused_path(&dir, "noext"), dir.join("noext (1)"));
        std::fs::remove_dir_all(&dir).ok();
    }
}
