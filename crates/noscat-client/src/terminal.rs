//! Hosting a terminal: a PTY running the user's login shell in their home
//! directory, as the user running noscat (never elevated), bridged to a
//! member's terminal stream. Computers only; on phones `SUPPORTED` is
//! false and requests are answered "unavailable".

#[cfg(not(any(target_os = "android", target_os = "ios")))]
use std::time::Duration;

use noscat_core::apps::IncomingTerminal;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use noscat_core::apps::TermFrame;
use tokio::sync::oneshot;

/// Whether this platform can host a terminal.
pub const SUPPORTED: bool = cfg!(not(any(target_os = "android", target_os = "ios")));

/// How long output may keep draining after the shell exited (a background
/// job can hold the PTY open forever).
#[cfg(not(any(target_os = "android", target_os = "ios")))]
const DRAIN: Duration = Duration::from_millis(300);

/// Environment the shell must not inherit from noscat.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
const SCRUB: [&str; 3] = ["NOSCAT_IDENTITY", "NOSCAT_DIR", "RUST_LOG"];

/// Start the shell, accept the request, and run the session until the
/// shell exits, the viewer goes away, or `end` fires. A shell that cannot
/// start refuses the request ("unavailable"). Returns the exit status sent
/// to the viewer.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub async fn host(t: IncomingTerminal, end: oneshot::Receiver<()>) -> Result<i32, String> {
    use portable_pty::{CommandBuilder, PtySize, native_pty_system};

    let size = |cols: u16, rows: u16| PtySize { rows: rows.max(1), cols: cols.max(1), pixel_width: 0, pixel_height: 0 };
    let spawned = (|| {
        let pair = native_pty_system().openpty(size(t.cols, t.rows)).map_err(|e| format!("pty: {e}"))?;
        let mut cmd = CommandBuilder::new_default_prog();
        cmd.env("TERM", &t.term);
        for k in SCRUB {
            cmd.env_remove(k);
        }
        if let Some(home) = home_dir() {
            cmd.cwd(home);
        }
        let child = pair.slave.spawn_command(cmd).map_err(|e| format!("shell: {e}"))?;
        Ok::<_, String>((pair.master, child))
    })();
    let (master, mut child) = match spawned {
        Ok(p) => p,
        Err(e) => {
            t.refuse().await;
            return Err(e);
        }
    };
    let (mut s, mut r) = match t.accept().await {
        Ok(p) => p,
        Err(e) => {
            let _ = child.kill();
            return Err(e.to_string());
        }
    };
    let mut killer = child.clone_killer();
    let mut reader = master.try_clone_reader().map_err(|e| format!("pty: {e}"))?;
    let mut writer = master.take_writer().map_err(|e| format!("pty: {e}"))?;

    // PTY output: a blocking reader thread into the async side.
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match std::io::Read::read(&mut reader, &mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if out_tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    // Input and resizes: a blocking writer thread.
    let (in_tx, in_rx) = std::sync::mpsc::channel::<TermFrame>();
    // Windows: ConPTY starts by asking where the cursor is (portable-pty
    // creates it with PSEUDOCONSOLE_INHERIT_CURSOR) and holds all output
    // until it hears back. A viewer whose terminal does not answer would
    // see nothing, ever, so the host answers that first query itself (top
    // left: a new console) and the viewer never sees it.
    #[cfg(windows)]
    let mut cursor_query = Some(in_tx.clone());
    std::thread::spawn(move || {
        for f in in_rx {
            match f {
                TermFrame::Input(b) => {
                    if std::io::Write::write_all(&mut writer, &b).is_err() {
                        break;
                    }
                    let _ = std::io::Write::flush(&mut writer);
                }
                TermFrame::Resize { cols, rows } => {
                    let _ = master.resize(size(cols, rows));
                }
                _ => {}
            }
        }
    });
    // The exit status.
    let (exit_tx, mut exit_rx) = oneshot::channel::<i32>();
    std::thread::spawn(move || {
        let code = child.wait().map_or(-1, |st| i32::try_from(st.exit_code()).unwrap_or(-1));
        let _ = exit_tx.send(code);
    });
    // Viewer frames.
    let reading = async move {
        while let Ok(Some(f)) = TermFrame::read(&mut r).await {
            if in_tx.send(f).is_err() {
                break;
            }
        }
    };
    tokio::pin!(reading);
    tokio::pin!(end);

    let mut code = None;
    let mut deadline = None::<tokio::time::Instant>;
    // Writing to the viewer failed: no point sending the exit status.
    let mut viewer_gone = false;
    loop {
        let drain_over = async {
            match deadline {
                Some(d) => tokio::time::sleep_until(d).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            out = out_rx.recv() => match out {
                Some(b) => {
                    #[cfg(windows)]
                    let b = answer_cursor_query(b, &mut cursor_query);
                    if s.write_all(&TermFrame::Output(b).encode()).await.is_err() {
                        viewer_gone = true;
                        break;
                    }
                }
                // The PTY closed: the shell and everything on it ended.
                None => break,
            },
            c = &mut exit_rx, if code.is_none() => {
                code = Some(c.unwrap_or(-1));
                deadline = Some(tokio::time::Instant::now() + DRAIN);
            }
            () = drain_over => break,
            // The viewer closed its side: it left.
            () = &mut reading => break,
            _ = &mut end => break,
        }
    }
    let code = match code {
        Some(c) => c,
        None => {
            // Ended by the viewer or the host: end the shell too.
            let _ = killer.kill();
            match tokio::time::timeout(Duration::from_secs(2), exit_rx).await {
                Ok(Ok(c)) => c,
                _ => -1,
            }
        }
    };
    if !viewer_gone {
        let _ = s.write_all(&TermFrame::Exit(code).encode()).await;
        let _ = s.finish();
        let _ = tokio::time::timeout(Duration::from_secs(2), s.stopped()).await;
    }
    Ok(code)
}

/// The cursor position query (DSR 6).
#[cfg(windows)]
const CURSOR_QUERY: &[u8] = b"\x1b[6n";

/// Answer ConPTY's cursor query (see `host`) and cut it from the output.
/// Only the first output chunk is looked at, where ConPTY puts it; later
/// queries come from programs and go to the viewer.
#[cfg(windows)]
fn answer_cursor_query(b: Vec<u8>, pending: &mut Option<std::sync::mpsc::Sender<TermFrame>>) -> Vec<u8> {
    let Some(tx) = pending.take() else { return b };
    let Some(at) = b.windows(CURSOR_QUERY.len()).position(|w| w == CURSOR_QUERY) else {
        return b;
    };
    let _ = tx.send(TermFrame::Input(b"\x1b[1;1R".to_vec()));
    let mut out = b[..at].to_vec();
    out.extend_from_slice(&b[at + CURSOR_QUERY.len()..]);
    out
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn the_first_cursor_query_is_answered_and_hidden() {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut pending = Some(tx);
        let out = answer_cursor_query(b"\x1b[?25l\x1b[6nhi".to_vec(), &mut pending);
        assert_eq!(out, b"\x1b[?25lhi");
        assert!(matches!(rx.try_recv(), Ok(TermFrame::Input(a)) if a == b"\x1b[1;1R"));
        // A program's later query goes to the viewer.
        let later = answer_cursor_query(b"\x1b[6n".to_vec(), &mut pending);
        assert_eq!(later, b"\x1b[6n");
        assert!(rx.try_recv().is_err());
    }
}

#[cfg(any(target_os = "android", target_os = "ios"))]
pub async fn host(t: IncomingTerminal, _end: oneshot::Receiver<()>) -> Result<i32, String> {
    t.refuse().await;
    Err("this platform hosts no terminal".into())
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn home_dir() -> Option<std::path::PathBuf> {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(var).filter(|h| !h.is_empty()).map(Into::into)
}
