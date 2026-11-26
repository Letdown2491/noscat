//! `noscat shell`: this terminal as the viewer of a member's shell. Raw
//! mode while the session runs, the window size followed, the remote exit
//! status passed through.

use std::io::{IsTerminal as _, Write as _};
use std::time::Duration;

use anyhow::Result;
use noscat_client::TermFrame;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

/// This terminal's size and `TERM`, for the request.
pub fn local_terminal() -> (u16, u16, String) {
    let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));
    let term = std::env::var("TERM").ok().filter(|t| !t.is_empty()).unwrap_or_else(|| "xterm-256color".into());
    (cols, rows, term)
}

/// Leaves raw mode however the session ends.
struct Raw(bool);

impl Drop for Raw {
    fn drop(&mut self) {
        if self.0 {
            let _ = crossterm::terminal::disable_raw_mode();
        }
    }
}

/// Run the session over `stream` (already started). Returns the remote
/// shell's exit status.
pub async fn run(stream: impl AsyncRead + AsyncWrite + Send + 'static) -> Result<i32> {
    let tty = std::io::stdin().is_terminal();
    let _raw = Raw(tty && crossterm::terminal::enable_raw_mode().is_ok());
    let (mut r, mut w) = tokio::io::split(stream);

    let input = async move {
        let mut stdin = tokio::io::stdin();
        let mut buf = vec![0u8; 8 * 1024];
        let mut size = crossterm::terminal::size().ok();
        let mut tick = tokio::time::interval(Duration::from_millis(250));
        loop {
            tokio::select! {
                n = stdin.read(&mut buf) => match n {
                    Ok(0) | Err(_) => {
                        // Piped input ended: end the remote shell's input
                        // the way a terminal would (Ctrl-D), then just wait.
                        let _ = w.write_all(&TermFrame::Input(vec![4]).encode()).await;
                        return std::future::pending::<()>().await;
                    }
                    Ok(n) => {
                        if w.write_all(&TermFrame::Input(buf[..n].to_vec()).encode()).await.is_err() {
                            return;
                        }
                    }
                },
                _ = tick.tick(), if tty => {
                    let now = crossterm::terminal::size().ok();
                    if now != size {
                        size = now;
                        if let Some((cols, rows)) = now {
                            if w.write_all(&TermFrame::Resize { cols, rows }.encode()).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            }
        }
    };
    let output = async move {
        let mut out = std::io::stdout();
        loop {
            match TermFrame::read(&mut r).await {
                Ok(Some(TermFrame::Output(b))) => {
                    let _ = out.write_all(&b);
                    let _ = out.flush();
                }
                Ok(Some(TermFrame::Exit(code))) => return Ok(code),
                Ok(Some(_)) => {}
                Ok(None) => anyhow::bail!("the session ended without an exit status"),
                Err(e) => anyhow::bail!("session: {e}"),
            }
        }
    };
    tokio::select! {
        code = output => code,
        () = input => anyhow::bail!("the session's connection closed"),
    }
}
