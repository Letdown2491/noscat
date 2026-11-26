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
struct Raw {
    on: bool,
    #[cfg(windows)]
    console: Option<win::Saved>,
}

impl Raw {
    fn enter(tty: bool) -> Self {
        let on = tty && crossterm::terminal::enable_raw_mode().is_ok();
        Raw {
            on,
            #[cfg(windows)]
            console: on.then(win::vt_utf8).flatten(),
        }
    }
}

impl Drop for Raw {
    fn drop(&mut self) {
        if self.on {
            let _ = crossterm::terminal::disable_raw_mode();
        }
        #[cfg(windows)]
        if let Some(saved) = self.console.take() {
            saved.restore();
        }
    }
}

/// The Windows console speaks the same bytes as a Unix terminal only with
/// VT input (keys arrive as escape sequences, not console key events),
/// VT output (older consoles print escapes literally) and the UTF-8 code
/// page both ways. All are set for the session and restored after.
#[cfg(windows)]
mod win {
    use windows_sys::Win32::System::Console::{
        DISABLE_NEWLINE_AUTO_RETURN, ENABLE_VIRTUAL_TERMINAL_INPUT, ENABLE_VIRTUAL_TERMINAL_PROCESSING,
        GetConsoleCP, GetConsoleMode, GetConsoleOutputCP, GetStdHandle, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
        SetConsoleCP, SetConsoleMode, SetConsoleOutputCP,
    };

    const UTF8: u32 = 65001;

    pub struct Saved {
        input: u32,
        output: Option<u32>,
        cp: u32,
        out_cp: u32,
    }

    pub fn vt_utf8() -> Option<Saved> {
        // Safety: plain Win32 console calls on this process's own standard
        // handles; a handle that is not a console fails GetConsoleMode.
        unsafe {
            let (hin, hout) = (GetStdHandle(STD_INPUT_HANDLE), GetStdHandle(STD_OUTPUT_HANDLE));
            let mut input = 0;
            if GetConsoleMode(hin, &mut input) == 0 {
                return None;
            }
            let mut out = 0;
            let output = (GetConsoleMode(hout, &mut out) != 0).then_some(out);
            let saved = Saved { input, output, cp: GetConsoleCP(), out_cp: GetConsoleOutputCP() };
            SetConsoleMode(hin, input | ENABLE_VIRTUAL_TERMINAL_INPUT);
            if let Some(out) = output {
                // Older consoles lack DISABLE_NEWLINE_AUTO_RETURN: then VT
                // output alone.
                if SetConsoleMode(hout, out | ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN) == 0 {
                    SetConsoleMode(hout, out | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
                }
            }
            SetConsoleCP(UTF8);
            SetConsoleOutputCP(UTF8);
            Some(saved)
        }
    }

    impl Saved {
        pub fn restore(self) {
            // Safety: as above.
            unsafe {
                SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), self.input);
                if let Some(out) = self.output {
                    SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), out);
                }
                SetConsoleCP(self.cp);
                SetConsoleOutputCP(self.out_cp);
            }
        }
    }
}

/// Run the session over `stream` (already started). Returns the remote
/// shell's exit status.
pub async fn run(stream: impl AsyncRead + AsyncWrite + Send + 'static) -> Result<i32> {
    let tty = std::io::stdin().is_terminal();
    let _raw = Raw::enter(tty);
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
