//! The system clipboard through each platform's native tool.

/// Put `text` on the system clipboard, using each platform's native tool:
/// pbcopy on macOS, Set-Clipboard via PowerShell on Windows, and wl-copy
/// (Wayland) / xclip / xsel (X11) on the other unixes (Linux, the BSDs).
/// All are stdin-piping executables, so the helper is the same pipe on
/// every platform; only the tool differs. Fails when no tool exists or
/// the display session is unreachable; callers print the text so nothing
/// is lost.
#[cfg(target_os = "macos")]
pub fn set_system_clipboard(text: &str) -> anyhow::Result<()> {
    pipe_to_clipboard_tool("pbcopy", &[], text)
}

#[cfg(target_os = "windows")]
pub fn set_system_clipboard(text: &str) -> anyhow::Result<()> {
    // clip.exe reads the console input code page rather than UTF-8, so
    // route through PowerShell, forcing UTF-8 on both ends of the pipe.
    let script = "$OutputEncoding = [Console]::InputEncoding = \
                  [System.Text.Encoding]::UTF8; $input | Set-Clipboard";
    pipe_to_clipboard_tool(
        "powershell",
        &["-NoProfile", "-Command", script],
        text,
    )
}

// Linux, the BSDs, and the other unixes: Wayland first, then X11 tools.
#[cfg(all(unix, not(target_os = "macos")))]
pub fn set_system_clipboard(text: &str) -> anyhow::Result<()> {
    let attempts: [(&str, &[&str]); 3] = [
        ("wl-copy", &["-f"]),
        ("xclip", &["-selection", "clipboard"]),
        ("xsel", &["--input", "--clipboard"]),
    ];
    let mut last: Option<String> = None;
    for (tool, args) in attempts {
        match pipe_to_clipboard_tool(tool, args, text) {
            Ok(()) => return Ok(()),
            Err(e) => last = Some(e.to_string()),
        }
    }
    Err(anyhow::anyhow!(
        "no clipboard tool worked: {}",
        last.unwrap_or_else(|| "none found".into())
    ))
}

/// Spawn `tool` with `args`, write `text` to its stdin, and require a
/// zero exit status. The tools here daemonize after reading stdin (or
/// exit), so waiting on the child is safe on every platform.
fn pipe_to_clipboard_tool(tool: &str, args: &[&str], text: &str) -> anyhow::Result<()> {
    use std::io::Write as _;
    use std::process::{Command, Stdio};
    let mut child = Command::new(tool)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| anyhow::anyhow!("{tool}: {e}"))?;
    child
        .stdin
        .as_mut()
        .expect("piped")
        .write_all(text.as_bytes())?;
    let status = child.wait()?;
    let code = status.code().map(|c| c.to_string()).unwrap_or_else(|| "signal".into());
    anyhow::ensure!(status.success(), "{tool} exited {code}");
    Ok(())
}

/// Read the system clipboard back, mirroring `set_system_clipboard`'s
/// tool choice per platform. Empty output is a valid result (an empty
/// clipboard), so only spawn/exit failures are errors.
#[cfg(target_os = "macos")]
pub fn get_system_clipboard() -> anyhow::Result<String> {
    read_from_clipboard_tool("pbpaste", &[])
}

#[cfg(target_os = "windows")]
pub fn get_system_clipboard() -> anyhow::Result<String> {
    // Get-Clipboard emits the console code page; force UTF-8 on both ends
    // of the pipe (mirrors the Set-Clipboard encoding dance).
    read_from_clipboard_tool(
        "powershell",
        &[
            "-NoProfile",
            "-Command",
            "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; Get-Clipboard",
        ],
    )
}

// Linux, the BSDs, and the other unixes: Wayland first, then X11 tools.
#[cfg(all(unix, not(target_os = "macos")))]
pub fn get_system_clipboard() -> anyhow::Result<String> {
    let attempts: [(&str, &[&str]); 3] = [
        ("wl-paste", &[]),
        ("xclip", &["-selection", "clipboard", "-o"]),
        ("xsel", &["--output", "--clipboard"]),
    ];
    let mut last: Option<String> = None;
    for (tool, args) in attempts {
        match read_from_clipboard_tool(tool, args) {
            Ok(text) => return Ok(text),
            Err(e) => last = Some(e.to_string()),
        }
    }
    Err(anyhow::anyhow!(
        "no clipboard tool worked: {}",
        last.unwrap_or_else(|| "none found".into())
    ))
}

/// Spawn `tool` with `args`, take its stdout as the clipboard contents.
fn read_from_clipboard_tool(tool: &str, args: &[&str]) -> anyhow::Result<String> {
    use std::process::{Command, Stdio};
    let out = Command::new(tool)
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|e| anyhow::anyhow!("{tool}: {e}"))?;
    anyhow::ensure!(out.status.success(), "{tool} exited {:?}", out.status.code());
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}
