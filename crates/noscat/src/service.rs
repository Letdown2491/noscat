//! `noscat service`: run `noscat up` in the background at login (and with
//! lingering, at boot) under the platform's service manager: a systemd
//! user unit on Linux and the BSDs that have systemd, a launchd agent on
//! macOS. The command line is rebuilt from the parsed options, with paths
//! made absolute, so the service runs exactly what `install` was given.

// Each platform uses only part of this module.
#![cfg_attr(not(all(unix, not(target_os = "macos"))), allow(dead_code, unused_imports))]

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context as _, Result, bail};

/// The service's name (systemd unit `noscat.service`) and launchd label.
const UNIT: &str = "noscat.service";
#[cfg(target_os = "macos")]
const LABEL: &str = "io.github.letdown2491.noscat";

/// Quote one argument for a systemd `ExecStart=` line: double quotes with
/// C escapes, `%` doubled (specifiers) and `$` doubled (variables).
pub fn systemd_quote(arg: &str) -> String {
    let mut out = String::from("\"");
    for c in arg.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '%' => out.push_str("%%"),
            '$' => out.push_str("$$"),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The systemd user unit running `argv`.
pub fn systemd_unit(argv: &[String]) -> String {
    // The program path stays bare when it can (older systemd wants it so).
    let plain = |a: &str| !a.is_empty() && a.chars().all(|c| c.is_ascii_alphanumeric() || "/._-+".contains(c));
    let exec = argv
        .iter()
        .enumerate()
        .map(|(i, a)| if i == 0 && plain(a) { a.clone() } else { systemd_quote(a) })
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "# Written by `noscat service install`; `noscat service uninstall` removes it.\n\
         [Unit]\n\
         Description=noscat device (your device mesh)\n\
         Documentation=man:noscat(1)\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={exec}\n\
         StandardInput=null\n\
         Restart=on-failure\n\
         RestartSec=10\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n"
    )
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// The launchd agent running `argv`, logging to `log`.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn launchd_plist(label: &str, argv: &[String], log: &Path) -> String {
    let args: String = argv.iter().map(|a| format!("        <string>{}</string>\n", xml_escape(a))).collect();
    let log = xml_escape(&log.to_string_lossy());
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
         \x20   <key>Label</key>\n\
         \x20   <string>{label}</string>\n\
         \x20   <key>ProgramArguments</key>\n\
         \x20   <array>\n\
         {args}\
         \x20   </array>\n\
         \x20   <key>RunAtLoad</key>\n\
         \x20   <true/>\n\
         \x20   <key>KeepAlive</key>\n\
         \x20   <dict>\n\
         \x20       <key>SuccessfulExit</key>\n\
         \x20       <false/>\n\
         \x20   </dict>\n\
         \x20   <key>ThrottleInterval</key>\n\
         \x20   <integer>10</integer>\n\
         \x20   <key>StandardOutPath</key>\n\
         \x20   <string>{log}</string>\n\
         \x20   <key>StandardErrorPath</key>\n\
         \x20   <string>{log}</string>\n\
         </dict>\n\
         </plist>\n"
    )
}

fn run(cmd: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(cmd).args(args).status().with_context(|| format!("could not run {cmd}"))?;
    if !status.success() {
        bail!("`{cmd} {}` failed ({status})", args.join(" "));
    }
    Ok(())
}

fn quiet(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn home() -> Result<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from).context("HOME is not set")
}

/// Whether the service is running now.
pub fn active() -> bool {
    #[cfg(target_os = "macos")]
    {
        quiet("launchctl", &["print", &format!("gui/{}/{LABEL}", uid())]).is_some_and(|s| s.contains("state = running"))
    }
    #[cfg(not(target_os = "macos"))]
    {
        quiet("systemctl", &["--user", "is-active", UNIT]).as_deref() == Some("active")
    }
}

#[cfg(target_os = "macos")]
fn uid() -> String {
    quiet("id", &["-u"]).unwrap_or_else(|| "501".into())
}

#[cfg(target_os = "macos")]
fn plist_path() -> Result<PathBuf> {
    Ok(home()?.join("Library/LaunchAgents").join(format!("{LABEL}.plist")))
}

#[cfg(not(target_os = "macos"))]
fn unit_path() -> Result<PathBuf> {
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|x| !x.is_empty())
        .map(PathBuf::from)
        .map_or_else(|| home().map(|h| h.join(".config")), Ok)?;
    Ok(config.join("systemd/user").join(UNIT))
}

/// Install (or replace) the service running `argv` and start it.
pub fn install(argv: &[String]) -> Result<()> {
    #[cfg(windows)]
    {
        let _ = argv;
        bail!("noscat service is not available on Windows yet; run `noscat up` from Task Scheduler at logon");
    }
    #[cfg(target_os = "macos")]
    {
        let path = plist_path()?;
        let log = home()?.join("Library/Logs/noscat.log");
        std::fs::create_dir_all(path.parent().expect("has a parent"))?;
        let target = format!("gui/{}", uid());
        // Replacing: unload the old one first (fails harmlessly when none).
        let _ = quiet("launchctl", &["bootout", &format!("{target}/{LABEL}")]);
        std::fs::write(&path, launchd_plist(LABEL, argv, &log))?;
        run("launchctl", &["bootstrap", &target, &path.to_string_lossy()])?;
        println!("installed {} and started it; it starts at every login", path.display());
        println!("logs: {}", log.display());
        Ok(())
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if quiet("systemctl", &["--user", "--version"]).is_none() {
            bail!("no systemd user manager here (`systemctl --user`); run `noscat up` from your init system instead");
        }
        let path = unit_path()?;
        std::fs::create_dir_all(path.parent().expect("has a parent"))?;
        std::fs::write(&path, systemd_unit(argv))?;
        run("systemctl", &["--user", "daemon-reload"])?;
        run("systemctl", &["--user", "enable", UNIT])?;
        run("systemctl", &["--user", "restart", UNIT])?;
        println!("installed {} and started it; it starts at every login", path.display());
        // Lingering keeps user services running without a login session
        // (boot, logout): what a server or always-on machine wants.
        let user = std::env::var("USER").unwrap_or_default();
        let lingering = quiet("loginctl", &["show-user", &user, "-p", "Linger", "--value"]).as_deref() == Some("yes");
        if !lingering && !user.is_empty() {
            if run("loginctl", &["enable-linger", &user]).is_ok() {
                println!("enabled lingering for {user}: noscat also runs at boot and after logout");
            } else {
                println!("to run it at boot and after logout too: loginctl enable-linger {user}");
            }
        }
        println!("logs: journalctl --user -u noscat -f");
        Ok(())
    }
}

/// Stop and remove the service.
pub fn uninstall() -> Result<()> {
    #[cfg(windows)]
    bail!("noscat service is not available on Windows");
    #[cfg(target_os = "macos")]
    {
        let path = plist_path()?;
        let _ = quiet("launchctl", &["bootout", &format!("gui/{}/{LABEL}", uid())]);
        if path.exists() {
            std::fs::remove_file(&path)?;
            println!("stopped and removed {}", path.display());
        } else {
            println!("no noscat service installed");
        }
        Ok(())
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let path = unit_path()?;
        if !path.exists() {
            println!("no noscat service installed");
            return Ok(());
        }
        let _ = quiet("systemctl", &["--user", "disable", "--now", UNIT]);
        std::fs::remove_file(&path)?;
        let _ = quiet("systemctl", &["--user", "daemon-reload"]);
        println!("stopped and removed {}", path.display());
        println!("lingering is left as it was (other services may use it): loginctl disable-linger turns it off");
        Ok(())
    }
}

/// Print the service manager's view of it.
pub fn status() -> Result<()> {
    #[cfg(windows)]
    bail!("noscat service is not available on Windows");
    #[cfg(target_os = "macos")]
    {
        if !plist_path()?.exists() {
            println!("no noscat service installed (noscat service install)");
            return Ok(());
        }
        let _ = Command::new("launchctl").args(["print", &format!("gui/{}/{LABEL}", uid())]).status();
        Ok(())
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if !unit_path()?.exists() {
            println!("no noscat service installed (noscat service install)");
            return Ok(());
        }
        let _ = Command::new("systemctl").args(["--user", "status", "--no-pager", UNIT]).status();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_start_quotes_specials() {
        assert_eq!(systemd_quote("a b"), "\"a b\"");
        assert_eq!(systemd_quote("50%$x\"\\"), "\"50%%$$x\\\"\\\\\"");
        let unit = systemd_unit(&["/usr/bin/noscat".into(), "up".into(), "--name".into(), "my box".into()]);
        assert!(unit.contains("ExecStart=/usr/bin/noscat \"up\" \"--name\" \"my box\"\n"));
        assert!(unit.contains("WantedBy=default.target"));
    }

    #[test]
    fn plist_escapes() {
        let p = launchd_plist("l", &["/bin/noscat".into(), "--name".into(), "a<b&c".into()], Path::new("/tmp/x.log"));
        assert!(p.contains("<string>a&lt;b&amp;c</string>"));
        assert!(p.contains("<string>/tmp/x.log</string>"));
    }
}
