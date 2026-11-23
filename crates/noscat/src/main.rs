use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use noscat_client::{Client, ClientConfig, Event, IdentitySource};

#[derive(Parser)]
#[command(
    name = "noscat",
    version,
    about = "like netcat, but over a Nostr-native mesh: npub-addressed tunnels, no root, no accounts"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a fresh one-off identity (rarely needed: any data-plane
    /// command creates and stores a default identity on first use).
    Keygen {
        /// Print the secret key (hex) alongside the npub. Handle with care.
        #[arg(long)]
        show_secret: bool,
    },
    /// Publish an overlay advert to relays so peers can discover this node.
    Advertise {
        /// Relay URLs to publish to (repeatable; defaults to the public set).
        #[arg(long = "relay")]
        relays: Vec<String>,
        /// Advertised endpoint, as `<transport>/<ip:port>`, e.g. `udp/203.0.113.7:41641`.
        #[arg(long = "endpoint")]
        endpoints: Vec<String>,
        /// Advert lifetime in seconds.
        #[arg(long, default_value_t = noscat_core::advert::ADVERT_TTL_SECS)]
        ttl: u64,
    },
    /// Watch relays for noscat adverts from any node.
    Watch {
        /// Relay URLs to subscribe to (repeatable; defaults to the public set).
        #[arg(long = "relay")]
        relays: Vec<String>,
    },
    /// Serve a tunnel: advertise a UDP endpoint, bridge the first peer to stdio.
    Serve {
        /// UDP address to listen on.
        #[arg(long, default_value_t = format!("0.0.0.0:{}", noscat_core::relay::DEFAULT_LISTEN_PORT))]
        listen: String,
        /// Relay URLs to advertise on (repeatable; defaults to the public set).
        #[arg(long = "relay")]
        relays: Vec<String>,
        /// Advert lifetime in seconds.
        #[arg(long, default_value_t = noscat_core::advert::ADVERT_TTL_SECS)]
        ttl: u64,
        /// Identity file override (default: ~/.noscat/identity.hex).
        #[arg(long)]
        identity: Option<std::path::PathBuf>,
        /// Restrict the tunnel to this mesh's device directory (MLS group
        /// membership becomes the authorization) [default: ~/.noscat/device].
        #[arg(long, num_args = 0..=1, default_missing_value = "")]
        mesh: Option<String>,
    },
    /// Pipe stdio into a tunnel to a peer by npub.
    Pipe {
        /// The peer's npub.
        target: String,
        /// Relay URLs to search for the peer's advert (repeatable).
        #[arg(long = "relay")]
        relays: Vec<String>,
        /// Identity file (default: ~/.noscat/identity.hex). A secret may
        /// instead come from the NOSCAT_IDENTITY env var (hex or nsec) -
        /// argv is visible to every local user via ps and shell history.
        #[arg(long)]
        identity: Option<std::path::PathBuf>,
        /// Restrict the tunnel to this mesh's device directory (MLS group
        /// membership becomes the authorization) [default: ~/.noscat/device].
        #[arg(long, num_args = 0..=1, default_missing_value = "")]
        mesh: Option<String>,
    },
    /// Send a file over a tunnel to a peer by npub.
    Send {
        /// The file to send.
        path: std::path::PathBuf,
        /// The receiving peer's npub.
        target: String,
        /// Relay URLs (repeatable; defaults to the public set).
        #[arg(long = "relay")]
        relays: Vec<String>,
        /// Identity file (default: ~/.noscat/identity.hex). A secret may
        /// instead come from the NOSCAT_IDENTITY env var (hex or nsec) -
        /// argv is visible to every local user via ps and shell history.
        #[arg(long)]
        identity: Option<std::path::PathBuf>,
        /// Restrict the tunnel to this mesh's device directory
        /// [default: ~/.noscat/device].
        #[arg(long, num_args = 0..=1, default_missing_value = "")]
        mesh: Option<String>,
    },
    /// Receive one file over a tunnel, into --out (default: cwd).
    Receive {
        /// Directory to write the incoming file into.
        #[arg(long, default_value = ".")]
        out: std::path::PathBuf,
        /// UDP address to listen on.
        #[arg(long, default_value_t = format!("0.0.0.0:{}", noscat_core::relay::DEFAULT_LISTEN_PORT))]
        listen: String,
        /// Relay URLs (repeatable; defaults to the public set).
        #[arg(long = "relay")]
        relays: Vec<String>,
        /// Identity file override (default: ~/.noscat/identity.hex).
        #[arg(long)]
        identity: Option<std::path::PathBuf>,
        /// Restrict the tunnel to this mesh's device directory
        /// [default: ~/.noscat/device].
        #[arg(long, num_args = 0..=1, default_missing_value = "")]
        mesh: Option<String>,
        /// Advert lifetime in seconds.
        #[arg(long, default_value_t = noscat_core::advert::ADVERT_TTL_SECS)]
        ttl: u64,
    },
    /// Expose a local TCP service to mesh peers over tunnels.
    /// Run the persistent mesh node: advertise, accept any number of
    /// inbound peers, auto-receive files, bridge raw tunnels.
    Up {
        /// Directory to save inbound files into (default: ~/Downloads).
        #[arg(long)]
        out: Option<std::path::PathBuf>,
        /// Friendly device name shown to peers (default: the hostname).
        #[arg(long)]
        name: Option<String>,
        /// Bridge raw inbound tunnels to this local service, e.g. 127.0.0.1:22.
        #[arg(long)]
        to: Option<std::net::SocketAddr>,
        /// UDP address to listen on.
        #[arg(long, default_value_t = format!("0.0.0.0:{}", noscat_core::relay::DEFAULT_LISTEN_PORT))]
        listen: String,
        /// Relay URLs (repeatable; defaults to the public set)
        #[arg(long)]
        relays: Vec<String>,
        /// Identity file override (default: ~/.noscat/identity.hex).
        #[arg(long)]
        identity: Option<std::path::PathBuf>,
        /// Mesh device directory - REQUIRED: membership authorizes inbound
        /// [default: ~/.noscat/device].
        #[arg(long, num_args = 0..=1, default_missing_value = "")]
        mesh: Option<String>,
        /// Advert lifetime in seconds.
        #[arg(long, default_value_t = noscat_core::advert::ADVERT_TTL_SECS)]
        ttl: u64,
    },
    Expose {
        /// The local service to expose, e.g. `127.0.0.1:8000`.
        #[arg(long)]
        to: String,
        /// UDP address to listen on.
        #[arg(long, default_value_t = format!("0.0.0.0:{}", noscat_core::relay::DEFAULT_LISTEN_PORT))]
        listen: String,
        /// Relay URLs (repeatable; defaults to the public set).
        #[arg(long = "relay")]
        relays: Vec<String>,
        /// Identity file override (default: ~/.noscat/identity.hex).
        #[arg(long)]
        identity: Option<std::path::PathBuf>,
        /// Restrict the tunnels to this mesh's device directory
        /// [default: ~/.noscat/device].
        #[arg(long, num_args = 0..=1, default_missing_value = "")]
        mesh: Option<String>,
        /// Advert lifetime in seconds.
        #[arg(long, default_value_t = noscat_core::advert::ADVERT_TTL_SECS)]
        ttl: u64,
    },
    /// Forward a local TCP port over tunnels to a peer by npub.
    Forward {
        /// The peer's npub (the side running `expose`).
        target: String,
        /// Local TCP port to listen on.
        #[arg(long)]
        port: u16,
        /// Local address for the listener. Loopback by default - anyone who
        /// can reach the port can make this process dial the target.
        #[arg(long, default_value = "127.0.0.1")]
        bind: std::net::IpAddr,
        /// Relay URLs (repeatable; defaults to the public set).
        #[arg(long = "relay")]
        relays: Vec<String>,
        /// Identity file (default: ~/.noscat/identity.hex). A secret may
        /// instead come from the NOSCAT_IDENTITY env var (hex or nsec) -
        /// argv is visible to every local user via ps and shell history.
        #[arg(long)]
        identity: Option<std::path::PathBuf>,
        /// Restrict the tunnels to this mesh's device directory
        /// [default: ~/.noscat/device].
        #[arg(long, num_args = 0..=1, default_missing_value = "")]
        mesh: Option<String>,
    },
    /// Mesh: a device's MLS group for owned-device meshing (spike).
    #[command(subcommand)]
    Mesh(MeshCommand),
    /// Emit shell completions (hidden; used by packaging).
    #[command(hide = true)]
    Completions {
        /// The shell to generate completions for.
        shell: Shell,
    },
}

#[derive(Subcommand)]
enum MeshCommand {
    /// Create a mesh owned by this device's directory.
    Create {
        /// Device directory holding the identity and MLS state.
        #[arg(long, default_value_os_t = default_device_dir())]
        dir: std::path::PathBuf,
        /// Relay URLs (repeatable; defaults to the public set).
        #[arg(long = "relay")]
        relays: Vec<String>,
    },
    /// Publish this device's MLS key package as a join request.
    Publish {
        /// Device directory holding the identity and MLS state.
        #[arg(long, default_value_os_t = default_device_dir())]
        dir: std::path::PathBuf,
        /// The mesh owner's npub: the request is addressed to them alone.
        #[arg(long)]
        owner: Option<String>,
        /// Relay URLs (repeatable; defaults to the public set).
        #[arg(long = "relay")]
        relays: Vec<String>,
    },
    /// Invite a device (by npub) into this device's mesh.
    Invite {
        /// The device directory of *this* (owner) device.
        #[arg(long, default_value_os_t = default_device_dir())]
        dir: std::path::PathBuf,
        /// The invitee's npub.
        device: String,
        /// Relay URLs (repeatable; defaults to the public set).
        #[arg(long = "relay")]
        relays: Vec<String>,
    },
    /// Wait for a gift-wrapped invitation and join the mesh.
    Join {
        /// Device directory holding the identity and MLS state.
        #[arg(long, default_value_os_t = default_device_dir())]
        dir: std::path::PathBuf,
        /// The mesh owner's npub (from the owner's QR): invitations from
        /// anyone else, or a mesh owned by anyone else, are refused.
        #[arg(long)]
        owner: String,
        /// Relay URLs (repeatable; defaults to the public set).
        #[arg(long = "relay")]
        relays: Vec<String>,
    },
    /// List the mesh's members and epoch.
    Members {
        /// Device directory holding the identity and MLS state.
        #[arg(long, default_value_os_t = default_device_dir())]
        dir: std::path::PathBuf,
    },
    /// Remove a device (by npub) from this mesh (owner only).
    Remove {
        /// The device directory of *this* (owner) device.
        #[arg(long, default_value_os_t = default_device_dir())]
        dir: std::path::PathBuf,
        /// The npub of the device to remove.
        device: String,
        /// Relay URLs (repeatable; defaults to the public set).
        #[arg(long = "relay")]
        relays: Vec<String>,
    },
    /// Merge pending mesh commits addressed to this device (run after an
    /// owner invited or removed someone).
    Sync {
        /// Device directory holding the identity and MLS state.
        #[arg(long, default_value_os_t = default_device_dir())]
        dir: std::path::PathBuf,
        /// How long to listen for commits (seconds). Stored commits are
        /// backfilled first (catching up on anything published while this
        /// device was offline), then the live listen runs.
        #[arg(long, default_value_t = 10)]
        for_secs: u64,
        /// Relay URLs (repeatable; defaults to the public set).
        #[arg(long = "relay")]
        relays: Vec<String>,
    },
    /// Re-publish this (owner) device's mesh commit chain so a member
    /// stranded at a stale epoch can catch up. Needed when a commit's
    /// gift wrap was never stored by any relay: the stranded member's own
    /// `mesh sync` can only fetch what the relays hold. Safe to run any
    /// time - up-to-date members skip the replays by epoch.
    Resend {
        /// The device directory of *this* (owner) device.
        #[arg(long, default_value_os_t = default_device_dir())]
        dir: std::path::PathBuf,
        /// Resend to this one member (npub) instead of every member.
        #[arg(long)]
        to: Option<String>,
        /// Relay URLs (repeatable; defaults to the public set).
        #[arg(long = "relay")]
        relays: Vec<String>,
    },
    /// Print the mesh's current epoch tunnel PSK (hex).
    Psk {
        /// Device directory holding the identity and MLS state.
        #[arg(long, default_value_os_t = default_device_dir())]
        dir: std::path::PathBuf,
    },
}

// The default mesh device directory, next to the shared identity.
// `--mesh` with no value (empty path) also resolves to this.
fn default_device_dir() -> std::path::PathBuf {
    // unix shells set HOME; Windows-native environments set USERPROFILE.
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(|h| std::path::PathBuf::from(h).join(".noscat").join("device"))
        .unwrap_or_else(|_| std::path::PathBuf::from(".noscat").join("device"))
}

/// Put `text` on the system clipboard, using each platform's native tool:
/// pbcopy on macOS, Set-Clipboard via PowerShell on Windows, and wl-copy
/// (Wayland) / xclip / xsel (X11) on the other unixes (Linux, the BSDs).
/// All are stdin-piping executables, so the helper is the same pipe on
/// every platform; only the tool differs. Fails when no tool exists or
/// the display session is unreachable; callers print the text so nothing
/// is lost.
#[cfg(target_os = "macos")]
fn set_system_clipboard(text: &str) -> anyhow::Result<()> {
    pipe_to_clipboard_tool("pbcopy", &[], text)
}

#[cfg(target_os = "windows")]
fn set_system_clipboard(text: &str) -> anyhow::Result<()> {
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
fn set_system_clipboard(text: &str) -> anyhow::Result<()> {
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
fn get_system_clipboard() -> anyhow::Result<String> {
    read_from_clipboard_tool("pbpaste", &[])
}

#[cfg(target_os = "windows")]
fn get_system_clipboard() -> anyhow::Result<String> {
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
fn get_system_clipboard() -> anyhow::Result<String> {
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

fn main() -> anyhow::Result<()> {
    // Default to our own logs only: nostr_sdk logs every relay reconnect as
    // ERROR (rate limits included), which drowns the chat REPL. RUST_LOG
    // restores the full firehose.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        tracing_subscriber::EnvFilter::new("noscat=info,noscat_core=info,nostr_sdk=off")
    });
    tracing_subscriber::fmt().with_env_filter(filter).init();
    let cli = Cli::parse();

    fn relays_or_default(relays: Vec<String>) -> Vec<String> {
        if relays.is_empty() {
            noscat_core::relay::DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect()
        } else {
            relays
        }
    }

    // One node identity per machine: every data-plane command shares
    // ~/.noscat/identity.hex unless --identity overrides it. The client
    // creates the file on first use.
    fn default_identity() -> Option<IdentitySource> {
        // unix shells set HOME; Windows-native environments set USERPROFILE.
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .ok()?;
        Some(IdentitySource::File(
            std::path::PathBuf::from(home).join(".noscat").join("identity.hex"),
        ))
    }

    /// Resolve a subcommand's identity: `--identity <file>`, else the
    /// NOSCAT_IDENTITY env var (hex or nsec), else the default file, else
    /// ephemeral. Secrets are never accepted on argv: ps and shell history
    /// expose it to every local user.
    fn identity_from_arg_or_env(path: Option<std::path::PathBuf>) -> IdentitySource {
        if let Some(path) = path {
            return IdentitySource::File(path);
        }
        match std::env::var("NOSCAT_IDENTITY") {
            Ok(secret) if !secret.trim().is_empty() => {
                IdentitySource::Secret(secret.trim().to_string())
            }
            _ => default_identity().unwrap_or(IdentitySource::Ephemeral),
        }
    }

    // The mesh's epoch PSK, if the operator scoped the tunnel to a group.
    fn mesh_psk(dir: &std::path::Path) -> anyhow::Result<[u8; 32]> {
        let device = noscat_core::mesh::Device::open(dir)?;
        let psk = device.tunnel_psk().map_err(|e| anyhow::anyhow!("{e}"))?;
        let psk: [u8; 32] = psk
            .try_into()
            .map_err(|_| anyhow::anyhow!("unexpected PSK length"))?;
        eprintln!("# 🔐 tunnel bound to mesh (psk) (epoch PSK loaded from {})", dir.display());
        Ok(psk)
    }

    // Build the shared client for the data-plane commands: identity, relays,
    // mesh scope, and listen address are resolved once, up front.
    fn make_client(
        identity: IdentitySource,
        relays: Vec<String>,
        mesh: Option<String>,
        listen: Option<std::net::SocketAddr>,
        ttl: u64,
        name: Option<String>,
    ) -> anyhow::Result<(Client, std::sync::mpsc::Receiver<Event>)> {
        // `--mesh` with no value is an empty string: the default device dir.
        let mesh = mesh.map(|d| if d.is_empty() { default_device_dir() } else { std::path::PathBuf::from(d) });
        if let Some(dir) = &mesh {
            mesh_psk(dir)?;
        }
        let mut client = Client::start(ClientConfig {
            identity,
            relays: Some(relays_or_default(relays)),
            listen,
            mesh_dir: mesh,
            device_name: name,
            advert_ttl_secs: ttl,
            max_incoming_bytes: None,
        })
        .map_err(|e| anyhow::anyhow!("{e}"))?;
        let rx = client.events().expect("fresh client");
        Ok((client, rx))
    }

    // Resolve a --mesh value (empty string = default device directory).
    fn mesh_dir_path(value: &str) -> std::path::PathBuf {
        if value.is_empty() {
            default_device_dir()
        } else {
            std::path::PathBuf::from(value)
        }
    }

    // Watch the relays for devices publishing key packages (asking to join
    // this mesh) and invite them once the operator confirms. Runs on its
    // own thread + runtime for the life of the `up` process; every failure
    // is non-fatal (the node keeps serving regardless).
    fn spawn_pairing_watcher(device_dir: std::path::PathBuf, relays: Vec<String>) {
        std::thread::Builder::new()
            .name("mesh-pairing".into())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        eprintln!("# pairing watcher disabled: {e}");
                        return;
                    }
                };
                rt.block_on(pairing_watcher(device_dir, relays));
            })
            .ok();
    }

    async fn pairing_watcher(device_dir: std::path::PathBuf, relays: Vec<String>) {
        use nostr::nips::nip19::ToBech32;

        // Only the mesh owner answers join requests; a member device's
        // `up` just serves its tunnels.
        let (members, own_npub) = match noscat_core::mesh::Device::open(&device_dir) {
            Ok(device) => match device.list_members() {
                Ok(members) => (members, device.identity.public_key()),
                Err(e) => {
                    eprintln!("# pairing watcher disabled: cannot list members: {e}");
                    return;
                }
            },
            Err(e) => {
                eprintln!("# pairing watcher disabled: cannot open device dir: {e}");
                return;
            }
        };
        if !members.iter().any(|m| m.is_owner) {
            eprintln!("# this device is not the mesh owner; join requests are answered by the owner device");
            return;
        }
        // Only key packages tagged to this device's npub surface here: a
        // device asks to join by scanning this owner's QR (or pasting it).

        let mut rx = match noscat_core::relay::watch_key_packages(&relays, own_npub).await {
            Ok(rx) => rx,
            Err(e) => {
                eprintln!("# pairing watcher disabled: {e}");
                return;
            }
        };
        eprintln!("# 🤝 watching for devices asking to join this mesh");

        while let Some(author) = rx.recv().await {
            // Refresh membership per request: earlier confirmations added
            // members, and the author may already be one of them.
            let members =
                match noscat_core::mesh::Device::open(&device_dir).and_then(|d| d.list_members())
                {
                    Ok(members) => members,
                    Err(e) => {
                        eprintln!("# pairing: cannot list members: {e}");
                        continue;
                    }
                };
            if members.iter().any(|m| m.npub == author.to_hex()) {
                continue;
            }

            eprintln!("# 🤝 device {author} wants to join this mesh");
            let npub = match author.to_bech32() {
                Ok(npub) => npub,
                Err(_) => continue,
            };
            if !confirm(&npub) {
                eprintln!("# declined {npub}");
                continue;
            }

            let mut device = match noscat_core::mesh::Device::open(&device_dir) {
                Ok(device) => device,
                Err(e) => {
                    eprintln!("# pairing: cannot open device dir: {e}");
                    continue;
                }
            };
            match device.invite(author, &relays).await {
                Ok(()) => eprintln!("# ✅ invited {npub} into the mesh"),
                Err(e) => eprintln!("# pairing: invite failed: {e}"),
            }
        }
    }

    // Ask on stderr, read the answer from stdin. EOF or anything but y/yes
    // declines: a backgrounded `up` (no tty) never lets anyone in.
    fn confirm(npub: &str) -> bool {
        use std::io::Write;
        eprint!("# accept {npub} into this mesh? [y/N] ");
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_err() {
            return false;
        }
        matches!(line.trim(), "y" | "Y" | "yes" | "Yes")
    }

    // Narrate one client event on stderr - the same shape the core's
    // run-to-completion operations used to print.
    /// The mesh roster plus a noise-key -> npub map, for the `up` chat
    /// REPL: incoming chats address peers by their Noise static key until an
    /// advert lookup resolves them, and `to <prefix>` needs real npubs.
    struct PeerBook {
        /// (bech32 npub, is_owner, friendly name from the advert)
        roster: Vec<(String, bool, Option<String>)>,
        /// Noise static key (hex) -> bech32 npub
        noise_to_npub: std::collections::HashMap<String, String>,
    }

    impl PeerBook {
        /// The best display label for a chat peer: its npub prefix when the
        /// roster or advert map knows one, else the raw peer string.
        fn label(&self, peer: &str) -> String {
            self.resolve_display(peer)
                .unwrap_or_else(|| peer.to_string())
        }

        /// The npub a chat peer refers to, if the book knows it.
        fn resolve_display(&self, peer: &str) -> Option<String> {
            if peer.starts_with("npub1") {
                return Some(peer.to_string());
            }
            let hex = peer.strip_prefix("noise key ").unwrap_or(peer);
            if hex.len() == 64 {
                return self.noise_to_npub.get(hex).cloned();
            }
            None
        }

        /// Resolve a `to <prefix>`: npub prefix, a noise-key prefix (as
        /// shown in a reply hint), or `owner`.
        fn resolve(&self, prefix: &str) -> anyhow::Result<String> {
            use anyhow::bail;
            let prefix = prefix
                .strip_prefix("noise key ")
                .unwrap_or(prefix)
                .trim();
            if prefix.eq_ignore_ascii_case("owner") {
                if let Some((npub, _, _)) = self.roster.iter().find(|(_, owner, _)| *owner) {
                    return Ok(npub.clone());
                }
                bail!("this device is not the mesh owner");
            }
            let mut npub_hits: Vec<String> = self
                .roster
                .iter()
                .filter(|(npub, _, _)| npub.starts_with(prefix))
                .map(|(npub, _, _)| npub.clone())
                .collect();
            if npub_hits.len() == 1 {
                return Ok(npub_hits.remove(0));
            }
            let noise_hits: Vec<String> = self
                .noise_to_npub
                .iter()
                .filter(|(k, _)| k.starts_with(prefix))
                .map(|(_, npub)| npub.clone())
                .collect();
            match noise_hits.len().max(npub_hits.len()) {
                1 => Ok(noise_hits.first().cloned().unwrap_or_else(|| {
                    npub_hits.first().cloned().unwrap_or_default()
                })),
                0 if self.roster.is_empty() => bail!("roster still loading - try again in a moment"),
                0 => bail!("no device matches '{prefix}'"),
                _ => bail!("'{prefix}' is ambiguous"),
            }
        }
    }

    fn short_npub(npub: &str) -> String {
        // Char-boundary safe: peers may carry arbitrary strings across the
        // FFI, and slicing at a byte offset would panic on multibyte UTF-8.
        let short: String = npub.chars().take(16).collect();
        format!("{short}...")
    }

    /// Print the roster for the `to` listing, each peer with its live
    /// presence from the advert watcher the node runs ("5s ago" fresh,
    /// "offline" otherwise).
    fn list_roster(client: &Client, peers: &std::sync::Mutex<PeerBook>) {
        let book = peers.lock().expect("peer book");
        if book.roster.is_empty() {
            eprintln!("# 💬 roster still loading - try again in a moment");
            return;
        }
        for (npub, owner, name) in &book.roster {
            let owner_tag = if *owner { " [owner]" } else { "" };
            let short = &npub[..npub.len().min(16)];
            // The presence map is hex-keyed; the roster speaks bech32.
            let presence = match nostr::prelude::PublicKey::parse(npub) {
                Ok(pk) => match client.member_age_secs(&pk.to_string()) {
                    Some(age) if client.member_online(&pk.to_string()) => {
                        format!(", seen {age}s ago")
                    }
                    _ => ", offline".to_string(),
                },
                Err(_) => String::new(),
            };
            match name {
                Some(n) => {
                    eprintln!("# 💬 {n}{owner_tag} - {}{presence} ({short})", short_npub(npub))
                }
                None => eprintln!(
                    "# 💬 {owner_tag}{}{presence} ({short})",
                    short_npub(npub)
                ),
            }
        }
    }

    /// Load the roster and each member's advert in the background, filling
    /// the peer book the REPL and the chat display share.
    fn spawn_peer_book(
        device_dir: std::path::PathBuf,
        relays: Vec<String>,
    ) -> std::sync::Arc<std::sync::Mutex<PeerBook>> {
        let book = std::sync::Arc::new(std::sync::Mutex::new(PeerBook {
            roster: Vec::new(),
            noise_to_npub: std::collections::HashMap::new(),
        }));
        let b = book.clone();
        std::thread::spawn(move || {
            let members = noscat_core::mesh::Device::open(&device_dir)
                .and_then(|d| d.list_members())
                .unwrap_or_default();
            let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
                Ok(rt) => rt,
                Err(_) => return,
            };
            // All members' adverts are fetched concurrently: an offline
            // member costs its FETCH_WAIT, not the roster's total.
            use nostr::nips::nip19::ToBech32;
            let fetched: Vec<(bool, String, Option<noscat_core::advert::Advert>)> = rt
                .block_on(futures_util::future::join_all(members.into_iter().map(|m| {
                    let relays = relays.clone();
                    async move {
                        let Ok(npub_hex) = nostr::prelude::PublicKey::from_hex(&m.npub) else {
                            return (m.is_owner, String::new(), None);
                        };
                        // to_bech32's error type is the never type: unwrappable.
                        let npub = npub_hex.to_bech32().expect("bech32 of a parsed key");
                        let advert = noscat_core::relay::fetch_advert_for(
                            &relays,
                            None,
                            Some(npub_hex),
                        )
                        .await
                        .ok()
                        .flatten();
                        (m.is_owner, npub, advert)
                    }
                })));
            for (is_owner, npub, advert) in fetched {
                if npub.is_empty() {
                    continue;
                }
                match advert {
                    Some(a) => {
                        b.lock()
                            .expect("peer book")
                            .noise_to_npub
                            .insert(hex::encode(a.noise_pub), npub.clone());
                        b.lock().expect("peer book").roster.push((npub, is_owner, a.name));
                    }
                    None => {
                        b.lock().expect("peer book").roster.push((npub, is_owner, None));
                    }
                }
            }
        });
        book
    }

    fn print_event(ev: Event, peers: Option<&std::sync::Mutex<PeerBook>>) {
        match ev {
            Event::Listening { npub, addr } => {
                eprintln!("# 🐈 serving as {npub} on udp/{addr} - waiting for a peer… (Ctrl-C to quit)");
                // The pairing QR: scanning it hands the scanner this node's
                // npub (noscat:<npub>, see docs/nip-noscat.md). Colors are
                // inverted: most terminals are dark-background, so dark QR
                // modules render as background and the code stays scannable.
                if let Ok(code) = qrcode::QrCode::new(format!("noscat:{npub}")) {
                    let qr = code
                        .render::<qrcode::render::unicode::Dense1x2>()
                        .dark_color(qrcode::render::unicode::Dense1x2::Light)
                        .light_color(qrcode::render::unicode::Dense1x2::Dark)
                        .quiet_zone(true)
                        .build();
                    eprintln!("{qr}");
                    eprintln!("# scan to pair, or paste the npub above");
                }
            }
            Event::TunnelUp { peer, addr } => {
                eprintln!("# 🔗 tunnel up with {peer} (udp/{addr})")
            }
            Event::TunnelClosed { peer, error } => match error {
                Some(e) => eprintln!("# ⚠️  session with {peer} failed: {e}"),
                None => eprintln!("# 🔁 session with {peer} closed"),
            },
            Event::Stopped { what, error } => match error {
                Some(e) => eprintln!("# ⚠️  {what} stopped: {e}"),
                None => eprintln!("# {what} stopped"),
            },
            Event::Incoming { .. } => {}
            Event::TransferDone { .. } => {}
            Event::TransferProgress { .. } => {} // the CLI narrates completion only
            Event::ChatMessage { peer, text } => {
                let label = peers
                    .and_then(|b| b.lock().ok().map(|b| b.label(&peer)))
                    .unwrap_or_else(|| peer.clone());
                println!("# 💬 {label}: {text}");
                println!("#    reply: 'to {label}' then type");
            }
            Event::ChatFailed { peer, error } => {
                eprintln!("# ⚠️  message to {} not delivered: {error}", short_npub(&peer))
            }
            Event::ChatDelivered { peer } => {
                eprintln!("# ✓ delivered to {}", short_npub(&peer))
            }
            Event::Clipboard { peer, text } => {
                let label = peers
                    .and_then(|b| b.lock().ok().map(|b| b.label(&peer)))
                    .unwrap_or_else(|| peer.clone());
                match set_system_clipboard(&text) {
                    Ok(()) => println!("# 📋 clipboard from {label}: copied {} bytes", text.len()),
                    Err(e) => {
                        println!("# 📋 clipboard from {label}:");
                        println!("{text}");
                        eprintln!("# ⚠️  could not reach a clipboard tool ({e}); text above")
                    }
                }
            }
            Event::TransferFailed { error, .. } => {
                eprintln!("# ⚠️  transfer failed: {error}")
            }
            Event::TransferCancelled { path, .. } => {
                eprintln!("# ✋ transfer cancelled: {} (the receiver keeps its partial; the next send resumes)", path.display())
            }
            Event::ForwardStopped { id, error: Some(e) } => {
                eprintln!("# ⚠️  forward {id} failed: {e}")
            }
            Event::ForwardStopped { id, error: None } => {
                eprintln!("# ✋ forward {id} stopped")
            }
        }
    }

    /// Reply to mesh chats from the `up` terminal: `to <prefix>` picks a
    /// peer (a roster npub prefix, `owner`, or the noise-key prefix from an
    /// incoming message's reply hint), every other non-empty line goes to
    /// them as a chat message. Bare `to` lists the roster. `clip` shares
    /// the local clipboard with the selected peer.
    fn spawn_chat_repl(
        client: Client,
        peers: std::sync::Arc<std::sync::Mutex<PeerBook>>,
    ) {
        std::thread::spawn(move || {
            let mut target: Option<String> = None;
            eprintln!(
                "# 💬 chat ready: 'to' lists devices, 'to <prefix>' picks one, then type lines to send ('clip' shares your clipboard)"
            );
            for line in std::io::stdin().lines().map_while(Result::ok) {
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }
                if line == "to" {
                    list_roster(&client, &peers);
                    continue;
                }
                if line == "clip" {
                    match &target {
                        Some(npub) => match get_system_clipboard() {
                            Ok(text) if !text.is_empty() => {
                                client.send_clipboard(npub, &text);
                                eprintln!(
                                    "# 📋 clipboard sent to {} ({} bytes)",
                                    short_npub(npub),
                                    text.len()
                                );
                            }
                            Ok(_) => eprintln!("# 📋 the local clipboard is empty - nothing to send"),
                            Err(e) => eprintln!("# ⚠️  could not read the local clipboard ({e})"),
                        },
                        None => eprintln!(
                            "# 💬 no peer selected: 'to' lists devices, 'to <prefix>' picks one"
                        ),
                    }
                    continue;
                }
                if let Some(prefix) = line.strip_prefix("to ").map(str::trim) {
                    if prefix.is_empty() {
                        list_roster(&client, &peers);
                        continue;
                    }
                    match peers.lock().expect("peer book").resolve(prefix) {
                        Ok(npub) => {
                            eprintln!("# 💬 chatting with {}...", short_npub(&npub));
                            target = Some(npub);
                        }
                        Err(e) => {
                            eprintln!("# ⚠️  {e}");
                            list_roster(&client, &peers);
                        }
                    }
                    continue;
                }
                match &target {
                    Some(npub) => client.send_chat(npub, &line),
                    None => eprintln!("# 💬 no peer selected: 'to' lists devices, 'to <prefix>' picks one"),
                }
            }
        });
    }

    // Print events in the background while the main thread runs a blocking
    // session (serve/pipe bridge stdio and cannot drain themselves). `peers`
    // decorates chat messages with roster identities when running as a node.
    /// Pump events until the in-flight transfer ends: `TransferDone` returns,
/// `TransferFailed` bails. Every event still goes through `print_event`
/// first so progress lines render in order.
fn wait_transfer(rx: std::sync::mpsc::Receiver<Event>) -> anyhow::Result<()> {
    for ev in rx {
        let failed = match &ev {
            Event::TransferDone { .. } => return Ok(()),
            Event::TransferFailed { error, .. } => Some(error.clone()),
            _ => None,
        };
        print_event(ev, None);
        if let Some(error) = failed {
            anyhow::bail!("transfer failed: {error}");
        }
    }
    Ok(())
}

fn spawn_printer(
        rx: std::sync::mpsc::Receiver<Event>,
        peers: Option<std::sync::Arc<std::sync::Mutex<PeerBook>>>,
    ) {
        std::thread::spawn(move || {
            for ev in rx {
                print_event(ev, peers.as_deref());
            }
        });
    }

    match cli.command {
        Command::Completions { shell } => {
            clap_complete::generate(shell, &mut Cli::command(), "noscat", &mut std::io::stdout());
        }
        Command::Keygen { show_secret } => {
            let id = noscat_core::Identity::generate();
            println!("{}", id.npub());
            if show_secret {
                println!("nsec-hex: {}", id.secret_hex());
            }
        }
        Command::Advertise {
            relays,
            endpoints,
            ttl,
        } => {
            let mut parsed = Vec::new();
            for e in endpoints {
                let (transport, addr) = e
                    .split_once('/')
                    .ok_or_else(|| anyhow::anyhow!("endpoint must be <transport>/<ip:port>, got {e}"))?;
                let transport = match transport {
                    "udp" => noscat_core::advert::Transport::Udp,
                    "tcp" => noscat_core::advert::Transport::Tcp,
                    other => anyhow::bail!("unknown transport {other:?} (want udp or tcp)"),
                };
                parsed.push(noscat_core::advert::Endpoint {
                    transport,
                    addr: addr.to_string(),
                });
            }
            if parsed.is_empty() {
                anyhow::bail!("no endpoints given: pass at least one --endpoint <transport>/<ip:port>");
            }
            let id = noscat_core::Identity::generate();
            eprintln!("# 🐈 advertising as {}", id.npub());
            let (noise_pub, _) = noscat_core::tunnel::noise_keypair(&id)?;
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(noscat_core::relay::publish_advert(
                &id,
                parsed,
                noise_pub,
                None,
                ttl,
                &relays_or_default(relays),
            ))?;
            eprintln!("# done");
        }
        Command::Watch { relays } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(noscat_core::relay::watch_adverts(&relays_or_default(relays)))?;
        }
        Command::Serve {
            listen,
            relays,
            ttl,
            identity,
            mesh,
        } => {
            let identity = identity
                .map(IdentitySource::File)
                .or_else(default_identity)
                .unwrap_or(IdentitySource::Ephemeral);
            let listen: std::net::SocketAddr = listen
                .parse()
                .map_err(|e| anyhow::anyhow!("bad --listen address: {e}"))?;
            let (client, rx) = make_client(identity, relays, mesh, Some(listen), ttl, None)?;
            spawn_printer(rx, None);
            client.serve_stdio()?;
        }
        Command::Pipe {
            target,
            relays,
            identity,
            mesh,
        } => {
            let identity = identity_from_arg_or_env(identity);
            let (client, rx) = make_client(
                identity,
                relays,
                mesh,
                None,
                noscat_core::advert::ADVERT_TTL_SECS,
                None,
            )?;
            spawn_printer(rx, None);
            client.pipe_stdio(&target)?;
        }
        Command::Send { path, target, relays, identity, mesh } => {
            let identity = identity_from_arg_or_env(identity);
            let (client, rx) = make_client(
                identity,
                relays,
                mesh,
                None,
                noscat_core::advert::ADVERT_TTL_SECS,
                None,
            )?;
            client.send_file(path, &target);
            wait_transfer(rx)?;
        }
        Command::Receive { out, listen, relays, identity, mesh, ttl } => {
            // Disk-write exposure without authorization: `up` hard-requires
            // --mesh for the same surface. Receive keeps unmeshed netcat
            // mode (scripted transfers over an explicit key), but it says
            // so loudly - anyone who has the public advert can dial.
            if mesh.is_none() {
                eprintln!(
                    "# ⚠️  no --mesh: ANY peer who learns this node's npub can connect and\n\
                     #    write files into {}. For owner-only inbound, run --mesh (or `up --mesh`).",
                    out.display()
                );
            }
            let identity = identity
                .map(IdentitySource::File)
                .or_else(default_identity)
                .unwrap_or(IdentitySource::Ephemeral);
            let listen: std::net::SocketAddr = listen
                .parse()
                .map_err(|e| anyhow::anyhow!("bad --listen address: {e}"))?;
            let (client, rx) = make_client(identity, relays, mesh, Some(listen), ttl, None)?;
            // Report readiness up front: receive_file blocks on the sender's
            // handshake, and without this the user stares at silence.
            print_event(Event::Listening { npub: client.npub().to_string(), addr: listen }, None);
            client.receive_file(out);
            wait_transfer(rx)?;
        }
        // --identity does not apply here: in mesh mode this command IS its
        // mesh device, so the identity comes from the device directory.
        Command::Up { out, to, listen, relays, identity: _, mesh, ttl, name } => {
            // Authorization comes from mesh membership; without it any npub
            // that scans the QR could push files to this machine.
            let Some(mesh) = mesh else {
                anyhow::bail!("up requires --mesh: mesh membership authorizes inbound connections (create one with `noscat mesh create`)");
            };
            let device_dir = mesh_dir_path(&mesh);
            // In mesh mode this node IS its mesh device: one identity
            // for the pairing QR, the invitations, and the tunnels. (The
            // phone does the same once it has joined.)
            let device = noscat_core::mesh::Device::open(&device_dir)?;
            let identity = IdentitySource::Secret(device.identity.secret_hex());
            let device_name = name.unwrap_or_else(noscat_core::default_device_name);
            let listen: std::net::SocketAddr = listen
                .parse()
                .map_err(|e| anyhow::anyhow!("bad --listen address: {e}"))?;
            let out_dir = out.unwrap_or_else(|| {
                std::env::var("HOME")
                    .or_else(|_| std::env::var("USERPROFILE"))
                    .map(|h| std::path::PathBuf::from(h).join("Downloads"))
                    .unwrap_or_else(|_| std::path::PathBuf::from("."))
            });
            // Pairing: when this device owns the mesh, it watches the
            // relays for devices asking to join (their published key
            // packages) and invites them on confirmation.
            let (client, rx) = make_client(identity, relays.clone(), Some(mesh), Some(listen), ttl, Some(device_name))?;
            let peers = spawn_peer_book(device_dir.clone(), relays_or_default(relays.clone()));
            spawn_printer(rx, Some(peers.clone()));
            spawn_pairing_watcher(device_dir.clone(), relays_or_default(relays));
            client.up(out_dir, to)?;
            spawn_chat_repl(client.clone(), peers);
            // The node runs on the client's background tasks; park forever
            // (park can return spuriously, so loop) until Ctrl-C.
            loop {
                std::thread::park();
            }
        }
        Command::Expose { to, listen, relays, identity, mesh, ttl } => {
            let identity = identity
                .map(IdentitySource::File)
                .or_else(default_identity)
                .unwrap_or(IdentitySource::Ephemeral);
            let listen: std::net::SocketAddr = listen
                .parse()
                .map_err(|e| anyhow::anyhow!("bad --listen address: {e}"))?;
            let to: std::net::SocketAddr = to
                .parse()
                .map_err(|e| anyhow::anyhow!("bad --to address: {e}"))?;
            let (client, rx) = make_client(identity, relays, mesh, Some(listen), ttl, None)?;
            client.expose(to)?;
            eprintln!("# 🔗 exposing tcp/{to} over tunnels");
            for ev in rx {
                match &ev {
                    Event::Stopped { error: Some(e), .. } => anyhow::bail!("{e}"),
                    _ => {}
                }
                print_event(ev, None);
            }
        }
        Command::Forward { target, port, bind, relays, identity, mesh } => {
            let identity = identity_from_arg_or_env(identity);
            let local = std::net::SocketAddr::new(bind, port);
            let (client, rx) = make_client(
                identity,
                relays,
                mesh,
                None,
                noscat_core::advert::ADVERT_TTL_SECS,
                None,
            )?;
            let id = client.forward(&target, local);
            eprintln!("# 🐈 forward {id}: tcp/{local} over tunnels to {target}");
            for ev in rx {
                match &ev {
                    Event::Stopped { error: Some(e), .. } => anyhow::bail!("{e}"),
                    Event::ForwardStopped { error: Some(e), .. } => anyhow::bail!("{e}"),
                    _ => {}
                }
                print_event(ev, None);
            }
        }
        Command::Mesh(cmd) => {
            let rt = tokio::runtime::Runtime::new()?;
            match cmd {
                MeshCommand::Create { dir, relays: _ } => {
                    let mut device = noscat_core::mesh::Device::open(&dir)?;
                    device.create_mesh()?;
                    eprintln!(
                        "# ✅ mesh created; owner is {} (dir: {})",
                        device.identity.npub(),
                        dir.display()
                    );
                }
                MeshCommand::Publish { dir, owner, relays } => {
                    let device = noscat_core::mesh::Device::open(&dir)?;
                    let target = match &owner {
                        Some(npub) => Some(nostr::prelude::PublicKey::parse(npub)
                            .map_err(|e| anyhow::anyhow!("bad npub: {e}"))?),
                        None => None,
                    };
                    rt.block_on(device.publish_key_package(&relays_or_default(relays), target))?;
                    eprintln!("# 📢 key package published as {}", device.identity.npub());
                }
                MeshCommand::Invite { dir, device: npub, relays } => {
                    let mut device = noscat_core::mesh::Device::open(&dir)?;
                    let invitee = nostr::prelude::PublicKey::parse(&npub)
                        .map_err(|e| anyhow::anyhow!("bad npub: {e}"))?;
                    rt.block_on(device.invite(invitee, &relays_or_default(relays)))?;
                    eprintln!("# ✅ invited {npub} into the mesh");
                }
                MeshCommand::Join { dir, owner, relays } => {
                    let mut device = noscat_core::mesh::Device::open(&dir)?;
                    let expected = nostr::prelude::PublicKey::parse(&owner)
                        .map_err(|e| anyhow::anyhow!("bad npub: {e}"))?;
                    rt.block_on(device.join_mesh(&relays_or_default(relays), expected))?;
                }
                MeshCommand::Members { dir } => {
                    let device = noscat_core::mesh::Device::open(&dir)?;
                    let members = device.list_members()?;
                    // Point-in-time presence: each member's freshest advert
                    // says when it was last live (published within the
                    // advert TTL = online). Offline members read as
                    // offline, never an error.
                    let relays = relays_or_default(Vec::new());
                    let now = nostr::prelude::Timestamp::now().as_secs();
                    let ages = members.iter().map(|m| async {
                        let Ok(pk) = nostr::prelude::PublicKey::from_hex(&m.npub) else {
                            return None;
                        };
                        noscat_core::relay::fetch_advert_for(&relays, None, Some(pk))
                            .await
                            .ok()
                            .flatten()
                            .map(|a| now.saturating_sub(a.created_at))
                    });
                    let ages = rt.block_on(futures_util::future::join_all(ages));
                    for (m, age) in members.into_iter().zip(ages) {
                        let presence = match age {
                            Some(a) if a < noscat_core::advert::ADVERT_TTL_SECS => {
                                format!("online, advert {a}s ago")
                            }
                            Some(a) => {
                                let (v, unit) = if a < 86_400 {
                                    (a / 60, "min")
                                } else {
                                    (a / 3_600, "h")
                                };
                                format!("offline, advert {v} {unit} ago")
                            }
                            None => "offline, no advert".to_string(),
                        };
                        println!(
                            "{} epoch={} {} ({presence})",
                            if m.is_owner { "owner " } else { "member" },
                            m.epoch,
                            m.npub
                        );
                    }
                }
                MeshCommand::Remove { dir, device: npub, relays } => {
                    let mut device = noscat_core::mesh::Device::open(&dir)?;
                    let removed = nostr::prelude::PublicKey::parse(&npub)
                        .map_err(|e| anyhow::anyhow!("bad npub: {e}"))?;
                    rt.block_on(device.remove_member(removed, &relays_or_default(relays)))?;
                    eprintln!("# ✅ removed {npub} from the mesh (epoch ratcheted)");
                }
                MeshCommand::Sync { dir, for_secs, relays } => {
                    let mut device = noscat_core::mesh::Device::open(&dir)?;
                    let merged = rt.block_on(device.sync_mesh(
                        &relays_or_default(relays),
                        std::time::Duration::from_secs(for_secs),
                    ))?;
                    eprintln!("# ✅ synced: {merged} commit(s) merged");
                    if merged == 0 {
                        eprintln!(
                            "# ℹ️  nothing merged. If other members' dials still fail with\n\
                             #    handshake timeouts, their epoch may be stranded: the owner\n\
                             #    should run `noscat mesh resend` to re-publish the commits."
                        );
                    }
                }
                MeshCommand::Resend { dir, to, relays } => {
                    let mut device = noscat_core::mesh::Device::open(&dir)?;
                    let target = match &to {
                        Some(npub) => Some(
                            nostr::prelude::PublicKey::parse(npub)
                                .map_err(|e| anyhow::anyhow!("bad npub: {e}"))?,
                        ),
                        None => None,
                    };
                    let sent = rt.block_on(device.resend_commits(target, &relays_or_default(relays)))?;
                    match to {
                        Some(npub) => eprintln!("# ✅ resent {sent} commit(s) to {npub}"),
                        None => eprintln!("# ✅ resent {sent} commit(s) to every member"),
                    }
                }
                MeshCommand::Psk { dir } => {
                    let device = noscat_core::mesh::Device::open(&dir)?;
                    println!("{}", hex::encode(device.tunnel_psk()?));
                }
            }
        }
    }
    Ok(())
}
