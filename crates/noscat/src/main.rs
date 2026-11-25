//! The noscat CLI: a thin skin over `noscat-client`.
//!
//! One process runs a device (its state directory is locked); every other
//! command on the same directory goes through that process's control
//! channel (`control.rs`), or starts the device itself when none runs.

mod clipboard;
mod control;
mod service;
mod ui;

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use noscat_client::{Client, ClientConfig, ClientError, Event, IdentitySource};

use crate::control::{Ctx, Op, Reply};

#[derive(Parser)]
#[command(
    name = "noscat",
    version,
    about = "like netcat, but over your own device mesh: npub-addressed, end-to-end encrypted, no root, no accounts"
)]
struct Cli {
    /// Info-level logs, plus the routine FIPS warnings hidden by default (startup, path upgrades, congestion). RUST_LOG overrides.
    #[arg(long, global = true)]
    verbose: bool,
    /// Device state directory (identity, mesh). Also NOSCAT_DIR.
    /// [default: the platform data directory, e.g. ~/.local/share/noscat]
    #[arg(long, global = true)]
    dir: Option<PathBuf>,
    #[command(flatten)]
    device: DeviceArgs,
    #[command(subcommand)]
    command: Command,
}

/// How the device runs; used by whichever command starts it.
#[derive(Args, Clone)]
struct DeviceArgs {
    /// Relay URL (repeatable) [default: the public set].
    #[arg(long = "relay", global = true)]
    relays: Vec<String>,
    /// UDP address of the data plane [default: any free port, 41641 with --reachable].
    #[arg(long, global = true)]
    listen: Option<SocketAddr>,
    /// Name other members see, for this run [default: the name saved by
    /// `noscat name`, else the hostname].
    #[arg(long, global = true)]
    name: Option<String>,
    /// This device is reachable from the internet (port forward, server,
    /// public IPv6). Give the public address, or nothing to learn it by STUN.
    /// Every mesh needs at least one reachable member.
    #[arg(long, global = true, num_args = 0..=1, default_missing_value = "")]
    reachable: Option<String>,
    /// A known address of a device, `<npub>@<ip:port>` (repeatable).
    #[arg(long = "peer", global = true)]
    peers: Vec<String>,
    /// Do not look for members on the LAN (mDNS).
    #[arg(long, global = true)]
    no_lan: bool,
    /// STUN server (repeatable) [default: the data plane's set].
    #[arg(long = "stun", global = true, hide = true)]
    stun: Vec<String>,
}

#[derive(Subcommand)]
enum Command {
    /// Print this device's npub and pairing QR.
    Id,
    /// Print this device's name, or rename it: saved for every later run,
    /// and a running device tells the members right away.
    Name {
        /// The new name; the words are joined with spaces.
        name: Vec<String>,
    },
    /// Generate a throwaway identity (devices create their own on first use).
    Keygen {
        /// Also print the secret key (hex). Handle with care.
        #[arg(long)]
        show_secret: bool,
    },
    /// Run this device: receive files, chat, serve members until Ctrl-C.
    Up(UpArgs),
    /// Run `noscat up` in the background at login and boot (systemd user
    /// unit on Linux, launchd agent on macOS).
    #[command(subcommand)]
    Service(ServiceCommand),
    /// Run this device and expose one TCP service to members.
    Expose {
        /// The local service, e.g. 127.0.0.1:8000.
        #[arg(long)]
        to: SocketAddr,
    },
    /// Netcat listen: bridge the first member stream to stdio.
    Serve,
    /// Netcat connect: bridge stdio to a member's default service.
    Pipe {
        /// The member (npub or noscat: URI).
        target: String,
    },
    /// Send a file to a member.
    Send {
        /// The file to send.
        path: PathBuf,
        /// The member (npub or noscat: URI).
        target: String,
    },
    /// Send a chat message to a member.
    Chat {
        /// The member (npub or noscat: URI).
        target: String,
        /// The message; the words are joined with spaces.
        #[arg(required = true, num_args = 1..)]
        text: Vec<String>,
    },
    /// Share this machine's clipboard with a member.
    Clip {
        /// The member (npub or noscat: URI).
        target: String,
    },
    /// Forward a local TCP port to a member.
    Forward {
        /// The member (npub or noscat: URI).
        target: String,
        /// Local TCP port to listen on.
        #[arg(long)]
        port: u16,
        /// Local address for the listener. Loopback by default: anyone who
        /// can reach it can use the forward.
        #[arg(long, default_value = "127.0.0.1")]
        bind: IpAddr,
        /// A port the member serves (`up --serve-port`) [default: its default service].
        #[arg(long, default_value_t = 0)]
        remote_port: u16,
    },
    /// Manage the mesh.
    #[command(subcommand)]
    Mesh(MeshCommand),
    /// Emit shell completions (hidden; used by packaging).
    #[command(hide = true)]
    Completions { shell: Shell },
}

/// `up`'s own options, shared with `service install`.
#[derive(Args, Clone)]
struct UpArgs {
    /// Where received files go [default: ~/Downloads].
    #[arg(long)]
    out: Option<PathBuf>,
    /// Bridge members' default-service streams to this TCP service, e.g. 127.0.0.1:22.
    #[arg(long)]
    to: Option<SocketAddr>,
    /// Let members forward to this local port by number (repeatable).
    #[arg(long = "serve-port")]
    serve_ports: Vec<u16>,
    /// Invite every device that asks to join (scanned this device's QR, or
    /// otherwise knows its npub) without asking. Off by default.
    #[arg(long)]
    accept_joins: bool,
}

#[derive(Subcommand)]
enum ServiceCommand {
    /// Install and start the service, running `noscat up` with the options
    /// given here (global ones like --reachable, --name, --relay too).
    /// Installing again replaces it.
    Install {
        #[command(flatten)]
        up: UpArgs,
    },
    /// Stop and remove the service.
    Uninstall,
    /// Show whether it runs, with its latest log lines.
    Status,
}

/// The `noscat up` command line a service runs: this executable, `up`, its
/// options, then the global ones (`--reachable` last: with no address it
/// would otherwise swallow the next word). Paths are absolute, since a
/// service starts elsewhere.
fn service_argv(cli_dir: Option<&Path>, verbose: bool, d: &DeviceArgs, up: &UpArgs) -> Result<Vec<String>> {
    let exe = std::env::current_exe().context("cannot find this executable")?;
    let exe = std::fs::canonicalize(&exe).unwrap_or(exe);
    let abs = |p: &Path| std::path::absolute(p).map(|p| p.to_string_lossy().into_owned());
    let mut a = vec![exe.to_string_lossy().into_owned(), "up".to_string()];
    if let Some(out) = &up.out {
        a.extend(["--out".into(), abs(out)?]);
    }
    if let Some(to) = up.to {
        a.extend(["--to".into(), to.to_string()]);
    }
    for p in &up.serve_ports {
        a.extend(["--serve-port".into(), p.to_string()]);
    }
    if up.accept_joins {
        a.push("--accept-joins".into());
    }
    if verbose {
        a.push("--verbose".into());
    }
    // An explicit dir, or NOSCAT_DIR (the service has no such variable).
    let dir = cli_dir
        .map(Path::to_path_buf)
        .or_else(|| std::env::var_os("NOSCAT_DIR").filter(|d| !d.is_empty()).map(PathBuf::from));
    if let Some(dir) = dir {
        a.extend(["--dir".into(), abs(&dir)?]);
    }
    for r in &d.relays {
        a.extend(["--relay".into(), r.clone()]);
    }
    if let Some(l) = d.listen {
        a.extend(["--listen".into(), l.to_string()]);
    }
    if let Some(n) = &d.name {
        a.extend(["--name".into(), n.clone()]);
    }
    for p in &d.peers {
        a.extend(["--peer".into(), p.clone()]);
    }
    if d.no_lan {
        a.push("--no-lan".into());
    }
    for s in &d.stun {
        a.extend(["--stun".into(), s.clone()]);
    }
    match d.reachable.as_deref() {
        Some("") => a.push("--reachable".into()),
        Some(addr) => a.push(format!("--reachable={addr}")),
        None => {}
    }
    Ok(a)
}

#[derive(Subcommand)]
enum MeshCommand {
    /// Start a new mesh with this device as its only member.
    Create {
        /// The mesh's name, shown to its members.
        name: String,
    },
    /// Add a device. It must be running, or waiting in `mesh join`.
    Invite {
        /// The device (npub or noscat: URI).
        target: String,
    },
    /// Ask a member to invite this device, wait for the invitation and join.
    Join {
        /// The member whose QR you scanned (npub or noscat: URI). Only its
        /// invitation is accepted.
        inviter: String,
        /// Give up after this many seconds.
        #[arg(long, default_value_t = 600)]
        timeout: u64,
    },
    /// Remove a member.
    Remove {
        /// The member (npub or noscat: URI).
        target: String,
    },
    /// Leave the mesh.
    Leave {
        /// Wait this long for another member to complete it.
        #[arg(long, default_value_t = 120)]
        timeout: u64,
    },
    /// List the members and their presence.
    Members,
    /// Print this device's pairing QR.
    Qr,
}

fn default_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("NOSCAT_DIR").filter(|d| !d.is_empty()) {
        return d.into();
    }
    #[cfg(target_os = "windows")]
    if let Some(a) = std::env::var_os("APPDATA") {
        return PathBuf::from(a).join("noscat");
    }
    #[cfg(target_os = "macos")]
    if let Some(h) = std::env::var_os("HOME") {
        return PathBuf::from(h).join("Library").join("Application Support").join("noscat");
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(x) = std::env::var_os("XDG_DATA_HOME").filter(|x| !x.is_empty()) {
            return PathBuf::from(x).join("noscat");
        }
        if let Some(h) = std::env::var_os("HOME") {
            return PathBuf::from(h).join(".local").join("share").join("noscat");
        }
    }
    PathBuf::from(".noscat")
}

/// The identity: NOSCAT_IDENTITY (hex or nsec; never argv, which `ps`
/// shows everyone), else `<dir>/identity.nsec`.
fn identity(dir: &Path) -> IdentitySource {
    match std::env::var("NOSCAT_IDENTITY") {
        Ok(s) if !s.trim().is_empty() => IdentitySource::Secret(s.trim().to_string()),
        _ => IdentitySource::File(dir.join("identity.nsec")),
    }
}

/// The name saved by `noscat name`, kept in the device directory.
fn name_file(dir: &Path) -> PathBuf {
    dir.join("name")
}

fn saved_name(dir: &Path) -> Option<String> {
    let n = std::fs::read_to_string(name_file(dir)).ok()?;
    let n = n.trim();
    (!n.is_empty()).then(|| n.to_string())
}

fn config(dir: &Path, d: &DeviceArgs) -> Result<ClientConfig> {
    let reachable = match d.reachable.as_deref() {
        None => None,
        Some("") => Some(None),
        Some(a) => Some(Some(a.parse().with_context(|| format!("bad --reachable address {a:?}"))?)),
    };
    let mut static_peers = Vec::new();
    for p in &d.peers {
        let (who, addr) = p.rsplit_once('@').with_context(|| format!("--peer wants <npub>@<ip:port>, got {p:?}"))?;
        static_peers.push((who.to_string(), addr.parse().with_context(|| format!("bad address in --peer {p:?}"))?));
    }
    Ok(ClientConfig {
        identity: identity(dir),
        relays: (!d.relays.is_empty()).then(|| d.relays.clone()),
        listen: d.listen,
        mesh_dir: Some(dir.to_path_buf()),
        device_name: d.name.clone().or_else(|| saved_name(dir)),
        reachable,
        lan_discovery: !d.no_lan,
        static_peers,
        stun_servers: (!d.stun.is_empty()).then(|| d.stun.clone()),
        ..ClientConfig::default()
    })
}

/// Start the device for `dir`, serving the control channel for others.
/// `None` when another process runs it.
fn start(dir: &Path, d: &DeviceArgs, rt: &tokio::runtime::Runtime) -> Result<Option<Ctx>> {
    let client = match Client::start(config(dir, d)?) {
        Ok(c) => c,
        Err(ClientError::Busy(_)) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let ctx = Ctx::new(client);
    rt.block_on(control::serve(ctx.clone(), dir))?;
    Ok(Some(ctx))
}

fn show(reply: Reply) {
    match reply {
        Reply::Line { text } => eprintln!("# {text}"),
        Reply::Members { mesh, members } => ui::print_members(mesh.as_deref(), &members),
        Reply::Done | Reply::Error { .. } => {}
    }
}

/// Run `op` on this directory's device: through the running process if
/// there is one, else on a device started here for the command.
fn run_op(dir: &Path, d: &DeviceArgs, op: Op) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    if let Some((conn, token)) = rt.block_on(control::connect(dir)) {
        return rt.block_on(control::ask(conn, token, op, show));
    }
    let Some(ctx) = start(dir, d, &rt)? else {
        // Another process holds the directory; it may still be starting.
        for _ in 0..20 {
            if let Some((conn, token)) = rt.block_on(control::connect(dir)) {
                return rt.block_on(control::ask(conn, token, op, show));
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        bail!("another noscat process is using {} and does not answer", dir.display());
    };
    let res = if let Op::Pipe { target } = &op {
        ctx.client.pipe_stdio(target).map_err(anyhow::Error::from)
    } else {
        rt.block_on(async {
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            let printer = tokio::spawn(async move {
                while let Some(r) = rx.recv().await {
                    show(r);
                }
            });
            let res = control::exec(&ctx, op, &tx, std::future::pending()).await;
            drop(tx);
            let _ = printer.await;
            res.map_err(|e| anyhow::anyhow!(e))
        })
    };
    control::remove(dir);
    drop(ctx);
    res
}

/// Narrate events until the process ends, labelling members by name.
fn spawn_printer(ctx: &Ctx, accept_joins: bool) {
    let client = ctx.client.clone();
    let mut rx = ctx.events.subscribe();
    std::thread::spawn(move || {
        let mut members = client.members();
        loop {
            let ev = match rx.blocking_recv() {
                Ok(ev) => ev,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => return,
            };
            if matches!(ev, Event::Roster { .. } | Event::MemberSeen { .. } | Event::MeshJoined { .. }) {
                members = client.members();
            }
            ui::print_event(&ev, &members);
            if let (true, Event::JoinRequest { peer, name }) = (accept_joins, &ev) {
                auto_invite(&client, peer.clone(), name.clone());
            }
        }
    });
}

/// `up --accept-joins`: invite a device that asked to join. Off the printer
/// thread, since an invite is a relay round trip.
fn auto_invite(client: &Client, peer: String, name: Option<String>) {
    let client = client.clone();
    std::thread::spawn(move || {
        let who = name.unwrap_or_else(|| "the device".into());
        match client.invite(&peer) {
            Ok(()) => eprintln!("# ✅ invited {who} ({peer})"),
            Err(e) => eprintln!("# ❌ could not invite {who} ({peer}): {e}"),
        }
    });
}

fn print_qr(npub: &str) {
    if let Some(qr) = ui::render_pairing_qr(npub) {
        eprintln!("{qr}");
    }
    eprintln!("# {npub}");
}

/// Run a device in the foreground until Ctrl-C.
fn run_device(dir: &Path, d: &DeviceArgs, accept_joins: bool, setup: impl FnOnce(&Client) -> Result<()>) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    let Some(ctx) = start(dir, d, &rt)? else {
        bail!("this device is already running (another noscat process uses {})", dir.display());
    };
    spawn_printer(&ctx, accept_joins);
    setup(&ctx.client)?;
    if accept_joins {
        eprintln!("# 🚪 accepting joins: any device that asks is invited (anyone who knows this npub can ask)");
    }
    if ctx.client.in_mesh() {
        eprintln!("# 🐈 mesh {:?}; scan the QR on a new device to join it", ctx.client.mesh_name().unwrap_or_default());
    } else {
        eprintln!("# not in a mesh yet: `noscat mesh create <name>` or `noscat mesh join <npub>` (in another terminal)");
    }
    print_qr(ctx.client.npub());
    ui::spawn_chat_repl(ctx.client.clone(), name_file(dir));
    loop {
        std::thread::park();
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    // Routine startup noise stays out of the default output (--verbose
    // shows the FIPS warnings): openmls logs at ERROR for an old advert from
    // the backlog a restarted device fetches; FIPS warns that the kernel
    // capped the UDP receive buffer (always, without root) and that a
    // member has no address yet or its retry failed (until its advert
    // arrives, or while it is offline). noscat reports real connection
    // failures itself.
    let filter = if cli.verbose {
        "noscat=info,noscat_core=info,noscat_client=info,nostr_sdk=off,fips_core=warn,openmls=off"
    } else {
        "warn,nostr_sdk=off,nostr_relay_pool=off,openmls=off,\
         fips_core::transport::udp::socket::platform=error,\
         fips_core::node::lifecycle::peer_config=error,\
         fips_core::node::retry=error,fips_core::node::lifecycle::discovery=error,fips_core::node::handlers::mmp=error,fips_core::node::handlers::forwarding=error"
    };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(filter));
    tracing_subscriber::fmt().with_env_filter(filter).with_writer(std::io::stderr).init();

    let dir = cli.dir.clone().unwrap_or_else(default_dir);
    let d = &cli.device;
    match cli.command {
        Command::Completions { shell } => {
            clap_complete::generate(shell, &mut Cli::command(), "noscat", &mut std::io::stdout());
        }
        Command::Keygen { show_secret } => {
            let id = noscat_core::Identity::generate();
            println!("{}", id.npub());
            if show_secret {
                println!("secret (hex): {}", id.secret_hex());
            }
        }
        Command::Id | Command::Mesh(MeshCommand::Qr) => {
            std::fs::create_dir_all(&dir)?;
            let npub = noscat_client::identity_npub(&identity(&dir))?;
            print_qr(&npub);
            println!("{npub}");
        }
        Command::Service(cmd) => match cmd {
            ServiceCommand::Install { up } => {
                if std::env::var("NOSCAT_IDENTITY").is_ok_and(|s| !s.trim().is_empty()) {
                    bail!("NOSCAT_IDENTITY is set, but a service uses the identity file in the device directory; unset it");
                }
                // A device already running here that is not the service
                // (a `noscat up` in a terminal) would make the service fail.
                if !service::active() {
                    let rt = tokio::runtime::Runtime::new()?;
                    if rt.block_on(control::connect(&dir)).is_some() {
                        bail!("this device is already running (a `noscat up`?); stop it, then install the service");
                    }
                }
                let argv = service_argv(cli.dir.as_deref(), cli.verbose, d, &up)?;
                service::install(&argv)?;
                println!("runs: {}", argv.join(" "));
            }
            ServiceCommand::Uninstall => service::uninstall()?,
            ServiceCommand::Status => service::status()?,
        },
        Command::Up(UpArgs { out, to, serve_ports, accept_joins }) => {
            let out = out.unwrap_or_else(|| {
                std::env::var_os("HOME")
                    .or_else(|| std::env::var_os("USERPROFILE"))
                    .map(|h| PathBuf::from(h).join("Downloads"))
                    .unwrap_or_else(|| PathBuf::from("."))
            });
            run_device(&dir, d, accept_joins, |c| {
                c.up(out.clone(), to)?;
                eprintln!("# 📥 files from members go to {}", out.display());
                if let Some(to) = to {
                    eprintln!("# 🔗 members' default-service streams go to tcp/{to}");
                }
                for p in &serve_ports {
                    c.serve_port(*p, true);
                    eprintln!("# 🔓 members may forward to local port {p}");
                }
                Ok(())
            })?;
        }
        Command::Expose { to } => {
            run_device(&dir, d, false, |c| {
                c.expose(to)?;
                eprintln!("# 🔗 exposing tcp/{to} to members");
                Ok(())
            })?;
        }
        Command::Serve => {
            let rt = tokio::runtime::Runtime::new()?;
            let Some(ctx) = start(&dir, d, &rt)? else {
                bail!("this device is already running; stop it to use serve");
            };
            eprintln!("# 🐈 waiting for a member to `noscat pipe {}`", ctx.client.npub());
            let res = ctx.client.serve_stdio();
            control::remove(&dir);
            res?;
        }
        Command::Pipe { target } => run_op(&dir, d, Op::Pipe { target })?,
        Command::Send { path, target } => {
            let path = std::fs::canonicalize(&path).with_context(|| format!("cannot read {}", path.display()))?;
            run_op(&dir, d, Op::Send { path, target })?;
        }
        Command::Chat { target, text } => {
            run_op(&dir, d, Op::Text { target, text: text.join(" "), clipboard: false })?;
        }
        Command::Clip { target } => {
            let text = clipboard::get_system_clipboard()?;
            anyhow::ensure!(!text.is_empty(), "the clipboard is empty");
            run_op(&dir, d, Op::Text { target, text, clipboard: true })?;
        }
        Command::Forward { target, port, bind, remote_port } => {
            run_op(&dir, d, Op::Forward { target, local: SocketAddr::new(bind, port), remote_port })?;
        }
        Command::Name { name } => {
            let name = name.join(" ");
            let name = name.trim();
            if name.is_empty() {
                let n = d.name.clone().or_else(|| saved_name(&dir)).unwrap_or_else(noscat_core::default_device_name);
                println!("{n}");
            } else {
                std::fs::create_dir_all(&dir)?;
                std::fs::write(name_file(&dir), format!("{name}\n"))?;
                run_op(&dir, d, Op::Rename { name: name.to_string() })?;
            }
        }
        Command::Mesh(cmd) => {
            let op = match cmd {
                MeshCommand::Create { name } => Op::Create { name },
                MeshCommand::Invite { target } => Op::Invite { target },
                MeshCommand::Join { inviter, timeout } => {
                    std::fs::create_dir_all(&dir)?;
                    let npub = noscat_client::identity_npub(&identity(&dir))?;
                    eprintln!("# on {inviter}, run `noscat mesh invite {npub}` (or scan this QR in the app):");
                    print_qr(&npub);
                    Op::Join { inviter, timeout_secs: timeout }
                }
                MeshCommand::Remove { target } => Op::Remove { target },
                MeshCommand::Leave { timeout } => Op::Leave { timeout_secs: timeout },
                MeshCommand::Members => Op::Members,
                MeshCommand::Qr => unreachable!("handled above"),
            };
            run_op(&dir, d, op)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What `service install` parses into the service's command line, and
    /// that the command line parses back as `up` with the same options.
    #[test]
    fn service_argv_round_trips() {
        let cli = Cli::try_parse_from([
            "noscat", "--reachable", "--name", "home box", "--relay", "wss://r.example", "service", "install",
            "--to", "127.0.0.1:22", "--serve-port", "8080", "--out", "inbox",
        ])
        .unwrap();
        let Command::Service(ServiceCommand::Install { up }) = &cli.command else { panic!("not service install") };
        let argv = service_argv(None, false, &cli.device, up).unwrap();
        assert_eq!(argv.last().map(String::as_str), Some("--reachable"));
        assert!(Path::new(&argv[argv.iter().position(|a| a == "--out").unwrap() + 1]).is_absolute());
        let back = Cli::try_parse_from(&argv).unwrap();
        let Command::Up(u) = back.command else { panic!("not up") };
        assert_eq!(u.to, Some("127.0.0.1:22".parse().unwrap()));
        assert_eq!(u.serve_ports, vec![8080]);
        assert_eq!(back.device.reachable.as_deref(), Some(""));
        assert_eq!(back.device.name.as_deref(), Some("home box"));
        assert_eq!(back.device.relays, vec!["wss://r.example".to_string()]);
    }
}
