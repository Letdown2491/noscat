//! The noscat CLI: a thin skin over `noscat-client`.
//!
//! One process runs a device (its state directory is locked); every other
//! command on the same directory goes through that process's control
//! channel (`control.rs`), or starts the device itself when none runs.

mod clipboard;
mod control;
mod service;
mod shell;
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
    /// public IPv6). Give the public address, or nothing to learn it by STUN
    /// (the mesh's STUN servers; a private mesh without any needs the address).
    /// Every mesh needs at least one reachable member.
    #[arg(long, global = true, num_args = 0..=1, default_missing_value = "")]
    reachable: Option<String>,
    /// A known address of a device, `<npub>@<ip:port>` (repeatable).
    #[arg(long = "peer", global = true)]
    peers: Vec<String>,
    /// Do not look for members on the LAN (mDNS).
    #[arg(long, global = true)]
    no_lan: bool,
    /// STUN server, `host:port` (repeatable). Overrides the mesh's own
    /// (`mesh stun`); without it a shared mesh with none uses public STUN
    /// servers and a private mesh uses none.
    #[arg(long = "stun", global = true)]
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
    /// Open a shell on a member, in this terminal. The member asks its user
    /// first unless it already allows this device `control`; exits with
    /// the remote shell's status.
    Shell {
        /// A member's name or npub.
        target: String,
    },
    /// List the terminal sessions members have open on this device, or
    /// end one.
    Sessions {
        #[command(subcommand)]
        cmd: Option<SessionsCommand>,
    },
    /// Show who may do what to this device: the defaults, members' own
    /// rules, and recent refused or asked requests. Kept on this device
    /// only; no other member learns them.
    Access {
        #[command(subcommand)]
        cmd: Option<AccessCommand>,
    },
    /// Allow a member an access group: `send` (files, chat, clipboard),
    /// `services` (forwards) or `control` (terminal). `everyone` as the
    /// member sets the default. Also answers a request that is waiting.
    Allow {
        /// A member's name or npub, or `everyone`.
        who: String,
        group: GroupArg,
        /// Allow one request only: the waiting one, or the member's next.
        #[arg(long)]
        once: bool,
    },
    /// Deny a member an access group (`everyone`: the default). Also
    /// refuses a request that is waiting.
    Deny {
        /// A member's name or npub, or `everyone`.
        who: String,
        group: GroupArg,
        /// Refuse the waiting request only; change no rule.
        #[arg(long)]
        once: bool,
    },
    /// Have `control` ask on first use for a member (`everyone`: the
    /// default). Without an app on this device to answer, asking refuses.
    Ask {
        /// A member's name or npub, or `everyone`.
        who: String,
        group: GroupArg,
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
    /// Devices that asked to join (scanned this device's QR) in the last
    /// 15 minutes. In a terminal, asks y/n for each and invites on y.
    Requests,
    /// Print this device's pairing QR. In a private mesh it names the
    /// mesh's relays, so a new device joins through them.
    Qr,
    /// List the mesh's relays, or change them (admins).
    Relays {
        #[command(subcommand)]
        cmd: Option<RelaysCommand>,
    },
    /// List the mesh's STUN servers, or change them (admins). Devices learn
    /// their public address from these instead of public STUN servers; a
    /// private mesh without any uses none. Applies from each device's next
    /// start.
    Stun {
        #[command(subcommand)]
        cmd: Option<StunCommand>,
    },
    /// Make the mesh private: its devices use only the mesh's relays, log
    /// in to them (NIP-42) and leave the public ones. For a members-only
    /// relay such as noscat-relay; add it with `mesh relays add` first.
    Private,
    /// Make the mesh shared again: its devices use their own relays too.
    Shared,
}

#[derive(Subcommand)]
enum RelaysCommand {
    /// Add relays to the mesh.
    Add {
        #[arg(required = true)]
        urls: Vec<String>,
    },
    /// Remove relays from the mesh.
    Remove {
        #[arg(required = true)]
        urls: Vec<String>,
    },
}

#[derive(Subcommand)]
enum SessionsCommand {
    /// End a session (its shell is killed).
    End { id: u64 },
}

#[derive(Subcommand)]
enum AccessCommand {
    /// Drop a member's own rules: the defaults apply to it again.
    Reset {
        /// A member's name or npub.
        who: String,
    },
}

/// An access group as the CLI names it.
#[derive(Clone, Copy, clap::ValueEnum)]
enum GroupArg {
    Send,
    Services,
    Control,
}

impl GroupArg {
    fn name(self) -> String {
        match self {
            GroupArg::Send => "send",
            GroupArg::Services => "services",
            GroupArg::Control => "control",
        }
        .to_string()
    }
}

#[derive(Subcommand)]
enum StunCommand {
    /// Add STUN servers (`ip:port`, e.g. noscat-relay's `STUN_ADDR`; no
    /// hostnames).
    Add {
        #[arg(required = true)]
        servers: Vec<String>,
    },
    /// Remove STUN servers.
    Remove {
        #[arg(required = true)]
        servers: Vec<String>,
    },
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
    start_device(dir, d, rt, Vec::new(), false)
}

/// How long a device waits for another process holding its directory: a
/// starting service (its control channel comes up after the relays) or a
/// device started for one command (`mesh members` from a relay's
/// MEMBERS_COMMAND, at boot, while `up` starts too).
const HOLDER_WAIT: Duration = Duration::from_secs(30);

/// Start the long-running device (`up`, `expose`, `serve`). A device
/// started for one command may hold the directory for a moment: wait for
/// it rather than fail. Another long-running device fails at once.
fn start_service(dir: &Path, d: &DeviceArgs, rt: &tokio::runtime::Runtime) -> Result<Ctx> {
    let deadline = std::time::Instant::now() + HOLDER_WAIT;
    let mut said = false;
    loop {
        if let Some(ctx) = start_device(dir, d, rt, Vec::new(), true)? {
            return Ok(ctx);
        }
        if rt.block_on(control::service_running(dir)) {
            bail!("this device is already running (another noscat process uses {})", dir.display());
        }
        if std::time::Instant::now() >= deadline {
            bail!(
                "another noscat command has used {} for {} s; stop it, or run the command through this one once it starts",
                dir.display(),
                HOLDER_WAIT.as_secs()
            );
        }
        if !said {
            eprintln!("# waiting for another noscat command to finish with {}", dir.display());
            said = true;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Wait up to [`HOLDER_WAIT`] for the process holding `dir` to answer on
/// its control channel.
fn wait_for_holder(dir: &Path, rt: &tokio::runtime::Runtime) -> Result<(tokio::net::TcpStream, String)> {
    let deadline = std::time::Instant::now() + HOLDER_WAIT;
    while std::time::Instant::now() < deadline {
        if let Some(c) = rt.block_on(control::connect(dir)) {
            return Ok(c);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    bail!("another noscat process is using {} and does not answer", dir.display());
}

/// As [`start`]; `join_relays` (a pairing code's) are the only relays used
/// until the join ends, so nothing reaches this device's own or the
/// default relays. `service`: the long-running device, as its control
/// file says to other processes.
fn start_device(
    dir: &Path,
    d: &DeviceArgs,
    rt: &tokio::runtime::Runtime,
    join_relays: Vec<String>,
    service: bool,
) -> Result<Option<Ctx>> {
    let mut cfg = config(dir, d)?;
    cfg.join_relays = join_relays;
    let client = match Client::start(cfg) {
        Ok(c) => c,
        Err(ClientError::Busy(_)) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let ctx = Ctx::new(client);
    rt.block_on(control::serve(ctx.clone(), dir, service))?;
    Ok(Some(ctx))
}

fn show(reply: Reply) {
    match reply {
        Reply::Line { text } => eprintln!("# {text}"),
        Reply::Members { mesh, members } => ui::print_members(mesh.as_deref(), &members),
        Reply::Qr { uri } => {
            print_qr(&uri);
            println!("{uri}");
        }
        Reply::Requests { requests } => {
            if requests.is_empty() {
                eprintln!("# no pending join requests (they expire after 15 minutes)");
            }
            for r in requests {
                println!("{}", request_line(&r));
            }
        }
        Reply::Done | Reply::Error { .. } => {}
    }
}

/// One join request: its name (the device's own claim), its npub and age.
fn request_line(r: &control::RequestRow) -> String {
    let name = r.name.as_deref().map(str::trim).filter(|n| !n.is_empty()).unwrap_or("(no name)");
    let age = if r.age_secs < 60 { "just now".to_string() } else { format!("{} min ago", r.age_secs / 60) };
    format!("{name}  {}  asked {age}", r.npub)
}

/// `mesh requests`: list pending join requests and, in a terminal, ask
/// y/n for each, inviting on y. Through the running process if there is
/// one (a service), else on a device started here.
fn requests(dir: &Path, d: &DeviceArgs) -> Result<()> {
    use std::io::{BufRead as _, IsTerminal as _, Write as _};
    let interactive = std::io::stdin().is_terminal();
    let rt = tokio::runtime::Runtime::new()?;
    let dev = Dev::open(dir, d, &rt)?;
    let mut list = Vec::new();
    dev.call(&rt, Op::Requests, |r| match r {
        Reply::Requests { requests } => list = requests,
        other => show(other),
    })?;
    if list.is_empty() || !interactive {
        show(Reply::Requests { requests: list });
        return Ok(());
    }
    eprintln!("# a name is the device's own claim: check the npub on its screen");
    let stdin = std::io::stdin();
    for r in list {
        eprint!("{}\ninvite? [y/N] ", request_line(&r));
        std::io::stderr().flush()?;
        let mut answer = String::new();
        if stdin.lock().read_line(&mut answer)? == 0 {
            break;
        }
        if matches!(answer.trim(), "y" | "Y" | "yes") {
            if let Err(e) = dev.call(&rt, Op::Invite { target: r.npub.clone() }, show) {
                eprintln!("# could not invite {}: {e}", r.npub);
            }
        }
    }
    Ok(())
}

/// The device a command runs on: the running process (through its
/// control channel) or one started here for the command.
enum Dev<'a> {
    Remote(&'a Path),
    Local(&'a Path, Ctx),
}

impl<'a> Dev<'a> {
    fn open(dir: &'a Path, d: &DeviceArgs, rt: &tokio::runtime::Runtime) -> Result<Self> {
        if rt.block_on(control::connect(dir)).is_some() {
            return Ok(Dev::Remote(dir));
        }
        if let Some(ctx) = start(dir, d, rt)? {
            return Ok(Dev::Local(dir, ctx));
        }
        // Another process holds the directory; it may still be starting.
        wait_for_holder(dir, rt)?;
        Ok(Dev::Remote(dir))
    }

    fn call(&self, rt: &tokio::runtime::Runtime, op: Op, mut show: impl FnMut(Reply)) -> Result<()> {
        match self {
            Dev::Remote(dir) => {
                let (conn, token) = rt
                    .block_on(control::connect(dir))
                    .ok_or_else(|| anyhow::anyhow!("the running noscat went away"))?;
                rt.block_on(control::ask(conn, token, op, show))
            }
            Dev::Local(_, ctx) => rt.block_on(async {
                let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
                let run = async move {
                    let res = control::exec(ctx, op, &tx, std::future::pending()).await;
                    drop(tx);
                    res
                };
                let drain = async {
                    while let Some(r) = rx.recv().await {
                        show(r);
                    }
                };
                let (res, ()) = tokio::join!(run, drain);
                res.map_err(|e| anyhow::anyhow!(e))
            }),
        }
    }
}

impl Drop for Dev<'_> {
    fn drop(&mut self) {
        if let Dev::Local(dir, _) = self {
            control::remove(dir);
        }
    }
}

/// Run `op` on this directory's device: through the running process if
/// there is one, else on a device started here for the command.
fn run_op(dir: &Path, d: &DeviceArgs, op: Op) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    if let Some((conn, token)) = rt.block_on(control::connect(dir)) {
        return rt.block_on(control::ask(conn, token, op, show));
    }
    // `mesh join` with a code naming a private mesh's relays: the device
    // started for it uses only those.
    let join_relays = match &op {
        Op::Join { inviter, .. } => noscat_client::parse_pairing_relays(inviter),
        _ => Vec::new(),
    };
    let Some(ctx) = start_device(dir, d, &rt, join_relays, false)? else {
        // Another process holds the directory; it may still be starting.
        let (conn, token) = wait_for_holder(dir, &rt)?;
        return rt.block_on(control::ask(conn, token, op, show));
    };
    let res = if let Op::Pipe { target } = &op {
        ctx.client.pipe_stdio(target).map_err(anyhow::Error::from)
    } else if let Op::Shell { target, cols, rows, term } = op {
        let code = rt.block_on(async {
            let stream = control::open_shell(&ctx, target, cols, rows, term, |r| show(r)).await.map_err(|e| anyhow::anyhow!(e))?;
            shell::run(stream).await
        });
        control::remove(dir);
        drop(ctx);
        std::process::exit(code?);
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

/// Print a pairing QR for `target` (an npub or a `noscat:` URI).
fn print_qr(target: &str) {
    if let Some(qr) = ui::render_pairing_qr(target) {
        eprintln!("{qr}");
    }
    eprintln!("# {target}");
}

/// Run a device in the foreground until Ctrl-C.
fn run_device(dir: &Path, d: &DeviceArgs, accept_joins: bool, setup: impl FnOnce(&Client) -> Result<()>) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    let ctx = start_service(dir, d, &rt)?;
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
    print_qr(&ctx.client.pairing_uri());
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
        Command::Id => {
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
            let ctx = start_service(&dir, d, &rt)?;
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
        Command::Shell { target } => {
            let (cols, rows, term) = shell::local_terminal();
            run_op(&dir, d, Op::Shell { target, cols, rows, term })?;
        }
        Command::Sessions { cmd } => run_op(&dir, d, Op::Sessions { end: cmd.map(|SessionsCommand::End { id }| id) })?,
        Command::Access { cmd } => match cmd {
            None => run_op(&dir, d, Op::Access)?,
            Some(AccessCommand::Reset { who }) => run_op(&dir, d, Op::ResetAccess { who })?,
        },
        Command::Allow { who, group, once } => {
            run_op(&dir, d, Op::SetAccess { who, group: group.name(), rule: "allow".into(), once })?;
        }
        Command::Deny { who, group, once } => {
            run_op(&dir, d, Op::SetAccess { who, group: group.name(), rule: "deny".into(), once })?;
        }
        Command::Ask { who, group } => {
            run_op(&dir, d, Op::SetAccess { who, group: group.name(), rule: "ask".into(), once: false })?;
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
                MeshCommand::Requests => return requests(&dir, d),
                MeshCommand::Qr => Op::Qr,
                MeshCommand::Relays { cmd } => match cmd {
                    None => Op::Relays { add: Vec::new(), remove: Vec::new() },
                    Some(RelaysCommand::Add { urls }) => Op::Relays { add: urls, remove: Vec::new() },
                    Some(RelaysCommand::Remove { urls }) => Op::Relays { add: Vec::new(), remove: urls },
                },
                MeshCommand::Stun { cmd } => match cmd {
                    None => Op::Stun { add: Vec::new(), remove: Vec::new() },
                    Some(StunCommand::Add { servers }) => Op::Stun { add: servers, remove: Vec::new() },
                    Some(StunCommand::Remove { servers }) => Op::Stun { add: Vec::new(), remove: servers },
                },
                MeshCommand::Private => Op::Private { private: true },
                MeshCommand::Shared => Op::Private { private: false },
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
