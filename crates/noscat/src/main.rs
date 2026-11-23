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
        #[arg(long, default_value_t = 3600)]
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
        /// UDP address to listen on, e.g. `0.0.0.0:41641`.
        #[arg(long, default_value = "0.0.0.0:41641")]
        listen: String,
        /// Relay URLs to advertise on (repeatable; defaults to the public set).
        #[arg(long = "relay")]
        relays: Vec<String>,
        /// Advert lifetime in seconds.
        #[arg(long, default_value_t = 3600)]
        ttl: u64,
        /// Identity file override (default: ~/.noscat/identity.hex).
        #[arg(long)]
        identity: Option<std::path::PathBuf>,
        /// Restrict the tunnel to this tailnet's device directory (MLS group
        /// membership becomes the authorization) [default: ~/.noscat/device].
        #[arg(long, num_args = 0..=1, default_missing_value = "")]
        tailnet: Option<String>,
    },
    /// Pipe stdio into a tunnel to a peer by npub.
    Pipe {
        /// The peer's npub.
        target: String,
        /// Relay URLs to search for the peer's advert (repeatable).
        #[arg(long = "relay")]
        relays: Vec<String>,
        /// Identity override (hex or nsec; default: ~/.noscat/identity.hex).
        #[arg(long)]
        identity: Option<String>,
        /// Restrict the tunnel to this tailnet's device directory (MLS group
        /// membership becomes the authorization) [default: ~/.noscat/device].
        #[arg(long, num_args = 0..=1, default_missing_value = "")]
        tailnet: Option<String>,
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
        /// Identity override (hex or nsec; default: ~/.noscat/identity.hex).
        #[arg(long)]
        identity: Option<String>,
        /// Restrict the tunnel to this tailnet's device directory
        /// [default: ~/.noscat/device].
        #[arg(long, num_args = 0..=1, default_missing_value = "")]
        tailnet: Option<String>,
    },
    /// Receive one file over a tunnel, into --out (default: cwd).
    Receive {
        /// Directory to write the incoming file into.
        #[arg(long, default_value = ".")]
        out: std::path::PathBuf,
        /// UDP address to listen on.
        #[arg(long, default_value = "0.0.0.0:41641")]
        listen: String,
        /// Relay URLs (repeatable; defaults to the public set).
        #[arg(long = "relay")]
        relays: Vec<String>,
        /// Identity file override (default: ~/.noscat/identity.hex).
        #[arg(long)]
        identity: Option<std::path::PathBuf>,
        /// Restrict the tunnel to this tailnet's device directory
        /// [default: ~/.noscat/device].
        #[arg(long, num_args = 0..=1, default_missing_value = "")]
        tailnet: Option<String>,
        /// Advert lifetime in seconds.
        #[arg(long, default_value_t = 3600)]
        ttl: u64,
    },
    /// Expose a local TCP service to tailnet peers over tunnels.
    /// Run the persistent tailnet node: advertise, accept any number of
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
        /// UDP address to listen on [default: 0.0.0.0:41641]
        #[arg(long, default_value = "0.0.0.0:41641")]
        listen: String,
        /// Relay URLs (repeatable; defaults to the public set)
        #[arg(long)]
        relays: Vec<String>,
        /// Identity file override (default: ~/.noscat/identity.hex).
        #[arg(long)]
        identity: Option<std::path::PathBuf>,
        /// Tailnet device directory - REQUIRED: membership authorizes inbound
        /// [default: ~/.noscat/device].
        #[arg(long, num_args = 0..=1, default_missing_value = "")]
        tailnet: Option<String>,
        /// Advert lifetime in seconds [default: 3600]
        #[arg(long, default_value = "3600")]
        ttl: u64,
    },
    Expose {
        /// The local service to expose, e.g. `127.0.0.1:8000`.
        #[arg(long)]
        to: String,
        /// UDP address to listen on.
        #[arg(long, default_value = "0.0.0.0:41641")]
        listen: String,
        /// Relay URLs (repeatable; defaults to the public set).
        #[arg(long = "relay")]
        relays: Vec<String>,
        /// Identity file override (default: ~/.noscat/identity.hex).
        #[arg(long)]
        identity: Option<std::path::PathBuf>,
        /// Restrict the tunnels to this tailnet's device directory
        /// [default: ~/.noscat/device].
        #[arg(long, num_args = 0..=1, default_missing_value = "")]
        tailnet: Option<String>,
        /// Advert lifetime in seconds.
        #[arg(long, default_value_t = 3600)]
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
        /// Identity override (hex or nsec; default: ~/.noscat/identity.hex).
        #[arg(long)]
        identity: Option<String>,
        /// Restrict the tunnels to this tailnet's device directory
        /// [default: ~/.noscat/device].
        #[arg(long, num_args = 0..=1, default_missing_value = "")]
        tailnet: Option<String>,
    },
    /// Tailnet: a device's MLS group for owned-device meshing (spike).
    #[command(subcommand)]
    Tailnet(TailnetCommand),
    /// Emit shell completions (hidden; used by packaging).
    #[command(hide = true)]
    Completions {
        /// The shell to generate completions for.
        shell: Shell,
    },
}

#[derive(Subcommand)]
enum TailnetCommand {
    /// Create a tailnet owned by this device's directory.
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
        /// The tailnet owner's npub: the request is addressed to them alone.
        #[arg(long)]
        owner: Option<String>,
        /// Relay URLs (repeatable; defaults to the public set).
        #[arg(long = "relay")]
        relays: Vec<String>,
    },
    /// Invite a device (by npub) into this device's tailnet.
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
    /// Wait for a gift-wrapped invitation and join the tailnet.
    Join {
        /// Device directory holding the identity and MLS state.
        #[arg(long, default_value_os_t = default_device_dir())]
        dir: std::path::PathBuf,
        /// The tailnet owner's npub: invitations from anyone else are ignored.
        #[arg(long)]
        owner: Option<String>,
        /// Relay URLs (repeatable; defaults to the public set).
        #[arg(long = "relay")]
        relays: Vec<String>,
    },
    /// List the tailnet's members and epoch.
    Members {
        /// Device directory holding the identity and MLS state.
        #[arg(long, default_value_os_t = default_device_dir())]
        dir: std::path::PathBuf,
    },
    /// Remove a device (by npub) from this tailnet (owner only).
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
    /// Merge pending tailnet commits addressed to this device (run after an
    /// owner invited or removed someone).
    Sync {
        /// Device directory holding the identity and MLS state.
        #[arg(long, default_value_os_t = default_device_dir())]
        dir: std::path::PathBuf,
        /// How long to listen for commits (seconds).
        #[arg(long, default_value_t = 10)]
        for_secs: u64,
        /// Relay URLs (repeatable; defaults to the public set).
        #[arg(long = "relay")]
        relays: Vec<String>,
    },
    /// Print the tailnet's current epoch tunnel PSK (hex).
    Psk {
        /// Device directory holding the identity and MLS state.
        #[arg(long, default_value_os_t = default_device_dir())]
        dir: std::path::PathBuf,
    },
}

// The default tailnet device directory, next to the shared identity.
// `--tailnet` with no value (empty path) also resolves to this.
fn default_device_dir() -> std::path::PathBuf {
    // unix shells set HOME; Windows-native environments set USERPROFILE.
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(|h| std::path::PathBuf::from(h).join(".noscat").join("device"))
        .unwrap_or_else(|_| std::path::PathBuf::from(".noscat").join("device"))
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
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

    // The default tailnet device directory, next to the shared identity.
    // `--tailnet` with no value (empty path) also resolves to this.
    fn default_device_dir() -> std::path::PathBuf {
        // unix shells set HOME; Windows-native environments set USERPROFILE.
        std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .map(|h| std::path::PathBuf::from(h).join(".noscat").join("device"))
            .unwrap_or_else(|_| std::path::PathBuf::from(".noscat").join("device"))
    }

    // The tailnet's epoch PSK, if the operator scoped the tunnel to a group.
    fn tailnet_psk(dir: &std::path::Path) -> anyhow::Result<[u8; 32]> {
        let device = noscat_core::tailnet::Device::open(dir)?;
        let psk = device.tunnel_psk().map_err(|e| anyhow::anyhow!("{e}"))?;
        let psk: [u8; 32] = psk
            .try_into()
            .map_err(|_| anyhow::anyhow!("unexpected PSK length"))?;
        eprintln!("# 🔐 tunnel bound to tailnet (epoch PSK loaded from {})", dir.display());
        Ok(psk)
    }

    // Build the shared client for the data-plane commands: identity, relays,
    // tailnet scope, and listen address are resolved once, up front.
    fn make_client(
        identity: IdentitySource,
        relays: Vec<String>,
        tailnet: Option<String>,
        listen: Option<std::net::SocketAddr>,
        ttl: u64,
        name: Option<String>,
    ) -> anyhow::Result<(Client, std::sync::mpsc::Receiver<Event>)> {
        // `--tailnet` with no value is an empty string: the default device dir.
        let tailnet = tailnet.map(|d| if d.is_empty() { default_device_dir() } else { std::path::PathBuf::from(d) });
        if let Some(dir) = &tailnet {
            tailnet_psk(dir)?;
        }
        let mut client = Client::start(ClientConfig {
            identity,
            relays: Some(relays_or_default(relays)),
            listen,
            tailnet_dir: tailnet,
            device_name: name,
            advert_ttl_secs: ttl,
        })
        .map_err(|e| anyhow::anyhow!("{e}"))?;
        let rx = client.events().expect("fresh client");
        Ok((client, rx))
    }

    // Resolve a --tailnet value (empty string = default device directory).
    fn tailnet_dir_path(value: &str) -> std::path::PathBuf {
        if value.is_empty() {
            default_device_dir()
        } else {
            std::path::PathBuf::from(value)
        }
    }

    // Watch the relays for devices publishing key packages (asking to join
    // this tailnet) and invite them once the operator confirms. Runs on its
    // own thread + runtime for the life of the `up` process; every failure
    // is non-fatal (the node keeps serving regardless).
    fn spawn_pairing_watcher(device_dir: std::path::PathBuf, relays: Vec<String>) {
        std::thread::Builder::new()
            .name("tailnet-pairing".into())
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

        // Only the tailnet owner answers join requests; a member device's
        // `up` just serves its tunnels.
        let (members, own_npub) = match noscat_core::tailnet::Device::open(&device_dir) {
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
            eprintln!("# this device is not the tailnet owner; join requests are answered by the owner device");
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
        eprintln!("# 🤝 watching for devices asking to join this tailnet");

        while let Some(author) = rx.recv().await {
            // Refresh membership per request: earlier confirmations added
            // members, and the author may already be one of them.
            let members =
                match noscat_core::tailnet::Device::open(&device_dir).and_then(|d| d.list_members())
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

            eprintln!("# 🤝 device {author} wants to join this tailnet");
            let npub = match author.to_bech32() {
                Ok(npub) => npub,
                Err(_) => continue,
            };
            if !confirm(&npub) {
                eprintln!("# declined {npub}");
                continue;
            }

            let mut device = match noscat_core::tailnet::Device::open(&device_dir) {
                Ok(device) => device,
                Err(e) => {
                    eprintln!("# pairing: cannot open device dir: {e}");
                    continue;
                }
            };
            match device.invite(author, &relays).await {
                Ok(()) => eprintln!("# ✅ invited {npub} into the tailnet"),
                Err(e) => eprintln!("# pairing: invite failed: {e}"),
            }
        }
    }

    // Ask on stderr, read the answer from stdin. EOF or anything but y/yes
    // declines: a backgrounded `up` (no tty) never lets anyone in.
    fn confirm(npub: &str) -> bool {
        use std::io::Write;
        eprint!("# accept {npub} into this tailnet? [y/N] ");
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_err() {
            return false;
        }
        matches!(line.trim(), "y" | "Y" | "yes" | "Yes")
    }

    // Narrate one client event on stderr - the same shape the core's
    // run-to-completion operations used to print.
    fn print_event(ev: Event) {
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
                println!("# 💬 {}...: {}", &peer[..peer.len().min(16)], text);
                println!("#    reply: 'to {}' then type", &peer[..peer.len().min(16)]);
            }
            Event::ChatFailed { peer, error } => {
                eprintln!("# ⚠️  message to {}... not delivered: {error}", &peer[..peer.len().min(16)])
            }
            Event::TransferFailed { error, .. } => {
                eprintln!("# ⚠️  transfer failed: {error}")
            }
        }
    }

    /// Reply to tailnet chats from the `up` terminal: `to <npub prefix>`
    /// picks the peer, every other non-empty line goes to them as a chat
    /// message. Incoming messages print via the event printer.
    fn spawn_chat_repl(client: Client, device_dir: std::path::PathBuf) {
        std::thread::spawn(move || {
            let mut target: Option<String> = None;
            eprintln!("# 💬 chat ready: 'to <npub prefix>' picks a peer, then type lines to send");
            for line in std::io::stdin().lines().map_while(Result::ok) {
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }
                if let Some(prefix) = line.strip_prefix("to ").map(str::trim) {
                    match resolve_member_prefix(&device_dir, prefix) {
                        Ok(npub) => {
                            eprintln!("# 💬 chatting with {}...", &npub[..16]);
                            target = Some(npub);
                        }
                        Err(e) => eprintln!("# ⚠️  {e}"),
                    }
                    continue;
                }
                match &target {
                    Some(npub) => client.send_chat(npub, &line),
                    None => eprintln!("# 💬 no peer selected: 'to <npub prefix>' first"),
                }
            }
        });
    }

    /// Resolve a (possibly partial) npub against the tailnet roster: exact
    /// npub, unique prefix, or `owner` for the owner device.
    fn resolve_member_prefix(
        device_dir: &std::path::PathBuf,
        prefix: &str,
    ) -> anyhow::Result<String> {
        use anyhow::bail;
        let device = noscat_core::tailnet::Device::open(device_dir)?;
        let members = device.list_members()?;
        if prefix.eq_ignore_ascii_case("owner") {
            return members
                .into_iter()
                .find(|m| m.is_owner)
                .map(|m| m.npub)
                .ok_or_else(|| anyhow::anyhow!("this device is not the tailnet owner"));
        }
        let hits: Vec<String> = members
            .into_iter()
            .map(|m| m.npub)
            .filter(|n| n.starts_with(prefix))
            .collect();
        match hits.len() {
            1 => Ok(hits[0].clone()),
            0 => bail!("no member matches '{prefix}'"),
            _ => bail!("'{prefix}' is ambiguous ({} matches)", hits.len()),
        }
    }

    // Print events in the background while the main thread runs a blocking
    // session (serve/pipe bridge stdio and cannot drain themselves).
    fn spawn_printer(rx: std::sync::mpsc::Receiver<Event>) {        std::thread::spawn(move || {
            for ev in rx {
                print_event(ev);
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
            tailnet,
        } => {
            let identity = identity
                .map(IdentitySource::File)
                .or_else(default_identity)
                .unwrap_or(IdentitySource::Ephemeral);
            let listen: std::net::SocketAddr = listen
                .parse()
                .map_err(|e| anyhow::anyhow!("bad --listen address: {e}"))?;
            let (client, rx) = make_client(identity, relays, tailnet, Some(listen), ttl, None)?;
            spawn_printer(rx);
            client.serve_stdio()?;
        }
        Command::Pipe {
            target,
            relays,
            identity,
            tailnet,
        } => {
            let identity = match identity {
                Some(secret) => IdentitySource::Secret(secret),
                None => default_identity().unwrap_or(IdentitySource::Ephemeral),
            };
            let (client, rx) = make_client(identity, relays, tailnet, None, 3600, None)?;
            spawn_printer(rx);
            client.pipe_stdio(&target)?;
        }
        Command::Send { path, target, relays, identity, tailnet } => {
            let identity = match identity {
                Some(secret) => IdentitySource::Secret(secret),
                None => default_identity().unwrap_or(IdentitySource::Ephemeral),
            };
            let (client, rx) = make_client(identity, relays, tailnet, None, 3600, None)?;
            client.send_file(path, &target);
            // wait for the transfer's terminal event
            for ev in rx {
                match &ev {
                    Event::TransferDone { .. } => break,
                    Event::TransferFailed { error, .. } => {
                        anyhow::bail!("transfer failed: {error}")
                    }
                    _ => {}
                }
                print_event(ev);
            }
        }
        Command::Receive { out, listen, relays, identity, tailnet, ttl } => {
            let identity = identity
                .map(IdentitySource::File)
                .or_else(default_identity)
                .unwrap_or(IdentitySource::Ephemeral);
            let listen: std::net::SocketAddr = listen
                .parse()
                .map_err(|e| anyhow::anyhow!("bad --listen address: {e}"))?;
            let (client, rx) = make_client(identity, relays, tailnet, Some(listen), ttl, None)?;
            // Report readiness up front: receive_file blocks on the sender's
            // handshake, and without this the user stares at silence.
            print_event(Event::Listening { npub: client.npub().to_string(), addr: listen });
            client.receive_file(out);
            for ev in rx {
                match &ev {
                    Event::TransferDone { .. } => break,
                    Event::TransferFailed { error, .. } => {
                        anyhow::bail!("transfer failed: {error}")
                    }
                    _ => {}
                }
                print_event(ev);
            }
        }
        Command::Up { out, to, listen, relays, identity, tailnet, ttl, name } => {
            // Authorization comes from tailnet membership; without it any npub
            // that scans the QR could push files to this machine.
            let Some(tailnet) = tailnet else {
                anyhow::bail!("up requires --tailnet: tailnet membership authorizes inbound connections (create one with `noscat tailnet create`)");
            };
            let device_dir = tailnet_dir_path(&tailnet);
            // In tailnet mode this node IS its tailnet device: one identity
            // for the pairing QR, the invitations, and the tunnels. (The
            // phone does the same once it has joined.)
            let device = noscat_core::tailnet::Device::open(&device_dir)?;
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
            // Pairing: when this device owns the tailnet, it watches the
            // relays for devices asking to join (their published key
            // packages) and invites them on confirmation.
            let (client, rx) = make_client(identity, relays.clone(), Some(tailnet), Some(listen), ttl, Some(device_name))?;
            spawn_printer(rx);
            spawn_pairing_watcher(device_dir.clone(), relays_or_default(relays));
            client.up(out_dir, to)?;
            spawn_chat_repl(client.clone(), device_dir);
            // The node runs on the client's background tasks; park forever
            // (park can return spuriously, so loop) until Ctrl-C.
            loop {
                std::thread::park();
            }
        }
        Command::Expose { to, listen, relays, identity, tailnet, ttl } => {
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
            let (client, rx) = make_client(identity, relays, tailnet, Some(listen), ttl, None)?;
            client.expose(to)?;
            eprintln!("# 🔗 exposing tcp/{to} over tunnels");
            for ev in rx {
                match &ev {
                    Event::Stopped { error: Some(e), .. } => anyhow::bail!("{e}"),
                    _ => {}
                }
                print_event(ev);
            }
        }
        Command::Forward { target, port, bind, relays, identity, tailnet } => {
            let identity = match identity {
                Some(secret) => IdentitySource::Secret(secret),
                None => default_identity().unwrap_or(IdentitySource::Ephemeral),
            };
            let local = std::net::SocketAddr::new(bind, port);
            let (client, rx) = make_client(identity, relays, tailnet, None, 3600, None)?;
            client.forward(&target, local)?;
            eprintln!("# 🐈 forwarding tcp/{local} over tunnels to {target}");
            for ev in rx {
                match &ev {
                    Event::Stopped { error: Some(e), .. } => anyhow::bail!("{e}"),
                    _ => {}
                }
                print_event(ev);
            }
        }
        Command::Tailnet(cmd) => {
            let rt = tokio::runtime::Runtime::new()?;
            match cmd {
                TailnetCommand::Create { dir, relays: _ } => {
                    let mut device = noscat_core::tailnet::Device::open(&dir)?;
                    device.create_tailnet()?;
                    eprintln!(
                        "# ✅ tailnet created; owner is {} (dir: {})",
                        device.identity.npub(),
                        dir.display()
                    );
                }
                TailnetCommand::Publish { dir, owner, relays } => {
                    let device = noscat_core::tailnet::Device::open(&dir)?;
                    let target = match &owner {
                        Some(npub) => Some(nostr::prelude::PublicKey::parse(npub)
                            .map_err(|e| anyhow::anyhow!("bad npub: {e}"))?),
                        None => None,
                    };
                    rt.block_on(device.publish_key_package(&relays_or_default(relays), target))?;
                    eprintln!("# 📢 key package published as {}", device.identity.npub());
                }
                TailnetCommand::Invite { dir, device: npub, relays } => {
                    let mut device = noscat_core::tailnet::Device::open(&dir)?;
                    let invitee = nostr::prelude::PublicKey::parse(&npub)
                        .map_err(|e| anyhow::anyhow!("bad npub: {e}"))?;
                    rt.block_on(device.invite(invitee, &relays_or_default(relays)))?;
                    eprintln!("# ✅ invited {npub} into the tailnet");
                }
                TailnetCommand::Join { dir, owner, relays } => {
                    let mut device = noscat_core::tailnet::Device::open(&dir)?;
                    let expected = match &owner {
                        Some(npub) => Some(nostr::prelude::PublicKey::parse(npub)
                            .map_err(|e| anyhow::anyhow!("bad npub: {e}"))?),
                        None => None,
                    };
                    rt.block_on(device.join_tailnet(&relays_or_default(relays), expected))?;
                }
                TailnetCommand::Members { dir } => {
                    let device = noscat_core::tailnet::Device::open(&dir)?;
                    for m in device.list_members()? {
                        println!(
                            "{} epoch={} {}",
                            if m.is_owner { "owner " } else { "member" },
                            m.epoch,
                            m.npub
                        );
                    }
                }
                TailnetCommand::Remove { dir, device: npub, relays } => {
                    let mut device = noscat_core::tailnet::Device::open(&dir)?;
                    let removed = nostr::prelude::PublicKey::parse(&npub)
                        .map_err(|e| anyhow::anyhow!("bad npub: {e}"))?;
                    rt.block_on(device.remove_member(removed, &relays_or_default(relays)))?;
                    eprintln!("# ✅ removed {npub} from the tailnet (epoch ratcheted)");
                }
                TailnetCommand::Sync { dir, for_secs, relays } => {
                    let mut device = noscat_core::tailnet::Device::open(&dir)?;
                    let merged = rt.block_on(device.sync_tailnet(
                        &relays_or_default(relays),
                        std::time::Duration::from_secs(for_secs),
                    ))?;
                    eprintln!("# ✅ synced: {merged} commit(s) merged");
                }
                TailnetCommand::Psk { dir } => {
                    let device = noscat_core::tailnet::Device::open(&dir)?;
                    println!("{}", hex::encode(device.tunnel_psk()?));
                }
            }
        }
    }
    Ok(())
}
