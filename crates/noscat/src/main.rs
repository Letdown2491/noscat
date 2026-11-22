use clap::{Parser, Subcommand};

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
    /// Generate a fresh ephemeral node identity.
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
        /// Reuse the same identity across runs by storing its secret in this file.
        #[arg(long)]
        identity: Option<std::path::PathBuf>,
    },
    /// Pipe stdio into a tunnel to a peer by npub.
    Pipe {
        /// The peer's npub.
        target: String,
        /// Relay URLs to search for the peer's advert (repeatable).
        #[arg(long = "relay")]
        relays: Vec<String>,
        /// Use this identity instead of a fresh ephemeral one (hex or nsec).
        #[arg(long)]
        identity: Option<String>,
    },
    /// Tailnet: a device's MLS group for owned-device meshing (spike).
    #[command(subcommand)]
    Tailnet(TailnetCommand),
}

#[derive(Subcommand)]
enum TailnetCommand {
    /// Create a tailnet owned by this device's directory.
    Create {
        /// Device directory holding the identity and MLS state.
        #[arg(long, default_value = "./noscat-device")]
        dir: std::path::PathBuf,
        /// Relay URLs (repeatable; defaults to the public set).
        #[arg(long = "relay")]
        relays: Vec<String>,
    },
    /// Publish this device's MLS key package so the owner can invite it.
    Publish {
        /// Device directory holding the identity and MLS state.
        #[arg(long, default_value = "./noscat-device")]
        dir: std::path::PathBuf,
        /// Relay URLs (repeatable; defaults to the public set).
        #[arg(long = "relay")]
        relays: Vec<String>,
    },
    /// Invite a device (by npub) into this device's tailnet.
    Invite {
        /// The device directory of *this* (owner) device.
        #[arg(long, default_value = "./noscat-device")]
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
        #[arg(long, default_value = "./noscat-device")]
        dir: std::path::PathBuf,
        /// Relay URLs (repeatable; defaults to the public set).
        #[arg(long = "relay")]
        relays: Vec<String>,
    },
    /// Print the tailnet's current epoch tunnel PSK (hex).
    Psk {
        /// Device directory holding the identity and MLS state.
        #[arg(long, default_value = "./noscat-device")]
        dir: std::path::PathBuf,
    },
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

    match cli.command {
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
        } => {
            let id = match &identity {
                Some(path) => {
                    let secret = std::fs::read_to_string(path)
                        .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;
                    let secret = secret.trim();
                    noscat_core::Identity::from_secret(secret).map_err(|e| {
                        anyhow::anyhow!("bad identity in {}: {e}", path.display())
                    })?
                }
                None => noscat_core::Identity::generate(),
            };
            let listen: std::net::SocketAddr = listen
                .parse()
                .map_err(|e| anyhow::anyhow!("bad --listen address: {e}"))?;
            let rt = tokio::runtime::Runtime::new()?;
            let who = rt.block_on(noscat_core::tunnel::serve(
                &id,
                listen,
                &relays_or_default(relays),
                ttl,
            ))?;
            eprintln!("# session with {who} closed");
        }
        Command::Pipe {
            target,
            relays,
            identity,
        } => {
            let id = match &identity {
                Some(secret) => noscat_core::Identity::from_secret(secret)
                    .map_err(|e| anyhow::anyhow!("bad --identity: {e}"))?,
                None => noscat_core::Identity::generate(),
            };
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(noscat_core::tunnel::pipe(
                &id,
                &target,
                &relays_or_default(relays),
            ))?;
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
                TailnetCommand::Publish { dir, relays } => {
                    let device = noscat_core::tailnet::Device::open(&dir)?;
                    rt.block_on(device.publish_key_package(&relays_or_default(relays)))?;
                    eprintln!("# 📢 key package published as {}", device.identity.npub());
                }
                TailnetCommand::Invite { dir, device: npub, relays } => {
                    let mut device = noscat_core::tailnet::Device::open(&dir)?;
                    let invitee = nostr::prelude::PublicKey::parse(&npub)
                        .map_err(|e| anyhow::anyhow!("bad npub: {e}"))?;
                    rt.block_on(device.invite(invitee, &relays_or_default(relays)))?;
                    eprintln!("# ✅ invited {npub} into the tailnet");
                }
                TailnetCommand::Join { dir, relays } => {
                    let mut device = noscat_core::tailnet::Device::open(&dir)?;
                    rt.block_on(device.join_tailnet(&relays_or_default(relays)))?;
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
