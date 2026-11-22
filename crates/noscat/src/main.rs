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
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(noscat_core::relay::publish_advert(
                &id,
                parsed,
                ttl,
                &relays_or_default(relays),
            ))?;
            eprintln!("# done");
        }
        Command::Watch { relays } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(noscat_core::relay::watch_adverts(&relays_or_default(relays)))?;
        }
    }
    Ok(())
}
