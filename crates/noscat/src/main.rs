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
    /// Start a tunnel server (not implemented yet).
    Serve,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    match cli.command {
        Command::Keygen { show_secret } => {
            let id = noscat_core::Identity::generate();
            println!("{}", id.npub());
            if show_secret {
                println!("nsec-hex: {}", id.secret_hex());
            }
        }
        Command::Serve => {
            let id = noscat_core::Identity::generate();
            eprintln!(
                "# 🐈 node identity: {} (tunnel not implemented yet — see research/00-synthesis.md)",
                id.npub()
            );
            std::process::exit(2);
        }
    }
    Ok(())
}
