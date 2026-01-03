use clap::{Parser, Subcommand};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

#[derive(Parser)]
#[command(name = "pmacs-vpn")]
#[command(about = "Split-tunnel VPN toolkit for PMACS cluster access")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Connect to PMACS VPN with split-tunneling
    Connect {
        /// Username for VPN authentication
        #[arg(short, long)]
        user: Option<String>,
    },
    /// Disconnect from VPN and clean up routes
    Disconnect,
    /// Show current VPN status
    Status,
    /// Generate default config file
    Init,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Set up logging
    let level = if cli.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };
    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    match cli.command {
        Commands::Connect { user } => {
            info!("Connecting to PMACS VPN...");
            if let Some(username) = user {
                info!("Using username: {}", username);
            }
            // TODO: Implement connection logic
            println!("Connect command not yet implemented");
        }
        Commands::Disconnect => {
            info!("Disconnecting from PMACS VPN...");
            // TODO: Implement disconnect logic
            println!("Disconnect command not yet implemented");
        }
        Commands::Status => {
            info!("Checking VPN status...");
            // TODO: Implement status check
            println!("Status command not yet implemented");
        }
        Commands::Init => {
            info!("Generating default config...");
            let config = pmacs_vpn::Config::default();
            let path = std::path::PathBuf::from("pmacs-vpn.toml");
            config.save(&path)?;
            println!("Created default config: pmacs-vpn.toml");
        }
    }

    Ok(())
}
