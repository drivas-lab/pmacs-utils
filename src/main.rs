use clap::{Parser, Subcommand};
use tracing::{error, info, Level};
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
    /// Script mode for OpenConnect integration
    ///
    /// This command is called by OpenConnect with environment variables
    /// describing the VPN connection. Do not call this directly.
    ///
    /// Usage: sudo openconnect ... -s 'pmacs-vpn script'
    Script,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Set up logging
    // Script mode uses stderr to avoid interfering with OpenConnect
    let level = if cli.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };
    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(false)
        .with_writer(std::io::stderr)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    match cli.command {
        Commands::Connect { user } => {
            info!("Connecting to PMACS VPN...");
            if let Some(username) = user {
                info!("Using username: {}", username);
            }
            // TODO: Implement connection logic (spawn OpenConnect)
            println!("Connect command not yet implemented");
            println!("For now, use: sudo openconnect psomvpn.uphs.upenn.edu --protocol=gp -u USERNAME -s 'pmacs-vpn script'");
        }
        Commands::Disconnect => {
            info!("Disconnecting from PMACS VPN...");
            // TODO: Implement disconnect logic (kill OpenConnect, cleanup)
            println!("Disconnect command not yet implemented");
        }
        Commands::Status => {
            info!("Checking VPN status...");
            if pmacs_vpn::VpnState::is_active() {
                match pmacs_vpn::VpnState::load() {
                    Ok(Some(state)) => {
                        println!("VPN Status: Connected");
                        println!("  Tunnel: {}", state.tunnel_device);
                        println!("  Gateway: {}", state.gateway);
                        println!("  Routes: {}", state.routes.len());
                        for route in &state.routes {
                            println!("    {} -> {}", route.hostname, route.ip);
                        }
                        println!("  Hosts entries: {}", state.hosts_entries.len());
                    }
                    Ok(None) => println!("VPN Status: Not connected"),
                    Err(e) => println!("Error reading state: {}", e),
                }
            } else {
                println!("VPN Status: Not connected");
            }
        }
        Commands::Init => {
            info!("Generating default config...");
            let config = pmacs_vpn::Config::default();
            let path = std::path::PathBuf::from("pmacs-vpn.toml");
            config.save(&path)?;
            println!("Created default config: pmacs-vpn.toml");
        }
        Commands::Script => {
            // Script mode - called by OpenConnect
            match pmacs_vpn::handle_script_mode() {
                Ok(()) => {
                    info!("Script completed successfully");
                }
                Err(e) => {
                    error!("Script failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }

    Ok(())
}
