use clap::{Parser, Subcommand};
use pmacs_vpn::gp;
use pmacs_vpn::vpn::routing::VpnRouter;
use pmacs_vpn::vpn::hosts::HostsManager;
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
            match connect_vpn(user).await {
                Ok(()) => info!("VPN connection closed"),
                Err(e) => {
                    error!("VPN connection failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Disconnect => {
            info!("Disconnecting from PMACS VPN...");
            match disconnect_vpn().await {
                Ok(()) => println!("Disconnected successfully"),
                Err(e) => {
                    error!("Disconnect failed: {}", e);
                    std::process::exit(1);
                }
            }
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

/// Connect to VPN using native GlobalProtect implementation
async fn connect_vpn(user: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Load config
    let config_path = std::path::PathBuf::from("pmacs-vpn.toml");
    let config = if config_path.exists() {
        pmacs_vpn::Config::load(&config_path)?
    } else {
        info!("No config file found, using defaults");
        pmacs_vpn::Config::default()
    };

    // 2. Get username (from arg or prompt)
    let username = user.unwrap_or_else(|| {
        print!("Username: ");
        use std::io::Write;
        std::io::stdout().flush().unwrap();
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        input.trim().to_string()
    });

    // 3. Prompt for password
    let password = rpassword::prompt_password("Password: ")?;

    // 4. Auth flow
    println!("Authenticating...");
    let prelogin = gp::auth::prelogin(&config.vpn.gateway).await?;
    info!("Auth method: {:?}", prelogin.auth_method);

    println!("Logging in (check phone for DUO push if prompted)...");
    let login = gp::auth::login(&config.vpn.gateway, &username, &password, Some("push")).await?;
    info!("Login successful: {}", login.username);

    println!("Getting tunnel configuration...");
    let tunnel_config = gp::auth::getconfig(&config.vpn.gateway, &login, None).await?;
    info!(
        "Tunnel config: IP={} MTU={}",
        tunnel_config.internal_ip, tunnel_config.mtu
    );

    // 5. Create tunnel
    println!("Establishing tunnel...");
    let mut tunnel = gp::tunnel::SslTunnel::connect(
        &config.vpn.gateway,
        &login.username,
        &login.auth_cookie,
        &tunnel_config,
    )
    .await?;

    // 6. Add routes for configured hosts
    println!("Adding routes...");
    let gateway_ip = tunnel_config.internal_ip.to_string();
    let router = VpnRouter::new(gateway_ip)?;

    let mut state = pmacs_vpn::VpnState::new(
        tunnel.tun_name().to_string(),
        tunnel_config.internal_ip,
    );

    let mut hosts_map = std::collections::HashMap::new();
    for host in &config.hosts {
        match router.add_host_route(host) {
            Ok(ip) => {
                state.add_route(host.clone(), ip);
                state.add_hosts_entry(host.clone(), ip);
                hosts_map.insert(host.clone(), ip);
                println!("  Added route for {} -> {}", host, ip);
            }
            Err(e) => {
                error!("Failed to add route for {}: {}", host, e);
            }
        }
    }

    // 7. Update hosts file
    let hosts_mgr = HostsManager::new();
    hosts_mgr.add_entries(&hosts_map)?;

    // 8. Save state for cleanup
    state.save()?;

    // 9. Run tunnel with signal handling
    println!("Connected! Press Ctrl+C to disconnect.");
    println!("TUN device: {}", tunnel.tun_name());
    println!("Internal IP: {}", tunnel_config.internal_ip);

    let result = tokio::select! {
        result = tunnel.run() => {
            result.map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
        }
        _ = tokio::signal::ctrl_c() => {
            println!("\nDisconnecting...");
            Ok(())
        }
    };

    // 10. Cleanup
    cleanup_vpn(&state).await?;

    result
}

/// Disconnect from VPN and clean up
async fn disconnect_vpn() -> Result<(), Box<dyn std::error::Error>> {
    if let Some(state) = pmacs_vpn::VpnState::load()? {
        cleanup_vpn(&state).await?;
        println!("Disconnected successfully");
    } else {
        println!("VPN is not connected");
    }
    Ok(())
}

/// Clean up routes, hosts, and state
async fn cleanup_vpn(state: &pmacs_vpn::VpnState) -> Result<(), Box<dyn std::error::Error>> {
    info!("Cleaning up VPN state...");

    // Remove hosts entries
    let hosts_mgr = HostsManager::new();
    if let Err(e) = hosts_mgr.remove_entries() {
        error!("Failed to remove hosts entries: {}", e);
    }

    // Remove routes
    let router = VpnRouter::new(state.gateway.to_string())?;
    for route in &state.routes {
        if let Err(e) = router.remove_host_route(&route.hostname) {
            error!("Failed to remove route for {}: {}", route.hostname, e);
        }
    }

    // Delete state file
    pmacs_vpn::VpnState::delete()?;

    Ok(())
}
