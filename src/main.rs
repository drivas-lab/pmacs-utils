use clap::{Parser, Subcommand};
use pmacs_vpn::gp;
use pmacs_vpn::vpn::routing::VpnRouter;
use pmacs_vpn::vpn::hosts::HostsManager;
use tracing::{error, info, warn, Level};
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

        /// Store password in system keychain after successful login
        #[arg(long)]
        save_password: bool,

        /// Delete stored password before prompting
        #[arg(long)]
        forget_password: bool,

        /// Use aggressive keepalive to prevent idle timeout (10s instead of 30s)
        #[arg(long)]
        keep_alive: bool,

        /// Run VPN in background (daemon mode)
        #[arg(long)]
        daemon: bool,

        /// Internal: PID passed from daemon parent (do not use directly)
        #[arg(long, hide = true)]
        _daemon_pid: Option<u32>,
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
    /// Delete stored password for a user
    ForgetPassword {
        /// Username whose password should be deleted
        #[arg(short, long)]
        user: String,
    },
    /// Run with system tray (GUI mode)
    Tray,
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
        Commands::Connect { user, save_password, forget_password, keep_alive, daemon, _daemon_pid } => {
            // Daemon mode: spawn detached child process
            if daemon {
                match spawn_daemon(&user, save_password, forget_password, keep_alive) {
                    Ok(pid) => {
                        println!("VPN daemon started (PID: {})", pid);
                        println!("Use 'pmacs-vpn status' to check connection");
                        println!("Use 'pmacs-vpn disconnect' to stop");
                    }
                    Err(e) => {
                        error!("Failed to start daemon: {}", e);
                        std::process::exit(1);
                    }
                }
            } else {
                // If _daemon_pid is set, we're running as a background daemon
                let is_daemon = _daemon_pid.is_some();
                info!("Connecting to PMACS VPN...");
                match connect_vpn(user, save_password, forget_password, keep_alive, is_daemon).await {
                    Ok(()) => info!("VPN connection closed"),
                    Err(e) => {
                        error!("VPN connection failed: {}", e);
                        std::process::exit(1);
                    }
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
                        // Check if daemon is still running
                        let daemon_status = if let Some(pid) = state.pid {
                            if state.is_daemon_running() {
                                format!("Running (PID: {})", pid)
                            } else {
                                format!("Stopped (stale PID: {})", pid)
                            }
                        } else {
                            "Foreground".to_string()
                        };

                        println!("VPN Status: Connected");
                        println!("  Mode: {}", daemon_status);
                        println!("  Tunnel: {}", state.tunnel_device);
                        println!("  Gateway: {}", state.gateway);
                        println!("  Connected: {}", state.connected_at);
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
        Commands::ForgetPassword { user } => {
            match pmacs_vpn::delete_password(&user) {
                Ok(()) => println!("Password deleted for user: {}", user),
                Err(e) => {
                    error!("Failed to delete password: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Tray => {
            info!("Starting system tray mode...");
            run_tray_mode().await;
        }
    }

    Ok(())
}

/// Run the VPN with system tray GUI
async fn run_tray_mode() {
    use pmacs_vpn::tray::{TrayApp, TrayCommand, VpnStatus};

    // Create tray app and get channels
    let (app, command_rx, status_tx) = TrayApp::new();

    // Load config for VPN operations (for future use)
    let config_path = std::path::PathBuf::from("pmacs-vpn.toml");
    let _config = if config_path.exists() {
        pmacs_vpn::Config::load(&config_path).ok()
    } else {
        None
    };

    // Clone for the command handler
    let status_tx_clone = status_tx.clone();

    // Spawn command handler on tokio runtime
    let handle = tokio::spawn(async move {
        while let Ok(cmd) = command_rx.recv() {
            match cmd {
                TrayCommand::Connect => {
                    info!("Tray: Received connect command");
                    let _ = status_tx_clone.send(VpnStatus::Connecting);

                    // For now, spawn the VPN as a daemon process
                    // A more integrated solution would run the VPN directly
                    let spawn_result = spawn_daemon(&None, false, false, false);
                    let pid_opt = spawn_result.ok();

                    if let Some(pid) = pid_opt {
                        info!("VPN daemon started with PID {}", pid);
                        // Wait a bit for connection to establish
                        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

                        // Check if connected
                        if let Ok(Some(state)) = pmacs_vpn::VpnState::load() {
                            let _ = status_tx_clone.send(VpnStatus::Connected {
                                ip: state.gateway.to_string(),
                            });
                        }
                    } else {
                        error!("Failed to start VPN daemon");
                        let _ = status_tx_clone.send(VpnStatus::Error("Failed to spawn daemon".to_string()));
                    }
                }
                TrayCommand::Disconnect => {
                    info!("Tray: Received disconnect command");
                    let _ = status_tx_clone.send(VpnStatus::Disconnecting);

                    // Kill daemon and cleanup
                    if let Ok(Some(state)) = pmacs_vpn::VpnState::load() {
                        if state.pid.is_some() && state.is_daemon_running() {
                            let _ = state.kill_daemon();
                        }
                    }

                    // Cleanup routes and hosts
                    match disconnect_vpn().await {
                        Ok(()) => {
                            let _ = status_tx_clone.send(VpnStatus::Disconnected);
                        }
                        Err(e) => {
                            error!("Disconnect error: {}", e);
                            let _ = status_tx_clone.send(VpnStatus::Error(e.to_string()));
                        }
                    }
                }
                TrayCommand::ShowStatus => {
                    info!("Tray: Show status requested");
                    // Future: Show a status window
                }
                TrayCommand::Exit => {
                    info!("Tray: Exit requested");
                    // Cleanup if connected
                    if let Ok(Some(state)) = pmacs_vpn::VpnState::load() {
                        if state.pid.is_some() && state.is_daemon_running() {
                            let _ = state.kill_daemon();
                        }
                        let _ = disconnect_vpn().await;
                    }
                    break;
                }
            }
        }
    });

    // Check initial VPN state
    if let Ok(Some(state)) = pmacs_vpn::VpnState::load() {
        if state.is_daemon_running() {
            let _ = status_tx.send(VpnStatus::Connected {
                ip: state.gateway.to_string(),
            });
        }
    }

    // Run tray (this blocks until exit)
    // Note: This will run on the current thread, not tokio
    std::thread::spawn(move || {
        app.run();
    });

    // Wait for the command handler to finish
    let _ = handle.await;
}

/// Spawn VPN as a detached background process (daemon mode)
fn spawn_daemon(
    user: &Option<String>,
    save_password: bool,
    forget_password: bool,
    keep_alive: bool,
) -> Result<u32, Box<dyn std::error::Error>> {
    use std::process::Command;

    // Build command with same args minus --daemon, plus --_daemon-pid marker
    let exe = std::env::current_exe()?;
    let mut cmd = Command::new(&exe);
    cmd.arg("connect");
    cmd.arg("--_daemon-pid=1"); // Marker that tells child it's a daemon (value ignored)

    if let Some(u) = user {
        cmd.args(["--user", u]);
    }
    if save_password {
        cmd.arg("--save-password");
    }
    if forget_password {
        cmd.arg("--forget-password");
    }
    if keep_alive {
        cmd.arg("--keep-alive");
    }

    // Platform-specific detachment
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
        const DETACHED_PROCESS: u32 = 0x00000008;
        cmd.creation_flags(CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS);
    }

    #[cfg(not(windows))]
    {
        use std::process::Stdio;
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::null());
    }

    let child = cmd.spawn()?;
    let pid = child.id();

    Ok(pid)
}

/// Prompt for input with optional default value
fn prompt(label: &str, default: Option<&str>) -> String {
    use std::io::Write;

    if let Some(def) = default {
        print!("{} [{}]: ", label, def);
    } else {
        print!("{}: ", label);
    }
    std::io::stdout().flush().unwrap();

    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
    let input = input.trim();

    if input.is_empty() {
        default.unwrap_or("").to_string()
    } else {
        input.to_string()
    }
}

/// Prompt for yes/no with default
fn prompt_yn(label: &str, default_yes: bool) -> bool {
    use std::io::Write;

    let suffix = if default_yes { "[Y/n]" } else { "[y/N]" };
    print!("{} {}: ", label, suffix);
    std::io::stdout().flush().unwrap();

    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
    let input = input.trim().to_lowercase();

    if input.is_empty() {
        default_yes
    } else {
        input.starts_with('y')
    }
}

/// Connect to VPN using native GlobalProtect implementation
async fn connect_vpn(user: Option<String>, save_password: bool, forget_password: bool, keep_alive: bool, is_daemon: bool) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Load or create config interactively
    let config_path = std::path::PathBuf::from("pmacs-vpn.toml");
    let (config, save_config) = if config_path.exists() {
        (pmacs_vpn::Config::load(&config_path)?, false)
    } else {
        println!("No config found. Let's set one up.\n");

        let defaults = pmacs_vpn::Config::default();

        let gateway = prompt("Gateway", Some(&defaults.vpn.gateway));
        let username_input = prompt("Username", None);
        let hosts_input = prompt("Hosts to route (comma-separated)", Some(&defaults.hosts.join(", ")));

        let hosts: Vec<String> = hosts_input
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        println!();
        let save = prompt_yn("Save config for next time?", true);

        let config = pmacs_vpn::Config {
            vpn: pmacs_vpn::VpnConfig {
                gateway,
                protocol: "gp".to_string(),
                username: Some(username_input),
            },
            hosts,
        };

        (config, save)
    };

    // Save config if user requested
    if save_config {
        config.save(&config_path)?;
        println!("Config saved to pmacs-vpn.toml\n");
    }

    // 2. Get username (from arg, config, or prompt)
    let username = user
        .or_else(|| config.vpn.username.clone())
        .unwrap_or_else(|| prompt("Username", None));

    // 3. Handle --forget-password: delete stored password before prompting
    if forget_password {
        if let Err(e) = pmacs_vpn::delete_password(&username) {
            warn!("Could not delete stored password: {}", e);
        } else {
            info!("Deleted stored password for {}", username);
        }
    }

    // 4. Get password (from keychain or prompt)
    let password = if !forget_password {
        // Try to get stored password first
        match pmacs_vpn::get_password(&username) {
            Some(stored) => {
                info!("Using stored password for {}", username);
                stored
            }
            None => rpassword::prompt_password("Password: ")?,
        }
    } else {
        // --forget-password was passed, always prompt
        rpassword::prompt_password("Password: ")?
    };

    // 5. Auth flow
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

    // 6. Create tunnel
    println!("Establishing tunnel...");
    let mut tunnel = gp::tunnel::SslTunnel::connect_with_options(
        &config.vpn.gateway,
        &login.username,
        &login.auth_cookie,
        &tunnel_config,
        keep_alive,
    )
    .await?;

    // 7. Prepare state and router
    let gateway_ip = tunnel_config.internal_ip.to_string();
    let tun_name = tunnel.tun_name().to_string();
    let internal_ip = tunnel_config.internal_ip;
    let dns_servers = tunnel_config.dns_servers.clone();
    let hosts_to_route = config.hosts.clone();

    println!("Connected! Press Ctrl+C to disconnect.");
    println!("  TUN device: {}", tun_name);
    println!("  Internal IP: {}", internal_ip);
    if keep_alive {
        println!("  Keep-alive: aggressive (10s interval)");
    }
    println!("  Session expires in: 16 hours");

    // 8. Save password if --save-password was passed
    if save_password {
        match pmacs_vpn::store_password(&username, &password) {
            Ok(()) => info!("Password stored for {}", username),
            Err(e) => warn!("Failed to store password: {}", e),
        }
    }

    // 9. Start tunnel in background FIRST, then add routes
    // This is critical: DNS queries need the tunnel running to forward packets!
    let tunnel_handle = tokio::spawn(async move {
        tunnel.run().await
    });

    // Give the tunnel a moment to start processing packets
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // 10. Now add routes (the tunnel is running and can forward DNS queries)
    println!("Adding routes...");
    // Use interface-aware routing for proper Windows TUN support
    let router = VpnRouter::with_interface(gateway_ip, tun_name.clone())?;

    let mut state = pmacs_vpn::VpnState::new(tun_name, internal_ip);

    // First add routes to VPN DNS servers
    if !dns_servers.is_empty() {
        info!("VPN DNS servers: {:?}", dns_servers);
        println!("  Adding routes to VPN DNS servers first...");
        for dns_server in &dns_servers {
            let dns_ip = dns_server.to_string();
            match router.add_ip_route(&dns_ip) {
                Ok(_) => {
                    info!("Added route to DNS server: {}", dns_ip);
                    println!("    Route to DNS: {}", dns_ip);
                }
                Err(e) => {
                    warn!("Failed to add route to DNS {}: {}", dns_ip, e);
                }
            }
        }
        println!(
            "  Using VPN DNS: {}",
            dns_servers
                .iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    } else {
        warn!("No VPN DNS servers provided, using system DNS");
    }

    let mut hosts_map = std::collections::HashMap::new();
    for host in &hosts_to_route {
        // Try VPN DNS first, fall back to system DNS
        let result = if !dns_servers.is_empty() {
            router.add_host_route_with_dns(host, &dns_servers)
        } else {
            router.add_host_route(host)
        };

        match result {
            Ok(ip) => {
                state.add_route(host.clone(), ip);
                state.add_hosts_entry(host.clone(), ip);
                hosts_map.insert(host.clone(), ip);
                println!("  Added route: {} -> {}", host, ip);
            }
            Err(e) => {
                error!("Failed to add route for {}: {}", host, e);
                println!("  WARN: Could not route {} - {}", host, e);
                println!("        Try: pmacs-vpn connect -v for more details");
            }
        }
    }

    // 11. Update hosts file
    let hosts_mgr = HostsManager::new();
    hosts_mgr.add_entries(&hosts_map)?;

    // 12. Save state for cleanup (include PID if running as daemon)
    if is_daemon {
        state.set_pid(std::process::id());
    }
    state.save()?;

    println!("Routes configured. VPN is ready.");

    // 13. Wait for tunnel completion or Ctrl+C
    let result = tokio::select! {
        result = tunnel_handle => {
            match result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(Box::new(e) as Box<dyn std::error::Error>),
                Err(e) => Err(Box::new(e) as Box<dyn std::error::Error>),
            }
        }
        _ = tokio::signal::ctrl_c() => {
            println!("\nDisconnecting...");
            Ok(())
        }
    };

    // 14. Cleanup
    cleanup_vpn(&state).await?;

    result
}

/// Disconnect from VPN and clean up
async fn disconnect_vpn() -> Result<(), Box<dyn std::error::Error>> {
    if let Some(state) = pmacs_vpn::VpnState::load()? {
        // Kill daemon process if running
        if state.pid.is_some() {
            if state.is_daemon_running() {
                info!("Stopping VPN daemon (PID: {:?})", state.pid);
                state.kill_daemon()?;
                // Give it a moment to clean up
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            } else {
                info!("Daemon process not running, cleaning up stale state");
            }
        }

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
