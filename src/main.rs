use clap::{Parser, Subcommand};
use pmacs_vpn::gp;
use pmacs_vpn::vpn::routing::VpnRouter;
use pmacs_vpn::vpn::hosts::HostsManager;
use pmacs_vpn::AuthToken;
use std::sync::Mutex;
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

/// Check if running with admin privileges (Windows)
#[cfg(windows)]
fn is_admin() -> bool {
    use std::process::Command;
    // Quick check using net session (requires admin)
    Command::new("net")
        .args(["session"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Check if running with root privileges (Unix)
#[cfg(not(windows))]
fn is_admin() -> bool {
    unsafe { nix::libc::geteuid() == 0 }
}

/// Commands that require admin privileges
fn requires_admin(cmd: &Commands) -> bool {
    matches!(cmd, Commands::Connect { .. } | Commands::Disconnect | Commands::Tray)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Check if we're running as daemon child (for file logging)
    let is_daemon_child = match &cli.command {
        Commands::Connect { _daemon_pid, .. } => _daemon_pid.is_some(),
        _ => false,
    };

    // Set up logging
    let level = if cli.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };

    if is_daemon_child {
        // Daemon mode: log to file since stdout/stderr are null
        let home = std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOME"))
            .or_else(|_| std::env::var("LOCALAPPDATA"))
            .unwrap_or_else(|_| ".".to_string());
        let log_path = std::path::PathBuf::from(home)
            .join(".pmacs-vpn")
            .join("daemon.log");

        // Create parent directory if needed
        if let Some(parent) = log_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        // Open log file (truncate on start for clean logs)
        let log_file = std::fs::File::create(&log_path)
            .expect("Failed to create daemon log file");

        let subscriber = FmtSubscriber::builder()
            .with_max_level(level)
            .with_target(false)
            .with_ansi(false) // No color codes in log file
            .with_writer(Mutex::new(log_file))
            .finish();
        tracing::subscriber::set_global_default(subscriber)?;
        info!("Daemon child started, logging to {:?}", log_path);
    } else {
        // Normal mode: log to stderr
        let subscriber = FmtSubscriber::builder()
            .with_max_level(level)
            .with_target(false)
            .with_writer(std::io::stderr)
            .finish();
        tracing::subscriber::set_global_default(subscriber)?;
    }

    // Check admin privileges for commands that need it
    if requires_admin(&cli.command) && !is_admin() {
        eprintln!("ERROR: This command requires Administrator privileges.\n");
        #[cfg(windows)]
        eprintln!("Options:");
        #[cfg(windows)]
        eprintln!("  1. Right-click terminal → Run as Administrator");
        #[cfg(windows)]
        eprintln!("  2. Use the desktop shortcut: scripts\\connect.ps1");
        #[cfg(not(windows))]
        eprintln!("Run with: sudo pmacs-vpn {}", match &cli.command {
            Commands::Connect { .. } => "connect",
            Commands::Disconnect => "disconnect",
            Commands::Tray => "tray",
            _ => "",
        });
        std::process::exit(1);
    }

    match cli.command {
        Commands::Connect { user, save_password, forget_password, keep_alive, daemon, _daemon_pid } => {
            // Daemon mode: do auth in parent, spawn detached child
            if daemon {
                match spawn_daemon(&user, save_password, forget_password, keep_alive).await {
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
                // If _daemon_pid is set, we're running as a background daemon child
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
            // On Windows, detach from console by respawning hidden
            #[cfg(windows)]
            {
                // Check if we're already the hidden child (via env var)
                if std::env::var("PMACS_VPN_TRAY_HIDDEN").is_err() {
                    // Respawn self with CREATE_NO_WINDOW
                    use std::os::windows::process::CommandExt;
                    use std::process::{Command, Stdio};

                    const CREATE_NO_WINDOW: u32 = 0x08000000;

                    let exe = std::env::current_exe().expect("Failed to get exe path");
                    let cwd = std::env::current_dir().ok();

                    let mut cmd = Command::new(&exe);
                    cmd.arg("tray");
                    cmd.env("PMACS_VPN_TRAY_HIDDEN", "1");
                    cmd.stdin(Stdio::null());
                    cmd.stdout(Stdio::null());
                    cmd.stderr(Stdio::null());
                    cmd.creation_flags(CREATE_NO_WINDOW);

                    if let Some(dir) = cwd {
                        cmd.current_dir(dir);
                    }

                    match cmd.spawn() {
                        Ok(_) => {
                            // Exit parent immediately - child runs in background
                            std::process::exit(0);
                        }
                        Err(e) => {
                            eprintln!("Failed to start tray in background: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
            }

            info!("Starting system tray mode...");
            run_tray_mode().await;
        }
    }

    Ok(())
}

/// Cleanup VPN when tray exits (called on Ctrl+C or normal exit)
fn cleanup_vpn_on_exit() {
    // Kill daemon if running
    if let Ok(Some(state)) = pmacs_vpn::VpnState::load() {
        if state.pid.is_some() && state.is_daemon_running() {
            let _ = state.kill_daemon();
        }
    }
    // Best-effort route/hosts cleanup (sync version)
    let _ = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("disconnect")
        .output();
}

/// Run the VPN with system tray GUI
async fn run_tray_mode() {
    use pmacs_vpn::tray::{TrayApp, TrayCommand, VpnStatus};
    use pmacs_vpn::notifications;

    // Set up Ctrl+C handler to cleanup on exit
    let _ = ctrlc::set_handler(move || {
        cleanup_vpn_on_exit();
        std::process::exit(0);
    });

    // Check if we have config and cached credentials for auto-connect
    let config_path = std::path::PathBuf::from("pmacs-vpn.toml");
    let (auto_connect, save_password, duo_method) = if config_path.exists() {
        if let Ok(config) = pmacs_vpn::Config::load(&config_path) {
            let has_cached_password = if let Some(ref username) = config.vpn.username {
                pmacs_vpn::get_password(username).is_some()
            } else {
                false
            };
            (
                has_cached_password,
                config.preferences.save_password,
                config.preferences.duo_method.clone(),
            )
        } else {
            (false, true, pmacs_vpn::DuoMethod::default())
        }
    } else {
        (false, true, pmacs_vpn::DuoMethod::default())
    };

    // Show setup notification if no credentials
    if !auto_connect {
        notifications::notify_setup_required();
    }

    // Create tray app with auto-connect setting
    let (app, command_rx, status_tx) = TrayApp::new(auto_connect, save_password, duo_method);

    // Clone for the command handler
    let status_tx_clone = status_tx.clone();

    // Spawn command handler on tokio runtime
    let _handle = tokio::spawn(async move {
        while let Ok(cmd) = command_rx.recv() {
            match cmd {
                TrayCommand::Connect => {
                    info!("Tray: Received connect command");
                    let _ = status_tx_clone.send(VpnStatus::Connecting);

                    // Show DUO notification immediately
                    notifications::notify_duo_push();

                    // Check if we have cached credentials
                    let config_path = std::path::PathBuf::from("pmacs-vpn.toml");
                    let has_config = config_path.exists();

                    if !has_config {
                        let _ = status_tx_clone.send(VpnStatus::Error(
                            "No config file. Run 'pmacs-vpn connect' first.".to_string()
                        ));
                        continue;
                    }

                    // Load config and check for cached password
                    let config = match pmacs_vpn::Config::load(&config_path) {
                        Ok(c) => c,
                        Err(e) => {
                            let _ = status_tx_clone.send(VpnStatus::Error(format!("Config error: {}", e)));
                            continue;
                        }
                    };

                    let username = config.vpn.username.clone().unwrap_or_default();
                    if username.is_empty() || pmacs_vpn::get_password(&username).is_none() {
                        let _ = status_tx_clone.send(VpnStatus::Error(
                            "No cached password. Run 'pmacs-vpn connect --save-password' first.".to_string()
                        ));
                        continue;
                    }

                    // Spawn daemon (auth happens in parent, passes token to child)
                    match spawn_daemon(&None, false, false, false).await {
                        Ok(pid) => {
                            info!("VPN daemon started with PID {}", pid);

                            // Poll for connection status instead of fixed wait
                            let mut connected = false;
                            for _ in 0..60 {  // max 30 seconds (DUO + TUN setup can be slow)
                                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                                if let Ok(Some(state)) = pmacs_vpn::VpnState::load() {
                                    if state.is_daemon_running() {
                                        notifications::notify_connected();
                                        let _ = status_tx_clone.send(VpnStatus::Connected {
                                            ip: state.gateway.to_string(),
                                        });
                                        connected = true;
                                        break;
                                    }
                                }
                            }
                            if !connected {
                                let _ = status_tx_clone.send(VpnStatus::Error(
                                    "Connection timeout - check logs".to_string()
                                ));
                            }
                        }
                        Err(e) => {
                            error!("Failed to start VPN daemon: {}", e);
                            let _ = status_tx_clone.send(VpnStatus::Error(format!("Failed: {}", e)));
                        }
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
                TrayCommand::ToggleSavePassword => {
                    info!("Tray: Toggle save password preference");
                    let config_path = std::path::PathBuf::from("pmacs-vpn.toml");
                    if let Ok(mut config) = pmacs_vpn::Config::load(&config_path) {
                        config.preferences.save_password = !config.preferences.save_password;
                        if let Err(e) = config.save(&config_path) {
                            error!("Failed to save config: {}", e);
                        } else {
                            info!("Save password preference updated to: {}", config.preferences.save_password);
                        }
                    }
                }
                TrayCommand::SetDuoMethod(method) => {
                    info!("Tray: Set DUO method to {:?}", method);
                    let config_path = std::path::PathBuf::from("pmacs-vpn.toml");
                    if let Ok(mut config) = pmacs_vpn::Config::load(&config_path) {
                        config.preferences.duo_method = method;
                        if let Err(e) = config.save(&config_path) {
                            error!("Failed to save config: {}", e);
                        } else {
                            info!("DUO method preference updated");
                        }
                    }
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

    // Spawn health monitor to detect daemon death (e.g., after sleep/wake)
    let status_tx_health = status_tx.clone();
    let _health_handle = tokio::spawn(async move {
        use std::sync::atomic::{AtomicBool, Ordering};
        static WAS_CONNECTED: AtomicBool = AtomicBool::new(false);

        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

            if let Ok(Some(state)) = pmacs_vpn::VpnState::load() {
                if state.pid.is_some() {
                    if state.is_daemon_running() {
                        WAS_CONNECTED.store(true, Ordering::Relaxed);
                    } else if WAS_CONNECTED.swap(false, Ordering::Relaxed) {
                        // Daemon died unexpectedly (was connected, now dead)
                        info!("Health monitor: Daemon died unexpectedly");
                        notifications::notify_error("VPN disconnected unexpectedly");
                        let _ = status_tx_health.send(VpnStatus::Disconnected);
                    }
                }
            }
        }
    });

    // Run tray (this blocks until exit)
    // Note: This will run on the current thread, not tokio
    let tray_handle = std::thread::spawn(move || {
        app.run();
    });

    // Wait for tray to exit
    let _ = tray_handle.join();

    // Cleanup VPN when tray exits (regardless of how it exited)
    cleanup_vpn_on_exit();
}

/// Spawn VPN as a detached background process (daemon mode)
/// Does authentication FIRST in parent, then passes token to child
async fn spawn_daemon(
    user: &Option<String>,
    save_password: bool,
    forget_password: bool,
    keep_alive: bool,
) -> Result<u32, Box<dyn std::error::Error + Send + Sync>> {
    use std::process::Command;

    // 1. Load or create config
    let config_path = std::path::PathBuf::from("pmacs-vpn.toml");
    let config = if config_path.exists() {
        pmacs_vpn::Config::load(&config_path)?
    } else {
        println!("No config found. Run 'pmacs-vpn connect' first to set up.");
        return Err("No config file".into());
    };

    // 2. Get username
    let username = user
        .clone()
        .or_else(|| config.vpn.username.clone())
        .unwrap_or_else(|| prompt("Username", None));

    // 3. Handle --forget-password
    if forget_password {
        if let Err(e) = pmacs_vpn::delete_password(&username) {
            warn!("Could not delete stored password: {}", e);
        } else {
            info!("Deleted stored password for {}", username);
        }
    }

    // 4. Get password (from keychain or prompt)
    let (password, was_cached) = if !forget_password {
        match pmacs_vpn::get_password(&username) {
            Some(stored) => {
                println!("Using saved password from keychain");
                (stored, true)
            }
            None => {
                let prompt = format!("Password for {}@{}: ", username, config.vpn.gateway);
                (rpassword::prompt_password(&prompt)?, false)
            }
        }
    } else {
        let prompt = format!("Password for {}@{}: ", username, config.vpn.gateway);
        (rpassword::prompt_password(&prompt)?, false)
    };

    // 5. Do auth flow
    println!("Authenticating...");
    let prelogin = gp::auth::prelogin(&config.vpn.gateway).await?;
    info!("Auth method: {:?}", prelogin.auth_method);

    // Get DUO method from config
    let duo_method = &config.preferences.duo_method;
    let duo_passcode = if *duo_method == pmacs_vpn::DuoMethod::Passcode {
        // Prompt for passcode
        let code = rpassword::prompt_password("DUO passcode: ")?;
        Some(code)
    } else {
        None
    };

    println!("Logging in ({})...", duo_method.description());
    let duo_str = duo_passcode.as_deref().or_else(|| duo_method.as_auth_str());
    let login = gp::auth::login(&config.vpn.gateway, &username, &password, duo_str).await?;
    println!("Login successful!");

    // 6. Save password if requested or offer to save
    if save_password {
        match pmacs_vpn::store_password(&username, &password) {
            Ok(()) => println!("Password saved to keychain"),
            Err(e) => warn!("Failed to store password: {}", e),
        }
    } else if !was_cached {
        // First-time user - ask if they want to save
        print!("Save password to keychain for next time? [Y/n]: ");
        std::io::Write::flush(&mut std::io::stdout())?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let input = input.trim().to_lowercase();
        if input.is_empty() || input == "y" || input == "yes" {
            match pmacs_vpn::store_password(&username, &password) {
                Ok(()) => println!("Password saved to keychain"),
                Err(e) => warn!("Failed to store password: {}", e),
            }
        }
    }

    // 7. Save auth token for daemon
    let token = AuthToken::new(
        config.vpn.gateway.clone(),
        login.username.clone(),
        login.auth_cookie.clone(),
        login.portal.clone(),
        login.domain.clone(),
        config.hosts.clone(),
        keep_alive,
    );
    token.save()?;

    // 8. Spawn daemon child (it will read the token file)
    let exe = std::env::current_exe()?;
    let mut cmd = Command::new(&exe);
    cmd.arg("connect");
    cmd.arg("--daemon-pid=1");

    // Set working directory (needed for config file access)
    if let Ok(cwd) = std::env::current_dir() {
        cmd.current_dir(cwd);
    }

    // Platform-specific detachment - redirect stdio to null (no console)
    {
        use std::process::Stdio;
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::null());
    }

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
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
    // Check if we're a daemon child with an auth token
    if is_daemon {
        if let Some(token) = AuthToken::load()? {
            // Delete token immediately (one-time use)
            AuthToken::delete()?;
            return connect_vpn_with_token(token).await;
        }
        // No token but is_daemon? That's an error
        return Err("Daemon mode requires auth token from parent".into());
    }

    // Normal interactive flow
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
            preferences: pmacs_vpn::Preferences::default(),
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
    let (password, was_cached) = if !forget_password {
        // Try to get stored password first
        match pmacs_vpn::get_password(&username) {
            Some(stored) => {
                println!("Using saved password from keychain");
                (stored, true)
            }
            None => {
                let prompt = format!("Password for {}@{}: ", username, config.vpn.gateway);
                (rpassword::prompt_password(&prompt)?, false)
            }
        }
    } else {
        // --forget-password was passed, always prompt
        let prompt = format!("Password for {}@{}: ", username, config.vpn.gateway);
        (rpassword::prompt_password(&prompt)?, false)
    };

    // 5. Auth flow
    println!("Authenticating...");
    let prelogin = gp::auth::prelogin(&config.vpn.gateway).await?;
    info!("Auth method: {:?}", prelogin.auth_method);

    // Get DUO method from config
    let duo_method = &config.preferences.duo_method;
    let duo_passcode = if *duo_method == pmacs_vpn::DuoMethod::Passcode {
        // Prompt for passcode
        let code = rpassword::prompt_password("DUO passcode: ")?;
        Some(code)
    } else {
        None
    };

    println!("Logging in ({})...", duo_method.description());
    let duo_str = duo_passcode.as_deref().or_else(|| duo_method.as_auth_str());
    let login = gp::auth::login(&config.vpn.gateway, &username, &password, duo_str).await?;
    println!("Login successful!");

    // 6. Save password if requested or offer to save
    if save_password {
        match pmacs_vpn::store_password(&username, &password) {
            Ok(()) => println!("Password saved to keychain"),
            Err(e) => warn!("Failed to store password: {}", e),
        }
    } else if !was_cached {
        // First-time user - ask if they want to save
        print!("Save password to keychain for next time? [Y/n]: ");
        std::io::Write::flush(&mut std::io::stdout())?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let input = input.trim().to_lowercase();
        if input.is_empty() || input == "y" || input == "yes" {
            match pmacs_vpn::store_password(&username, &password) {
                Ok(()) => println!("Password saved to keychain"),
                Err(e) => warn!("Failed to store password: {}", e),
            }
        }
    }

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

    // 7. Start tunnel in background FIRST, then add routes
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

    // 12. Cleanup
    cleanup_vpn(&state).await?;

    result
}

/// Connect to VPN using pre-authenticated token (daemon child)
async fn connect_vpn_with_token(token: AuthToken) -> Result<(), Box<dyn std::error::Error>> {
    info!("Daemon: connecting with auth token...");

    // Get tunnel config using the auth cookie
    let tunnel_config = gp::auth::getconfig_with_cookie(
        &token.gateway,
        &token.username,
        &token.auth_cookie,
        &token.portal,
        &token.domain,
        None,
    ).await?;
    info!(
        "Tunnel config: IP={} MTU={}",
        tunnel_config.internal_ip, tunnel_config.mtu
    );

    // Create tunnel
    let mut tunnel = gp::tunnel::SslTunnel::connect_with_options(
        &token.gateway,
        &token.username,
        &token.auth_cookie,
        &tunnel_config,
        token.keep_alive,
    )
    .await?;

    // Prepare state and router
    let gateway_ip = tunnel_config.internal_ip.to_string();
    let tun_name = tunnel.tun_name().to_string();
    let internal_ip = tunnel_config.internal_ip;
    let dns_servers = tunnel_config.dns_servers.clone();
    let hosts_to_route = token.hosts.clone();

    info!("Daemon: tunnel established, TUN={}", tun_name);

    // Start tunnel in background
    let tunnel_handle = tokio::spawn(async move {
        tunnel.run().await
    });

    // Give the tunnel a moment to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Add routes
    let router = VpnRouter::with_interface(gateway_ip, tun_name.clone())?;
    let mut state = pmacs_vpn::VpnState::new(tun_name, internal_ip);

    // Route to DNS servers first
    for dns_server in &dns_servers {
        let dns_ip = dns_server.to_string();
        if let Err(e) = router.add_ip_route(&dns_ip) {
            warn!("Failed to add route to DNS {}: {}", dns_ip, e);
        }
    }

    // Route to target hosts
    let mut hosts_map = std::collections::HashMap::new();
    for host in &hosts_to_route {
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
                info!("Added route: {} -> {}", host, ip);
            }
            Err(e) => {
                error!("Failed to add route for {}: {}", host, e);
            }
        }
    }

    // Update hosts file
    let hosts_mgr = HostsManager::new();
    hosts_mgr.add_entries(&hosts_map)?;

    // Save state with PID
    state.set_pid(std::process::id());
    state.save()?;

    info!("Daemon: VPN ready");

    // Wait for tunnel completion or signal
    let result = tokio::select! {
        result = tunnel_handle => {
            match result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(Box::new(e) as Box<dyn std::error::Error>),
                Err(e) => Err(Box::new(e) as Box<dyn std::error::Error>),
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Daemon: received shutdown signal");
            Ok(())
        }
    };

    // Cleanup
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
