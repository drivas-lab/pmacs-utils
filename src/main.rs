use clap::{Parser, Subcommand};
use pmacs_vpn::AuthToken;
use pmacs_vpn::gp;
use pmacs_vpn::notifications;
use pmacs_vpn::vpn::hosts::HostsManager;
use pmacs_vpn::vpn::routing::VpnRouter;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal};
use tracing::{Level, debug, error, info, warn};
use tracing_subscriber::FmtSubscriber;

/// Global flag to indicate user-initiated disconnect is in progress
/// This prevents the health monitor from triggering auto-reconnect
static USER_DISCONNECT_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

/// Get the config file path.
fn get_config_path() -> std::path::PathBuf {
    pmacs_vpn::resolve_config_path()
}

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
        #[arg(short = 's', long)]
        save_password: bool,

        /// Delete stored password before prompting
        #[arg(short = 'f', long)]
        forget_password: bool,

        /// Use aggressive keepalive to prevent idle timeout (10s instead of 30s)
        #[arg(short = 'k', long)]
        keep_alive: bool,

        /// Run VPN in background
        #[arg(short = 'b', long)]
        background: bool,

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
    /// Delete stored password for a user
    ForgetPassword {
        /// Username whose password should be deleted
        #[arg(short, long)]
        user: String,
    },
    /// Run with system tray (GUI mode)
    Tray {
        /// Internal: mark tray launch as OS login/autostart launch
        #[arg(long, hide = true)]
        launched_at_login: bool,
    },
}

/// Check if running with admin privileges (Windows)
#[cfg(windows)]
fn is_admin() -> bool {
    use windows::Win32::UI::Shell::IsUserAnAdmin;
    unsafe { IsUserAnAdmin().as_bool() }
}

/// Check if running with root privileges (Unix)
#[cfg(not(windows))]
fn is_admin() -> bool {
    unsafe { nix::libc::geteuid() == 0 }
}

/// Commands that require admin privileges
fn requires_admin(cmd: &Commands) -> bool {
    match cmd {
        // Connect/Disconnect require root on all platforms (TUN device, routes, /etc/hosts)
        Commands::Connect { .. } | Commands::Disconnect => true,

        // On Windows, tray needs admin upfront (spawns daemon directly)
        #[cfg(windows)]
        Commands::Tray { .. } => true,
        #[cfg(not(windows))]
        Commands::Tray { .. } => false,
        _ => false,
    }
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
        let log_file = std::fs::File::create(&log_path).expect("Failed to create daemon log file");

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
        eprintln!(
            "Run with: sudo pmacs-vpn {}",
            match &cli.command {
                Commands::Connect { .. } => "connect",
                Commands::Disconnect => "disconnect",
                Commands::Tray { .. } => "tray",
                _ => "",
            }
        );
        std::process::exit(1);
    }

    match cli.command {
        Commands::Connect {
            user,
            save_password,
            forget_password,
            keep_alive,
            background,
            _daemon_pid,
        } => {
            // Background mode: do auth in parent, spawn detached child
            if background {
                match spawn_daemon(&user, save_password, forget_password, keep_alive).await {
                    Ok(pid) => {
                        println!("VPN running in background (PID: {})", pid);
                        println!("Use 'pmacs-vpn status' to check connection");
                        println!("Use 'pmacs-vpn disconnect' to stop");
                    }
                    Err(e) => {
                        error!("Failed to start background process: {}", e);
                        std::process::exit(1);
                    }
                }
            } else {
                // If _daemon_pid is set, we're running as a background daemon child
                let is_daemon = _daemon_pid.is_some();
                info!("Connecting to PMACS VPN...");
                match connect_vpn(user, save_password, forget_password, keep_alive, is_daemon).await
                {
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
            if !pmacs_vpn::VpnState::is_active() {
                println!("VPN Status: Not connected");
            } else {
                match pmacs_vpn::VpnState::load() {
                    Ok(Some(state)) => {
                        // If we have a daemon PID, treat stale PID as disconnected.
                        if let Some(pid) = state.pid
                            && !state.is_daemon_running()
                        {
                            println!("VPN Status: Not connected");
                            println!("  Note: Found stale state (PID {} is not running)", pid);
                            println!(
                                "  Cleanup: Run 'sudo pmacs-vpn disconnect' to remove stale routes/hosts"
                            );
                            return Ok(());
                        }

                        // Connected (or foreground state without PID)
                        let mode = if let Some(pid) = state.pid {
                            format!("Running (PID: {})", pid)
                        } else {
                            "Foreground".to_string()
                        };

                        println!("VPN Status: Connected");
                        println!("  Mode: {}", mode);
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
            }
        }
        Commands::Init => {
            info!("Generating default config...");
            let config = pmacs_vpn::Config::default();
            let path = get_config_path();
            config.save(&path)?;
            println!("Created default config: {}", path.display());
        }
        Commands::ForgetPassword { user } => match pmacs_vpn::delete_password(&user) {
            Ok(()) => println!("Password deleted for user: {}", user),
            Err(e) => {
                error!("Failed to delete password: {}", e);
                std::process::exit(1);
            }
        },
        Commands::Tray { launched_at_login } => {
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
                    if launched_at_login {
                        cmd.arg("--launched-at-login");
                    }
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
            run_tray_mode(launched_at_login).await;
        }
    }

    Ok(())
}

/// Cleanup VPN when tray exits (called on Ctrl+C or normal exit)
fn cleanup_vpn_on_exit() {
    // Ask daemon to disconnect cleanly via IPC first.
    if let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        let ipc_client = pmacs_vpn::ipc::IpcClient::new();
        let _ = rt.block_on(ipc_client.disconnect());
    }

    // Privileged cleanup is only possible when running as admin/root.
    if !is_admin() {
        info!("Tray exit cleanup: skipping privileged route cleanup (not admin)");
        return;
    }

    if let Ok(Some(state)) = pmacs_vpn::VpnState::load()
        && state.pid.is_some()
        && state.is_daemon_running()
    {
        let _ = state.kill_daemon();
    }

    if let Ok(exe) = std::env::current_exe() {
        let _ = std::process::Command::new(exe).arg("disconnect").output();
    }
}

#[derive(Clone)]
struct TrayStartupConfig {
    auto_connect: bool,
    save_password: bool,
    duo_method: pmacs_vpn::DuoMethod,
    show_setup_required: bool,
}

fn is_truthy_env_var(name: &str) -> bool {
    std::env::var(name)
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn is_login_autostart_launch(cli_flag: bool) -> bool {
    cli_flag || is_truthy_env_var("PMACS_VPN_LAUNCHED_AT_LOGIN")
}

fn load_tray_startup_config(launched_at_login: bool) -> TrayStartupConfig {
    let config_path = get_config_path();
    if !config_path.exists() {
        return TrayStartupConfig {
            auto_connect: false,
            save_password: true,
            duo_method: pmacs_vpn::DuoMethod::default(),
            show_setup_required: true,
        };
    }

    match pmacs_vpn::Config::load(&config_path) {
        Ok(mut config) => {
            let mut startup_enabled = pmacs_vpn::startup::is_start_at_login_enabled();
            if startup_enabled && !config.preferences.start_at_login {
                warn!(
                    "Found stale start-at-login registration while config disables it; removing stale startup entry"
                );
                match pmacs_vpn::startup::disable_start_at_login() {
                    Ok(()) => {
                        startup_enabled = false;
                        info!("Removed stale start-at-login registration");
                    }
                    Err(e) => warn!("Failed to remove stale start-at-login registration: {}", e),
                }
            }

            if config.preferences.start_at_login != startup_enabled {
                config.preferences.start_at_login = startup_enabled;
                if let Err(e) = config.save(&config_path) {
                    warn!("Failed to sync start_at_login preference to config: {}", e);
                }
            }

            let has_cached_password = config
                .vpn
                .username
                .as_ref()
                .and_then(|username| pmacs_vpn::get_password(username))
                .is_some();

            let auto_connect_enabled = config.preferences.auto_connect && has_cached_password;
            if launched_at_login && auto_connect_enabled {
                info!("Skipping auto-connect for login/autostart tray launch");
            }

            TrayStartupConfig {
                auto_connect: auto_connect_enabled && !launched_at_login,
                save_password: config.preferences.save_password,
                duo_method: config.preferences.duo_method,
                show_setup_required: !has_cached_password,
            }
        }
        Err(e) => {
            warn!("Failed to load tray config: {}", e);
            TrayStartupConfig {
                auto_connect: false,
                save_password: true,
                duo_method: pmacs_vpn::DuoMethod::default(),
                show_setup_required: true,
            }
        }
    }
}

fn ensure_cached_tray_credentials() -> Result<(), String> {
    let config_path = get_config_path();
    if !config_path.exists() {
        return Err("No config file. Run 'pmacs-vpn connect' first.".to_string());
    }

    let config =
        pmacs_vpn::Config::load(&config_path).map_err(|e| format!("Config error: {}", e))?;
    let username = config.vpn.username.clone().unwrap_or_default();
    if username.is_empty() || pmacs_vpn::get_password(&username).is_none() {
        return Err(
            "No cached password. Run 'pmacs-vpn connect --save-password' first.".to_string(),
        );
    }

    Ok(())
}

fn wait_for_daemon_online(rt: &tokio::runtime::Handle) -> Option<String> {
    let ipc_client = pmacs_vpn::ipc::IpcClient::new();

    for _ in 0..60 {
        if let Ok(status) = rt.block_on(ipc_client.get_status()) {
            return Some(status.gateway);
        }

        if let Ok(Some(state)) = pmacs_vpn::VpnState::load()
            && state.is_daemon_running()
        {
            return Some(state.gateway.to_string());
        }

        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    None
}

fn wait_for_daemon_offline(rt: &tokio::runtime::Handle) {
    let ipc_client = pmacs_vpn::ipc::IpcClient::new();

    for _ in 0..20 {
        if rt.block_on(ipc_client.ping()).is_err() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

fn best_effort_admin_cleanup(rt: &tokio::runtime::Handle) -> Result<(), String> {
    if !is_admin() {
        return Ok(());
    }

    if let Ok(Some(state)) = pmacs_vpn::VpnState::load()
        && state.pid.is_some()
        && state.is_daemon_running()
    {
        let _ = state.kill_daemon();
    }

    rt.block_on(disconnect_vpn()).map_err(|e| e.to_string())
}

fn tray_connect(rt: &tokio::runtime::Handle) -> Result<String, String> {
    ensure_cached_tray_credentials()?;

    let pid = rt
        .block_on(spawn_daemon(&None, false, false, true))
        .map_err(|e| e.to_string())?;
    if pid > 0 {
        info!("Tray: VPN daemon started (PID {})", pid);
    } else {
        info!("Tray: VPN daemon started");
    }

    wait_for_daemon_online(rt).ok_or_else(|| "Connection timeout - check logs".to_string())
}

fn tray_request_disconnect(rt: &tokio::runtime::Handle) -> Result<(), String> {
    let ipc_client = pmacs_vpn::ipc::IpcClient::new();
    rt.block_on(ipc_client.disconnect())
        .map_err(|e| e.to_string())
}

fn run_tray_diagnostics() {
    #[cfg(target_os = "macos")]
    {
        use pmacs_vpn::macos_permissions::PermissionState;
        let report = pmacs_vpn::macos_permissions::collect_permissions_diagnostics();

        for line in report.lines() {
            info!("macOS diagnostics: {}", line);
        }

        let accessibility = match report.accessibility {
            PermissionState::Granted => "granted",
            PermissionState::Missing => "missing",
            PermissionState::Unknown => "unknown",
        };
        let input_monitoring = match report.input_monitoring {
            PermissionState::Granted => "granted",
            PermissionState::Missing => "missing",
            PermissionState::Unknown => "unknown",
        };

        let summary = format!(
            "Accessibility: {}, Input Monitoring: {}",
            accessibility, input_monitoring
        );
        notifications::show_notification("PMACS VPN diagnostics", &summary);
    }

    #[cfg(not(target_os = "macos"))]
    {
        notifications::show_notification(
            "PMACS VPN diagnostics",
            "No extra tray permissions are required on this platform.",
        );
    }
}

async fn initialize_tray_status(status_tx: &std::sync::mpsc::Sender<pmacs_vpn::tray::VpnStatus>) {
    use pmacs_vpn::tray::VpnStatus;

    let ipc_client = pmacs_vpn::ipc::IpcClient::new();
    if let Ok(status) = ipc_client.get_status().await {
        let _ = status_tx.send(VpnStatus::Connected { ip: status.gateway });
        return;
    }

    if let Ok(Some(state)) = pmacs_vpn::VpnState::load()
        && state.is_daemon_running()
    {
        let _ = status_tx.send(VpnStatus::Connected {
            ip: state.gateway.to_string(),
        });
    }
}

fn spawn_tray_command_handler(
    rt: tokio::runtime::Handle,
    command_rx: std::sync::mpsc::Receiver<pmacs_vpn::tray::TrayCommand>,
    status_tx: std::sync::mpsc::Sender<pmacs_vpn::tray::VpnStatus>,
) {
    use pmacs_vpn::tray::{TrayCommand, VpnStatus};

    std::thread::spawn(move || {
        while let Ok(cmd) = command_rx.recv() {
            match cmd {
                TrayCommand::Connect => {
                    info!("Tray: Connect requested");
                    let _ = status_tx.send(VpnStatus::Connecting);

                    match tray_connect(&rt) {
                        Ok(ip) => {
                            notifications::notify_connected();
                            let _ = status_tx.send(VpnStatus::Connected { ip });
                        }
                        Err(e) => {
                            error!("Tray connect failed: {}", e);
                            let _ = status_tx.send(VpnStatus::Error(e));
                        }
                    }
                }
                TrayCommand::Disconnect => {
                    info!("Tray: Disconnect requested");
                    USER_DISCONNECT_IN_PROGRESS.store(true, Ordering::SeqCst);
                    let _ = status_tx.send(VpnStatus::Disconnecting);

                    let result = match tray_request_disconnect(&rt) {
                        Ok(()) => {
                            wait_for_daemon_offline(&rt);
                            Ok(())
                        }
                        Err(e) => {
                            info!("Tray disconnect via IPC failed: {}", e);
                            if is_admin() {
                                best_effort_admin_cleanup(&rt)
                            } else {
                                Err("Could not reach VPN daemon. If cleanup is needed, run: sudo pmacs-vpn disconnect".to_string())
                            }
                        }
                    };

                    match result {
                        Ok(()) => {
                            notifications::notify_disconnected();
                            let _ = status_tx.send(VpnStatus::Disconnected);
                        }
                        Err(e) => {
                            error!("Tray disconnect failed: {}", e);
                            let _ = status_tx.send(VpnStatus::Error(e));
                        }
                    }

                    USER_DISCONNECT_IN_PROGRESS.store(false, Ordering::SeqCst);
                }
                TrayCommand::Reconnect => {
                    info!("Tray: Reconnect requested");
                    USER_DISCONNECT_IN_PROGRESS.store(true, Ordering::SeqCst);

                    let disconnect_result = tray_request_disconnect(&rt);
                    if is_admin() {
                        let _ = best_effort_admin_cleanup(&rt);
                    } else if disconnect_result.is_err()
                        && let Ok(Some(state)) = pmacs_vpn::VpnState::load()
                        && state.pid.is_some()
                        && state.is_daemon_running()
                    {
                        USER_DISCONNECT_IN_PROGRESS.store(false, Ordering::SeqCst);
                        let _ = status_tx.send(VpnStatus::Error(
                            "Reconnect failed: could not signal existing VPN daemon. Try Disconnect first."
                                .to_string(),
                        ));
                        continue;
                    }
                    wait_for_daemon_offline(&rt);

                    USER_DISCONNECT_IN_PROGRESS.store(false, Ordering::SeqCst);
                    let _ = status_tx.send(VpnStatus::Connecting);

                    match tray_connect(&rt) {
                        Ok(ip) => {
                            notifications::notify_connected();
                            let _ = status_tx.send(VpnStatus::Connected { ip });
                        }
                        Err(e) => {
                            error!("Tray reconnect failed: {}", e);
                            let _ = status_tx
                                .send(VpnStatus::Error(format!("Reconnect failed: {}", e)));
                        }
                    }
                }
                TrayCommand::AutoReconnect { attempt } => {
                    info!("Tray: Auto-reconnect attempt {}", attempt);
                    let _ = tray_request_disconnect(&rt);
                    if is_admin() {
                        let _ = best_effort_admin_cleanup(&rt);
                    }
                    wait_for_daemon_offline(&rt);

                    match tray_connect(&rt) {
                        Ok(ip) => {
                            notifications::notify_connected();
                            let _ = status_tx.send(VpnStatus::Connected { ip });
                        }
                        Err(e) => {
                            error!("Tray auto-reconnect failed: {}", e);
                            let _ = status_tx
                                .send(VpnStatus::Error(format!("Auto-reconnect failed: {}", e)));
                        }
                    }
                }
                TrayCommand::ShowStatus => {
                    info!("Tray: Show status requested");
                }
                TrayCommand::ShowDiagnostics => {
                    info!("Tray: Diagnostics requested");
                    run_tray_diagnostics();
                }
                TrayCommand::ToggleSavePassword => {
                    info!("Tray: Toggle save password preference");
                    let config_path = get_config_path();
                    if let Ok(mut config) = pmacs_vpn::Config::load(&config_path) {
                        config.preferences.save_password = !config.preferences.save_password;
                        if let Err(e) = config.save(&config_path) {
                            error!("Failed to save config: {}", e);
                        } else {
                            info!(
                                "Save password preference updated to: {}",
                                config.preferences.save_password
                            );
                        }
                    }
                }
                TrayCommand::SetDuoMethod(method) => {
                    info!("Tray: Set DUO method to {:?}", method);
                    let config_path = get_config_path();
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
                    USER_DISCONNECT_IN_PROGRESS.store(true, Ordering::SeqCst);
                    let _ = tray_request_disconnect(&rt);
                    if is_admin() {
                        let _ = best_effort_admin_cleanup(&rt);
                    }
                    break;
                }
            }
        }
    });
}

fn spawn_tray_health_monitor(
    rt: &tokio::runtime::Handle,
    status_tx: std::sync::mpsc::Sender<pmacs_vpn::tray::VpnStatus>,
    command_tx: std::sync::mpsc::Sender<pmacs_vpn::tray::TrayCommand>,
) {
    use pmacs_vpn::tray::{TrayCommand, VpnStatus};

    let rt = rt.clone();
    rt.spawn(async move {
        let config_path = get_config_path();
        let (auto_reconnect_enabled, max_attempts, base_delay) =
            if let Ok(config) = pmacs_vpn::Config::load(&config_path) {
                (
                    config.preferences.auto_reconnect,
                    config.preferences.max_reconnect_attempts,
                    config.preferences.reconnect_delay_secs,
                )
            } else {
                (true, 3, 5)
            };

        let ipc_client = pmacs_vpn::ipc::IpcClient::new();
        let mut was_connected = false;
        let mut reconnect_attempts = 0u32;

        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

            if USER_DISCONNECT_IN_PROGRESS.load(Ordering::SeqCst) {
                was_connected = false;
                reconnect_attempts = 0;
                continue;
            }

            let daemon_alive = ipc_client.ping().await.is_ok();

            if daemon_alive {
                was_connected = true;
                reconnect_attempts = 0;
                continue;
            }

            if !was_connected {
                if let Ok(Some(state)) = pmacs_vpn::VpnState::load()
                    && state.pid.is_some()
                    && state.is_daemon_running()
                {
                    debug!("Health monitor: daemon PID exists but IPC not ready");
                }
                continue;
            }

            was_connected = false;
            if USER_DISCONNECT_IN_PROGRESS.load(Ordering::SeqCst) {
                reconnect_attempts = 0;
                continue;
            }

            if auto_reconnect_enabled && reconnect_attempts < max_attempts {
                reconnect_attempts += 1;
                let delay = std::cmp::min(base_delay * (1 << (reconnect_attempts - 1)), 60);
                notifications::notify_reconnecting(reconnect_attempts, max_attempts);
                let _ = status_tx.send(VpnStatus::Reconnecting {
                    attempt: reconnect_attempts,
                    max_attempts,
                });

                tokio::time::sleep(tokio::time::Duration::from_secs(delay as u64)).await;
                if USER_DISCONNECT_IN_PROGRESS.load(Ordering::SeqCst) {
                    let _ = status_tx.send(VpnStatus::Disconnected);
                    reconnect_attempts = 0;
                    continue;
                }

                let _ = command_tx.send(TrayCommand::AutoReconnect {
                    attempt: reconnect_attempts,
                });
            } else {
                if auto_reconnect_enabled {
                    notifications::notify_reconnect_failed();
                } else {
                    notifications::notify_unexpected_disconnect();
                }
                let _ = status_tx.send(VpnStatus::Disconnected);
                reconnect_attempts = 0;
            }
        }
    });
}

fn start_tray_services(
    rt: &tokio::runtime::Handle,
    launched_at_login: bool,
) -> (
    pmacs_vpn::tray::TrayApp,
    std::sync::mpsc::Sender<pmacs_vpn::tray::VpnStatus>,
) {
    use pmacs_vpn::tray::TrayApp;

    let startup = load_tray_startup_config(launched_at_login);
    if startup.show_setup_required {
        notifications::notify_setup_required();
    }

    let (app, command_rx, status_tx, command_tx) = TrayApp::new(
        startup.auto_connect,
        startup.save_password,
        startup.duo_method,
    );

    spawn_tray_command_handler(rt.clone(), command_rx, status_tx.clone());
    spawn_tray_health_monitor(rt, status_tx.clone(), command_tx);

    (app, status_tx)
}

/// Run the VPN with system tray GUI.
async fn run_tray_mode(launched_at_login: bool) {
    let _ = ctrlc::set_handler(move || {
        cleanup_vpn_on_exit();
        std::process::exit(0);
    });

    let rt = tokio::runtime::Handle::current();
    let launched_at_login = is_login_autostart_launch(launched_at_login);
    let (app, status_tx) = start_tray_services(&rt, launched_at_login);
    initialize_tray_status(&status_tx).await;

    #[cfg(target_os = "macos")]
    {
        // AppKit/tray must run on the process main thread on macOS.
        app.run();
    }

    #[cfg(not(target_os = "macos"))]
    let tray_handle = std::thread::spawn(move || {
        app.run();
    });

    #[cfg(not(target_os = "macos"))]
    let _ = tray_handle.join();
    #[cfg(not(target_os = "macos"))]
    {
        cleanup_vpn_on_exit();
    }
}

#[cfg(target_os = "macos")]
fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(target_os = "macos")]
fn applescript_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(target_os = "macos")]
fn spawn_daemon_via_macos_elevation(
    exe: &std::path::Path,
) -> Result<u32, Box<dyn std::error::Error + Send + Sync>> {
    use nix::unistd::{Gid, Uid};
    use std::process::Command;

    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_err(|_| "HOME is not set")?;
    let cwd = std::env::current_dir()?;
    let pid_file = std::path::PathBuf::from(&home)
        .join(".pmacs-vpn")
        .join("tray-daemon.pid");

    if let Some(parent) = pid_file.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _ = std::fs::remove_file(&pid_file);

    let uid = Uid::current().as_raw();
    let gid = Gid::current().as_raw();

    let shell_cmd = format!(
        "export HOME={home}; export PMACS_VPN_IPC_UID={uid}; export PMACS_VPN_IPC_GID={gid}; cd {cwd}; {exe} connect --daemon-pid=1 >/dev/null 2>&1 & echo $! > {pid_file}",
        home = shell_single_quote(&home),
        uid = uid,
        gid = gid,
        cwd = shell_single_quote(&cwd.display().to_string()),
        exe = shell_single_quote(&exe.display().to_string()),
        pid_file = shell_single_quote(&pid_file.display().to_string()),
    );

    let applescript = format!(
        "do shell script \"{}\" with administrator privileges",
        applescript_escape(&shell_cmd)
    );

    let status = Command::new("osascript")
        .arg("-e")
        .arg(&applescript)
        .status()?;
    if !status.success() {
        return Err("macOS elevation prompt was cancelled or failed".into());
    }

    for _ in 0..30 {
        if let Ok(raw) = std::fs::read_to_string(&pid_file)
            && let Ok(pid) = raw.trim().parse::<u32>()
        {
            let _ = std::fs::remove_file(&pid_file);
            return Ok(pid);
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    warn!("Daemon started via elevation, but PID file was not available yet");
    let _ = std::fs::remove_file(&pid_file);
    Ok(0)
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

    // Prefer IPC check first (works across privilege boundaries).
    if pmacs_vpn::ipc::daemon_is_alive().await {
        println!("VPN is already running (daemon reachable via IPC)");
        println!("Use 'pmacs-vpn disconnect' first, or 'pmacs-vpn status' to check.");
        return Err("VPN already connected".into());
    }

    // Check persisted state as a fallback.
    if let Ok(Some(state)) = pmacs_vpn::VpnState::load() {
        if state.pid.is_some() && state.is_daemon_running() {
            println!("VPN is already running (PID: {:?})", state.pid);
            println!("Use 'pmacs-vpn disconnect' first, or 'pmacs-vpn status' to check.");
            return Err("VPN already connected".into());
        } else if state.pid.is_some() {
            // Daemon was running but is now dead - clean up stale state
            println!("Cleaning up stale VPN state from previous session...");
            // Can't call async cleanup from here easily, just delete state
            let _ = pmacs_vpn::VpnState::delete();
        }
    }

    // 1. Load config (daemon mode requires existing config)
    let config_path = get_config_path();
    let config = if config_path.exists() {
        match pmacs_vpn::Config::load(&config_path) {
            Ok(config) => config,
            Err(e) => {
                eprintln!("Error loading config file: {}", e);
                eprintln!();
                eprintln!("Your config file may be corrupted. Options:");
                eprintln!("  1. Fix the syntax error in pmacs-vpn.toml");
                eprintln!("  2. Delete pmacs-vpn.toml and run 'pmacs-vpn connect' to recreate");
                return Err(e.into());
            }
        }
    } else {
        println!("No config found. Run 'pmacs-vpn connect' first to set up.");
        return Err("No config file".into());
    };

    // 2. Get username
    let (username, username_was_prompted) = if let Some(u) = user.clone() {
        (u, false) // from --user arg
    } else if let Some(u) = config.vpn.username.clone() {
        (u, false) // from config
    } else {
        (prompt("Username", None), true) // prompted
    };

    // 3. Handle --forget-password
    if forget_password {
        if let Err(e) = pmacs_vpn::delete_password(&username) {
            warn!("Could not delete stored password: {}", e);
        } else {
            info!("Deleted stored password for {}", username);
        }
    }

    // 4. Get password (from keychain or prompt)
    let (mut password, mut was_cached) =
        get_vpn_password(&username, forget_password).map_err(|e| e.to_string())?;

    // 5. Do auth flow
    println!("Authenticating...");
    let prelogin = gp::auth::prelogin(&config.vpn.gateway).await?;
    info!("Auth method: {:?}", prelogin.auth_method);

    // Get DUO method from config
    let duo_method = &config.preferences.duo_method;

    // Login loop with password retry on auth failure
    let login = loop {
        let duo_passcode = if *duo_method == pmacs_vpn::DuoMethod::Passcode {
            let code = rpassword::prompt_password("DUO passcode: ")?;
            Some(code)
        } else {
            None
        };

        println!("Logging in ({})...", duo_method.description());
        if *duo_method == pmacs_vpn::DuoMethod::Push {
            notifications::notify_duo_push();
        }
        let duo_str = duo_passcode.as_deref().or_else(|| duo_method.as_auth_str());

        match gp::auth::login(&config.vpn.gateway, &username, &password, duo_str).await {
            Ok(login) => break login,
            Err(gp::AuthError::AuthFailed(msg)) => {
                eprintln!("Login failed: {}", msg);
                if was_cached {
                    eprintln!("(Saved password may be stale)");
                }
                eprintln!();
                let prompt = format!("Password for {}: ", username);
                password = rpassword::prompt_password(&prompt)?;
                was_cached = false;
                continue;
            }
            Err(e) => return Err(e.into()),
        }
    };
    println!("Login successful!");

    // 6. Save password if requested or offer to save
    let should_save = prompt_save_password(save_password, was_cached).map_err(|e| e.to_string())?;

    if should_save {
        match pmacs_vpn::store_password(&username, &password) {
            Ok(()) => println!("VPN password saved to Keychain"),
            Err(e) => warn!("Failed to store password: {}", e),
        }
    }

    // Save username to config if it was prompted
    if username_was_prompted {
        let mut updated_config = config.clone();
        updated_config.vpn.username = Some(username.clone());
        if let Err(e) = updated_config.save(&config_path) {
            warn!("Failed to save username to config: {}", e);
        }
    }

    // 7. Save auth token for daemon (include IPC path)
    let ipc_path = pmacs_vpn::ipc::ipc_path();
    let token = AuthToken::with_ipc_path(
        config.vpn.gateway.clone(),
        login.username.clone(),
        login.auth_cookie.clone(),
        login.portal.clone(),
        login.domain.clone(),
        config.hosts.clone(),
        keep_alive,
        ipc_path,
    );
    token.save()?;

    // 8. Spawn daemon child (it will read the token file)
    let exe = std::env::current_exe()?;

    #[cfg(target_os = "macos")]
    if !is_admin() {
        info!("Spawning daemon via macOS administrator prompt");
        return spawn_daemon_via_macos_elevation(&exe);
    }

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

/// Get VPN password from keychain or prompt user
/// Returns (password, was_cached) where was_cached indicates if password came from keychain
fn get_vpn_password(username: &str, forget_password: bool) -> Result<(String, bool), String> {
    #[cfg(target_os = "macos")]
    {
        // On macOS, accessing the keychain may trigger a system dialog.
        // This dialog asks for your Mac login password (not PMACS password).
        // Click "Always Allow" to prevent future prompts.
    }

    if !forget_password {
        match pmacs_vpn::get_password(username) {
            Some(stored) => {
                println!("Using saved password from keychain");
                Ok((stored, true))
            }
            None => {
                println!("No saved VPN password found.");
                println!("Enter your PMACS VPN password (for GlobalProtect, not SSH):");
                let prompt = format!("Password for {}: ", username);
                let password = rpassword::prompt_password(&prompt)
                    .map_err(|e| format!("Failed to read password: {}", e))?;
                Ok((password, false))
            }
        }
    } else {
        println!("Enter your PMACS VPN password (for GlobalProtect, not SSH):");
        let prompt = format!("Password for {}: ", username);
        let password = rpassword::prompt_password(&prompt)
            .map_err(|e| format!("Failed to read password: {}", e))?;
        Ok((password, false))
    }
}

/// Determine if password should be saved to keychain
/// Returns true if password should be saved, false otherwise
fn prompt_save_password(save_password_flag: bool, was_cached: bool) -> Result<bool, String> {
    if save_password_flag {
        Ok(true)
    } else if !was_cached {
        // First-time user - ask if they want to save
        println!();
        println!("Save VPN password to macOS Keychain?");
        println!("  (If yes, future connections won't ask for this password)");
        print!("[Y/n]: ");
        std::io::Write::flush(&mut std::io::stdout())
            .map_err(|e| format!("Failed to flush stdout: {}", e))?;
        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .map_err(|e| format!("Failed to read input: {}", e))?;
        let input = input.trim().to_lowercase();
        Ok(input.is_empty() || input == "y" || input == "yes")
    } else {
        Ok(false)
    }
}

/// Connect to VPN using native GlobalProtect implementation
async fn connect_vpn(
    user: Option<String>,
    save_password: bool,
    forget_password: bool,
    keep_alive: bool,
    is_daemon: bool,
) -> Result<(), Box<dyn std::error::Error>> {
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

    // Check if VPN is already connected
    if let Ok(Some(state)) = pmacs_vpn::VpnState::load() {
        if state.pid.is_some() && state.is_daemon_running() {
            println!("VPN is already running (PID: {:?})", state.pid);
            println!("Use 'pmacs-vpn disconnect' first, or 'pmacs-vpn status' to check.");
            return Ok(());
        } else if state.pid.is_some() {
            // Daemon was running but is now dead - clean up stale state
            println!("Cleaning up stale VPN state from previous session...");
            cleanup_vpn(&state).await?;
        }
        // If no PID, it was a foreground session that didn't clean up properly
        // Proceed with new connection, routes will be overwritten
    }

    // Normal interactive flow
    // 1. Load or create config interactively
    let config_path = get_config_path();
    let (config, save_config) = if config_path.exists() {
        match pmacs_vpn::Config::load(&config_path) {
            Ok(config) => (config, false),
            Err(e) => {
                eprintln!("Error loading config file: {}", e);
                eprintln!();
                eprintln!("Your config file may be corrupted. Options:");
                eprintln!("  1. Fix the syntax error in pmacs-vpn.toml");
                eprintln!("  2. Delete pmacs-vpn.toml and run 'pmacs-vpn connect' to recreate");
                eprintln!("  3. Run 'pmacs-vpn init' to generate a fresh config");
                return Err(e.into());
            }
        }
    } else {
        // First-time setup: just ask for username, use sensible defaults
        println!("First-time setup:\n");

        let username_input = prompt("PennKey username", None);

        let config = pmacs_vpn::Config {
            vpn: pmacs_vpn::VpnConfig {
                gateway: "psomvpn.uphs.upenn.edu".to_string(),
                protocol: "gp".to_string(),
                username: Some(username_input),
            },
            hosts: vec!["prometheus.pmacs.upenn.edu".to_string()],
            preferences: pmacs_vpn::Preferences::default(),
        };

        // Auto-save config
        config.save(&config_path)?;
        println!("Config saved.\n");

        (config, false) // already saved above
    };

    // Save config if user requested
    if save_config {
        config.save(&config_path)?;
        println!("Config saved to pmacs-vpn.toml\n");
    }

    // 2. Get username (from arg, config, or prompt)
    let (username, username_was_prompted) = if let Some(u) = user {
        (u, false) // from --user arg, don't auto-save
    } else if let Some(u) = config.vpn.username.clone() {
        (u, false) // from config, already saved
    } else {
        (prompt("Username", None), true) // prompted, should save
    };

    // 3. Handle --forget-password: delete stored password before prompting
    if forget_password {
        if let Err(e) = pmacs_vpn::delete_password(&username) {
            warn!("Could not delete stored password: {}", e);
        } else {
            info!("Deleted stored password for {}", username);
        }
    }

    // 4. Get password (from keychain or prompt)
    let (mut password, mut was_cached) = get_vpn_password(&username, forget_password)?;

    // 5. Auth flow
    println!("Authenticating...");
    let prelogin = gp::auth::prelogin(&config.vpn.gateway).await?;
    info!("Auth method: {:?}", prelogin.auth_method);

    // Get DUO method from config
    let duo_method = &config.preferences.duo_method;

    // Login loop with password retry on auth failure
    let login = loop {
        let duo_passcode = if *duo_method == pmacs_vpn::DuoMethod::Passcode {
            let code = rpassword::prompt_password("DUO passcode: ")?;
            Some(code)
        } else {
            None
        };

        println!("Logging in ({})...", duo_method.description());
        if *duo_method == pmacs_vpn::DuoMethod::Push {
            notifications::notify_duo_push();
        }
        let duo_str = duo_passcode.as_deref().or_else(|| duo_method.as_auth_str());

        match gp::auth::login(&config.vpn.gateway, &username, &password, duo_str).await {
            Ok(login) => break login,
            Err(gp::AuthError::AuthFailed(msg)) => {
                eprintln!("Login failed: {}", msg);
                if was_cached {
                    eprintln!("(Saved password may be stale)");
                }
                eprintln!();
                let prompt = format!("Password for {}: ", username);
                password = rpassword::prompt_password(&prompt)?;
                was_cached = false;
                continue;
            }
            Err(e) => return Err(e.into()),
        }
    };
    println!("Login successful!");

    // 6. Save password if requested or offer to save
    let should_save = prompt_save_password(save_password, was_cached).map_err(|e| e.to_string())?;

    if should_save {
        match pmacs_vpn::store_password(&username, &password) {
            Ok(()) => println!("VPN password saved to Keychain"),
            Err(e) => warn!("Failed to store password: {}", e),
        }
    }

    // Save username to config if it was prompted (not from --user or config)
    if username_was_prompted {
        let mut updated_config = config.clone();
        updated_config.vpn.username = Some(username.clone());
        if let Err(e) = updated_config.save(&config_path) {
            warn!("Failed to save username to config: {}", e);
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
        Some(config.preferences.inbound_timeout_secs as u64),
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
    let tunnel_handle = tokio::spawn(async move { tunnel.run().await });

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

    // Show one-time tip about Touch ID on macOS
    #[cfg(target_os = "macos")]
    {
        // Check if Touch ID for sudo is configured
        if let Ok(pam_sudo) = std::fs::read_to_string("/etc/pam.d/sudo")
            && !pam_sudo.contains("pam_tid.so")
        {
            println!();
            println!("TIP: Enable Touch ID for sudo to skip password prompts.");
            println!("     See README.md for instructions.");
        }
    }

    // 13. Wait for tunnel completion or shutdown signal
    let result = {
        #[cfg(unix)]
        {
            let mut sigterm = signal(SignalKind::terminate())?;
            let mut sighup = signal(SignalKind::hangup())?;

            tokio::select! {
                result = tunnel_handle => {
                    match result {
                        Ok(Ok(())) => Ok(()),
                        Ok(Err(e)) => Err(Box::new(e) as Box<dyn std::error::Error>),
                        Err(e) => Err(Box::new(e) as Box<dyn std::error::Error>),
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("Received interrupt signal");
                    println!("\nDisconnecting...");
                    Ok(())
                }
                _ = sigterm.recv() => {
                    info!("Received SIGTERM");
                    println!("\nDisconnecting...");
                    Ok(())
                }
                _ = sighup.recv() => {
                    info!("Received SIGHUP");
                    println!("\nDisconnecting...");
                    Ok(())
                }
            }
        }
        #[cfg(not(unix))]
        {
            tokio::select! {
                result = tunnel_handle => {
                    match result {
                        Ok(Ok(())) => Ok(()),
                        Ok(Err(e)) => Err(Box::new(e) as Box<dyn std::error::Error>),
                        Err(e) => Err(Box::new(e) as Box<dyn std::error::Error>),
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("Received interrupt signal");
                    println!("\nDisconnecting...");
                    Ok(())
                }
            }
        }
    };

    // 12. Cleanup
    cleanup_vpn(&state).await?;

    result
}

/// Connect to VPN using pre-authenticated token (daemon child)
async fn connect_vpn_with_token(token: AuthToken) -> Result<(), Box<dyn std::error::Error>> {
    use pmacs_vpn::ipc::{DaemonState, IpcServer, cleanup_ipc};

    info!("Daemon: connecting with auth token...");

    // Load config for timeout settings
    let config_path = get_config_path();
    let inbound_timeout = if config_path.exists() {
        pmacs_vpn::Config::load(&config_path)
            .map(|c| c.preferences.inbound_timeout_secs as u64)
            .unwrap_or(45)
    } else {
        45 // default
    };

    // Get IPC path from token (or use default)
    let ipc_path = token
        .ipc_path
        .clone()
        .unwrap_or_else(pmacs_vpn::ipc::ipc_path);

    // Get tunnel config using the auth cookie
    let tunnel_config = gp::auth::getconfig_with_cookie(
        &token.gateway,
        &token.username,
        &token.auth_cookie,
        &token.portal,
        &token.domain,
        None,
    )
    .await?;
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
        Some(inbound_timeout),
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
    let tunnel_handle = tokio::spawn(async move { tunnel.run().await });

    // Give the tunnel a moment to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Add routes
    let router = VpnRouter::with_interface(gateway_ip.clone(), tun_name.clone())?;
    let mut state = pmacs_vpn::VpnState::new(tun_name.clone(), internal_ip);

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

    // Start IPC server for tray communication
    let daemon_state = DaemonState::new(tun_name, gateway_ip, state.connected_at.clone());
    let (ipc_server, mut ipc_shutdown_rx) = IpcServer::new(ipc_path.clone(), daemon_state);

    // Run IPC server in background
    let ipc_handle = tokio::spawn(async move {
        if let Err(e) = ipc_server.run().await {
            warn!("IPC server error: {}", e);
        }
    });

    info!("Daemon: VPN ready, IPC server listening");

    // Wait for tunnel completion, shutdown signal, or IPC disconnect request
    let result = {
        #[cfg(unix)]
        {
            let mut sigterm = signal(SignalKind::terminate())?;
            let mut sighup = signal(SignalKind::hangup())?;

            tokio::select! {
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
                _ = sigterm.recv() => {
                    info!("Daemon: received SIGTERM");
                    Ok(())
                }
                _ = sighup.recv() => {
                    info!("Daemon: received SIGHUP");
                    Ok(())
                }
                Ok(()) = ipc_shutdown_rx.recv() => {
                    info!("Daemon: received IPC disconnect request");
                    Ok(())
                }
            }
        }
        #[cfg(not(unix))]
        {
            tokio::select! {
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
                Ok(()) = ipc_shutdown_rx.recv() => {
                    info!("Daemon: received IPC disconnect request");
                    Ok(())
                }
            }
        }
    };

    // Stop IPC server
    ipc_handle.abort();
    cleanup_ipc(&ipc_path);

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

    // Remove routes using stored IPs (don't resolve - VPN may be down)
    let router = VpnRouter::new(state.gateway.to_string())?;
    for route in &state.routes {
        if let Err(e) = router.remove_ip_route(&route.ip.to_string()) {
            error!(
                "Failed to remove route for {} ({}): {}",
                route.hostname, route.ip, e
            );
        }
    }

    // Delete state file
    pmacs_vpn::VpnState::delete()?;

    Ok(())
}
