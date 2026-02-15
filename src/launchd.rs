//! macOS LaunchDaemon management for VPN daemon
//!
//! This module handles installing/uninstalling a privileged daemon via launchd.
//! The daemon runs as root and starts the VPN connection automatically.

use std::path::Path;
use std::process::Command;
use tracing::{debug, info};

/// LaunchDaemon label
pub const DAEMON_LABEL: &str = "com.pmacs.vpn.daemon";

/// Path to the LaunchDaemon plist
pub const DAEMON_PLIST_PATH: &str = "/Library/LaunchDaemons/com.pmacs.vpn.daemon.plist";

/// Trigger file that launchd watches to start the daemon
pub const TRIGGER_FILE: &str = "/tmp/pmacs-vpn-connect-trigger";

/// Generate the LaunchDaemon plist content
///
/// # Arguments
/// * `exe_path` - Path to the pmacs-vpn executable
/// * `working_dir` - Directory containing pmacs-vpn.toml
///
/// # Returns
/// XML plist string suitable for LaunchDaemon
pub fn generate_daemon_plist(exe_path: &Path, working_dir: &Path) -> String {
    let exe_path_str = exe_path.display();
    let working_dir_str = working_dir.display();

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
        <string>connect</string>
        <string>--daemon-pid=1</string>
    </array>
    <key>WorkingDirectory</key>
    <string>{}</string>
    <key>RunAtLoad</key>
    <false/>
    <key>WatchPaths</key>
    <array>
        <string>{}</string>
    </array>
    <key>KeepAlive</key>
    <false/>
    <key>StandardOutPath</key>
    <string>/tmp/pmacs-vpn-daemon.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/pmacs-vpn-daemon.log</string>
</dict>
</plist>"#,
        DAEMON_LABEL, exe_path_str, working_dir_str, TRIGGER_FILE
    )
}

/// Escape a string for use in AppleScript
fn applescript_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Install and start the VPN daemon via launchd
///
/// Uses osascript with admin privileges to:
/// 1. Write plist to /Library/LaunchDaemons/
/// 2. Set ownership to root:wheel
/// 3. Set permissions to 644
/// 4. Run launchctl load
///
/// # Arguments
/// * `exe_path` - Path to the pmacs-vpn executable
/// * `working_dir` - Directory containing pmacs-vpn.toml
///
/// # Returns
/// Ok(()) on success, Err with message on failure
pub fn install_and_start_daemon(exe_path: &Path, working_dir: &Path) -> Result<(), String> {
    info!("Installing LaunchDaemon: {}", DAEMON_LABEL);
    debug!("Executable: {}", exe_path.display());
    debug!("Working directory: {}", working_dir.display());

    let plist_content = generate_daemon_plist(exe_path, working_dir);

    // Build the shell command that will run with admin privileges
    let shell_cmd = format!(
        r#"launchctl unload {} 2>/dev/null
rm -f {}
cat > {} << 'PLIST_EOF'
{}
PLIST_EOF
chown root:wheel {}
chmod 644 {}
launchctl load -w {}"#,
        DAEMON_PLIST_PATH,
        TRIGGER_FILE,
        DAEMON_PLIST_PATH,
        plist_content,
        DAEMON_PLIST_PATH,
        DAEMON_PLIST_PATH,
        DAEMON_PLIST_PATH
    );

    let escaped_shell_cmd = applescript_escape(&shell_cmd);

    let applescript = format!(
        r#"do shell script "{}" with administrator privileges"#,
        escaped_shell_cmd
    );

    debug!("Executing osascript for daemon installation");
    let status = Command::new("osascript")
        .arg("-e")
        .arg(&applescript)
        .status()
        .map_err(|e| format!("Failed to execute osascript: {}", e))?;
    if !status.success() {
        return Err("LaunchDaemon installation was cancelled or failed".to_string());
    }

    info!("LaunchDaemon installation completed");
    Ok(())
}

/// Stop and uninstall the VPN daemon
///
/// Uses osascript with admin privileges to:
/// 1. Run launchctl unload (ignore errors if not loaded)
/// 2. Remove plist file
///
/// # Returns
/// Ok(()) on success, Err with message on failure
pub fn stop_and_uninstall_daemon() -> Result<(), String> {
    info!("Stopping and uninstalling LaunchDaemon: {}", DAEMON_LABEL);

    // Build the shell command that will run with admin privileges
    // Use 2>/dev/null to ignore errors if daemon is not loaded
    let shell_cmd = format!(
        r#"launchctl unload {} 2>/dev/null; rm -f {}; rm -f {}"#,
        DAEMON_PLIST_PATH, DAEMON_PLIST_PATH, TRIGGER_FILE
    );

    let escaped_shell_cmd = applescript_escape(&shell_cmd);

    let applescript = format!(
        r#"do shell script "{}" with administrator privileges"#,
        escaped_shell_cmd
    );

    debug!("Executing osascript for daemon uninstallation");
    let status = Command::new("osascript")
        .arg("-e")
        .arg(&applescript)
        .status()
        .map_err(|e| format!("Failed to execute osascript: {}", e))?;
    if !status.success() {
        return Err("LaunchDaemon uninstallation was cancelled or failed".to_string());
    }

    info!("LaunchDaemon uninstallation completed");
    Ok(())
}

/// Check if the daemon plist exists
///
/// # Returns
/// true if the plist file exists, false otherwise
pub fn is_daemon_installed() -> bool {
    Path::new(DAEMON_PLIST_PATH).exists()
}

/// Check whether installed daemon plist matches current executable and working dir.
pub fn is_daemon_plist_current(exe_path: &Path, working_dir: &Path) -> bool {
    let actual = match std::fs::read_to_string(DAEMON_PLIST_PATH) {
        Ok(v) => v,
        Err(_) => return false,
    };

    let expected = generate_daemon_plist(exe_path, working_dir);
    actual == expected
}

/// Trigger the daemon to start by touching the trigger file
///
/// launchd watches this file and starts the daemon when it changes.
/// This requires NO privileges. The trigger file owner is later used to
/// assign IPC socket ownership back to the tray user.
pub fn trigger_daemon_start() -> Result<(), String> {
    use std::fs::OpenOptions;

    info!("Triggering daemon start via {}", TRIGGER_FILE);

    // Touch the file (create or update mtime)
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(TRIGGER_FILE)
        .map_err(|e| format!("Failed to create trigger file: {}", e))?;

    info!("Trigger file created - launchd should start daemon");
    Ok(())
}

/// Remove the trigger file
pub fn remove_trigger_file() {
    let _ = std::fs::remove_file(TRIGGER_FILE);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_generate_daemon_plist() {
        let exe_path = PathBuf::from("/usr/local/bin/pmacs-vpn");
        let working_dir = PathBuf::from("/etc/pmacs-vpn");

        let plist = generate_daemon_plist(&exe_path, &working_dir);

        // Verify key elements are present
        assert!(plist.contains("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(plist.contains("<plist version=\"1.0\">"));
        assert!(plist.contains(DAEMON_LABEL));
        assert!(plist.contains("/usr/local/bin/pmacs-vpn"));
        assert!(plist.contains("<string>connect</string>"));
        assert!(plist.contains("<string>--daemon-pid=1</string>"));
        assert!(plist.contains("/etc/pmacs-vpn"));
        assert!(plist.contains("<key>RunAtLoad</key>"));
        assert!(plist.contains("<key>WatchPaths</key>"));
        assert!(plist.contains(TRIGGER_FILE));
        assert!(plist.contains("<key>KeepAlive</key>"));
        assert!(plist.contains("<false/>"));
        assert!(plist.contains("/tmp/pmacs-vpn-daemon.log"));
    }

    #[test]
    fn test_applescript_escape() {
        assert_eq!(applescript_escape("hello"), "hello");
        assert_eq!(applescript_escape("hello\"world"), "hello\\\"world");
        assert_eq!(applescript_escape("path\\to\\file"), "path\\\\to\\\\file");
        assert_eq!(applescript_escape("path\\to\"file"), "path\\\\to\\\"file");
    }

    #[test]
    fn test_daemon_label() {
        assert_eq!(DAEMON_LABEL, "com.pmacs.vpn.daemon");
    }

    #[test]
    fn test_daemon_plist_path() {
        assert_eq!(
            DAEMON_PLIST_PATH,
            "/Library/LaunchDaemons/com.pmacs.vpn.daemon.plist"
        );
    }
}
