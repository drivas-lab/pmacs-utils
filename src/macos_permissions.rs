//! macOS permission diagnostics for tray mode.
//!
//! These checks are focused on permissions commonly required by input/hotkey
//! features. pmacs-vpn tray itself does not require these today, but this
//! diagnostic helps users preflight future capabilities.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionState {
    Granted,
    Missing,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct PermissionDiagnostics {
    pub accessibility: PermissionState,
    pub input_monitoring: PermissionState,
}

impl PermissionDiagnostics {
    pub fn lines(&self) -> Vec<String> {
        let mut lines = vec![
            format!("Accessibility: {}", state_label(self.accessibility)),
            format!("Input Monitoring: {}", state_label(self.input_monitoring)),
        ];

        if self.accessibility == PermissionState::Missing {
            lines.push(
                "Grant in System Settings -> Privacy & Security -> Accessibility".to_string(),
            );
        }

        if self.input_monitoring == PermissionState::Missing {
            lines.push(
                "Grant in System Settings -> Privacy & Security -> Input Monitoring".to_string(),
            );
        }

        if self.accessibility == PermissionState::Granted
            && self.input_monitoring == PermissionState::Granted
        {
            lines.push(
                "No extra input permissions are required for current tray features.".to_string(),
            );
        } else {
            lines.push(
                "These permissions are only needed for future hotkey/input capture features."
                    .to_string(),
            );
        }

        lines
    }
}

fn state_label(state: PermissionState) -> &'static str {
    match state {
        PermissionState::Granted => "granted",
        PermissionState::Missing => "missing",
        PermissionState::Unknown => "unknown",
    }
}

#[cfg(target_os = "macos")]
#[link(name = "ApplicationServices", kind = "framework")]
unsafe extern "C" {
    fn AXIsProcessTrusted() -> bool;
    fn CGPreflightListenEventAccess() -> bool;
}

pub fn collect_permissions_diagnostics() -> PermissionDiagnostics {
    #[cfg(target_os = "macos")]
    {
        let accessibility = unsafe {
            if AXIsProcessTrusted() {
                PermissionState::Granted
            } else {
                PermissionState::Missing
            }
        };

        let input_monitoring = unsafe {
            if CGPreflightListenEventAccess() {
                PermissionState::Granted
            } else {
                PermissionState::Missing
            }
        };

        PermissionDiagnostics {
            accessibility,
            input_monitoring,
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        PermissionDiagnostics {
            accessibility: PermissionState::Unknown,
            input_monitoring: PermissionState::Unknown,
        }
    }
}
