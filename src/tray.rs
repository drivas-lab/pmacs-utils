//! System tray integration for pmacs-vpn
//!
//! Provides a system tray icon with context menu for VPN control.
//! Uses the `tray-icon` crate with `tao` for the event loop.

use std::sync::mpsc;
use tao::event::{Event, StartCause};
use tao::event_loop::{ControlFlow, EventLoopBuilder};
#[cfg(target_os = "windows")]
use tao::platform::windows::EventLoopBuilderExtWindows;
use tray_icon::menu::{CheckMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem, Submenu};
use tray_icon::{TrayIcon, TrayIconBuilder, TrayIconEvent};
use tracing::{debug, error, info};

use crate::config::DuoMethod;
use crate::notifications;
use crate::startup;

// Platform-specific startup menu label
#[cfg(target_os = "windows")]
const STARTUP_LABEL: &str = "Start with Windows";
#[cfg(not(target_os = "windows"))]
const STARTUP_LABEL: &str = "Start at Login";

/// Commands that can be sent from the tray to the VPN controller
#[derive(Debug, Clone)]
pub enum TrayCommand {
    /// Start VPN connection
    Connect,
    /// Stop VPN connection
    Disconnect,
    /// Show status window (future)
    ShowStatus,
    /// Exit the application
    Exit,
    /// Toggle save password preference
    ToggleSavePassword,
    /// Set DUO authentication method
    SetDuoMethod(DuoMethod),
}

/// VPN state updates sent from the VPN controller to the tray
#[derive(Debug, Clone, PartialEq)]
pub enum VpnStatus {
    Disconnected,
    Connecting,
    Connected { ip: String },
    Disconnecting,
    Error(String),
}

/// Custom event for the tray event loop
enum UserEvent {
    TrayIcon(TrayIconEvent),
    Menu(MenuEvent),
    VpnStatus(VpnStatus),
}

/// Tray application state
pub struct TrayApp {
    command_tx: mpsc::Sender<TrayCommand>,
    status_rx: mpsc::Receiver<VpnStatus>,
    auto_connect: bool,
    save_password: bool,
    duo_method: DuoMethod,
}

impl TrayApp {
    /// Create a new tray application
    ///
    /// Returns the app and channels for communication:
    /// - command_rx: Receive commands from tray (connect, disconnect, etc.)
    /// - status_tx: Send VPN status updates to tray
    ///
    /// If `auto_connect` is true, the tray will send a Connect command on startup.
    pub fn new(
        auto_connect: bool,
        save_password: bool,
        duo_method: DuoMethod,
    ) -> (Self, mpsc::Receiver<TrayCommand>, mpsc::Sender<VpnStatus>) {
        let (command_tx, command_rx) = mpsc::channel();
        let (status_tx, status_rx) = mpsc::channel();

        let app = Self {
            command_tx,
            status_rx,
            auto_connect,
            save_password,
            duo_method,
        };

        (app, command_rx, status_tx)
    }

    /// Run the tray application (blocking)
    ///
    /// This function runs the platform event loop and never returns
    /// until the user exits the application.
    pub fn run(self) -> ! {
        info!("Starting system tray application");

        // Build event loop with custom user events
        // On Windows, allow running on non-main thread (we're spawned from tokio)
        #[cfg(target_os = "windows")]
        let event_loop = EventLoopBuilder::<UserEvent>::with_user_event()
            .with_any_thread(true)
            .build();
        #[cfg(not(target_os = "windows"))]
        let event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
        let proxy = event_loop.create_proxy();

        // Set up event handlers to forward tray/menu events into event loop
        let proxy_clone = proxy.clone();
        TrayIconEvent::set_event_handler(Some(move |event| {
            let _ = proxy_clone.send_event(UserEvent::TrayIcon(event));
        }));

        let proxy_clone = proxy.clone();
        MenuEvent::set_event_handler(Some(move |event| {
            let _ = proxy_clone.send_event(UserEvent::Menu(event));
        }));

        // Create menu items
        let status_item = MenuItem::new("Status: Disconnected", false, None);
        let connect_item = MenuItem::new("Connect", true, None);
        let disconnect_item = MenuItem::new("Disconnect", false, None);

        // Preferences menu items
        let save_password_item = CheckMenuItem::new("Save Password", true, self.save_password, None);

        // DUO method submenu
        let duo_submenu = Submenu::new("DUO Method", true);
        let duo_push_item = CheckMenuItem::new("Push", true, self.duo_method == DuoMethod::Push, None);
        let duo_sms_item = CheckMenuItem::new("SMS", true, self.duo_method == DuoMethod::Sms, None);
        let duo_call_item = CheckMenuItem::new("Call", true, self.duo_method == DuoMethod::Call, None);
        let duo_passcode_item = CheckMenuItem::new("Passcode", true, self.duo_method == DuoMethod::Passcode, None);

        duo_submenu.append_items(&[
            &duo_push_item,
            &duo_sms_item,
            &duo_call_item,
            &duo_passcode_item,
        ]).expect("Failed to build DUO submenu");

        let startup_item = CheckMenuItem::new(STARTUP_LABEL, true, startup::is_startup_enabled(), None);
        let exit_item = MenuItem::new("Exit", true, None);

        // Store item IDs for event matching
        let connect_id = connect_item.id().clone();
        let disconnect_id = disconnect_item.id().clone();
        let save_password_id = save_password_item.id().clone();
        let duo_push_id = duo_push_item.id().clone();
        let duo_sms_id = duo_sms_item.id().clone();
        let duo_call_id = duo_call_item.id().clone();
        let duo_passcode_id = duo_passcode_item.id().clone();
        let startup_id = startup_item.id().clone();
        let exit_id = exit_item.id().clone();

        // Build menu
        let menu = Menu::new();
        menu.append_items(&[
            &status_item,
            &PredefinedMenuItem::separator(),
            &connect_item,
            &disconnect_item,
            &PredefinedMenuItem::separator(),
            &save_password_item,
            &duo_submenu,
            &startup_item,
            &PredefinedMenuItem::separator(),
            &exit_item,
        ])
        .expect("Failed to build menu");

        // Tray icon will be created after event loop starts
        let mut tray_icon: Option<TrayIcon> = None;
        let mut current_status = VpnStatus::Disconnected;
        let command_tx = self.command_tx;
        let status_rx = self.status_rx;
        let auto_connect = self.auto_connect;
        let mut auto_connect_sent = false;

        // Spawn a thread to forward status updates
        let proxy_clone = proxy.clone();
        std::thread::spawn(move || {
            while let Ok(status) = status_rx.recv() {
                let _ = proxy_clone.send_event(UserEvent::VpnStatus(status));
            }
        });

        // Run the event loop (never returns)
        event_loop.run(move |event, _elwt, control_flow| {
            *control_flow = ControlFlow::Wait;

            match event {
                Event::NewEvents(StartCause::Init) => {
                    // Create tray icon after event loop starts
                    debug!("Creating tray icon");
                    let icon = create_disconnected_icon();
                    tray_icon = Some(
                        TrayIconBuilder::new()
                            .with_menu(Box::new(menu.clone()))
                            .with_tooltip("PMACS VPN - Disconnected")
                            .with_icon(icon)
                            .build()
                            .expect("Failed to create tray icon"),
                    );
                    info!("Tray icon created successfully");

                    // Auto-connect if credentials are cached
                    if auto_connect && !auto_connect_sent {
                        info!("Auto-connecting on startup");
                        let _ = command_tx.send(TrayCommand::Connect);
                        auto_connect_sent = true;
                    }
                }

                Event::UserEvent(UserEvent::Menu(event)) => {
                    if event.id == connect_id {
                        info!("Tray: Connect clicked");
                        let _ = command_tx.send(TrayCommand::Connect);
                    } else if event.id == disconnect_id {
                        info!("Tray: Disconnect clicked");
                        let _ = command_tx.send(TrayCommand::Disconnect);
                    } else if event.id == save_password_id {
                        info!("Tray: Save Password toggle clicked");
                        let new_state = !save_password_item.is_checked();
                        save_password_item.set_checked(new_state);
                        let _ = command_tx.send(TrayCommand::ToggleSavePassword);
                    } else if event.id == duo_push_id {
                        info!("Tray: DUO Push selected");
                        duo_push_item.set_checked(true);
                        duo_sms_item.set_checked(false);
                        duo_call_item.set_checked(false);
                        duo_passcode_item.set_checked(false);
                        let _ = command_tx.send(TrayCommand::SetDuoMethod(DuoMethod::Push));
                    } else if event.id == duo_sms_id {
                        info!("Tray: DUO SMS selected");
                        duo_push_item.set_checked(false);
                        duo_sms_item.set_checked(true);
                        duo_call_item.set_checked(false);
                        duo_passcode_item.set_checked(false);
                        let _ = command_tx.send(TrayCommand::SetDuoMethod(DuoMethod::Sms));
                    } else if event.id == duo_call_id {
                        info!("Tray: DUO Call selected");
                        duo_push_item.set_checked(false);
                        duo_sms_item.set_checked(false);
                        duo_call_item.set_checked(true);
                        duo_passcode_item.set_checked(false);
                        let _ = command_tx.send(TrayCommand::SetDuoMethod(DuoMethod::Call));
                    } else if event.id == duo_passcode_id {
                        info!("Tray: DUO Passcode selected");
                        duo_push_item.set_checked(false);
                        duo_sms_item.set_checked(false);
                        duo_call_item.set_checked(false);
                        duo_passcode_item.set_checked(true);
                        let _ = command_tx.send(TrayCommand::SetDuoMethod(DuoMethod::Passcode));
                    } else if event.id == startup_id {
                        info!("Tray: Startup toggle clicked");
                        match startup::toggle_startup() {
                            Ok(enabled) => {
                                startup_item.set_checked(enabled);
                                info!("Startup {}", if enabled { "enabled" } else { "disabled" });
                            }
                            Err(e) => {
                                error!("Failed to toggle startup: {}", e);
                            }
                        }
                    } else if event.id == exit_id {
                        info!("Tray: Exit clicked");

                        // Kill daemon synchronously before exiting
                        // (can't rely on async handler - event loop exits immediately)
                        if let Ok(Some(state)) = crate::VpnState::load() {
                            if state.pid.is_some() && state.is_daemon_running() {
                                info!("Killing VPN daemon before exit");
                                let _ = state.kill_daemon();
                            }
                        }

                        let _ = command_tx.send(TrayCommand::Exit);
                        *control_flow = ControlFlow::Exit;
                    }
                }

                Event::UserEvent(UserEvent::VpnStatus(status)) => {
                    if status != current_status {
                        debug!("VPN status changed: {:?}", status);

                        // Notifications are sent from main.rs command handlers
                        // Only handle error notifications here (not sent elsewhere)
                        if let VpnStatus::Error(msg) = &status {
                            notifications::notify_error(msg);
                        }

                        // Update menu items based on status
                        match &status {
                            VpnStatus::Disconnected => {
                                status_item.set_text("Status: Disconnected");
                                connect_item.set_enabled(true);
                                disconnect_item.set_enabled(false);
                            }
                            VpnStatus::Connecting => {
                                status_item.set_text("Status: Connecting...");
                                connect_item.set_enabled(false);
                                disconnect_item.set_enabled(false);
                            }
                            VpnStatus::Connected { ip } => {
                                status_item.set_text(format!("Status: Connected ({})", ip));
                                connect_item.set_enabled(false);
                                disconnect_item.set_enabled(true);
                            }
                            VpnStatus::Disconnecting => {
                                status_item.set_text("Status: Disconnecting...");
                                connect_item.set_enabled(false);
                                disconnect_item.set_enabled(false);
                            }
                            VpnStatus::Error(_) => {
                                status_item.set_text("Status: Error");
                                connect_item.set_enabled(true);
                                disconnect_item.set_enabled(false);
                            }
                        }

                        current_status = status.clone();
                        if let Some(ref tray) = tray_icon {
                            update_tray_for_status(tray, &status);
                        }
                    }
                }

                Event::UserEvent(UserEvent::TrayIcon(event)) => {
                    debug!("Tray icon event: {:?}", event);
                    // Handle double-click to toggle connection (optional)
                }

                _ => {}
            }
        })
    }
}

/// Create a simple colored icon for disconnected state
fn create_disconnected_icon() -> tray_icon::Icon {
    // Create a simple 16x16 red/gray icon
    create_solid_icon(128, 128, 128, 255) // Gray
}

/// Create a simple colored icon for connected state
fn create_connected_icon() -> tray_icon::Icon {
    create_solid_icon(0, 180, 0, 255) // Green
}

/// Create a simple colored icon for connecting state
fn create_connecting_icon() -> tray_icon::Icon {
    create_solid_icon(255, 180, 0, 255) // Orange/Yellow
}

/// Create a simple colored icon for error state
fn create_error_icon() -> tray_icon::Icon {
    create_solid_icon(220, 50, 50, 255) // Red
}

/// Create a solid-color 16x16 icon
fn create_solid_icon(r: u8, g: u8, b: u8, a: u8) -> tray_icon::Icon {
    let size = 16u32;
    let mut rgba = Vec::with_capacity((size * size * 4) as usize);

    // Create a simple circle icon
    let center = size as f32 / 2.0;
    let radius = center - 1.0;

    for y in 0..size {
        for x in 0..size {
            let dx = x as f32 - center;
            let dy = y as f32 - center;
            let dist = (dx * dx + dy * dy).sqrt();

            if dist <= radius {
                // Inside circle - use color
                rgba.push(r);
                rgba.push(g);
                rgba.push(b);
                rgba.push(a);
            } else if dist <= radius + 1.0 {
                // Edge - anti-aliased
                let alpha = ((radius + 1.0 - dist) * a as f32) as u8;
                rgba.push(r);
                rgba.push(g);
                rgba.push(b);
                rgba.push(alpha);
            } else {
                // Outside - transparent
                rgba.push(0);
                rgba.push(0);
                rgba.push(0);
                rgba.push(0);
            }
        }
    }

    tray_icon::Icon::from_rgba(rgba, size, size).expect("Failed to create icon")
}

/// Update tray icon and tooltip based on VPN status
fn update_tray_for_status(tray: &TrayIcon, status: &VpnStatus) {
    let (icon, tooltip) = match status {
        VpnStatus::Disconnected => (create_disconnected_icon(), "PMACS VPN - Disconnected"),
        VpnStatus::Connecting => (create_connecting_icon(), "PMACS VPN - Connecting..."),
        VpnStatus::Connected { ip } => {
            let tooltip = format!("PMACS VPN - Connected ({})", ip);
            // Leak the string since set_tooltip needs &str with static lifetime behavior
            // This is fine since we only have a few status changes
            let tooltip_static: &'static str = Box::leak(tooltip.into_boxed_str());
            (create_connected_icon(), tooltip_static)
        }
        VpnStatus::Disconnecting => (create_connecting_icon(), "PMACS VPN - Disconnecting..."),
        VpnStatus::Error(msg) => {
            let tooltip = format!("PMACS VPN - Error: {}", msg);
            let tooltip_static: &'static str = Box::leak(tooltip.into_boxed_str());
            (create_error_icon(), tooltip_static)
        }
    };

    if let Err(e) = tray.set_icon(Some(icon)) {
        error!("Failed to set tray icon: {}", e);
    }
    if let Err(e) = tray.set_tooltip(Some(tooltip)) {
        error!("Failed to set tooltip: {}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vpn_status_equality() {
        assert_eq!(VpnStatus::Disconnected, VpnStatus::Disconnected);
        assert_eq!(VpnStatus::Connecting, VpnStatus::Connecting);
        assert_ne!(VpnStatus::Disconnected, VpnStatus::Connecting);
    }

    #[test]
    fn test_vpn_status_connected() {
        let s1 = VpnStatus::Connected {
            ip: "10.0.0.1".to_string(),
        };
        let s2 = VpnStatus::Connected {
            ip: "10.0.0.1".to_string(),
        };
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_create_solid_icon() {
        // Just verify it doesn't panic
        let _icon = create_solid_icon(255, 0, 0, 255);
        let _icon = create_disconnected_icon();
        let _icon = create_connected_icon();
        let _icon = create_connecting_icon();
        let _icon = create_error_icon();
    }

    #[test]
    fn test_tray_command_clone() {
        let cmd = TrayCommand::Connect;
        let _cmd2 = cmd.clone();
    }
}
