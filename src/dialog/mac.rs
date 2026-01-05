//! Native macOS dialogs using Cocoa/AppKit
//!
//! Uses NSAlert with NSSecureTextField for password prompts,
//! avoiding osascript which gets SIGKILL'd when called from background threads.

use objc2::{MainThreadMarker, MainThreadOnly};
use objc2_app_kit::{NSAlert, NSAlertStyle, NSApplication, NSSecureTextField, NSTextField, NSView};
use objc2_foundation::{NSPoint, NSRect, NSSize, NSString};

/// Response constant for first button (Connect)
/// NSAlertFirstButtonReturn = 1000
const NS_ALERT_FIRST_BUTTON_RETURN: isize = 1000;

/// Prompt for username and password using native NSAlert with accessory view
///
/// Must be called from the main thread on macOS.
pub fn prompt_credentials(title: &str, message: &str) -> Option<(String, String)> {
    // Get main thread marker - returns None if not on main thread
    let mtm = match MainThreadMarker::new() {
        Some(m) => m,
        None => {
            tracing::error!("prompt_credentials must be called from the main thread");
            return None;
        }
    };

    prompt_credentials_impl(mtm, title, message)
}

fn prompt_credentials_impl(
    mtm: MainThreadMarker,
    title: &str,
    message: &str,
) -> Option<(String, String)> {
    // Ensure NSApplication is initialized
    let _app = NSApplication::sharedApplication(mtm);

    // Create alert
    let alert = NSAlert::new(mtm);
    alert.setAlertStyle(NSAlertStyle::Informational);
    alert.setMessageText(&NSString::from_str(title));
    alert.setInformativeText(&NSString::from_str(message));

    // Add buttons (first button = default/Enter, second = Cancel/Escape)
    alert.addButtonWithTitle(&NSString::from_str("Connect"));
    alert.addButtonWithTitle(&NSString::from_str("Cancel"));

    // Create container view for username + password fields
    let container_frame = NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(300.0, 54.0));
    let container = NSView::initWithFrame(NSView::alloc(mtm), container_frame);

    // Username field (top)
    let username_frame = NSRect::new(NSPoint::new(0.0, 30.0), NSSize::new(300.0, 22.0));
    let username_field = NSTextField::initWithFrame(NSTextField::alloc(mtm), username_frame);
    username_field.setPlaceholderString(Some(&NSString::from_str("Username (PennKey)")));
    container.addSubview(&username_field);

    // Password field (bottom)
    let password_frame = NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(300.0, 22.0));
    let password_field =
        NSSecureTextField::initWithFrame(NSSecureTextField::alloc(mtm), password_frame);
    password_field.setPlaceholderString(Some(&NSString::from_str("Password")));
    container.addSubview(&password_field);

    // Set accessory view
    alert.setAccessoryView(Some(&container));

    // Make username field first responder
    let window = alert.window();
    window.setInitialFirstResponder(Some(&username_field));

    // Run modal
    let response = alert.runModal();

    // Check if Connect was clicked (NSModalResponse is a type alias for isize)
    if response == NS_ALERT_FIRST_BUTTON_RETURN {
        let username = username_field.stringValue().to_string();
        let password = password_field.stringValue().to_string();

        if !username.is_empty() && !password.is_empty() {
            return Some((username, password));
        }
    }

    None
}

/// Prompt for password only (username already known)
///
/// Must be called from the main thread on macOS.
pub fn prompt_password(title: &str, username: &str) -> Option<String> {
    let mtm = match MainThreadMarker::new() {
        Some(m) => m,
        None => {
            tracing::error!("prompt_password must be called from the main thread");
            return None;
        }
    };

    prompt_password_impl(mtm, title, username)
}

fn prompt_password_impl(mtm: MainThreadMarker, title: &str, username: &str) -> Option<String> {
    let _app = NSApplication::sharedApplication(mtm);

    let alert = NSAlert::new(mtm);
    alert.setAlertStyle(NSAlertStyle::Informational);
    alert.setMessageText(&NSString::from_str(title));
    alert.setInformativeText(&NSString::from_str(&format!(
        "Enter password for {}",
        username
    )));

    alert.addButtonWithTitle(&NSString::from_str("Connect"));
    alert.addButtonWithTitle(&NSString::from_str("Cancel"));

    // Password field
    let frame = NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(300.0, 22.0));
    let password_field = NSSecureTextField::initWithFrame(NSSecureTextField::alloc(mtm), frame);
    password_field.setPlaceholderString(Some(&NSString::from_str("Password")));

    alert.setAccessoryView(Some(&password_field));

    let window = alert.window();
    window.setInitialFirstResponder(Some(&password_field));

    let response = alert.runModal();

    if response == NS_ALERT_FIRST_BUTTON_RETURN {
        let password = password_field.stringValue().to_string();
        if !password.is_empty() {
            return Some(password);
        }
    }

    None
}

/// Show a simple message dialog
pub fn show_message(title: &str, message: &str, is_error: bool) {
    let mtm = match MainThreadMarker::new() {
        Some(m) => m,
        None => {
            // Fall back to logging if not on main thread
            if is_error {
                tracing::error!("{}: {}", title, message);
            } else {
                tracing::info!("{}: {}", title, message);
            }
            return;
        }
    };

    let _app = NSApplication::sharedApplication(mtm);

    let alert = NSAlert::new(mtm);
    alert.setAlertStyle(if is_error {
        NSAlertStyle::Critical
    } else {
        NSAlertStyle::Informational
    });
    alert.setMessageText(&NSString::from_str(title));
    alert.setInformativeText(&NSString::from_str(message));
    alert.addButtonWithTitle(&NSString::from_str("OK"));

    alert.runModal();
}
