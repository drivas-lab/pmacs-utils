//! Native Windows dialogs
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Foundation::{BOOL, HWND};
use windows::Win32::Security::Credentials::{
    CredUIPromptForCredentialsW, CREDUI_FLAGS_ALWAYS_SHOW_UI, CREDUI_FLAGS_DO_NOT_PERSIST,
    CREDUI_FLAGS_GENERIC_CREDENTIALS, CREDUI_INFOW,
};
use windows::Win32::UI::WindowsAndMessaging::{
    MessageBoxW, MB_ICONERROR, MB_ICONINFORMATION, MB_OK,
};

/// Prompt for credentials - using native Windows CredUI
pub fn prompt_credentials(title: &str, message: &str) -> Option<(String, String)> {
    prompt_creds_internal(title, message, None)
}

/// Prompt for password only - pre-filling username
pub fn prompt_password(title: &str, username: &str) -> Option<String> {
    prompt_creds_internal(title, "", Some(username)).map(|(_, pwd)| pwd)
}

fn prompt_creds_internal(
    title: &str,
    message: &str,
    username: Option<&str>,
) -> Option<(String, String)> {
    let mut username_buf = [0u16; 514]; // CREDUI_MAX_USERNAME_LENGTH + 1
    let mut password_buf = [0u16; 514]; // CREDUI_MAX_PASSWORD_LENGTH + safety
    let mut save = BOOL(0);

    // Pre-fill username if provided
    if let Some(user) = username {
        let user_wide: Vec<u16> = user.encode_utf16().chain(std::iter::once(0)).collect();
        if user_wide.len() <= username_buf.len() {
             username_buf[..user_wide.len()].copy_from_slice(&user_wide);
        }
    }

    let message_h = HSTRING::from(message);
    let title_h = HSTRING::from(title);

    let info = CREDUI_INFOW {
        cbSize: std::mem::size_of::<CREDUI_INFOW>() as u32,
        hwndParent: HWND(0),
        pszMessageText: if message.is_empty() {
            PCWSTR::null()
        } else {
            PCWSTR::from_raw(message_h.as_ptr())
        },
        pszCaptionText: PCWSTR::from_raw(title_h.as_ptr()),
        hbmBanner: Default::default(),
    };

    let flags = CREDUI_FLAGS_GENERIC_CREDENTIALS
        | CREDUI_FLAGS_ALWAYS_SHOW_UI
        | CREDUI_FLAGS_DO_NOT_PERSIST;

    let result = unsafe {
        CredUIPromptForCredentialsW(
            Some(&info),
            PCWSTR::null(),
            None,
            0,
            Some(&mut username_buf),
            Some(&mut password_buf),
            Some(&mut save),
            flags,
        )
    };

    if result == 0 { // NO_ERROR
         let username = String::from_utf16_lossy(&username_buf)
            .trim_matches(char::from(0))
            .to_string();
        let password = String::from_utf16_lossy(&password_buf)
            .trim_matches(char::from(0))
            .to_string();
        Some((username, password))
    } else {
        None
    }
}

/// Show a message dialog
pub fn show_message(title: &str, message: &str, is_error: bool) {
    let title = HSTRING::from(title);
    let message = HSTRING::from(message);
    
    let icon = if is_error {
        MB_ICONERROR
    } else {
        MB_ICONINFORMATION
    };

    unsafe {
        MessageBoxW(HWND(0), PCWSTR::from_raw(message.as_ptr()), PCWSTR::from_raw(title.as_ptr()), MB_OK | icon);
    }
}