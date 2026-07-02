//! Diagnostic probe: replicate dialog::prompt_password's CredUI call and print the raw
//! Win32 result code. Run with: cargo run --release --example credui_probe [variant]
//! variant: "current" (default, null target name) | "target" (with target name)
#[cfg(target_os = "windows")]
fn main() {
    use windows::Win32::Foundation::BOOL;
    use windows::Win32::Foundation::HWND;
    use windows::Win32::Security::Credentials::{
        CREDUI_FLAGS_ALWAYS_SHOW_UI, CREDUI_FLAGS_DO_NOT_PERSIST, CREDUI_FLAGS_GENERIC_CREDENTIALS,
        CREDUI_INFOW, CredUIPromptForCredentialsW,
    };
    use windows::core::{HSTRING, PCWSTR};

    let variant = std::env::args().nth(1).unwrap_or_else(|| "current".into());

    let mut username_buf = [0u16; 514];
    let mut password_buf = [0u16; 514];
    let mut save = BOOL(0);

    let user_wide: Vec<u16> = "yjk".encode_utf16().chain(std::iter::once(0)).collect();
    username_buf[..user_wide.len()].copy_from_slice(&user_wide);

    let title_h = HSTRING::from("PMACS VPN \u{2014} probe");
    let target_h = HSTRING::from("pmacs-vpn");

    let info = CREDUI_INFOW {
        cbSize: std::mem::size_of::<CREDUI_INFOW>() as u32,
        hwndParent: HWND(std::ptr::null_mut()),
        pszMessageText: PCWSTR::null(),
        pszCaptionText: PCWSTR::from_raw(title_h.as_ptr()),
        hbmBanner: Default::default(),
    };

    let flags = CREDUI_FLAGS_GENERIC_CREDENTIALS
        | CREDUI_FLAGS_ALWAYS_SHOW_UI
        | CREDUI_FLAGS_DO_NOT_PERSIST;

    let target = match variant.as_str() {
        "target" => PCWSTR::from_raw(target_h.as_ptr()),
        _ => PCWSTR::null(),
    };

    let result = unsafe {
        CredUIPromptForCredentialsW(
            Some(&info),
            target,
            None,
            0,
            &mut username_buf,
            &mut password_buf,
            Some(&mut save),
            flags,
        )
    };

    // Zero the password buffer before exit; we only care about the result code.
    password_buf.fill(0);
    println!("variant={} result={:?}", variant, result);
}

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("windows-only probe");
}
