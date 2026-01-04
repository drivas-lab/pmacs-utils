# macOS UX Implementation Plan

**Goal:** Seamless VPN experience for non-technical users (wet lab)

## Config Structure

```toml
hosts = ["prometheus.pmacs.upenn.edu"]

[vpn]
gateway = "psomvpn.uphs.upenn.edu"
username = "yjk"

[preferences]
save_password = true        # Store in macOS Keychain
duo_method = "push"         # push | sms | call | passcode
start_at_login = false      # LaunchAgent
auto_connect = true         # Connect on tray launch if creds cached
```

## Menu Bar Design

```
┌─────────────────────────┐
│ ● Connected (10.5.2.3)  │
├─────────────────────────┤
│ Disconnect              │
├─────────────────────────┤
│ ✓ Save Password         │
│ ○ Start at Login        │
│ DUO Method          ▶   │
│   ● Push                │
│   ○ SMS                 │
│   ○ Call                │
│   ○ Passcode            │
├─────────────────────────┤
│ Quit                    │
└─────────────────────────┘
```

## Implementation Tasks

### 1. Config Expansion (`src/config.rs`)
- Add `Preferences` struct with fields above
- Add `DuoMethod` enum
- Backward compatible (missing section = defaults)

### 2. First-Run Password UX (`src/main.rs`)
- Clearer prompt: "Enter VPN password for yjk@psomvpn.uphs.upenn.edu:"
- After success, ask: "Save password to Keychain? [Y/n]"
- Update config with preference

### 3. macOS Notifications (`src/notifications.rs`)
- Add `notify-rust` crate (cross-platform)
- Implement for macOS:
  - `notify_duo_push()` - "Check your phone for DUO push"
  - `notify_connected()` - "Connected successfully"
  - `notify_disconnected()` - "Disconnected"

### 4. Menu Bar App (`src/tray.rs`)
- Remove Windows-only guards where applicable
- Add preference checkboxes to menu
- Add DUO method submenu
- Save changes to config on toggle

### 5. LaunchAgent (`src/startup.rs`)
- Create `~/Library/LaunchAgents/com.pmacs.vpn.plist`
- Functions: `enable_start_at_login()`, `disable_start_at_login()`, `is_start_at_login_enabled()`

### 6. Auth Flow Updates (`src/gp/auth.rs`)
- Support DUO methods beyond push
- Pass method from config to login request

## File Changes Summary

| File | Changes |
|------|---------|
| `Cargo.toml` | Add `notify-rust` |
| `src/config.rs` | Add `Preferences`, `DuoMethod` |
| `src/main.rs` | First-run UX, load preferences |
| `src/notifications.rs` | macOS support via notify-rust |
| `src/tray.rs` | Preference menu items, cross-platform |
| `src/startup.rs` | LaunchAgent for macOS |
| `src/gp/auth.rs` | DUO method parameter |

## Testing

1. `cargo build --release` on macOS
2. `./target/release/pmacs-vpn tray` launches menu bar
3. Clicking toggles saves to config
4. Start at Login creates/removes LaunchAgent
5. DUO method submenu changes auth behavior
6. Notifications appear for DUO/connect/disconnect
