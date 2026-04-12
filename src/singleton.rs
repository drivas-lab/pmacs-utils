//! Single-instance enforcement for the tray process.
//!
//! Prevents multiple tray instances from running simultaneously.
//! - Windows: Named mutex (`Global\pmacs-vpn-tray`)
//! - macOS/Linux: Advisory file lock (flock) on `~/.pmacs-vpn/tray.lock`

use tracing::info;

#[cfg(windows)]
mod platform {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Threading::CreateMutexW;
    use windows::core::PCWSTR;

    const MUTEX_NAME: &str = "Global\\pmacs-vpn-tray";

    pub struct TrayLock {
        handle: HANDLE,
    }

    impl TrayLock {
        pub fn acquire() -> Result<Self, String> {
            let wide: Vec<u16> = MUTEX_NAME.encode_utf16().chain(std::iter::once(0)).collect();

            unsafe {
                let handle = CreateMutexW(None, true, PCWSTR::from_raw(wide.as_ptr()))
                    .map_err(|e| format!("CreateMutexW failed: {}", e))?;

                // Check if mutex already existed (another instance holds it)
                let last_error = windows::Win32::Foundation::GetLastError();
                if last_error == windows::Win32::Foundation::ERROR_ALREADY_EXISTS {
                    let _ = CloseHandle(handle);
                    return Err("Another tray instance is already running".to_string());
                }

                Ok(TrayLock { handle })
            }
        }
    }

    impl Drop for TrayLock {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

#[cfg(not(windows))]
mod platform {
    use nix::fcntl::Flock;
    use std::fs::OpenOptions;
    use std::os::fd::OwnedFd;
    use std::path::PathBuf;

    pub struct TrayLock {
        // The Flock guard owns the locked fd — lock is released on drop.
        _flock: Flock<OwnedFd>,
        path: PathBuf,
    }

    fn lock_path() -> Result<PathBuf, String> {
        let home = std::env::var("HOME")
            .map_err(|_| "HOME not set".to_string())?;
        let dir = PathBuf::from(home).join(".pmacs-vpn");
        if !dir.exists() {
            std::fs::create_dir_all(&dir)
                .map_err(|e| format!("Failed to create lock dir: {}", e))?;
        }
        Ok(dir.join("tray.lock"))
    }

    impl TrayLock {
        pub fn acquire() -> Result<Self, String> {
            use nix::fcntl::FlockArg;

            let path = lock_path()?;
            let file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .open(&path)
                .map_err(|e| format!("Failed to open lock file: {}", e))?;

            // Write PID for debugging before converting to OwnedFd
            {
                use std::io::Write;
                let mut f = &file;
                let _ = f.write_all(format!("{}", std::process::id()).as_bytes());
            }

            // Convert File → OwnedFd; Flock::lock takes ownership
            let owned_fd: OwnedFd = file.into();

            // Non-blocking exclusive lock; Flock guard keeps the lock held
            match Flock::lock(owned_fd, FlockArg::LockExclusiveNonblock) {
                Ok(flock) => Ok(TrayLock { _flock: flock, path }),
                Err(_) => Err("Another tray instance is already running".to_string()),
            }
        }
    }

    impl Drop for TrayLock {
        fn drop(&mut self) {
            // Lock is released when _flock drops (unlocks and closes the fd).
            // Remove the lock file for cleanliness.
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

pub use platform::TrayLock;

/// Acquire the singleton tray lock.
/// Returns Ok(guard) if this is the only instance, Err(message) if another is running.
/// The lock is held until the returned guard is dropped.
pub fn acquire_tray_lock() -> Result<TrayLock, String> {
    match TrayLock::acquire() {
        Ok(lock) => {
            info!("Acquired singleton tray lock");
            Ok(lock)
        }
        Err(e) => {
            info!("Singleton check failed: {}", e);
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE: These tests use the real production lock (Global\pmacs-vpn-tray on Windows,
    // ~/.pmacs-vpn/tray.lock on Unix). They will fail if a tray instance is running.
    // Run with: cargo test singleton -- --test-threads=1

    #[test]
    fn test_acquire_lock_succeeds() {
        // First acquisition should succeed
        let lock = acquire_tray_lock();
        assert!(lock.is_ok(), "First lock acquisition should succeed");
        // Lock is dropped here
    }

    #[test]
    fn test_second_lock_fails() {
        let _lock1 = acquire_tray_lock().expect("First lock should succeed");
        let lock2 = acquire_tray_lock();
        assert!(lock2.is_err(), "Second lock acquisition should fail");
    }
}
