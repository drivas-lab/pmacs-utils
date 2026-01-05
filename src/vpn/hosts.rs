//! /etc/hosts file management for VPN hostnames

use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::IpAddr;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum HostsError {
    #[error("Failed to read hosts file: {0}")]
    ReadError(#[from] io::Error),
}

const HOSTS_MARKER_START: &str = "# BEGIN pmacs-vpn";
const HOSTS_MARKER_END: &str = "# END pmacs-vpn";

pub struct HostsManager {
    path: String,
}

impl HostsManager {
    pub fn new() -> Self {
        Self {
            path: if cfg!(windows) {
                r"C:\Windows\System32\drivers\etc\hosts".to_string()
            } else {
                "/etc/hosts".to_string()
            },
        }
    }

    pub fn with_path(path: String) -> Self {
        Self { path }
    }

    pub fn add_entries(&self, entries: &HashMap<String, IpAddr>) -> Result<(), HostsError> {
        let content = fs::read_to_string(&self.path)?;
        let new_content = self.update_content(&content, entries);
        fs::write(&self.path, new_content)?;
        Ok(())
    }

    pub fn remove_entries(&self) -> Result<(), HostsError> {
        let content = fs::read_to_string(&self.path)?;
        let new_content = self.remove_managed_section(&content);
        fs::write(&self.path, new_content)?;
        Ok(())
    }

    fn update_content(&self, content: &str, entries: &HashMap<String, IpAddr>) -> String {
        let cleaned = self.remove_managed_section(content);
        let mut result = cleaned.trim_end().to_string();

        if !entries.is_empty() {
            result.push_str("\n\n");
            result.push_str(HOSTS_MARKER_START);
            result.push('\n');
            for (hostname, ip) in entries {
                result.push_str(&format!("{}\t{}\n", ip, hostname));
            }
            result.push_str(HOSTS_MARKER_END);
            result.push('\n');
        }

        result
    }

    fn remove_managed_section(&self, content: &str) -> String {
        let mut result = String::new();
        let mut in_managed_section = false;

        for line in content.lines() {
            if line.trim() == HOSTS_MARKER_START {
                in_managed_section = true;
                continue;
            }
            if line.trim() == HOSTS_MARKER_END {
                in_managed_section = false;
                continue;
            }
            if !in_managed_section {
                result.push_str(line);
                result.push('\n');
            }
        }

        result
    }
}

impl Default for HostsManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use tempfile::TempDir;

    fn create_test_manager(temp_dir: &TempDir, filename: &str, content: &str) -> HostsManager {
        let path = temp_dir.path().join(filename);
        fs::write(&path, content).unwrap();
        HostsManager::with_path(path.to_string_lossy().to_string())
    }

    #[test]
    fn test_default_path_unix() {
        let manager = HostsManager::new();
        if cfg!(unix) {
            assert_eq!(manager.path, "/etc/hosts");
        }
    }

    #[test]
    fn test_with_path() {
        let manager = HostsManager::with_path("/custom/path".to_string());
        assert_eq!(manager.path, "/custom/path");
    }

    #[test]
    fn test_update_content_adds_section() {
        let manager = HostsManager::with_path(String::new());
        let original = "127.0.0.1\tlocalhost\n";

        let mut entries = HashMap::new();
        entries.insert(
            "test.example.com".to_string(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        );

        let result = manager.update_content(original, &entries);

        assert!(result.contains("127.0.0.1\tlocalhost"));
        assert!(result.contains("# BEGIN pmacs-vpn"));
        assert!(result.contains("10.0.0.1\ttest.example.com"));
        assert!(result.contains("# END pmacs-vpn"));
    }

    #[test]
    fn test_update_content_empty_entries() {
        let manager = HostsManager::with_path(String::new());
        let original = "127.0.0.1\tlocalhost\n";

        let entries = HashMap::new();
        let result = manager.update_content(original, &entries);

        assert!(result.contains("127.0.0.1\tlocalhost"));
        assert!(!result.contains("# BEGIN pmacs-vpn"));
        assert!(!result.contains("# END pmacs-vpn"));
    }

    #[test]
    fn test_update_content_replaces_existing_section() {
        let manager = HostsManager::with_path(String::new());
        let original = "127.0.0.1\tlocalhost\n\
                        # BEGIN pmacs-vpn\n\
                        10.0.0.1\told.example.com\n\
                        # END pmacs-vpn\n\
                        ::1\tlocalhost\n";

        let mut entries = HashMap::new();
        entries.insert(
            "new.example.com".to_string(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        );

        let result = manager.update_content(original, &entries);

        assert!(result.contains("127.0.0.1\tlocalhost"));
        assert!(result.contains("::1\tlocalhost"));
        assert!(!result.contains("old.example.com"));
        assert!(result.contains("10.0.0.2\tnew.example.com"));
    }

    #[test]
    fn test_remove_managed_section() {
        let manager = HostsManager::with_path(String::new());
        let content = "127.0.0.1\tlocalhost\n\
                       # BEGIN pmacs-vpn\n\
                       10.0.0.1\ttest.example.com\n\
                       # END pmacs-vpn\n\
                       ::1\tlocalhost\n";

        let result = manager.remove_managed_section(content);

        assert!(result.contains("127.0.0.1\tlocalhost"));
        assert!(result.contains("::1\tlocalhost"));
        assert!(!result.contains("# BEGIN pmacs-vpn"));
        assert!(!result.contains("test.example.com"));
        assert!(!result.contains("# END pmacs-vpn"));
    }

    #[test]
    fn test_remove_managed_section_no_section() {
        let manager = HostsManager::with_path(String::new());
        let content = "127.0.0.1\tlocalhost\n::1\tlocalhost\n";

        let result = manager.remove_managed_section(content);

        assert!(result.contains("127.0.0.1\tlocalhost"));
        assert!(result.contains("::1\tlocalhost"));
    }

    #[test]
    fn test_add_entries_file_operations() {
        let temp_dir = TempDir::new().unwrap();
        let original_content = "127.0.0.1\tlocalhost\n";
        let manager = create_test_manager(&temp_dir, "hosts", original_content);

        let mut entries = HashMap::new();
        entries.insert(
            "test.example.com".to_string(),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        );

        manager.add_entries(&entries).unwrap();

        let content = fs::read_to_string(&manager.path).unwrap();
        assert!(content.contains("# BEGIN pmacs-vpn"));
        assert!(content.contains("192.168.1.100\ttest.example.com"));
        assert!(content.contains("# END pmacs-vpn"));
    }

    #[test]
    fn test_remove_entries_file_operations() {
        let temp_dir = TempDir::new().unwrap();
        let original_content = "127.0.0.1\tlocalhost\n\
                                # BEGIN pmacs-vpn\n\
                                10.0.0.1\ttest.example.com\n\
                                # END pmacs-vpn\n";
        let manager = create_test_manager(&temp_dir, "hosts", original_content);

        manager.remove_entries().unwrap();

        let content = fs::read_to_string(&manager.path).unwrap();
        assert!(content.contains("127.0.0.1\tlocalhost"));
        assert!(!content.contains("# BEGIN pmacs-vpn"));
        assert!(!content.contains("test.example.com"));
    }

    #[test]
    fn test_ipv6_address() {
        let manager = HostsManager::with_path(String::new());
        let original = "127.0.0.1\tlocalhost\n";

        let mut entries = HashMap::new();
        entries.insert(
            "ipv6.example.com".to_string(),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        );

        let result = manager.update_content(original, &entries);

        assert!(result.contains("2001:db8::1\tipv6.example.com"));
    }

    #[test]
    fn test_multiple_entries() {
        let manager = HostsManager::with_path(String::new());
        let original = "127.0.0.1\tlocalhost\n";

        let mut entries = HashMap::new();
        entries.insert(
            "host1.example.com".to_string(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        );
        entries.insert(
            "host2.example.com".to_string(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        );

        let result = manager.update_content(original, &entries);

        assert!(result.contains("10.0.0.1\thost1.example.com"));
        assert!(result.contains("10.0.0.2\thost2.example.com"));
    }
}
