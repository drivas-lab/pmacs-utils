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
    #[error("Failed to parse hosts entry")]
    ParseError,
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
