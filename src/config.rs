//! Configuration handling for PMACS VPN

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Failed to read config file: {0}")]
    ReadError(#[from] std::io::Error),
    #[error("Failed to parse config: {0}")]
    ParseError(#[from] toml::de::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub vpn: VpnConfig,
    pub hosts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnConfig {
    pub gateway: String,
    pub protocol: String,
    /// Username for VPN authentication (optional, will prompt if not set)
    #[serde(default)]
    pub username: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            vpn: VpnConfig {
                gateway: "psomvpn.uphs.upenn.edu".to_string(),
                protocol: "gp".to_string(),
                username: None,
            },
            hosts: vec!["prometheus.pmacs.upenn.edu".to_string()],
        }
    }
}

impl Config {
    pub fn load(path: &PathBuf) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    pub fn save(&self, path: &PathBuf) -> Result<(), ConfigError> {
        let content = toml::to_string_pretty(self).expect("Failed to serialize config");
        std::fs::write(path, content)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.vpn.gateway, "psomvpn.uphs.upenn.edu");
        assert_eq!(config.vpn.protocol, "gp");
        assert_eq!(config.hosts.len(), 1);
        assert_eq!(config.hosts[0], "prometheus.pmacs.upenn.edu");
    }

    #[test]
    fn test_save_and_load_config() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("test-config.toml");

        let config = Config::default();
        config.save(&config_path).unwrap();

        let loaded = Config::load(&config_path).unwrap();
        assert_eq!(loaded.vpn.gateway, config.vpn.gateway);
        assert_eq!(loaded.vpn.protocol, config.vpn.protocol);
        assert_eq!(loaded.hosts, config.hosts);
    }

    #[test]
    fn test_custom_config_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("custom-config.toml");

        let config = Config {
            vpn: VpnConfig {
                gateway: "custom.vpn.example.com".to_string(),
                protocol: "anyconnect".to_string(),
                username: Some("testuser".to_string()),
            },
            hosts: vec![
                "host1.example.com".to_string(),
                "host2.example.com".to_string(),
            ],
        };
        config.save(&config_path).unwrap();

        let loaded = Config::load(&config_path).unwrap();
        assert_eq!(loaded.vpn.gateway, "custom.vpn.example.com");
        assert_eq!(loaded.vpn.protocol, "anyconnect");
        assert_eq!(loaded.hosts.len(), 2);
    }

    #[test]
    fn test_load_nonexistent_file() {
        let path = PathBuf::from("/nonexistent/path/config.toml");
        let result = Config::load(&path);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_invalid_toml() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("invalid.toml");

        std::fs::write(&config_path, "this is not valid toml {{{{").unwrap();

        let result = Config::load(&config_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_config_serialization_format() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("format-test.toml");

        let config = Config::default();
        config.save(&config_path).unwrap();

        let content = std::fs::read_to_string(&config_path).unwrap();
        assert!(content.contains("[vpn]"));
        assert!(content.contains("gateway"));
        assert!(content.contains("protocol"));
        assert!(content.contains("hosts"));
    }
}
