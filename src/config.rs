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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            vpn: VpnConfig {
                gateway: "psomvpn.uphs.upenn.edu".to_string(),
                protocol: "gp".to_string(),
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
