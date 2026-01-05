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
    #[error("Failed to serialize config: {0}")]
    SerializeError(#[from] toml::ser::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DuoMethod {
    #[default]
    Push,
    Sms,
    Call,
    Passcode,
}

impl DuoMethod {
    /// Convert to the string used by GlobalProtect auth API
    pub fn as_auth_str(&self) -> Option<&'static str> {
        match self {
            DuoMethod::Push => Some("push"),
            DuoMethod::Sms => Some("sms1"),  // DUO uses sms1 for first SMS
            DuoMethod::Call => Some("phone1"), // DUO uses phone1 for first phone
            DuoMethod::Passcode => None,  // User will be prompted for passcode
        }
    }

    /// Get user-friendly description for prompts
    pub fn description(&self) -> &'static str {
        match self {
            DuoMethod::Push => "DUO push",
            DuoMethod::Sms => "DUO SMS",
            DuoMethod::Call => "DUO phone call",
            DuoMethod::Passcode => "DUO passcode",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Preferences {
    /// Save password to OS keychain
    #[serde(default = "default_true")]
    pub save_password: bool,

    /// DUO authentication method
    #[serde(default)]
    pub duo_method: DuoMethod,

    /// Start VPN at system login
    #[serde(default)]
    pub start_at_login: bool,

    /// Auto-connect when tray starts (if credentials cached)
    #[serde(default = "default_true")]
    pub auto_connect: bool,
}

fn default_true() -> bool {
    true
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            save_password: true,
            duo_method: DuoMethod::default(),
            start_at_login: false,
            auto_connect: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub vpn: VpnConfig,
    pub hosts: Vec<String>,
    #[serde(default)]
    pub preferences: Preferences,
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
            preferences: Preferences::default(),
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
        let content = toml::to_string_pretty(self)?;
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
            preferences: Preferences::default(),
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

    #[test]
    fn test_preferences_default() {
        let prefs = Preferences::default();
        assert!(prefs.save_password);
        assert_eq!(prefs.duo_method, DuoMethod::Push);
        assert!(!prefs.start_at_login);
        assert!(prefs.auto_connect);
    }

    #[test]
    fn test_preferences_serialization() {
        let prefs = Preferences {
            save_password: false,
            duo_method: DuoMethod::Sms,
            start_at_login: true,
            auto_connect: false,
        };

        let toml_str = toml::to_string(&prefs).unwrap();
        assert!(toml_str.contains("save_password = false"));
        assert!(toml_str.contains("duo_method = \"sms\""));
        assert!(toml_str.contains("start_at_login = true"));
        assert!(toml_str.contains("auto_connect = false"));
    }

    #[test]
    fn test_preferences_deserialization() {
        let toml_str = r#"
            save_password = false
            duo_method = "call"
            start_at_login = true
            auto_connect = false
        "#;

        let prefs: Preferences = toml::from_str(toml_str).unwrap();
        assert!(!prefs.save_password);
        assert_eq!(prefs.duo_method, DuoMethod::Call);
        assert!(prefs.start_at_login);
        assert!(!prefs.auto_connect);
    }

    #[test]
    fn test_duo_method_values() {
        // Test that all enum variants work correctly
        let methods = vec![
            DuoMethod::Push,
            DuoMethod::Sms,
            DuoMethod::Call,
            DuoMethod::Passcode,
        ];

        for method in methods {
            // Ensure they can be cloned and compared
            let cloned = method.clone();
            assert_eq!(method, cloned);
        }

        // Test default
        assert_eq!(DuoMethod::default(), DuoMethod::Push);
    }

    #[test]
    fn test_duo_method_in_preferences_serialization() {
        // Test serialization in context of a struct
        let prefs = Preferences {
            save_password: true,
            duo_method: DuoMethod::Sms,
            start_at_login: false,
            auto_connect: true,
        };

        let toml_str = toml::to_string(&prefs).unwrap();
        assert!(toml_str.contains("duo_method = \"sms\""));

        // Test deserialization
        let deserialized: Preferences = toml::from_str(&toml_str).unwrap();
        assert_eq!(deserialized.duo_method, DuoMethod::Sms);
    }

    #[test]
    fn test_config_with_preferences() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("prefs-test.toml");

        let mut config = Config::default();
        config.preferences.save_password = false;
        config.preferences.duo_method = DuoMethod::Passcode;
        config.preferences.start_at_login = true;

        config.save(&config_path).unwrap();
        let loaded = Config::load(&config_path).unwrap();

        assert!(!loaded.preferences.save_password);
        assert_eq!(loaded.preferences.duo_method, DuoMethod::Passcode);
        assert!(loaded.preferences.start_at_login);
        assert!(loaded.preferences.auto_connect); // Still defaults to true
    }

    #[test]
    fn test_backward_compatibility_missing_preferences() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("old-config.toml");

        // Simulate an old config file without preferences section
        let old_config = r#"hosts = ["prometheus.pmacs.upenn.edu"]

[vpn]
gateway = "psomvpn.uphs.upenn.edu"
protocol = "gp"
"#;

        std::fs::write(&config_path, old_config).unwrap();

        let loaded = Config::load(&config_path).unwrap();

        // Should use default preferences
        assert!(loaded.preferences.save_password);
        assert_eq!(loaded.preferences.duo_method, DuoMethod::Push);
        assert!(!loaded.preferences.start_at_login);
        assert!(loaded.preferences.auto_connect);
    }

    #[test]
    fn test_partial_preferences_uses_defaults() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("partial-prefs.toml");

        // Config with only some preference fields
        let partial_config = r#"hosts = ["prometheus.pmacs.upenn.edu"]

[vpn]
gateway = "psomvpn.uphs.upenn.edu"
protocol = "gp"

[preferences]
duo_method = "sms"
"#;

        std::fs::write(&config_path, partial_config).unwrap();

        let loaded = Config::load(&config_path).unwrap();

        // Specified field
        assert_eq!(loaded.preferences.duo_method, DuoMethod::Sms);

        // Unspecified fields should use defaults
        assert!(loaded.preferences.save_password);
        assert!(!loaded.preferences.start_at_login);
        assert!(loaded.preferences.auto_connect);
    }
}
