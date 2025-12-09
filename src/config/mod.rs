use serde::Deserialize;
use std::path::Path;
use anyhow::Result;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub general: GeneralConfig,
    pub telegram: TelegramConfig,
    pub r2: R2Config,
    pub detection: DetectionConfig,
    pub paths: PathsConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct GeneralConfig {
    pub log_level: String,
    pub hostname: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TelegramConfig {
    pub enabled: bool,
    pub bot_token: String,
    pub chat_id: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct R2Config {
    pub enabled: bool,
    pub account_id: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub bucket_name: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DetectionConfig {
    pub brute_force_threshold: u32,
    pub brute_force_window_secs: u64,
    pub alert_on_successful_login: bool,
    pub track_commands_after_login: bool,
    #[serde(default = "default_alert_every_n_attempts")]
    pub alert_every_n_attempts: u32,
    #[serde(default)]
    pub auto_block_enabled: bool,
    #[serde(default = "default_auto_block_threshold")]
    pub auto_block_threshold: u32,
    #[serde(default = "default_block_duration_secs")]
    pub block_duration_secs: u64,
}

fn default_auto_block_threshold() -> u32 {
    3
}

fn default_block_duration_secs() -> u64 {
    3600 // 1 hour
}

fn default_alert_every_n_attempts() -> u32 {
    2
}

#[derive(Debug, Deserialize, Clone)]
pub struct PathsConfig {
    pub auth_log: String,
    pub audit_log: String,
}

impl Config {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    pub fn default_path() -> &'static str {
        "/etc/shelltrack/shelltrack.toml"
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            general: GeneralConfig {
                log_level: "info".to_string(),
                hostname: None,
            },
            telegram: TelegramConfig {
                enabled: true,
                bot_token: String::new(),
                chat_id: String::new(),
            },
            r2: R2Config {
                enabled: false,
                account_id: String::new(),
                access_key_id: String::new(),
                secret_access_key: String::new(),
                bucket_name: "shelltrack-logs".to_string(),
            },
            detection: DetectionConfig {
                brute_force_threshold: 3,
                brute_force_window_secs: 60,
                alert_on_successful_login: true,
                track_commands_after_login: true,
                alert_every_n_attempts: 2,
                auto_block_enabled: false,
                auto_block_threshold: 3,
                block_duration_secs: 3600,
            },
            paths: PathsConfig {
                auth_log: "/var/log/auth.log".to_string(),
                audit_log: "/var/log/audit/audit.log".to_string(),
            },
        }
    }
}
