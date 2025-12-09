use anyhow::Result;
use async_trait::async_trait;
use chrono::Utc;
use s3::bucket::Bucket;
use s3::creds::Credentials;
use s3::region::Region;
use tracing::{debug, info};

use crate::collectors::CommandEvent;
use crate::config::R2Config;
use crate::detectors::Alert;
use super::Storage;

pub struct R2Storage {
    bucket: Box<Bucket>,
}

impl R2Storage {
    pub async fn new(config: &R2Config) -> Result<Self> {
        let credentials = Credentials::new(
            Some(&config.access_key_id),
            Some(&config.secret_access_key),
            None,
            None,
            None,
        )?;

        // R2 endpoint format: https://<account_id>.r2.cloudflarestorage.com
        let endpoint = format!(
            "https://{}.r2.cloudflarestorage.com",
            config.account_id
        );

        let region = Region::Custom {
            region: "auto".to_string(),
            endpoint,
        };

        let bucket = Bucket::new(&config.bucket_name, region, credentials)?
            .with_path_style();

        info!("R2 storage initialized for bucket: {}", config.bucket_name);

        Ok(Self { bucket })
    }

    fn generate_key(prefix: &str, suffix: &str) -> String {
        let now = Utc::now();
        format!(
            "{}/{}/{}/{}-{}",
            prefix,
            now.format("%Y/%m/%d"),
            now.format("%H"),
            now.format("%Y%m%d-%H%M%S-%3f"),
            suffix
        )
    }
}

#[async_trait]
impl Storage for R2Storage {
    async fn store_alert(&self, alert: &Alert) -> Result<String> {
        let (prefix, suffix) = match alert {
            Alert::BruteForceAttempt { ip, .. } => {
                ("alerts/bruteforce", format!("{}.json", ip.replace('.', "-")))
            }
            Alert::SuccessfulLogin { username, ip, .. } => {
                ("alerts/login", format!("{}-{}.json", username, ip.replace('.', "-")))
            }
            Alert::SuspiciousCommand { username, .. } => {
                ("alerts/suspicious", format!("{}.json", username))
            }
            Alert::IpBlocked { ip, .. } => {
                ("alerts/blocked", format!("{}.json", ip.replace('.', "-")))
            }
        };

        let key = Self::generate_key(prefix, &suffix);
        let body = serde_json::to_vec_pretty(alert)?;

        self.bucket
            .put_object_with_content_type(&key, &body, "application/json")
            .await?;

        info!("Stored alert to R2: {}", key);
        Ok(key)
    }

    async fn store_command(&self, event: &CommandEvent) -> Result<String> {
        let key = Self::generate_key(
            &format!("commands/{}", event.username),
            &format!("{}.json", event.pid),
        );

        let body = serde_json::to_vec_pretty(event)?;

        self.bucket
            .put_object_with_content_type(&key, &body, "application/json")
            .await?;

        debug!("Stored command to R2: {}", key);
        Ok(key)
    }

    async fn store_session_log(&self, session_id: &str, commands: &[CommandEvent]) -> Result<String> {
        if commands.is_empty() {
            anyhow::bail!("No commands to store");
        }

        let username = &commands[0].username;
        let key = Self::generate_key(
            &format!("sessions/{}", username),
            &format!("session-{}.json", session_id),
        );

        let session_log = SessionLog {
            session_id: session_id.to_string(),
            username: username.clone(),
            command_count: commands.len(),
            start_time: commands.first().map(|c| c.timestamp),
            end_time: commands.last().map(|c| c.timestamp),
            commands: commands.to_vec(),
        };

        let body = serde_json::to_vec_pretty(&session_log)?;

        self.bucket
            .put_object_with_content_type(&key, &body, "application/json")
            .await?;

        info!("Stored session log to R2: {} ({} commands)", key, commands.len());
        Ok(key)
    }
}

#[derive(serde::Serialize)]
struct SessionLog {
    session_id: String,
    username: String,
    command_count: usize,
    start_time: Option<chrono::DateTime<Utc>>,
    end_time: Option<chrono::DateTime<Utc>>,
    commands: Vec<CommandEvent>,
}

/// Mock storage for testing without R2
pub struct MockStorage;

#[async_trait]
impl Storage for MockStorage {
    async fn store_alert(&self, alert: &Alert) -> Result<String> {
        info!("Mock: would store alert {:?}", alert);
        Ok("mock://alert".to_string())
    }

    async fn store_command(&self, event: &CommandEvent) -> Result<String> {
        debug!("Mock: would store command {:?}", event);
        Ok("mock://command".to_string())
    }

    async fn store_session_log(&self, session_id: &str, commands: &[CommandEvent]) -> Result<String> {
        info!("Mock: would store session {} with {} commands", session_id, commands.len());
        Ok("mock://session".to_string())
    }
}
