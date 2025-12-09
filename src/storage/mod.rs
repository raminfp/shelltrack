pub mod r2;

pub use r2::R2Storage;

use crate::collectors::CommandEvent;
use crate::detectors::Alert;
use anyhow::Result;
use async_trait::async_trait;

#[async_trait]
pub trait Storage: Send + Sync {
    async fn store_alert(&self, alert: &Alert) -> Result<String>;
    async fn store_command(&self, event: &CommandEvent) -> Result<String>;
    async fn store_session_log(&self, session_id: &str, commands: &[CommandEvent]) -> Result<String>;
}
