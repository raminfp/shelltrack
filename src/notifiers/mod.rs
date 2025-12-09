pub mod telegram;

pub use telegram::TelegramNotifier;

use crate::collectors::CommandEvent;
use crate::detectors::Alert;
use anyhow::Result;
use async_trait::async_trait;

#[async_trait]
pub trait Notifier: Send + Sync {
    async fn send_alert(&self, alert: &Alert, hostname: &str) -> Result<()>;
    async fn send_command_log(&self, event: &CommandEvent, hostname: &str) -> Result<()>;
}
