use anyhow::Result;
use async_trait::async_trait;
use reqwest::Client;
use serde::Serialize;
use tracing::{debug, error, info};

use crate::collectors::CommandEvent;
use crate::config::TelegramConfig;
use crate::detectors::Alert;
use super::Notifier;

pub struct TelegramNotifier {
    client: Client,
    bot_token: String,
    chat_id: String,
}

#[derive(Serialize)]
struct SendMessageRequest {
    chat_id: String,
    text: String,
    parse_mode: String,
    disable_web_page_preview: bool,
}

impl TelegramNotifier {
    pub fn new(config: &TelegramConfig) -> Self {
        Self {
            client: Client::new(),
            bot_token: config.bot_token.clone(),
            chat_id: config.chat_id.clone(),
        }
    }

    async fn send_message(&self, text: &str) -> Result<()> {
        let url = format!(
            "https://api.telegram.org/bot{}/sendMessage",
            self.bot_token
        );

        let request = SendMessageRequest {
            chat_id: self.chat_id.clone(),
            text: text.to_string(),
            parse_mode: "HTML".to_string(),
            disable_web_page_preview: true,
        };

        let response = self.client
            .post(&url)
            .json(&request)
            .send()
            .await?;

        if response.status().is_success() {
            debug!("Telegram message sent successfully");
            Ok(())
        } else {
            let error_text = response.text().await?;
            error!("Failed to send Telegram message: {}", error_text);
            anyhow::bail!("Telegram API error: {}", error_text)
        }
    }

    fn format_alert(&self, alert: &Alert, hostname: &str) -> String {
        match alert {
            Alert::BruteForceAttempt {
                timestamp,
                ip,
                attempt_count,
                window_secs,
                usernames,
            } => {
                let emoji = alert.get_emoji();
                let severity = alert.get_severity();
                let usernames_str = if usernames.len() > 5 {
                    format!("{} and {} more",
                        usernames[..5].join(", "),
                        usernames.len() - 5)
                } else {
                    usernames.join(", ")
                };

                format!(
                    "{emoji} <b>BRUTE FORCE DETECTED</b> {emoji}\n\n\
                    <b>Severity:</b> {severity}\n\
                    <b>Host:</b> <code>{hostname}</code>\n\
                    <b>Attacker IP:</b> <code>{ip}</code>\n\
                    <b>Attempts:</b> {attempt_count} in {window_secs}s\n\
                    <b>Targeted Users:</b> <code>{usernames_str}</code>\n\
                    <b>Time:</b> {timestamp}\n\n\
                    #bruteforce #security #shelltrack"
                )
            }

            Alert::SuccessfulLogin {
                timestamp,
                username,
                ip,
                method,
                suspicious,
                reason,
            } => {
                let emoji = alert.get_emoji();
                let status = if *suspicious {
                    "⚠️ SUSPICIOUS LOGIN"
                } else {
                    "✅ SUCCESSFUL LOGIN"
                };

                let mut message = format!(
                    "{emoji} <b>{status}</b>\n\n\
                    <b>Host:</b> <code>{hostname}</code>\n\
                    <b>User:</b> <code>{username}</code>\n\
                    <b>IP:</b> <code>{ip}</code>\n\
                    <b>Method:</b> {method}\n\
                    <b>Time:</b> {timestamp}"
                );

                if let Some(r) = reason {
                    message.push_str(&format!("\n<b>Warning:</b> {}", r));
                }

                message.push_str("\n\n#ssh #login #shelltrack");
                message
            }

            Alert::SuspiciousCommand {
                timestamp,
                username,
                command,
                reason,
            } => {
                let emoji = alert.get_emoji();
                format!(
                    "{emoji} <b>SUSPICIOUS COMMAND</b> {emoji}\n\n\
                    <b>Host:</b> <code>{hostname}</code>\n\
                    <b>User:</b> <code>{username}</code>\n\
                    <b>Command:</b> <code>{}</code>\n\
                    <b>Reason:</b> {reason}\n\
                    <b>Time:</b> {timestamp}\n\n\
                    #suspicious #command #shelltrack",
                    Self::escape_html(command)
                )
            }

            Alert::IpBlocked {
                timestamp,
                ip,
                attempt_count,
                reason,
            } => {
                format!(
                    "🛑 <b>IP BLOCKED</b> 🛑\n\n\
                    <b>Host:</b> <code>{hostname}</code>\n\
                    <b>Blocked IP:</b> <code>{ip}</code>\n\
                    <b>Failed Attempts:</b> {attempt_count}\n\
                    <b>Reason:</b> {reason}\n\
                    <b>Time:</b> {timestamp}\n\n\
                    #blocked #security #shelltrack"
                )
            }
        }
    }

    fn format_command_event(&self, event: &CommandEvent, hostname: &str) -> String {
        format!(
            "🖥️ <b>Command Executed</b>\n\n\
            <b>Host:</b> <code>{hostname}</code>\n\
            <b>User:</b> <code>{}</code>\n\
            <b>PID:</b> {}\n\
            <b>Command:</b> <code>{}</code>\n\
            <b>CWD:</b> <code>{}</code>\n\
            <b>Time:</b> {}\n\n\
            #command #audit #shelltrack",
            event.username,
            event.pid,
            Self::escape_html(&event.command),
            event.cwd.as_deref().unwrap_or("N/A"),
            event.timestamp
        )
    }

    fn escape_html(text: &str) -> String {
        text.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    }
}

#[async_trait]
impl Notifier for TelegramNotifier {
    async fn send_alert(&self, alert: &Alert, hostname: &str) -> Result<()> {
        let message = self.format_alert(alert, hostname);
        info!("Sending alert to Telegram: {:?}", alert);
        self.send_message(&message).await
    }

    async fn send_command_log(&self, event: &CommandEvent, hostname: &str) -> Result<()> {
        let message = self.format_command_event(event, hostname);
        debug!("Sending command log to Telegram");
        self.send_message(&message).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn make_test_notifier() -> TelegramNotifier {
        TelegramNotifier {
            client: Client::new(),
            bot_token: "test_token".to_string(),
            chat_id: "test_chat".to_string(),
        }
    }

    #[test]
    fn test_format_brute_force_alert() {
        let notifier = make_test_notifier();
        let alert = Alert::BruteForceAttempt {
            timestamp: Utc::now(),
            ip: "192.168.1.100".to_string(),
            attempt_count: 10,
            window_secs: 60,
            usernames: vec!["admin".to_string(), "root".to_string()],
        };

        let message = notifier.format_alert(&alert, "test-server");
        assert!(message.contains("BRUTE FORCE"));
        assert!(message.contains("192.168.1.100"));
        assert!(message.contains("admin"));
    }

    #[test]
    fn test_escape_html() {
        assert_eq!(
            TelegramNotifier::escape_html("<script>alert('xss')</script>"),
            "&lt;script&gt;alert('xss')&lt;/script&gt;"
        );
    }
}
