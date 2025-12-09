pub mod ssh;
pub mod audit;
pub mod audit_ssh;

pub use ssh::SshCollector;
pub use audit::AuditCollector;
pub use audit_ssh::AuditSshCollector;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SshEvent {
    LoginSuccess {
        timestamp: DateTime<Utc>,
        username: String,
        ip: String,
        port: Option<u16>,
        method: String,
    },
    LoginFailed {
        timestamp: DateTime<Utc>,
        username: String,
        ip: String,
        reason: String,
    },
    SessionClosed {
        timestamp: DateTime<Utc>,
        username: String,
    },
    InvalidUser {
        timestamp: DateTime<Utc>,
        username: String,
        ip: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandEvent {
    pub timestamp: DateTime<Utc>,
    pub username: String,
    pub uid: u32,
    pub pid: u32,
    pub ppid: u32,
    pub command: String,
    pub cwd: Option<String>,
    pub terminal: Option<String>,
    pub session_id: String,
}

impl SshEvent {
    pub fn get_ip(&self) -> Option<&str> {
        match self {
            SshEvent::LoginSuccess { ip, .. } => Some(ip),
            SshEvent::LoginFailed { ip, .. } => Some(ip),
            SshEvent::InvalidUser { ip, .. } => Some(ip),
            SshEvent::SessionClosed { .. } => None,
        }
    }

    pub fn get_username(&self) -> &str {
        match self {
            SshEvent::LoginSuccess { username, .. } => username,
            SshEvent::LoginFailed { username, .. } => username,
            SshEvent::SessionClosed { username, .. } => username,
            SshEvent::InvalidUser { username, .. } => username,
        }
    }

    pub fn get_timestamp(&self) -> DateTime<Utc> {
        match self {
            SshEvent::LoginSuccess { timestamp, .. } => *timestamp,
            SshEvent::LoginFailed { timestamp, .. } => *timestamp,
            SshEvent::SessionClosed { timestamp, .. } => *timestamp,
            SshEvent::InvalidUser { timestamp, .. } => *timestamp,
        }
    }

    pub fn is_failed(&self) -> bool {
        matches!(self, SshEvent::LoginFailed { .. } | SshEvent::InvalidUser { .. })
    }

    pub fn is_success(&self) -> bool {
        matches!(self, SshEvent::LoginSuccess { .. })
    }
}
