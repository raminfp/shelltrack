pub mod brute_force;

pub use brute_force::BruteForceDetector;

use crate::collectors::SshEvent;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Alert {
    BruteForceAttempt {
        timestamp: DateTime<Utc>,
        ip: String,
        attempt_count: u32,
        window_secs: u64,
        usernames: Vec<String>,
    },
    SuccessfulLogin {
        timestamp: DateTime<Utc>,
        username: String,
        ip: String,
        method: String,
        suspicious: bool,
        reason: Option<String>,
    },
    SuspiciousCommand {
        timestamp: DateTime<Utc>,
        username: String,
        command: String,
        reason: String,
    },
    IpBlocked {
        timestamp: DateTime<Utc>,
        ip: String,
        attempt_count: u32,
        reason: String,
    },
}

impl Alert {
    pub fn get_severity(&self) -> AlertSeverity {
        match self {
            Alert::BruteForceAttempt { attempt_count, .. } => {
                if *attempt_count >= 20 {
                    AlertSeverity::Critical
                } else if *attempt_count >= 10 {
                    AlertSeverity::High
                } else {
                    AlertSeverity::Medium
                }
            }
            Alert::SuccessfulLogin { suspicious, .. } => {
                if *suspicious {
                    AlertSeverity::High
                } else {
                    AlertSeverity::Low
                }
            }
            Alert::SuspiciousCommand { .. } => AlertSeverity::High,
            Alert::IpBlocked { .. } => AlertSeverity::High,
        }
    }

    pub fn get_emoji(&self) -> &'static str {
        match self.get_severity() {
            AlertSeverity::Critical => "🚨",
            AlertSeverity::High => "⚠️",
            AlertSeverity::Medium => "🔔",
            AlertSeverity::Low => "ℹ️",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertSeverity::Low => write!(f, "LOW"),
            AlertSeverity::Medium => write!(f, "MEDIUM"),
            AlertSeverity::High => write!(f, "HIGH"),
            AlertSeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}
