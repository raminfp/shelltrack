use anyhow::Result;
use chrono::{DateTime, Datelike, Local, NaiveDateTime, Utc};
use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use regex::Regex;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use super::SshEvent;

pub struct SshCollector {
    log_path: String,
    patterns: SshPatterns,
}

struct SshPatterns {
    accepted: Regex,
    failed: Regex,
    invalid_user: Regex,
    session_closed: Regex,
    // Support for ISO 8601 timestamps (systemd-journald)
    accepted_iso: Regex,
    failed_iso: Regex,
    invalid_user_iso: Regex,
}

impl SshCollector {
    pub fn new(log_path: String) -> Self {
        let patterns = SshPatterns {
            // Accepted publickey for user from 192.168.1.1 port 22 ssh2
            // Accepted password for user from 192.168.1.1 port 22 ssh2
            accepted: Regex::new(
                r"(\w+\s+\d+\s+\d+:\d+:\d+).*sshd\[\d+\]:\s+Accepted\s+(\w+)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)"
            ).unwrap(),

            // Failed password for user from 192.168.1.1 port 22 ssh2
            // Failed password for invalid user admin from 192.168.1.1 port 22 ssh2
            failed: Regex::new(
                r"(\w+\s+\d+\s+\d+:\d+:\d+).*sshd\[\d+\]:\s+Failed\s+(\w+)\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+(\S+)"
            ).unwrap(),

            // Invalid user admin from 192.168.1.1 port 22
            invalid_user: Regex::new(
                r"(\w+\s+\d+\s+\d+:\d+:\d+).*sshd\[\d+\]:\s+Invalid user\s+(\S+)\s+from\s+(\S+)"
            ).unwrap(),

            // pam_unix(sshd:session): session closed for user
            session_closed: Regex::new(
                r"(\w+\s+\d+\s+\d+:\d+:\d+).*sshd\[\d+\]:\s+pam_unix\(sshd:session\):\s+session closed for user\s+(\S+)"
            ).unwrap(),

            // ISO 8601 format: 2025-12-08T11:01:20.943461+03:30 zen sshd[80350]: Accepted password for raminfp from 127.0.0.1 port 47696 ssh2
            accepted_iso: Regex::new(
                r"(\d{4}-\d{2}-\d{2}T[\d:.+-]+)\s+\S+\s+sshd\[\d+\]:\s+Accepted\s+(\w+)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)"
            ).unwrap(),

            // ISO 8601 format: 2025-12-08T09:49:10.662305+03:30 zen sshd[51373]: Failed password for invalid user wronguser from 127.0.0.1 port 45118 ssh2
            failed_iso: Regex::new(
                r"(\d{4}-\d{2}-\d{2}T[\d:.+-]+)\s+\S+\s+sshd\[\d+\]:\s+Failed\s+(\w+)\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+(\S+)"
            ).unwrap(),

            // ISO 8601 format: Invalid user
            invalid_user_iso: Regex::new(
                r"(\d{4}-\d{2}-\d{2}T[\d:.+-]+)\s+\S+\s+sshd\[\d+\]:\s+Invalid user\s+(\S+)\s+from\s+(\S+)"
            ).unwrap(),
        };

        Self { log_path, patterns }
    }

    fn parse_syslog_timestamp(timestamp_str: &str) -> DateTime<Utc> {
        let current_year = Local::now().year();
        let with_year = format!("{} {}", current_year, timestamp_str);

        if let Ok(naive) = NaiveDateTime::parse_from_str(&with_year, "%Y %b %d %H:%M:%S") {
            if let Some(local_time) = naive.and_local_timezone(Local).single() {
                return local_time.with_timezone(&Utc);
            }
        }

        Utc::now()
    }

    fn parse_iso_timestamp(timestamp_str: &str) -> DateTime<Utc> {
        // Try to parse ISO 8601 format: 2025-12-08T09:49:10.662305+03:30
        if let Ok(dt) = DateTime::parse_from_rfc3339(timestamp_str) {
            return dt.with_timezone(&Utc);
        }
        
        // Fallback: try to parse without timezone
        // Format: 2025-12-08T09:49:10.662305
        let timestamp_clean = timestamp_str.split('+').next().unwrap_or(timestamp_str)
                                          .split('-').take(3).collect::<Vec<_>>().join("-")
                                          + "T" + timestamp_str.split('T').nth(1).unwrap_or("00:00:00").split('+').next().unwrap_or("00:00:00");
        
        if let Ok(naive) = NaiveDateTime::parse_from_str(&timestamp_clean, "%Y-%m-%dT%H:%M:%S%.f") {
            if let Some(local_time) = naive.and_local_timezone(Local).single() {
                return local_time.with_timezone(&Utc);
            }
        }

        Utc::now()
    }

    fn parse_line(&self, line: &str) -> Option<SshEvent> {
        // Check for accepted login (ISO 8601 format first)
        if let Some(caps) = self.patterns.accepted_iso.captures(line) {
            let timestamp = Self::parse_iso_timestamp(&caps[1]);
            return Some(SshEvent::LoginSuccess {
                timestamp,
                method: caps[2].to_string(),
                username: caps[3].to_string(),
                ip: caps[4].to_string(),
                port: caps[5].parse().ok(),
            });
        }

        // Check for failed login (ISO 8601 format)
        if let Some(caps) = self.patterns.failed_iso.captures(line) {
            let timestamp = Self::parse_iso_timestamp(&caps[1]);
            return Some(SshEvent::LoginFailed {
                timestamp,
                reason: caps[2].to_string(),
                username: caps[3].to_string(),
                ip: caps[4].to_string(),
            });
        }

        // Check for invalid user (ISO 8601 format)
        if let Some(caps) = self.patterns.invalid_user_iso.captures(line) {
            let timestamp = Self::parse_iso_timestamp(&caps[1]);
            return Some(SshEvent::InvalidUser {
                timestamp,
                username: caps[2].to_string(),
                ip: caps[3].to_string(),
            });
        }

        // Check for accepted login (traditional syslog format)
        if let Some(caps) = self.patterns.accepted.captures(line) {
            let timestamp = Self::parse_syslog_timestamp(&caps[1]);
            return Some(SshEvent::LoginSuccess {
                timestamp,
                method: caps[2].to_string(),
                username: caps[3].to_string(),
                ip: caps[4].to_string(),
                port: caps[5].parse().ok(),
            });
        }

        // Check for failed login (traditional syslog format)
        if let Some(caps) = self.patterns.failed.captures(line) {
            let timestamp = Self::parse_syslog_timestamp(&caps[1]);
            return Some(SshEvent::LoginFailed {
                timestamp,
                reason: caps[2].to_string(),
                username: caps[3].to_string(),
                ip: caps[4].to_string(),
            });
        }

        // Check for invalid user (traditional syslog format)
        if let Some(caps) = self.patterns.invalid_user.captures(line) {
            let timestamp = Self::parse_syslog_timestamp(&caps[1]);
            return Some(SshEvent::InvalidUser {
                timestamp,
                username: caps[2].to_string(),
                ip: caps[3].to_string(),
            });
        }

        // Check for session closed
        if let Some(caps) = self.patterns.session_closed.captures(line) {
            let timestamp = Self::parse_syslog_timestamp(&caps[1]);
            return Some(SshEvent::SessionClosed {
                timestamp,
                username: caps[2].to_string(),
            });
        }

        None
    }

    pub async fn start(&self, tx: mpsc::Sender<SshEvent>) -> Result<()> {
        let log_path = self.log_path.clone();
        let patterns = Arc::new(SshPatterns {
            accepted: self.patterns.accepted.clone(),
            failed: self.patterns.failed.clone(),
            invalid_user: self.patterns.invalid_user.clone(),
            session_closed: self.patterns.session_closed.clone(),
            accepted_iso: self.patterns.accepted_iso.clone(),
            failed_iso: self.patterns.failed_iso.clone(),
            invalid_user_iso: self.patterns.invalid_user_iso.clone(),
        });

        info!("Starting SSH collector for: {}", log_path);

        // Spawn blocking task for file watching
        let tx_clone = tx.clone();
        tokio::task::spawn_blocking(move || {
            Self::watch_file(&log_path, patterns, tx_clone)
        });

        Ok(())
    }

    fn watch_file(
        log_path: &str,
        patterns: Arc<SshPatterns>,
        tx: mpsc::Sender<SshEvent>,
    ) -> Result<()> {
        let path = Path::new(log_path);

        // Open file and seek to end
        let mut file = std::fs::File::open(path)?;
        let mut pos = file.seek(SeekFrom::End(0))?;

        let (notify_tx, notify_rx) = std::sync::mpsc::channel();
        let mut watcher = RecommendedWatcher::new(notify_tx, Config::default())?;
        watcher.watch(path, RecursiveMode::NonRecursive)?;

        info!("Watching SSH log file: {}", log_path);

        loop {
            match notify_rx.recv() {
                Ok(Ok(event)) => {
                    if event.kind.is_modify() {
                        // Read new content
                        file.seek(SeekFrom::Start(pos))?;
                        let reader = BufReader::new(&file);

                        for line in reader.lines().map_while(Result::ok) {
                            if let Some(event) = Self::parse_line_static(&patterns, &line) {
                                debug!("Parsed SSH event: {:?}", event);
                                if tx.blocking_send(event).is_err() {
                                    warn!("Failed to send SSH event - channel closed");
                                    return Ok(());
                                }
                            }
                        }

                        pos = file.seek(SeekFrom::End(0))?;
                    }
                }
                Ok(Err(e)) => {
                    error!("Watch error: {:?}", e);
                }
                Err(e) => {
                    error!("Channel error: {:?}", e);
                    break;
                }
            }
        }

        Ok(())
    }

    fn parse_line_static(patterns: &SshPatterns, line: &str) -> Option<SshEvent> {
        // Check for accepted login (ISO 8601 format first)
        if let Some(caps) = patterns.accepted_iso.captures(line) {
            let timestamp = Self::parse_iso_timestamp(&caps[1]);
            return Some(SshEvent::LoginSuccess {
                timestamp,
                method: caps[2].to_string(),
                username: caps[3].to_string(),
                ip: caps[4].to_string(),
                port: caps[5].parse().ok(),
            });
        }

        // Check for failed login (ISO 8601 format)
        if let Some(caps) = patterns.failed_iso.captures(line) {
            let timestamp = Self::parse_iso_timestamp(&caps[1]);
            return Some(SshEvent::LoginFailed {
                timestamp,
                reason: caps[2].to_string(),
                username: caps[3].to_string(),
                ip: caps[4].to_string(),
            });
        }

        // Check for invalid user (ISO 8601 format)
        if let Some(caps) = patterns.invalid_user_iso.captures(line) {
            let timestamp = Self::parse_iso_timestamp(&caps[1]);
            return Some(SshEvent::InvalidUser {
                timestamp,
                username: caps[2].to_string(),
                ip: caps[3].to_string(),
            });
        }

        // Check for accepted login (traditional syslog format)
        if let Some(caps) = patterns.accepted.captures(line) {
            let timestamp = Self::parse_syslog_timestamp(&caps[1]);
            return Some(SshEvent::LoginSuccess {
                timestamp,
                method: caps[2].to_string(),
                username: caps[3].to_string(),
                ip: caps[4].to_string(),
                port: caps[5].parse().ok(),
            });
        }

        // Check for failed login (traditional syslog format)
        if let Some(caps) = patterns.failed.captures(line) {
            let timestamp = Self::parse_syslog_timestamp(&caps[1]);
            return Some(SshEvent::LoginFailed {
                timestamp,
                reason: caps[2].to_string(),
                username: caps[3].to_string(),
                ip: caps[4].to_string(),
            });
        }

        // Check for invalid user (traditional syslog format)
        if let Some(caps) = patterns.invalid_user.captures(line) {
            let timestamp = Self::parse_syslog_timestamp(&caps[1]);
            return Some(SshEvent::InvalidUser {
                timestamp,
                username: caps[2].to_string(),
                ip: caps[3].to_string(),
            });
        }

        // Check for session closed
        if let Some(caps) = patterns.session_closed.captures(line) {
            let timestamp = Self::parse_syslog_timestamp(&caps[1]);
            return Some(SshEvent::SessionClosed {
                timestamp,
                username: caps[2].to_string(),
            });
        }

        None
    }

    /// Parse existing log file for historical analysis
    pub fn parse_file(&self, path: &str) -> Result<Vec<SshEvent>> {
        let file = std::fs::File::open(path)?;
        let reader = BufReader::new(file);
        let mut events = Vec::new();

        for line in reader.lines().map_while(Result::ok) {
            if let Some(event) = self.parse_line(&line) {
                events.push(event);
            }
        }

        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_accepted_login() {
        let collector = SshCollector::new("/var/log/auth.log".to_string());

        let line = "Dec  8 10:30:45 server sshd[12345]: Accepted publickey for admin from 192.168.1.100 port 54321 ssh2";
        let event = collector.parse_line(line);

        assert!(matches!(event, Some(SshEvent::LoginSuccess { .. })));
        if let Some(SshEvent::LoginSuccess { username, ip, method, .. }) = event {
            assert_eq!(username, "admin");
            assert_eq!(ip, "192.168.1.100");
            assert_eq!(method, "publickey");
        }
    }

    #[test]
    fn test_parse_failed_login() {
        let collector = SshCollector::new("/var/log/auth.log".to_string());

        let line = "Dec  8 10:30:45 server sshd[12345]: Failed password for admin from 192.168.1.100 port 54321 ssh2";
        let event = collector.parse_line(line);

        assert!(matches!(event, Some(SshEvent::LoginFailed { .. })));
        if let Some(SshEvent::LoginFailed { username, ip, .. }) = event {
            assert_eq!(username, "admin");
            assert_eq!(ip, "192.168.1.100");
        }
    }

    #[test]
    fn test_parse_invalid_user() {
        let collector = SshCollector::new("/var/log/auth.log".to_string());

        let line = "Dec  8 10:30:45 server sshd[12345]: Invalid user hacker from 192.168.1.100 port 54321";
        let event = collector.parse_line(line);

        assert!(matches!(event, Some(SshEvent::InvalidUser { .. })));
        if let Some(SshEvent::InvalidUser { username, ip, .. }) = event {
            assert_eq!(username, "hacker");
            assert_eq!(ip, "192.168.1.100");
        }
    }

    #[test]
    fn test_parse_failed_login_iso() {
        let collector = SshCollector::new("/var/log/auth.log".to_string());

        let line = "2025-12-08T09:49:10.662305+03:30 zen sshd[51373]: Failed password for invalid user wronguser from 127.0.0.1 port 45118 ssh2";
        let event = collector.parse_line(line);

        assert!(matches!(event, Some(SshEvent::LoginFailed { .. })));
        if let Some(SshEvent::LoginFailed { username, ip, reason, .. }) = event {
            assert_eq!(username, "wronguser");
            assert_eq!(ip, "127.0.0.1");
            assert_eq!(reason, "password");
        }
    }

    #[test]
    fn test_parse_invalid_user_iso() {
        let collector = SshCollector::new("/var/log/auth.log".to_string());

        let line = "2025-12-08T09:49:10.662305+03:30 zen sshd[51373]: Invalid user wronguser from 127.0.0.1 port 45118";
        let event = collector.parse_line(line);

        assert!(matches!(event, Some(SshEvent::InvalidUser { .. })));
        if let Some(SshEvent::InvalidUser { username, ip, .. }) = event {
            assert_eq!(username, "wronguser");
            assert_eq!(ip, "127.0.0.1");
        }
    }

    #[test]
    fn test_parse_accepted_login_iso() {
        let collector = SshCollector::new("/var/log/auth.log".to_string());

        let line = "2025-12-08T11:01:20.943461+03:30 zen sshd[80350]: Accepted password for raminfp from 127.0.0.1 port 47696 ssh2";
        let event = collector.parse_line(line);

        assert!(matches!(event, Some(SshEvent::LoginSuccess { .. })));
        if let Some(SshEvent::LoginSuccess { username, ip, method, .. }) = event {
            assert_eq!(username, "raminfp");
            assert_eq!(ip, "127.0.0.1");
            assert_eq!(method, "password");
        }
    }
}
