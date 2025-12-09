use anyhow::Result;
use chrono::{DateTime, Utc};
use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use regex::Regex;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use super::SshEvent;

/// Collector for SSH events from audit.log (Ubuntu 22.04 and systems without auth.log)
pub struct AuditSshCollector {
    log_path: String,
    patterns: AuditSshPatterns,
}

struct AuditSshPatterns {
    // type=USER_AUTH ... acct="username" ... addr=1.2.3.4 ... res=failed
    user_auth: Regex,
    // type=USER_LOGIN ... addr=1.2.3.4 ... res=failed
    user_login: Regex,
    // Extract timestamp from msg=audit(1234567890.123:456)
    timestamp: Regex,
    // Extract account name (may be hex encoded)
    acct: Regex,
    // Extract IP address
    addr: Regex,
    // Extract result
    res: Regex,
}

impl AuditSshCollector {
    pub fn new(log_path: String) -> Self {
        let patterns = AuditSshPatterns {
            user_auth: Regex::new(r"type=USER_AUTH.*exe=./usr/sbin/sshd.").unwrap(),
            user_login: Regex::new(r"type=USER_LOGIN.*exe=./usr/sbin/sshd.").unwrap(),
            timestamp: Regex::new(r"msg=audit\((\d+\.\d+):(\d+)\)").unwrap(),
            acct: Regex::new(r#"acct="?([^"\s]+)"?"#).unwrap(),
            addr: Regex::new(r"addr=(\d+\.\d+\.\d+\.\d+)").unwrap(),
            res: Regex::new(r"res=(\w+)").unwrap(),
        };

        Self { log_path, patterns }
    }

    fn parse_timestamp(epoch_str: &str) -> Option<DateTime<Utc>> {
        let epoch: f64 = epoch_str.parse().ok()?;
        let secs = epoch as i64;
        let nsecs = ((epoch - secs as f64) * 1_000_000_000.0) as u32;
        DateTime::from_timestamp(secs, nsecs)
    }

    fn hex_to_string(hex: &str) -> Option<String> {
        // Check if it's hex encoded (all hex chars)
        if hex.chars().all(|c| c.is_ascii_hexdigit()) && hex.len() > 2 {
            let bytes: Result<Vec<u8>, _> = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
                .collect();

            if let Ok(b) = bytes {
                let s = String::from_utf8_lossy(&b).to_string();
                // Filter out non-printable characters
                let clean: String = s.chars().filter(|c| c.is_ascii_graphic() || *c == ' ').collect();
                if !clean.is_empty() {
                    return Some(clean);
                }
            }
        }
        // Not hex, return as-is
        Some(hex.to_string())
    }

    fn parse_line(&self, line: &str) -> Option<SshEvent> {
        // Only process USER_AUTH and USER_LOGIN from sshd
        let is_auth = self.patterns.user_auth.is_match(line);
        let is_login = self.patterns.user_login.is_match(line);

        if !is_auth && !is_login {
            return None;
        }

        // Extract timestamp
        let timestamp = self.patterns.timestamp.captures(line)
            .and_then(|c| Self::parse_timestamp(&c[1]))
            .unwrap_or_else(Utc::now);

        // Extract IP address
        let ip = self.patterns.addr.captures(line)
            .map(|c| c[1].to_string())
            .unwrap_or_else(|| "unknown".to_string());

        // Extract account/username
        let username = self.patterns.acct.captures(line)
            .and_then(|c| Self::hex_to_string(&c[1]))
            .unwrap_or_else(|| "unknown".to_string());

        // Extract result (success/failed)
        let result = self.patterns.res.captures(line)
            .map(|c| c[1].to_string())
            .unwrap_or_default();

        let is_failed = result == "failed";

        if is_failed {
            Some(SshEvent::LoginFailed {
                timestamp,
                username,
                ip,
                reason: "authentication".to_string(),
            })
        } else if result == "success" {
            Some(SshEvent::LoginSuccess {
                timestamp,
                username,
                ip,
                port: None,
                method: "password".to_string(),
            })
        } else {
            None
        }
    }

    pub async fn start(&self, tx: mpsc::Sender<SshEvent>) -> Result<()> {
        let log_path = self.log_path.clone();
        let patterns = Arc::new(AuditSshPatterns {
            user_auth: self.patterns.user_auth.clone(),
            user_login: self.patterns.user_login.clone(),
            timestamp: self.patterns.timestamp.clone(),
            acct: self.patterns.acct.clone(),
            addr: self.patterns.addr.clone(),
            res: self.patterns.res.clone(),
        });

        info!("Starting Audit SSH collector for: {}", log_path);

        tokio::task::spawn_blocking(move || {
            Self::watch_file(&log_path, patterns, tx)
        });

        Ok(())
    }

    fn watch_file(
        log_path: &str,
        patterns: Arc<AuditSshPatterns>,
        tx: mpsc::Sender<SshEvent>,
    ) -> Result<()> {
        let path = Path::new(log_path);

        if !path.exists() {
            warn!("Audit log file does not exist: {}. SSH events from audit will not be collected.", log_path);
            return Ok(());
        }

        let mut file = std::fs::File::open(path)?;
        let mut pos = file.seek(SeekFrom::End(0))?;

        let (notify_tx, notify_rx) = std::sync::mpsc::channel();
        let mut watcher = RecommendedWatcher::new(notify_tx, Config::default())?;
        watcher.watch(path, RecursiveMode::NonRecursive)?;

        info!("Watching audit log for SSH events: {}", log_path);

        loop {
            match notify_rx.recv() {
                Ok(Ok(event)) => {
                    if event.kind.is_modify() {
                        file.seek(SeekFrom::Start(pos))?;
                        let reader = BufReader::new(&file);

                        for line in reader.lines().map_while(Result::ok) {
                            if let Some(event) = Self::parse_line_static(&patterns, &line) {
                                debug!("Parsed audit SSH event: {:?}", event);
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

    fn parse_line_static(patterns: &AuditSshPatterns, line: &str) -> Option<SshEvent> {
        // Only process USER_AUTH and USER_LOGIN from sshd
        let is_auth = patterns.user_auth.is_match(line);
        let is_login = patterns.user_login.is_match(line);

        if !is_auth && !is_login {
            return None;
        }

        // Extract timestamp
        let timestamp = patterns.timestamp.captures(line)
            .and_then(|c| Self::parse_timestamp(&c[1]))
            .unwrap_or_else(Utc::now);

        // Extract IP address
        let ip = patterns.addr.captures(line)
            .map(|c| c[1].to_string())
            .unwrap_or_else(|| "unknown".to_string());

        // Extract account/username
        let username = patterns.acct.captures(line)
            .and_then(|c| Self::hex_to_string(&c[1]))
            .unwrap_or_else(|| "unknown".to_string());

        // Extract result (success/failed)
        let result = patterns.res.captures(line)
            .map(|c| c[1].to_string())
            .unwrap_or_default();

        let is_failed = result == "failed";

        if is_failed {
            Some(SshEvent::LoginFailed {
                timestamp,
                username,
                ip,
                reason: "authentication".to_string(),
            })
        } else if result == "success" {
            Some(SshEvent::LoginSuccess {
                timestamp,
                username,
                ip,
                port: None,
                method: "password".to_string(),
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_user_auth_failed() {
        let collector = AuditSshCollector::new("/var/log/audit/audit.log".to_string());

        let line = r#"type=USER_AUTH msg=audit(1765192972.144:273): pid=468860 uid=0 auid=4294967295 ses=4294967295 subj=unconfined msg='op=PAM:authentication grantors=? acct="ftpuser" exe="/usr/sbin/sshd" hostname=161.35.95.3 addr=161.35.95.3 terminal=ssh res=failed'UID="root" AUID="unset""#;

        let event = collector.parse_line(line);
        assert!(matches!(event, Some(SshEvent::LoginFailed { .. })));

        if let Some(SshEvent::LoginFailed { username, ip, .. }) = event {
            assert_eq!(username, "ftpuser");
            assert_eq!(ip, "161.35.95.3");
        }
    }

    #[test]
    fn test_parse_user_login_failed() {
        let collector = AuditSshCollector::new("/var/log/audit/audit.log".to_string());

        let line = r#"type=USER_LOGIN msg=audit(1765192972.068:271): pid=468860 uid=0 auid=4294967295 ses=4294967295 subj=unconfined msg='op=login acct=28756E6B6E6F776E207573657229 exe="/usr/sbin/sshd" hostname=? addr=161.35.95.3 terminal=sshd res=failed'UID="root" AUID="unset""#;

        let event = collector.parse_line(line);
        assert!(matches!(event, Some(SshEvent::LoginFailed { .. })));

        if let Some(SshEvent::LoginFailed { ip, .. }) = event {
            assert_eq!(ip, "161.35.95.3");
        }
    }

    #[test]
    fn test_hex_to_string() {
        // "ftpuser" in hex
        let result = AuditSshCollector::hex_to_string("667470757365721234");
        assert!(result.is_some());

        // Regular string
        let result = AuditSshCollector::hex_to_string("ftpuser");
        assert_eq!(result, Some("ftpuser".to_string()));
    }
}
