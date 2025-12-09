use anyhow::Result;
use chrono::{DateTime, Utc};
use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use regex::Regex;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use super::CommandEvent;

pub struct AuditCollector {
    log_path: String,
    patterns: AuditPatterns,
}

struct AuditPatterns {
    execve: Regex,
    execve_args: Regex,
    syscall: Regex,
    proctitle: Regex,
    cwd: Regex,
}

#[derive(Debug, Default)]
struct AuditRecord {
    timestamp: Option<DateTime<Utc>>,
    uid: Option<u32>,
    pid: Option<u32>,
    ppid: Option<u32>,
    command: Option<String>,
    args: Vec<String>,
    cwd: Option<String>,
    terminal: Option<String>,
    session_id: Option<String>,
    username: Option<String>,
}

impl AuditCollector {
    pub fn new(log_path: String) -> Self {
        let patterns = AuditPatterns {
            // type=EXECVE msg=audit(1234567890.123:456): argc=3 a0="ls" a1="-la" a2="/tmp"
            execve: Regex::new(
                r#"type=EXECVE msg=audit\((\d+\.\d+):(\d+)\).*argc=(\d+)"#
            ).unwrap(),

            // a0="command" a1="arg1" etc
            execve_args: Regex::new(
                r#"a(\d+)="([^"]*)""#
            ).unwrap(),

            // type=SYSCALL ... uid=1000 ... pid=12345 ppid=12344 ... tty=pts0 ... ses=1
            syscall: Regex::new(
                r#"type=SYSCALL.*uid=(\d+).*pid=(\d+).*ppid=(\d+).*tty=(\S+).*ses=(\d+)"#
            ).unwrap(),

            // type=PROCTITLE ... proctitle=6C73002D6C61
            proctitle: Regex::new(
                r#"type=PROCTITLE.*proctitle=([0-9A-Fa-f]+)"#
            ).unwrap(),

            // type=CWD ... cwd="/home/user"
            cwd: Regex::new(
                r#"type=CWD.*cwd="([^"]*)""#
            ).unwrap(),
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
        let bytes: Result<Vec<u8>, _> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
            .collect();

        bytes.ok().map(|b| {
            String::from_utf8_lossy(&b)
                .replace('\0', " ")
                .trim()
                .to_string()
        })
    }

    fn parse_execve_line(&self, line: &str) -> Option<(DateTime<Utc>, String, Vec<String>)> {
        let caps = self.patterns.execve.captures(line)?;
        let timestamp = Self::parse_timestamp(&caps[1])?;
        let _msg_id = &caps[2];
        let _argc: usize = caps[3].parse().ok()?;

        let mut args: Vec<(usize, String)> = self.patterns.execve_args
            .captures_iter(line)
            .filter_map(|c| {
                let idx: usize = c[1].parse().ok()?;
                Some((idx, c[2].to_string()))
            })
            .collect();

        args.sort_by_key(|(idx, _)| *idx);
        let args: Vec<String> = args.into_iter().map(|(_, s)| s).collect();

        let command = args.first().cloned().unwrap_or_default();
        Some((timestamp, command, args))
    }

    fn parse_syscall_line(&self, line: &str) -> Option<(u32, u32, u32, String, String)> {
        let caps = self.patterns.syscall.captures(line)?;
        let uid: u32 = caps[1].parse().ok()?;
        let pid: u32 = caps[2].parse().ok()?;
        let ppid: u32 = caps[3].parse().ok()?;
        let tty = caps[4].to_string();
        let session = caps[5].to_string();
        Some((uid, pid, ppid, tty, session))
    }

    fn parse_cwd_line(&self, line: &str) -> Option<String> {
        let caps = self.patterns.cwd.captures(line)?;
        Some(caps[1].to_string())
    }

    pub async fn start(
        &self,
        tx: mpsc::Sender<CommandEvent>,
        tracked_users: Arc<tokio::sync::RwLock<HashMap<String, bool>>>,
    ) -> Result<()> {
        let log_path = self.log_path.clone();
        let patterns = Arc::new(AuditPatterns {
            execve: self.patterns.execve.clone(),
            execve_args: self.patterns.execve_args.clone(),
            syscall: self.patterns.syscall.clone(),
            proctitle: self.patterns.proctitle.clone(),
            cwd: self.patterns.cwd.clone(),
        });

        info!("Starting Audit collector for: {}", log_path);

        tokio::task::spawn_blocking(move || {
            Self::watch_file(&log_path, patterns, tx, tracked_users)
        });

        Ok(())
    }

    fn watch_file(
        log_path: &str,
        patterns: Arc<AuditPatterns>,
        tx: mpsc::Sender<CommandEvent>,
        tracked_users: Arc<tokio::sync::RwLock<HashMap<String, bool>>>,
    ) -> Result<()> {
        let path = Path::new(log_path);

        // Check if file exists
        if !path.exists() {
            warn!("Audit log file does not exist: {}. Make sure auditd is running.", log_path);
            return Ok(());
        }

        let mut file = std::fs::File::open(path)?;
        let mut pos = file.seek(SeekFrom::End(0))?;

        let (notify_tx, notify_rx) = std::sync::mpsc::channel();
        let mut watcher = RecommendedWatcher::new(notify_tx, Config::default())?;
        watcher.watch(path, RecursiveMode::NonRecursive)?;

        info!("Watching audit log file: {}", log_path);

        // Buffer to accumulate related audit records
        let mut current_record: Option<AuditRecord> = None;

        loop {
            match notify_rx.recv() {
                Ok(Ok(event)) => {
                    if event.kind.is_modify() {
                        file.seek(SeekFrom::Start(pos))?;
                        let reader = BufReader::new(&file);

                        for line in reader.lines().map_while(Result::ok) {
                            // Parse EXECVE line
                            if line.contains("type=EXECVE") {
                                if let Some((ts, cmd, args)) = Self::parse_execve_line_static(&patterns, &line) {
                                    let mut record = AuditRecord::default();
                                    record.timestamp = Some(ts);
                                    record.command = Some(cmd);
                                    record.args = args;
                                    current_record = Some(record);
                                }
                            }
                            // Parse SYSCALL line
                            else if line.contains("type=SYSCALL") && current_record.is_some() {
                                if let Some((uid, pid, ppid, tty, session)) = Self::parse_syscall_line_static(&patterns, &line) {
                                    if let Some(ref mut record) = current_record {
                                        record.uid = Some(uid);
                                        record.pid = Some(pid);
                                        record.ppid = Some(ppid);
                                        record.terminal = Some(tty);
                                        record.session_id = Some(session);

                                        // Try to get username from uid
                                        if let Some(user) = users::get_user_by_uid(uid) {
                                            record.username = Some(user.name().to_string_lossy().to_string());
                                        }
                                    }
                                }
                            }
                            // Parse CWD line
                            else if line.contains("type=CWD") && current_record.is_some() {
                                if let Some(cwd) = Self::parse_cwd_line_static(&patterns, &line) {
                                    if let Some(ref mut record) = current_record {
                                        record.cwd = Some(cwd);
                                    }
                                }
                            }
                            // End of record - type=EOE or new EXECVE
                            else if line.contains("type=EOE") || line.contains("type=PROCTITLE") {
                                if let Some(record) = current_record.take() {
                                    if let Some(event) = Self::record_to_event(record) {
                                        // Check if we should track this user
                                        let should_send = {
                                            let rt = tokio::runtime::Handle::current();
                                            rt.block_on(async {
                                                let users = tracked_users.read().await;
                                                users.contains_key(&event.username)
                                            })
                                        };

                                        if should_send {
                                            debug!("Parsed command event: {:?}", event);
                                            if tx.blocking_send(event).is_err() {
                                                warn!("Failed to send command event - channel closed");
                                                return Ok(());
                                            }
                                        }
                                    }
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

    fn record_to_event(record: AuditRecord) -> Option<CommandEvent> {
        let command = if record.args.is_empty() {
            record.command?
        } else {
            record.args.join(" ")
        };

        Some(CommandEvent {
            timestamp: record.timestamp?,
            username: record.username.unwrap_or_else(|| "unknown".to_string()),
            uid: record.uid?,
            pid: record.pid?,
            ppid: record.ppid?,
            command,
            cwd: record.cwd,
            terminal: record.terminal,
            session_id: record.session_id.unwrap_or_else(|| "unknown".to_string()),
        })
    }

    fn parse_execve_line_static(patterns: &AuditPatterns, line: &str) -> Option<(DateTime<Utc>, String, Vec<String>)> {
        let caps = patterns.execve.captures(line)?;
        let timestamp = Self::parse_timestamp(&caps[1])?;

        let mut args: Vec<(usize, String)> = patterns.execve_args
            .captures_iter(line)
            .filter_map(|c| {
                let idx: usize = c[1].parse().ok()?;
                Some((idx, c[2].to_string()))
            })
            .collect();

        args.sort_by_key(|(idx, _)| *idx);
        let args: Vec<String> = args.into_iter().map(|(_, s)| s).collect();

        let command = args.first().cloned().unwrap_or_default();
        Some((timestamp, command, args))
    }

    fn parse_syscall_line_static(patterns: &AuditPatterns, line: &str) -> Option<(u32, u32, u32, String, String)> {
        let caps = patterns.syscall.captures(line)?;
        let uid: u32 = caps[1].parse().ok()?;
        let pid: u32 = caps[2].parse().ok()?;
        let ppid: u32 = caps[3].parse().ok()?;
        let tty = caps[4].to_string();
        let session = caps[5].to_string();
        Some((uid, pid, ppid, tty, session))
    }

    fn parse_cwd_line_static(patterns: &AuditPatterns, line: &str) -> Option<String> {
        let caps = patterns.cwd.captures(line)?;
        Some(caps[1].to_string())
    }
}
