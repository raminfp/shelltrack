mod blocker;
mod collectors;
mod config;
mod detectors;
mod notifiers;
mod storage;

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

use blocker::IpBlocker;
use collectors::{AuditCollector, AuditSshCollector, CommandEvent, SshCollector, SshEvent};
use config::Config;
use detectors::{Alert, BruteForceDetector};
use notifiers::{Notifier, TelegramNotifier};
use storage::{R2Storage, Storage};
use chrono::Utc;

#[derive(Parser)]
#[command(name = "shelltrack")]
#[command(about = "SSH security monitoring with brute force detection")]
#[command(version)]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "/etc/shelltrack/shelltrack.toml")]
    config: String,

    /// Run in debug mode
    #[arg(short, long)]
    debug: bool,

    /// Test mode - don't actually send notifications
    #[arg(long)]
    test: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Setup logging
    let log_level = if args.debug { Level::DEBUG } else { Level::INFO };
    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(true)
        .with_thread_ids(true)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("Starting ShellTrack v{}", env!("CARGO_PKG_VERSION"));

    // Load configuration
    let config = match Config::load(&args.config) {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to load config from {}: {}. Using defaults.", args.config, e);
            Config::default()
        }
    };

    // Get hostname
    let hostname = config
        .general
        .hostname
        .clone()
        .unwrap_or_else(|| gethostname::gethostname().to_string_lossy().to_string());

    info!("Monitoring host: {}", hostname);

    // Setup channels
    let (ssh_tx, mut ssh_rx) = mpsc::channel::<SshEvent>(1000);
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<CommandEvent>(1000);
    let (alert_tx, mut alert_rx) = mpsc::channel::<Alert>(100);

    // Track users who logged in (for audit log filtering)
    let tracked_users: Arc<RwLock<HashMap<String, bool>>> = Arc::new(RwLock::new(HashMap::new()));

    // Initialize collectors
    let ssh_collector = SshCollector::new(config.paths.auth_log.clone());
    let audit_collector = AuditCollector::new(config.paths.audit_log.clone());
    let audit_ssh_collector = AuditSshCollector::new(config.paths.audit_log.clone());

    // Start SSH collector (for auth.log - Ubuntu 24.04)
    ssh_collector.start(ssh_tx.clone()).await?;

    // Start Audit SSH collector (for audit.log - Ubuntu 22.04)
    audit_ssh_collector.start(ssh_tx).await?;

    // Start audit collector
    if config.detection.track_commands_after_login {
        audit_collector.start(cmd_tx.clone(), tracked_users.clone()).await?;
    }

    // Initialize notifier
    let notifier: Option<Arc<dyn Notifier>> = if config.telegram.enabled && !args.test {
        Some(Arc::new(TelegramNotifier::new(&config.telegram)))
    } else {
        if args.test {
            info!("Test mode - notifications disabled");
        }
        None
    };

    // Initialize storage
    let storage: Option<Arc<dyn Storage>> = if config.r2.enabled && !args.test {
        match R2Storage::new(&config.r2).await {
            Ok(s) => Some(Arc::new(s)),
            Err(e) => {
                error!("Failed to initialize R2 storage: {}", e);
                None
            }
        }
    } else {
        None
    };

    // Spawn alert handler
    let notifier_clone = notifier.clone();
    let storage_clone = storage.clone();
    let hostname_clone = hostname.clone();
    tokio::spawn(async move {
        while let Some(alert) = alert_rx.recv().await {
            info!("Processing alert: {:?}", alert);

            // Send notification
            if let Some(ref n) = notifier_clone {
                if let Err(e) = n.send_alert(&alert, &hostname_clone).await {
                    error!("Failed to send notification: {}", e);
                }
            }

            // Store alert
            if let Some(ref s) = storage_clone {
                if let Err(e) = s.store_alert(&alert).await {
                    error!("Failed to store alert: {}", e);
                }
            }
        }
    });

    // Spawn command handler
    let notifier_clone = notifier.clone();
    let storage_clone = storage.clone();
    let hostname_clone = hostname.clone();
    tokio::spawn(async move {
        while let Some(cmd_event) = cmd_rx.recv().await {
            info!("Command executed by {}: {}", cmd_event.username, cmd_event.command);

            // Send to Telegram
            if let Some(ref n) = notifier_clone {
                if let Err(e) = n.send_command_log(&cmd_event, &hostname_clone).await {
                    error!("Failed to send command notification: {}", e);
                }
            }

            // Store in R2
            if let Some(ref s) = storage_clone {
                if let Err(e) = s.store_command(&cmd_event).await {
                    error!("Failed to store command: {}", e);
                }
            }
        }
    });

    // Main SSH event processing loop
    let mut detector = BruteForceDetector::new(
        config.detection.brute_force_threshold,
        config.detection.brute_force_window_secs,
        config.detection.alert_every_n_attempts,
    );

    // Initialize IP blocker
    let mut ip_blocker = IpBlocker::new(
        config.detection.auto_block_enabled,
        config.detection.block_duration_secs,
    );
    let auto_block_threshold = config.detection.auto_block_threshold;

    let mut cleanup_interval = tokio::time::interval(tokio::time::Duration::from_secs(60));

    info!("ShellTrack is now monitoring SSH activity");
    info!(
        "Brute force detection: {} attempts in {} seconds, alert every {} new attempts",
        config.detection.brute_force_threshold,
        config.detection.brute_force_window_secs,
        config.detection.alert_every_n_attempts
    );
    if config.detection.auto_block_enabled {
        info!(
            "Auto-block enabled: IPs will be blocked after {} failed attempts for {} seconds",
            config.detection.auto_block_threshold,
            config.detection.block_duration_secs
        );
    }

    loop {
        tokio::select! {
            Some(ssh_event) = ssh_rx.recv() => {
                // Process SSH event
                if let Some(alert) = detector.process_event(&ssh_event) {
                    // Handle successful login - start tracking commands
                    if let Alert::SuccessfulLogin { ref username, .. } = alert {
                        if config.detection.track_commands_after_login {
                            let mut users = tracked_users.write().await;
                            users.insert(username.clone(), true);
                            info!("Now tracking commands for user: {}", username);
                        }
                    }

                    // Auto-block IP if threshold reached
                    if let Alert::BruteForceAttempt { ref ip, attempt_count, .. } = alert {
                        if ip_blocker.is_enabled()
                            && attempt_count >= auto_block_threshold
                            && !ip_blocker.is_blocked(ip)
                        {
                            match ip_blocker.block_ip(ip) {
                                Ok(true) => {
                                    let block_alert = Alert::IpBlocked {
                                        timestamp: Utc::now(),
                                        ip: ip.clone(),
                                        attempt_count,
                                        reason: format!(
                                            "Exceeded {} failed SSH attempts",
                                            auto_block_threshold
                                        ),
                                    };
                                    if alert_tx.send(block_alert).await.is_err() {
                                        error!("Failed to send block alert - channel closed");
                                    }
                                }
                                Ok(false) => {}
                                Err(e) => {
                                    error!("Failed to block IP {}: {}", ip, e);
                                }
                            }
                        }
                    }

                    // Send alert if it meets criteria
                    let should_alert = match &alert {
                        Alert::BruteForceAttempt { .. } => true,
                        Alert::SuccessfulLogin { suspicious, .. } => {
                            *suspicious || config.detection.alert_on_successful_login
                        }
                        Alert::SuspiciousCommand { .. } => true,
                        Alert::IpBlocked { .. } => true,
                    };

                    if should_alert {
                        if alert_tx.send(alert).await.is_err() {
                            error!("Failed to send alert - channel closed");
                        }
                    }
                }

                // Handle session closed - stop tracking
                if let SshEvent::SessionClosed { username, .. } = &ssh_event {
                    let mut users = tracked_users.write().await;
                    users.remove(username);
                    info!("Stopped tracking commands for user: {}", username);
                }
            }

            _ = cleanup_interval.tick() => {
                detector.cleanup();
                ip_blocker.cleanup_expired();

                let stats = detector.get_stats();
                let blocked_count = ip_blocker.get_blocked_count();
                if stats.tracked_ips > 0 || blocked_count > 0 {
                    info!(
                        "Detector stats: {} IPs tracked, {} total failed attempts, {} IPs blocked",
                        stats.tracked_ips, stats.total_failed_attempts, blocked_count
                    );
                }
            }
        }
    }
}
