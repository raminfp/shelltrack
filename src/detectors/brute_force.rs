use std::collections::HashMap;
use std::time::{Duration, Instant};
use chrono::Utc;
use tracing::{debug, info, warn};

use crate::collectors::SshEvent;
use super::Alert;

#[derive(Debug)]
struct FailedAttempt {
    timestamp: Instant,
    username: String,
}

pub struct BruteForceDetector {
    threshold: u32,
    window: Duration,
    failed_attempts: HashMap<String, Vec<FailedAttempt>>,
    alerted_ips: HashMap<String, (Instant, u32)>, // (last_alert_time, last_alerted_count)
    alert_cooldown: Duration,
    alert_every_n_attempts: u32,
}

impl BruteForceDetector {
    pub fn new(threshold: u32, window_secs: u64, alert_every_n_attempts: u32) -> Self {
        Self {
            threshold,
            window: Duration::from_secs(window_secs),
            failed_attempts: HashMap::new(),
            alerted_ips: HashMap::new(),
            alert_cooldown: Duration::from_secs(300), // 5 minute cooldown between alerts for same IP
            alert_every_n_attempts,
        }
    }

    pub fn process_event(&mut self, event: &SshEvent) -> Option<Alert> {
        match event {
            SshEvent::LoginFailed { ip, username, .. } |
            SshEvent::InvalidUser { ip, username, .. } => {
                self.record_failed_attempt(ip, username)
            }
            SshEvent::LoginSuccess { ip, username, method, timestamp, .. } => {
                // Check if this IP was previously attempting brute force
                let suspicious = self.was_brute_forcing(ip);
                let reason = if suspicious {
                    Some(format!("IP {} had {} failed attempts before successful login",
                        ip, self.get_failed_count(ip)))
                } else {
                    None
                };

                // Clear failed attempts for this IP on successful login
                self.failed_attempts.remove(ip);

                Some(Alert::SuccessfulLogin {
                    timestamp: *timestamp,
                    username: username.clone(),
                    ip: ip.clone(),
                    method: method.clone(),
                    suspicious,
                    reason,
                })
            }
            _ => None,
        }
    }

    fn record_failed_attempt(&mut self, ip: &str, username: &str) -> Option<Alert> {
        let now = Instant::now();

        // Add the new attempt
        let attempts = self.failed_attempts.entry(ip.to_string()).or_default();
        attempts.push(FailedAttempt {
            timestamp: now,
            username: username.to_string(),
        });

        // Clean up old attempts outside the window
        attempts.retain(|a| now.duration_since(a.timestamp) <= self.window);

        let count = attempts.len() as u32;
        debug!("IP {} has {} failed attempts in window", ip, count);

        // Check if threshold exceeded
        if count >= self.threshold {
            // Check if we should send an alert
            let should_alert = if let Some((last_alert_time, last_alerted_count)) = self.alerted_ips.get(ip) {
                // Check cooldown first (prevents spam)
                if now.duration_since(*last_alert_time) < Duration::from_secs(10) {
                    debug!("IP {} in short cooldown (10s), skipping alert", ip);
                    return None;
                }
                
                // Send alert if count increased by alert_every_n_attempts
                let attempts_since_last_alert = count.saturating_sub(*last_alerted_count);
                if attempts_since_last_alert >= self.alert_every_n_attempts {
                    info!(
                        "IP {} has {} new attempts since last alert (was {}, now {})",
                        ip, attempts_since_last_alert, last_alerted_count, count
                    );
                    true
                } else {
                    debug!(
                        "IP {} has only {} new attempts (need {} for alert)",
                        ip, attempts_since_last_alert, self.alert_every_n_attempts
                    );
                    false
                }
            } else {
                // First time exceeding threshold
                true
            };

            if should_alert {
                // Generate alert
                let usernames: Vec<String> = attempts
                    .iter()
                    .map(|a| a.username.clone())
                    .collect::<std::collections::HashSet<_>>()
                    .into_iter()
                    .collect();

                warn!(
                    "Brute force detected from IP {}: {} attempts in {} seconds",
                    ip, count, self.window.as_secs()
                );

                // Update alert tracking with current count
                self.alerted_ips.insert(ip.to_string(), (now, count));

                return Some(Alert::BruteForceAttempt {
                    timestamp: Utc::now(),
                    ip: ip.to_string(),
                    attempt_count: count,
                    window_secs: self.window.as_secs(),
                    usernames,
                });
            }
        }

        None
    }

    fn was_brute_forcing(&self, ip: &str) -> bool {
        self.get_failed_count(ip) >= 3
    }

    fn get_failed_count(&self, ip: &str) -> u32 {
        self.failed_attempts
            .get(ip)
            .map(|a| a.len() as u32)
            .unwrap_or(0)
    }

    /// Clean up old entries to prevent memory growth
    pub fn cleanup(&mut self) {
        let now = Instant::now();

        // Clean up old failed attempts
        self.failed_attempts.retain(|_, attempts| {
            attempts.retain(|a| now.duration_since(a.timestamp) <= self.window);
            !attempts.is_empty()
        });

        // Clean up old alerts
        self.alerted_ips.retain(|_, (last_alert_time, _)| {
            now.duration_since(*last_alert_time) < Duration::from_secs(3600) // Keep for 1 hour
        });
    }

    /// Get statistics about current state
    pub fn get_stats(&self) -> BruteForceStats {
        BruteForceStats {
            tracked_ips: self.failed_attempts.len(),
            total_failed_attempts: self.failed_attempts.values().map(|v| v.len()).sum(),
            alerted_ips: self.alerted_ips.len(),
        }
    }
}

#[derive(Debug)]
pub struct BruteForceStats {
    pub tracked_ips: usize,
    pub total_failed_attempts: usize,
    pub alerted_ips: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn make_failed_event(ip: &str, username: &str) -> SshEvent {
        SshEvent::LoginFailed {
            timestamp: Utc::now(),
            username: username.to_string(),
            ip: ip.to_string(),
            reason: "password".to_string(),
        }
    }

    #[test]
    fn test_brute_force_detection() {
        let mut detector = BruteForceDetector::new(5, 60, 2);

        // First 4 attempts should not trigger
        for i in 0..4 {
            let event = make_failed_event("192.168.1.100", &format!("user{}", i));
            let alert = detector.process_event(&event);
            assert!(alert.is_none(), "Should not alert on attempt {}", i + 1);
        }

        // 5th attempt should trigger
        let event = make_failed_event("192.168.1.100", "admin");
        let alert = detector.process_event(&event);
        assert!(matches!(alert, Some(Alert::BruteForceAttempt { .. })));

        if let Some(Alert::BruteForceAttempt { attempt_count, .. }) = alert {
            assert_eq!(attempt_count, 5);
        }
    }

    #[test]
    fn test_successful_login_after_failures() {
        let mut detector = BruteForceDetector::new(5, 60, 2);

        // Add some failed attempts
        for _ in 0..3 {
            let event = make_failed_event("192.168.1.100", "admin");
            detector.process_event(&event);
        }

        // Successful login should be marked as suspicious
        let success = SshEvent::LoginSuccess {
            timestamp: Utc::now(),
            username: "admin".to_string(),
            ip: "192.168.1.100".to_string(),
            port: Some(22),
            method: "password".to_string(),
        };

        let alert = detector.process_event(&success);
        assert!(matches!(alert, Some(Alert::SuccessfulLogin { suspicious: true, .. })));
    }

    #[test]
    fn test_different_ips_tracked_separately() {
        let mut detector = BruteForceDetector::new(5, 60, 2);

        // Failed attempts from IP 1
        for _ in 0..3 {
            let event = make_failed_event("192.168.1.100", "admin");
            detector.process_event(&event);
        }

        // Failed attempts from IP 2
        for _ in 0..3 {
            let event = make_failed_event("192.168.1.200", "admin");
            detector.process_event(&event);
        }

        let stats = detector.get_stats();
        assert_eq!(stats.tracked_ips, 2);
        assert_eq!(stats.total_failed_attempts, 6);
    }
}
