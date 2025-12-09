use std::collections::HashMap;
use std::process::Command;
use std::time::{Duration, Instant};
use anyhow::Result;
use tracing::{info, warn, error};

pub struct IpBlocker {
    blocked_ips: HashMap<String, Instant>,
    block_duration: Duration,
    enabled: bool,
}

impl IpBlocker {
    pub fn new(enabled: bool, block_duration_secs: u64) -> Self {
        Self {
            blocked_ips: HashMap::new(),
            block_duration: Duration::from_secs(block_duration_secs),
            enabled,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn block_ip(&mut self, ip: &str) -> Result<bool> {
        if !self.enabled {
            return Ok(false);
        }

        // Skip if already blocked
        if self.blocked_ips.contains_key(ip) {
            info!("IP {} is already blocked", ip);
            return Ok(false);
        }

        // Skip localhost and private IPs (optional safety)
        if ip == "127.0.0.1" || ip.starts_with("::1") {
            warn!("Skipping block for localhost IP: {}", ip);
            return Ok(false);
        }

        // Block using iptables
        let output = Command::new("iptables")
            .args(["-A", "INPUT", "-s", ip, "-j", "DROP"])
            .output()?;

        if output.status.success() {
            info!("Successfully blocked IP: {}", ip);
            self.blocked_ips.insert(ip.to_string(), Instant::now());
            Ok(true)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!("Failed to block IP {}: {}", ip, stderr);
            Ok(false)
        }
    }

    pub fn unblock_ip(&mut self, ip: &str) -> Result<bool> {
        if !self.blocked_ips.contains_key(ip) {
            return Ok(false);
        }

        let output = Command::new("iptables")
            .args(["-D", "INPUT", "-s", ip, "-j", "DROP"])
            .output()?;

        if output.status.success() {
            info!("Successfully unblocked IP: {}", ip);
            self.blocked_ips.remove(ip);
            Ok(true)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("Failed to unblock IP {}: {}", ip, stderr);
            Ok(false)
        }
    }

    /// Clean up expired blocks
    pub fn cleanup_expired(&mut self) {
        let now = Instant::now();
        let expired: Vec<String> = self
            .blocked_ips
            .iter()
            .filter(|(_, blocked_at)| now.duration_since(**blocked_at) >= self.block_duration)
            .map(|(ip, _)| ip.clone())
            .collect();

        for ip in expired {
            if let Err(e) = self.unblock_ip(&ip) {
                error!("Failed to unblock expired IP {}: {}", ip, e);
            }
        }
    }

    pub fn is_blocked(&self, ip: &str) -> bool {
        self.blocked_ips.contains_key(ip)
    }

    pub fn get_blocked_count(&self) -> usize {
        self.blocked_ips.len()
    }
}
