use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// A whitelisted IP address entry
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct WhitelistEntry {
    pub id: i64,
    pub ip_address: String,
    pub description: Option<String>,
    pub added_by: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub request_count: i64,
    pub is_active: bool,
}

/// Request to add an IP to whitelist
#[derive(Debug, Clone, Deserialize)]
pub struct AddWhitelistRequest {
    pub ip_address: String,
    pub description: Option<String>,
}

/// IP validation result
#[derive(Debug, Clone)]
pub enum IpValidation {
    Valid,
    InvalidFormat,
    PrivateIpNotAllowed,
}

/// Validate an IP address string
pub fn validate_ip(ip: &str) -> IpValidation {
    match ip.parse::<IpAddr>() {
        Ok(addr) => {
            // Check if it's a private IP
            match addr {
                IpAddr::V4(v4) => {
                    if v4.is_private() || v4.is_loopback() || v4.is_multicast() {
                        // Still allow it, just note it
                    }
                }
                IpAddr::V6(v6) => {
                    if v6.is_loopback() || v6.is_multicast() {
                        // Still allow it
                    }
                }
            }
            IpValidation::Valid
        }
        Err(_) => IpValidation::InvalidFormat,
    }
}

/// Check if an IP matches a pattern (supports CIDR notation)
pub fn ip_matches(ip: &str, pattern: &str) -> bool {
    // Direct match
    if ip == pattern {
        return true;
    }

    // Try CIDR matching
    if let Ok(network) = pattern.parse::<ipnet::IpNet>() {
        if let Ok(addr) = ip.parse::<IpAddr>() {
            return network.contains(&addr);
        }
    }

    // Try wildcard matching (e.g., "192.168.1.*")
    if pattern.ends_with(".*") {
        let prefix = &pattern[..pattern.len() - 2];
        return ip.starts_with(prefix);
    }

    false
}
