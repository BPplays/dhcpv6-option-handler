pub mod dhclient;
pub mod packet;

use anyhow::Result;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::path::Path;

// ─────────────────────────────────────────────────────────────────────────────
// Core data types
// ─────────────────────────────────────────────────────────────────────────────

/// A single DHCPv6 lease: one interface, one set of option payloads.
///
/// `options` maps DHCPv6 option codes to their raw bytes.  Handlers are
/// responsible for interpreting those bytes according to the relevant RFC.
#[derive(Debug, Clone)]
pub struct Lease {
    /// Network interface this lease was obtained on.
    pub interface: String,

    /// Absolute wall-clock time at which this lease expires.
    ///
    /// `None` means the expiry is unknown; such a lease is treated as valid.
    pub expires: Option<DateTime<Utc>>,

    /// Raw option data keyed by DHCPv6 option code.
    pub options: HashMap<u16, Vec<u8>>,
}

impl Lease {
    /// Returns `true` if this lease has a known expiry that has already passed.
    pub fn is_expired(&self) -> bool {
        self.expires.map(|e| e < Utc::now()).unwrap_or(false)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lease discovery
// ─────────────────────────────────────────────────────────────────────────────

/// Scan well-known locations for DHCPv6 lease files and return all leases.
///
/// Supported formats
/// ─────────────────
/// • ISC dhclient6  text lease files  (`/var/lib/dhclient/dhclient6.leases`, …)
/// • dhcpcd         binary lease files (`/var/lib/dhcpcd/*.lease6`)
pub fn discover_and_parse() -> Result<Vec<Lease>> {
    let mut leases = Vec::new();

    // ── ISC dhclient6 text-format leases ─────────────────────────────────────
    for path_str in &[
        "/var/lib/dhclient/dhclient6.leases",
        "/var/lib/dhcp/dhclient6.leases",
        "/var/lib/NetworkManager/dhclient6.conf",
    ] {
        let p = Path::new(path_str);
        if p.exists() {
            log::info!("Parsing ISC dhclient6 leases from {}", path_str);
            match dhclient::parse_file(p) {
                Ok(mut batch) => leases.append(&mut batch),
                Err(e) => log::warn!("Skipping {}: {:#}", path_str, e),
            }
        }
    }

    // ── dhcpcd binary lease files ─────────────────────────────────────────────
    let dhcpcd_dir = Path::new("/var/lib/dhcpcd");
    if dhcpcd_dir.is_dir() {
        match std::fs::read_dir(dhcpcd_dir) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().map_or(false, |e| e == "lease6") {
                        log::info!("Parsing dhcpcd lease from {:?}", path);
                        match packet::parse_file(&path) {
                            Ok(mut batch) => leases.append(&mut batch),
                            Err(e) => log::warn!("Skipping {:?}: {:#}", path, e),
                        }
                    }
                }
            }
            Err(e) => log::warn!("Could not read dhcpcd dir: {}", e),
        }
    }

    if leases.is_empty() {
        log::warn!("No DHCPv6 lease files found on this system");
    }

    Ok(leases)
}
