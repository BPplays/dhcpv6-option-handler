//! Parser for raw DHCPv6 packets as stored by dhcpcd.
//!
//! dhcpcd stores the last received DHCP reply as a raw binary packet at
//! `/var/lib/dhcpcd/<interface>.lease6`.  The interface name is derived from
//! the filename stem.  Lease expiry is estimated from the IA_NA / IAADDR
//! valid-lifetime fields plus the file's mtime as the "starts" reference.

use super::Lease;
use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::path::Path;
use std::time::SystemTime;

// ─────────────────────────────────────────────────────────────────────────────
// DHCPv6 option codes we care about while parsing structure
// ─────────────────────────────────────────────────────────────────────────────
const OPT_IA_NA: u16 = 3;
const OPT_IA_PD: u16 = 25;
const OPT_IAADDR: u16 = 5;
const OPT_IAPREFIX: u16 = 26;

// ─────────────────────────────────────────────────────────────────────────────
// Public entry point
// ─────────────────────────────────────────────────────────────────────────────

pub fn parse_file(path: &Path) -> Result<Vec<Lease>> {
    let data = std::fs::read(path).with_context(|| format!("Reading {:?}", path))?;

    // Use mtime as the "starts" anchor for lifetime calculations
    let mtime: DateTime<Utc> = std::fs::metadata(path)
        .and_then(|m| m.modified())
        .unwrap_or(SystemTime::now())
        .into();

    // Derive interface from filename stem: "eth0.lease6" → "eth0"
    let interface = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string();

    parse_packet(&data, &interface, mtime)
}

// ─────────────────────────────────────────────────────────────────────────────
// Packet parsing
// ─────────────────────────────────────────────────────────────────────────────

fn parse_packet(data: &[u8], interface: &str, starts: DateTime<Utc>) -> Result<Vec<Lease>> {
    // DHCPv6 wire format: 1 byte msg-type + 3 bytes transaction-id + options
    if data.len() < 4 {
        bail!("Packet too short ({} bytes)", data.len());
    }

    let (options, min_valid_life) = parse_options_section(&data[4..])?;

    let expires = min_valid_life.map(|secs| {
        starts + chrono::Duration::seconds(secs as i64)
    });

    Ok(vec![Lease {
        interface: interface.to_string(),
        expires,
        options,
    }])
}

/// Recursively parse the DHCPv6 TLV options section.
///
/// Returns `(option_map, minimum_valid_lifetime_secs)`.
/// The minimum lifetime is used to compute the absolute expiry time.
fn parse_options_section(data: &[u8]) -> Result<(HashMap<u16, Vec<u8>>, Option<u32>)> {
    let mut options: HashMap<u16, Vec<u8>> = HashMap::new();
    let mut min_life: Option<u32> = None;
    let mut pos = 0usize;

    while pos + 4 <= data.len() {
        let code = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        if pos + len > data.len() {
            log::debug!(
                "Option {} claims {} bytes but only {} remain; stopping",
                code,
                len,
                data.len() - pos
            );
            break;
        }

        let opt_data = &data[pos..pos + len];

        match code {
            // IA_NA / IA_PD: 4-byte IAID + 4-byte T1 + 4-byte T2 + suboptions
            OPT_IA_NA | OPT_IA_PD => {
                if opt_data.len() >= 12 {
                    let (_, life) = parse_options_section(&opt_data[12..])?;
                    if let Some(l) = life {
                        min_life = Some(min_life.unwrap_or(u32::MAX).min(l));
                    }
                }
            }

            // IAADDR: 16-byte addr + 4-byte preferred-life + 4-byte valid-life + subopts
            OPT_IAADDR => {
                if opt_data.len() >= 24 {
                    let valid_life = u32::from_be_bytes([
                        opt_data[20],
                        opt_data[21],
                        opt_data[22],
                        opt_data[23],
                    ]);
                    min_life = Some(min_life.unwrap_or(u32::MAX).min(valid_life));
                }
            }

            // IAPREFIX (inside IA_PD): 4-byte pref + 4-byte valid + 1-byte plen + 16-byte pfx
            OPT_IAPREFIX => {
                if opt_data.len() >= 25 {
                    let valid_life = u32::from_be_bytes([
                        opt_data[4],
                        opt_data[5],
                        opt_data[6],
                        opt_data[7],
                    ]);
                    min_life = Some(min_life.unwrap_or(u32::MAX).min(valid_life));
                }
            }

            // Everything else is a leaf option we hand to the handlers
            _ => {
                options.entry(code).or_insert_with(|| opt_data.to_vec());
            }
        }

        pos += len;
    }

    Ok((options, min_life))
}
