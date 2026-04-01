//! Parser for ISC dhclient6 text-format lease files.
//!
//! Handles the `lease6 { … }` blocks written by `dhclient -6`.
//!
//! Supported option encodings found in the wild
//! ─────────────────────────────────────────────
//! • `option dhcp6.ntp-servers 2001:db8::1 2001:db8::2;`      space-sep IPv6
//! • `option dhcp6.unknown-42  "America/Los_Angeles";`         quoted string
//! • `option dhcp6.unknown-56  00:01:00:10:20:01:...;`         colon-hex bytes
//! • `option unknown-NNN       ...;`                           generic fallback

use super::Lease;
use anyhow::{Context, Result};
use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::path::Path;

// ─────────────────────────────────────────────────────────────────────────────
// Public entry point
// ─────────────────────────────────────────────────────────────────────────────

pub fn parse_file(path: &Path) -> Result<Vec<Lease>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Reading {:?}", path))?;
    parse_content(&content)
}

// ─────────────────────────────────────────────────────────────────────────────
// Block extraction
// ─────────────────────────────────────────────────────────────────────────────

fn parse_content(content: &str) -> Result<Vec<Lease>> {
    let mut leases = Vec::new();
    let mut remaining = content;

    loop {
        // Find the next "lease6" keyword
        let start = match remaining.find("lease6") {
            Some(i) => i,
            None => break,
        };
        remaining = &remaining[start + 6..]; // skip "lease6"

        // Skip whitespace to the opening brace
        let brace_pos = match remaining.find('{') {
            Some(i) => i,
            None => break,
        };
        let body_start = brace_pos + 1;
        let body = &remaining[body_start..];

        // Find the matching closing brace (depth counting)
        let mut depth = 1usize;
        let mut end = 0usize;
        for (i, b) in body.bytes().enumerate() {
            match b {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = i;
                        break;
                    }
                }
                _ => {}
            }
        }

        if depth != 0 {
            // Unterminated block — stop parsing
            break;
        }

        let block_body = &body[..end];
        match parse_lease6_block(block_body) {
            Ok(lease) => leases.push(lease),
            Err(e) => log::debug!("Skipping malformed lease6 block: {}", e),
        }

        remaining = &body[end + 1..];
    }

    Ok(leases)
}

// ─────────────────────────────────────────────────────────────────────────────
// Block parsing
// ─────────────────────────────────────────────────────────────────────────────

fn parse_lease6_block(block: &str) -> Result<Lease> {
    let mut interface = String::new();
    let mut expires: Option<DateTime<Utc>> = None;
    let mut options: HashMap<u16, Vec<u8>> = HashMap::new();

    // Expiry can be derived from iaaddr: starts + max-life
    let mut ia_starts: Option<i64> = None;
    let mut ia_max_life: Option<i64> = None;

    for raw_line in block.lines() {
        let line = raw_line.trim();

        if line.starts_with("interface") {
            // interface "eth0";
            if let Some(name) = extract_quoted(line) {
                interface = name;
            }
        } else if line.starts_with("expire") || line.starts_with("renew") {
            // expire 3 2024/01/17 12:00:00;
            if let Ok(dt) = parse_dhclient_time(line) {
                // Keep the earliest timestamp we see
                match expires {
                    None => expires = Some(dt),
                    Some(e) if dt < e => expires = Some(dt),
                    _ => {}
                }
            }
        } else if line.starts_with("starts ") {
            // starts 1706000000;  (epoch, inside an iaaddr sub-block)
            if let Some(v) = parse_trailing_u64(line) {
                ia_starts = Some(v as i64);
            }
        } else if line.starts_with("max-life") {
            // max-life 7200;
            if let Some(v) = parse_trailing_u64(line) {
                ia_max_life = Some(v as i64);
            }
        } else if line.starts_with("option ") {
            if let Some((code, data)) = parse_option_line(line) {
                options.entry(code).or_insert(data);
            }
        }
    }

    // Fall back to computing expiry from iaaddr timers
    if expires.is_none() {
        if let (Some(starts), Some(max_life)) = (ia_starts, ia_max_life) {
            if let Some(dt) = DateTime::from_timestamp(starts + max_life, 0) {
                expires = Some(dt);
            }
        }
    }

    if interface.is_empty() {
        anyhow::bail!("lease6 block has no interface line");
    }

    Ok(Lease {
        interface,
        expires,
        options,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Line-level helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Extract the first `"…"` string from a line.
fn extract_quoted(s: &str) -> Option<String> {
    let start = s.find('"')? + 1;
    let end = s[start..].find('"')?;
    Some(s[start..start + end].to_string())
}

/// Parse the trailing number before the `;` on a line like `max-life 7200;`.
fn parse_trailing_u64(line: &str) -> Option<u64> {
    line.split_whitespace()
        .last()?
        .trim_end_matches(';')
        .parse()
        .ok()
}

/// Parse a `renew`/`expire` time line.
///
/// Format: `expire 3 2024/01/17 12:00:00;`
///   - field[0] = keyword
///   - field[1] = day-of-week (ignored)
///   - field[2] = YYYY/MM/DD
///   - field[3] = HH:MM:SS[;]
fn parse_dhclient_time(line: &str) -> Result<DateTime<Utc>> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 4 {
        anyhow::bail!("too few fields in time line: {:?}", line);
    }
    let date = parts[2].replace('/', "-");
    let time = parts[3].trim_end_matches(';');
    let combined = format!("{} {}", date, time);
    NaiveDateTime::parse_from_str(&combined, "%Y-%m-%d %H:%M:%S")
        .map(|ndt| Utc.from_utc_datetime(&ndt))
        .with_context(|| format!("Parsing datetime {:?}", combined))
}

// ─────────────────────────────────────────────────────────────────────────────
// Option line parser
// ─────────────────────────────────────────────────────────────────────────────

/// Parse `option <name> <value>;` → `(option_code, raw_bytes)`.
fn parse_option_line(line: &str) -> Option<(u16, Vec<u8>)> {
    // Strip "option " prefix
    let rest = line.strip_prefix("option ")?.trim();

    // Split on first space: name vs value
    let (name, value_with_semi) = rest.split_once(' ')?;
    let value = value_with_semi.trim().trim_end_matches(';');

    let code = resolve_option_code(name)?;
    let bytes = decode_value(code, name, value)?;
    Some((code, bytes))
}

/// Map a DHCPv6 option name to its numeric code.
fn resolve_option_code(name: &str) -> Option<u16> {
    match name {
        // Well-known names (extend as needed)
        "dhcp6.ntp-servers" | "dhcp6.sntp-servers" => Some(56),
        "dhcp6.new-tzdb-timezone" | "dhcp6.tzdb-timezone" => Some(42),
        "dhcp6.new-posix-timezone" | "dhcp6.posix-timezone" => Some(41),
        "dhcp6.name-servers" | "dhcp6.domain-name-servers" => Some(23),
        "dhcp6.domain-search" => Some(24),
        _ => {
            // Try  dhcp6.unknown-NNN  or  unknown-NNN
            let numeric_str = name
                .strip_prefix("dhcp6.unknown-")
                .or_else(|| name.strip_prefix("unknown-"))?;
            numeric_str.parse().ok()
        }
    }
}

/// Convert an option value string to raw bytes.
///
/// Handles three encodings:
///   1. Colon-hex:   `00:01:00:10:20:01:…`
///   2. Quoted str:  `"America/Los_Angeles"`
///   3. Space-sep IPv6 addresses (for servers options):  `2001:db8::1 2001:db8::2`
fn decode_value(code: u16, name: &str, value: &str) -> Option<Vec<u8>> {
    if value.is_empty() {
        return None;
    }

    // ── Quoted string ─────────────────────────────────────────────────────────
    if value.starts_with('"') && value.ends_with('"') {
        let inner = &value[1..value.len() - 1];
        return Some(inner.as_bytes().to_vec());
    }

    // ── Colon-hex bytes  (no spaces, all hex digits + colons) ─────────────────
    //   But NOT an IPv6 address like "2001:db8::1" which contains "::"
    let looks_like_hex_bytes = !value.contains("::") && !value.contains(' ')
        && value.contains(':')
        && value.split(':').all(|h| h.len() <= 2 && h.chars().all(|c| c.is_ascii_hexdigit()));

    if looks_like_hex_bytes {
        let bytes: Option<Vec<u8>> = value
            .split(':')
            .map(|h| u8::from_str_radix(h, 16).ok())
            .collect();
        if let Some(b) = bytes {
            return Some(b);
        }
    }

    // ── Space/comma separated IPv6 addresses ─────────────────────────────────
    //   Used for ntp-servers, name-servers, etc.
    let is_addr_option = name.contains("server")
        || name.contains("address")
        || name.contains("addr")
        || matches!(code, 23 | 31 | 56);

    if is_addr_option {
        let mut bytes = Vec::new();
        for token in value.split(|c: char| c == ' ' || c == ',') {
            let token = token.trim();
            if let Ok(addr) = token.parse::<Ipv6Addr>() {
                bytes.extend_from_slice(&addr.octets());
            }
        }
        if !bytes.is_empty() {
            return Some(bytes);
        }
    }

    // ── Fallback: treat as UTF-8 string ──────────────────────────────────────
    Some(value.as_bytes().to_vec())
}
