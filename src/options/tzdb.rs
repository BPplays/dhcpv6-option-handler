//! DHCPv6 option 42 — TZDB / IANA timezone name.
//!
//! Collects timezone strings from every non-expired lease and applies the most
//! consensual valid IANA timezone to the system.
//!
//! Selection algorithm
//! ───────────────────
//! If there are **more than 50** candidates → use the **first valid** one.
//!
//! Otherwise, for each candidate C compute:
//!   score(C) = Σ jaro_winkler(C, X)  for all X in the candidate list
//!
//! Then return the valid IANA timezone with the **highest score**.
//!
//! "Valid" means `tz.parse::<chrono_tz::Tz>()` succeeds.  If no candidate is
//! directly valid, the closest IANA timezone by Jaro-Winkler distance is used.

use super::OptionHandler;
use crate::lease::Lease;
use anyhow::{bail, Context, Result};
use std::path::Path;

pub const OPTION_CODE: u16 = 42;

// ─────────────────────────────────────────────────────────────────────────────
// Handler
// ─────────────────────────────────────────────────────────────────────────────

pub struct TzdbHandler;

impl OptionHandler for TzdbHandler {
    fn option_code(&self) -> u16 {
        OPTION_CODE
    }
    fn name(&self) -> &str {
        "TZDB Timezone"
    }

    fn process(&self, leases: &[Lease], _all_interfaces: &[String]) -> Result<()> {
        // Collect TZ strings from non-expired leases that carry option 42
        let candidates: Vec<String> = leases
            .iter()
            .filter(|l| !l.is_expired())
            .filter_map(|l| l.options.get(&OPTION_CODE))
            .filter_map(|data| {
                std::str::from_utf8(data)
                    .ok()
                    .map(|s| s.trim().trim_matches('\0').to_string())
            })
            .filter(|s| !s.is_empty())
            .collect();

        if candidates.is_empty() {
            log::info!("No TZDB option (42) found in any active lease — skipping");
            return Ok(());
        }

        log::info!(
            "TZDB candidates from {} active lease(s): {:?}",
            candidates.len(),
            candidates
        );

        match select_timezone(&candidates) {
            Some(tz) => {
                log::info!("Selected timezone: {}", tz);
                apply_timezone(&tz)
            }
            None => {
                log::warn!(
                    "Could not resolve a valid IANA timezone from candidates: {:?}",
                    candidates
                );
                Ok(())
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Timezone selection
// ─────────────────────────────────────────────────────────────────────────────

/// Choose the best timezone from the candidate list.
fn select_timezone(candidates: &[String]) -> Option<String> {
    // Partition into valid / invalid IANA timezone names
    let valid: Vec<&String> = candidates.iter().filter(|s| is_valid_tz(s)).collect();

    // If we have no directly valid names, find the closest IANA match
    if valid.is_empty() {
        log::debug!(
            "No candidate is a valid IANA timezone; falling back to closest-match"
        );
        return closest_iana_tz(candidates);
    }

    // Large list fast-path
    if candidates.len() > 50 {
        log::info!(
            "Candidate list has {} entries (> 50), using first valid timezone",
            candidates.len()
        );
        return valid.first().map(|s| s.to_string());
    }

    // Compute per-candidate similarity scores against the whole list
    let scores: Vec<f64> = candidates
        .iter()
        .map(|c| {
            candidates
                .iter()
                .map(|other| strsim::jaro_winkler(c.as_str(), other.as_str()))
                .sum::<f64>()
        })
        .collect();

    log::debug!("Candidate similarity scores:");
    for (c, s) in candidates.iter().zip(scores.iter()) {
        log::debug!("  {:40} score = {:.4}", c, s);
    }

    // Pick the valid candidate with the highest similarity score
    valid
        .into_iter()
        .max_by(|a, b| {
            let sa = index_of(candidates, a)
                .and_then(|i| scores.get(i))
                .copied()
                .unwrap_or(0.0);
            let sb = index_of(candidates, b)
                .and_then(|i| scores.get(i))
                .copied()
                .unwrap_or(0.0);
            sa.partial_cmp(&sb).unwrap_or(std::cmp::Ordering::Equal)
        })
        .map(|s| s.to_string())
}

/// Find the IANA timezone whose name has the highest Jaro-Winkler similarity
/// to any of the given candidates.
fn closest_iana_tz(candidates: &[String]) -> Option<String> {
    chrono_tz::TZ_VARIANTS
        .iter()
        .map(|tz| {
            let name = tz.name();
            // Best score this IANA timezone achieves against any candidate
            let best = candidates
                .iter()
                .map(|c| strsim::jaro_winkler(c.as_str(), name))
                .fold(0.0_f64, f64::max);
            (name, best)
        })
        .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
        .map(|(name, score)| {
            log::info!(
                "Closest IANA timezone to invalid candidates: {} (score {:.4})",
                name,
                score
            );
            name.to_string()
        })
}

/// Check if `s` is a valid IANA/TZDB timezone understood by chrono-tz.
fn is_valid_tz(s: &str) -> bool {
    s.parse::<chrono_tz::Tz>().is_ok()
}

fn index_of(slice: &[String], item: &str) -> Option<usize> {
    slice.iter().position(|s| s == item)
}

// ─────────────────────────────────────────────────────────────────────────────
// System timezone application
// ─────────────────────────────────────────────────────────────────────────────

/// Apply `tz` as the system timezone.
///
/// 1. Writes the name to `/etc/timezone`.
/// 2. Atomically replaces `/etc/localtime` with a symlink to the corresponding
///    zoneinfo file under `/usr/share/zoneinfo/`.
fn apply_timezone(tz: &str) -> Result<()> {
    // Validate the zoneinfo file exists before touching anything
    let zoneinfo = format!("/usr/share/zoneinfo/{}", tz);
    if !Path::new(&zoneinfo).exists() {
        bail!(
            "Timezone file does not exist: {} \
             (is the tzdata package installed?)",
            zoneinfo
        );
    }

    // Write /etc/timezone
    std::fs::write("/etc/timezone", format!("{}\n", tz))
        .context("Writing /etc/timezone")?;

    // Update /etc/localtime symlink atomically:
    //   write to a temp path, then rename over the target
    let localtime = Path::new("/etc/localtime");
    let tmp = Path::new("/etc/localtime.dhcpv6-tmp");

    // Remove stale temp if it exists
    let _ = std::fs::remove_file(tmp);

    std::os::unix::fs::symlink(&zoneinfo, tmp)
        .with_context(|| format!("Creating temporary symlink {:?} → {}", tmp, zoneinfo))?;

    std::fs::rename(tmp, localtime)
        .context("Atomically replacing /etc/localtime")?;

    log::info!("System timezone set to {} (→ {})", tz, zoneinfo);
    Ok(())
}
