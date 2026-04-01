mod interfaces;
mod lease;
mod options;

use anyhow::Result;
use log::info;

fn main() -> Result<()> {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .init();

    // ── 1. Discover all non-loopback network interfaces ──────────────────────
    let all_interfaces = interfaces::discover()?;
    info!(
        "Discovered {} interface(s): {:?}",
        all_interfaces.len(),
        all_interfaces
    );

    // ── 2. Parse every DHCPv6 lease file we can find ─────────────────────────
    let leases = lease::discover_and_parse()?;
    let valid_count = leases.iter().filter(|l| !l.is_expired()).count();
    info!(
        "Parsed {} lease(s) total, {} non-expired",
        leases.len(),
        valid_count
    );

    // ── 3. Build option handler registry ─────────────────────────────────────
    //
    //   To add a new option handler:
    //     1. Create  src/options/myoption.rs  implementing `OptionHandler`.
    //     2. Add     pub mod myoption;        in src/options/mod.rs.
    //     3. Register it below with           registry.register(…).
    //
    let mut registry = options::HandlerRegistry::new();
    registry.register(Box::new(options::ntp::NtpHandler));
    registry.register(Box::new(options::tzdb::TzdbHandler));

    // ── 4. Run every handler ──────────────────────────────────────────────────
    registry.process_all(&leases, &all_interfaces)?;

    Ok(())
}
