//! Option handler infrastructure.
//!
//! # Adding a new option handler
//!
//! 1. Create `src/options/myoption.rs` and implement the `OptionHandler` trait.
//! 2. Add `pub mod myoption;` in this file.
//! 3. In `main.rs`, call `registry.register(Box::new(options::myoption::MyHandler));`
//!
//! The `OptionHandler::process` method receives:
//! - `leases`        — all parsed leases, including expired ones (filter yourself)
//! - `all_interfaces`— every non-loopback interface on the host
//!
//! Use these to decide which interfaces have active leases and which are
//! unmanaged (no valid lease), then perform whatever system-level action is
//! appropriate for your option.

pub mod ntp;
pub mod tzdb;

use crate::lease::Lease;
use anyhow::Result;

// ─────────────────────────────────────────────────────────────────────────────
// Trait
// ─────────────────────────────────────────────────────────────────────────────

/// Implement this trait to handle a DHCPv6 option.
pub trait OptionHandler: Send + Sync {
    /// The DHCPv6 option code this handler is responsible for.
    fn option_code(&self) -> u16;

    /// Human-readable name for log messages.
    fn name(&self) -> &str;

    /// Process the option across all leases and interfaces.
    ///
    /// Implementors should:
    /// - Filter `leases` with `!lease.is_expired()` to get active leases.
    /// - Use `all_interfaces` to detect unmanaged interfaces
    ///   (those not present in any non-expired lease's `interface` field).
    /// - Perform the desired system action (write config, set tz, etc.).
    fn process(&self, leases: &[Lease], all_interfaces: &[String]) -> Result<()>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Registry
// ─────────────────────────────────────────────────────────────────────────────

/// Holds all registered option handlers and dispatches to them.
pub struct HandlerRegistry {
    handlers: Vec<Box<dyn OptionHandler>>,
}

impl HandlerRegistry {
    pub fn new() -> Self {
        Self {
            handlers: Vec::new(),
        }
    }

    /// Register an option handler.  Each option code may have at most one
    /// handler; if you register a second handler for the same code the first
    /// is silently replaced.
    pub fn register(&mut self, handler: Box<dyn OptionHandler>) {
        log::info!(
            "Registering handler for option {} ({})",
            handler.option_code(),
            handler.name()
        );
        // Replace any existing handler for the same option code
        if let Some(pos) = self
            .handlers
            .iter()
            .position(|h| h.option_code() == handler.option_code())
        {
            self.handlers[pos] = handler;
        } else {
            self.handlers.push(handler);
        }
    }

    /// Run every registered handler, logging errors but continuing on failure.
    pub fn process_all(&self, leases: &[Lease], all_interfaces: &[String]) -> Result<()> {
        for handler in &self.handlers {
            log::info!(
                "Running handler: option {} ({})",
                handler.option_code(),
                handler.name()
            );
            if let Err(e) = handler.process(leases, all_interfaces) {
                log::error!(
                    "Handler option {} ({}) failed: {:#}",
                    handler.option_code(),
                    handler.name(),
                    e
                );
            }
        }
        Ok(())
    }
}
