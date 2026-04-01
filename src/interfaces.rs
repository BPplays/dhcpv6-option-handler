use anyhow::Result;
use std::fs;

/// Return a sorted list of every non-loopback network interface on the system.
pub fn discover() -> Result<Vec<String>> {
    let mut interfaces = Vec::new();

    let dir = match fs::read_dir("/sys/class/net") {
        Ok(d) => d,
        Err(e) => {
            log::warn!("Could not read /sys/class/net: {}", e);
            return Ok(interfaces);
        }
    };

    for entry in dir.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name != "lo" {
            interfaces.push(name);
        }
    }

    interfaces.sort();
    Ok(interfaces)
}
