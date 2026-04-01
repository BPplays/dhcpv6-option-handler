mod interfaces;
mod lease;
mod options;

use chrono::{DateTime, Duration, Utc};

use anyhow::Result;
use log::info;

use std::{
    collections::{HashMap, HashSet},
    error::Error,
    net::Ipv6Addr,
};

use dhcproto::v6::{Decoder as DhcpDecoder, Decodable, Message};
use etherparse::SlicedPacket;
use pcap::{Capture, Device};

const DHCPV6_SERVER_PORT: u16 = 547;
const DHCPV6_CLIENT_PORT: u16 = 546;

const OPT_NTP_SERVER: u16 = 56;
const OPT_TZDB: u16 = 42;
const OPT_RELAY_MESSAGE: u16 = 9;
const OPT_INFORMATION_REFRESH_TIME: u16 = 32;
const IRT_INFINITY: u32 = 0xffff_ffff;

#[derive(Debug, Default, Clone)]
struct PacketFacts {
    pub ntp_servers: Vec<String>,
    pub tzdb_names: Vec<String>,
    pub expires: Option<DateTime<Utc>>,
}

trait OptionHandler: Send + Sync {
    fn code(&self) -> u16;
    fn handle(&self, value: &[u8], out: &mut PacketFacts) -> Result<(), String>;
}

struct Registry {
    handlers: HashMap<u16, Box<dyn OptionHandler>>,
}

impl Registry {
    fn new() -> Self {
        let mut handlers: HashMap<u16, Box<dyn OptionHandler>> = HashMap::new();
        handlers.insert(OPT_NTP_SERVER, Box::new(NtpHandler));
        handlers.insert(OPT_TZDB, Box::new(TzdbHandler));
        Self { handlers }
    }

    fn handle(&self, code: u16, value: &[u8], out: &mut PacketFacts) -> Result<(), String> {
        if let Some(h) = self.handlers.get(&code) {
            h.handle(value, out)
        } else {
            Ok(())
        }
    }
}

struct NtpHandler;
struct TzdbHandler;

impl OptionHandler for NtpHandler {
    fn code(&self) -> u16 {
        OPT_NTP_SERVER
    }

    fn handle(&self, value: &[u8], out: &mut PacketFacts) -> Result<(), String> {
        // RFC 5908 option 56 is a container with NTP server suboptions.
        // We decode the suboptions generically so the exact suboption list is easy to extend.
        let mut rest = value;

        while rest.len() >= 4 {
            let subcode = u16::from_be_bytes([rest[0], rest[1]]);
            let len = u16::from_be_bytes([rest[2], rest[3]]) as usize;

            if rest.len() < 4 + len {
                break;
            }

            let body = &rest[4..4 + len];

            match subcode {
                // IPv6 address server location
                1 | 2 if len == 16 => {
                    let addr = Ipv6Addr::from(<[u8; 16]>::try_from(body).unwrap());
                    out.ntp_servers.push(addr.to_string());
                }
                // Hostname/FQDN server location, encoded as a DNS name
                3 => {
                    if let Ok(name) = decode_dns_name(body) {
                        if !name.is_empty() {
                            out.ntp_servers.push(name);
                        }
                    }
                }
                _ => {}
            }

            rest = &rest[4 + len..];
        }

        Ok(())
    }
}

impl OptionHandler for TzdbHandler {
    fn code(&self) -> u16 {
        OPT_TZDB
    }

    fn handle(&self, value: &[u8], out: &mut PacketFacts) -> Result<(), String> {
        // RFC 4833 option 42 is the TZ database string.
        let s = std::str::from_utf8(value).map_err(|e| e.to_string())?;
        let s = s.trim_end_matches('\0').trim();
        if !s.is_empty() {
            out.tzdb_names.push(s.to_string());
        }
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let dev = Device::lookup()?.ok_or("no default device")?;
    let mut cap = Capture::from_device(dev)?
        .promisc(true)
        .timeout(1000)
        .open()?;

    // DHCPv6 client/server traffic.
    cap.filter("udp and (port 546 or port 547)", true)?;

    let registry = Registry::new();

    loop {
        match cap.next_packet() {
            Ok(pkt) => {
                if let Some(payload) = extract_dhcpv6_payload(pkt.data) {
                    match parse_dhcpv6_message(payload, &registry) {
                        Ok(facts) => {
                            if !facts.ntp_servers.is_empty() || !facts.tzdb_names.is_empty() {
                                println!("{facts:#?}");
                            }
                        }
                        Err(e) => eprintln!("parse error: {e}"),
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => return Err(Box::new(e)),
        }
    }
}

fn parse_dhcpv6_message(payload: &[u8], registry: &Registry) -> Result<PacketFacts, String> {
    // dhcproto validates the DHCPv6 framing.
    let _msg = Message::decode(&mut DhcpDecoder::new(payload)).map_err(|e| e.to_string())?;

    // Then we walk the raw options ourselves so we can get exact option bodies.
    // This keeps option handling easy to extend.
    parse_dhcpv6_options(payload)
        .map(|facts| {
            // facts already collected from options
            facts
        })
}

fn parse_dhcpv6_options(payload: &[u8]) -> Result<PacketFacts, String> {
    if payload.len() < 4 {
        return Err("short DHCPv6 message".into());
    }

    let mut facts = PacketFacts::default();
    parse_options_recursive(&payload[4..], &mut facts)?;
    Ok(facts)
}

fn parse_options_recursive(mut data: &[u8], facts: &mut PacketFacts) -> Result<(), String> {
    while data.len() >= 4 {
        let code = u16::from_be_bytes([data[0], data[1]]);
        let len = u16::from_be_bytes([data[2], data[3]]) as usize;

        if data.len() < 4 + len {
            break;
        }

        let value = &data[4..4 + len];

        match code {
            OPT_RELAY_MESSAGE => {
                // Relay-Message contains another DHCPv6 message.
                if value.len() >= 4 {
                    let _ = parse_dhcpv6_options(value).map(|nested| {
                        facts.ntp_servers.extend(nested.ntp_servers);
                        facts.tzdb_names.extend(nested.tzdb_names);
                    });
                }
            }
            OPT_NTP_SERVER => parse_ntp_option(value, facts)?,
            OPT_TZDB => parse_tzdb_option(value, facts)?,
            OPT_INFORMATION_REFRESH_TIME => parse_information_refresh_time(value, facts)?,
            _ => {}
        }

        data = &data[4 + len..];
    }

    Ok(())
}

fn parse_information_refresh_time(value: &[u8], facts: &mut PacketFacts) -> Result<(), String> {
    if value.len() != 4 {
        return Err("invalid information refresh time length".into());
    }

    let secs = u32::from_be_bytes(value.try_into().unwrap());

    if secs == IRT_INFINITY {
        facts.expires = None;
        return Ok(());
    }

    let expire_at = Utc::now() + Duration::seconds(secs as i64);
    facts.expires = Some(expire_at);
    Ok(())
}

fn parse_ntp_option(value: &[u8], facts: &mut PacketFacts) -> Result<(), String> {
    let mut rest = value;

    while rest.len() >= 4 {
        let subcode = u16::from_be_bytes([rest[0], rest[1]]);
        let len = u16::from_be_bytes([rest[2], rest[3]]) as usize;

        if rest.len() < 4 + len {
            break;
        }

        let body = &rest[4..4 + len];

        match subcode {
            1 | 2 if len == 16 => {
                let addr = Ipv6Addr::from(<[u8; 16]>::try_from(body).unwrap());
                facts.ntp_servers.push(addr.to_string());
            }
            3 => {
                if let Ok(name) = decode_dns_name(body) {
                    if !name.is_empty() {
                        facts.ntp_servers.push(name);
                    }
                }
            }
            _ => {}
        }

        rest = &rest[4 + len..];
    }

    Ok(())
}

fn parse_tzdb_option(value: &[u8], facts: &mut PacketFacts) -> Result<(), String> {
    let s = std::str::from_utf8(value).map_err(|e| e.to_string())?;
    let s = s.trim_end_matches('\0').trim();
    if !s.is_empty() {
        facts.tzdb_names.push(s.to_string());
    }
    Ok(())
}

fn extract_dhcpv6_payload(frame: &[u8]) -> Option<&[u8]> {
    let sliced = SlicedPacket::from_ethernet(frame).ok()?;
    let transport = sliced.transport?;

    match transport {
        etherparse::TransportSlice::Udp(udp) => {
            let src = udp.source_port();
            let dst = udp.destination_port();
            if (src == DHCPV6_CLIENT_PORT && dst == DHCPV6_SERVER_PORT)
                || (src == DHCPV6_SERVER_PORT && dst == DHCPV6_CLIENT_PORT)
            {
                Some(udp.payload())
            } else {
                None
            }
        }
        _ => None,
    }
}

fn decode_dns_name(mut data: &[u8]) -> Result<String, String> {
    let mut labels = Vec::new();

    while !data.is_empty() {
        let len = data[0] as usize;
        if len == 0 {
            return Ok(labels.join("."));
        }
        if len & 0xC0 != 0 {
            return Err("compressed names not supported".into());
        }
        if data.len() < 1 + len {
            return Err("truncated DNS name".into());
        }

        let label = std::str::from_utf8(&data[1..1 + len]).map_err(|e| e.to_string())?;
        labels.push(label.to_string());
        data = &data[1 + len..];
    }

    Err("unterminated DNS name".into())
}

// fn main() -> Result<()> {
//     env_logger::Builder::from_env(
//         env_logger::Env::default().default_filter_or("info"),
//     )
//     .init();
//
//     // ── 1. Discover all non-loopback network interfaces ──────────────────────
//     let all_interfaces = interfaces::discover()?;
//     info!(
//         "Discovered {} interface(s): {:?}",
//         all_interfaces.len(),
//         all_interfaces
//     );
//
//     // ── 2. Parse every DHCPv6 lease file we can find ─────────────────────────
//     let leases = lease::discover_and_parse()?;
//     let valid_count = leases.iter().filter(|l| !l.is_expired()).count();
//     info!(
//         "Parsed {} lease(s) total, {} non-expired",
//         leases.len(),
//         valid_count
//     );
//
//     // ── 3. Build option handler registry ─────────────────────────────────────
//     //
//     //   To add a new option handler:
//     //     1. Create  src/options/myoption.rs  implementing `OptionHandler`.
//     //     2. Add     pub mod myoption;        in src/options/mod.rs.
//     //     3. Register it below with           registry.register(…).
//     //
//     let mut registry = options::HandlerRegistry::new();
//     registry.register(Box::new(options::ntp::NtpHandler));
//     registry.register(Box::new(options::tzdb::TzdbHandler));
//
//     // ── 4. Run every handler ──────────────────────────────────────────────────
//     registry.process_all(&leases, &all_interfaces)?;
//
//     Ok(())
// }
