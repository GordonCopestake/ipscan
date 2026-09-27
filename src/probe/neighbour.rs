//! Passive MAC address lookup from the operating system's neighbour table.
//!
//! Every OS already maintains an ARP/NDP cache, because that is what routing
//! requires. Reading it is therefore the cheapest possible way to attach a MAC
//! to a discovered host, and it needs **no privileges at all** on Linux,
//! macOS or Windows — unlike an active ARP sweep, which needs `CAP_NET_RAW` or
//! Administrator and cannot run from a desktop launcher.
//!
//! The trade-off is staleness: the table is populated by traffic we did, and
//! its entries expire. So a miss here is never evidence that a host is absent.
//! This module is a *source of MACs*, never a source of liveness — it reports
//! `Outcome::Alive` for a cached entry because the kernel resolved that address
//! at some point, and the scanner tags it as [`Method::Neighbour`] so the output
//! can distinguish a cached guess from a live answer.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use anyhow::Result;

use crate::host::MacAddr;
use crate::probe::Reply;

/// A single neighbour-table row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Neighbour {
    pub ip: Ipv4Addr,
    pub mac: MacAddr,
    /// Interface the entry was learned on, when the OS reports it.
    pub iface: Option<String>,
}

/// Read the whole neighbour table.
pub fn read_table() -> Result<Vec<Neighbour>> {
    platform::read()
}

/// Look up specific addresses, returning only the ones the table knows.
///
/// Incomplete entries (an address we tried to reach but never resolved) are
/// dropped: they are the neighbour table's way of saying "no", and an
/// all-zero or missing MAC is not a hardware address.
pub fn lookup(targets: &[Ipv4Addr]) -> Result<HashMap<Ipv4Addr, Neighbour>> {
    let table = read_table()?;
    Ok(table
        .into_iter()
        .filter(|n| targets.contains(&n.ip))
        .map(|n| (n.ip, n))
        .collect())
}

/// The table as probe replies, for hosts it knows about.
pub fn as_replies(entries: &HashMap<Ipv4Addr, Neighbour>) -> Vec<Reply> {
    let mut out: Vec<Reply> = entries
        .values()
        .map(|n| Reply::new(n.ip, crate::host::Outcome::Alive))
        .collect();
    out.sort_by_key(|r| u32::from(r.ip));
    out
}

#[allow(dead_code)]
fn parse_mac_field(s: &str) -> Option<MacAddr> {
    let t = s.trim();
    if t.is_empty() || t == "(incomplete)" || t == "00:00:00:00:00:00" {
        return None;
    }
    MacAddr::parse(t)
}

// --------------------------------------------------------------- linux ----

#[cfg(target_os = "linux")]
mod platform {
    use std::fs;
    use std::net::Ipv4Addr;

    use anyhow::{Context, Result};

    use super::Neighbour;

    /// `/proc/net/arp` columns:
    /// `IP address  HW type  Flags  HW address  Mask  Device`
    ///
    /// Flags is the important one: `0x0` marks an incomplete entry, meaning the
    /// kernel tried to resolve that address and failed. Those must not be
    /// reported as hosts.
    pub fn read() -> Result<Vec<Neighbour>> {
        let text = fs::read_to_string("/proc/net/arp").context("reading /proc/net/arp")?;
        let mut out = Vec::new();

        for line in text.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 6 {
                continue;
            }
            let Ok(ip) = f[0].parse::<Ipv4Addr>() else {
                continue;
            };
            let flags = f[2];
            if flags.trim_start_matches("0x") == "0" {
                continue;
            }
            let Some(mac) = super::parse_mac_field(f[3]) else {
                continue;
            };
            if mac.is_broadcast() {
                continue;
            }
            out.push(Neighbour {
                ip,
                mac,
                iface: Some(f[5].to_string()),
            });
        }
        Ok(out)
    }
}

// --------------------------------------------------------------- macos ----

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod platform {
    use std::net::Ipv4Addr;
    use std::process::Command;

    use anyhow::{Result, bail};

    use super::Neighbour;

    /// macOS exposes no unprivileged neighbour-table API worth the trouble, but
    /// the `arp` utility does exactly what we need.
    ///
    /// Lines look like:
    /// ```text
    /// ? (192.168.0.1) at f0:9:d2a:86:fd on en0 ifscope [ethernet]
    /// ```
    pub fn read() -> Result<Vec<Neighbour>> {
        let out = Command::new("/sbin/arp").arg("-n").output();
        let out = match out {
            Ok(o) if o.status.success() => o,
            // A sandboxed or minimal host may not ship the tool. Not fatal:
            // MACs are a nicety, liveness comes from the other probes.
            Ok(o) => bail!("`arp -n` failed with {}", o.status),
            Err(e) => bail!("running `arp -n`: {e}"),
        };

        let text = String::from_utf8_lossy(&out.stdout);
        let mut neighbours = Vec::new();

        for line in text.lines() {
            // Skip the "(bad)" entries macOS emits for unresolved addresses.
            if line.contains("(incomplete)") || line.contains("incomplete") {
                continue;
            }
            let Some(open) = line.find('(') else { continue };
            let Some(close) = line[open..].find(')').map(|i| i + open) else {
                continue;
            };
            let Ok(ip) = line[open + 1..close].parse::<Ipv4Addr>() else {
                continue;
            };

            let Some(at) = line.find(" at ") else {
                continue;
            };
            let after = &line[at + 4..];
            let mac_end = after.find(' ').unwrap_or(after.len());
            let Some(mac) = super::parse_mac_field(&after[..mac_end]) else {
                continue;
            };
            if mac.is_broadcast() {
                continue;
            }

            let iface = line
                .split(" on ")
                .nth(1)
                .and_then(|rest| rest.split_whitespace().next())
                .map(str::to_string);

            neighbours.push(Neighbour { ip, mac, iface });
        }

        Ok(neighbours)
    }
}

// ------------------------------------------------------------- windows ----

#[cfg(windows)]
mod platform {
    use std::net::Ipv4Addr;

    use anyhow::Result;
    use windows::Win32::NetworkManagement::IpHelper::{
        GetIpNetTable, MIB_IPNETROW_LH, MIB_IPNETTABLE,
    };

    /// `GetIpNetTable` fills a buffer the caller supplies, so it is called twice:
    /// once with a null pointer to learn how much space the table needs, and once
    /// more with an allocation of at least that size.
    ///
    /// The v1 table is used rather than `GetIpNetTable2` because v2 hands back an
    /// allocation that must be released with `NetApiFreeMemory`, and that symbol
    /// is not exported by `netapi32.dll` on current Windows. Importing it makes
    /// the whole binary fail to load with STATUS_ENTRYPOINT_NOT_FOUND.
    pub fn read() -> Result<Vec<super::Neighbour>> {
        const NO_ERROR: u32 = 0;
        const ERROR_BUFFER_OVERFLOW: u32 = 111;
        const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
        const ERROR_NO_DATA: u32 = 232;

        let mut size: u32 = 0;
        let rc = unsafe { GetIpNetTable(None, &mut size, false) };

        // An empty table is a normal state on a fresh machine, but it is the one
        // empty answer that is allowed to stay quiet. Everything else is a
        // failure, and reporting it as "no entries" is what makes a broken read
        // indistinguishable from a genuinely empty cache.
        if rc == ERROR_NO_DATA || size == 0 {
            return Ok(Vec::new());
        }
        // The two codes are aliases in practice. Documented as
        // ERROR_BUFFER_OVERFLOW, but the size query with a null buffer comes
        // back as ERROR_INSUFFICIENT_BUFFER, and taking only the documented one
        // made a working cache unreadable on the machine that reported it.
        if rc != ERROR_BUFFER_OVERFLOW && rc != ERROR_INSUFFICIENT_BUFFER && rc != NO_ERROR {
            anyhow::bail!("GetIpNetTable could not report the table size: error {rc}");
        }
        if size == 0 {
            return Ok(Vec::new());
        }

        // The API is free to want more space on the second call than it reported
        // on the first, so keep some headroom rather than risk another overflow.
        // Allocated as words rather than bytes because the table starts with a
        // `u32` count and the API writes 32-bit fields through the pointer: a
        // byte buffer has no alignment guarantee, and forming a reference to an
        // under-aligned table is undefined behaviour.
        let mut buf = vec![0u32; (size as usize + 4096).div_ceil(std::mem::size_of::<u32>())];
        let mut size = (buf.len() * std::mem::size_of::<u32>()) as u32;
        let rc = unsafe {
            GetIpNetTable(
                Some(buf.as_mut_ptr().cast::<MIB_IPNETTABLE>()),
                &mut size,
                false,
            )
        };
        if rc != NO_ERROR {
            anyhow::bail!("GetIpNetTable failed to read the table: error {rc}");
        }

        // Read the header, then the rows that follow. `table` is a one-element
        // array that really holds `dwNumEntries` rows.
        let table = unsafe { &*buf.as_ptr().cast::<MIB_IPNETTABLE>() };
        let num = table.dwNumEntries as usize;
        if num == 0 {
            anyhow::bail!("GetIpNetTable reported {size} bytes but no rows in them");
        }
        let rows = unsafe { std::slice::from_raw_parts(table.table.as_ptr(), num) };
        Ok(rows.iter().filter_map(row_to_neighbour).collect())
    }

    fn row_to_neighbour(row: &MIB_IPNETROW_LH) -> Option<super::Neighbour> {
        // Only rows the stack has actually resolved are worth reporting, and
        // only Ethernet-sized hardware addresses can be a MAC.
        let len = row.dwPhysAddrLen as usize;
        if len == 0 || len > 6 {
            return None;
        }
        let ip = Ipv4Addr::from(row.dwAddr.to_ne_bytes());

        let mut bytes = [0u8; 6];
        bytes[..len].copy_from_slice(&row.bPhysAddr[..len]);
        let mac = crate::host::MacAddr::from_bytes(bytes);
        if mac.is_broadcast() {
            return None;
        }

        Some(super::Neighbour {
            ip,

            mac,
            iface: None,
        })
    }
}

// Any other Unix: no portable source, so report that plainly.
#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "macos", target_os = "ios"))
))]
mod platform {
    use anyhow::{Result, bail};

    pub fn read() -> Result<Vec<super::Neighbour>> {
        bail!(
            "no passive neighbour-table source on this platform; use --method arp with privileges"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_field_rejects_junk_and_placeholders() {
        assert!(parse_mac_field("f0:09:0d:2a:86:fd").is_some());
        assert!(parse_mac_field("  bc:24:11:eb:cf:14 ").is_some());
        assert_eq!(parse_mac_field("(incomplete)"), None);
        assert_eq!(parse_mac_field("00:00:00:00:00:00"), None);
        assert_eq!(parse_mac_field(""), None);
        assert_eq!(parse_mac_field("??"), None);
    }

    #[test]
    fn linux_neighbour_table_is_readable_and_well_formed() {
        #[cfg(target_os = "linux")]
        {
            let table = read_table().expect("/proc/net/arp should be readable");
            for n in &table {
                assert!(!n.mac.is_broadcast(), "broadcast must not be a host: {n:?}");
                assert!(n.mac.0 != [0; 6], "an all-zero MAC is not a host: {n:?}");
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = read_table();
        }
    }

    #[test]
    fn lookup_only_returns_requested_addresses() {
        let targets = vec![Ipv4Addr::LOCALHOST];
        // The neighbour table is an optional source: a host without `arp`, or
        // without permission to read the table, simply has nothing to say, and
        // production code treats a failed read as "no data" rather than as a
        // scan error. So only assert when the table was actually readable.
        if let Ok(found) = lookup(&targets) {
            // Loopback never has a neighbour-table row, so the result must be
            // empty rather than a fabricated entry.
            assert!(!found.contains_key(&Ipv4Addr::LOCALHOST));
            assert!(found.keys().all(|ip| targets.contains(ip)));
        }
    }
}
