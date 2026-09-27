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
        GetIpNetTable2, MIB_IPNET_ROW2, MIB_IPNET_TABLE2,
    };
    use windows::Win32::Networking::WinSock::AF_INET;

    /// `GetIpNetTable2` allocates the table for us and reports ERROR_BUFFER_OVERFLOW
    /// the first time, so it is called twice: once to learn there is a table at
    /// all, and once more to actually fill it.
    pub fn read() -> Result<Vec<super::Neighbour>> {
        let mut raw: *mut MIB_IPNET_TABLE2 = std::ptr::null_mut();
        let rc = unsafe { GetIpNetTable2(AF_INET, &mut raw) };

        // ERROR_NO_DATA (232) means the neighbour table is simply empty, which is
        // a normal state on a fresh machine and not an error.
        if rc.0 != 0 || raw.is_null() {
            return Ok(Vec::new());
        }

        // The table is owned by the OS once it has been handed back, so it has
        // to be released no matter how the rows are read.
        let guard = TableGuard(raw);
        let table = unsafe { &*guard.0 };

        let num = table.NumEntries as usize;
        if num == 0 {
            return Ok(Vec::new());
        }
        // `Table` is a one-element array that really holds `NumEntries` rows.
        let rows = unsafe { std::slice::from_raw_parts(table.Table.as_ptr(), num) };

        Ok(rows.iter().filter_map(row_to_neighbour).collect())
    }

    /// Frees the table with `NetApiFreeMemory` on drop.
    struct TableGuard(*mut MIB_IPNET_TABLE2);

    impl Drop for TableGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { net_api_free_memory(self.0.cast()) };
            }
        }
    }

    // `NetApiFreeMemory` is not in the `windows` bindings, so it is declared
    // here. It lives in `netapi32.dll` and is the documented counterpart to the
    // allocation `GetIpNetTable2` performs.
    #[link(name = "netapi32")]
    unsafe extern "system" {
        #[link_name = "NetApiFreeMemory"]
        fn net_api_free_memory(buffer: *mut std::ffi::c_void);
    }

    fn row_to_neighbour(row: &MIB_IPNET_ROW2) -> Option<super::Neighbour> {
        // Only rows the stack has actually resolved are worth reporting, and
        // only Ethernet-sized hardware addresses can be a MAC.
        let len = row.PhysicalAddressLength as usize;
        if len == 0 || len > 6 {
            return None;
        }
        if unsafe { row.Address.si_family } != AF_INET {
            return None;
        }
        let sin = unsafe { row.Address.Ipv4 };
        let ip = Ipv4Addr::from(unsafe { sin.sin_addr.S_un.S_addr }.to_ne_bytes());

        let mut bytes = [0u8; 6];
        bytes[..len].copy_from_slice(&row.PhysicalAddress[..len]);
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
        // Loopback never has a neighbour-table row, so the result must be empty
        // rather than a fabricated entry.
        let targets = vec![Ipv4Addr::LOCALHOST];
        let found = lookup(&targets).unwrap();
        assert!(!found.contains_key(&Ipv4Addr::LOCALHOST));
    }
}
