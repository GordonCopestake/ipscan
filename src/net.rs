//! Network interface discovery.
//!
//! With no target on the command line, `ipscan` has to answer "which network
//! am I on?" by itself. The reliable way is to ask the routing table which
//! source address it would pick, rather than guessing from interface names.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

use anyhow::{Context, Result, bail};

/// An IPv4-capable interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    pub name: String,
    pub addr: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub prefix: u8,
    pub broadcast: Option<Ipv4Addr>,
    pub loopback: bool,
}

impl Interface {
    /// First address of this interface's subnet.
    pub fn network(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.addr) & u32::from(self.netmask))
    }

    /// Usable host count, excluding network and broadcast addresses.
    pub fn usable_hosts(&self) -> u64 {
        let total = 1u64 << (32 - self.prefix);
        if self.prefix >= 31 {
            total
        } else {
            total.saturating_sub(2)
        }
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & u32::from(self.netmask) == u32::from(self.network())
    }

    /// True for interfaces that are tunnels, container bridges or overlays
    /// rather than a physical LAN. Scanning these by default is rarely useful.
    pub fn is_virtual(&self) -> bool {
        const PREFIXES: &[&str] = &[
            "docker",
            "veth",
            "br-",
            "virbr",
            "vmnet",
            "cni",
            "flannel",
            "cali",
            "kube",
            "wg",
            "tun",
            "tap",
            "zt",
            "tailscale",
            "utun",
            "ppp",
            "lo",
            "ip6tnl",
            "gre",
        ];
        PREFIXES.iter().any(|p| self.name.starts_with(p))
    }

    /// A /32 has no neighbours to find; it is a tunnel or a loopback.
    pub fn is_point_to_point(&self) -> bool {
        self.prefix >= 32
    }
}

/// Every interface on the host that has an IPv4 address.
pub fn list() -> Result<Vec<Interface>> {
    let ifaces = if_addrs::get_if_addrs().context("enumerating network interfaces")?;
    Ok(ifaces
        .into_iter()
        .filter_map(|i| match i.addr {
            if_addrs::IfAddr::V4(v4) => {
                let prefix = prefix_from_netmask(v4.netmask);
                Some(Interface {
                    name: i.name,
                    addr: v4.ip,
                    netmask: v4.netmask,
                    prefix,
                    broadcast: v4.broadcast,
                    loopback: v4.ip.is_loopback(),
                })
            }
            if_addrs::IfAddr::V6(_) => None,
        })
        .collect())
}

/// Look up one interface by name.
pub fn find(name: &str) -> Result<Interface> {
    list()?
        .into_iter()
        .find(|i| i.name == name)
        .with_context(|| format!("no interface named {name:?}"))
}

/// Pick the interface the OS would use to reach the outside world.
///
/// The trick is to open a UDP socket and `connect` it to a public address.
/// UDP is connectionless so nothing is transmitted, but the kernel still runs
/// routing and picks a source address, which tells us both which interface is
/// primary and which of its addresses is in play. Guessing from names like
/// `eth0` or `en0` gets this wrong on laptops with VPNs and container bridges.
pub fn primary() -> Result<Interface> {
    let candidates = list()?;

    if let Some(local) = default_source_addr() {
        if let Some(found) = candidates.iter().find(|i| i.addr == local) {
            return Ok(found.clone());
        }
    }

    // No usable route (offline, or the default route points nowhere). Fall back
    // to the most plausible physical interface.
    let mut plausible: Vec<&Interface> = candidates
        .iter()
        .filter(|i| !i.loopback && !i.is_virtual() && !i.is_point_to_point())
        .collect();
    plausible.sort_by_key(|i| std::cmp::Reverse(i.prefix));
    if let Some(best) = plausible.first() {
        return Ok((*best).clone());
    }

    // Last resort: anything not loopback.
    if let Some(any) = candidates.iter().find(|i| !i.loopback) {
        return Ok(any.clone());
    }

    bail!(
        "no usable IPv4 interface found. Pass a target explicitly, e.g. `ipscan 192.168.1.0/24`, \
         or list interfaces with `ipscan --list`"
    )
}

/// Ask the routing table which source address it would use.
fn default_source_addr() -> Option<Ipv4Addr> {
    // A documented public address that is never actually contacted.
    const PROBE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    let sock = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).ok()?;
    sock.connect(SocketAddr::from((PROBE, 53))).ok()?;
    match sock.local_addr() {
        Ok(a) => match a.ip() {
            std::net::IpAddr::V4(v4) if !v4.is_unspecified() => Some(v4),
            _ => None,
        },
        Err(_) => None,
    }
}

/// Count leading one-bits in a netmask to get a CIDR prefix length.
fn prefix_from_netmask(mask: Ipv4Addr) -> u8 {
    u32::from(mask).count_ones() as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(name: &str, addr: &str, mask: &str) -> Interface {
        let a: Ipv4Addr = addr.parse().unwrap();
        let m: Ipv4Addr = mask.parse().unwrap();
        Interface {
            name: name.into(),
            addr: a,
            netmask: m,
            prefix: prefix_from_netmask(m),
            broadcast: None,
            loopback: a.is_loopback(),
        }
    }

    #[test]
    fn prefix_is_derived_from_the_netmask() {
        assert_eq!(prefix_from_netmask(Ipv4Addr::new(255, 255, 255, 0)), 24);
        assert_eq!(prefix_from_netmask(Ipv4Addr::new(255, 255, 255, 255)), 32);
        assert_eq!(prefix_from_netmask(Ipv4Addr::new(0, 0, 0, 0)), 0);
        assert_eq!(prefix_from_netmask(Ipv4Addr::new(255, 255, 0, 0)), 16);
    }

    #[test]
    fn network_and_host_count() {
        let w = iface("wlan0", "192.168.0.79", "255.255.255.0");
        assert_eq!(w.network(), Ipv4Addr::new(192, 168, 0, 0));
        assert_eq!(w.usable_hosts(), 254);
        assert!(w.contains(Ipv4Addr::new(192, 168, 0, 1)));
        assert!(!w.contains(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn a_slash_32_has_no_usable_hosts() {
        let t = iface("tailscale0", "100.105.67.23", "255.255.255.255");
        assert!(t.is_point_to_point());
        assert_eq!(t.usable_hosts(), 1);
    }

    #[test]
    fn virtual_interfaces_are_recognised() {
        assert!(iface("docker0", "172.17.0.1", "255.255.0.0").is_virtual());
        assert!(iface("veth9f2a", "172.17.0.2", "255.255.0.0").is_virtual());
        assert!(iface("tailscale0", "100.64.0.1", "255.255.255.255").is_virtual());
        assert!(!iface("wlp0s20f3", "192.168.0.79", "255.255.255.0").is_virtual());
    }

    #[test]
    fn listing_finds_this_machines_interfaces() {
        let ifaces = list().expect("enumerating interfaces should work");
        assert!(!ifaces.is_empty());
    }
}
