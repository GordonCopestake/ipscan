//! Active ARP sweeping.
//!
//! ARP is the strongest liveness signal available on a directly-connected
//! link, and the cheapest: the request is a broadcast that every host on the
//! segment must answer, and no host firewall can interfere, because it is
//! answered below the layer where firewalls live. It is also the only method
//! that yields a MAC address for a host which does not answer ICMP.
//!
//! # The trade-off, stated plainly
//!
//! ARP is *link-local*. It cannot cross a router, so it is only meaningful for
//! targets on a subnet this machine is directly attached to; on a /16 the other
//! fifteen /24s are invisible to it no matter how many hosts they contain. It
//! also needs raw packet access, so it is unavailable to an unprivileged
//! process. For those two reasons this probe is an **accelerator layered on top
//! of the passive neighbour table**, not the backbone of the scan: the scanner
//! runs the passive table first, and only reaches for this when privileges and a
//! directly-connected target set are both available.

use std::net::Ipv4Addr;
use std::time::Duration;

use anyhow::Result;

use crate::probe::{ProbeConfig, Reply};

/// Whether an active sweep can run at all, and why not if it cannot.
#[derive(Debug, Clone)]
pub struct Availability {
    pub available: bool,
    /// Human-readable explanation, shown in `--verbose` and in error messages.
    pub reason: String,
}

// Which of these constructors is used depends on the target: only platforms
// with an active ARP path can report success.
#[allow(dead_code)]
impl Availability {
    fn ok(reason: impl Into<String>) -> Self {
        Availability {
            available: true,
            reason: reason.into(),
        }
    }

    fn no(reason: impl Into<String>) -> Self {
        Availability {
            available: false,
            reason: reason.into(),
        }
    }
}

pub struct ArpProber {
    inner: platform::Inner,
}

impl ArpProber {
    /// Probe the platform for sweep capability without needing a target list.
    pub fn availability() -> Availability {
        platform::availability()
    }

    pub fn new(cfg: &ProbeConfig) -> Result<Self> {
        Ok(ArpProber {
            inner: platform::Inner::new(cfg)?,
        })
    }

    /// Broadcast one request per target and collect the replies.
    pub fn probe_round(&mut self, targets: &[Ipv4Addr]) -> Result<Vec<Reply>> {
        self.inner.probe_round(targets)
    }

    pub fn timeout(&self) -> Duration {
        self.inner.timeout()
    }
}

/// Replies carry the MAC alongside the liveness verdict, because for ARP the
/// hardware address is the payload rather than an afterthought.
pub use crate::host::MacAddr as ArpMac;

// ---------------------------------------------------------------- linux ----

#[cfg(target_os = "linux")]
mod platform {
    use std::net::Ipv4Addr;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::time::{Duration, Instant};

    use anyhow::{Result, bail};
    use libc::{AF_PACKET, ETH_P_ALL, ETH_P_ARP, SOCK_RAW, c_void, pollfd};

    use super::{Availability, Reply};
    use crate::host::{MacAddr, Outcome};
    use crate::probe::ProbeConfig;

    /// Offset of the fields we want inside `struct arphdr`.
    const ARPHDR_FIXED_LEN: usize = 8;
    const HTYPE_ETHER: u16 = 1;
    /// The EtherType for ARP, in the 16-bit form the wire format uses.
    const ETHERTYPE_ARP: u16 = 0x0806;

    pub struct Inner {
        fd: OwnedFd,
        iface: String,
        ifindex: i32,
        our_mac: [u8; 6],
        our_ip: Ipv4Addr,
        timeout: Duration,
    }

    pub fn availability() -> Availability {
        let probe = unsafe {
            libc::socket(
                AF_PACKET,
                SOCK_RAW | libc::SOCK_CLOEXEC,
                (ETH_P_ALL as u16).to_be() as i32,
            )
        };
        if probe < 0 {
            let e = std::io::Error::last_os_error();
            return Availability::no(format!(
                "active ARP needs CAP_NET_RAW (or root): {e}. \
                 The passive neighbour table is used instead and needs no privileges."
            ));
        }
        unsafe { libc::close(probe) };
        Availability::ok("AF_PACKET raw socket")
    }

    impl Inner {
        pub fn new(cfg: &ProbeConfig) -> Result<Self> {
            let Some(iface_name) = cfg.iface.clone() else {
                bail!("--method arp needs an interface; pass --interface or let ipscan pick one")
            };

            let fd = unsafe {
                libc::socket(
                    AF_PACKET,
                    SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                    0,
                )
            };
            if fd < 0 {
                bail!(
                    "cannot open an AF_PACKET socket: {}. Active ARP needs root or CAP_NET_RAW; \
                     the unprivileged neighbour table is used by default instead.",
                    std::io::Error::last_os_error()
                );
            }
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };

            let ifindex = interface_index(&iface_name)?;
            let (our_mac, our_ip) = interface_identity(&iface_name)?;

            // Bind to the interface and the ARP ethertype, so the kernel only
            // hands us frames from this link and only of the type we asked for.
            let sll = libc::sockaddr_ll {
                sll_family: AF_PACKET as u16,
                sll_protocol: (ETH_P_ARP as u16).to_be(),
                sll_ifindex: ifindex,
                sll_hatype: 1,
                sll_pkttype: 0,
                sll_halen: 6,
                sll_addr: [0; 8],
            };
            let rc = unsafe {
                libc::bind(
                    fd.as_raw_fd(),
                    &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
                )
            };
            if rc < 0 {
                bail!(
                    "binding AF_PACKET to {iface_name}: {}",
                    std::io::Error::last_os_error()
                );
            }

            Ok(Inner {
                fd,
                iface: iface_name,
                ifindex,
                our_mac,
                our_ip,
                timeout: cfg.timeout,
            })
        }

        pub fn timeout(&self) -> Duration {
            self.timeout
        }

        pub fn probe_round(&mut self, targets: &[Ipv4Addr]) -> Result<Vec<Reply>> {
            if targets.is_empty() {
                return Ok(Vec::new());
            }

            let broadcast = self.broadcast_address();
            let mut sent = 0usize;
            for &ip in targets {
                let frame = self.build_request(ip, broadcast);
                if self.send(&frame).is_ok() {
                    sent += 1;
                }
            }
            if sent == 0 {
                return Ok(Vec::new());
            }

            self.collect(targets, Duration::from_millis(250))
        }

        /// Build an Ethernet II frame carrying an ARP "who has X, tell me" request.
        fn build_request(&self, target: Ipv4Addr, _broadcast: Ipv4Addr) -> Vec<u8> {
            let mut f = Vec::with_capacity(42);
            // Ethernet: broadcast destination, us as source, ARP ethertype.
            f.extend_from_slice(&[0xff; 6]);
            f.extend_from_slice(&self.our_mac);
            f.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());
            // ARP: hardware ethernet/IPv4, request, our MAC and IP as sender,
            // target IP as the address we want, and a zero sender to be filled
            // in by whoever answers.
            f.extend_from_slice(&HTYPE_ETHER.to_be_bytes());
            f.extend_from_slice(&0x0800u16.to_be_bytes());
            f.extend_from_slice(&8u8.to_be_bytes());
            f.extend_from_slice(&4u8.to_be_bytes());
            f.extend_from_slice(&HTYPE_ETHER.to_be_bytes());
            f.extend_from_slice(&0x0800u16.to_be_bytes());
            f.extend_from_slice(&6u8.to_be_bytes());
            f.extend_from_slice(&4u8.to_be_bytes());
            f.extend_from_slice(&HTYPE_ETHER.to_be_bytes());
            f.extend_from_slice(&self.our_mac);
            f.extend_from_slice(&self.our_ip.octets());
            f.extend_from_slice(&[0u8; 6]);
            f.extend_from_slice(&target.octets());
            f
        }

        fn send(&self, frame: &[u8]) -> std::io::Result<usize> {
            let dst = libc::sockaddr_ll {
                sll_family: AF_PACKET as u16,
                sll_protocol: (ETH_P_ARP as u16).to_be(),
                sll_ifindex: self.ifindex,
                sll_hatype: 1,
                sll_pkttype: 0,
                sll_halen: 6,
                sll_addr: [0xff; 8],
            };
            let n = unsafe {
                libc::sendto(
                    self.fd.as_raw_fd(),
                    frame.as_ptr() as *const c_void,
                    frame.len(),
                    0,
                    &dst as *const libc::sockaddr_ll as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
                )
            };
            if n < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }

        /// Read replies until the grace period passes or every target answered.
        fn collect(&mut self, targets: &[Ipv4Addr], grace: Duration) -> Result<Vec<Reply>> {
            let deadline = Instant::now() + self.timeout.max(grace);
            let mut found: Vec<Reply> = Vec::new();
            let mut buf = [0u8; 2048];

            while Instant::now() < deadline && found.len() < targets.len() {
                let remaining = deadline.saturating_duration_since(Instant::now());
                let mut pfd = pollfd {
                    fd: self.fd.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                let ms = remaining.as_millis().min(200) as libc::c_int;
                let rc = unsafe { libc::poll(&mut pfd, 1, ms) };
                if rc < 0 {
                    let e = std::io::Error::last_os_error();
                    if e.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(e.into());
                }
                if rc == 0 {
                    continue;
                }

                let n = unsafe {
                    libc::recv(
                        self.fd.as_raw_fd(),
                        buf.as_mut_ptr() as *mut c_void,
                        buf.len(),
                        0,
                    )
                };
                if n <= 0 {
                    continue;
                }
                let frame = &buf[..n as usize];
                if let Some((ip, mac)) = parse_arp_reply(frame) {
                    // Ignore replies for addresses we never asked about: they
                    // are somebody else's traffic, not our evidence.
                    if targets.contains(&ip) && !found.iter().any(|r| r.ip == ip) {
                        found.push(Reply::new(ip, Outcome::Alive).with_mac(mac));
                    }
                }
            }
            Ok(found)
        }

        fn broadcast_address(&self) -> Ipv4Addr {
            match crate::net::find(&self.iface) {
                Ok(i) => Ipv4Addr::from(u32::from(i.addr) | !u32::from(i.netmask)),
                Err(_) => Ipv4Addr::BROADCAST,
            }
        }
    }

    /// Pull the sender's protocol address and hardware address out of a frame
    /// that carries an ARP reply. Returns `None` for requests and for
    /// non-IPv4/non-ethernet ARP, which we have no use for.
    pub(super) fn parse_arp_reply(frame: &[u8]) -> Option<(Ipv4Addr, MacAddr)> {
        const ETH_HDR: usize = 14;
        if frame.len() < ETH_HDR + ARPHDR_FIXED_LEN + 8 {
            return None;
        }
        if u16::from_be_bytes([frame[12], frame[13]]) != ETHERTYPE_ARP {
            return None;
        }
        let arp = &frame[ETH_HDR..];
        if u16::from_be_bytes([arp[0], arp[1]]) != HTYPE_ETHER {
            return None;
        }
        if u16::from_be_bytes([arp[2], arp[3]]) != 0x0800 {
            return None;
        }
        if u16::from_be_bytes([arp[6], arp[7]]) != 2 {
            return None; // opcode 2 is a reply; 1 is a request
        }
        let hw_len = arp[4] as usize;
        let proto_len = arp[5] as usize;
        if hw_len != 6 || proto_len != 4 {
            return None;
        }
        let sha = &arp[8..14];
        let spa = Ipv4Addr::new(arp[14], arp[15], arp[16], arp[17]);
        Some((
            spa,
            MacAddr::from_bytes([sha[0], sha[1], sha[2], sha[3], sha[4], sha[5]]),
        ))
    }

    fn interface_index(name: &str) -> Result<i32> {
        let c = std::ffi::CString::new(name)?;
        let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
        if idx == 0 {
            bail!(
                "unknown interface {name:?}: {}",
                std::io::Error::last_os_error()
            );
        }
        Ok(idx as i32)
    }

    fn interface_identity(name: &str) -> Result<([u8; 6], Ipv4Addr)> {
        let iface = crate::net::find(name)?;
        // The hardware address needs SIOCGIFHWADDR.
        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        // `ifr_name` is a fixed 16-byte array, not a pointer, so copy the name in
        // with a NUL terminator and leave the tail zeroed.
        let bytes = name.as_bytes();
        if bytes.len() >= libc::IFNAMSIZ {
            bail!("interface name {name:?} is too long");
        }
        for (slot, b) in ifr.ifr_name.iter_mut().zip(bytes) {
            *slot = *b as i8;
        }
        let rc = unsafe {
            libc::ioctl(
                libc::AF_INET,
                libc::SIOCGIFHWADDR,
                &mut ifr as *mut libc::ifreq,
            )
        };
        if rc < 0 {
            bail!(
                "reading the hardware address of {name}: {}",
                std::io::Error::last_os_error()
            );
        }
        let sa = unsafe { ifr.ifr_ifru.ifru_hwaddr.sa_data };
        let mut mac = [0u8; 6];
        for (dst, src) in mac.iter_mut().zip(sa.iter()) {
            *dst = *src as u8;
        }
        Ok((mac, iface.addr))
    }
}

// ------------------------------------------------------------- windows ----

#[cfg(windows)]
mod platform {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use anyhow::Result;
    use windows::Win32::NetworkManagement::IpHelper::SendARP;

    use super::{Availability, Reply};
    use crate::host::Outcome;
    use crate::probe::ProbeConfig;

    pub struct Inner {
        timeout: Duration,
        source: Option<Ipv4Addr>,
        concurrency: usize,
    }

    /// `SendARP` lives in iphlpapi and works for ordinary users, so unlike the
    /// Unix raw-socket path this needs no capability check.
    pub fn availability() -> Availability {
        Availability::ok("SendARP (no privileges needed)")
    }

    impl Inner {
        pub fn new(cfg: &ProbeConfig) -> Result<Self> {
            Ok(Inner {
                timeout: cfg.timeout,
                source: cfg.source,
                concurrency: cfg.concurrency,
            })
        }

        pub fn timeout(&self) -> Duration {
            self.timeout
        }

        /// `SendARP` is synchronous and per-target: it blocks until that one
        /// address answers or the stack gives up on it. Called in a plain loop
        /// those waits add up, so a /24 turns into hundreds of back-to-back
        /// stalls and reads as a hang. The waits are independent, so they are
        /// overlapped across a bounded pool instead: the wall clock becomes
        /// `targets / workers` timeouts rather than `targets` of them.
        pub fn probe_round(&mut self, targets: &[Ipv4Addr]) -> Result<Vec<Reply>> {
            let workers = crate::probe::blocking_workers(targets.len(), self.concurrency);
            if workers == 0 {
                return Ok(Vec::new());
            }
            let chunk = targets.len().div_ceil(workers);
            let source = self.source;

            let answered: Vec<Reply> = std::thread::scope(|scope| {
                let handles: Vec<_> = targets
                    .chunks(chunk)
                    .map(|batch| {
                        scope.spawn(move || {
                            let mut out = Vec::new();
                            for &ip in batch {
                                if let Some(mac) = send_one(source, ip) {
                                    out.push(Reply::new(ip, Outcome::Alive).with_mac(mac));
                                }
                            }
                            out
                        })
                    })
                    .collect();
                handles
                    .into_iter()
                    .flat_map(|h| h.join().unwrap_or_default())
                    .collect()
            });

            Ok(answered)
        }
    }

    /// `SendARP` takes both addresses as `u32` in network byte order and writes
    /// the hardware address into a caller-supplied buffer, returning the number
    /// of bytes written. Zero means the host did not answer.
    ///
    /// The address that comes back *is* the reason to be here: an ARP sweep
    /// that only reported a boolean threw away the one thing this probe can
    /// learn that ICMP and TCP cannot, leaving the MAC column empty on the
    /// platform where it should be full.
    fn send_one(source: Option<Ipv4Addr>, ip: Ipv4Addr) -> Option<crate::host::MacAddr> {
        // Both arguments are IPAddr "in network byte order", so the value has to
        // be the big-endian reading of the octets. `from_ne_bytes` is the
        // little-endian one on x86 and asks about a different address entirely.
        let dest = u32::from_be_bytes(ip.octets());
        let src = u32::from_be_bytes(source.unwrap_or(Ipv4Addr::UNSPECIFIED).octets());

        let mut mac = [0u8; 6];
        let mut len = mac.len() as u32;
        let rc = unsafe { SendARP(dest, src, mac.as_mut_ptr().cast(), &mut len as *mut u32) };
        if rc != 0 || len as usize != mac.len() {
            return None;
        }

        let mac = crate::host::MacAddr::from_bytes(mac);
        // Broadcast and all-zero are addresses, not hosts.
        if mac.is_broadcast() || mac.is_unspecified() {
            return None;
        }
        Some(mac)
    }
}

// Everything else: say so, and let the scanner fall back to the passive table.
#[cfg(not(any(target_os = "linux", windows)))]
mod platform {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use anyhow::{Result, bail};

    use super::{Availability, Reply};
    use crate::probe::ProbeConfig;

    pub struct Inner;

    pub fn availability() -> Availability {
        Availability::no(
            "active ARP is implemented for Linux and Windows only; \
             the passive neighbour table is used instead",
        )
    }

    impl Inner {
        pub fn new(_cfg: &ProbeConfig) -> Result<Self> {
            bail!(
                "active ARP is not implemented on this platform; the passive neighbour table is used instead"
            )
        }

        pub fn timeout(&self) -> Duration {
            Duration::from_millis(0)
        }

        pub fn probe_round(&mut self, _targets: &[Ipv4Addr]) -> Result<Vec<Reply>> {
            Ok(Vec::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Only the Linux frame parser builds `MacAddr` values, so the import has to
    // be gated with it or the other targets report it as unused.
    #[cfg(target_os = "linux")]
    use crate::host::MacAddr;

    /// Availability must never panic and must explain itself either way.
    #[test]
    fn availability_always_explains_itself() {
        let a = ArpProber::availability();
        assert!(
            !a.reason.is_empty(),
            "availability must carry an explanation"
        );
        if !a.available {
            assert!(
                a.reason.to_lowercase().contains("neighbour"),
                "an unavailable ARP path should point at the fallback, got: {}",
                a.reason
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn arp_reply_parsing_extracts_sender() {
        let mut frame = vec![0u8; 14];
        frame[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
        let mut arp = vec![0u8; 28];
        arp[0..2].copy_from_slice(&1u16.to_be_bytes()); // ethernet
        arp[2..4].copy_from_slice(&0x0800u16.to_be_bytes()); // ipv4
        arp[4] = 6;
        arp[5] = 4;
        arp[6..8].copy_from_slice(&2u16.to_be_bytes()); // reply
        arp[8..14].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        arp[14..18].copy_from_slice(&[192, 168, 1, 50]);
        frame.extend_from_slice(&arp);

        let (ip, mac) = super::platform::parse_arp_reply(&frame).expect("should parse a reply");
        assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 50));
        assert_eq!(mac, MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn arp_requests_and_junk_are_ignored() {
        let mut frame = vec![0u8; 14];
        frame[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
        let mut arp = vec![0u8; 28];
        arp[0..2].copy_from_slice(&1u16.to_be_bytes());
        arp[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
        arp[4] = 6;
        arp[5] = 4;
        arp[6..8].copy_from_slice(&1u16.to_be_bytes()); // opcode 1 = request
        arp[8..14].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        arp[14..18].copy_from_slice(&[10, 0, 0, 1]);
        frame.extend_from_slice(&arp);

        assert!(
            super::platform::parse_arp_reply(&frame).is_none(),
            "a request is not evidence anyone is alive"
        );
        assert!(super::platform::parse_arp_reply(&[0u8; 4]).is_none());
        assert!(super::platform::parse_arp_reply(&[]).is_none());
    }
}
