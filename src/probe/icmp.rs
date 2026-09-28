//! ICMP echo probing.
//!
//! # Why the sequence number is the only thing we match on
//!
//! On Linux, an unprivileged ICMP socket (`SOCK_DGRAM` + `IPPROTO_ICMP`,
//! gated on `net.ipv4.ping_group_range`) is the whole reason this tool needs no
//! privileges. But the kernel **rewrites the ICMP identifier** on those
//! sockets, and the socket cannot see it, so identifier matching is dead on
//! arrival. The sequence number, by contrast, passes through untouched.
//!
//! So rather than matching on a field the kernel may or may not preserve, every
//! probe carries a 4-byte magic in its payload followed by a copy of its own
//! sequence number. Any reply — echo or ICMP error — echoes that payload back
//! intact, so a single substring search recovers the sequence regardless of
//! which socket type we ended up with, what the kernel did to the identifier,
//! or whether an IP header is prepended. A packet we cannot match that way is
//! dropped, which also filters out unrelated traffic and trivial spoofing.

use std::net::Ipv4Addr;

use anyhow::Result;

use super::{Outcome, ProbeConfig, Reply};

/// Laid out by the platform backends.
pub use imp::SocketKind;

/// Builds a prober, or explains why the platform cannot.
pub struct IcmpProber {
    inner: imp::Inner,
}

impl IcmpProber {
    pub fn new(cfg: &ProbeConfig) -> Result<Self> {
        Ok(IcmpProber {
            inner: imp::Inner::new(cfg)?,
        })
    }

    /// Send one echo request to each target and collect what comes back before
    /// the deadline. Performs no retries; the scheduler owns retry policy so it
    /// can drop answered targets from subsequent rounds.
    pub fn probe_round(&mut self, targets: &[Ipv4Addr]) -> Result<Vec<Reply>> {
        self.inner.probe_round(targets, self.inner.timeout())
    }

    /// Which kind of socket we ended up with, for `--verbose` and diagnostics.
    pub fn socket_kind(&self) -> SocketKind {
        self.inner.socket_kind()
    }
}

/// Shared ICMP constants and helpers, used by both backends.
///
/// The wire helpers are only exercised by the raw-socket backend. The Windows
/// backend asks the ICMP API to fill in a reply struct, so it never needs to
/// find a sequence number in raw bytes.
#[allow(dead_code)]
mod wire {
    pub const MAGIC: &[u8; 4] = b"IPS\x01";
    pub const ECHO_REPLY: u8 = 0;
    pub const DEST_UNREACH: u8 = 3;

    /// The two unreachable codes that can only originate from the target host.
    pub const ICMP_UNREACH_PORT: u8 = 3;
    pub const ICMP_UNREACH_PROTOCOL: u8 = 2;

    /// The unreachable code from an ICMP error, or `None` if this is not one.
    ///
    /// The code is what separates "nothing is at that address" from "something
    /// is there and would not talk to us", and the two are otherwise
    /// indistinguishable to a scanner that only looks at the message type.
    pub fn unreachable_code(icmp: &[u8]) -> Option<u8> {
        if icmp.first().copied()? != DEST_UNREACH {
            return None;
        }
        Some(icmp[1])
    }

    /// One's-complement checksum over an ICMP message.
    pub fn checksum(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut chunks = data.chunks_exact(2);
        for c in &mut chunks {
            sum += u16::from_be_bytes([c[0], c[1]]) as u32;
        }
        if let Some(&b) = chunks.remainder().first() {
            sum += u32::from(b) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// Build an echo request: header, then magic, then a copy of the sequence.
    ///
    /// The magic must sit immediately after the 8-byte header so a reply's
    /// sequence is always 2 bytes before the magic and can be found by search.
    pub fn echo_request(seq: u16, identifier: u16) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(8 + MAGIC.len() + 2 + 8);
        pkt.extend_from_slice(&[8, 0, 0, 0]); // type=echo-request, code, cksum
        pkt.extend_from_slice(&identifier.to_be_bytes());
        pkt.extend_from_slice(&seq.to_be_bytes());
        pkt.extend_from_slice(MAGIC);
        pkt.extend_from_slice(&seq.to_be_bytes());
        pkt.extend_from_slice(&[0u8; 8]); // pad so replies are a full MTU
        let cksum = checksum(&pkt);
        pkt[2..4].copy_from_slice(&cksum.to_be_bytes());
        pkt
    }

    /// Recover a sequence number from any packet that echoes our payload.
    pub fn find_seq(buf: &[u8]) -> Option<u16> {
        let at = buf.windows(MAGIC.len()).position(|w| w == MAGIC)?;
        let seq_at = at.checked_sub(2)?;
        let bytes = buf.get(seq_at..seq_at + 2)?;
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    }
}

// ---------------------------------------------------------------- unix ----

#[cfg(unix)]
mod imp {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::collections::HashMap;
    use std::io;
    use std::net::Ipv4Addr;
    use std::os::fd::{AsRawFd, OwnedFd, RawFd};
    use std::time::{Duration, Instant};

    use anyhow::{Result, bail};

    use super::wire;
    use crate::host::Outcome;
    use crate::probe::{ProbeConfig, Reply};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum SocketKind {
        /// Unprivileged ping socket. Kernel fixes the checksum and identifier.
        Unprivileged,
        /// Raw ICMP socket. Needs CAP_NET_RAW or Administrator.
        Raw,
    }

    impl SocketKind {
        pub fn as_str(self) -> &'static str {
            match self {
                SocketKind::Unprivileged => "unprivileged datagram (no privileges needed)",
                SocketKind::Raw => "raw ICMP (needs root/Administrator)",
            }
        }
    }

    struct Pending {
        ip: Ipv4Addr,
        sent: Instant,
    }

    pub struct Inner {
        fd: OwnedFd,
        kind: SocketKind,
        /// True when received packets have no IP header in front of the ICMP one.
        stripped: bool,
        /// Our identifier. The kernel overwrites it on datagram sockets, so it
        /// is only trustworthy on the raw path; we never match on it regardless.
        identifier: u16,
        inflight: HashMap<u16, Pending>,
        next_seq: u16,
        timeout: Duration,
    }

    impl Inner {
        pub fn new(cfg: &ProbeConfig) -> Result<Self> {
            // Prefer the unprivileged path. It needs no capabilities and is
            // available to ordinary users wherever ping_group_range allows it.
            let (fd, kind) = match open(libc::SOCK_DGRAM) {
                Ok(fd) => (fd, SocketKind::Unprivileged),
                Err(dgram_err) => match open(libc::SOCK_RAW) {
                    Ok(fd) => (fd, SocketKind::Raw),
                    Err(raw_err) => {
                        bail!(
                            "cannot open an ICMP socket.\n  \
                             unprivileged datagram socket: {dgram_err}\n  \
                             raw socket: {raw_err}\n\
                             On Linux the unprivileged path needs \
                             `sysctl net.ipv4.ping_group_range` to include your user, \
                             otherwise run with elevated privileges for the raw socket."
                        );
                    }
                },
            };

            // SO_BROADCAST lets us probe the subnet's directed broadcast, which
            // is a legitimate way to detect a host that ignores unicast.
            setsockopt_i32(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_BROADCAST, 1);

            let stripped = configure_socket(fd.as_raw_fd(), kind);

            // Pinning the source address is what forces traffic out of the
            // interface the user asked for instead of whatever the route table
            // happens to prefer.
            if let Some(src) = cfg.source {
                let sa = sockaddr_v4(src, 0);
                // Not fatal: some kernels refuse to bind a ping socket, and the
                // probe still works, just via the default route.
                unsafe {
                    libc::bind(
                        fd.as_raw_fd(),
                        &sa as *const libc::sockaddr_in as *const libc::sockaddr,
                        size_of_sockaddr_in(),
                    );
                }
            }

            // A per-process identifier keeps our traffic distinguishable in a
            // capture. Seeding from the pid also avoids colliding with a
            // concurrently running `ping`.
            let identifier = (std::process::id() as u16) | 0x4000;

            Ok(Inner {
                fd,
                kind,
                stripped,
                identifier,
                inflight: HashMap::new(),
                next_seq: (std::process::id() as u16) ^ 0x5a5a,
                timeout: cfg.timeout,
            })
        }

        pub fn timeout(&self) -> Duration {
            self.timeout
        }

        pub fn socket_kind(&self) -> SocketKind {
            self.kind
        }

        pub fn probe_round(
            &mut self,
            targets: &[Ipv4Addr],
            timeout: Duration,
        ) -> Result<Vec<Reply>> {
            self.inflight.clear();

            for ip in targets {
                let seq = self.alloc_seq();
                let pkt = wire::echo_request(seq, self.identifier);
                if self.send(*ip, &pkt).is_ok() {
                    self.inflight.insert(
                        seq,
                        Pending {
                            ip: *ip,
                            sent: Instant::now(),
                        },
                    );
                }
            }

            if self.inflight.is_empty() {
                return Ok(Vec::new());
            }

            let deadline = Instant::now() + timeout;
            let mut replies = Vec::with_capacity(self.inflight.len());

            while !self.inflight.is_empty() {
                let now = Instant::now();
                if now >= deadline {
                    break;
                }
                match self.wait_readable(deadline - now) {
                    Ok(false) => break, // deadline reached
                    Ok(true) => {}
                    Err(e) if is_retryable(&e) => continue,
                    Err(e) => return Err(e.into()),
                }
                while !self.inflight.is_empty() {
                    match self.recv_one() {
                        Ok(Some(reply)) => replies.push(reply),
                        Ok(None) => break, // drained
                        Err(e) if is_retryable(&e) => break,
                        Err(e) => return Err(e.into()),
                    }
                }
            }

            // Anything still in flight is a timeout. The scheduler decides
            // whether to retry or escalate to another method.
            self.inflight.clear();
            Ok(replies)
        }

        fn alloc_seq(&mut self) -> u16 {
            self.next_seq = self.next_seq.wrapping_add(1);
            self.next_seq
        }

        fn send(&self, ip: Ipv4Addr, pkt: &[u8]) -> io::Result<usize> {
            // Datagram ping sockets require port 0 in the destination.
            let dst = sockaddr_v4(ip, 0);
            let n = unsafe {
                libc::sendto(
                    self.fd.as_raw_fd(),
                    pkt.as_ptr() as *const libc::c_void,
                    pkt.len(),
                    0,
                    &dst as *const libc::sockaddr_in as *const libc::sockaddr,
                    size_of_sockaddr_in(),
                )
            };
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }

        /// Block until the socket is readable or the slice of time elapses.
        fn wait_readable(&self, timeout: Duration) -> io::Result<bool> {
            let mut pfd = libc::pollfd {
                fd: self.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let ms = timeout.as_millis().min(i32::MAX as u128) as libc::c_int;
            loop {
                let rc = unsafe { libc::poll(&mut pfd, 1, ms) };
                if rc < 0 {
                    let e = io::Error::last_os_error();
                    if e.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(e);
                }
                if rc == 0 {
                    return Ok(false);
                }
                if pfd.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
                    return Err(io::Error::other("ICMP socket error"));
                }
                return Ok(true);
            }
        }

        fn recv_one(&mut self) -> io::Result<Option<Reply>> {
            let mut buf = [0u8; 1500];
            let mut cmsg_buf = [0u8; 256];
            let mut iov = libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                iov_len: buf.len(),
            };
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = cmsg_buf.len() as _;

            let n = unsafe { libc::recvmsg(self.fd.as_raw_fd(), &mut msg, 0) };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            let n = n as usize;
            if n < 8 {
                return Ok(None);
            }

            // Where the ICMP header starts: at zero when the kernel strips the
            // IP header, otherwise after the variable-length IP options.
            let icmp_at = if self.stripped {
                0
            } else {
                let ihl = usize::from(buf[0] & 0x0f) * 4;
                if ihl < 20 || n < ihl + 8 {
                    return Ok(None);
                }
                ihl
            };
            let icmp_type = buf[icmp_at];

            // Only echo replies and unreachable errors are meaningful here.
            if icmp_type != wire::ECHO_REPLY && icmp_type != wire::DEST_UNREACH {
                return Ok(None);
            }

            // Recover the sequence from our echoed payload. Anything that does
            // not carry it was not ours and is dropped.
            let Some(seq) = wire::find_seq(&buf[..n]) else {
                return Ok(None);
            };
            let Some(pending) = self.inflight.remove(&seq) else {
                return Ok(None);
            };

            let ttl = extract_ttl(&msg);

            let reply = match icmp_type {
                wire::ECHO_REPLY => Reply {
                    ip: pending.ip,
                    outcome: Outcome::Alive,
                    rtt: Some(pending.sent.elapsed()),
                    ttl,
                    port: None,
                    mac: None,
                },
                // An unreachable error is one of four things, and only two of
                // them mean a host is there. The code is the second byte of the
                // ICMP header and has to actually be read: protocol and port
                // unreachable can only be sent by the host itself, which had to
                // exist to reject the datagram, so those prove life. Network and
                // host unreachable are the network reporting that nothing is at
                // the address, and treating them as proof of life is how a scan
                // ends up reporting a subnet full of machines that `ping` calls
                // unreachable.
                _ => match wire::unreachable_code(&buf[icmp_at..n]) {
                    Some(c) if c == wire::ICMP_UNREACH_PROTOCOL || c == wire::ICMP_UNREACH_PORT => {
                        Reply {
                            ip: pending.ip,
                            outcome: Outcome::Filtered,
                            rtt: None,
                            ttl,
                            port: None,
                            mac: None,
                        }
                    }
                    _ => return Ok(None),
                },
            };
            Ok(Some(reply))
        }
    }

    fn open(sock_type: libc::c_int) -> io::Result<OwnedFd> {
        // `socket2` is used rather than `libc::socket` because `SOCK_NONBLOCK`
        // and `SOCK_CLOEXEC` are Linux extensions that BSD and macOS do not
        // have; it sets both with the right per-platform mechanism.
        let ty = if sock_type == libc::SOCK_DGRAM {
            Type::DGRAM
        } else {
            Type::RAW
        };
        let sock = Socket::new(Domain::IPV4, ty, Some(Protocol::ICMPV4))?;
        sock.set_nonblocking(true)?;
        Ok(sock.into())
    }

    /// A `sockaddr_in` for `ip:port`.
    ///
    /// Zeroed rather than built with a struct literal, because BSD and macOS
    /// carry an extra `sin_len` field that Linux does not have, and a literal
    /// would have to name it per platform.
    fn sockaddr_v4(ip: Ipv4Addr, port: u16) -> libc::sockaddr_in {
        let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        sa.sin_family = libc::AF_INET as libc::sa_family_t;
        sa.sin_port = port.to_be();
        sa.sin_addr = libc::in_addr {
            s_addr: u32::from_ne_bytes(ip.octets()),
        };
        #[cfg(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "dragonfly"
        ))]
        {
            sa.sin_len = size_of_sockaddr_in() as u8;
        }
        sa
    }

    /// `IP_STRIPHDR`, which `libc` does not expose for Darwin targets.
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    const IP_STRIPHDR: libc::c_int = 0x0010;

    /// Platform socket options. Returns whether headers arrive stripped.
    #[cfg(target_os = "linux")]
    fn configure_socket(fd: RawFd, kind: SocketKind) -> bool {
        // Ask for TTL as ancillary data: datagram sockets get no IP header, so
        // this is the only way to recover it.
        setsockopt_i32(fd, libc::IPPROTO_IP, libc::IP_RECVTTL, 1);
        // Ask for ICMP error messages too, so a host that answers
        // destination-unreachable is reported as filtered rather than silent.
        setsockopt_i32(fd, libc::IPPROTO_IP, libc::IP_RECVERR, 1);
        // Datagram ping sockets always arrive with the IP header removed.
        kind == SocketKind::Unprivileged
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    fn configure_socket(fd: RawFd, _kind: SocketKind) -> bool {
        // Darwin keeps the IP header unless asked not to.
        setsockopt_i32(fd, libc::IPPROTO_IP, IP_STRIPHDR, 1);
        true
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "ios")))]
    fn configure_socket(_fd: RawFd, kind: SocketKind) -> bool {
        kind == SocketKind::Unprivileged
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "ios"))]
    fn extract_ttl(msg: &libc::msghdr) -> Option<u8> {
        let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(msg) };
        while !cmsg.is_null() {
            let level = unsafe { (*cmsg).cmsg_level };
            let ctype = unsafe { (*cmsg).cmsg_type };
            if level == libc::IPPROTO_IP && ctype == libc::IP_TTL {
                return Some(unsafe { *(libc::CMSG_DATA(cmsg) as *const u8) });
            }
            cmsg = unsafe { libc::CMSG_NXTHDR(msg, cmsg) };
        }
        None
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "ios")))]
    fn extract_ttl(_msg: &libc::msghdr) -> Option<u8> {
        None
    }

    fn setsockopt_i32(fd: RawFd, level: libc::c_int, name: libc::c_int, value: libc::c_int) {
        unsafe {
            libc::setsockopt(
                fd,
                level,
                name,
                &value as *const libc::c_int as *const libc::c_void,
                size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }

    fn is_retryable(e: &io::Error) -> bool {
        matches!(
            e.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
        )
    }

    fn size_of_sockaddr_in() -> libc::socklen_t {
        std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
    }

    use std::mem::size_of;
}

// ------------------------------------------------------------- windows ----

/// What an `IcmpSendEcho2` status code means about the target.
///
/// The codes are fixed values from the Windows SDK, restated here so the rule
/// can be tested on any host. Which of them count as proof that the target is
/// there, and the requirement that the reply came from the target at all, are
/// both easy to get subtly wrong and impossible to notice from one scan: a
/// router answering echo for a range it only routes looks exactly like a room
/// full of hosts.
#[cfg_attr(not(windows), allow(dead_code))]
fn windows_verdict(status: u32, answered_us: bool) -> Option<Outcome> {
    const IP_SUCCESS: u32 = 0;
    const IP_TTL_EXPIRED: u32 = 1;

    // Only a genuine echo reply, and only from the address we asked.
    match status {
        // IP_SUCCESS with our own address as the source is the one result that
        // means a host answered our question.
        IP_SUCCESS if answered_us => Some(Outcome::Alive),
        // IP_SUCCESS from somewhere else is a reply to somebody else's probe.
        IP_SUCCESS => None,
        // IP_TTL_EXPIRED proves something is alive on the path, not the target.
        IP_TTL_EXPIRED => None,
        // Every unreachable status is discarded, and the reason is empirical
        // rather than theoretical.
        //
        // The textbook reading is that port and protocol unreachable can only
        // come from the target, so they prove it exists, while host and network
        // unreachable prove the opposite. That reading is wrong in practice. On
        // a Windows host attached to a Hyper-V virtual switch, IcmpSendEcho2
        // returns IP_DEST_PROT_UNREACHABLE (11010) for *every* address --
        // hosts that answer `ping` and addresses where nothing is listening at
        // all -- and times out for others, including the default gateway. The
        // status carries no information about the target on such a host.
        //
        // So a differential test against `ping` over a live /24, with both run
        // from the same machine at the same moment, found 134 addresses reported
        // alive that `ping` answered "destination host unreachable" for, and 78
        // that ping reached and the scan missed. Treating an unreachable error
        // as evidence of life is what produced both: it invented the first
        // group and, because the fabricated replies settled those targets, it
        // stopped the cascade from ever escalating to the TCP probe that would
        // have found the second.
        //
        // `ping` itself does not count these as replies, and neither does this.
        // A host that filters echo is still found: the cascade escalates to a
        // TCP connect, and a refused connection is proof of life that can be
        // verified. What is given up is claiming a host on the strength of an
        // error message that demonstrably does not mean what it claims.
        _ => None,
    }
}

#[cfg(test)]
mod windows_verdict_tests {
    use super::*;

    #[test]
    fn success_from_the_target_is_alive() {
        assert_eq!(windows_verdict(0, true), Some(Outcome::Alive));
    }

    #[test]
    fn success_from_another_address_is_not_the_target() {
        // The whole point: a device echoing on behalf of an address it merely
        // routes must not be credited with that host.
        assert_eq!(windows_verdict(0, false), None);
    }

    #[test]
    fn no_unreachable_status_is_evidence_of_a_host() {
        // Checked against `ping` on a real Windows host rather than against the
        // documentation. IcmpSendEcho2 there returns 11010 for addresses that
        // answer `ping` and for addresses that are simply empty, and times out
        // for others including the default gateway, so the status does not
        // describe the target.
        //
        // Trusting it is what made a /24 look like 191 live hosts when `ping`
        // could reach 111 of them: 134 invented addresses that ping called
        // unreachable, and 78 real ones the tool never found because the
        // fabricated replies had settled those targets and stopped the cascade
        // escalating to a TCP connect.
        for status in [11001u32, 11002, 11004, 11010, 11013] {
            assert_eq!(
                windows_verdict(status, true),
                None,
                "status {status} must not be counted as a host"
            );
            assert_eq!(
                windows_verdict(status, false),
                None,
                "status {status} must not be counted as a host"
            );
        }
    }

    #[test]
    fn an_expired_echo_proves_the_path_not_the_target() {
        assert_eq!(windows_verdict(1, true), None);
    }

    #[test]
    fn unknown_codes_are_not_evidence() {
        assert_eq!(windows_verdict(12345, true), None);
    }
}

#[cfg(windows)]
mod imp {
    use std::net::Ipv4Addr;
    use std::time::{Duration, Instant};

    use anyhow::{Context, Result};

    use super::windows_verdict;
    use super::wire;
    use crate::host::Outcome;
    use crate::probe::{ProbeConfig, Reply};
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::NetworkManagement::IpHelper::{
        ICMP_ECHO_REPLY, IP_OPTION_INFORMATION, IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho2,
    };

    /// The `IP_*` codes that mean the network answered with an error rather
    /// than the target staying silent.
    const IP_DEST_HOST_UNREACHABLE: u32 = 11004;
    const IP_DEST_NET_UNREACHABLE: u32 = 11001;
    const IP_DEST_PROT_UNREACHABLE: u32 = 11010;

    /// Windows has one viable ICMP path and no privilege ladder to climb.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum SocketKind {
        /// `IcmpSendEcho2`. Works for ordinary users; fails only for Guest.
        Native,
    }

    impl SocketKind {
        pub fn as_str(self) -> &'static str {
            "IcmpSendEcho2 (no privileges needed)"
        }
    }

    /// An `IcmpCreateFile` handle shared across worker threads.
    ///
    /// `HANDLE` is a raw pointer and therefore `!Send`, but the ICMP API is
    /// documented as safe to call concurrently on one handle, and `Inner` only
    /// ever closes it after every worker has been joined.
    #[derive(Clone, Copy)]
    struct SharedHandle(HANDLE);
    // SAFETY: see the type-level comment above. The handle is never closed
    // while a worker can still hold a copy.
    unsafe impl Send for SharedHandle {}
    unsafe impl Sync for SharedHandle {}

    pub struct Inner {
        handle: SharedHandle,
        timeout_ms: u32,
        concurrency: usize,
    }

    // The handle is owned by `Inner` and closed in `Drop`; these calls are
    // unconditionally safe because they only ever touch that one field.
    impl Inner {
        pub fn new(cfg: &ProbeConfig) -> Result<Self> {
            let handle = unsafe { IcmpCreateFile() }
                .context("opening an ICMP handle (blocked for the Guest account)")?;
            Ok(Inner {
                handle: SharedHandle(handle),
                timeout_ms: cfg.timeout.as_millis().min(u32::MAX as u128) as u32,
                concurrency: cfg.concurrency.max(1),
            })
        }

        pub fn timeout(&self) -> std::time::Duration {
            std::time::Duration::from_millis(u64::from(self.timeout_ms))
        }

        pub fn socket_kind(&self) -> SocketKind {
            SocketKind::Native
        }

        /// `IcmpSendEcho2` is synchronous and cannot demultiplex, so targets are
        /// spread over a small thread pool. Unlike a raw socket there is no
        /// single-socket trick available here.
        ///
        /// The pool is bounded on purpose. Chunking by
        /// `len.div_ceil(concurrency)` looks like it bounds the workers, but it
        /// inverts: a /24 against the default concurrency of 256 gives a chunk
        /// size of one and therefore a thread per address.
        pub fn probe_round(
            &mut self,
            targets: &[Ipv4Addr],
            _timeout: std::time::Duration,
        ) -> Result<Vec<Reply>> {
            if targets.is_empty() {
                return Ok(Vec::new());
            }

            let workers = crate::probe::blocking_workers(targets.len(), self.concurrency);
            let chunk = targets.len().div_ceil(workers);
            let handle = self.handle;
            let timeout_ms = self.timeout_ms;

            let replies: Vec<Reply> = std::thread::scope(|scope| {
                let handles: Vec<_> = targets
                    .chunks(chunk)
                    .map(|batch| {
                        scope.spawn(move || {
                            let out = Vec::new();
                            let opts = IP_OPTION_INFORMATION {
                                Ttl: 128,
                                Tos: 0,
                                Flags: 0,
                                OptionsSize: 0,
                                OptionsData: std::ptr::null_mut(),
                            };
                            // Windows fills in the ICMP_ECHO_REPLY struct
                            // itself, so this only has to be big enough for that
                            // plus the payload we sent.
                            let mut reply_buf = [0u8; 1024];
                            let mut out = out;
                            for &ip in batch {
                                if let Some(r) =
                                    send_one(&handle, ip, timeout_ms, &opts, &mut reply_buf)
                                {
                                    out.push(r);
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

            Ok(replies)
        }
    }

    impl Drop for Inner {
        fn drop(&mut self) {
            // Nothing useful can be done with a failure here, and `Drop` has no
            // way to report one.
            let _ = unsafe { IcmpCloseHandle(self.handle.0) };
        }
    }

    /// One synchronous echo exchange. Returns `None` when the target said
    /// nothing at all, so a single dead target cannot abort the round.
    fn send_one(
        handle: &SharedHandle,
        ip: Ipv4Addr,
        timeout_ms: u32,
        opts: &IP_OPTION_INFORMATION,
        reply_buf: &mut [u8],
    ) -> Option<Reply> {
        let request = wire::echo_request(0x1234, 0x4000);
        let sent = Instant::now();

        // `destinationaddress` is the target in network byte order, not a
        // `SOCKADDR_IN`. `IcmpSendEcho2` returns 0 on success and otherwise the
        // specific reason, which the `IP_*` status codes below describe.
        let status = unsafe {
            IcmpSendEcho2(
                handle.0,
                None,
                None,
                None,
                u32::from_ne_bytes(ip.octets()),
                request.as_ptr() as *const std::ffi::c_void,
                request.len() as u16,
                Some(opts as *const IP_OPTION_INFORMATION),
                reply_buf.as_mut_ptr() as *mut std::ffi::c_void,
                reply_buf.len() as u32,
                timeout_ms,
            )
        };
        if status != 0 {
            return None;
        }

        // With a non-null options pointer the buffer starts with an
        // `ICMP_ECHO_REPLY`, not a bare ICMP header, so the verdict is in the
        // struct rather than in the bytes. Windows already measures the round
        // trip for us, so the wall clock is only used as a fallback.
        if reply_buf.len() < size_of::<ICMP_ECHO_REPLY>() {
            return None;
        }
        let echo: ICMP_ECHO_REPLY =
            unsafe { std::ptr::read_unaligned(reply_buf.as_ptr() as *const ICMP_ECHO_REPLY) };

        let rtt = if echo.RoundTripTime > 0 {
            Some(Duration::from_millis(u64::from(echo.RoundTripTime)))
        } else {
            Some(sent.elapsed())
        };
        // A TTL of zero was never set by a sender, so it means Windows left the
        // field alone rather than that a packet arrived with a dead lifetime.
        // Reporting it as a real TTL would be worse than admitting we have none.
        let ttl = match echo.Options.Ttl {
            0 => None,
            n => u8::try_from(n).ok(),
        };
        // `Address` is who actually sent the reply, which is not necessarily who
        // we asked. Something that answers echo on behalf of a range it merely
        // routes would otherwise be credited with those hosts, on exactly the
        // reasoning that made a proxy-arp segment look crowded.
        let from = std::net::Ipv4Addr::from(echo.Address);
        let answered_us = from == ip;

        match windows_verdict(echo.Status, answered_us) {
            Some(Outcome::Alive) => Some(Reply {
                ip,
                outcome: Outcome::Alive,
                rtt,
                ttl,
                port: None,
                mac: None,
            }),
            Some(outcome) => Some(Reply {
                ip,
                outcome,
                rtt,
                ttl,
                port: None,
                mac: None,
            }),
            // Either the target did not answer, or somebody who is not the target
            // did. Neither is evidence about the target.
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::wire;

    #[test]
    fn checksum_is_valid_for_a_known_vector() {
        // RFC 1071 style: summing a correct packet including its checksum
        // yields zero.
        let pkt = wire::echo_request(0x1234, 0x4000);
        let without_cksum = {
            let mut p = pkt.clone();
            p[2] = 0;
            p[3] = 0;
            p
        };
        let cksum = wire::checksum(&without_cksum);
        let mut full = without_cksum.clone();
        full[2..4].copy_from_slice(&cksum.to_be_bytes());
        assert_eq!(wire::checksum(&full), 0, "a valid packet checksums to zero");
    }

    #[test]
    fn echo_request_layout_places_magic_after_the_header() {
        let pkt = wire::echo_request(0xbeef, 0x4000);
        assert_eq!(pkt[0], 8, "type is echo-request");
        // Summing a packet that already carries a correct checksum yields 0.
        assert_eq!(wire::checksum(&pkt), 0, "checksum must verify: {pkt:02x?}");
        assert_eq!(
            &pkt[8..12],
            wire::MAGIC,
            "magic sits right after the header"
        );
        assert_eq!(&pkt[12..14], &0xbeefu16.to_be_bytes());
    }

    #[test]
    fn sequence_is_recovered_from_a_bare_reply() {
        let req = wire::echo_request(0x0abc, 0x4000);
        // A reply is the same bytes with type flipped to echo-reply.
        let mut reply = req.clone();
        reply[0] = wire::ECHO_REPLY;
        assert_eq!(wire::find_seq(&reply), Some(0x0abc));
    }

    #[test]
    fn sequence_is_recovered_from_an_icmp_error_wrapping_our_request() {
        // A destination-unreachable arrives as an ICMP error whose body is the
        // original IPv4 packet, which itself contains our echo request.
        let req = wire::echo_request(0x1234, 0x4000);
        let mut original_ip = vec![0x45, 0, 0, 20];
        original_ip.extend_from_slice(&[0; 8]);
        original_ip.extend_from_slice(&req);

        let mut err = vec![wire::DEST_UNREACH, 3, 0, 0];
        err.extend_from_slice(&[0; 4]); // unused
        err.extend_from_slice(&original_ip);

        assert_eq!(wire::find_seq(&err), Some(0x1234));
    }

    #[test]
    fn unrelated_packets_are_not_matched() {
        assert_eq!(wire::find_seq(&[0, 0, 0, 0, 0, 0, 0, 0]), None);
        let mut near_miss = vec![0u8; 32];
        near_miss[8] = b'I';
        assert_eq!(
            wire::find_seq(&near_miss),
            None,
            "a partial magic is not a match"
        );
    }

    #[test]
    fn a_truncated_reply_yields_no_sequence() {
        let req = wire::echo_request(0x0001, 0x4000);
        assert_eq!(wire::find_seq(&req[..4]), None);
    }
}
