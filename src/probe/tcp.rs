//! TCP connect probing.
//!
//! This is the method that always works: it needs no privileges, no raw
//! sockets, and no cooperation from the target's IP stack. It is also the only
//! method that reports a port, so it earns its place in the cascade for two
//! reasons.
//!
//! # The three states that matter
//!
//! A connect scan must not collapse its results into a boolean:
//!
//! * **connection accepted** — definitely alive, and we know a service is on it.
//! * **connection reset** (`ECONNREFUSED`) — *also* definitely alive. The host
//!   sent a packet back. It is up and it is refusing us, which is exactly the
//!   situation a firewall that blocks ICMP creates. Reporting this as "dead"
//!   would be the single worst bug in a tool like this.
//! * **timeout** — carries no information at all, and is indistinguishable from
//!   a powered-off machine. Those targets get escalated to another method or
//!   left as "not found"; they are never reported as absent hosts.

use std::collections::HashSet;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};

use anyhow::Result;
use polling::{Event, Events, Poller};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::host::Outcome;
use crate::probe::{ProbeConfig, Reply};

/// Ports tried by default, chosen for being common on consumer and office
/// hardware rather than for any particular platform.
pub const DEFAULT_PORTS: &[u16] = &[80, 443, 22, 445, 3389, 8080];

pub struct TcpProber {
    ports: Vec<u16>,
    timeout: Duration,
    concurrency: usize,
    /// Source address to originate connections from, so traffic leaves via the
    /// interface the user selected.
    source: Option<Ipv4Addr>,
    /// Connections that could not even be attempted, kept for `--verbose`.
    failures: Vec<String>,
}

impl TcpProber {
    pub fn new(cfg: &ProbeConfig) -> Self {
        TcpProber {
            ports: cfg.ports.clone(),
            timeout: cfg.timeout,
            concurrency: cfg.concurrency.max(1),
            source: cfg.source,
            failures: Vec::new(),
        }
    }

    /// Why individual connections could not be attempted at all, as opposed to
    /// targets that simply did not answer. Useful when a scan returns nothing
    /// and the cause is a local routing problem rather than an empty subnet.
    pub fn failures(&self) -> &[String] {
        &self.failures
    }

    pub fn ports(&self) -> &[u16] {
        &self.ports
    }

    /// Probe every target on every configured port concurrently, reporting the
    /// first conclusive answer per target.
    ///
    /// Ports are tried in the order given, so the reported open port is the
    /// lowest-numbered one that answered. Once a target is settled its other
    /// sockets are closed immediately rather than run to completion.
    pub fn probe_round(&mut self, targets: &[Ipv4Addr]) -> Result<Vec<Reply>> {
        if targets.is_empty() || self.ports.is_empty() {
            return Ok(Vec::new());
        }

        let poller = Poller::new()?;
        let deadline = Instant::now() + self.timeout;

        // Work list, port-interleaved so one slow target cannot starve the batch.
        let mut queue: Vec<(Ipv4Addr, u16)> = Vec::with_capacity(targets.len() * self.ports.len());
        for &ip in targets {
            for &port in &self.ports {
                queue.push((ip, port));
            }
        }

        // Slots hold the sockets; `inflight` holds their keys. The poller hands
        // the key back on readiness, which is safer than keying by file
        // descriptor because descriptors get reused.
        let mut slots: Vec<Option<Pending>> = Vec::with_capacity(self.concurrency);
        let mut inflight: HashSet<usize> = HashSet::new();
        let mut replies: Vec<Reply> = Vec::new();
        let mut next_job = 0usize;
        let mut events = Events::new();

        loop {
            // Fill up to the concurrency ceiling.
            //
            // Every port of every target is attempted, and a target is never
            // retired after answering. Stopping at the first conclusive answer
            // made the port column a sample rather than an inventory: a machine
            // with 80, 443 and 22 open was reported as whichever of those came
            // back first, and the other two silently disappeared. Asking which
            // ports are open means asking about each of them, and the cost is
            // bounded by `--concurrency` either way.
            while inflight.len() < self.concurrency && next_job < queue.len() {
                let (ip, port) = queue[next_job];
                next_job += 1;
                match start_connect(ip, port, self.source) {
                    Start::Connected => {
                        replies.push(Reply::new(ip, Outcome::Alive).with_port(port));
                    }
                    Start::Refused => {
                        replies.push(Reply::new(ip, Outcome::Filtered).with_port(port));
                    }
                    Start::InFlight(sock) => {
                        let key = slots.len();
                        if unsafe { poller.add(&sock, Event::writable(key)) }.is_ok() {
                            slots.push(Some(Pending {
                                ip,
                                port,
                                sock,
                                started: Instant::now(),
                            }));
                            inflight.insert(key);
                        }
                    }
                    // No route, or the network is unreachable. No information
                    // about the target, and not worth retrying this round.
                    Start::Failed(e) => {
                        if self.failures.len() < 8 {
                            self.failures.push(format!("{ip}:{port} {e}"));
                        }
                    }
                }
            }

            if inflight.is_empty() {
                break;
            }

            if poller.wait_deadline(&mut events, deadline).is_err() {
                break;
            }
            // The round deadline expired with nothing left to collect. Without
            // this the loop would ask for more events, be told "none, already
            // past the deadline", and spin at full speed until the sockets
            // timed out on their own.
            if events.is_empty() {
                break;
            }

            for event in events.iter() {
                let key = event.key;
                if !inflight.remove(&key) {
                    continue;
                }
                let Some(job) = slots[key].take() else {
                    continue;
                };
                // Unregister before the socket closes, so the poller drops its
                // reference to the descriptor.
                let _ = poller.delete(&job.sock);

                // `take_error` reports the pending SO_ERROR and clears it, so it
                // must be called exactly once per socket. Linux hands back a
                // completed refusal as `Ok(Some(..))` rather than `Err(..)`, so
                // the inner error has to be inspected too.
                let pending = job.sock.take_error();
                if pending.as_ref().is_ok_and(|e| e.is_none()) {
                    // No pending error: the three-way handshake completed.
                    let rtt = job.started.elapsed();
                    replies.push(
                        Reply::new(job.ip, Outcome::Alive)
                            .with_port(job.port)
                            .with_rtt(rtt),
                    );
                } else if refused(&pending) {
                    // The host answered with a RST. It is up; it just will not
                    // talk to us on this port.
                    replies.push(Reply::new(job.ip, Outcome::Filtered).with_port(job.port));
                }
                // Anything else (timeout, host unreachable, route missing) says
                // nothing about whether the host exists.
            }
            events.clear();
        }

        for key in &inflight {
            if let Some(job) = &slots[*key] {
                let _ = poller.delete(&job.sock);
            }
        }

        // Keep all open ports per target. Multiple rows for the same IP will be
        // collapsed into a single host with all its open ports in the output.
        replies.sort_by(|a, b| {
            u32::from(a.ip)
                .cmp(&u32::from(b.ip))
                .then(a.port.cmp(&b.port))
        });
        Ok(replies)
    }
}

#[derive(Debug)]
struct Pending {
    ip: Ipv4Addr,
    port: u16,
    sock: Socket,
    started: Instant,
}

enum Start {
    /// The handshake finished before we returned.
    Connected,
    /// The host refused before we returned.
    Refused,
    /// The SYN is out; the verdict is on its way.
    InFlight(Socket),
    Failed(io::Error),
}

fn start_connect(ip: Ipv4Addr, port: u16, source: Option<Ipv4Addr>) -> Start {
    let sock = match Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)) {
        Ok(s) => s,
        Err(e) => return Start::Failed(e),
    };
    if let Some(src) = source
        && let Err(e) = sock.bind(&SockAddr::from(SocketAddr::V4(SocketAddrV4::new(src, 0))))
    {
        return Start::Failed(e);
    }
    if let Err(e) = sock.set_nonblocking(true) {
        return Start::Failed(e);
    }

    let dst = SockAddr::from(SocketAddr::V4(SocketAddrV4::new(ip, port)));
    match sock.connect(&dst) {
        Ok(()) => Start::Connected,
        // `InProgress` is `EINPROGRESS`/`EAGAIN` on Linux, and `WouldBlock` is
        // what the same call reports on macOS and the BSDs. Both mean the same
        // thing here: the SYN is out and the verdict is on its way.
        Err(e) if is_in_progress(&e) => Start::InFlight(sock),
        // A refusal this early is still a refusal, and still proof of life.
        Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => Start::Refused,
        Err(e) => Start::Failed(e),
    }
}

/// Raw error codes that mean "the handshake is still on its way".
///
/// [`io::ErrorKind::InProgress`] would express this exactly, but it is still an
/// unstable std feature, so the codes are spelled out per platform instead.
#[cfg(unix)]
const IN_PROGRESS: &[i32] = &[libc::EINPROGRESS, libc::EALREADY, libc::EAGAIN];

/// `WSAEWOULDBLOCK`, `WSAEALREADY` and `WSAEINVAL`, which is what a nonblocking
/// `connect` on Windows reports while a handshake is outstanding.
#[cfg(windows)]
const IN_PROGRESS: &[i32] = &[10035, 10036, 10022];

/// `ECONNRESET` / `WSAECONNRESET`, for the case where a RST arrives before the
/// connect ever reported a refusal.
#[cfg(unix)]
const RESET: i32 = libc::ECONNRESET;
#[cfg(windows)]
const RESET: i32 = 10054;

/// Whether an error from `connect` means "still waiting", across platforms.
fn is_in_progress(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::WouldBlock
        || e.raw_os_error()
            .is_some_and(|code| IN_PROGRESS.contains(&code))
}

/// Whether the result of [`socket2::Socket::take_error`] reports a refusal.
///
/// A reset mid-handshake surfaces differently depending on the platform and on
/// where in the handshake it lands: as `Err` from the call itself, or as a
/// successful call carrying the pending `SO_ERROR`. Both are refusals.
fn refused(result: &io::Result<Option<io::Error>>) -> bool {
    let is_refusal = |e: &io::Error| {
        e.kind() == io::ErrorKind::ConnectionRefused || e.raw_os_error() == Some(RESET)
    };
    match result {
        Ok(Some(e)) => is_refusal(e),
        Err(e) => is_refusal(e),
        Ok(None) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn prober_on(ports: &[u16]) -> TcpProber {
        TcpProber::new(&ProbeConfig {
            ports: ports.to_vec(),
            timeout: Duration::from_millis(1500),
            concurrency: 32,
            ..ProbeConfig::default()
        })
    }

    /// `ECONNREFUSED` / `WSAECONNREFUSED`, the other shape a reset can take.
    #[cfg(unix)]
    const REFUSED: i32 = libc::ECONNREFUSED;
    #[cfg(windows)]
    const REFUSED: i32 = 10061;

    /// `ETIMEDOUT` / `WSAETIMEDOUT`, which says nothing about the host at all.
    #[cfg(unix)]
    const TIMED_OUT: i32 = libc::ETIMEDOUT;
    #[cfg(windows)]
    const TIMED_OUT: i32 = 10060;

    /// `EHOSTUNREACH` / `WSAEHOSTUNREACH`, which says nothing either.
    #[cfg(unix)]
    const HOST_UNREACH: i32 = libc::EHOSTUNREACH;
    #[cfg(windows)]
    const HOST_UNREACH: i32 = 10065;

    /// The reset classification, tested directly so it is covered everywhere.
    ///
    /// This is the rule that matters most in the whole tool, and it has to hold
    /// on a host that cannot be persuaded to actually reset anything, so it is
    /// checked against the error codes themselves rather than against the
    /// network.
    #[test]
    fn a_reset_is_classified_as_a_refusal_and_a_clean_socket_is_not() {
        // Both shapes a refusal can take: a successful call carrying the pending
        // SO_ERROR, and an error from the call itself.
        assert!(
            refused(&Ok(Some(io::Error::from_raw_os_error(REFUSED)))),
            "a refusal is proof of life"
        );
        assert!(
            refused(&Err(io::Error::from_raw_os_error(RESET))),
            "a reset is proof of life"
        );

        // A completed handshake has no pending error, and must not be mistaken
        // for a refusal.
        assert!(!refused(&Ok(None)), "a completed connect is not a refusal");
        assert!(
            !refused(&Ok(Some(io::Error::from_raw_os_error(TIMED_OUT)))),
            "a timeout says nothing and is not a refusal"
        );
        assert!(
            !refused(&Err(io::Error::from_raw_os_error(HOST_UNREACH))),
            "an unreachable host is not a refusal"
        );
    }

    /// A port, below the dynamic range, that is confirmed to refuse connections.
    ///
    /// Two things make this harder than binding an ephemeral port and letting it
    /// go. A port released that way can be claimed by another test before the
    /// prober dials it, turning the expected refusal into an accept. And Windows
    /// protects the ephemeral range, so a connect to a port it has just handed
    /// out is met with silence rather than a reset, which is indistinguishable
    /// from a filtered host.
    ///
    /// So pick a low port, only consider one we can actually take, and keep it
    /// only once a refusal has been observed.
    fn confirmed_refusing_port() -> Option<u16> {
        // Only a bounded number of candidates are tried: each miss costs a
        // connect timeout, and on a host that never resets anything an unbounded
        // scan of the port range would take minutes to fail.
        for port in (1024..40_000).step_by(997).take(40) {
            let Ok(addr) = format!("127.0.0.1:{port}").parse::<SocketAddr>() else {
                continue;
            };
            // Only a port we can take is a port we know nothing is listening on.
            if std::net::TcpListener::bind(addr).is_err() {
                continue;
            }
            match std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(200)) {
                Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => return Some(port),
                _ => continue,
            }
        }
        None
    }

    #[test]
    fn finds_a_listening_port() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let _ = listener.accept();
        });

        let mut p = prober_on(&[port]);
        let replies = p.probe_round(&[Ipv4Addr::LOCALHOST]).unwrap();

        assert_eq!(replies.len(), 1, "a listening port must be found");
        assert_eq!(replies[0].outcome, Outcome::Alive);
        assert_eq!(replies[0].port, Some(port));
        assert!(
            replies[0].rtt.is_some(),
            "an accepted connection has an rtt"
        );
    }

    #[test]
    fn a_reset_is_reported_as_filtered_not_silent() {
        // This is the case that matters most: a host that is up but refuses us.
        let Some(port) = confirmed_refusing_port() else {
            eprintln!("skipping: no port on this host answers with a reset");
            return;
        };
        let mut p = prober_on(&[port]);
        let replies = p.probe_round(&[Ipv4Addr::LOCALHOST]).unwrap();

        assert_eq!(replies.len(), 1);
        assert_eq!(
            replies[0].outcome,
            Outcome::Filtered,
            "a refused connection proves the host is alive"
        );
        assert!(replies[0].outcome.proves_alive());
    }

    #[test]
    fn an_unroutable_target_reports_nothing() {
        // A black-holed address in TEST-NET-1: nothing answers, so there is no
        // evidence and nothing may be claimed.
        let mut p = prober_on(&[80]);
        let replies = p.probe_round(&[Ipv4Addr::new(192, 0, 2, 1)]).unwrap();
        assert!(
            replies.is_empty(),
            "a timeout must not manufacture a host, got {replies:?}"
        );
    }

    #[test]
    fn empty_input_short_circuits() {
        let mut p = prober_on(&[80]);
        assert!(p.probe_round(&[]).unwrap().is_empty());
    }

    #[test]
    fn every_open_port_of_a_host_is_reported() {
        // Two real listeners, so the host has two open ports at once. Retiring a
        // target after its first answer -- which is what this used to do --
        // reported one of them and lost the other, making the port column a
        // sample of the host's services rather than a list of them.
        let mut open_ports: Vec<u16> = Vec::new();
        let mut keeps: Vec<TcpListener> = Vec::new();
        for _ in 0..2 {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            open_ports.push(l.local_addr().unwrap().port());
            keeps.push(l);
        }
        for l in keeps {
            std::thread::spawn(move || {
                let _ = l.accept();
            });
        }

        let mut p = prober_on(&open_ports);
        let replies = p.probe_round(&[Ipv4Addr::LOCALHOST]).unwrap();

        let mut found: Vec<u16> = replies
            .iter()
            .filter(|r| r.outcome == Outcome::Alive)
            .filter_map(|r| r.port)
            .collect();
        found.sort_unstable();
        let mut expected = open_ports.clone();
        expected.sort_unstable();
        assert_eq!(
            found, expected,
            "both open ports must be reported, not just the first"
        );
    }

    /// More targets than the concurrency limit, to exercise the refill path.
    ///
    /// Only Linux treats the whole of `127.0.0.0/8` as local. macOS and Windows
    /// route just `127.0.0.1`, so the remaining addresses are genuinely absent
    /// there and correctly produce no evidence at all, which makes an assertion
    /// of 64 replies untrue on those platforms rather than the prober wrong.
    #[cfg(target_os = "linux")]
    #[test]
    fn many_targets_are_handled_with_a_small_socket_budget() {
        // Every address is genuinely present: the one with the listener accepts,
        // and the rest refuse. That makes this a test of refill and reset
        // handling at the same time.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let _ = listener.accept();
        });

        let targets: Vec<Ipv4Addr> = (1..=64).map(|i| Ipv4Addr::new(127, 0, 0, i)).collect();
        let Some(closed) = confirmed_refusing_port() else {
            eprintln!("skipping: no port on this host answers with a reset");
            return;
        };
        let mut p = prober_on(&[port, closed]);
        let replies = p.probe_round(&targets).unwrap();

        // Two ports per address, and neither is retired after the first answer,
        // so every address yields exactly two replies: one accept, one refusal.
        assert_eq!(
            replies.len(),
            128,
            "every loopback address answers on both probed ports"
        );
        // The one address with a listener accepts on that port and refuses on
        // the other; every other address refuses on both.
        for r in replies.iter().filter(|r| r.port != Some(port)) {
            assert_eq!(
                r.outcome,
                Outcome::Filtered,
                "a refusal still proves the host exists: {r:?}"
            );
        }
        assert_eq!(
            replies
                .iter()
                .filter(|r| r.ip == Ipv4Addr::LOCALHOST && r.port == Some(port))
                .count(),
            1,
            "the address with the listener accepts on it"
        );
    }

    /// Refilling the queue past the concurrency ceiling must not invent evidence.
    ///
    /// This is the portable half of the test above: it needs more targets than
    /// the socket budget but no assumption that any of them is reachable, so it
    /// holds on every platform.
    #[test]
    fn refill_does_not_invent_evidence_for_unreachable_targets() {
        let targets: Vec<Ipv4Addr> = (1..=64).map(|i| Ipv4Addr::new(192, 0, 2, i)).collect();
        // The targets are unroutable, so nothing local has to be listening and
        // no port needs to be negotiated: the connect never leaves the host.
        let mut p = TcpProber::new(&ProbeConfig {
            ports: vec![9],
            // Kept short so a whole batch of timeouts does not dominate the run.
            timeout: Duration::from_millis(400),
            concurrency: 8,
            ..ProbeConfig::default()
        });
        let replies = p.probe_round(&targets).unwrap();
        assert!(
            replies.is_empty(),
            "unreachable targets must stay silent, got {replies:?}"
        );
    }
}
