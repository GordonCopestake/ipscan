//! Probe implementations.
//!
//! Each probe answers one question — "is this host up?" — in a way that has a
//! different blind spot from the others. The scanner runs them in a cascade for
//! exactly that reason; see [`crate::scan`].

pub mod arp;
pub mod icmp;
pub mod neighbour;
pub mod tcp;

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crate::host::{Evidence, Method, Outcome};

/// Tunables shared by every probe.
#[derive(Debug, Clone)]
pub struct ProbeConfig {
    /// How long to wait for any one exchange to complete.
    pub timeout: Duration,
    /// Extra attempts for a target that did not answer the first one.
    pub retries: u32,
    /// Ceiling on probes per second, if the user set one.
    pub rate: Option<u32>,
    /// How many targets to have in flight at once.
    pub concurrency: usize,
    /// Ports for the TCP connect method.
    pub ports: Vec<u16>,
    /// Source address to send from, pinning traffic to one interface.
    pub source: Option<Ipv4Addr>,
    /// Interface name, needed by layer-2 methods.
    pub iface: Option<String>,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        ProbeConfig {
            timeout: Duration::from_millis(1000),
            retries: 1,
            rate: None,
            concurrency: 256,
            ports: tcp::DEFAULT_PORTS.to_vec(),
            source: None,
            iface: None,
        }
    }
}

/// Ceiling on worker threads for probes that are synchronous per target.
///
/// `SendARP` and `IcmpSendEcho2` offer no way to overlap several outstanding
/// requests on one socket, so the only concurrency available is one thread per
/// in-flight target. That makes a thread count a resource decision rather than a
/// formatting one: every worker owns a stack and a thread-pool slot, so taking
/// `--concurrency` literally on these paths costs far more than it buys and is
/// enough to make a machine crawl. These calls are I/O-blocked, so a few dozen
/// workers already keep every timeout window occupied.
pub const MAX_BLOCKING_WORKERS: usize = 128;

/// How many threads to use for a blocking, per-target probe of `total`
/// targets: enough to keep the waits overlapped, never more than there are
/// targets, and never the absurd.
pub fn blocking_workers(total: usize, concurrency: usize) -> usize {
    if total == 0 {
        return 0;
    }
    concurrency.clamp(1, MAX_BLOCKING_WORKERS).min(total)
}

/// A pacing gate for probes that would otherwise fire as fast as the loop can
/// turn.
///
/// `--rate` exists because a sweep that floods a segment loses its own replies:
/// a switch or a host with a small receive queue drops the responses we most
/// want, so the fastest sweep is not the one that finds the most hosts. It is
/// also the knob for a network where the scanner is the loudest thing on the
/// wire.
///
/// The limiter is deliberately coarse. It spaces *starts*, not packets, and it
/// never holds a probe past the point where waiting would eat the timeout it is
/// about to be measured against: a probe that starts late has already lost part
/// of its window. So the wait is capped at half the probe timeout, and a rate
/// too slow to fit a whole round inside the deadline is reported rather than
/// silently obeyed.
#[derive(Debug, Clone)]
pub struct Throttle {
    /// Time between probe starts. `None` means no pacing.
    gap: Option<Duration>,
    /// Longest wait we are willing to impose on a single probe.
    cap: Duration,
    next: Instant,
}

impl Throttle {
    /// Build a throttle from a probes-per-second ceiling, if one was asked for.
    pub fn new(rate_pps: Option<u32>, timeout: Duration) -> Self {
        let gap = rate_pps
            .filter(|r| *r > 0)
            .map(|r| Duration::from_secs_f64(1.0 / f64::from(r)));
        Throttle {
            gap,
            cap: timeout / 2,
            next: Instant::now(),
        }
    }

    pub fn paced(&self) -> bool {
        self.gap.is_some()
    }

    /// The gap between starts, already clipped by the per-probe cap.
    ///
    /// A backend that cannot hold a throttle across its worker threads paces by
    /// sleeping this long per probe instead.
    pub fn gap(&self) -> Option<Duration> {
        self.gap.map(|g| g.min(self.cap))
    }

    /// Block until this probe may start, and advance the schedule.
    ///
    /// Returns how long the caller had to wait, so a phase can push its deadline
    /// out by the same amount: pacing must not also shorten the window each probe
    /// is allowed for an answer.
    pub fn wait(&mut self) -> Duration {
        let Some(gap) = self.gap else {
            return Duration::ZERO;
        };
        let now = Instant::now();
        if now >= self.next {
            // Behind schedule: start now rather than banking unused credit, which
            // would let a slow phase burst afterwards.
            self.next = now + gap;
            return Duration::ZERO;
        }
        let wait = (self.next - now).min(self.cap);
        std::thread::sleep(wait);
        self.next += gap;
        wait
    }
}

/// The result of probing a single target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub ip: Ipv4Addr,
    pub outcome: Outcome,
    pub rtt: Option<Duration>,
    pub ttl: Option<u8>,
    pub port: Option<u16>,
    /// Hardware address, when the probe happened to learn one.
    pub mac: Option<crate::host::MacAddr>,
}

impl Reply {
    pub fn new(ip: Ipv4Addr, outcome: Outcome) -> Self {
        Reply {
            ip,
            outcome,
            rtt: None,
            ttl: None,
            port: None,
            mac: None,
        }
    }

    pub fn with_rtt(mut self, rtt: Duration) -> Self {
        self.rtt = Some(rtt);
        self
    }

    pub fn with_ttl(mut self, ttl: u8) -> Self {
        self.ttl = Some(ttl);
        self
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    pub fn with_mac(mut self, mac: crate::host::MacAddr) -> Self {
        self.mac = Some(mac);
        self
    }

    /// Whether this reply settles the target's existence, ending the cascade
    /// for it. A `Silent` reply does not, and lets the next method try.
    pub fn is_conclusive(&self) -> bool {
        self.outcome.proves_alive()
    }

    pub fn into_evidence(self, method: Method) -> Evidence {
        let Reply {
            outcome,
            rtt,
            ttl,
            port,
            ..
        } = self;
        let mut ev = Evidence::new(method, outcome);
        ev.rtt = rtt;
        ev.ttl = ttl;
        ev.port = port;
        ev
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_conclusive_replies_stop_the_cascade() {
        let alive = Reply::new("10.0.0.1".parse().unwrap(), Outcome::Alive);
        let filtered = Reply::new("10.0.0.2".parse().unwrap(), Outcome::Filtered);
        let silent = Reply::new("10.0.0.3".parse().unwrap(), Outcome::Silent);
        assert!(alive.is_conclusive());
        assert!(
            filtered.is_conclusive(),
            "a refused connection still proves life"
        );
        assert!(
            !silent.is_conclusive(),
            "a timeout must escalate to the next method"
        );
    }

    #[test]
    fn reply_converts_to_evidence() {
        let r = Reply::new("10.0.0.1".parse().unwrap(), Outcome::Alive)
            .with_rtt(Duration::from_millis(4))
            .with_ttl(64)
            .with_port(80);
        let ev = r.into_evidence(Method::Tcp);
        assert_eq!(ev.method, Method::Tcp);
        assert_eq!(ev.port, Some(80));
        assert_eq!(ev.ttl, Some(64));
        assert_eq!(ev.rtt, Some(Duration::from_millis(4)));
    }

    #[test]
    fn default_ports_are_sane() {
        let cfg = ProbeConfig::default();
        assert!(cfg.ports.contains(&80));
        assert!(cfg.ports.contains(&443));
        assert!(cfg.ports.contains(&22));
    }

    #[test]
    fn blocking_probes_never_explode_into_a_thread_per_address() {
        // The whole point: a /24 must not become 256 threads.
        assert_eq!(blocking_workers(256, 256), MAX_BLOCKING_WORKERS);
        assert_eq!(blocking_workers(256, 3), 3);
    }

    #[test]
    fn blocking_probes_never_exceed_the_target_count() {
        assert_eq!(blocking_workers(4, 256), 4);
        assert_eq!(blocking_workers(1, 256), 1);
    }

    #[test]
    fn blocking_probes_survive_nonsense_concurrency() {
        assert_eq!(blocking_workers(256, 0), 1, "a zero is raised to one");
        assert_eq!(blocking_workers(0, 256), 0, "no targets, no workers");
    }

    #[test]
    fn no_rate_means_no_pacing() {
        // The common case must cost nothing: an unpaced throttle never sleeps
        // and never reports a gap.
        let mut t = Throttle::new(None, Duration::from_millis(500));
        assert!(!t.paced());
        assert!(t.gap().is_none());
        let started = Instant::now();
        for _ in 0..50 {
            assert_eq!(t.wait(), Duration::ZERO);
        }
        assert!(
            started.elapsed() < Duration::from_millis(50),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_zero_rate_is_not_a_rate() {
        // `--rate 0` would mean "wait forever between probes", which is not a
        // thing anyone means when they type it.
        let t = Throttle::new(Some(0), Duration::from_millis(500));
        assert!(!t.paced(), "a zero must fall back to unpaced");
    }

    #[test]
    fn pacing_spaces_the_starts() {
        // 2000 pps is a 0.5ms gap. Ten starts must therefore take several
        // milliseconds, not zero, and the measured rate must be near the
        // requested one.
        let mut t = Throttle::new(Some(2000), Duration::from_millis(500));
        assert!(t.paced());
        let started = Instant::now();
        for _ in 0..10 {
            t.wait();
        }
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_millis(4),
            "10 starts at 2000pps should take ~4.5ms, got {elapsed:?}"
        );
    }

    #[test]
    fn pacing_never_eats_the_timeout_it_is_measured_against() {
        // An absurd rate must not turn into a wait longer than the probe's own
        // deadline, or `--rate 1` would make every probe time out for a reason
        // that has nothing to do with the target. The cap is half the timeout,
        // so a 1s gap against a 400ms probe is clipped to 200ms.
        let t = Throttle::new(Some(1), Duration::from_millis(400));
        assert_eq!(
            t.gap(),
            Some(Duration::from_millis(200)),
            "a 1s gap must be clipped to half the probe timeout"
        );
        let started = Instant::now();
        let mut t = t;
        t.wait();
        assert!(
            started.elapsed() <= Duration::from_millis(250),
            "a wait must be capped at half the probe timeout, got {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn an_unpaced_throttle_does_not_accumulate_credit() {
        // A throttle that has been idle must not burst afterwards: waiting is
        // scheduled from "now" whenever the schedule is already in the past.
        let mut t = Throttle::new(Some(1000), Duration::from_millis(500));
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(
            t.wait(),
            Duration::ZERO,
            "behind schedule means start immediately"
        );
    }
}
