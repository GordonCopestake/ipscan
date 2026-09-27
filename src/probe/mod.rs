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
use std::time::Duration;

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

/// Check the one address that is definitionally alive, so scans have a sanity
/// anchor and the output always contains something on a working machine.
pub fn self_check(addr: Ipv4Addr) -> bool {
    addr.is_loopback() || addr.is_unspecified()
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
}
