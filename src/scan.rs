//! Scan orchestration: the probe cascade.
//!
//! # Why a cascade and not one prober
//!
//! Every way of asking "is this host up?" is wrong in a different direction, so
//! running only one of them means systematically missing a class of hosts:
//!
//! | Method       | Blind to                                                        |
//! |--------------|-----------------------------------------------------------------|
//! | ICMP echo    | hosts whose firewall drops echo — the Windows default            |
//! | TCP connect  | hosts with none of the probed ports open, and filtered droppers |
//! | ARP          | anything off-subnet; IPv6-only hosts; needs privileges           |
//!
//! So the scanner escalates instead. Every target starts with the cheapest
//! method that can be trusted, and only what comes back *unanswered* is passed
//! to the next one. The critical rule is that a timeout is not a negative
//! answer — it is the absence of one, and those targets keep escalating.
//!
//! The neighbour table is read twice, and the ordering is deliberate. Read
//! *before* the sweep, it primes the probe order with addresses the kernel has
//! recently resolved, so likely-live hosts are tried first. Read *after* the
//! sweep, it supplies MAC addresses for exactly the hosts that answered,
//! because answering an ICMP echo requires an ARP resolution — which is what
//! populates the table. That makes the post-sweep read a side effect of our own
//! probe rather than a guess, and it needs no privileges.

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use anyhow::Result;

use crate::host::{Host, HostTable, Method, Outcome};
use crate::net::Interface;
use crate::probe::arp::ArpProber;
use crate::probe::icmp::IcmpProber;
use crate::probe::neighbour;
use crate::probe::tcp::TcpProber;
use crate::probe::{ProbeConfig, Reply};
use crate::target::TargetSet;

/// Which probes to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum MethodChoice {
    /// Run the full cascade. The default.
    Auto,
    Icmp,
    Tcp,
    Arp,
}

impl MethodChoice {
    pub fn as_str(self) -> &'static str {
        match self {
            MethodChoice::Auto => "auto",
            MethodChoice::Icmp => "icmp",
            MethodChoice::Tcp => "tcp",
            MethodChoice::Arp => "arp",
        }
    }
}

/// What to scan and how.
#[derive(Debug, Clone)]
pub struct ScanPlan {
    pub targets: TargetSet,
    pub method: MethodChoice,
    pub config: ProbeConfig,
    /// Interface the scan is anchored to, when one was selected or detected.
    pub interface: Option<Interface>,
    /// Reverse-resolve discovered addresses.
    pub resolve_hostnames: bool,
    /// Include addresses known only to the neighbour cache, flagged as cached.
    pub include_cached: bool,
    /// Emit progress to stderr.
    pub progress: bool,
}

/// Counters for what the scan actually did, for the summary and for tests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanStats {
    pub addresses: usize,
    pub icmp_probes: u64,
    pub tcp_connections: u64,
    pub arp_requests: u64,
    /// Addresses handed to the TCP fallback because ICMP never answered.
    pub escalated_to_tcp: usize,
    /// Addresses skipped by ARP because they are not on a directly-attached link.
    pub arp_unreachable: usize,
    /// Diagnostics: skipped methods, degraded paths, hints.
    pub notes: Vec<String>,
}

impl ScanStats {
    fn note(&mut self, msg: impl Into<String>) {
        self.notes.push(msg.into());
    }
}

/// Everything the output layer needs.
#[derive(Debug)]
pub struct ScanReport {
    pub hosts: Vec<Host>,
    pub stats: ScanStats,
    pub interface: Option<Interface>,
    pub target_spec: String,
    pub elapsed: Duration,
}

/// Run a scan to completion.
pub fn run(plan: &ScanPlan) -> Result<ScanReport> {
    let started = Instant::now();
    let mut stats = ScanStats {
        addresses: plan.targets.len() as usize,
        ..ScanStats::default()
    };
    let mut table = HostTable::new();

    // Addresses, in the order they will be probed. Read once for MACs and for
    // a better probe order, then re-read after the sweep for the real mapping.
    let mut all: Vec<Ipv4Addr> = plan.targets.iter().collect();
    let seed: HashSet<Ipv4Addr> = neighbour::read_table()
        .unwrap_or_default()
        .into_iter()
        .map(|n| n.ip)
        .collect();

    // Prioritise addresses the kernel resolved recently: if it answered for them
    // a moment ago it probably will again, and this is most of the difference
    // between a scan that feels instant and one that feels sluggish. Numeric
    // order is kept within each group so output stays predictable.
    all.sort_by(|a, b| {
        seed.contains(b)
            .cmp(&seed.contains(a))
            .then_with(|| u32::from(*a).cmp(&u32::from(*b)))
    });

    let mut settled: HashSet<Ipv4Addr> = HashSet::new();

    // ------------------------------------------------------------- ARP ----
    if matches!(plan.method, MethodChoice::Arp | MethodChoice::Auto) {
        run_arp(plan, &all, &mut table, &mut stats, &mut settled);
    }

    // ------------------------------------------------------------ ICMP ----
    if matches!(plan.method, MethodChoice::Icmp | MethodChoice::Auto) {
        let pending: Vec<Ipv4Addr> = all
            .iter()
            .copied()
            .filter(|ip| !settled.contains(ip))
            .collect();
        if !pending.is_empty() {
            if plan.progress {
                eprintln!("probing {} addresses with icmp...", pending.len());
            }
            match IcmpProber::new(&plan.config) {
                Ok(mut prober) => {
                    if plan.progress {
                        eprintln!("  via {}", prober.socket_kind().as_str());
                    }
                    stats.icmp_probes +=
                        run_icmp_rounds(&mut prober, &pending, plan, &mut table, &mut settled);
                }
                Err(e) => stats.note(format!("icmp unavailable, falling back to tcp: {e:#}")),
            }
        }
    }

    // ------------------------------------------------------------- TCP ----
    // Only the residue. These are addresses nothing has answered for, which is
    // the whole point: spending a connect on an already-confirmed host wastes
    // both time and a few packets on the target.
    if matches!(plan.method, MethodChoice::Tcp | MethodChoice::Auto) {
        let residue: Vec<Ipv4Addr> = all
            .iter()
            .copied()
            .filter(|ip| !settled.contains(ip))
            .collect();
        if !residue.is_empty() {
            stats.escalated_to_tcp = residue.len();
            if plan.progress {
                eprintln!(
                    "icmp gave no answer for {} addresses, trying tcp...",
                    residue.len()
                );
            }
            let mut prober = TcpProber::new(&plan.config);
            stats.tcp_connections += (residue.len() * prober.ports().len()) as u64;
            for reply in prober.probe_round(&residue)? {
                record(&mut table, &mut settled, reply, Method::Tcp);
            }
            for f in prober.failures() {
                stats.note(format!("tcp connect could not be attempted: {f}"));
            }
        }
    }

    // ------------------------------------------------- neighbour re-read ----
    // After the sweep the table holds resolutions our own probes caused, so this
    // is a consequence of the scan rather than a stale guess.
    let after = neighbour::read_table().unwrap_or_default();
    let mut macs_added = 0usize;
    for n in &after {
        if !seed.contains(&n.ip) {
            macs_added += 1;
        }
        table.record_mac(n.ip, n.mac);
    }
    if macs_added > 0 && plan.progress {
        eprintln!("resolved {macs_added} hardware addresses from the neighbour table");
    }

    // Addresses the cache knows but no probe confirmed.
    if plan.include_cached {
        for n in &after {
            if !table.alive().iter().any(|h| h.ip == n.ip) {
                table.record(
                    n.ip,
                    crate::host::Evidence::new(Method::Neighbour, Outcome::Alive),
                );
            }
        }
    }

    // ------------------------------------------------------- hostnames ----
    if plan.resolve_hostnames {
        let alive: Vec<Ipv4Addr> = table.alive().iter().map(|h| h.ip).collect();
        for ip in alive {
            if let Some(name) = reverse_dns(ip) {
                table.record_hostname(ip, name);
            }
        }
    }

    let mut hosts = table.alive().into_iter().cloned().collect::<Vec<Host>>();
    hosts.sort_by_key(|h| u32::from(h.ip));

    Ok(ScanReport {
        hosts,
        stats,
        interface: plan.interface.clone(),
        target_spec: plan.targets.spec().to_string(),
        elapsed: started.elapsed(),
    })
}

/// Active ARP, restricted to addresses on a directly-attached link.
///
/// ARP cannot be routed, so probing an off-subnet address is not merely
/// useless, it is misleading: the request goes nowhere and the target looks
/// dead. Those targets are counted and handed to the next method instead.
fn run_arp(
    plan: &ScanPlan,
    all: &[Ipv4Addr],
    table: &mut HostTable,
    stats: &mut ScanStats,
    settled: &mut HashSet<Ipv4Addr>,
) {
    let on_link: Vec<Ipv4Addr> = match &plan.interface {
        Some(iface) => all
            .iter()
            .copied()
            .filter(|ip| iface.contains(*ip))
            .collect(),
        // Without a known interface there is no way to know what is on-link,
        // and guessing would produce false negatives. Skip rather than lie.
        None => {
            stats.note("active arp skipped: no interface selected, so on-link targets are unknown");
            return;
        }
    };
    let off_link = all.len() - on_link.len();
    if off_link > 0 {
        stats.arp_unreachable = off_link;
    }
    if on_link.is_empty() {
        return;
    }

    let availability = ArpProber::availability();
    if !availability.available {
        stats.note(format!("active arp unavailable: {}", availability.reason));
        return;
    }

    match ArpProber::new(&plan.config) {
        Ok(mut prober) => {
            stats.arp_requests += on_link.len() as u64;
            if plan.progress {
                eprintln!("probing {} on-link addresses with arp...", on_link.len());
            }
            match prober.probe_round(&on_link) {
                Ok(replies) => {
                    for reply in replies {
                        if let Some(mac) = reply.mac {
                            table.record_mac(reply.ip, mac);
                        }
                        record(table, settled, reply, Method::Arp);
                    }
                }
                Err(e) => stats.note(format!("active arp failed: {e:#}")),
            }
        }
        Err(e) => stats.note(format!("active arp unavailable: {e:#}")),
    }
}

/// ICMP, with retries over the addresses that did not answer.
fn run_icmp_rounds(
    prober: &mut IcmpProber,
    pending: &[Ipv4Addr],
    plan: &ScanPlan,
    table: &mut HostTable,
    settled: &mut HashSet<Ipv4Addr>,
) -> u64 {
    let mut sent = 0u64;
    let mut round_targets: Vec<Ipv4Addr> = pending.to_vec();
    let rounds = plan.config.retries as usize + 1;

    for round in 0..rounds {
        if round_targets.is_empty() {
            break;
        }
        sent += round_targets.len() as u64;
        let replies = prober.probe_round(&round_targets).unwrap_or_default();

        let mut answered: HashSet<Ipv4Addr> = HashSet::new();
        for reply in replies {
            answered.insert(reply.ip);
            record(table, settled, reply, Method::Icmp);
        }

        if round + 1 < rounds {
            round_targets.retain(|ip| !answered.contains(ip));
        }
    }
    sent
}

/// Fold a reply into the table and mark its target settled.
fn record(table: &mut HostTable, settled: &mut HashSet<Ipv4Addr>, reply: Reply, method: Method) {
    if let Some(mac) = reply.mac {
        table.record_mac(reply.ip, mac);
    }
    // A `Silent` reply is recorded so the target appears in the table, but it
    // does not settle the target and does not make it alive.
    table.record(reply.ip, reply.clone().into_evidence(method));
    if reply.is_conclusive() {
        settled.insert(reply.ip);
    }
}

/// Reverse DNS, with a hard timeout so one black-holed resolver cannot hang the
/// whole scan. Neither `getnameinfo` nor `GetAddrInfoW` has a timeout knob, so
/// each lookup is isolated on a thread that we simply stop waiting for.
fn reverse_dns(ip: Ipv4Addr) -> Option<String> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        if let Some(name) = crate::dns::lookup(ip) {
            let _ = tx.send(name);
        }
    });

    rx.recv_timeout(Duration::from_millis(750)).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::MacAddr;

    fn plan_for(spec: &str) -> ScanPlan {
        ScanPlan {
            targets: TargetSet::parse([spec]).unwrap(),
            method: MethodChoice::Auto,
            config: ProbeConfig {
                timeout: Duration::from_millis(300),
                retries: 0,
                concurrency: 32,
                ..ProbeConfig::default()
            },
            interface: None,
            resolve_hostnames: false,
            include_cached: false,
            progress: false,
        }
    }

    #[test]
    fn a_single_loopback_target_is_found_by_arp() {
        // Loopback has no ARP, so this exercises the cascade's other paths.
        let report = run(&plan_for("127.0.0.1")).unwrap();
        assert!(
            report.hosts.iter().any(|h| h.ip == Ipv4Addr::LOCALHOST),
            "loopback must be discovered, got {:?}",
            report.hosts
        );
    }

    #[test]
    fn the_report_never_contains_a_host_without_proof() {
        let report = run(&plan_for("127.0.0.1")).unwrap();
        for h in &report.hosts {
            assert!(
                h.is_alive(),
                "host {} was reported without conclusive evidence: {:?}",
                h.ip,
                h.evidence
            );
        }
    }

    #[test]
    fn stats_account_for_every_address() {
        let report = run(&plan_for("127.0.0.0/30")).unwrap();
        assert_eq!(report.stats.addresses, 4);
        assert!(
            report.elapsed.as_millis() < 5_000,
            "a /30 should be near-instant"
        );
    }

    #[test]
    fn method_choice_naming_is_stable() {
        assert_eq!(MethodChoice::Auto.as_str(), "auto");
        assert_eq!(MethodChoice::Icmp.as_str(), "icmp");
        assert_eq!(MethodChoice::Tcp.as_str(), "tcp");
        assert_eq!(MethodChoice::Arp.as_str(), "arp");
    }

    #[test]
    fn recording_a_silent_reply_does_not_settle_the_target() {
        let mut table = HostTable::new();
        let mut settled = HashSet::new();
        let reply = Reply::new(Ipv4Addr::new(10, 0, 0, 9), Outcome::Silent);
        record(&mut table, &mut settled, reply, Method::Icmp);

        assert!(settled.is_empty(), "a timeout must leave the target open");
        assert!(table.alive().is_empty(), "and must not become a host");
    }

    #[test]
    fn recording_a_filtered_reply_settles_the_target() {
        let mut table = HostTable::new();
        let mut settled = HashSet::new();
        let reply = Reply::new(Ipv4Addr::new(10, 0, 0, 9), Outcome::Filtered);
        record(&mut table, &mut settled, reply, Method::Tcp);

        assert!(settled.contains(&Ipv4Addr::new(10, 0, 0, 9)));
        assert_eq!(table.alive().len(), 1);
    }

    #[test]
    fn a_reply_mac_reaches_the_host() {
        let mut table = HostTable::new();
        let mut settled = HashSet::new();
        let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
        let reply = Reply::new(Ipv4Addr::new(10, 0, 0, 9), Outcome::Alive).with_mac(mac);
        record(&mut table, &mut settled, reply, Method::Arp);
        assert_eq!(table.alive()[0].mac, Some(mac));
    }

    #[test]
    fn arp_is_skipped_rather_than_guessed_without_an_interface() {
        let mut plan = plan_for("10.0.0.0/24");
        plan.method = MethodChoice::Arp;
        plan.interface = None;
        let report = run(&plan).unwrap();
        assert!(
            report.stats.notes.iter().any(|n| n.contains("arp skipped")),
            "expected an explanatory note, got {:?}",
            report.stats.notes
        );
    }
}
