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

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;

use crate::host::{Host, HostTable, MacAddr, Method, Outcome};
use crate::net::Interface;
use crate::probe::arp::ArpProber;
use crate::probe::icmp::IcmpProber;
use crate::probe::neighbour;
use crate::probe::tcp::TcpProber;
use crate::probe::{ProbeConfig, Reply};
use crate::target::TargetSet;

/// How often a blocked phase says that it is still going.
const TICK: Duration = Duration::from_secs(2);

/// Threads used to overlap reverse lookups. Lookups block in the system
/// resolver, so the count is a parallelism choice, not a formatting one.
const DNS_WORKERS: usize = 32;

/// How long a single reverse lookup is given before the set is called done.
const DNS_PER_LOOKUP: Duration = Duration::from_millis(750);

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
    if plan.progress {
        eprintln!("reading the neighbour cache...");
    }
    let cache_started = Instant::now();
    // The reason is kept rather than discarded. "No entries" and "the read
    // failed" look identical from the outside, and on Windows that is the
    // difference between an empty network and a probe that is silently broken.
    let (cached, cache_error) = match neighbour::read_table() {
        Ok(table) => (table, None),
        Err(e) => (Vec::new(), Some(format!("{e:#}"))),
    };
    if let Some(reason) = &cache_error {
        if plan.progress {
            eprintln!("  neighbour cache: unreadable: {reason}");
        }
        stats.note(format!("neighbour cache unreadable: {reason}"));
    } else if plan.progress {
        eprintln!(
            "  neighbour cache: {} entries in {}",
            cached.len(),
            human(cache_started.elapsed())
        );
    }
    let seed: HashSet<Ipv4Addr> = cached.iter().map(|n| n.ip).collect();

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
                    let before = settled.len();
                    let ticker = Ticker::start("icmp");
                    let phase_started = Instant::now();
                    stats.icmp_probes +=
                        run_icmp_rounds(&mut prober, &pending, plan, &mut table, &mut settled);
                    ticker.stop();
                    if plan.progress {
                        eprintln!(
                            "  icmp: {} answered of {} in {}",
                            settled.len().saturating_sub(before),
                            pending.len(),
                            human(phase_started.elapsed())
                        );
                    }
                }
                Err(e) => {
                    if plan.progress {
                        eprintln!("  icmp unavailable: {e:#}");
                    }
                    stats.note(format!("icmp unavailable, falling back to tcp: {e:#}"));
                }
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
            let before = settled.len();
            let attempts = residue.len() * TcpProber::new(&plan.config).ports().len();
            let ticker = Ticker::start("tcp");
            let phase_started = Instant::now();
            let mut prober = TcpProber::new(&plan.config);
            stats.tcp_connections += attempts as u64;
            for reply in prober.probe_round(&residue)? {
                record(&mut table, &mut settled, reply, Method::Tcp);
            }
            for f in prober.failures() {
                stats.note(format!("tcp connect could not be attempted: {f}"));
            }
            ticker.stop();
            if plan.progress {
                eprintln!(
                    "  tcp: {} answered of {} connects in {}",
                    settled.len().saturating_sub(before),
                    attempts,
                    human(phase_started.elapsed())
                );
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
    if plan.progress && macs_added > 0 {
        eprintln!("resolved {macs_added} hardware addresses from the neighbour cache");
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
        if plan.progress && !alive.is_empty() {
            eprintln!("resolving hostnames for {} addresses...", alive.len());
        }
        let ticker = Ticker::start("dns");
        let phase_started = Instant::now();
        let names = resolve_all(&alive);
        for (ip, name) in &names {
            table.record_hostname(*ip, name.clone());
        }
        ticker.stop();
        if plan.progress && !alive.is_empty() {
            eprintln!(
                "  dns: {} of {} resolved in {}",
                names.len(),
                alive.len(),
                human(phase_started.elapsed())
            );
        }
    }

    let mut hosts = table.alive().into_iter().cloned().collect::<Vec<Host>>();
    hosts.sort_by_key(|h| u32::from(h.ip));

    if plan.progress {
        eprintln!(
            "done: {} host{} in {}",
            hosts.len(),
            if hosts.len() == 1 { "" } else { "s" },
            human(started.elapsed())
        );
    }

    Ok(ScanReport {
        hosts,
        stats,
        interface: plan.interface.clone(),
        target_spec: plan.targets.spec().to_string(),
        elapsed: started.elapsed(),
    })
}

/// Warn when a single hardware account answers for most of the subnet.
///
/// This is the shape of **proxy-ARP**: a router, a hypervisor switch, or a NAC
/// appliance replies to ARP on behalf of an address range it merely routes. Each
/// of those is a genuine, successful ARP exchange, so a sweep that reads
/// "the exchange succeeded" as "a host is there" cheerfully reports an entire
/// routed range as a room full of machines.
///
/// The tell is the hardware address. Real hosts have distinct MACs; a proxying
/// device answers with its own, over and over. Keeping the MAC — the thing
/// `SendARP` hands back, and which this probe used to throw away — is what
/// turns an undetectable false positive into a sentence the user can act on.
///
/// The threshold is deliberately conservative: one MAC must account for a
/// *majority* of the replies, because a handful of addresses legitimately
/// sharing an address (a bridge with several IPs, say) is not an anomaly.
fn warn_if_one_mac_answers_everything(plan: &ScanPlan, stats: &mut ScanStats, replies: &[Reply]) {
    if replies.len() < 2 {
        return;
    }
    let mut by_mac: HashMap<MacAddr, usize> = HashMap::new();
    for reply in replies {
        if let Some(mac) = reply.mac {
            *by_mac.entry(mac).or_default() += 1;
        }
    }
    let Some((&mac, &count)) = by_mac.iter().max_by_key(|(_, n)| **n) else {
        return;
    };
    if count < 2 || count * 2 <= replies.len() {
        return;
    }
    let msg = format!(
        "{count} of {} arp replies came from the single hardware address {mac}, \
         which is proxy-arp: one device answering for a range it routes rather \
         than {count} separate hosts",
        replies.len()
    );
    if plan.progress {
        eprintln!("  warning: {msg}");
    }
    stats.note(msg);
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
            let ticker = Ticker::start("arp");
            let phase_started = Instant::now();
            let alive = match prober.probe_round(&on_link) {
                Ok(replies) => {
                    let n = replies.len();
                    warn_if_one_mac_answers_everything(plan, stats, &replies);
                    for reply in replies {
                        if let Some(mac) = reply.mac {
                            table.record_mac(reply.ip, mac);
                        }
                        record(table, settled, reply, Method::Arp);
                    }
                    n
                }
                Err(e) => {
                    stats.note(format!("active arp failed: {e:#}"));
                    0
                }
            };
            ticker.stop();
            if plan.progress {
                eprintln!(
                    "  arp: {alive} alive of {} in {}",
                    on_link.len(),
                    human(phase_started.elapsed())
                );
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

/// Reverse-resolve a set of addresses, concurrently.
///
/// Neither `getnameinfo` nor `GetAddrInfoExW` has a timeout knob, and a
/// black-holed resolver can sit in a call for the operating system's full
/// several-seconds DNS timeout. Two things follow. Each lookup has to be
/// isolated on a thread the caller is willing to walk away from, and the
/// abandoned threads must be *bounded* — one per address turned a large scan
/// into a few hundred threads stuck in the resolver, which is its own kind of
/// hang. So the set is drained by a small pool, and the pool is given one
/// overall budget sized by how many rounds of it the set needs.
fn resolve_all(ips: &[Ipv4Addr]) -> HashMap<Ipv4Addr, String> {
    let mut found: HashMap<Ipv4Addr, String> = HashMap::new();
    if ips.is_empty() {
        return found;
    }

    let workers = crate::probe::blocking_workers(ips.len(), DNS_WORKERS);
    let queue = Arc::new(Mutex::new(ips.to_vec()));
    let (tx, rx) = mpsc::channel::<(Ipv4Addr, String)>();

    for _ in 0..workers {
        let queue = Arc::clone(&queue);
        let tx = tx.clone();
        // Detached on purpose: a resolver call cannot be cancelled, so the main
        // thread gives up on it rather than joining it. The pool bounds how
        // many such calls can be outstanding.
        std::thread::spawn(move || {
            loop {
                let next = queue.lock().expect("reverse-dns queue poisoned").pop();
                let Some(ip) = next else { return };
                if let Some(name) = crate::dns::lookup(ip) {
                    // A send error means the scan stopped waiting; the work is moot.
                    if tx.send((ip, name)).is_err() {
                        return;
                    }
                }
            }
        });
    }
    // Releasing our own handle lets `recv` end promptly once the pool drains,
    // instead of waiting out the budget on a scan where every lookup answered.
    drop(tx);

    let rounds = ips.len().div_ceil(workers).max(1) as u32;
    let deadline = Instant::now() + DNS_PER_LOOKUP * rounds;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        match rx.recv_timeout(left) {
            Ok((ip, name)) => {
                found.insert(ip, name);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => break,
            // Every worker has returned, so no further names are coming.
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    found
}

/// Human-readable elapsed time: sub-second phases keep one decimal, longer ones
/// do not, and anything past ten minutes reads as minutes rather than as a
/// five-digit number of milliseconds.
fn human(elapsed: Duration) -> String {
    let secs = elapsed.as_secs_f64();
    if secs < 10.0 {
        format!("{secs:.1}s")
    } else if secs < 600.0 {
        format!("{secs:.0}s")
    } else {
        format!("{}m{:02}s", (secs / 60.0) as u64, (secs % 60.0) as u64)
    }
}

/// Progress reporting for a phase that may block on the operating system.
///
/// The point is that a scan of a subnet full of machines that never answer
/// spends real minutes inside `SendARP` and the ICMP handle. That used to be
/// indistinguishable from a crashed process: the only line printed was the one
/// naming the phase, and nothing followed it. A heartbeat turns dead air into
/// visible elapsed time, and phases that finish inside a tick print nothing at
/// all, so a fast scan is unaffected.
struct Ticker {
    stop: Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Ticker {
    fn start(label: &'static str) -> Self {
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            let mut waited = Duration::ZERO;
            loop {
                // Polled in short slices so stopping does not have to wait out a
                // whole tick before the scan continues.
                for _ in 0..20 {
                    if flag.load(std::sync::atomic::Ordering::Relaxed) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                waited += TICK;
                eprintln!("  {label}: waiting, {:.0}s elapsed", waited.as_secs_f64());
            }
        });
        Ticker {
            stop,
            handle: Some(handle),
        }
    }

    fn stop(mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
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
        // A /30 is 4 addresses of which .0 and .3 are network and broadcast, so
        // the two in the middle are the whole scan.
        let report = run(&plan_for("127.0.0.0/30")).unwrap();
        assert_eq!(report.stats.addresses, 2);
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

    #[test]
    fn elapsed_reads_as_seconds_then_minutes() {
        assert_eq!(human(Duration::from_millis(4200)), "4.2s");
        assert_eq!(human(Duration::from_millis(90_000)), "90s");
        assert_eq!(human(Duration::from_secs(3725)), "62m05s");
    }

    #[test]
    fn resolving_nothing_resolves_nothing() {
        assert!(resolve_all(&[]).is_empty());
    }

    #[test]
    fn a_ticker_reports_nothing_until_it_is_stopped() {
        // The heartbeat must not fire for a phase that finishes inside a tick,
        // or every fast scan would gain a line of noise.
        let ticker = Ticker::start("test");
        ticker.stop();
    }

    fn arp_reply(ip: Ipv4Addr, mac: &str) -> Reply {
        Reply::new(ip, Outcome::Alive).with_mac(MacAddr::parse(mac).unwrap())
    }

    #[test]
    fn one_mac_answering_for_a_crowd_is_called_out_as_proxy_arp() {
        // The shape seen on a real Windows scan: 40 replies, all one hardware
        // address. That is a router answering for a range, not 40 hosts, and
        // reporting it as such is the failure that matters.
        let plan = plan_for("10.0.0.0/24");
        let mut stats = ScanStats::default();
        let replies: Vec<Reply> = (1..=40u8)
            .map(|i| arp_reply(Ipv4Addr::new(10, 0, 0, i), "aa:bb:cc:dd:ee:ff"))
            .collect();

        warn_if_one_mac_answers_everything(&plan, &mut stats, &replies);
        assert!(
            stats.notes.iter().any(|n| n.contains("proxy-arp")),
            "expected a proxy-arp warning, got {:?}",
            stats.notes
        );
    }

    #[test]
    fn a_normal_network_of_distinct_macs_is_not_warned_about() {
        let plan = plan_for("10.0.0.0/24");
        let mut stats = ScanStats::default();
        let replies: Vec<Reply> = (1..=20u8)
            .map(|i| {
                arp_reply(
                    Ipv4Addr::new(10, 0, 0, i),
                    &format!("aa:bb:cc:dd:ee:{:02x}", i),
                )
            })
            .collect();

        warn_if_one_mac_answers_everything(&plan, &mut stats, &replies);
        assert!(
            stats.notes.is_empty(),
            "distinct hardware addresses are ordinary, got {:?}",
            stats.notes
        );
    }

    #[test]
    fn a_few_addresses_sharing_a_mac_is_not_an_anomaly() {
        // Three addresses behind one bridge is normal; only a majority counts.
        let plan = plan_for("10.0.0.0/24");
        let mut stats = ScanStats::default();
        let mut replies: Vec<Reply> = (1..=3u8)
            .map(|i| arp_reply(Ipv4Addr::new(10, 0, 0, i), "aa:bb:cc:dd:ee:01"))
            .collect();
        for i in 4..=20u8 {
            replies.push(arp_reply(
                Ipv4Addr::new(10, 0, 0, i),
                &format!("aa:bb:cc:dd:ee:{:02x}", i),
            ));
        }

        warn_if_one_mac_answers_everything(&plan, &mut stats, &replies);
        assert!(
            stats.notes.is_empty(),
            "a minority share is not proxy-arp, got {:?}",
            stats.notes
        );
    }
}
