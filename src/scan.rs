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
    /// The user named ports with `-p`, rather than taking the default list.
    ///
    /// This changes what the TCP phase is for. Left to itself the cascade only
    /// spends a connect on addresses nothing else answered for, which is the
    /// right way to find out who is there. But someone who names ports is
    /// asking which ports are open, and skipping the check because a host
    /// already answered ARP is answering a question they did not ask.
    pub ports_explicit: bool,
    /// List addresses that answered but which nothing could be attributed to.
    ///
    /// Off by default, because a host that answered ICMP on a directly-attached
    /// link without ARP having named it is a contradiction rather than a finding.
    /// Listing it alongside real hosts turns "who is here" into a number that
    /// cannot be believed. They are counted in the summary either way, so
    /// nothing is hidden -- it is only kept out of the list by default.
    pub include_unverified: bool,
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
    /// Answers withheld from the default listing because nothing attributed them
    /// to a device. Counted rather than discarded, so the summary can say so.
    pub unverified_omitted: usize,
    /// Hosts reported on a resolved neighbour-table entry with no probe reply.
    /// Counted separately because they are the weakest thing in the list.
    pub cache_only_hosts: usize,
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
    // Addresses the table already names. The active sweep skips them: the MAC is
    // the thing it would learn, the table has it, and asking again costs a
    // `SendARP` timeout per address for an answer we hold. Liveness is not lost
    // by skipping -- the ICMP and TCP phases confirm it -- and the hardware
    // address is recorded into the table below either way.
    //
    // The one thing this does cost is the ability to say the sweep *saw* the
    // host. An address is in the table because something already resolved it,
    // which is the same evidence the sweep would gather, so a cached hit cannot
    // distinguish a live host from a stale one. The counts are reported
    // separately for that reason: "1 alive of 121" on its own reads as a broken
    // sweep rather than as 121 targets deliberately left alone.
    let cached_mac: HashSet<Ipv4Addr> = cached
        .iter()
        .filter(|n| !n.mac.is_unspecified() && !n.mac.is_broadcast())
        .map(|n| n.ip)
        .collect();

    // Record the initial cache MACs into the table. A direct ARP reply (which
    // comes later) will overwrite via `record_mac`, but if no reply arrives
    // the cache MAC remains as attribution. This is the primary MAC source on
    // platforms where the active sweep cannot run or is skipped.
    for n in &cached {
        if !n.mac.is_unspecified() && !n.mac.is_broadcast() {
            table.record_mac(n.ip, n.mac);
        }
    }

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
        run_arp(
            plan,
            &all,
            &mut table,
            &mut stats,
            &mut settled,
            &cached_mac,
        );
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
    // The residue by default: addresses nothing has answered for, which is the
    // whole point of escalating. Spending a connect on an already-confirmed host
    // wastes both time and a few packets on the target.
    //
    // Naming ports with `-p` is a different request. The cascade is a way of
    // answering "who is here", but a named port is a question about that port,
    // and the fact that ARP already found the host is not an answer to it. So
    // with explicit ports the live set is probed too, and only the addresses
    // already known to be dead are skipped.
    if matches!(plan.method, MethodChoice::Tcp | MethodChoice::Auto) {
        let live: HashSet<Ipv4Addr> = table.alive().iter().map(|h| h.ip).collect();
        let (targets_for_tcp, known_live) = tcp_targets(plan.ports_explicit, &all, &settled, &live);
        if !targets_for_tcp.is_empty() {
            stats.escalated_to_tcp = targets_for_tcp.len();
            if plan.progress {
                if known_live > 0 {
                    eprintln!(
                        "probing {} live host{} on the named ports, plus \
                         {} that nothing answered for...",
                        known_live,
                        if known_live == 1 { "" } else { "s" },
                        targets_for_tcp.len() - known_live,
                    );
                } else {
                    eprintln!(
                        "icmp gave no answer for {} addresses, trying tcp...",
                        targets_for_tcp.len()
                    );
                }
            }
            let before = settled.len();
            let attempts = targets_for_tcp.len() * plan.config.ports.len();
            let ticker = Ticker::start("tcp");
            let phase_started = Instant::now();
            let mut prober = TcpProber::new(&plan.config);
            stats.tcp_connections += attempts as u64;
            for reply in prober.probe_round(&targets_for_tcp)? {
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

    // The targets for which a hardware address is meaningful, and so the only
    // ones whose liveness has to be explained by something other than a later
    // probe. Off-link and loopback are exempt: no ARP exchange could ever name
    // them, and with the phase deliberately skipped the cache is the only source
    // available.
    let arp_could_run = matches!(plan.method, MethodChoice::Arp | MethodChoice::Auto);
    let eligible = if arp_could_run {
        arp_eligible(plan, &all)
    } else {
        HashSet::new()
    };

    // ------------------------------------------------ late attribution ----
    // Reading the neighbour table again once the probes are done is not
    // redundant. Sending an echo to a host on our own link requires having
    // resolved it first, so every host that answered at all has a hardware
    // address in the table by now -- including the ones the concurrent sweep lost
    // a reply for, which is easy to do when a few hundred requests saturate the
    // reply path. On a real Windows scan this recovered a host the sweep had
    // missed but the OS had, the difference between a census of 115 and of 116.
    //
    // On a platform where the sweep cannot run at all it matters even more: the
    // passive table is then the *only* source of hardware addresses, and without
    // this pass a scan on Linux reports live hosts with no device behind them and
    // no way to say which one.
    //
    // A direct reply still wins. `record_mac_if_absent` refuses to overwrite an
    // address the sweep already named, because a reply we asked for is better
    // evidence than an entry we merely read, and it only counts hosts that
    // actually gained something, so the number reported is the number of hosts
    // rescued rather than the size of the table.
    //
    // We restrict to `eligible` (on-link, non-loopback) because off-link and
    // loopback addresses never require an ARP exchange -- answering an echo to
    // 127.0.0.1 never touches a wire, so the neighbour table has no business
    // naming it. Attributing a MAC there would be a phantom device.
    let mut resolved_from_cache = 0usize;
    match neighbour::read_table() {
        Ok(entries) => {
            for n in &entries {
                // An all-zero address is an entry the OS never finished
                // resolving, not a device, so it cannot attribute anything.
                if eligible.contains(&n.ip)
                    && !n.mac.is_unspecified()
                    && table.record_mac_if_absent(n.ip, n.mac)
                {
                    resolved_from_cache += 1;
                }
            }
            // Addresses the table knows that no probe confirmed.
            //
            // A resolved entry is a completed protocol exchange, not a guess: the
            // kernel got a hardware address back for that address, so something
            // was there. That is weaker than a reply we watched arrive, because
            // it may predate the scan, and it is reported as `neighbour` so the
            // two are never confused. But it is frequently the only evidence
            // available at all: where the ICMP API does not work, a differential
            // test against `ping` found the probes reached 20 of 113 live
            // addresses while the neighbour table accounted for all 113.
            //
            // Restricted to the addresses actually being scanned. The table
            // covers every interface on the host, so without this a scan of
            // 192.168.51.0/24 reported 172.24.101.200, which lives on a
            // different network entirely.
            if plan.include_cached {
                let mut cache_only = 0usize;
                let alive_ips: HashSet<Ipv4Addr> = table.alive().iter().map(|h| h.ip).collect();
                for n in &entries {
                    if !alive_ips.contains(&n.ip)
                        && plan.targets.contains(n.ip)
                        && !n.mac.is_unspecified()
                        && !n.mac.is_broadcast()
                    {
                        table.record(
                            n.ip,
                            crate::host::Evidence::new(Method::Neighbour, Outcome::Alive),
                        );
                        cache_only += 1;
                    }
                }
                if cache_only > 0 {
                    stats.cache_only_hosts = cache_only;
                    stats.note(format!(
                        "{cache_only} host{} reported from the neighbour table alone, \
                         with no probe reply to confirm them; they may have gone \
                         away since the address was last resolved",
                        if cache_only == 1 { "" } else { "s" }
                    ));
                }
            }
        }
        Err(e) => stats.note(format!(
            "neighbour table re-read after probing failed: {e:#}"
        )),
    }
    if resolved_from_cache > 0 && plan.progress {
        eprintln!(
            "  attributed {resolved_from_cache} host{} from the neighbour table",
            if resolved_from_cache == 1 { "" } else { "s" }
        );
    }
    if resolved_from_cache > 0 {
        stats.note(format!(
            "attributed {resolved_from_cache} host{} from the neighbour table that the \
             arp sweep had not answered for",
            if resolved_from_cache == 1 { "" } else { "s" }
        ));
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

    // Addresses that answered a later phase without ARP naming them are kept out
    // of the default list, but only inside the set where ARP could have named
    // them. `eligible` is that set: on-link, non-loopback, and only when the ARP
    // phase was going to run. With `-m icmp` it is empty, so a sweep that worked
    // exactly as asked still reports everything it found.
    //
    // The ratio has to be a crowd as well. A handful of addresses that dropped an
    // ARP reply is ordinary, and hiding a real machine because of a heuristic is
    // worse than listing it with a dash.
    let mut hosts = table.alive().into_iter().cloned().collect::<Vec<Host>>();
    hosts.sort_by_key(|h| u32::from(h.ip));
    let (attributed, unattributed) = split_by_attribution(&hosts, &eligible);

    warn_about_unattributable_hosts(plan, &mut stats, &hosts, &eligible);

    let drop_unverified = should_withhold(
        attributed.len(),
        unattributed.len(),
        plan.include_unverified,
    );
    if attributed.is_empty() && !unattributed.is_empty() {
        stats.note(format!(
            "no hardware address is known for any of the {} address{} that \
             answered, so none can be named; the arp phase did not get an answer \
             for this link and the results are listed without a MAC",
            unattributed.len(),
            if unattributed.len() == 1 { "" } else { "es" }
        ));
    }

    if drop_unverified {
        stats.unverified_omitted = unattributed.len();
        if plan.progress {
            eprintln!(
                "  note: --strict is hiding {} of the {} addresses that answered but \
                 have no known hardware address; drop --strict to list them",
                unattributed.len(),
                hosts.len()
            );
        }
    }
    let hosts = if drop_unverified {
        attributed.into_iter().cloned().collect::<Vec<Host>>()
    } else {
        hosts
    };

    if plan.progress {
        // Say what was withheld, so the shorter list is never mistaken for the
        // whole sweep.
        match stats.unverified_omitted {
            0 => eprintln!(
                "done: {} host{} in {}",
                hosts.len(),
                if hosts.len() == 1 { "" } else { "s" },
                human(started.elapsed())
            ),
            n => eprintln!(
                "done: {} host{} in {} ({} unattributed answer{} withheld)",
                hosts.len(),
                if hosts.len() == 1 { "" } else { "s" },
                human(started.elapsed()),
                n,
                if n == 1 { "" } else { "s" }
            ),
        }
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

/// Which addresses the TCP phase should spend a connect on, and how many live
/// hosts are already known dead enough to skip.
///
/// The cascade escalates to TCP for the addresses nothing answered for, which
/// is what makes it cheap: no connect is spent on a host ARP already found. That
/// is the right behaviour when the question is "who is here".
///
/// It is the wrong behaviour when the question is about a port, and a named port
/// is that question. `-p 80,443` followed by no port column at all, because
/// every address had already settled, is not an answer to "which ports are
/// open". So with explicit ports, the hosts already known to be alive are
/// included, and only the ones known to be dead are skipped. Nothing is spent on
/// an address that has been shown to be empty.
fn tcp_targets(
    ports_explicit: bool,
    all: &[Ipv4Addr],
    settled: &HashSet<Ipv4Addr>,
    live: &HashSet<Ipv4Addr>,
) -> (Vec<Ipv4Addr>, usize) {
    let residue: Vec<Ipv4Addr> = all
        .iter()
        .copied()
        .filter(|ip| !settled.contains(ip))
        .collect();
    if !ports_explicit {
        return (residue, 0);
    }
    let also_live: Vec<Ipv4Addr> = all
        .iter()
        .copied()
        .filter(|ip| settled.contains(ip) && live.contains(ip))
        .collect();
    let n = also_live.len();
    let mut targets = also_live;
    targets.extend(residue);
    (targets, n)
}

/// Whether a live host can be tied to a device.
///
/// The question is whether a hardware address is known for the address, not
/// whether the active sweep was the thing that learned it. Those come apart in
/// two directions, and getting it wrong in either is a lie the operator cannot
/// see:
///
/// - Where the sweep cannot run, the passive neighbour table is the only source
///   of hardware addresses. Demanding `Method::Arp` evidence there means a Linux
///   scan prints a column full of addresses and then warns that none of them can
///   be attributed to anything.
/// - Where the sweep ran and lost a reply, the address can still be resolved from
///   the table afterwards.
///
/// So this asks the same question the output column answers, and it rejects the
/// all-zero address here as well as where the table is read: "a hardware address
/// is known" should not be satisfiable by a row the OS never finished resolving,
/// however that row reached us.
fn is_attributable(host: &Host) -> bool {
    host.mac.is_some_and(|m| !m.is_unspecified())
}

/// The targets for which an ARP exchange is meaningful.
///
/// ARP resolves names on a broadcast domain, so it applies to a directly-attached
/// network and nowhere else. Loopback is excluded deliberately: a packet to
/// `127.0.0.0/8` is delivered locally and never reaches a wire, so expecting a
/// hardware address from it is expecting something the protocol cannot produce.
/// Without a known interface there is no way to tell what is on-link, and
/// guessing would produce false negatives, so that yields nothing rather than a
/// guess.
fn arp_eligible(plan: &ScanPlan, all: &[Ipv4Addr]) -> HashSet<Ipv4Addr> {
    let Some(iface) = plan.interface.as_ref() else {
        return HashSet::new();
    };
    all.iter()
        .copied()
        .filter(|ip| iface.contains(*ip) && !ip.is_loopback())
        .collect()
}

/// Split the live hosts into those the sweep can attribute to a device and those
/// it cannot.
///
/// A host counts as attributed when ARP named it, or when ARP could not have named
/// it: off-link, on loopback, or with the phase deliberately skipped. Only an
/// address inside `eligible` is held to the standard, because only there does
/// answering ICMP without a hardware address amount to a contradiction.
fn split_by_attribution<'a>(
    hosts: &'a [Host],
    eligible: &HashSet<Ipv4Addr>,
) -> (Vec<&'a Host>, Vec<&'a Host>) {
    let mut attributed = Vec::new();
    let mut unattributed = Vec::new();
    for h in hosts {
        if !eligible.contains(&h.ip) || is_attributable(h) {
            attributed.push(h);
        } else {
            unattributed.push(h);
        }
    }
    (attributed, unattributed)
}

/// Hosts that answered a later phase but which ARP never named are not evidence
/// of a host, and on a directly-attached link the combination is contradictory
/// rather than merely thin.
///
/// Sending the echo requires resolving the target's hardware address first. So a
/// host that answers ICMP on our own subnet has necessarily been resolved, and
/// either the ARP phase should have named it or the reply did not come from the
/// address we asked. Devices that answer echo on behalf of a range they merely
/// route do exist, and they forge the source address correctly enough to pass a
/// reply-source check, so this cannot be settled by looking harder at the reply.
///
/// The tell that settles it is the round-trip time. Real hosts on one link
/// answer in well under a millisecond and scatter; a single responder has one
/// periodic cycle, so its answers land in a handful of buckets. Reporting these
/// separately from the named hosts is the honest outcome: they may be there, but
/// nothing in the sweep has shown that they are.
fn warn_about_unattributable_hosts(
    plan: &ScanPlan,
    stats: &mut ScanStats,
    hosts: &[Host],
    eligible: &HashSet<Ipv4Addr>,
) {
    if hosts.is_empty() {
        return;
    }
    let (attributed, ghosts) = split_by_attribution(hosts, eligible);
    // One or two could be a busy host that dropped an ARP reply. A large share of
    // the sweep is a different thing entirely, so only speak up at that scale.
    if ghosts.len() * 2 < hosts.len() {
        return;
    }
    let named = attributed.len();

    // Round-trip times are corroboration, and they only corroborate one story if
    // they actually have the shape of that story. A device replying on a fixed
    // schedule produces times that bunch; real machines at different distances
    // produce times that spread. Reporting a wide spread as the signature of a
    // single responder would be reading a number backwards, and the spread is
    // the number a reader is most likely to check against the table below.
    let mut rtts: Vec<u128> = ghosts
        .iter()
        .filter_map(|h| h.evidence.iter().find_map(|e| e.rtt))
        .map(|d| d.as_millis())
        .collect();
    rtts.sort_unstable();
    let timing = match (rtts.first().copied(), rtts.len()) {
        (None, _) => "No round-trip time was recorded for them".to_string(),
        (Some(lo), 1) => format!("The only round-trip time recorded was {lo:.1}ms"),
        (Some(lo), _) => {
            let hi = rtts[rtts.len() - 1];
            let text = format!("Their round-trip times span {lo:.1}ms to {hi:.1}ms");
            // Times within a factor of two of each other are a cluster; wider
            // than that is ordinary variation between machines.
            if hi <= lo.saturating_mul(2) {
                format!("{text}, which is what one device replying on a schedule looks like")
            } else {
                format!(
                    "{text}, which is the spread real machines at different distances \
                     produce rather than the bunching of a single responder"
                )
            }
        }
    };
    let msg = format!(
        "{} of the {} live host{} cannot be attributed to a device: no hardware \
         address is known for them, so nothing here can say which device they \
         are. On a directly-attached link that combination is contradictory, \
         because answering icmp requires having resolved the target's hardware \
         address first. Something is answering echo on behalf of {} addresses \
         it does not own, or the sweep lost {} replies. {}. Only the {} host{} \
         that were attributed should be counted as a host census; treat the rest \
         as unverified.",
        ghosts.len(),
        hosts.len(),
        if hosts.len() == 1 { "" } else { "s" },
        ghosts.len(),
        ghosts.len(),
        timing,
        named,
        if named == 1 { "" } else { "s" },
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
/// Whether the unattributable answers should be withheld from the default list.
///
/// The `attributed == 0` guard is the one that matters most, and it exists because
/// of how this went wrong the first time. On a virtual interface where the ARP
/// phase cannot work, every answer is unattributable, and the rule taken naively
/// deleted every host the sweep had found and reported an empty network. A phase
/// that named nothing has failed; it has not proved the segment is empty, and the
/// two must not be confused.
fn should_withhold(attributed: usize, unattributed: usize, include_unverified: bool) -> bool {
    !include_unverified
        && unattributed > 0
        && attributed > 0
        && unattributed * 2 > attributed + unattributed
}

/// Returns whether the ARP phase actually executed (prober available and ran).
fn run_arp(
    plan: &ScanPlan,
    all: &[Ipv4Addr],
    table: &mut HostTable,
    stats: &mut ScanStats,
    settled: &mut HashSet<Ipv4Addr>,
    cached_mac: &HashSet<Ipv4Addr>,
) -> bool {
    let eligible = arp_eligible(plan, all);
    if eligible.is_empty() {
        if plan.interface.is_none() {
            stats.note("active arp skipped: no interface selected, so on-link targets are unknown");
        }
        return false;
    }
    // Skip targets that already have a valid MAC in the neighbour cache.
    // This avoids redundant SendARP calls whose internal timeout dominates
    // the scan time on Windows.
    let on_link: Vec<Ipv4Addr> = all
        .iter()
        .copied()
        .filter(|ip| eligible.contains(ip) && !cached_mac.contains(ip))
        .collect();
    let off_link = all.len() - eligible.len();
    if off_link > 0 {
        stats.arp_unreachable = off_link;
    }
    if on_link.is_empty() {
        return false;
    }

    let availability = ArpProber::availability();
    if !availability.available {
        stats.note(format!("active arp unavailable: {}", availability.reason));
        return false;
    }

    match ArpProber::new(&plan.config) {
        Ok(mut prober) => {
            stats.arp_requests += on_link.len() as u64;
            // Reported once, and the count of deliberately-skipped targets is
            // part of the same line: "1 alive of 120" beside a cache of 134
            // otherwise reads as a broken sweep rather than as 120 probes chosen
            // because the table already answered for the rest.
            let skipped = cached_mac.iter().filter(|ip| eligible.contains(ip)).count();
            if plan.progress {
                if skipped > 0 {
                    eprintln!(
                        "probing {} on-link addresses with arp ({} already named by the \
                         neighbour table)...",
                        on_link.len(),
                        skipped
                    );
                } else {
                    eprintln!("probing {} on-link addresses with arp...", on_link.len());
                }
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
                if skipped > 0 {
                    eprintln!(
                        "  arp: {alive} alive of {} probed in {} ({skipped} more were \
                         already named by the neighbour table)",
                        on_link.len(),
                        human(phase_started.elapsed())
                    );
                } else {
                    eprintln!(
                        "  arp: {alive} alive of {} in {}",
                        on_link.len(),
                        human(phase_started.elapsed())
                    );
                }
            }
            true
        }
        Err(e) => {
            stats.note(format!("active arp unavailable: {e:#}"));
            false
        }
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

impl Drop for Ticker {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{Evidence, MacAddr};

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
            ports_explicit: false,
            include_unverified: false,
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

    /// Treat every host in the fixture as arp-eligible: these tests are about how
    /// a verdict is drawn, not about which addresses are on-link.
    fn all_eligible(hosts: &[Host]) -> HashSet<Ipv4Addr> {
        hosts.iter().map(|h| h.ip).collect()
    }

    /// A host table shaped like the real v0.1.3 scan: arp named a minority,
    /// and the rest are icmp answers with no hardware address.
    fn split_hosts(named: u8, ghosts: u8, rtt_ms: u64) -> Vec<Host> {
        let mut hosts = Vec::new();
        for i in 0..named {
            let mut h = Host::new(Ipv4Addr::new(10, 0, 0, i + 1));
            h.mac = Some(MacAddr([i, 1, 2, 3, 4, 5]));
            h.evidence.push(Evidence {
                method: Method::Arp,
                outcome: Outcome::Alive,
                rtt: None,
                ttl: None,
                port: None,
            });
            hosts.push(h);
        }
        for i in 0..ghosts {
            let mut h = Host::new(Ipv4Addr::new(10, 0, 0, 100 + i));
            h.evidence.push(Evidence {
                method: Method::Icmp,
                outcome: Outcome::Alive,
                rtt: Some(Duration::from_millis(rtt_ms)),
                ttl: None,
                port: None,
            });
            hosts.push(h);
        }
        hosts
    }

    /// The neighbour table covers every interface on the host, so using it as
    /// evidence of life has to be restricted to the addresses being scanned.
    ///
    /// Unrestricted, a scan of 192.168.51.0/24 reported 172.24.101.200, which is
    /// on a different network: a real address belonging to another interface,
    /// presented as though it were part of the sweep.
    #[test]
    fn only_addresses_inside_the_target_set_may_come_from_the_cache() {
        let targets = TargetSet::parse(["192.168.51.0/24"]).unwrap();
        let wanted = Ipv4Addr::new(192, 168, 51, 99);
        let elsewhere = Ipv4Addr::new(172, 24, 101, 200);

        let in_scope = targets.contains(wanted);
        let out_of_scope = targets.contains(elsewhere);
        assert!(in_scope, "a target address is in the set");
        assert!(
            !out_of_scope,
            "an address on another interface must not be: {elsewhere}"
        );
    }

    #[test]
    fn a_crowd_of_unattributable_hosts_is_called_out() {
        // The shape of a real scan: 118 hosts arp named, 136 that only icmp
        // claimed. Reporting 254 live hosts is the failure that matters, because
        // the 136 cannot be attributed to any device.
        let plan = plan_for("10.0.0.0/24");
        let mut stats = ScanStats::default();
        let hosts = split_hosts(118, 136, 760);

        warn_about_unattributable_hosts(&plan, &mut stats, &hosts, &all_eligible(&hosts));
        let note = stats
            .notes
            .iter()
            .find(|n| n.contains("cannot be attributed"))
            .unwrap_or_else(|| panic!("expected a warning, got {:?}", stats.notes));
        assert!(note.contains("136"), "should count the ghosts: {note}");
        assert!(
            note.contains("118"),
            "should say how many were named: {note}"
        );
        assert!(
            note.contains("760ms to 760ms"),
            "should report the round-trip spread: {note}"
        );
    }

    #[test]
    fn a_few_unnamed_hosts_do_not_raise_a_crowd_warning() {
        // Two hosts that dropped an ARP reply is ordinary. It is not evidence of
        // a responder, and warning about it would train people to ignore the
        // warning that does matter.
        let plan = plan_for("10.0.0.0/24");
        let mut stats = ScanStats::default();
        let hosts = split_hosts(40, 2, 1);

        warn_about_unattributable_hosts(&plan, &mut stats, &hosts, &all_eligible(&hosts));
        assert!(
            stats.notes.is_empty(),
            "expected silence for 2 of 42, got {:?}",
            stats.notes
        );
    }

    #[test]
    fn a_fully_named_sweep_is_silent() {
        let plan = plan_for("10.0.0.0/24");
        let mut stats = ScanStats::default();
        let hosts = split_hosts(254, 0, 0);

        warn_about_unattributable_hosts(&plan, &mut stats, &hosts, &all_eligible(&hosts));
        assert!(stats.notes.is_empty(), "got {:?}", stats.notes);
    }

    #[test]
    fn a_cached_zero_address_does_not_disguise_an_unattributed_host() {
        // Windows keeps rows for entries it has not finished resolving, and
        // those carry six zero bytes. If that counted as a hardware address, the
        // hosts it describes would look named and the warning would stay quiet
        // on exactly the sweep that needs it.
        let plan = plan_for("10.0.0.0/24");
        let mut stats = ScanStats::default();
        let mut hosts = split_hosts(4, 6, 991);
        for h in hosts.iter_mut().skip(4) {
            h.mac = Some(MacAddr([0; 6]));
        }

        warn_about_unattributable_hosts(&plan, &mut stats, &hosts, &all_eligible(&hosts));
        assert!(
            stats
                .notes
                .iter()
                .any(|n| n.contains("cannot be attributed")),
            "a zero hardware address must not count as a name, got {:?}",
            stats.notes
        );
    }

    #[test]
    fn a_host_attributed_by_the_neighbour_table_is_not_a_ghost() {
        // Regression. Attribution used to require `Method::Arp` evidence, which is
        // wrong wherever the passive table is the source: on Linux without
        // CAP_NET_RAW the sweep cannot run, so a scan printed a column full of
        // hardware addresses and then warned that none of the hosts could be
        // attributed to a device, ending with "Only the 0 hosts arp named".
        //
        // The table is the only source there, and an address it knows is a
        // device, so a host with a hardware address and no arp evidence is
        // attributed.
        let mut hosts = split_hosts(0, 3, 40);
        for h in hosts.iter_mut() {
            h.mac = Some(MacAddr([9, 8, 7, 6, 5, 4]));
        }
        let eligible = all_eligible(&hosts);
        let (attributed, unattributed) = split_by_attribution(&hosts, &eligible);
        assert_eq!(attributed.len(), 3, "a known address is a device");
        assert!(unattributed.is_empty());

        // And the warning must stay quiet about it, rather than accusing a scan
        // whose table plainly shows the addresses.
        let plan = plan_for("10.0.0.0/24");
        let mut stats = ScanStats::default();
        warn_about_unattributable_hosts(&plan, &mut stats, &hosts, &eligible);
        assert!(
            !stats
                .notes
                .iter()
                .any(|n| n.contains("cannot be attributed")),
            "every host has a hardware address, so there is nothing to warn about: {:?}",
            stats.notes
        );
    }

    #[test]
    fn a_wide_round_trip_spread_is_not_reported_as_one_responder() {
        // The warning claimed a "signature of a single periodic responder" for
        // whatever spread it was handed. On a wireless network that is 2ms to
        // 367ms -- ordinary distance variation between real machines -- and the
        // sentence was reading the number backwards.
        let plan = plan_for("10.0.0.0/24");
        let mut stats = ScanStats::default();
        // One attributed host, and ghosts at a gateway's distance and a laptop's.
        let mut hosts = split_hosts(1, 3, 900);
        for (i, ms) in [2u64, 40, 367].iter().enumerate() {
            hosts[1 + i].evidence[0].rtt = Some(Duration::from_millis(*ms));
        }
        warn_about_unattributable_hosts(&plan, &mut stats, &hosts, &all_eligible(&hosts));
        let note = stats
            .notes
            .iter()
            .find(|n| n.contains("cannot be attributed"))
            .expect("three of four hosts is a crowd");
        assert!(
            note.contains("spread real machines at different distances"),
            "a wide spread must be reported as variation, not as one device: {note}"
        );

        // The clustered case keeps the accusation, because there it fits.
        let mut stats = ScanStats::default();
        let hosts = split_hosts(1, 3, 900);
        warn_about_unattributable_hosts(&plan, &mut stats, &hosts, &all_eligible(&hosts));
        let note = stats
            .notes
            .iter()
            .find(|n| n.contains("cannot be attributed"))
            .expect("three of four hosts is a crowd");
        assert!(
            note.contains("one device replying on a schedule"),
            "a tight cluster is still reported as one device: {note}"
        );
    }

    #[test]
    fn zero_and_broadcast_are_not_hardware_addresses() {
        assert!(MacAddr([0; 6]).is_unspecified());
        assert!(!MacAddr([0, 0, 0, 0, 0, 1]).is_unspecified());
        assert!(MacAddr::BROADCAST.is_broadcast());
        assert!(!MacAddr([0; 6]).is_broadcast());
    }

    #[test]
    fn a_target_arp_could_never_name_is_not_held_to_it() {
        // Loopback has no broadcast domain and no wire, so no hardware address can
        // exist for it. Demanding one is demanding the impossible, and it made
        // `ipscan 127.0.0.1` report nothing at all.
        let hosts = split_hosts(0, 1, 1);
        let eligible = arp_eligible(
            &plan_with_interface("lo", "127.0.0.0/8"),
            &[Ipv4Addr::LOCALHOST],
        );
        let (attributed, unattributed) = split_by_attribution(&hosts, &eligible);
        assert!(
            eligible.is_empty(),
            "loopback must not be arp-eligible, got {eligible:?}"
        );
        assert_eq!(attributed.len(), 1, "the host must still be reported");
        assert!(unattributed.is_empty());
    }

    #[test]
    fn an_off_link_target_is_not_held_to_arp_either() {
        let hosts = split_hosts(0, 4, 1);
        // 10.9.9.0/24 is a different network from the interface's 10.0.0.0/24.
        let eligible = arp_eligible(
            &plan_with_interface("eth0", "10.0.0.0/24"),
            &[Ipv4Addr::new(10, 9, 9, 1)],
        );
        assert!(eligible.is_empty());
        let (attributed, unattributed) = split_by_attribution(&hosts, &eligible);
        assert_eq!(attributed.len(), 4, "icmp alone is enough off-link");
        assert!(unattributed.is_empty());
    }

    #[test]
    fn an_on_link_target_is_held_to_arp() {
        let hosts = split_hosts(0, 4, 1);
        let eligible = arp_eligible(
            &plan_with_interface("eth0", "10.0.0.0/24"),
            &[Ipv4Addr::new(10, 0, 0, 100)],
        );
        assert_eq!(eligible.len(), 1, "on-link and not loopback is eligible");
        let (_, unattributed) = split_by_attribution(&hosts, &eligible);
        assert_eq!(unattributed.len(), 1, "the on-link one is unattributable");
    }

    fn parse_cidr_for_test(cidr: &str) -> (Ipv4Addr, u8) {
        let (addr, len) = cidr.split_once('/').expect("test cidr needs a prefix");
        (
            addr.parse().expect("test cidr address"),
            len.parse().expect("test cidr prefix"),
        )
    }

    /// A plan whose interface covers `cidr`, so on-link tests have something real
    /// to be on-link relative to.
    fn plan_with_interface(name: &str, cidr: &str) -> ScanPlan {
        let (addr, prefix) = parse_cidr_for_test(cidr);
        let mask = u32::MAX << (32 - prefix);
        let mut plan = plan_for("10.0.0.0/24");
        plan.interface = Some(Interface {
            name: name.to_string(),
            addr,
            netmask: Ipv4Addr::from(mask),
            prefix,
            broadcast: Some(Ipv4Addr::from(u32::from(addr) | !mask)),
            loopback: name == "lo",
        });
        plan
    }

    #[test]
    fn a_broken_arp_phase_never_empties_the_sweep() {
        // The real failure this rule caused: a virtual interface where arp cannot
        // work, so every answer is unattributable and the naive rule reported zero
        // hosts for a working scan. A phase that named nothing has failed, not
        // proved the segment empty.
        assert!(
            !should_withhold(0, 20, false),
            "an ineffective arp phase must not delete every host"
        );
    }

    #[test]
    fn a_real_crowd_of_unattributable_answers_is_withheld() {
        // The shape of the Windows scan: 118 named, 136 not.
        assert!(should_withhold(118, 136, false));
        assert!(
            !should_withhold(136, 118, false),
            "a minority is not a crowd"
        );
    }

    #[test]
    fn the_flag_always_wins() {
        assert!(!should_withhold(118, 136, true));
        assert!(!should_withhold(0, 20, true));
    }

    #[test]
    fn nothing_to_withhold_is_not_a_withholding() {
        assert!(!should_withhold(20, 0, false));
        assert!(!should_withhold(0, 0, false));
    }

    #[test]
    fn named_ports_reach_hosts_arp_already_found() {
        // The case that prompted this: `-p 80,443` and no port column, because
        // every address had already settled on an earlier phase.
        let all: Vec<Ipv4Addr> = (1..=6u8).map(|i| Ipv4Addr::new(10, 0, 0, i)).collect();
        let settled: HashSet<Ipv4Addr> = all[..4].iter().copied().collect();
        let live = settled.clone();

        let (targets, known_live) = tcp_targets(true, &all, &settled, &live);
        assert_eq!(targets.len(), 6, "every address gets its ports probed");
        assert_eq!(known_live, 4, "four were already alive");
        assert!(targets.contains(&Ipv4Addr::new(10, 0, 0, 5)));
    }

    #[test]
    fn default_ports_still_spend_nothing_on_confirmed_hosts() {
        // The cascade's whole value: no connect on a host arp already found.
        let all: Vec<Ipv4Addr> = (1..=6u8).map(|i| Ipv4Addr::new(10, 0, 0, i)).collect();
        let settled: HashSet<Ipv4Addr> = all[..4].iter().copied().collect();
        let live = settled.clone();

        let (targets, known_live) = tcp_targets(false, &all, &settled, &live);
        assert_eq!(targets.len(), 2, "only the residue");
        assert_eq!(known_live, 0);
        assert!(!targets.contains(&Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn named_ports_never_probe_an_address_shown_to_be_dead() {
        // Withdrawing from a settled address is what the cascade does when it has
        // no answer. Naming ports must not resurrect one.
        let all: Vec<Ipv4Addr> = (1..=3u8).map(|i| Ipv4Addr::new(10, 0, 0, i)).collect();
        let settled: HashSet<Ipv4Addr> = [Ipv4Addr::new(10, 0, 0, 1)].into_iter().collect();
        let live: HashSet<Ipv4Addr> = HashSet::new();

        let (targets, _) = tcp_targets(true, &all, &settled, &live);
        assert_eq!(targets.len(), 2);
        assert!(!targets.contains(&Ipv4Addr::new(10, 0, 0, 1)));
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
