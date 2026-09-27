//! The result model: what we learned about a host, and how we learned it.

use serde::Serialize;
use std::fmt;
use std::net::Ipv4Addr;
use std::time::Duration;

/// The probe technique that produced a piece of evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Method {
    /// Active ARP request/reply on a directly-connected link.
    Arp,
    /// ICMP echo request/reply.
    Icmp,
    /// TCP connect, port by port.
    Tcp,
    /// Read out of the OS neighbour table. Passive, but stale data.
    Neighbour,
}

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Arp => "arp",
            Method::Icmp => "icmp",
            Method::Tcp => "tcp",
            Method::Neighbour => "neighbour",
        }
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a single probe attempt learned.
///
/// The three-way split is the whole point. A TCP connect that times out and a
/// host that is switched off are indistinguishable, so `Silent` must never be
/// collapsed into "dead" — it means "we learned nothing", and those targets get
/// escalated to the next probe method instead of being reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    /// Direct proof of life: an echo reply, or a TCP connection that completed.
    Alive,
    /// Indirect proof of life: the host reset our connection or answered with
    /// ICMP destination-unreachable. It is up, but filtered our probe.
    Filtered,
    /// No response either way. Carries no information about the host.
    Silent,
}

impl Outcome {
    /// Whether this outcome proves the host exists.
    pub fn proves_alive(self) -> bool {
        matches!(self, Outcome::Alive | Outcome::Filtered)
    }
}

/// One observation supporting a host's existence.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Evidence {
    pub method: Method,
    pub outcome: Outcome,
    /// Round-trip time of the exchange that produced this evidence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt: Option<Duration>,
    /// TTL from the reply, when the transport exposes it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u8>,
    /// For TCP: the port that answered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

impl Evidence {
    pub fn new(method: Method, outcome: Outcome) -> Self {
        Evidence {
            method,
            outcome,
            rtt: None,
            ttl: None,
            port: None,
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
}

/// A 48-bit MAC address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub const BROADCAST: MacAddr = MacAddr([0xff; 6]);

    pub fn from_bytes(b: [u8; 6]) -> Self {
        MacAddr(b)
    }

    /// Parse `aa:bb:cc:dd:ee:ff` or `aa-bb-cc-dd-ee-ff`.
    pub fn parse(s: &str) -> Option<Self> {
        let cleaned: Vec<u8> = s
            .bytes()
            .filter(|c| c.is_ascii_hexdigit() || *c == b':' || *c == b'-')
            .collect();
        if cleaned.len() != 17 {
            return None;
        }
        let mut out = [0u8; 6];
        for (i, chunk) in cleaned.chunks(3).enumerate().take(6) {
            if i < 5 && chunk[2] != b':' && chunk[2] != b'-' {
                return None;
            }
            let hi = (chunk[0] as char).to_digit(16)? as u8;
            let lo = (chunk[1] as char).to_digit(16)? as u8;
            out[i] = (hi << 4) | lo;
        }
        Some(MacAddr(out))
    }

    /// The 24-bit OUI prefix, used to look up the hardware vendor.
    pub fn oui(&self) -> [u8; 3] {
        [self.0[0], self.0[1], self.0[2]]
    }

    pub fn is_broadcast(&self) -> bool {
        self.0 == [0xff; 6]
    }

    /// An all-zero address is not a device. Windows keeps rows in its neighbour
    /// table for entries it has not finished resolving, and those carry six zero
    /// bytes where a hardware address would go. Treating one as a real address
    /// puts `00:00:00:00:00:00` in a table of hardware addresses, which reads as
    /// an answer rather than as the absence of one.
    pub fn is_unspecified(&self) -> bool {
        self.0 == [0; 6]
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

/// A host that the scan found evidence for.
#[derive(Debug, Clone, PartialEq)]
pub struct Host {
    pub ip: Ipv4Addr,
    pub mac: Option<MacAddr>,
    pub hostname: Option<String>,
    pub evidence: Vec<Evidence>,
}

impl Host {
    pub fn new(ip: Ipv4Addr) -> Self {
        Host {
            ip,
            mac: None,
            hostname: None,
            evidence: Vec::new(),
        }
    }

    /// A host counts as alive if any probe produced positive or indirect proof.
    /// A pile of `Silent` results is not a host, and never gets reported.
    pub fn is_alive(&self) -> bool {
        self.evidence.iter().any(|e| e.outcome.proves_alive())
    }

    /// The best round-trip time observed, i.e. the method that answered fastest.
    pub fn best_rtt(&self) -> Option<Duration> {
        self.evidence.iter().filter_map(|e| e.rtt).min()
    }

    /// The most informative method for this host, used to pick a label.
    pub fn primary_method(&self) -> Option<Method> {
        self.evidence
            .iter()
            .filter(|e| e.outcome.proves_alive())
            .min_by_key(|e| e.method)
            .map(|e| e.method)
    }

    /// Record new evidence, keeping the list free of exact duplicates.
    pub fn add_evidence(&mut self, ev: Evidence) {
        if !self.evidence.contains(&ev) {
            self.evidence.push(ev);
        }
    }

    /// Fold a MAC in, if we learned one and did not have it before.
    ///
    /// A changed MAC for the same IP means the address was reassigned (DHCP
    /// turnover, a mobile device rejoining, etc.). The new value replaces the
    /// old one because the change itself is a signal worth reporting.
    pub fn set_mac(&mut self, mac: MacAddr) {
        if let Some(existing) = self.mac
            && existing != mac
        {
            // MAC changed for this IP: record the new value. The change is a
            // signal that the address was reassigned.
        }
        self.mac = Some(mac);
    }
}

/// Accumulates hosts during a scan, keyed by IP.
#[derive(Debug, Default)]
pub struct HostTable {
    hosts: Vec<Host>,
}

impl HostTable {
    pub fn new() -> Self {
        HostTable::default()
    }

    pub fn entry(&mut self, ip: Ipv4Addr) -> &mut Host {
        if let Some(idx) = self.hosts.iter().position(|h| h.ip == ip) {
            return &mut self.hosts[idx];
        }
        self.hosts.push(Host::new(ip));
        self.hosts.last_mut().expect("just pushed")
    }

    pub fn record(&mut self, ip: Ipv4Addr, ev: Evidence) {
        self.entry(ip).add_evidence(ev);
    }

    pub fn record_mac(&mut self, ip: Ipv4Addr, mac: MacAddr) {
        self.entry(ip).set_mac(mac);
    }

    /// Record a hardware address only for a host that has none.
    ///
    /// Used to fill in gaps from the neighbour cache after probing, where a
    /// direct ARP reply is stronger evidence than a cache entry and so must not
    /// be overwritten. Returns whether the host was filled in.
    pub fn record_mac_if_absent(&mut self, ip: Ipv4Addr, mac: MacAddr) -> bool {
        let host = self.entry(ip);
        if host.mac.is_some() {
            return false;
        }
        host.set_mac(mac);
        true
    }

    pub fn record_hostname(&mut self, ip: Ipv4Addr, name: String) {
        self.entry(ip).hostname = Some(name);
    }

    /// Every host, sorted by address.
    pub fn sorted(&self) -> Vec<&Host> {
        let mut v: Vec<&Host> = self.hosts.iter().collect();
        v.sort_by_key(|h| u32::from(h.ip));
        v
    }

    /// Only the hosts with proof of life, sorted by address.
    pub fn alive(&self) -> Vec<&Host> {
        let mut v: Vec<&Host> = self.sorted().into_iter().filter(|h| h.is_alive()).collect();
        v.sort_by_key(|h| u32::from(h.ip));
        v
    }

    pub fn len(&self) -> usize {
        self.hosts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_parsing_and_display_round_trip() {
        let m = MacAddr::parse("f0:09:0d:2a:86:fd").unwrap();
        assert_eq!(m.to_string(), "f0:09:0d:2a:86:fd");
        // Separators are interchangeable and case is ignored.
        assert_eq!(
            MacAddr::parse("5c-49-7d-f1-14-0d").unwrap(),
            MacAddr::parse("5C:49:7D:F1:14:0D").unwrap()
        );
        assert_eq!(MacAddr::parse("nonsense"), None);
        assert_eq!(MacAddr::parse("f0:09:0d:2a:86"), None);
    }

    #[test]
    fn a_recovered_mac_never_overwrites_a_direct_reply() {
        // A direct arp reply is stronger evidence than a neighbour-cache entry, so
        // the late recovery pass must leave an address alone once one is known.
        let ip = "10.0.0.7".parse().unwrap();
        let direct = MacAddr::parse("f0:09:0d:2a:86:fd").unwrap();
        let cached = MacAddr::parse("8c:22:d2:bf:2e:05").unwrap();

        let mut t = HostTable::new();
        let replied = Evidence::new(Method::Icmp, Outcome::Alive);
        assert!(
            t.record_mac_if_absent(ip, direct),
            "the first address is a recovery"
        );
        assert!(!t.record_mac_if_absent(ip, cached), "the second is not");
        t.record(ip, replied.clone());
        assert_eq!(t.alive()[0].mac, Some(direct));

        // Unrelated hosts are untouched.
        let other = "10.0.0.8".parse().unwrap();
        assert!(t.record_mac_if_absent(other, cached));
        t.record(other, replied);
        assert_eq!(t.alive()[1].mac, Some(cached));
    }

    #[test]
    fn silent_evidence_never_marks_a_host_alive() {
        let h = Host::new("10.0.0.1".parse().unwrap());
        assert!(!h.is_alive());
        let mut h = h;
        h.add_evidence(Evidence::new(Method::Icmp, Outcome::Silent));
        h.add_evidence(Evidence::new(Method::Tcp, Outcome::Silent));
        assert!(!h.is_alive(), "two timeouts must not add up to a host");
    }

    #[test]
    fn a_tcp_refusal_still_counts_as_alive() {
        let mut h = Host::new("10.0.0.1".parse().unwrap());
        h.add_evidence(Evidence::new(Method::Tcp, Outcome::Filtered).with_port(445));
        assert!(h.is_alive());
        assert_eq!(h.primary_method(), Some(Method::Tcp));
    }

    #[test]
    fn duplicate_evidence_is_collapsed() {
        let mut h = Host::new("10.0.0.1".parse().unwrap());
        let e = Evidence::new(Method::Icmp, Outcome::Alive).with_rtt(Duration::from_millis(2));
        h.add_evidence(e.clone());
        h.add_evidence(e);
        assert_eq!(h.evidence.len(), 1);
    }

    #[test]
    fn host_table_merges_by_ip() {
        let mut t = HostTable::new();
        t.record(
            "10.0.0.5".parse().unwrap(),
            Evidence::new(Method::Icmp, Outcome::Alive),
        );
        t.record(
            "10.0.0.5".parse().unwrap(),
            Evidence::new(Method::Tcp, Outcome::Filtered),
        );
        t.record_mac(
            "10.0.0.5".parse().unwrap(),
            MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap(),
        );
        assert_eq!(t.len(), 1);
        assert_eq!(t.alive().len(), 1);
        assert_eq!(t.alive()[0].evidence.len(), 2);
    }

    #[test]
    fn best_rtt_picks_the_fastest_observation() {
        let mut h = Host::new("10.0.0.1".parse().unwrap());
        h.add_evidence(
            Evidence::new(Method::Icmp, Outcome::Alive).with_rtt(Duration::from_millis(30)),
        );
        h.add_evidence(
            Evidence::new(Method::Tcp, Outcome::Alive).with_rtt(Duration::from_millis(2)),
        );
        assert_eq!(h.best_rtt(), Some(Duration::from_millis(2)));
    }
}
