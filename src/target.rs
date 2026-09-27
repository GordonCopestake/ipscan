//! Parsing and expansion of target specifications.
//!
//! Accepted forms, comma-separated within a single argument and repeatable
//! across arguments:
//!
//! | Form                    | Example                    |
//! |-------------------------|----------------------------|
//! | CIDR block              | `192.168.1.0/24`           |
//! | Explicit range          | `192.168.1.10-192.168.1.20`|
//! | Short range             | `192.168.1.10-20`          |
//! | Wildcard                | `192.168.1.*`              |
//! | Single address          | `192.168.1.1`              |

use std::net::Ipv4Addr;

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TargetError {
    #[error("not a valid IPv4 address: {0:?}")]
    BadAddress(String),

    #[error("{spec:?} is not a valid prefix length (expected 0-32)")]
    BadPrefix { spec: String },

    #[error(
        "{spec:?} is not a valid target. Try 192.168.1.0/24, 192.168.1.1-20, 192.168.1.* or 192.168.1.1"
    )]
    BadTarget { spec: String },

    #[error("range start {start} is above range end {end}")]
    InvertedRange { start: Ipv4Addr, end: Ipv4Addr },

    #[error(
        "mixed range {spec:?}: use either two full addresses (192.168.1.1-192.168.1.20) or a full address and a last octet (192.168.1.1-20)"
    )]
    MixedRange { spec: String },

    #[error("wildcard {spec:?} must be trailing (192.168.1.* or 192.168.*.*)")]
    NonTrailingWildcard { spec: String },

    #[error(
        "range would probe {count} addresses, over the limit of {limit}. Narrow the target or raise --max-hosts"
    )]
    TooManyHosts { count: u64, limit: u64 },
}

/// A set of IPv4 addresses, stored compactly as sorted, merged half-open ranges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetSet {
    /// Address ranges as inclusive `u32` bounds, sorted and non-overlapping.
    ranges: Vec<(u32, u32)>,
    /// The text the user typed, for reporting.
    spec: String,
}

impl TargetSet {
    /// Parse one or more target specifications, merging them into one set.
    pub fn parse<I, S>(specs: I) -> Result<Self, TargetError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut ranges: Vec<(u32, u32)> = Vec::new();
        let mut spec_parts: Vec<String> = Vec::new();

        for raw in specs {
            for piece in raw.as_ref().split(',') {
                let piece = piece.trim();
                if piece.is_empty() {
                    continue;
                }
                ranges.push(parse_one(piece)?);
                spec_parts.push(piece.to_string());
            }
        }

        if ranges.is_empty() {
            return Err(TargetError::BadTarget {
                spec: String::new(),
            });
        }

        Ok(TargetSet {
            ranges: merge(ranges),
            spec: spec_parts.join(","),
        })
    }

    /// Build a set covering an entire network block.
    pub fn from_network(addr: Ipv4Addr, prefix: u8) -> Result<Self, TargetError> {
        TargetSet::parse([format!("{addr}/{prefix}")])
    }

    pub fn spec(&self) -> &str {
        &self.spec
    }

    /// Total number of addresses in the set.
    pub fn len(&self) -> u64 {
        self.ranges
            .iter()
            .map(|(lo, hi)| u64::from(*hi) - u64::from(*lo) + 1)
            .sum()
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Whether the set contains a given address.
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let v = u32::from(ip);
        self.ranges.iter().any(|(lo, hi)| v >= *lo && v <= *hi)
    }

    /// Materialise the set, refusing to expand past `max` addresses.
    ///
    /// Expansion is what the scheduler actually walks, so the guard lives here:
    /// a fat-fingered `/8` should fail loudly rather than allocate 64 MB.
    pub fn expand(&self, max: u64) -> Result<Vec<Ipv4Addr>, TargetError> {
        let count = self.len();
        if count > max {
            return Err(TargetError::TooManyHosts { count, limit: max });
        }
        let mut out = Vec::with_capacity(count as usize);
        for (lo, hi) in &self.ranges {
            for v in *lo..=*hi {
                out.push(Ipv4Addr::from(v));
            }
        }
        Ok(out)
    }

    /// Iterate lazily, without the size guard. Used for streaming passes.
    pub fn iter(&self) -> TargetIter<'_> {
        TargetIter {
            ranges: &self.ranges,
            idx: 0,
            current: self.ranges.first().map(|(lo, _)| *lo),
        }
    }
}

/// Lazy iterator over a [`TargetSet`], so large blocks never need materialising.
pub struct TargetIter<'a> {
    ranges: &'a [(u32, u32)],
    idx: usize,
    current: Option<u32>,
}

impl Iterator for TargetIter<'_> {
    type Item = Ipv4Addr;

    fn next(&mut self) -> Option<Ipv4Addr> {
        loop {
            let v = self.current?;
            let (_, hi) = self.ranges[self.idx];
            if v > hi {
                self.idx += 1;
                self.current = self.ranges.get(self.idx).map(|(lo, _)| *lo);
                continue;
            }
            self.current = v.checked_add(1);
            return Some(Ipv4Addr::from(v));
        }
    }
}

impl std::iter::FusedIterator for TargetIter<'_> {}

/// Sort ranges and coalesce the ones that touch or overlap, so no address is
/// probed twice when a user passes overlapping targets.
fn merge(ranges: Vec<(u32, u32)>) -> Vec<(u32, u32)> {
    let mut sorted = ranges;
    sorted.sort_unstable();

    let mut out: Vec<(u32, u32)> = Vec::with_capacity(sorted.len());
    for (lo, hi) in sorted {
        match out.last_mut() {
            // `lo <= prev_hi + 1` covers both overlap and adjacency.
            Some(prev) if u64::from(lo) <= u64::from(prev.1) + 1 => {
                prev.1 = prev.1.max(hi);
            }
            _ => out.push((lo, hi)),
        }
    }
    out
}

fn parse_one(spec: &str) -> Result<(u32, u32), TargetError> {
    if spec.contains('/') {
        parse_cidr(spec)
    } else if spec.contains('*') {
        parse_wildcard(spec)
    } else if spec.contains('-') {
        parse_range(spec)
    } else {
        let ip = parse_ipv4(spec)?;
        let v = u32::from(ip);
        Ok((v, v))
    }
}

fn parse_cidr(spec: &str) -> Result<(u32, u32), TargetError> {
    let (addr_part, prefix_part) = spec.split_once('/').expect("caller checked for /");
    let addr = parse_ipv4(addr_part.trim())?;
    let prefix: u8 = prefix_part
        .trim()
        .parse()
        .map_err(|_| TargetError::BadPrefix {
            spec: spec.to_string(),
        })?;
    if prefix > 32 {
        return Err(TargetError::BadPrefix {
            spec: spec.to_string(),
        });
    }
    // A /32 mask of u32::MAX would overflow the shift, so guard the shift.
    let mask: u32 = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let lo = u32::from(addr) & mask;
    let hi = lo | !mask;

    // A CIDR names a network block, and on any block wider than a point-to-point
    // link the first and last addresses are the network and broadcast
    // addresses rather than hosts. Probing them is not merely useless, it is
    // actively misleading: the broadcast address draws a reply from everything
    // on the segment and the network address from the gateway, and the cascade
    // would then report both as live machines. This is also what makes the count
    // match `Interface::usable_hosts`, which excludes them too.
    //
    // /31 is exempt: RFC 3021 gives it two usable endpoints. /32 is a host.
    if prefix <= 30 {
        return Ok((lo + 1, hi - 1));
    }
    Ok((lo, hi))
}

fn parse_wildcard(spec: &str) -> Result<(u32, u32), TargetError> {
    let octets: Vec<&str> = spec.trim().split('.').collect();
    let Some(first_star) = octets.iter().position(|o| *o == "*") else {
        // Not actually a wildcard; fall back to plain address parsing.
        let ip = parse_ipv4(spec)?;
        let v = u32::from(ip);
        return Ok((v, v));
    };
    if octets.iter().skip(first_star).any(|o| *o != "*") {
        return Err(TargetError::NonTrailingWildcard {
            spec: spec.to_string(),
        });
    }
    let mut lo: u32 = 0;
    let mut hi: u32 = 0;
    for (i, octet) in octets.iter().enumerate() {
        if *octet == "*" {
            // Free octet: all 256 values.
            lo |= u32::from(0u8) << (8 * (3 - i));
            hi |= u32::from(255u8) << (8 * (3 - i));
        } else {
            let v: u8 = octet.parse().map_err(|_| TargetError::BadTarget {
                spec: spec.to_string(),
            })?;
            lo |= u32::from(v) << (8 * (3 - i));
            hi |= u32::from(v) << (8 * (3 - i));
        }
    }
    Ok((lo, hi))
}

fn parse_range(spec: &str) -> Result<(u32, u32), TargetError> {
    let (left, right) = spec.split_once('-').expect("caller checked for -");
    let (left, right) = (left.trim(), right.trim());

    let start = parse_ipv4(left)?;

    // Short form: the right side is a bare last octet, so the first three
    // octets of the left side supply the network part.
    let end = if let Ok(last_octet) = right.parse::<u8>() {
        let o = start.octets();
        if right.contains('.') {
            return Err(TargetError::MixedRange {
                spec: spec.to_string(),
            });
        }
        Ipv4Addr::new(o[0], o[1], o[2], last_octet)
    } else {
        parse_ipv4(right)?
    };

    let (lo, hi) = (u32::from(start), u32::from(end));
    if lo > hi {
        return Err(TargetError::InvertedRange { start, end });
    }
    Ok((lo, hi))
}

fn parse_ipv4(s: &str) -> Result<Ipv4Addr, TargetError> {
    s.parse()
        .map_err(|_| TargetError::BadAddress(s.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(spec: &str) -> TargetSet {
        TargetSet::parse([spec]).expect("should parse")
    }

    fn all(spec: &str) -> Vec<Ipv4Addr> {
        set(spec).iter().collect()
    }

    #[test]
    fn single_address() {
        assert_eq!(all("10.0.0.7"), vec![Ipv4Addr::new(10, 0, 0, 7)]);
    }

    #[test]
    fn cidr_24_excludes_the_network_and_broadcast_addresses() {
        let s = set("192.168.1.0/24");
        assert_eq!(s.len(), 254);
        let v = all("192.168.1.0/24");
        assert_eq!(v.first(), Some(&Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(v.last(), Some(&Ipv4Addr::new(192, 168, 1, 254)));
        assert!(
            !s.contains(Ipv4Addr::new(192, 168, 1, 0)),
            "the network address is not a host"
        );
        assert!(
            !s.contains(Ipv4Addr::new(192, 168, 1, 255)),
            "the broadcast address is not a host"
        );
    }

    #[test]
    fn cidr_with_host_bits_set_is_masked_not_rejected() {
        // 192.168.1.77/24 means the whole 192.168.1.0/24 block.
        let v = all("192.168.1.77/24");
        assert_eq!(v.len(), 254);
        assert_eq!(v.first(), Some(&Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn cidr_slash_32_and_31() {
        assert_eq!(all("10.0.0.1/32"), vec![Ipv4Addr::new(10, 0, 0, 1)]);
        assert_eq!(all("10.0.0.0/31").len(), 2);
    }

    #[test]
    fn cidr_slash_zero_is_the_whole_space() {
        assert_eq!(set("0.0.0.0/0").len(), (1u64 << 32) - 2);
    }

    #[test]
    fn explicit_range() {
        let v = all("192.168.1.10-192.168.1.12");
        assert_eq!(
            v,
            vec![
                Ipv4Addr::new(192, 168, 1, 10),
                Ipv4Addr::new(192, 168, 1, 11),
                Ipv4Addr::new(192, 168, 1, 12),
            ]
        );
    }

    #[test]
    fn short_range_takes_network_from_left() {
        let v = all("192.168.1.10-12");
        assert_eq!(v.len(), 3);
        assert_eq!(v[0], Ipv4Addr::new(192, 168, 1, 10));
        assert_eq!(v[2], Ipv4Addr::new(192, 168, 1, 12));
    }

    #[test]
    fn wildcard_single_and_double_octet() {
        assert_eq!(all("192.168.1.*").len(), 256);
        let v = all("10.0.*.*");
        assert_eq!(v.len(), 65536);
        assert_eq!(v.first(), Some(&Ipv4Addr::new(10, 0, 0, 0)));
        assert_eq!(v.last(), Some(&Ipv4Addr::new(10, 0, 255, 255)));
    }

    #[test]
    fn wildcard_must_be_trailing() {
        assert!(matches!(
            TargetSet::parse(["192.168.*.1"]),
            Err(TargetError::NonTrailingWildcard { .. })
        ));
    }

    #[test]
    fn comma_separated_and_repeated_arguments_merge() {
        let s = TargetSet::parse(["10.0.0.1,10.0.0.2", "10.0.0.3"]).unwrap();
        assert_eq!(s.len(), 3);
    }

    #[test]
    fn overlapping_targets_are_probed_once() {
        let s = TargetSet::parse(["10.0.0.0/24", "10.0.0.10-10.0.0.20", "10.0.0.5"]).unwrap();
        assert_eq!(s.len(), 254, "overlap must not inflate the count");
        let v: Vec<_> = s.iter().collect();
        let mut sorted = v.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), v.len());
    }

    #[test]
    fn adjacent_ranges_coalesce() {
        let s = TargetSet::parse(["10.0.0.1-10.0.0.10", "10.0.0.11-10.0.0.20"]).unwrap();
        assert_eq!(s.len(), 20);
    }

    #[test]
    fn inverted_range_is_rejected() {
        assert!(matches!(
            TargetSet::parse(["192.168.1.20-192.168.1.10"]),
            Err(TargetError::InvertedRange { .. })
        ));
    }

    #[test]
    fn bad_input_is_rejected_with_a_useful_message() {
        assert!(TargetSet::parse(["192.168.1"]).is_err());
        assert!(TargetSet::parse(["192.168.1.0/33"]).is_err());
        assert!(TargetSet::parse(["hello"]).is_err());
        assert!(TargetSet::parse(["999.1.1.1"]).is_err());
    }

    #[test]
    fn contains_respects_membership() {
        // A /28 is 192.168.1.0-15, of which .0 and .15 are network/broadcast.
        let s = set("192.168.1.0/28");
        assert!(!s.contains(Ipv4Addr::new(192, 168, 1, 0)));
        assert!(s.contains(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(s.contains(Ipv4Addr::new(192, 168, 1, 14)));
        assert!(!s.contains(Ipv4Addr::new(192, 168, 1, 15)));
        assert!(!s.contains(Ipv4Addr::new(192, 168, 1, 16)));
    }

    #[test]
    fn expand_enforces_the_host_limit() {
        let s = set("10.0.0.0/8");
        assert!(matches!(
            s.expand(1024),
            Err(TargetError::TooManyHosts { .. })
        ));
        assert!(set("10.0.0.0/24").expand(1024).is_ok());
    }

    #[test]
    fn from_network_builds_the_subnet() {
        let s = TargetSet::from_network(Ipv4Addr::new(192, 168, 0, 79), 24).unwrap();
        assert_eq!(s.len(), 254);
        assert!(s.contains(Ipv4Addr::new(192, 168, 0, 1)));
    }

    #[test]
    fn lazy_iteration_matches_expansion() {
        let s = set("10.0.0.0/28");
        assert_eq!(s.iter().count() as u64, s.len());
    }
}
