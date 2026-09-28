//! Rendering a [`ScanReport`] as text, JSON, CSV, or bare addresses.
//!
//! Every format is produced by the same [`render`] call, so `--format` and
//! `--output` always agree: writing to a file with `-o results.json` gives
//! exactly the bytes `--format json` would print.

use std::fmt::Write as _;

use anyhow::Result;
use serde::Serialize;

use crate::host::{Host, Method, Outcome};
use crate::scan::ScanReport;

/// Every port this host answered on, lowest first.
///
/// A host commonly has more than one service open, and reporting only the
/// lowest -- which is what stopping at the first conclusive answer did -- turns
/// a service inventory into a sample of it. All of them are probed and all of
/// them are shown.
///
/// Only `Alive` counts. A refused connection is proof the host is there but
/// proof the port is *not* open, and listing `22` next to a host's real services
/// because nothing was listening there would be a lie in a column whose entire
/// purpose is to say which services are reachable.
fn open_ports(h: &Host) -> Vec<u16> {
    let mut ports: Vec<u16> = h
        .evidence
        .iter()
        .filter(|e| e.method == Method::Tcp && e.outcome == Outcome::Alive)
        .filter_map(|e| e.port)
        .collect();
    ports.sort_unstable();
    ports.dedup();
    ports
}

/// The open ports as one cell, e.g. `80,443`.
fn ports_cell(h: &Host) -> Option<String> {
    let ports = open_ports(h);
    if ports.is_empty() {
        None
    } else {
        Some(
            ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(","),
        )
    }
}

/// Output shapes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, Default)]
pub enum Format {
    /// Aligned columns, suitable for a terminal.
    #[default]
    Table,
    /// Aligned columns including a hostname column, for wide terminals.
    Wide,
    /// A JSON array.
    Json,
    /// One JSON object per line, for piping into `jq` or a log pipeline.
    Jsonl,
    /// Comma-separated, with a header row.
    Csv,
    /// Just the addresses, one per line. For feeding other tools.
    Bare,
    /// A markdown table.
    Md,
}

/// How to order rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, Default)]
pub enum SortBy {
    /// Numeric address order. Stable and predictable.
    #[default]
    Ip,
    /// Fastest responder first.
    Rtt,
    /// A to Z.
    Hostname,
    /// MAC address order.
    Mac,
}

#[derive(Debug, Clone)]
pub struct OutputOptions {
    pub format: Format,
    pub sort: SortBy,
    /// Emit ANSI colour. Only meaningful for `Table`.
    pub color: bool,
    /// Append a human-readable summary block.
    pub summary: bool,
    /// Include the scanner's diagnostic notes.
    pub notes: bool,
}

impl Default for OutputOptions {
    fn default() -> Self {
        OutputOptions {
            format: Format::Table,
            sort: SortBy::Ip,
            color: false,
            summary: true,
            notes: false,
        }
    }
}

// ------------------------------------------------------------------ json ----

/// One host, as JSON. Field names are stable and lower-case.
#[derive(Debug, Serialize)]
struct HostJson {
    ip: String,
    alive: bool,
    hostname: Option<String>,
    mac: Option<String>,
    /// The lowest open TCP port, for compatibility with earlier output.
    port: Option<u16>,
    /// Every open TCP port found on this host.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    ports: Vec<u16>,
    /// Best round-trip time across all methods, in milliseconds.
    rtt_ms: Option<f64>,
    ttl: Option<u8>,
    /// The most informative method that proved this host alive.
    method: Option<String>,
    /// Every probe result, so nothing observed is hidden from the consumer.
    probes: Vec<ProbeJson>,
}

#[derive(Debug, Serialize)]
struct ProbeJson {
    method: String,
    outcome: &'static str,
    rtt_ms: Option<f64>,
    ttl: Option<u8>,
    port: Option<u16>,
}

#[derive(Debug, Serialize)]
struct ReportJson {
    tool: &'static str,
    version: &'static str,
    target: String,
    interface: Option<InterfaceJson>,
    addresses_scanned: usize,
    hosts_alive: usize,
    elapsed_ms: u128,
    hosts: Vec<HostJson>,
    /// Addresses that answered but could not be tied to a device, and were
    /// withheld from `hosts`. Reported so that a consumer counting `hosts` knows
    /// it is not the whole census, exactly as the text summary says out loud.
    #[serde(skip_serializing_if = "Option::is_none")]
    unverified_omitted: Option<usize>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    notes: Vec<String>,
}

#[derive(Debug, Serialize)]
struct InterfaceJson {
    name: String,
    address: String,
    netmask: String,
    prefix: u8,
}

// ------------------------------------------------------------- rendering ----

/// Render a report according to `opts`.
pub fn render(report: &ScanReport, opts: &OutputOptions) -> Result<String> {
    let mut hosts: Vec<&Host> = report.hosts.iter().collect();
    sort_hosts(&mut hosts, opts.sort);

    let mut out = match opts.format {
        Format::Bare => render_bare(&hosts),
        Format::Csv => render_csv(&hosts)?,
        Format::Md => render_md(&hosts, report),
        Format::Json | Format::Jsonl => render_json(report, &hosts, opts)?,
        Format::Table => render_table(&hosts, opts, false),
        Format::Wide => render_table(&hosts, opts, true),
    };

    if opts.notes && !report.stats.notes.is_empty() {
        let _ = writeln!(out);
        for n in &report.stats.notes {
            let _ = writeln!(out, "note: {n}");
        }
    }
    if opts.summary && matches!(opts.format, Format::Table | Format::Wide | Format::Bare) {
        let _ = write!(out, "{}", render_summary(report, opts));
    }

    Ok(out)
}

fn sort_hosts(hosts: &mut [&Host], by: SortBy) {
    match by {
        SortBy::Ip => hosts.sort_by_key(|h| u32::from(h.ip)),
        SortBy::Rtt => hosts.sort_by(|a, b| {
            // Hosts that only ever refused have no round trip to compare, and
            // `None` sorts before `Some`, so they would otherwise lead the list.
            // They go last, and ties break on the address for a stable order.
            match (a.best_rtt(), b.best_rtt()) {
                (Some(x), Some(y)) => x
                    .cmp(&y)
                    .then_with(|| u32::from(a.ip).cmp(&u32::from(b.ip))),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => u32::from(a.ip).cmp(&u32::from(b.ip)),
            }
        }),
        SortBy::Hostname => hosts.sort_by(|a, b| {
            a.hostname
                .as_deref()
                .unwrap_or("")
                .to_lowercase()
                .cmp(&b.hostname.as_deref().unwrap_or("").to_lowercase())
                .then_with(|| u32::from(a.ip).cmp(&u32::from(b.ip)))
        }),
        SortBy::Mac => hosts.sort_by(|a, b| {
            a.mac
                .map(|m| m.to_string())
                .unwrap_or_default()
                .cmp(&b.mac.map(|m| m.to_string()).unwrap_or_default())
                .then_with(|| u32::from(a.ip).cmp(&u32::from(b.ip)))
        }),
    }
}

fn render_bare(hosts: &[&Host]) -> String {
    let mut out = String::new();
    for h in hosts {
        let _ = writeln!(out, "{}", h.ip);
    }
    out
}

fn render_csv(hosts: &[&Host]) -> Result<String> {
    let mut wtr = csv::Writer::from_writer(Vec::new());
    wtr.write_record([
        "ip", "hostname", "mac", "port", "rtt_ms", "ttl", "method", "outcome",
    ])?;
    for h in hosts {
        let ev = h.primary_method();
        let outcome = h
            .evidence
            .iter()
            .find(|e| e.outcome.proves_alive())
            .map(|e| e.outcome);
        wtr.write_record([
            h.ip.to_string(),
            h.hostname.clone().unwrap_or_default(),
            h.mac.map(|m| m.to_string()).unwrap_or_default(),
            ports_cell(h).unwrap_or_default(),
            h.best_rtt()
                .map(|d| format!("{:.2}", d.as_secs_f64() * 1000.0))
                .unwrap_or_default(),
            h.evidence
                .iter()
                .find_map(|e| e.ttl)
                .map(|t| t.to_string())
                .unwrap_or_default(),
            ev.map(|m| m.to_string()).unwrap_or_default(),
            outcome.map(outcome_str).unwrap_or_default().to_string(),
        ])?;
    }
    Ok(String::from_utf8(wtr.into_inner()?)?)
}

fn render_md(hosts: &[&Host], report: &ScanReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "| IP | Hostname | MAC | Port | RTT | Method |");
    let _ = writeln!(out, "|---|---|---|---|---|---|");
    for h in hosts {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} | {} |",
            h.ip,
            md_cell(h.hostname.as_deref()),
            md_cell(h.mac.map(|m| m.to_string()).as_deref()),
            ports_cell(h).unwrap_or_else(|| "-".into()),
            h.best_rtt()
                .map(|d| format!("{:.2} ms", d.as_secs_f64() * 1000.0))
                .unwrap_or_else(|| "-".into()),
            h.primary_method()
                .map(|m| m.to_string())
                .unwrap_or_else(|| "-".into()),
        );
    }
    let _ = writeln!(out, "\n_{}_", one_line_summary(report));
    out
}

fn md_cell(s: Option<&str>) -> String {
    match s {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => "-".into(),
    }
}

fn render_json(report: &ScanReport, hosts: &[&Host], opts: &OutputOptions) -> Result<String> {
    let host_json: Vec<HostJson> = hosts
        .iter()
        .map(|h| HostJson {
            ip: h.ip.to_string(),
            alive: h.is_alive(),
            hostname: h.hostname.clone(),
            mac: h.mac.map(|m| m.to_string()),
            port: open_ports(h).first().copied(),
            ports: open_ports(h),
            rtt_ms: h.best_rtt().map(|d| d.as_secs_f64() * 1000.0),
            ttl: h.evidence.iter().find_map(|e| e.ttl),
            method: h.primary_method().map(|m| m.to_string()),
            probes: h
                .evidence
                .iter()
                .map(|e| ProbeJson {
                    method: e.method.to_string(),
                    outcome: outcome_str(e.outcome),
                    rtt_ms: e.rtt.map(|d| d.as_secs_f64() * 1000.0),
                    ttl: e.ttl,
                    port: e.port,
                })
                .collect(),
        })
        .collect();

    match opts.format {
        Format::Jsonl => {
            let mut out = String::new();
            for h in &host_json {
                out.push_str(&serde_json::to_string(h)?);
                out.push('\n');
            }
            Ok(out)
        }
        _ => {
            let doc = ReportJson {
                tool: "ipscan",
                version: env!("CARGO_PKG_VERSION"),
                target: report.target_spec.clone(),
                interface: report.interface.as_ref().map(|i| InterfaceJson {
                    name: i.name.clone(),
                    address: i.addr.to_string(),
                    netmask: i.netmask.to_string(),
                    prefix: i.prefix,
                }),
                addresses_scanned: report.stats.addresses,
                hosts_alive: host_json.len(),
                elapsed_ms: report.elapsed.as_millis(),
                hosts: host_json,
                unverified_omitted: (report.stats.unverified_omitted > 0)
                    .then_some(report.stats.unverified_omitted),
                notes: if opts.notes {
                    report.stats.notes.clone()
                } else {
                    Vec::new()
                },
            };
            Ok(format!("{}\n", serde_json::to_string_pretty(&doc)?))
        }
    }
}

fn outcome_str(o: Outcome) -> &'static str {
    match o {
        Outcome::Alive => "alive",
        Outcome::Filtered => "filtered",
        Outcome::Silent => "silent",
    }
}

// ----------------------------------------------------------------- table ----

/// Columns are right-aligned when they hold numbers and left-aligned otherwise,
/// which is what makes an RTT column scannable by eye.
const RIGHT_ALIGNED: [usize; 2] = [3, 4]; // port, rtt
const COLUMNS: [&str; 7] = ["IP", "HOSTNAME", "MAC", "PORT", "RTT", "TTL", "METHOD"];

fn render_table(hosts: &[&Host], opts: &OutputOptions, wide: bool) -> String {
    let palette = Palette {
        enabled: opts.color,
    };
    let blank = "-".to_string();

    // Build cells per host. `HOSTNAME` is dropped in narrow mode to keep the
    // line under 80 columns on a default terminal.
    let rows: Vec<Vec<String>> = hosts
        .iter()
        .map(|h| {
            let hostname = h.hostname.clone().unwrap_or_else(|| blank.clone());
            let mac = h
                .mac
                .map(|m| m.to_string())
                .unwrap_or_else(|| blank.clone());
            let port = ports_cell(h).unwrap_or_else(|| blank.clone());
            let rtt = h
                .best_rtt()
                .map(|d| format!("{:.2} ms", d.as_secs_f64() * 1000.0))
                .unwrap_or_else(|| blank.clone());
            let ttl = h
                .evidence
                .iter()
                .find_map(|e| e.ttl)
                .map(|t| t.to_string())
                .unwrap_or_else(|| blank.clone());
            let method = h
                .primary_method()
                .map(|m| m.to_string())
                .unwrap_or_else(|| "-".to_string());

            if wide {
                vec![
                    h.ip.to_string(),
                    palette.hostname(&hostname),
                    mac,
                    port,
                    rtt,
                    ttl,
                    method,
                ]
            } else {
                vec![palette.ip(&h.ip.to_string()), mac, port, rtt, ttl, method]
            }
        })
        .collect();

    let headers: Vec<&str> = if wide {
        COLUMNS.to_vec()
    } else {
        ["IP", "MAC", "PORT", "RTT", "TTL", "METHOD"].to_vec()
    };
    let shift = if wide { 0 } else { 1 };
    let widths: Vec<usize> = headers
        .iter()
        .enumerate()
        .map(|(i, h)| {
            let right = RIGHT_ALIGNED.contains(&(i + shift));
            let w = rows
                .iter()
                .filter_map(|r| r.get(i))
                .map(|c| visible_len(c))
                .chain(std::iter::once(h.len()))
                .max()
                .unwrap_or(0);
            let _ = right;
            w
        })
        .collect();

    let mut out = String::new();
    let header_line: Vec<String> = headers
        .iter()
        .enumerate()
        .map(|(i, h)| pad(h, widths[i], RIGHT_ALIGNED.contains(&(i + shift))))
        .collect();
    let _ = writeln!(out, "{}", palette.heading(&header_line.join("  ")));

    for row in &rows {
        let cells: Vec<String> = headers
            .iter()
            .enumerate()
            .map(|(i, _)| pad(&row[i], widths[i], RIGHT_ALIGNED.contains(&(i + shift))))
            .collect();
        let _ = writeln!(out, "{}", cells.join("  ").trim_end());
    }

    // The summary is appended by `render`, which is the only place that knows
    // whether `-q` was asked for. Appending it here as well would print it
    // twice and ignore `--quiet`.
    out
}

fn render_summary(report: &ScanReport, opts: &OutputOptions) -> String {
    let palette = Palette {
        enabled: opts.color,
    };
    let mut out = String::new();
    let _ = writeln!(out, "\n{}", palette.bold(&one_line_summary(report)));
    out
}

fn one_line_summary(report: &ScanReport) -> String {
    let mut s = format!(
        "{} host{} found out of {} address{} scanned in {:.2}s",
        report.hosts.len(),
        if report.hosts.len() == 1 { "" } else { "s" },
        report.stats.addresses,
        if report.stats.addresses == 1 {
            ""
        } else {
            "es"
        },
        report.elapsed.as_secs_f64(),
    );
    if let Some(iface) = &report.interface {
        let _ = write!(s, " via {} ({})", iface.name, iface.addr);
    }
    s
}

// ---------------------------------------------------------------- colour ----

struct Palette {
    enabled: bool,
}

impl Palette {
    fn wrap(&self, code: &str, s: &str) -> String {
        if self.enabled && !s.is_empty() {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }

    fn ip(&self, s: &str) -> String {
        self.wrap("1;36", s)
    }

    fn hostname(&self, s: &str) -> String {
        self.wrap("33", s)
    }

    fn heading(&self, s: &str) -> String {
        self.wrap("2", s)
    }

    fn bold(&self, s: &str) -> String {
        self.wrap("1", s)
    }
}

// ----------------------------------------------------------------- utils ----

/// Width of a cell ignoring ANSI escapes, so colour never skews alignment.
fn visible_len(s: &str) -> usize {
    let mut len = 0usize;
    let mut in_escape = false;
    for c in s.chars() {
        if in_escape {
            if c == 'm' {
                in_escape = false;
            }
        } else if c == '\x1b' {
            in_escape = true;
        } else {
            len += 1;
        }
    }
    len
}

fn pad(s: &str, width: usize, right: bool) -> String {
    let visible = visible_len(s);
    let fill = width.saturating_sub(visible);
    if right {
        format!("{}{s}", " ".repeat(fill))
    } else {
        format!("{s}{}", " ".repeat(fill))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{Evidence, MacAddr, Method};
    use crate::net::Interface;
    use crate::scan::ScanStats;
    use std::time::Duration;

    fn report_with(hosts: Vec<Host>) -> ScanReport {
        ScanReport {
            hosts,
            stats: ScanStats {
                addresses: 254,
                notes: vec!["icmp fell back to tcp".into()],
                ..ScanStats::default()
            },
            interface: Some(Interface {
                name: "wlan0".into(),
                addr: "192.168.1.10".parse().unwrap(),
                netmask: "255.255.255.0".parse().unwrap(),
                prefix: 24,
                broadcast: None,
                loopback: false,
            }),
            target_spec: "192.168.1.0/24".into(),
            elapsed: Duration::from_millis(1250),
        }
    }

    fn host(
        ip: &str,
        mac: Option<&str>,
        port: Option<u16>,
        rtt_ms: Option<u64>,
        ttl: Option<u8>,
    ) -> Host {
        let mut h = Host::new(ip.parse().unwrap());
        if let Some(m) = mac {
            h.set_mac(MacAddr::parse(m).unwrap());
        }
        if let Some(p) = port {
            h.add_evidence(
                Evidence::new(Method::Tcp, Outcome::Alive)
                    .with_port(p)
                    .with_rtt(Duration::from_millis(rtt_ms.unwrap_or(1))),
            );
        } else {
            h.add_evidence(
                Evidence::new(Method::Icmp, Outcome::Alive)
                    .with_rtt(Duration::from_millis(rtt_ms.unwrap_or(1)))
                    .with_ttl(ttl.unwrap_or(64)),
            );
        }
        h
    }

    fn sample() -> ScanReport {
        let mut a = host(
            "192.168.1.1",
            Some("f0:09:0d:2a:86:fd"),
            None,
            Some(10),
            Some(64),
        );
        a.hostname = Some("router.lan".into());
        let mut b = host(
            "192.168.1.42",
            Some("bc:24:11:eb:cf:14"),
            Some(445),
            Some(2),
            None,
        );
        b.hostname = Some("nas.lan".into());
        report_with(vec![a, b])
    }

    #[test]
    fn table_columns_line_up_without_colour() {
        let out = render(
            &sample(),
            &OutputOptions {
                summary: false,
                ..Default::default()
            },
        )
        .unwrap();
        let lines: Vec<&str> = out.lines().collect();
        let header = lines[0];
        assert!(header.starts_with("IP"), "header first: {header}");
        let mac_col = header.find("MAC").expect("header has a MAC column");
        // Every host row must put the address at column 0 and the MAC where the
        // header says it belongs. Trailing summary lines are not host rows.
        let rows: Vec<&&str> = lines[1..]
            .iter()
            .filter(|l| {
                l.split_whitespace()
                    .next()
                    .is_some_and(|t| t.parse::<std::net::Ipv4Addr>().is_ok())
            })
            .collect();
        assert_eq!(rows.len(), 2, "both hosts should have rows:\n{out}");
        for line in rows {
            let ip = line.split_whitespace().next().unwrap();
            assert_eq!(
                line.find(ip),
                Some(0),
                "row must start with the address: {line}"
            );
            let mac = line
                .split_whitespace()
                .find(|f| f.contains(':') && f.len() == 17)
                .unwrap_or("-");
            assert_eq!(line.find(mac), Some(mac_col), "MAC column drift in: {line}");
        }
    }

    #[test]
    fn colour_does_not_disturb_alignment() {
        let plain = render(
            &sample(),
            &OutputOptions {
                summary: false,
                color: false,
                ..Default::default()
            },
        )
        .unwrap();
        let colored = render(
            &sample(),
            &OutputOptions {
                summary: false,
                color: true,
                ..Default::default()
            },
        )
        .unwrap();
        // Colour is only ever an escape around existing text, so removing every
        // escape sequence must reproduce the plain output byte for byte.
        let strip = |s: &str| {
            let mut out = String::with_capacity(s.len());
            let mut chars = s.chars();
            while let Some(c) = chars.next() {
                if c == '\x1b' {
                    for c in chars.by_ref() {
                        if c.is_ascii_alphabetic() {
                            break;
                        }
                    }
                } else {
                    out.push(c);
                }
            }
            out
        };
        assert_eq!(strip(&colored), plain, "colour must only add escapes");
    }

    #[test]
    fn wide_format_adds_the_hostname_column() {
        let out = render(
            &sample(),
            &OutputOptions {
                format: Format::Wide,
                summary: false,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(out.contains("HOSTNAME"), "{out}");
        assert!(out.contains("router.lan"), "{out}");
    }

    #[test]
    fn bare_format_is_only_addresses() {
        let out = render(
            &sample(),
            &OutputOptions {
                format: Format::Bare,
                summary: false,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(out, "192.168.1.1\n192.168.1.42\n");
    }

    #[test]
    fn csv_has_a_header_and_one_row_per_host() {
        let out = render(
            &sample(),
            &OutputOptions {
                format: Format::Csv,
                summary: false,
                ..Default::default()
            },
        )
        .unwrap();
        let mut lines = out.lines();
        assert_eq!(
            lines.next().unwrap(),
            "ip,hostname,mac,port,rtt_ms,ttl,method,outcome"
        );
        assert_eq!(lines.count(), 2, "one row per host");
        assert!(out.contains("445"), "the open port must be reported: {out}");
    }

    #[test]
    fn json_is_valid_and_carries_every_observation() {
        let out = render(
            &sample(),
            &OutputOptions {
                format: Format::Json,
                summary: false,
                ..Default::default()
            },
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["hosts_alive"], 2);
        assert_eq!(v["addresses_scanned"], 254);
        assert_eq!(v["target"], "192.168.1.0/24");
        assert_eq!(v["interface"]["name"], "wlan0");
        let first = &v["hosts"][0];
        assert_eq!(first["ip"], "192.168.1.1");
        assert_eq!(first["mac"], "f0:09:0d:2a:86:fd");
        assert_eq!(first["hostname"], "router.lan");
        assert!(
            first["probes"].is_array(),
            "per-probe detail must be present"
        );
        // A clean scan withholds nothing, so the field stays out of the way.
        assert!(
            v.get("unverified_omitted").is_none(),
            "an unremarkable scan must not carry a key it has nothing to say about"
        );
    }

    #[test]
    fn json_says_how_many_hosts_were_withheld() {
        // The text summary states this out loud, so the machine-readable form has
        // to carry it too: a consumer counting `hosts` is otherwise reading a
        // censored list as if it were the census.
        let mut report = sample();
        report.stats.unverified_omitted = 137;
        let out = render(
            &report,
            &OutputOptions {
                format: Format::Json,
                summary: false,
                ..Default::default()
            },
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["unverified_omitted"], 137);
    }

    #[test]
    fn jsonl_is_one_object_per_line() {
        let out = render(
            &sample(),
            &OutputOptions {
                format: Format::Jsonl,
                summary: false,
                ..Default::default()
            },
        )
        .unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2);
        for l in lines {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            assert!(v["ip"].is_string());
        }
    }

    #[test]
    fn sorting_by_rtt_puts_the_fastest_first() {
        let out = render(
            &sample(),
            &OutputOptions {
                sort: SortBy::Rtt,
                summary: false,
                ..Default::default()
            },
        )
        .unwrap();
        let first_ip = out
            .lines()
            .nth(1)
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap();
        assert_eq!(first_ip, "192.168.1.42", "2ms should beat 10ms:\n{out}");
    }

    #[test]
    fn notes_are_hidden_unless_requested() {
        let quiet = render(
            &sample(),
            &OutputOptions {
                summary: false,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(
            !quiet.contains("icmp fell back"),
            "notes must be opt-in: {quiet}"
        );
        let loud = render(
            &sample(),
            &OutputOptions {
                summary: false,
                notes: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(loud.contains("icmp fell back"), "{loud}");
    }

    #[test]
    fn summary_counts_hosts_and_addresses() {
        let out = render(&sample(), &OutputOptions::default()).unwrap();
        assert!(out.contains("2 hosts found"), "{out}");
        assert!(out.contains("254 addresses"), "{out}");
        assert!(out.contains("wlan0"), "{out}");
    }

    #[test]
    fn an_empty_result_still_renders_valid_output() {
        let empty = report_with(vec![]);
        for f in [
            Format::Table,
            Format::Csv,
            Format::Json,
            Format::Jsonl,
            Format::Bare,
            Format::Md,
            Format::Wide,
        ] {
            let out = render(
                &empty,
                &OutputOptions {
                    format: f,
                    summary: true,
                    ..Default::default()
                },
            );
            assert!(
                out.is_ok(),
                "{f:?} failed to render an empty report: {out:?}"
            );
        }
        let out = render(
            &empty,
            &OutputOptions {
                format: Format::Json,
                ..Default::default()
            },
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["hosts_alive"], 0);
    }

    #[test]
    fn a_host_with_several_open_ports_lists_them_all() {
        let mut h = Host::new("192.168.1.9".parse().unwrap());
        h.add_evidence(
            Evidence::new(Method::Tcp, Outcome::Alive)
                .with_port(443)
                .with_rtt(Duration::from_millis(3)),
        );
        h.add_evidence(
            Evidence::new(Method::Tcp, Outcome::Alive)
                .with_port(80)
                .with_rtt(Duration::from_millis(1)),
        );
        // A refusal is not an open port and must not appear in the list.
        h.add_evidence(Evidence::new(Method::Tcp, Outcome::Filtered).with_port(22));

        assert_eq!(open_ports(&h), vec![80, 443]);

        let out = render(
            &report_with(vec![h.clone()]),
            &OutputOptions {
                summary: false,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(out.contains("80,443"), "every open port, in order: {out}");

        // JSON carries the full set as well as the lowest, for old consumers.
        let out = render(
            &report_with(vec![h.clone()]),
            &OutputOptions {
                format: Format::Json,
                summary: false,
                ..Default::default()
            },
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(
            v["hosts"][0]["port"], 80,
            "lowest port kept for compatibility"
        );
        assert_eq!(v["hosts"][0]["ports"], serde_json::json!([80, 443]));
    }

    #[test]
    fn visible_len_ignores_escapes() {
        assert_eq!(visible_len("\x1b[1;36m192.168.1.1\x1b[0m"), 11);
        assert_eq!(visible_len("plain"), 5);
    }

    #[test]
    fn missing_fields_render_as_placeholders() {
        let bare = host("192.168.1.9", None, None, None, None);
        let out = render(
            &report_with(vec![bare]),
            &OutputOptions {
                summary: false,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(out.contains("-"), "absent fields need a placeholder: {out}");
        // A host with no TTL or port must not print a bogus zero.
        assert!(!out.contains("0.00 ms"), "{out}");
    }
}
