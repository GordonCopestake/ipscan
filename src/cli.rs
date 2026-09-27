//! Command-line interface definition.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;

use crate::net::Interface;
use crate::output::{Format, OutputOptions, SortBy};
use crate::probe::ProbeConfig;
use crate::scan::{MethodChoice, ScanPlan};
use crate::target::TargetSet;

/// Default ceiling on how many addresses one invocation will probe.
///
/// The point is to turn a fat-fingered `/8` into an error rather than a huge
/// allocation. Raise it with `--max-hosts`.
pub const DEFAULT_MAX_HOSTS: u64 = 1_048_576;

/// Find alive hosts on the local network.
#[derive(Parser, Debug)]
#[command(
    name = "ipscan",
    version,
    about = "Find alive hosts on the local network",
    long_about = "Scans a network for alive hosts using a cascade of probes (ARP, ICMP echo, \
                  TCP connect), reporting each host only when something actually answered.\n\n\
                  With no TARGET, the running machine's own address and subnet mask are used, \
                  so a bare `ipscan` scans the network you are attached to.",
    after_help = "EXAMPLES:\n  \
                  ipscan                          scan the network this machine is on\n  \
                  ipscan 192.168.1.0/24           scan an explicit block\n  \
                  ipscan 192.168.1.1-254          scan an explicit range\n  \
                  ipscan 10.0.0.0/8 -p 80,443     scan a big block on two ports only\n  \
                  ipscan -f json -o hosts.json     write JSON to a file\n  \
                  ipscan -f bare | nmap -iL -     pipe addresses into another tool\n  \
                  ipscan -L                      list local interfaces"
)]
pub struct Cli {
    /// What to scan: CIDR, range (10-20 or 10-10.0.0.20), wildcard, or address.
    #[arg(value_name = "TARGET")]
    pub targets: Vec<String>,

    // ------------------------------------------------------ selection ----
    /// Interface to scan from. Defaults to the one used for the default route.
    #[arg(short = 'i', long, value_name = "NAME")]
    pub interface: Option<String>,

    /// List local interfaces and their addresses, then exit.
    #[arg(short = 'L', long)]
    pub list_interfaces: bool,

    /// Which probe to use. `auto` runs the full cascade.
    #[arg(short = 'm', long, value_enum, default_value_t = MethodChoice::Auto)]
    pub method: MethodChoice,

    // --------------------------------------------------------- probing ----
    /// TCP ports to try, comma-separated. Defaults to 80,443,22,445,3389,8080.
    #[arg(short = 'p', long, value_name = "PORTS", value_delimiter = ',')]
    pub ports: Option<Vec<u16>>,

    /// Milliseconds to wait for any single probe.
    #[arg(long, value_name = "MS", default_value_t = 1000)]
    pub timeout: u64,

    /// Extra attempts for targets that do not answer the first probe.
    #[arg(long, value_name = "N", default_value_t = 1)]
    pub retries: u32,

    /// Cap probe rate, in probes per second.
    #[arg(long, value_name = "PPS")]
    pub rate: Option<u32>,

    /// Maximum probes in flight at once.
    #[arg(short = 'c', long, value_name = "N")]
    pub concurrency: Option<usize>,

    // ---------------------------------------------------------- output ----
    /// Output format.
    #[arg(short = 'f', long, value_enum, default_value_t = Format::Table)]
    pub format: Format,

    /// Write results to this file instead of stdout. Honours `--format`.
    #[arg(short = 'o', long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// How to order results.
    #[arg(long, value_enum, default_value_t = SortBy::Ip)]
    pub sort: SortBy,

    /// Reverse-resolve discovered addresses. Slows the scan noticeably.
    #[arg(long)]
    pub dns: bool,

    /// Also report addresses known only to the OS neighbour cache, marked as
    /// such. They were resolved at some point but did not answer this scan.
    #[arg(long)]
    pub cached: bool,

    /// List addresses that answered but which nothing attributed to a device.
    ///
    /// Withheld by default. An address that answers ICMP on a directly-attached
    /// link without ARP having named it is a contradiction: answering the echo
    /// required resolving the target's hardware address first. A device echoing
    /// on behalf of a range it merely routes produces exactly this, so counting
    /// those answers as hosts reports a segment far fuller than it is. The count
    /// is always in the summary, so nothing is lost by leaving them out.
    #[arg(long)]
    pub include_unverified: bool,

    /// Suppress the summary line.
    #[arg(short = 'q', long)]
    pub quiet: bool,

    /// Never emit ANSI colour.
    #[arg(long)]
    pub no_color: bool,

    /// Include scanner diagnostics.
    #[arg(short = 'v', long)]
    pub verbose: bool,

    /// Refuse to probe more than this many addresses.
    #[arg(long, value_name = "N", default_value_t = DEFAULT_MAX_HOSTS)]
    pub max_hosts: u64,
}

impl Cli {
    /// Whether colour is wanted, honouring `--no-color` and the `NO_COLOR`
    /// convention, and never colouring a pipe or a file.
    pub fn wants_color(&self, to_stdout: bool) -> bool {
        if self.no_color || std::env::var_os("NO_COLOR").is_some() {
            return false;
        }
        to_stdout && std::io::IsTerminal::is_terminal(&std::io::stdout())
    }

    /// Resolve the interface to scan from: the one named, or the primary one.
    pub fn resolve_interface(&self) -> anyhow::Result<Option<Interface>> {
        match &self.interface {
            Some(name) => crate::net::find(name).map(Some),
            None => match crate::net::primary() {
                Ok(i) => Ok(Some(i)),
                // Only tolerable when explicit targets were given, because then
                // the target list may not depend on local addressing at all.
                Err(e) if !self.targets.is_empty() => {
                    eprintln!("note: could not determine a default interface: {e:#}");
                    Ok(None)
                }
                Err(e) => Err(e),
            },
        }
    }

    /// Work out the address set to scan.
    ///
    /// With no TARGET this is the point of the tool: take the machine's own
    /// address and subnet mask and scan exactly that network.
    pub fn resolve_targets(&self, iface: Option<&Interface>) -> Result<TargetSet, anyhow::Error> {
        if !self.targets.is_empty() {
            return Ok(TargetSet::parse(&self.targets)?);
        }
        let Some(iface) = iface else {
            anyhow::bail!(
                "no target given and no interface to derive one from. \
                 Pass a target (for example 192.168.1.0/24) or an interface with --interface."
            );
        };
        Ok(TargetSet::from_network(iface.addr, iface.prefix)?)
    }

    /// Assemble the probe configuration.
    pub fn probe_config(&self, iface: Option<&Interface>) -> ProbeConfig {
        ProbeConfig {
            timeout: Duration::from_millis(self.timeout.max(1)),
            retries: self.retries,
            rate: self.rate,
            concurrency: self.concurrency.unwrap_or(256).max(1),
            ports: match &self.ports {
                Some(p) if !p.is_empty() => p.clone(),
                _ => crate::probe::tcp::DEFAULT_PORTS.to_vec(),
            },
            // Pinning the source address is what makes `--interface` mean
            // something: the kernel would otherwise pick its own route.
            source: iface.map(|i| i.addr),
            iface: iface.map(|i| i.name.clone()),
        }
    }

    /// Whether progress reporting is wanted.
    ///
    /// On by default when stderr is a terminal, because a scan blocks inside
    /// operating-system calls for long enough that silence reads as a crash.
    /// It goes to stderr, so a redirected or piped stdout is unaffected, and
    /// `--verbose` forces it on for the cases stderr is not a terminal but a
    /// human is watching — a log file, a CI step, a `tee`.
    pub fn wants_progress(&self) -> bool {
        !self.quiet && (self.verbose || std::io::IsTerminal::is_terminal(&std::io::stderr()))
    }

    pub fn to_plan(&self, targets: TargetSet, iface: Option<Interface>) -> ScanPlan {
        ScanPlan {
            targets,
            method: self.method,
            config: self.probe_config(iface.as_ref()),
            interface: iface,
            resolve_hostnames: self.dns,
            include_cached: self.cached,
            ports_explicit: self.ports.is_some(),
            include_unverified: self.include_unverified,
            progress: self.wants_progress(),
        }
    }

    pub fn to_output_options(&self, to_stdout: bool) -> OutputOptions {
        // The machine-readable formats carry their own metadata, so a prose
        // summary would only get in the way of a parser.
        let summary =
            !self.quiet && matches!(self.format, Format::Table | Format::Wide | Format::Bare);
        OutputOptions {
            format: self.format,
            sort: self.sort,
            color: self.wants_color(to_stdout),
            summary,
            notes: self.verbose,
        }
    }
}

/// Render the `--list-interfaces` table.
pub fn format_interfaces(ifaces: &[Interface]) -> String {
    if ifaces.is_empty() {
        return "no IPv4 interfaces found\n".into();
    }
    let mut rows: Vec<[String; 6]> = vec![[
        "NAME".into(),
        "ADDRESS".into(),
        "NETMASK".into(),
        "PREFIX".into(),
        "HOSTS".into(),
        "NETWORK".into(),
    ]];
    for i in ifaces {
        rows.push([
            i.name.clone(),
            i.addr.to_string(),
            i.netmask.to_string(),
            i.prefix.to_string(),
            i.usable_hosts().to_string(),
            i.network().to_string(),
        ]);
    }
    let mut widths = [0usize; 6];
    for row in &rows {
        for (w, cell) in widths.iter_mut().zip(row) {
            *w = (*w).max(cell.len());
        }
    }
    let mut out = String::new();
    for (idx, row) in rows.iter().enumerate() {
        let cells: Vec<String> = row
            .iter()
            .enumerate()
            .map(|(i, c)| format!("{:width$}", c, width = widths[i]))
            .collect();
        out.push_str(cells.join("  ").trim_end());
        out.push('\n');
        if idx == 0 {
            out.push('\n');
        }
    }
    out
}

/// Convenience for tests and callers that only have addresses.
pub fn single_target(ip: Ipv4Addr) -> TargetSet {
    TargetSet::from_network(ip, 32).expect("a /32 is always valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(std::iter::once("ipscan").chain(args.iter().copied()))
            .expect("should parse")
    }

    #[test]
    fn the_cli_definition_is_internally_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn defaults_match_the_documented_behaviour() {
        let c = parse(&[]);
        assert_eq!(c.method, MethodChoice::Auto);
        assert_eq!(c.format, Format::Table);
        assert_eq!(c.retries, 1);
        assert_eq!(c.timeout, 1000);
        assert_eq!(c.ports, None);
        assert!(c.targets.is_empty());
    }

    #[test]
    fn target_forms_are_accepted() {
        for spec in [
            "192.168.1.0/24",
            "192.168.1.1-20",
            "192.168.1.*",
            "192.168.1.1",
        ] {
            let c = parse(&[spec]);
            assert_eq!(c.targets, vec![spec.to_string()]);
        }
    }

    #[test]
    fn ports_parse_from_a_comma_list() {
        assert_eq!(parse(&["-p", "22,80,443"]).ports, Some(vec![22, 80, 443]));
        assert_eq!(
            parse(&[]).ports,
            None,
            "unset ports must fall back to the default list"
        );
    }

    #[test]
    fn an_unset_port_list_resolves_to_the_documented_defaults() {
        let cfg = parse(&[]).probe_config(None);
        assert_eq!(cfg.ports, vec![80, 443, 22, 445, 3389, 8080]);
        let cfg = parse(&["-p", "22"]).probe_config(None);
        assert_eq!(cfg.ports, vec![22]);
    }

    #[test]
    fn method_and_format_are_validated() {
        assert_eq!(parse(&["-m", "tcp"]).method, MethodChoice::Tcp);
        assert_eq!(parse(&["-f", "json"]).format, Format::Json);
        assert!(Cli::try_parse_from(["ipscan", "-m", "telepathy"]).is_err());
        assert!(Cli::try_parse_from(["ipscan", "-f", "yaml"]).is_err());
    }

    #[test]
    fn max_hosts_has_a_default_and_can_be_raised() {
        assert_eq!(parse(&[]).max_hosts, DEFAULT_MAX_HOSTS);
        assert_eq!(parse(&["--max-hosts", "100"]).max_hosts, 100);
    }

    #[test]
    fn colour_is_off_for_files_even_on_a_terminal() {
        let c = parse(&["-o", "out.txt"]);
        assert!(!c.wants_color(false), "a file must never receive colour");
    }

    #[test]
    fn machine_formats_never_get_a_prose_summary() {
        for f in ["json", "jsonl", "csv", "md"] {
            let c = parse(&["-f", f]);
            let o = c.to_output_options(true);
            assert!(!o.summary, "{f} should not carry a summary block");
        }
        let o = parse(&["-f", "table"]).to_output_options(true);
        assert!(o.summary);
    }

    #[test]
    fn interface_listing_has_an_address_column_per_interface() {
        let ifaces = vec![
            Interface {
                name: "wlan0".into(),
                addr: "192.168.1.10".parse().unwrap(),
                netmask: "255.255.255.0".parse().unwrap(),
                prefix: 24,
                broadcast: None,
                loopback: false,
            },
            Interface {
                name: "lo".into(),
                addr: "127.0.0.1".parse().unwrap(),
                netmask: "255.0.0.0".parse().unwrap(),
                prefix: 8,
                broadcast: None,
                loopback: true,
            },
        ];
        let out = format_interfaces(&ifaces);
        assert!(
            out.contains("wlan0") && out.contains("192.168.1.10"),
            "{out}"
        );
        assert!(out.contains("lo") && out.contains("127.0.0.1"), "{out}");
        assert!(out.contains("192.168.1.0"), "network column: {out}");
    }
}
