use std::io::Write as _;
use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;

use ipscan::cli::{Cli, format_interfaces};
use ipscan::output;

/// Exit codes.
const EXIT_OK: u8 = 0;
const EXIT_ERROR: u8 = 1;

fn main() -> ExitCode {
    match real_main() {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            // Chain formatting keeps the root cause visible without a
            // backtrace for what are usually user-input errors.
            eprintln!("ipscan: {e:#}");
            ExitCode::from(EXIT_ERROR)
        }
    }
}

fn real_main() -> Result<u8> {
    let cli = Cli::parse();

    if cli.list_interfaces {
        print!("{}", format_interfaces(&ipscan::net::list()?));
        return Ok(EXIT_OK);
    }

    let iface = cli.resolve_interface()?;
    let targets = cli.resolve_targets(iface.as_ref())?;

    // Fail before spending a single packet, rather than partway through.
    let size = targets.len();
    if size > cli.max_hosts {
        anyhow::bail!(
            "refusing to probe {size} addresses, over the limit of {}. \
             Narrow the target, or raise the limit with --max-hosts {}.",
            cli.max_hosts,
            cli.max_hosts
        );
    }

    let plan = cli.to_plan(targets, iface);

    // Say what is about to happen *before* the first packet. A scan of a real
    // subnet spends a long time inside blocking operating-system calls, and
    // until it printed the first line the process was indistinguishable from
    // one that had wedged. This goes to stderr, so redirecting stdout to a file
    // or a pipe still yields clean machine-readable output.
    if plan.progress {
        banner(&plan);
    }

    let report = ipscan::scan::run(&plan)?;

    // The same renderer serves stdout and files, so `-o` and `-f` always agree.
    let to_stdout = cli.output.is_none();
    let opts = cli.to_output_options(to_stdout);
    let text = output::render(&report, &opts)?;

    match &cli.output {
        Some(path) => {
            std::fs::write(path, &text)
                .map_err(|e| anyhow::anyhow!("writing {}: {e}", path.display()))?;
            if !cli.quiet {
                eprintln!("wrote {} hosts to {}", report.hosts.len(), path.display());
            }
        }
        None => {
            let mut out = std::io::stdout().lock();
            out.write_all(text.as_bytes())?;
            out.flush()?;
        }
    }

    Ok(EXIT_OK)
}

/// Print the plan before it runs, so the user can see the shape of the job and
/// abort it early if it is not what they meant.
fn banner(plan: &ipscan::scan::ScanPlan) {
    use ipscan::scan::MethodChoice;

    let ports = plan
        .config
        .ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(", ");

    let method = match plan.method {
        MethodChoice::Auto => "auto (arp, then icmp, then tcp)",
        MethodChoice::Arp => "arp only",
        MethodChoice::Icmp => "icmp only",
        MethodChoice::Tcp => "tcp only",
    };

    eprintln!("ipscan {}", env!("CARGO_PKG_VERSION"));
    eprintln!("  target      {}", plan.targets.spec());
    match &plan.interface {
        Some(i) => eprintln!("  interface   {} ({}/{})", i.name, i.addr, i.prefix),
        None => eprintln!("  interface   none detected"),
    }
    eprintln!("  addresses   {}", plan.targets.len());
    eprintln!("  method      {method}");
    eprintln!(
        "  timeout     {}ms, {} retr{}",
        plan.config.timeout.as_millis(),
        plan.config.retries,
        if plan.config.retries == 1 { "y" } else { "ies" }
    );
    eprintln!("  ports       {ports}");
    if plan.resolve_hostnames {
        eprintln!("  hostnames   reverse-resolving enabled");
    }
    eprintln!();
}
