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
