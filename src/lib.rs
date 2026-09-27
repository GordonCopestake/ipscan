//! `ipscan` — find alive hosts on the local network.
//!
//! The crate is split so the interesting logic is testable without a network:
//! [`target`] parses what to scan, [`probe`] talks to hosts, [`scan`] decides
//! what order to talk to them in, and [`output`] renders the result.
//! [`dns`] holds the reverse lookups, which need a syscall per platform.

pub mod cli;
pub mod dns;
pub mod host;
pub mod net;
pub mod output;
pub mod probe;
pub mod scan;
pub mod target;
