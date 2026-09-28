# ipscan

Find out who is on your network, quickly, without asking for root.

`ipscan` sweeps a range of IPv4 addresses and tells you which ones are actually
in use, then tries to tell you *what* they are. On a `/24` it takes about three
seconds, and it needs no privileges on Linux.

```
$ ipscan
IP             MAC                PORT      RTT  TTL  METHOD
192.168.0.1    f0:09:0d:2a:86:fd     80    2.12 ms  64   icmp
192.168.0.11   5c:49:7d:f1:14:0d    445    1.96 ms  64   icmp
192.168.0.79  -                      -    0.81 ms  64   icmp
192.168.0.90  1a:28:61:34:77:4a   8080   92.04 ms  64   icmp

3 hosts found out of 256 addresses scanned in 2.98s via wlp0s20f3
```

## A timeout does not mean a machine is dead

This is the part that separates a scanner from a coin flip. Three outcomes are
reported, not two:

| Outcome | Meaning | Evidence |
|---|---|---|
| `alive` | It answered an echo, or accepted a connection. | Unambiguous. |
| `filtered` | It sent back a reset, or an ICMP unreachable. | Unambiguous: something is there and refusing us. |
| `silent` | Nothing came back. | **No evidence either way.** |

`silent` is never counted as a dead host. A firewall, a sleeping laptop, and an
empty IP address all look identical from outside, and pretending otherwise is
how you end up power-cycling a machine that was fine.

## How it probes

Cheapest and most conclusive method first, and each stage only runs against the
addresses the previous one could not settle:

1. **ARP** — settles the whole local subnet in one shot. Needs `CAP_NET_RAW`, so
   it is skipped with a note rather than a failure when unprivileged.
2. **ICMP echo** — one unprivileged datagram socket, one `sendto` per target,
   all replies read from a single socket.
3. **TCP connect** — only for addresses nothing has answered for yet. A
   connection that is accepted is `alive`; one that is reset is `filtered`,
   because a refused connection still proves the host exists.

Hardware addresses come from the kernel's neighbour table, read both before the
sweep (to prioritise addresses that answered recently) and after it (to attach
MACs to hosts the scan itself resolved).

## Install

### Prebuilt binaries

Grab a release archive for your platform from
[the releases page](https://github.com/GordonCopestake/ipscan/releases),
unpack it, and put `ipscan` on your `PATH`. No runtime or build tools needed.

| Platform | File |
|---|---|
| Linux x86-64 | `ipscan-v0.2.3-x86_64-unknown-linux-gnu.tar.gz` |
| Windows x86-64 | `ipscan-v0.2.3-x86_64-pc-windows-msvc.zip` |

Each archive ships a `.sha256` file next to it. On Linux, verify before running:

```
sha256sum -c ipscan-v0.2.3-x86_64-unknown-linux-gnu.tar.gz.sha256
```

macOS and arm64 Linux builds are not published as binaries; build from source
there, or use a package manager.

### Building from source

You need the [Rust toolchain](https://rustup.rs); edition 2024 means **1.85 or
newer**. On Debian/Ubuntu that is `apt install build-essential`, plus `pkg-config`
if you would rather let the linker find system libraries. No other dependencies:
everything else comes from crates.io.

```
git clone https://github.com/GordonCopestake/ipscan.git
cd ipscan

# a debug build for hacking on
cargo build

# an optimised build, which is what you want to run
cargo build --release

# the binary lands at target/release/ipscan
./target/release/ipscan --help
```

Or install it onto your system, which puts `ipscan` in `~/.cargo/bin`:

```
cargo install --path .
```

To check the build before trusting it:

```
cargo test          # 81 unit tests
cargo clippy --all-targets
```

Cross-compiling to another platform needs that platform's target and linker,
so it is usually easier to let the release workflow do it. To type-check a
target without producing a runnable binary:

```
rustup target add x86_64-pc-windows-msvc
cargo check --target x86_64-pc-windows-msvc
```

## Usage

Scan your own subnet:

```
ipscan
```

A scan prints what it is about to do, and how each phase is getting on, before
and while it runs. On a subnet full of machines that never answer, several probe
methods spend real time blocked inside the operating system, so silence would
be indistinguishable from a crash:

```
ipscan 0.2.3
  target      192.168.0.0/24
  interface   eth0 (192.168.0.79/24)
  addresses   256
  method      auto (arp, then icmp, then tcp)
  timeout     1000ms, 1 retry
  ports       80, 443, 22, 445, 3389, 8080

reading the neighbour cache...
  neighbour cache: 25 entries in 0.0s
probing 256 on-link addresses with arp...
  arp: waiting, 2s elapsed
  arp: 4 alive of 256 in 6.1s
probing 252 addresses with icmp...
  via unprivileged datagram (no privileges needed)
  icmp: 12 answered of 252 in 4.2s
icmp gave no answer for 240 addresses, trying tcp...
  tcp: 6 answered of 1440 connects in 1.4s
done: 18 hosts in 11.7s
```

That goes to **stderr**, so machine-readable output stays clean when it is
redirected or piped. It appears by default only when stderr is a terminal; use
`--verbose` to keep it in a log or a CI step, and `--quiet` to silence it.

Scan anything:

```
ipscan 192.168.1.0/24          # a network
ipscan 10.0.0.5                # one address
ipscan 10.0.0.1-254            # a range
ipscan 10.0.0.1,10.0.0.9       # a list
ipscan 10.0.0.0/24 172.16.0.0/16
```

A CIDR names a network block, and on any block wider than a point-to-point link
the first and last addresses are the network and broadcast addresses rather than
hosts. Those are skipped, as every mainstream scanner does: `ipscan
192.168.1.0/24` probes 254 addresses. It matters because the broadcast address
draws a reply from everything on the segment and the network address from the
gateway, and reporting either as a live machine is simply wrong. `/31` and `/32`
are exempt — `/31` has two usable endpoints under RFC 3021, and `/32` is a host.

Ranges, wildcards and bare addresses are taken literally: `ipscan
192.168.1.1-255` really does include `.255`, because you asked for it by name.

Pick the interface, the ports, or the method:

```
ipscan -i eth0                  # force the interface and its subnet
ipscan -p 22,80,443             # probe these ports on every live host
ipscan -m icmp                  # skip ARP and TCP entirely
ipscan --timeout 500 --retries 0
```

Choose an output format, and where it goes:

```
ipscan -f table                 # aligned columns (default)
ipscan -f wide                  # adds hostname
ipscan -f json -o report.json
ipscan -f jsonl | jq .ip        # one object per line
ipscan -f csv -o hosts.csv
ipscan -f bare | while read ip; do ...; done
ipscan -f md                    # a markdown table
```

Other useful flags:

```
ipscan -L                       # list interfaces and their subnets
ipscan --dns                    # reverse-resolve (slower)
ipscan --cached                 # also show addresses only the OS cache knows
ipscan --strict                 # list only hosts with a known hardware address
ipscan --sort rtt               # order by latency, ip, or hostname
ipscan -q                       # no summary line
ipscan -v                       # per-stage progress and notes
```

`ipscan --help` has the full list.

## Privileges

On Linux, active ARP needs `CAP_NET_RAW` and everything else does not. Without it
you still get a full scan from ICMP and TCP, plus MACs for any address the
kernel happens to have resolved; `ipscan -v` says so explicitly rather than
failing.

## Platforms

Linux, macOS, and Windows are supported. ICMP uses an unprivileged datagram
socket on Unix and `IcmpSendEcho2` on Windows, ARP uses `AF_PACKET` on Linux and
`SendARP` on Windows, and the neighbour table is read from `/proc/net/arp`,
`arp -n`, or `GetIpNetTable` respectively.

Some platform APIs are synchronous per target and have no timeout of their own,
so a probe built on them cannot overlap requests the way an event loop can.
`ipscan` runs those across a bounded pool of worker threads rather than in a
loop, and reports elapsed time while they run, so a Windows scan of a sparse
subnet takes seconds instead of minutes. The cap is deliberate: thread-per-
request means a thread and a stack per in-flight target, so a large
`--concurrency` is clamped on these paths rather than taken literally.

### Proxy-ARP will lie to you

One hardware address answering for most of a subnet is not a crowd of machines;
it is one device answering for a range it merely routes. A router with
proxy-ARP enabled, a hypervisor switch, or a NAC appliance all reply to ARP on
behalf of addresses they do not host. Each reply is a real, successful exchange,
so a sweep that reads "the exchange succeeded" as "a host is there" reports the
whole routed range as a room full of machines.

Real hosts have distinct MACs, so `ipscan` keeps the hardware address that
`SendARP` returns and says so when one address accounts for a majority of the
replies:

```
probing 254 on-link addresses with arp...
  warning: 119 of 119 arp replies came from the single hardware address
  aa:bb:cc:dd:ee:ff, which is proxy-arp: one device answering for a range it
  routes rather than 119 separate hosts
```

Treat such addresses as *routed*, not *present*. If you need a trustworthy host
count on a proxied segment, ARP cannot give you one.

### So can a device that answers ping for others

Yes, and it is harder to catch than proxy-ARP, because it forges the source
address correctly. Something answering echo for a range it only routes produces
a perfect `IP_SUCCESS` from the address you asked, so there is nothing in the
reply to distrust.

The contradiction is one level up. Answering ICMP on a directly-attached link
requires having resolved the target's hardware address first, so a host that
answers echo on your own subnet has necessarily been resolved. If ARP did not
name it and ICMP claims it anyway, one of those is wrong. The round-trip times
settle which: real hosts on one link answer in well under a millisecond and
scatter, while one responder has a single periodic cycle, so its answers land in
a handful of buckets. A sweep where most live hosts have a dash in the MAC
column and their RTTs span a suspiciously narrow range is that, and `ipscan`
says so:

```
warning: 136 of the 254 live hosts cannot be attributed to a device: arp did not
name them ... Their round-trip times span 758ms to 1002ms, which is the signature
of a single periodic responder rather than 136 separate machines. Only the 118
hosts arp named should be counted as a host census; treat the rest as unverified.
```

The warning is deliberately quiet about a handful of unnamed hosts. A busy
machine that dropped one ARP reply is ordinary, and a warning that fires on
ordinary noise teaches you to ignore the warning that matters.

Every address that answered is listed. Finding alive hosts is the tool's job,
and a host that answered is a host -- a VM behind a virtual switch is a real
machine whether or not the sweep managed to name it. The hardware address is a
bonus, not a qualification, so its absence never hides a responder.

`--strict` is the opt-in to the other question. It lists only hosts with a
known hardware address, which is what you want when you are counting *devices*
rather than detecting liveness -- on a segment where something answers echo for a
range it merely routes, a liveness census and a device census are not the same
number. Addresses hidden this way are always counted in the summary, so a shorter
list is never mistaken for the whole sweep, and `--include-unverified` lists them
alongside the rest.

Loopback and off-link addresses are exempt from `--strict` either way. A packet
to `127.0.0.0/8` never reaches a wire, so ARP could not have named it, and
demanding a hardware address there demands the impossible.

### Asking the cache again, because a sweep loses replies

Sweeping a few hundred addresses at once saturates the reply path, and a real
machine that loses its ARP reply is then indistinguishable from an address nothing
owns. So after probing, the neighbour cache is read a second time and any address
that still has no hardware address is looked up in it.

That is nearly free, and it is not redundant. To send an echo to a host on our own
link the stack has to resolve it first, so a host that answered at all has a
hardware address in the cache by the end of the scan — including the ones the
concurrent sweep dropped. On a real Windows scan this recovered a host that
`arp -a` had and the sweep had not, which is the difference between a census of 115
and one of 116.

It only ever adds attribution, never removes it. A direct ARP reply is stronger
evidence than a cache entry, so a known address is never overwritten, and an
address nothing owns has no entry to be found in. There is no reason to switch it
off, so there is no switch.

The warning that used to say "Only the 0 hosts arp named should be counted"
was wrong on any platform where the active sweep cannot run. On Linux without
CAP_NET_RAW the neighbour table is the only source of hardware addresses, so
a scan that printed a column full of addresses would then accuse its own
output. Attribution is now "a hardware address is known", not "the active
sweep said so". A zero address still counts as nothing, because an entry the
OS never finished resolving is not a device.

The single-responder claim is now conditional. Round-trip times that bunch
together (within a factor of two) are reported as what one device replying on
a schedule looks like. Times that spread wider are reported as what real
machines at different distances produce -- which is evidence the ghosts are
*not* a single device, and the warning says so.

### `-p` now means "probe these ports on every live host"

The cascade only spends a TCP connect on addresses nothing else answered for,
which is what makes it cheap and is the right behaviour when the question is "who
is here". But `-p 80,443` is a question about those ports, and "ARP already found
this host" is not an answer to it. So naming ports includes the hosts already
known to be alive:

```
ipscan -p 80,443 192.168.1.0/24     # probes both ports on every live host
ipscan 192.168.1.0/24               # probes ports only where nothing else answered
```

Addresses already shown to be dead are still skipped either way. Naming ports
never turns into spending connects on addresses that have proved empty.

Every open port is listed, not just the first one to answer. A host with 80, 443
and 22 open is reported as `80,22,443`: retiring a target after its first
conclusive answer made the column a sample of the host's services rather than a
list of them. A refused connection proves the host is there but that the port is
*not* open, so it is proof of life rather than a service and is not listed.

### ARP cache reuse avoids redundant probes

The neighbour table is read at the start of every scan. If it already contains a
valid hardware address for a target, the active ARP sweep skips that target --
the cache entry is fresher than any reply a new request would get, and the late
attribution pass will copy it in. On Windows where `SendARP` has a fixed internal
timeout, this can cut the ARP phase from ~13 s to ~1 s on a /24.

### Faster default timeout

The default probe timeout is now 500 ms (was 1000 ms). With the default one
retry this halves the worst-case time for non-responders from 2 s to 1 s.
Restore the old behaviour with `--timeout 1000`.

### `-p` is a question about ports, not a fallback

The cascade only spends a TCP connect on addresses nothing else answered for,
which is what makes it cheap and is the right behaviour when the question is "who
is here". But `-p 80,443` is a question about those ports, and "ARP already found
this host" is not an answer to it. So naming ports includes the hosts already
known to be alive:

```
ipscan -p 80,443 192.168.1.0/24     # probes both ports on every live host
ipscan 192.168.1.0/24               # probes ports only where nothing else answered
```

Addresses already shown to be dead are still skipped either way. Naming ports
never turns into spending connects on addresses that have proved empty.

## Licence

MIT or Apache-2.0, at your option.
