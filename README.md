# NetPeek

**NetPeek** is a high-performance, modular network scanner written in C. It is designed for fast port scanning, service probing, OS fingerprinting, and extensible scripting via its built-in **NPE (NetPeek Probe Engine)**.

NetPeek focuses on speed, flexibility, and clean architecture, making it suitable both as a practical scanning tool and as a research and learning codebase for network reconnaissance techniques.

---

## Key Features

- TCP connect scanning
- TCP SYN scanning (raw packets, requires root privileges)
- UDP scanning
- CIDR expansion and hostname resolution
- Multi-threaded and multi-worker execution model
- OS fingerprinting and detection
- Scriptable probing engine (NPE)
- Proxy support (SOCKS5 / HTTP)
- Multiple output formats: human-readable, JSON, CSV, grepable
- Clean separation between CLI, runtime, scanner, and recon-output layers

---

## Project Structure

```text
.
├── include/                # Public and internal headers
│   ├── evasion/            # Scan evasion techniques
│   ├── npe/                # NPE scripting engine headers
│   ├── npe_lib/            # Built-in NPE libraries
│   ├── npe_proto/          # Protocol helpers for NPE
│   ├── os_detect/          # OS fingerprinting
│   ├── recon/              # Recon output interfaces + graph/query APIs
│   ├── ui/                 # Shared terminal style constants/helpers
│   ├── packet/             # Raw packet building/parsing
│   ├── runtime/            # Threading, workers, queues
│   └── scanner/            # Scan engines
│
├── src/                    # Implementation
│   ├── cli/                # Command-line interface and commands
│   ├── evasion/            # Evasion logic
│   ├── npe/                # NPE engine core
│   ├── npe_lib/            # Built-in NPE scripts
│   ├── npe_proto/          # Protocol bindings
│   ├── os_detect/          # OS detection implementation
│   ├── recon/              # Recon output writers + pipeline
│   ├── runtime/            # Scheduler, threads, workers
│   └── scanner/            # TCP/UDP/SYN scanners
│
├── scripts/                # NPE scripts
│   ├── auth/
│   ├── default/
│   ├── discovery/
│   ├── intrusive/
│   ├── safe/
│   └── vuln/
│
├── utils/                  # Shared helpers and utilities
├── docs/                   # Documentation and notes
├── build/                  # Build artifacts (generated)
├── Makefile                # Build system
└── README.md
```

---

## Requirements

NetPeek depends on several system libraries:

- C compiler: GCC or Clang (C11 compatible)
- libpcap
- Lua 5.4 or newer (system-installed, not bundled)
- OpenSSL (required)
- PCRE2
- libssh2
- pthread

Dependency detection supports Homebrew on macOS and standard system paths on Linux.

---

## Build

Clone the repository and build using `make`:

```bash
make
```

Common targets:

```bash
make            # Build NetPeek
make clean      # Remove build artifacts
make rebuild    # Clean and rebuild
```

The resulting binary is placed in:

```text
build/bin/netpeek
```

---

## Getting Started

Run NetPeek without arguments to display the built-in help:

```bash
./build/bin/netpeek
```

General usage pattern:

```text
netpeek <command> [options] <target> [target ...]
```

Available commands:

- `scan`        – Port scanning (default)
- `npe`         – NPE scripting engine
- `os-detect`   – OS fingerprinting (requires sudo/root)
- `os`          – Alias for `os-detect`
- `subenum`     – Subdomain enumeration and discovery
- `dns`         – Compatibility alias for subdomain enumeration
- `diff`        – Compare two JSON scan outputs
- `route`       – Traceroute then scan open ports on each hop
- `help`        – Show help information
- `version`     – Show version information

Help invocation patterns:

- `netpeek --help`
- `netpeek -h`
- `netpeek help <command>`
- `netpeek <command> --help`
- `netpeek <command> help`

---

## Scan Command

### TARGET SPECIFICATION

Can pass hostnames, IP addresses, networks, etc.
Ex: scanme.nmap.org, microsoft.com/24, 192.168.0.1; 10.0.0-255.1-254
-iL <inputfilename>: Input from list of hosts/networks
-iR <num hosts>: Choose random targets
--exclude <host1[,host2][,host3],...>: Exclude hosts/networks
--excludefile <exclude_file>: Exclude list from file

### Core Options

- `-t, --target <host>`      Target host (repeatable)
- `-p, --ports <list>`       Port list or range (e.g. `80`, `80,443`, `1-1000`, `-`)
- `-T, --threads <n>`        Number of threads
- `-W, --workers <n>`        Number of worker processes
- `--timeout <ms>`           Timeout per probe in milliseconds
- `--timing-template <0-5>`  Timing profile presets (Nmap-like)
- `--fast`                   Nmap-style fast UDP profile (`-T4`, drop filtered, threads=`NCPU`)
- `--min-hostgroup <size>`   Minimum parallel host scan group size
- `--max-hostgroup <size>`   Maximum parallel host scan group size
- `--min-parallelism <n>`    Minimum per-host probe parallelism
- `--max-parallelism <n>`    Maximum per-host probe parallelism
- `--min-rtt-timeout <time>` Minimum probe RTT timeout
- `--max-rtt-timeout <time>` Maximum probe RTT timeout
- `--initial-rtt-timeout <time>` Initial probe RTT timeout
- `--host-timeout <time>`    Give up on target after this long
- `--scan-delay <time>`      Delay between probes
- `--max-scan-delay <time>`  Maximum delay between probes
- `--min-rate <number>`      Send packets no slower than this pps
- `--max-rate <number>`      Send packets no faster than this pps
- `--max-retries <tries>`    Cap number of probe retransmissions
- `--proxy <url>`            Route traffic through a proxy
- `-sV`                      Probe discovered ports for service/version info
- `--version-intensity <0-9>` Set version probe intensity
- `--version-light`          Most likely probes only (intensity 2)
- `--version-all`            Try all probes (intensity 9)
- `--version-trace`          Show detailed version scan activity

### Host Discovery

- `-sL`                       List targets only
- `-sn`                       Ping scan only (no port scan)
- `-Pn`                       Treat all hosts as online
- `-PS/PA/PU/PY[portlist]`    TCP SYN/ACK, UDP, SCTP discovery probes
- `-PE/PP/PM`                 ICMP echo/timestamp/netmask probes
- `-PO[protocol list]`        IP protocol ping
- `-n/-R`                     Never/Always DNS resolution
- `--dns-servers <list>`      Custom DNS servers (comma-separated)
- `--system-dns`              Force OS resolver
- `--traceroute`              Trace hop path to each host

### Timing/Performance Time Format

- `<time>` accepts values in seconds by default.
- Optional suffixes: `ms` (milliseconds), `s` (seconds), `m` (minutes), `h` (hours).
- Examples: `250ms`, `2s`, `1m`, `1h`, `30`.

### Scan Technique Matrix

| Technique | Flags | Packet Style | Typical Result Semantics | Privileges |
|---|---|---|---|---|
| TCP SYN | `-sS`, `--syn` | TCP SYN | `open` on SYN/ACK, `closed` on RST, `filtered` on timeout | root/raw |
| TCP Connect | `-sT`, `--connect` | OS `connect()` | `open`/`closed`/`filtered` by socket outcome | user |
| TCP ACK | `-sA`, `--ack` | TCP ACK | RST indicates reachable path (`unfiltered`-like), timeout indicates filtered | root/raw |
| TCP Window | `-sW`, `--window` | TCP ACK + window analysis | RST window heuristics + timeout filtered | root/raw |
| TCP Maimon | `-sM`, `--maimon` | FIN/ACK | RST usually `closed`, no reply often `open|filtered` | root/raw |
| UDP | `-sU`, `--udp` | UDP probe | `open`, `closed`, or `filtered/open|filtered` | user |
| TCP Null | `-sN`, `--null` | No TCP flags | RST `closed`, no reply `open|filtered` | root/raw |
| TCP FIN | `-sF`, `--fin` | FIN | RST `closed`, no reply `open|filtered` | root/raw |
| TCP Xmas | `-sX`, `--xmas` | FIN+PSH+URG | RST `closed`, no reply `open|filtered` | root/raw |
| Custom TCP | `--scanflags <flags>` | User-defined TCP flags | Technique-dependent; use with caution | root/raw |
| Idle Scan | `-sI <zombie[:probeport]>` | Zombie IPID side-channel | Implemented engine task with zombie IPID delta analysis | root/raw |
| SCTP INIT | `-sY`, `--sctp-init` | SCTP INIT | Implemented SCTP probe task | root/raw |
| SCTP COOKIE-ECHO | `-sZ`, `--sctp-cookie` | SCTP COOKIE-ECHO | Implemented SCTP probe task | root/raw |
| IP Protocol | `-sO`, `--ip-proto` | Raw IP protocol probes | Implemented protocol probe task (0-255) | root/raw |

### `--scanflags` Format

- Symbolic list: `syn,ack`, `fin,psh,urg`, `ack,rst`
- Numeric mask: `0x12`, `18`, `0x29`
- Supported names: `fin,syn,rst,psh,ack,urg,ece,cwr`

### Output Options

- `-o, --output <file>`      Write results to file
- `--json`                   JSON output
- `--csv`                    CSV output
- `--grep`                   Grep-friendly output
- `--xml <file>`             XML output file (Nmap-style schema)
- `--html <file>`            Self-contained HTML report
- `-oX <file>`               Short alias for XML output
- `--show-closed`            Include closed ports in output (default output is open-only)

---

## Examples

Basic TCP scan:

```bash
netpeek scan 192.168.1.1
```

Scan specific ports:

```bash
netpeek scan example.com -p 80,443
```

Full port TCP SYN scan:

```bash
sudo netpeek scan 10.0.0.0/24 -p - --syn
```

UDP scan with JSON output:

```bash
netpeek scan 192.168.1.1 -p 53 --udp --json
```

ACK scan:

```bash
sudo netpeek scan 192.168.1.10 -p 22,80 -sA
```

Null/FIN/Xmas scans:

```bash
sudo netpeek scan 192.168.1.10 -p 1-1024 -sN
sudo netpeek scan 192.168.1.10 -p 1-1024 -sF
sudo netpeek scan 192.168.1.10 -p 1-1024 -sX
```

Custom scan flags:

```bash
sudo netpeek scan 192.168.1.10 -p 443 --scanflags syn,ack
sudo netpeek scan 192.168.1.10 -p 443 --scanflags 0x12
```

Service/version detection:

```bash
netpeek scan 192.168.1.10 -p 22,80,443 -sV
netpeek scan 192.168.1.10 -p 1-1024 -sV --version-light
netpeek scan 192.168.1.10 -p 1-1024 -sV --version-all --version-trace
```

Without `-sV`, output formats omit per-port version fields/columns.

Host discovery:

```bash
netpeek scan 10.0.0.0/24 -sL
netpeek scan 10.0.0.0/24 -sn
netpeek scan 10.0.0.0/24 -sn -PS22,80,443
netpeek scan scanme.nmap.org -Pn -p 1-1024 --traceroute
```

Route mapping + hop scanning:

```bash
sudo netpeek route scanme.nmap.org -p 22,80,443
sudo netpeek route scanme.nmap.org --json -o route.json
```

---

## OS Detection

Detect the operating system of a target host:

```bash
sudo netpeek os-detect -t 192.168.1.1 -p 22 -v
```

Note: NetPeek enforces effective UID 0 for root-required scan modes/probes and for `os-detect`.

OS-detect flags:

- `-t, --target <host>` target hostname or IPv4
- `-p, --port <port>` target TCP port
- `-s, --sigfile <path>` external signature file
- `-B, --builtin` use compiled-in signatures only
- `-o, --output <file>` write output to file
- `--json` JSON output
- `--csv` CSV output
- `-v, --verbose` verbose fingerprint details
- `-h, --help` command help

Tip: `netpeek help os-detect` and `netpeek help os` show the same command help.

---

## Recon UX Presets

`netpeek recon` supports modern host-centric terminal output with style presets:

```bash
netpeek recon run -t 10.0.0.0/24 -sS --style modern
```

Useful recon output flags:

- `--style classic|modern|compact|json|report`
- `--format text|json|md|html|xml|sarif|diff`
- `--output text|json|md|html|xml|sarif|diff` (alias for `--format`)
- `--out <file>` output path (`.json/.txt/.md/.html/.xml/.sarif/.diff` auto-select format)
- `--compact` compact one-line service display
- `--evidence` expand evidence sources
- `--verbose` expanded evidence/details
- `--summary-only` summary footer only
- `--no-color` disable ANSI colors
- `--recon-serial` force serial module execution (disable dependency-parallel scheduler)
- `--recon-workers <n>` cap recon module scheduler workers (default auto from CPU)

Execution precedence for recon scheduler workers:

1. `--recon-serial` forces 1 worker
2. `--recon-workers <n>` caps worker count
3. CPU auto worker sizing

`recon analyze` now includes an Analyze Graph section with module timeline,
OS distribution, and service-version coverage.

`recon analyze` executes both a TCP enumeration pass and a UDP enumeration pass
(UDP uses the built-in top 1000 UDP ports).

Format precedence for recon output:

1. `--format` (or `--output`) explicit value
2. `--out` extension mapping
3. default `text`

Recon diff also supports a git-like human view for recon JSON outputs:

```bash
netpeek recon diff old-recon.json new-recon.json
```

---

## Diff Command

Compare two NetPeek JSON scan outputs:

```bash
netpeek diff scan-old.json scan-new.json
```

Diff flags:

- `-j, --json` print structured diff JSON to stdout
- `--html <file>` alias for `--format html --out <file>`
- `--format text|json|md|html|xml|sarif|diff`
- `--out <file>` output path (extension auto-selects format)
- `-h, --help` command help

---

## NPE (NetPeek Probe Engine)

NPE is NetPeek’s embedded scripting and probing engine, designed for advanced service discovery and vulnerability checks.

List NPE options:

```bash
netpeek npe --help
```

NPE flags:

- `-s, --script <expr>` script expression (**required**)
- `-H, --script-help` script listing/help mode
- `-t, --target <host>` target host (repeatable)
- `-p, --ports <port>` single target port (default `80`)
- `-j, --json` JSON output
- `-v, --verbose` verbose logging
- `-h, --help` command help

Run an NPE script:

```bash
netpeek npe --script banner-grab -t 192.168.1.10 -p 22
```

Scripts are organized under the `scripts/` directory by category (safe, intrusive, vuln, etc.).

### Auth brute scripts

NetPeek includes intrusive auth brute scripts in `scripts/auth/`:

- `ssh-brute`
- `ftp-brute`
- `http-brute`
- `mysql-brute`
- `redis-brute`
- `smtp-brute`

These scripts require explicit credentials input via `--script-args`.

Example:

```bash
netpeek npe --script ssh-brute -t 192.168.1.10 -p 22 --script-args usernames=admin,root,passwords=admin,123456
```

### Vulnerability scripts

NetPeek includes vulnerability-focused scripts in `scripts/vuln/`:

- `ssl-heartbleed` (CVE-2014-0160)
- `ssl-poodle` (CVE-2014-3566)
- `ssl-ccs-injection` (CVE-2014-0224)
- `http-shellshock` (CVE-2014-6271)
- `http-log4shell` (CVE-2021-44228)
- `smb-ms17-010` (MS17-010)
- `http-vuln-cve` (generic HTTP CVE fingerprinting)

These scripts use active probes and should only be run against systems you are authorized to test.

Example:

```bash
netpeek npe --script vuln -t 192.168.1.10 -p 80,443,445
```

---

## Development Notes

- CLI logic is implemented in `src/cli/`
- Scanner implementations live in `src/scanner/`
- Keep CLI flags, runtime configuration, and help output in sync
- New scan types should integrate via existing scanner abstractions
- NPE extensions should prefer reusable protocol helpers

---

## Disclaimer

NetPeek is intended for **authorized security testing and research only**.
Do not use this tool against systems or networks without explicit permission.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

