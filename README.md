# Simple TCP Port Scanner

A lightweight, multithreaded TCP port scanner written in Python. Built as a
hands-on project to learn the fundamentals of network programming and how
tools like Nmap work under the hood.

## What It Does

- Scans a target host (IP or hostname) across a range or list of TCP ports
- Uses multithreading to scan many ports concurrently instead of one at a time
- Attempts to grab service banners on open ports (e.g. server headers,
  greeting strings) to help identify what's running
- Reports total scan time and a summary of open ports

## Why I Built This

I wanted to understand what network scanning tools are actually doing
under the hood rather than just running `nmap` as a black box. Building
this from scratch covers:

- **Socket programming** — how TCP connections are actually established
  (`connect_ex`, timeouts, error handling)
- **Concurrency** — why naive sequential scanning is too slow for real
  use, and how a thread pool + queue pattern solves that
- **Reconnaissance fundamentals** — the first step of any penetration
  test or security assessment is mapping what's exposed on a target

## How It Works

1. The target hostname is resolved to an IP address via DNS
2. The requested ports are loaded into a thread-safe queue
3. A pool of worker threads pulls ports off the queue and attempts a TCP
   connection to each one
4. If a connection succeeds, the port is marked open, and the scanner
   tries to read the first bytes returned (a banner) before closing
5. Results are collected and printed once every port has been checked

## Usage

```bash
# Scan default range (1-1024) with default settings
python3 port_scanner.py <target>

# Scan a specific range
python3 port_scanner.py <target> -p 1-65535

# Scan specific ports, or a mix of ranges and specific ports
python3 port_scanner.py <target> -p 22,80,443
python3 port_scanner.py <target> -p 20-25,80,443

# Tune thread count and timeout
python3 port_scanner.py <target> -t 200 --timeout 1.0
```

### Example Output

```
=======================================================
 Target        : scanme.nmap.org (45.33.32.156)
 Port range    : 1-1024  (1024 ports)
 Threads       : 100
 Started at    : 2026-08-31 09:12:03
=======================================================
[+] Port    22 OPEN   | SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
[+] Port    80 OPEN   | No banner
=======================================================
 Scan complete in 4.31 seconds
 Open ports found: 2
   - 22: SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
   - 80: No banner
=======================================================
```

## Requirements

- Python 3.6+
- No external dependencies — uses only the Python standard library
  (`socket`, `threading`, `queue`, `argparse`)

## Possible Improvements (Next Steps)

- Add UDP scanning support
- Export results to JSON/CSV for reporting
- Add service/version fingerprinting beyond raw banner grabs
- Add a stealth SYN scan mode using raw sockets (requires root)
- Progress bar for large port ranges

## ⚠️ Legal & Ethical Use

Port scanning systems you do not own or do not have explicit written
permission to test is illegal in most jurisdictions (e.g. under the UK
Computer Misuse Act or the US Computer Fraud and Abuse Act) and can
result in serious consequences.

Only run this tool against:
- Systems you own
- Systems you have explicit written authorization to test
- Legal public test targets, e.g. `scanme.nmap.org` (maintained by the
  Nmap project specifically for this purpose)

This project was built and tested only against `localhost` and
`scanme.nmap.org`.
