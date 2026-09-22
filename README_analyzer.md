# Simple Log File Analyzer

A Python tool that parses connection logs and flags suspicious patterns
— built specifically to read the logs produced by my
[TCP Listener / Mini Honeypot](../simple-port-scanner) project. This is
the "analyst" piece that closes the loop with my other two projects:
the port scanner probes, the listener logs what happened, and this
tool is the step where the logged data actually gets interpreted.

## What It Does

- Parses timestamped connection log entries (IP, port, time)
- Groups activity by source IP
- Flags any IP making an unusually high number of connections within
  a short time window — a common signature of port scanning or
  brute-force attempts, as opposed to normal, occasional human traffic
- Surfaces any data sent by connecting clients (e.g. attempted
  usernames/passwords against a fake login banner)
- Prints a clear summary report: total connections, unique IPs, top
  offenders, and a flagged/clean verdict

## Why I Built This

This is the core skill behind SOC (Security Operations Center) analyst
work: a SIEM tool (Splunk, Wazuh, etc.) collects logs at scale, but a
human still has to interpret what the data means and decide whether
it's a real threat or noise. Building a small version of that logic
from scratch — rather than just using a pre-built tool — helped me
understand:

- **Log parsing with regex** — real logs are just structured text;
  learning to reliably extract fields from them is a foundational
  analyst skill
- **Baseline vs anomaly thinking** — the core of detection isn't
  "is this activity bad," it's "is this different from normal,"
  which is why the tool flags *rate* of connections, not just their
  existence
- **The full attack-to-detection lifecycle** — I can generate real
  log data myself (scan my own listener with my own port scanner),
  then analyze what got logged, understanding both the offensive and
  defensive side of the same event

## How It Works

1. Reads the log file line by line
2. Uses regex to match two line types: connection events and
   received-data events (matching the exact format `tcp_listener.py`
   writes to `honeypot_log.txt`)
3. Groups all connections by source IP and counts them
4. For each IP, checks every connection against a sliding time window
   — if `N` or more connections from the same IP fall within that
   window, it's flagged as suspicious
5. Prints a summary: totals, top source IPs, flagged/clean verdict,
   and any data clients sent (useful for spotting attempted
   credentials against a fake login banner)

## Usage

```bash
# Analyze a log with default settings (flag 5+ connections within 60s)
python3 log_analyzer.py honeypot_log.txt

# Adjust sensitivity - flag 3+ connections within a 30 second window
python3 log_analyzer.py honeypot_log.txt --window 30 --threshold 3
```

### Example Workflow (Full Loop)

```bash
# Terminal 1: start the listener
python3 tcp_listener.py -p 8080 --banner "SSH-2.0-OpenSSH_8.9"

# Terminal 2: scan it with the port scanner (generates real log data)
python3 port_scanner.py 127.0.0.1 -p 8080

# Then analyze what got logged
python3 log_analyzer.py honeypot_log.txt
```

### Example Output

```
=======================================================
 Log file        : honeypot_log.txt
 Total connections: 6
 Unique source IPs: 2
 Time range       : 2026-09-22 19:53:10 to 2026-09-22 19:54:08
=======================================================

Top source IPs by connection count:
  192.168.1.50         5 connection(s)
  127.0.0.1            1 connection(s)

=======================================================
 [!] SUSPICIOUS ACTIVITY DETECTED
 (>= 5 connections within 60s window)
=======================================================
  192.168.1.50         5 connections in a 60s window
=======================================================

Data received from connecting clients (2 entries):
  [2026-09-22 19:54:01] 192.168.1.50: 'admin'
  [2026-09-22 19:54:03] 192.168.1.50: 'root'
```

## Requirements

- Python 3.6+
- No external dependencies — standard library only (`re`, `argparse`,
  `datetime`, `collections`)

## Possible Improvements (Next Steps)

- Support standard log formats beyond my own honeypot format (e.g.
  Linux `auth.log`, Apache/nginx access logs)
- Export flagged results to CSV/JSON for reporting
- Add a configurable IP allowlist (so known/trusted IPs are never flagged)
- Track patterns over multiple log files (detect activity across days,
  not just within one file)

## ⚠️ Legal & Ethical Use

This tool only reads and analyzes log files - it doesn't scan, probe,
or connect to anything. Only run it against logs you generated
yourself or have explicit permission to analyze (e.g. logs from your
own systems).
