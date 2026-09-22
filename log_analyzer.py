#!/usr/bin/env python3
"""
Simple Log File Analyzer
--------------------------
Parses connection logs (built to read the honeypot_log.txt format
produced by tcp_listener.py) and flags suspicious patterns, such as
many connections from the same IP in a short window - a common sign
of scanning or brute-force activity.

This is the "defensive analyst" companion to the port scanner and
TCP listener projects: the scanner probes, the listener logs, and
this tool is the step where a human (or SOC analyst) actually makes
sense of what got logged.

Author: Allister
For educational use on logs you own or generated yourself.
"""

import argparse
import re
import sys
from collections import defaultdict
from datetime import datetime

# Matches: [2026-09-22 19:53:10] Connection from 127.0.0.1:34574
CONNECTION_RE = re.compile(
    r"^\[(?P<timestamp>[\d\-]+ [\d:]+)\] Connection from (?P<ip>[\d\.]+):(?P<port>\d+)$"
)

# Matches: [2026-09-22 19:53:10]   <- Received from 127.0.0.1: 'some data'
RECEIVED_RE = re.compile(
    r"^\[(?P<timestamp>[\d\-]+ [\d:]+)\]\s+<-\s+Received from (?P<ip>[\d\.]+): (?P<data>.+)$"
)

TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def parse_log(filepath):
    """Read the log file and extract connection events and received-data events."""
    connections = []  # list of (datetime, ip, port)
    received = []     # list of (datetime, ip, data)

    try:
        with open(filepath, "r") as f:
            for line in f:
                line = line.rstrip("\n")

                match = CONNECTION_RE.match(line)
                if match:
                    ts = datetime.strptime(match.group("timestamp"), TIME_FORMAT)
                    connections.append((ts, match.group("ip"), match.group("port")))
                    continue

                match = RECEIVED_RE.match(line)
                if match:
                    ts = datetime.strptime(match.group("timestamp"), TIME_FORMAT)
                    received.append((ts, match.group("ip"), match.group("data")))
                    continue

    except FileNotFoundError:
        print(f"[!] Log file not found: {filepath}")
        sys.exit(1)

    return connections, received


def find_rapid_connections(connections, window_seconds, threshold):
    """
    Flag IPs that made `threshold` or more connections within any
    `window_seconds`-second sliding window - a sign of scanning
    or automated probing rather than normal human activity.
    """
    by_ip = defaultdict(list)
    for ts, ip, port in connections:
        by_ip[ip].append(ts)

    flagged = {}
    for ip, timestamps in by_ip.items():
        timestamps.sort()
        for i in range(len(timestamps)):
            window_end = timestamps[i]
            window_start_limit = window_end.timestamp() - window_seconds
            count_in_window = sum(
                1 for t in timestamps if t.timestamp() >= window_start_limit and t.timestamp() <= window_end.timestamp()
            )
            if count_in_window >= threshold:
                flagged[ip] = max(flagged.get(ip, 0), count_in_window)

    return flagged


def main():
    parser = argparse.ArgumentParser(
        description="Analyze honeypot/connection logs for suspicious activity."
    )
    parser.add_argument("logfile", help="Path to the log file (e.g. honeypot_log.txt)")
    parser.add_argument(
        "--window", type=int, default=60,
        help="Time window in seconds to check for rapid connections (default: 60)"
    )
    parser.add_argument(
        "--threshold", type=int, default=5,
        help="Number of connections within the window to flag as suspicious (default: 5)"
    )
    args = parser.parse_args()

    connections, received = parse_log(args.logfile)

    if not connections:
        print(f"[!] No connection entries found in {args.logfile}")
        sys.exit(0)

    by_ip = defaultdict(int)
    for ts, ip, port in connections:
        by_ip[ip] += 1

    first_seen = min(ts for ts, ip, port in connections)
    last_seen = max(ts for ts, ip, port in connections)

    print("=" * 55)
    print(f" Log file        : {args.logfile}")
    print(f" Total connections: {len(connections)}")
    print(f" Unique source IPs: {len(by_ip)}")
    print(f" Time range       : {first_seen} to {last_seen}")
    print("=" * 55)

    print("\nTop source IPs by connection count:")
    for ip, count in sorted(by_ip.items(), key=lambda x: -x[1])[:10]:
        print(f"  {ip:<20} {count} connection(s)")

    flagged = find_rapid_connections(connections, args.window, args.threshold)
    print("\n" + "=" * 55)
    if flagged:
        print(f" [!] SUSPICIOUS ACTIVITY DETECTED")
        print(f" (>= {args.threshold} connections within {args.window}s window)")
        print("=" * 55)
        for ip, count in sorted(flagged.items(), key=lambda x: -x[1]):
            print(f"  {ip:<20} {count} connections in a {args.window}s window")
    else:
        print(f" No IPs exceeded {args.threshold} connections within {args.window}s.")
        print(" No rapid-scanning pattern detected.")
    print("=" * 55)

    if received:
        print(f"\nData received from connecting clients ({len(received)} entries):")
        for ts, ip, data in received[:20]:
            print(f"  [{ts}] {ip}: {data}")
        if len(received) > 20:
            print(f"  ... and {len(received) - 20} more")


if __name__ == "__main__":
    main()
