#!/usr/bin/env python3
"""
Simple TCP Port Scanner
------------------------
Scans a target host for open TCP ports within a given range, using
multithreading for speed, and attempts to grab service banners on
open ports.

Author: Allister
For educational and authorized security testing use only.
"""

import argparse
import socket
import sys
import threading
from datetime import datetime
from queue import Queue

# Thread-safe list to store results
open_ports = []
lock = threading.Lock()


def grab_banner(sock):
    """Try to read a short banner/response from an open socket."""
    try:
        sock.settimeout(1)
        banner = sock.recv(1024).decode(errors="ignore").strip()
        return banner if banner else "No banner"
    except Exception:
        return "No banner"


def scan_port(target, port, timeout):
    """Attempt to connect to a single port. Record it if open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            if result == 0:
                banner = grab_banner(sock)
                with lock:
                    open_ports.append((port, banner))
                    print(f"[+] Port {port:>5} OPEN   | {banner}")
    except socket.error:
        pass


def worker(target, timeout, queue):
    """Pull ports off the queue and scan them until it's empty."""
    while not queue.empty():
        port = queue.get()
        scan_port(target, port, timeout)
        queue.task_done()


def resolve_target(target):
    """Resolve a hostname to an IP address, exit cleanly if it fails."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[!] Could not resolve hostname: {target}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="A simple multithreaded TCP port scanner for authorized security testing."
    )
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument(
        "-p", "--ports", default="1-1024",
        help="Port range to scan, e.g. 1-1024 or 80,443,8080 (default: 1-1024)"
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=100,
        help="Number of concurrent threads (default: 100)"
    )
    parser.add_argument(
        "--timeout", type=float, default=0.5,
        help="Socket timeout in seconds per port (default: 0.5)"
    )
    args = parser.parse_args()

    # Parse port spec: supports "80,443", "1-1024", or a mix like "20-25,80,443"
    ports = []
    for part in args.ports.split(","):
        part = part.strip()
        if "-" in part:
            start, end = map(int, part.split("-"))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    ports = sorted(set(ports))

    ip = resolve_target(args.target)

    print("=" * 55)
    print(f" Target        : {args.target} ({ip})")
    print(f" Port range    : {args.ports}  ({len(ports)} ports)")
    print(f" Threads       : {args.threads}")
    print(f" Started at    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 55)

    queue = Queue()
    for port in ports:
        queue.put(port)

    start_time = datetime.now()
    threads = []
    for _ in range(min(args.threads, len(ports))):
        t = threading.Thread(target=worker, args=(ip, args.timeout, queue))
        t.daemon = True
        t.start()
        threads.append(t)

    queue.join()
    duration = (datetime.now() - start_time).total_seconds()

    print("=" * 55)
    print(f" Scan complete in {duration:.2f} seconds")
    print(f" Open ports found: {len(open_ports)}")
    if open_ports:
        for port, banner in sorted(open_ports):
            print(f"   - {port}: {banner}")
    print("=" * 55)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(0)
