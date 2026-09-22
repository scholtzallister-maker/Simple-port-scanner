#!/usr/bin/env python3
"""
Simple TCP Connection Logger / Mini Honeypot
----------------------------------------------
Listens on a chosen TCP port and logs every connection attempt:
timestamp, source IP, source port, and any data the client sends.

Optionally sends back a fake service "banner" to see how scanners
(like a port scanner's banner grabber) react to it.

This does NOT require root - it's a normal server socket, not raw
packet capture. Great for understanding what a scanner sees on the
other end of an open port.

Author: Allister
For educational use on your own devices/network only.
"""

import argparse
import socket
import sys
import threading
from datetime import datetime

LOG_FILE = "honeypot_log.txt"
lock = threading.Lock()


def log(message):
    """Print a timestamped message and append it to the log file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {message}"
    print(line)
    with lock:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")


def handle_client(conn, addr, banner):
    """Handle a single incoming connection: log it, optionally send a banner, log any data received."""
    ip, port = addr
    log(f"Connection from {ip}:{port}")

    try:
        if banner:
            conn.sendall((banner + "\r\n").encode())
            log(f"  -> Sent banner to {ip}: {banner!r}")

        conn.settimeout(3)
        data = conn.recv(1024)
        if data:
            decoded = data.decode(errors="ignore").strip()
            log(f"  <- Received from {ip}: {decoded!r}")
        else:
            log(f"  <- {ip} sent no data before disconnecting")
    except socket.timeout:
        log(f"  <- {ip} did not send data within timeout")
    except Exception as e:
        log(f"  !! Error handling {ip}: {e}")
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(
        description="A simple TCP connection logger / mini honeypot for learning purposes."
    )
    parser.add_argument(
        "-p", "--port", type=int, default=8080,
        help="Port to listen on (default: 8080). Use a port above 1024 to avoid needing root."
    )
    parser.add_argument(
        "-b", "--banner", default=None,
        help="Optional fake banner to send to connecting clients, e.g. 'SSH-2.0-OpenSSH_8.9'"
    )
    args = parser.parse_args()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind(("0.0.0.0", args.port))
    except PermissionError:
        print(f"[!] Permission denied binding to port {args.port}.")
        print("    Ports below 1024 need root. Try a port above 1024, e.g. -p 8080")
        sys.exit(1)
    except OSError as e:
        print(f"[!] Could not bind to port {args.port}: {e}")
        sys.exit(1)

    server.listen(5)

    print("=" * 55)
    print(f" Listening on 0.0.0.0:{args.port}")
    print(f" Banner       : {args.banner or '(none)'}")
    print(f" Log file     : {LOG_FILE}")
    print(f" Started at   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(" Press Ctrl+C to stop")
    print("=" * 55)

    try:
        while True:
            conn, addr = server.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr, args.banner))
            t.daemon = True
            t.start()
    except KeyboardInterrupt:
        print("\n[!] Shutting down listener.")
    finally:
        server.close()


if __name__ == "__main__":
    main()
