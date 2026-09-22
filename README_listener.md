# Simple TCP Connection Logger (Mini Honeypot)

A lightweight Python tool that listens on a TCP port and logs every
connection attempt made against it — timestamp, source IP, source port,
and any data sent. Built as a companion to my [TCP Port Scanner](../simple-port-scanner)
project, to see the network from the *server* side instead of the client side.

## What It Does

- Opens a TCP port and waits for incoming connections
- Logs every connection attempt to the console and to `honeypot_log.txt`
- Can send back a fake service "banner" (e.g. pretending to be an SSH
  server) to see how that interacts with scanning tools
- Handles multiple simultaneous connections using threads

## Why I Built This

After building a port scanner, I wanted to understand the other half of
the interaction — what does a service actually see and log when
something connects to it? This covers:

- **Server-side socket programming** — `bind()`, `listen()`, `accept()`,
  as opposed to the `connect()` side used by the scanner
- **Honeypot fundamentals** — real-world honeypots work on this exact
  principle: expose a fake service, log every interaction, and use that
  as an early-warning signal for scanning/probing activity
- **Full-loop testing** — running this alongside my own port scanner
  let me verify both tools end-to-end: the scanner correctly detects the
  open port and captures the exact banner the listener sends back

## How It Works

1. The script binds to `0.0.0.0` (all network interfaces) on the chosen
   port and starts listening
2. Each incoming connection is handed off to its own thread, so multiple
   clients can connect at once without blocking each other
3. For each connection, it logs the source IP/port, optionally sends a
   fake banner, then waits briefly to see if the client sends any data
4. Everything is logged with a timestamp to both the console and
   `honeypot_log.txt`

## Usage

```bash
# Listen on the default port (8080), no banner
python3 tcp_listener.py

# Listen on a specific port
python3 tcp_listener.py -p 2222

# Send a fake banner to anything that connects
python3 tcp_listener.py -p 2222 --banner "SSH-2.0-OpenSSH_8.9"
```

Press `Ctrl+C` to stop the listener.

### Example: Testing Against My Own Port Scanner

With the listener running in one terminal:
```bash
python3 tcp_listener.py -p 8080 --banner "SSH-2.0-OpenSSH_8.9"
```

And the port scanner run against it from another session:
```bash
python3 port_scanner.py <your-ip> -p 8080
```

The scanner correctly detects the port as open and captures the exact
banner the listener sent — confirming both tools work correctly
end-to-end.

## Requirements

- Python 3.6+
- No external dependencies — standard library only (`socket`,
  `threading`, `argparse`)
- **No root required** — this uses a normal server socket on a port
  above 1024, unlike raw packet capture (e.g. Wireshark/scapy-style
  sniffing), which does require root/elevated privileges and isn't
  possible on a non-rooted Android device running Termux

## Possible Improvements (Next Steps)

- Log to a structured format (JSON/CSV) for easier analysis
- Add more realistic fake banners for different common services
- Rate-limit or flag repeated connections from the same IP
- Add a simple summary report (most active source IPs, most probed
  timing patterns)

## ⚠️ Legal & Ethical Use

This tool only listens passively — it doesn't scan, probe, or connect
to anything else, so it's safe to run on your own devices and home
network. Only run it on infrastructure you own. If you plan to expose
this to the wider internet (e.g. on a VPS) rather than just your home
network, be aware you may attract genuine scanning traffic from bots —
that's expected honeypot behavior, but treat any logged data
responsibly and don't leave it exposed indefinitely without monitoring it.
