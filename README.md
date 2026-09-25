Home Network Security Toolkit
A set of three small Python tools built to learn network security
fundamentals from the ground up — covering both the offensive and
defensive sides of the same interaction. Built and tested entirely on
Android using Termux, no laptop required.
Tool
Role
What it does
port_scanner.py
Offense
Scans a target for open TCP ports and grabs service banners
tcp_listener.py
Defense
Listens on a port and logs every connection attempt against it
log_analyzer.py
Analysis
Reads those logs and flags suspicious connection patterns
How they fit together: the scanner plays the role of an attacker
probing a target; the listener plays the role of a defended system,
logging everything that touches it; the analyzer plays the role of a
SOC analyst, reading those logs and deciding what's a real threat. All
three were tested against each other directly — the scanner detecting
the listener's fake banner, and the analyzer correctly flagging
repeated scans as suspicious activity, confirmed with real generated
log data.
