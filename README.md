# SSH Brute Force Detector
A Python tool that analyzes Linux auth logs to detect SSH brute force attacks.

## Usage
python3 ssh_detector.py

Choose option 1 for the real auth log (`/var/log/auth.log`, usually needs `sudo`),
option 2 for any log file, or option 3 to generate a sample log and analyze it.
Requires Python 3.9+ and nothing outside the standard library.

## How it works
- Parses auth log for repeated failed SSH login attempts
- Flags IPs that exceed the threshold (default: 5 attempts)
- Flags a likely breach when a login succeeds after failures from the same IP
- Groups several offending IPs from one /24 (IPv4) or /64 (IPv6) as a coordinated cluster
- Recommends UFW firewall commands to block suspicious IPs
- Optionally saves a JSON report

## Supported input
- Timestamps: syslog (`Nov 20 10:00:01`) and ISO-8601 (`2026-11-20T10:00:01`, with optional fraction and UTC offset)
- Addresses: IPv4 and IPv6
- Whitelist: IPs or CIDR ranges, for example `10.0.0.0/8, 2001:db8::/32`
- Unknown-username probes are counted once per attempt, even though sshd logs them twice
- Usernames come from the log, so control characters are escaped before they reach your terminal

## Tests
python3 -m pip install pytest
python3 -m pytest
