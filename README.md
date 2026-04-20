# SSH Brute Force Detector
A Python tool that analyzes Linux auth logs to detect SSH brute force attacks.

## Usage
python3 ssh_detector.py

Choose option 1 for real auth log or option 2 for sample testing.

## How it works
- Parses auth log for repeated failed SSH login attempts
- Flags IPs that exceed the threshold (default: 5 attempts)
- Recommends UFW firewall commands to block suspicious IPs


