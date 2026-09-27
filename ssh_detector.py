# ssh_brute_detector.py
import re
import json
import ipaddress
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

# ── Data ──────────────────────────────────────────────────────────────

@dataclass
class Attempt:
    timestamp: datetime
    ip:        str
    user:      str
    port:      int
    success:   bool

@dataclass
class IPReport:
    ip:       str
    attempts: list[Attempt] = field(default_factory=list)

    @property
    def failed(self) -> int:
        return sum(1 for a in self.attempts if not a.success)

    @property
    def succeeded(self) -> int:
        return sum(1 for a in self.attempts if a.success)

    @property
    def usernames(self) -> set[str]:
        return {a.user for a in self.attempts if not a.success}

    @property
    def first_seen(self) -> datetime:
        return min(a.timestamp for a in self.attempts)

    @property
    def last_seen(self) -> datetime:
        return max(a.timestamp for a in self.attempts)

    @property
    def duration(self) -> timedelta:
        return self.last_seen - self.first_seen

    @property
    def rate_per_min(self) -> float:
        mins = self.duration.total_seconds() / 60
        return round(self.failed / mins, 1) if mins > 0 else float(self.failed)

    @property
    def subnet(self) -> str:
        return str(ipaddress.ip_network(f"{self.ip}/24", strict=False))

    @property
    def breach_likely(self) -> bool:
        """A success that arrived after at least one failure = probable breach."""
        failures  = [a for a in self.attempts if not a.success]
        successes = [a for a in self.attempts if a.success]
        if not failures or not successes:
            return False
        return min(s.timestamp for s in successes) > min(f.timestamp for f in failures)

@dataclass
class ScanResult:
    log_file:    str
    threshold:   int
    scanned_at:  datetime
    total_lines: int
    reports:     dict[str, IPReport]
    whitelist:   set[str]

    @property
    def suspicious(self) -> list[IPReport]:
        return sorted(
            [r for ip, r in self.reports.items()
             if r.failed >= self.threshold and ip not in self.whitelist],
            key=lambda r: r.failed, reverse=True,
        )

    @property
    def breaches(self) -> list[IPReport]:
        return [r for r in self.suspicious if r.breach_likely]

    @property
    def subnet_clusters(self) -> dict[str, list[str]]:
        """Multiple IPs from the same /24 = likely coordinated attack."""
        clusters: dict[str, list[str]] = defaultdict(list)
        for r in self.suspicious:
            clusters[r.subnet].append(r.ip)
        return {s: ips for s, ips in clusters.items() if len(ips) > 1}

    def to_dict(self) -> dict:
        return {
            "log_file":         self.log_file,
            "scanned_at":       self.scanned_at.isoformat(),
            "total_lines":      self.total_lines,
            "threshold":        self.threshold,
            "suspicious_count": len(self.suspicious),
            "breach_count":     len(self.breaches),
            "ips": [
                {
                    "ip":            r.ip,
                    "failed":        r.failed,
                    "succeeded":     r.succeeded,
                    "usernames":     sorted(r.usernames),
                    "first_seen":    r.first_seen.isoformat(),
                    "last_seen":     r.last_seen.isoformat(),
                    "rate_per_min":  r.rate_per_min,
                    "breach_likely": r.breach_likely,
                }
                for r in self.suspicious
            ],
            "subnet_clusters": self.subnet_clusters,
        }

# ── Log parsing ───────────────────────────────────────────────────────

# Handles: "Jan  5 14:23:01" and "Jan 15 14:23:01" (syslog, auth.log, journald)
_TS = r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"

_FAILED_RE   = re.compile(_TS + r".*Failed password for (?:invalid user )?(\S+) from ([\d.]+) port (\d+)")
_INVALID_RE  = re.compile(_TS + r".*Invalid user (\S+) from ([\d.]+)(?:\s+port (\d+))?")
_ACCEPTED_RE = re.compile(_TS + r".*Accepted (?:password|publickey) for (\S+) from ([\d.]+) port (\d+)")

def _parse_ts(raw: str) -> datetime:
    try:
        normalized = " ".join(raw.strip().split())   # collapse "Jan  5" → "Jan 5"
        return datetime.strptime(f"{datetime.now().year} {normalized}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return datetime.now()

def _parse_line(line: str) -> Attempt | None:
    for pattern, success in (
        (_FAILED_RE,   False),
        (_INVALID_RE,  False),
        (_ACCEPTED_RE, True),
    ):
        m = pattern.search(line)
        if m:
            ts_str, user, ip = m.group(1), m.group(2), m.group(3)
            port = int(m.group(4)) if m.group(4) else 22
            return Attempt(_parse_ts(ts_str), ip, user, port, success)
    return None

# ── Core ──────────────────────────────────────────────────────────────

def analyze_log(
    log_file:    str,
    threshold:   int = 5,
    whitelist:   set[str] | None = None,
    time_window: int | None = None,
) -> ScanResult:
    """
    Parse an SSH auth log and return a structured ScanResult.

    Args:
        log_file:    Path to log file (auth.log, syslog, journald export).
        threshold:   Min failed attempts before an IP is flagged suspicious.
        whitelist:   IPs to ignore (your jump host, monitoring servers, etc.).
        time_window: Only count attempts within the last N minutes.
    """
    whitelist = whitelist or set()
    reports: dict[str, IPReport] = {}

    try:
        lines = Path(log_file).read_text().splitlines()
    except FileNotFoundError:
        raise FileNotFoundError(f"Log file not found: '{log_file}'")

    cutoff = datetime.now() - timedelta(minutes=time_window) if time_window else None

    for line in lines:
        attempt = _parse_line(line)
        if not attempt or (cutoff and attempt.timestamp < cutoff):
            continue
        if attempt.ip not in reports:
            reports[attempt.ip] = IPReport(ip=attempt.ip)
        reports[attempt.ip].attempts.append(attempt)

    return ScanResult(
        log_file=log_file,
        threshold=threshold,
        scanned_at=datetime.now(),
        total_lines=len(lines),
        reports=reports,
        whitelist=whitelist,
    )

# ── Display ───────────────────────────────────────────────────────────

_W = 62

def display(result: ScanResult) -> None:
    print(f"\n{'─'*_W}")
    print(f"  SSH Brute Force Detector")
    print(f"  Log     : {result.log_file}")
    print(f"  Lines   : {result.total_lines:,}")
    print(f"  Scanned : {result.scanned_at.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Thresh  : ≥{result.threshold} failed attempts")
    print(f"{'─'*_W}\n")

    suspicious = result.suspicious
    if not suspicious:
        print("  ✅ No suspicious IPs found.\n")
        return

    # ── Summary table ──
    print(f"  {'IP':<18} {'FAILS':>6} {'OK':>4} {'RATE/min':>9}  STATUS")
    print(f"  {'─'*(_W-2)}")
    for r in suspicious:
        tag = "🔴 BREACH " if r.breach_likely else "⚠️  SUSPECT"
        print(f"  {r.ip:<18} {r.failed:>6} {r.succeeded:>4} {r.rate_per_min:>8.1f}  {tag}")

    # ── Per-IP detail ──
    print(f"\n{'─'*_W}")
    print("  DETAIL\n")
    for r in suspicious:
        span  = str(r.duration).split(".")[0]
        users = ", ".join(sorted(r.usernames)) or "—"
        print(f"  ▸ {r.ip}")
        print(f"    Usernames tried : {users}")
        print(f"    First seen      : {r.first_seen.strftime('%b %d %H:%M:%S')}")
        print(f"    Last seen       : {r.last_seen.strftime('%b %d %H:%M:%S')}")
        print(f"    Attack window   : {span}")
        if r.breach_likely:
            print(f"    🔴 Successful login after failures — investigate immediately!")
        print(f"    Block cmd       : sudo ufw deny from {r.ip}\n")

    # ── Subnet clusters ──
    clusters = result.subnet_clusters
    if clusters:
        print(f"{'─'*_W}")
        print("  COORDINATED CLUSTERS (multiple IPs from same /24)\n")
        for subnet, ips in clusters.items():
            print(f"  ▸ {subnet}  ({len(ips)} IPs)")
            for ip in ips:
                print(f"      {ip}")
            print(f"    Block subnet : sudo ufw deny from {subnet}\n")

    # ── Breach summary ──
    if result.breaches:
        print(f"{'─'*_W}")
        print(f"  🔴 LIKELY BREACHES ({len(result.breaches)})\n")
        for r in result.breaches:
            print(f"    {r.ip}  —  {r.succeeded} login(s) succeeded after {r.failed} failures")
        print()

    # ── Footer ──
    print(f"{'─'*_W}")
    print(f"  Suspicious IPs  : {len(suspicious)}")
    print(f"  Likely breaches : {len(result.breaches)}")
    print(f"  Subnet clusters : {len(clusters)}")
    print(f"{'─'*_W}\n")

# ── Sample log generator ──────────────────────────────────────────────

def generate_sample_log(path: str = "sample_auth.log") -> None:
    """Write a realistic auth.log that exercises every detector feature."""
    now = datetime.now()
    def ts(minutes_ago: int = 0) -> str:
        return (now - timedelta(minutes=minutes_ago)).strftime("%b %d %H:%M:%S")

    entries: list[str] = []

    # 1. Classic brute force: 20 attempts on root from one IP
    for i in range(20):
        entries.append(
            f"{ts(60 - i*2)} server sshd[1001]: Failed password for root "
            f"from 192.168.1.50 port 54321 ssh2"
        )
    # 2. Distributed attack: 3 IPs from the same /24, 6 failures each → subnet cluster
    for j in range(3):
        for i in range(6):
            entries.append(
                f"{ts(45 - i - j*7)} server sshd[1002]: Failed password for admin "
                f"from 10.0.0.{100+j} port 12345 ssh2"
            )
    # 3. Invalid user probing
    for i in range(8):
        entries.append(
            f"{ts(30 - i)} server sshd[1003]: Invalid user deploy "
            f"from 172.16.0.99 port 44444"
        )
    # 4. Breach: 6 failures then a successful login
    for i in range(6):
        entries.append(
            f"{ts(15 - i)} server sshd[1004]: Failed password for alice "
            f"from 203.0.113.42 port 9999 ssh2"
        )
    entries.append(
        f"{ts(8)} server sshd[1004]: Accepted password for alice "
        f"from 203.0.113.42 port 9999 ssh2"
    )
    # 5. Legitimate user: 1 typo then success (stays below threshold)
    entries.append(f"{ts(3)} server sshd[1005]: Failed password for bob from 198.51.100.1 port 11111 ssh2")
    entries.append(f"{ts(2)} server sshd[1005]: Accepted password for bob from 198.51.100.1 port 11111 ssh2")

    Path(path).write_text("\n".join(entries) + "\n")
    print(f"  Sample log → '{path}'  ({len(entries)} lines)\n")

# ── JSON export ───────────────────────────────────────────────────────

def save_report(result: ScanResult, path: str) -> None:
    Path(path).write_text(json.dumps(result.to_dict(), indent=2))
    print(f"  JSON report saved → '{path}'")

# ── Entry point ───────────────────────────────────────────────────────

if __name__ == "__main__":
    print("SSH Brute Force Detector")
    print("  1. /var/log/auth.log")
    print("  2. Custom log file")
    print("  3. Generate sample log + analyze")
    choice = input("\nChoose (1/2/3): ").strip()

    if choice == "1":
        log = "/var/log/auth.log"
    elif choice == "2":
        log = input("Log file path: ").strip()
    elif choice == "3":
        log = "sample_auth.log"
        generate_sample_log(log)
    else:
        print("Invalid choice.")
        raise SystemExit(1)

    thresh = int(input("Threshold      [5]: ").strip() or 5)
    win    = input("Time window mins (blank = all): ").strip()
    wl     = input("Whitelist IPs, comma-separated (blank = none): ").strip()
    out    = input("Save JSON report to (blank = skip): ").strip() or None

    try:
        result = analyze_log(
            log,
            threshold=thresh,
            whitelist=set(ip.strip() for ip in wl.split(",")) if wl else None,
            time_window=int(win) if win else None,
        )
        display(result)
        if out:
            save_report(result, out)
    except FileNotFoundError as e:
        print(f"Error: {e}")
