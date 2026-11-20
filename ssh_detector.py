# ssh_brute_detector.py
from __future__ import annotations

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
    pid:       str | None = None   # sshd process id, when the line carries one
    probe:     bool = False        # an "Invalid user" notice rather than a password try

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
        """The /24 (IPv4) or /64 (IPv6) the address belongs to."""
        prefix = 24 if ipaddress.ip_address(self.ip).version == 4 else 64
        return str(ipaddress.ip_network(f"{self.ip}/{prefix}", strict=False))

    @property
    def breach_likely(self) -> bool:
        """A success that arrived after at least one failure = probable breach."""
        failures  = [a for a in self.attempts if not a.success]
        successes = [a for a in self.attempts if a.success]
        if not failures or not successes:
            return False
        return min(s.timestamp for s in successes) > min(f.timestamp for f in failures)

def is_whitelisted(ip: str, whitelist: set[str]) -> bool:
    """True if ip equals, or falls inside, any whitelist entry (address or CIDR)."""
    addr = ipaddress.ip_address(ip)
    for entry in whitelist:
        net = ipaddress.ip_network(entry, strict=False)
        if net.version == addr.version and addr in net:
            return True
    return False

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
             if r.failed >= self.threshold and not is_whitelisted(ip, self.whitelist)],
            key=lambda r: r.failed, reverse=True,
        )

    @property
    def breaches(self) -> list[IPReport]:
        return [r for r in self.suspicious if r.breach_likely]

    @property
    def subnet_clusters(self) -> dict[str, list[str]]:
        """Multiple IPs from the same /24 (IPv4) or /64 (IPv6) = likely coordinated attack."""
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

# Handles syslog stamps ("Jan  5 14:23:01", "Jan 15 14:23:01") and ISO-8601
# stamps ("2026-04-20T10:00:01", with optional fraction and UTC offset), as
# written by rsyslog's RFC 3339 template and journald exports.
_TS = (
    r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
    r"|\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
)

_PID_RE = re.compile(r"sshd(?:-session)?\[(\d+)\]")

_FAILED_RE   = re.compile(_TS + r".*Failed password for (?:invalid user )?(\S+) from ([0-9A-Fa-f:.]+) port (\d+)")
_INVALID_RE  = re.compile(_TS + r".*Invalid user (\S+) from ([0-9A-Fa-f:.]+)(?:\s+port (\d+))?")
_ACCEPTED_RE = re.compile(_TS + r".*Accepted (?:password|publickey) for (\S+) from ([0-9A-Fa-f:.]+) port (\d+)")

_ISO_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:[.,]\d+)?(Z|[+-]\d{2}:?\d{2})?$"
)

def _parse_ts(raw: str, now: datetime | None = None) -> datetime | None:
    """
    Turn a log timestamp into a naive local datetime, or None if it can't be read.

    Syslog stamps carry no year, so assume the current one, falling back to the
    previous year when that would put the entry in the future (a December line
    read in January) or the date doesn't exist (Feb 29 in a non-leap year).
    """
    now = now or datetime.now()
    raw = raw.strip()

    m = _ISO_RE.match(raw)
    if m:
        date, clock, tz = m.groups()
        if tz == "Z":
            tz = "+00:00"
        elif tz and ":" not in tz:
            tz = tz[:3] + ":" + tz[3:]
        try:
            parsed = datetime.fromisoformat(f"{date}T{clock}{tz or ''}")
        except ValueError:
            return None
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone().replace(tzinfo=None)
        return parsed

    normalized = " ".join(raw.split())   # collapse "Jan  5" -> "Jan 5"
    for year in (now.year, now.year - 1):
        try:
            parsed = datetime.strptime(f"{year} {normalized}", "%Y %b %d %H:%M:%S")
        except ValueError:
            continue
        if parsed <= now + timedelta(days=1):
            return parsed
    return None

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
            ts = _parse_ts(ts_str)
            if ts is None:
                return None
            try:
                ip = str(ipaddress.ip_address(ip))   # reject junk, normalise IPv6
            except ValueError:
                return None
            pid = _PID_RE.search(line)
            return Attempt(
                ts, ip, user, port, success,
                pid=pid.group(1) if pid else None,
                probe=pattern is _INVALID_RE,
            )
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
        whitelist:   IPs or CIDR ranges to ignore (jump host, monitoring, office network).
        time_window: Only count attempts within the last N minutes.
    """
    whitelist = set(whitelist or ())
    for entry in whitelist:
        try:
            ipaddress.ip_network(entry, strict=False)
        except ValueError:
            raise ValueError(f"Invalid whitelist entry (expected IP or CIDR): '{entry}'") from None
    reports: dict[str, IPReport] = {}

    try:
        # Logs can hold stray non-UTF-8 bytes (attackers control usernames), so
        # decode leniently rather than crash on the first one.
        lines = Path(log_file).read_text(encoding="utf-8", errors="replace").splitlines()
    except FileNotFoundError:
        raise FileNotFoundError(f"Log file not found: '{log_file}'") from None
    except PermissionError:
        raise PermissionError(
            f"Permission denied reading '{log_file}' (try sudo, or copy the log first)"
        ) from None
    except IsADirectoryError:
        raise IsADirectoryError(f"'{log_file}' is a directory, not a log file") from None

    cutoff = datetime.now() - timedelta(minutes=time_window) if time_window else None

    parsed = [a for a in map(_parse_line, lines) if a]

    # sshd logs a probe of an unknown account twice: "Invalid user X from ..."
    # and then "Failed password for invalid user X from ..." for each try. Count
    # the password failures and drop the notice they already account for.
    tried = {(a.pid, a.ip, a.user) for a in parsed if not a.probe and not a.success}
    parsed = [a for a in parsed if not (a.probe and (a.pid, a.ip, a.user) in tried)]

    for attempt in parsed:
        if cutoff and attempt.timestamp < cutoff:
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

def safe(text: str, limit: int = 64) -> str:
    """
    Make attacker-controlled text (usernames come straight from the log) safe
    to print: control characters, including ESC, are shown as \\xNN escapes so
    they can't rewrite the terminal, and very long values are truncated.
    """
    out = "".join(
        c if c.isprintable() else f"\\x{ord(c):02x}" if ord(c) < 256 else f"\\u{ord(c):04x}"
        for c in text
    )
    return out if len(out) <= limit else out[: limit - 1] + "…"

def display(result: ScanResult) -> None:
    print(f"\n{'─'*_W}")
    print(f"  SSH Brute Force Detector")
    print(f"  Log     : {safe(result.log_file, 200)}")
    print(f"  Lines   : {result.total_lines:,}")
    print(f"  Scanned : {result.scanned_at.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Thresh  : ≥{result.threshold} failed attempts")
    print(f"{'─'*_W}\n")

    suspicious = result.suspicious
    if not suspicious:
        print("  ✅ No suspicious IPs found.\n")
        return

    # ── Summary table ──
    ipw = max(18, *(len(r.ip) for r in suspicious))   # IPv6 addresses are wider
    print(f"  {'IP':<{ipw}} {'FAILS':>6} {'OK':>4} {'RATE/min':>9}  STATUS")
    print(f"  {'─'*(_W-2)}")
    for r in suspicious:
        tag = "🔴 BREACH " if r.breach_likely else "⚠️  SUSPECT"
        print(f"  {r.ip:<{ipw}} {r.failed:>6} {r.succeeded:>4} {r.rate_per_min:>8.1f}  {tag}")

    # ── Per-IP detail ──
    print(f"\n{'─'*_W}")
    print("  DETAIL\n")
    for r in suspicious:
        span  = str(r.duration).split(".")[0]
        users = ", ".join(safe(u) for u in sorted(r.usernames)) or "—"
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

    thresh_raw = input("Threshold      [5]: ").strip()
    win    = input("Time window mins (blank = all): ").strip()
    wl     = input("Whitelist IPs/CIDRs, comma-separated (blank = none): ").strip()
    out    = input("Save JSON report to (blank = skip): ").strip() or None

    try:
        thresh = int(thresh_raw or 5)
        result = analyze_log(
            log,
            threshold=thresh,
            whitelist=set(ip.strip() for ip in wl.split(",") if ip.strip()) if wl else None,
            time_window=int(win) if win else None,
        )
        display(result)
        if out:
            save_report(result, out)
    except (OSError, ValueError) as e:
        print(f"Error: {e}")
        raise SystemExit(1)
