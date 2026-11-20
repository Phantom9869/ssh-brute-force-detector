from datetime import datetime, timezone
from pathlib import Path

import ssh_detector as d

NOW = datetime(2026, 1, 10, 12, 0, 0)
ROOT = Path(__file__).resolve().parent.parent


def test_syslog_stamp_uses_current_year():
    assert d._parse_ts("Jan  5 14:23:01", now=NOW) == datetime(2026, 1, 5, 14, 23, 1)


def test_december_line_read_in_january_belongs_to_last_year():
    assert d._parse_ts("Dec 31 23:59:59", now=NOW) == datetime(2025, 12, 31, 23, 59, 59)


def test_leap_day_in_non_leap_year_falls_back_to_leap_year():
    now = datetime(2025, 3, 1, 0, 0, 0)  # 2025 has no Feb 29, 2024 does
    assert d._parse_ts("Feb 29 10:00:00", now=now) == datetime(2024, 2, 29, 10, 0, 0)


def test_impossible_date_is_rejected_not_replaced_by_now():
    assert d._parse_ts("Feb 30 10:00:00", now=NOW) is None


def test_iso_stamp_without_zone():
    assert d._parse_ts("2026-04-20T10:00:01", now=NOW) == datetime(2026, 4, 20, 10, 0, 1)


def test_iso_stamp_with_space_and_fraction():
    assert d._parse_ts("2026-04-20 10:00:01.123456", now=NOW) == datetime(2026, 4, 20, 10, 0, 1)


def test_iso_stamp_with_offset_is_converted_to_local_naive_time():
    expected = (
        datetime(2026, 4, 20, 10, 0, 1, tzinfo=timezone.utc).astimezone().replace(tzinfo=None)
    )
    for raw in ("2026-04-20T10:00:01Z", "2026-04-20T10:00:01+00:00", "2026-04-20T10:00:01+0000"):
        assert d._parse_ts(raw, now=NOW) == expected


def test_garbage_stamp_returns_none():
    assert d._parse_ts("not a time", now=NOW) is None
    assert d._parse_ts("2026-13-45T99:00:00", now=NOW) is None


def test_parse_line_reads_iso_failed_password():
    line = "2026-04-20T10:00:01 server sshd: Failed password for root from 192.168.1.101 port 22 ssh2"
    a = d._parse_line(line)
    assert a is not None
    assert (a.ip, a.user, a.port, a.success) == ("192.168.1.101", "root", 22, False)
    assert a.timestamp == datetime(2026, 4, 20, 10, 0, 1)


def test_parse_line_skips_line_with_unreadable_date():
    line = "Feb 30 10:00:00 server sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2"
    assert d._parse_line(line) is None


def test_bundled_sample_log_is_actually_parsed():
    result = d.analyze_log(str(ROOT / "sample_auth.log"), threshold=2)
    found = {r.ip: r.failed for r in result.suspicious}
    assert found == {"192.168.1.101": 6, "192.168.1.105": 2, "10.0.0.55": 2}
