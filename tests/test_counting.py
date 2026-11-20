from pathlib import Path

import ssh_detector as d


def write(tmp_path: Path, lines: list[str]) -> str:
    p = tmp_path / "auth.log"
    p.write_text("\n".join(lines) + "\n")
    return str(p)


def test_invalid_user_probe_is_not_counted_twice(tmp_path):
    # One real sshd session: a notice, three password tries, then a disconnect.
    log = write(tmp_path, [
        "Nov 20 10:00:00 h sshd[500]: Invalid user admin from 203.0.113.9 port 4000",
        "Nov 20 10:00:01 h sshd[500]: Failed password for invalid user admin from 203.0.113.9 port 4000 ssh2",
        "Nov 20 10:00:03 h sshd[500]: Failed password for invalid user admin from 203.0.113.9 port 4000 ssh2",
        "Nov 20 10:00:05 h sshd[500]: Failed password for invalid user admin from 203.0.113.9 port 4000 ssh2",
    ])
    result = d.analyze_log(log, threshold=1)
    assert result.reports["203.0.113.9"].failed == 3


def test_invalid_user_notice_alone_still_counts(tmp_path):
    log = write(tmp_path, [
        "Nov 20 10:00:00 h sshd[501]: Invalid user deploy from 198.51.100.7 port 4001",
        "Nov 20 10:00:10 h sshd[502]: Invalid user deploy from 198.51.100.7 port 4002",
    ])
    assert d.analyze_log(log, threshold=1).reports["198.51.100.7"].failed == 2


def test_separate_sessions_are_not_merged(tmp_path):
    # Different pids: the notice of session 601 is not covered by session 600's failure.
    log = write(tmp_path, [
        "Nov 20 10:00:00 h sshd[600]: Failed password for invalid user bob from 192.0.2.1 port 1 ssh2",
        "Nov 20 10:00:01 h sshd[601]: Invalid user bob from 192.0.2.1 port 2",
    ])
    assert d.analyze_log(log, threshold=1).reports["192.0.2.1"].failed == 2


def test_different_usernames_are_not_merged(tmp_path):
    log = write(tmp_path, [
        "Nov 20 10:00:00 h sshd[700]: Invalid user alice from 192.0.2.5 port 1",
        "Nov 20 10:00:01 h sshd[700]: Failed password for invalid user carol from 192.0.2.5 port 1 ssh2",
    ])
    assert d.analyze_log(log, threshold=1).reports["192.0.2.5"].failed == 2


def test_pid_is_parsed_from_sshd_and_session_tags():
    a = d._parse_line("Nov 20 10:00:00 h sshd[42]: Failed password for root from 1.2.3.4 port 22 ssh2")
    assert a.pid == "42" and a.probe is False
    b = d._parse_line("Nov 20 10:00:00 h sshd[43]: Invalid user x from 1.2.3.4 port 22")
    assert b.pid == "43" and b.probe is True
    c = d._parse_line("Nov 20 10:00:00 h sshd: Failed password for root from 1.2.3.4 port 22 ssh2")
    assert c.pid is None


def test_breach_detection_unchanged_by_dedupe(tmp_path):
    log = write(tmp_path, [
        "Nov 20 10:00:00 h sshd[1]: Failed password for alice from 192.0.2.50 port 1 ssh2",
        "Nov 20 10:00:01 h sshd[2]: Failed password for alice from 192.0.2.50 port 1 ssh2",
        "Nov 20 10:00:09 h sshd[3]: Accepted password for alice from 192.0.2.50 port 1 ssh2",
    ])
    result = d.analyze_log(log, threshold=2)
    assert [r.ip for r in result.breaches] == ["192.0.2.50"]
