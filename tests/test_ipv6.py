from pathlib import Path

import pytest

import ssh_detector as d


def write(tmp_path: Path, lines):
    p = tmp_path / "auth.log"
    p.write_text("\n".join(lines) + "\n")
    return str(p)


def fails(ip, n, user="root", start=0):
    return [
        f"Nov 20 10:00:{start + i:02d} h sshd[{900 + i}]: Failed password for {user} from {ip} port 22 ssh2"
        for i in range(n)
    ]


def test_ipv6_failures_are_parsed(tmp_path):
    result = d.analyze_log(write(tmp_path, fails("2001:db8::1", 5)), threshold=5)
    assert [r.ip for r in result.suspicious] == ["2001:db8::1"]


def test_ipv6_is_normalised_so_spellings_are_grouped(tmp_path):
    lines = fails("2001:0db8:0000:0000:0000:0000:0000:0001", 3) + fails("2001:DB8::1", 3, start=10)
    result = d.analyze_log(write(tmp_path, lines), threshold=1)
    assert list(result.reports) == ["2001:db8::1"]
    assert result.reports["2001:db8::1"].failed == 6


def test_ipv6_accepted_login_and_invalid_user_lines(tmp_path):
    lines = [
        "Nov 20 10:00:00 h sshd[1]: Invalid user test from 2001:db8::7 port 5000",
        "Nov 20 10:00:05 h sshd[2]: Accepted publickey for test from 2001:db8::7 port 5001 ssh2",
    ]
    r = d.analyze_log(write(tmp_path, lines), threshold=1).reports["2001:db8::7"]
    assert (r.failed, r.succeeded) == (1, 1)
    assert r.breach_likely is True   # success arrived after a failure


def test_ipv6_subnet_is_a_slash_64():
    r = d.IPReport(ip="2001:db8:1:2:aaaa:bbbb:cccc:dddd")
    assert r.subnet == "2001:db8:1:2::/64"
    assert d.IPReport(ip="203.0.113.77").subnet == "203.0.113.0/24"


def test_ipv6_cluster_detected(tmp_path):
    lines = fails("2001:db8:1:2::a", 5) + fails("2001:db8:1:2::b", 5, start=10)
    result = d.analyze_log(write(tmp_path, lines), threshold=5)
    clusters = {k: sorted(v) for k, v in result.subnet_clusters.items()}
    assert clusters == {"2001:db8:1:2::/64": ["2001:db8:1:2::a", "2001:db8:1:2::b"]}


def test_junk_address_is_ignored(tmp_path):
    lines = ["Nov 20 10:00:00 h sshd[1]: Failed password for root from 999.1.1.1 port 22 ssh2",
             "Nov 20 10:00:01 h sshd[2]: Failed password for root from ... port 22 ssh2"]
    assert d.analyze_log(write(tmp_path, lines), threshold=1).reports == {}


def test_whitelist_accepts_cidr_and_alternate_ipv6_spelling(tmp_path):
    lines = fails("10.1.2.3", 6) + fails("2001:db8::5", 6, start=10) + fails("198.51.100.4", 6, start=20)
    log = write(tmp_path, lines)
    result = d.analyze_log(log, threshold=5, whitelist={"10.0.0.0/8", "2001:0db8:0:0:0:0:0:0/32"})
    assert [r.ip for r in result.suspicious] == ["198.51.100.4"]


def test_whitelist_plain_ip_still_works(tmp_path):
    log = write(tmp_path, fails("10.1.2.3", 6) + fails("10.1.2.4", 6, start=10))
    result = d.analyze_log(log, threshold=5, whitelist={"10.1.2.3"})
    assert [r.ip for r in result.suspicious] == ["10.1.2.4"]


def test_invalid_whitelist_entry_fails_loudly(tmp_path):
    log = write(tmp_path, fails("10.1.2.3", 1))
    with pytest.raises(ValueError, match="Invalid whitelist entry"):
        d.analyze_log(log, whitelist={"not-an-ip"})
