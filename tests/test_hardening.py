import os
import subprocess
import sys
from pathlib import Path

import pytest

import ssh_detector as d

ROOT = Path(__file__).resolve().parent.parent


def test_safe_escapes_terminal_control_characters():
    assert d.safe("root\x1b[2J\x07") == "root\\x1b[2J\\x07"
    assert "\x1b" not in d.safe("\x1b]0;pwned\x07")
    assert d.safe("a\u202eb") == "a\\u202eb"   # bidi override can disguise text


def test_safe_leaves_normal_text_alone():
    assert d.safe("deploy-user_01") == "deploy-user_01"
    assert d.safe("tëst") == "tëst"


def test_safe_truncates_long_values():
    out = d.safe("A" * 500, limit=64)
    assert len(out) == 64 and out.endswith("…")


def test_hostile_username_cannot_inject_escape_codes_into_report(tmp_path, capsys):
    log = tmp_path / "auth.log"
    log.write_text("\n".join(
        f"Nov 20 10:00:0{i} h sshd[{i}]: Failed password for evil\x1b[31m\x1b]0;owned\x07 "
        "from 192.0.2.66 port 22 ssh2" for i in range(6)
    ) + "\n")
    d.display(d.analyze_log(str(log), threshold=5))
    out = capsys.readouterr().out
    assert "\x1b" not in out and "\x07" not in out
    assert "evil" in out


def test_log_with_invalid_utf8_does_not_crash(tmp_path):
    log = tmp_path / "auth.log"
    log.write_bytes(
        b"Nov 20 10:00:00 h sshd[1]: Failed password for caf\xe9\xff from 192.0.2.9 port 22 ssh2\n"
        b"Nov 20 10:00:01 h sshd[2]: Failed password for root from 192.0.2.9 port 22 ssh2\n"
    )
    assert d.analyze_log(str(log), threshold=1).reports["192.0.2.9"].failed == 2


def test_missing_file_message(tmp_path):
    with pytest.raises(FileNotFoundError, match="Log file not found"):
        d.analyze_log(str(tmp_path / "nope.log"))


def test_directory_gives_clear_error(tmp_path):
    with pytest.raises(IsADirectoryError, match="is a directory"):
        d.analyze_log(str(tmp_path))


@pytest.mark.skipif(os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
                    reason="permissions are not enforced for root / Windows")
def test_unreadable_file_gives_clear_error(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("x\n")
    log.chmod(0)
    try:
        with pytest.raises(PermissionError, match="Permission denied"):
            d.analyze_log(str(log))
    finally:
        log.chmod(0o600)


def run_cli(*answers):
    return subprocess.run(
        [sys.executable, str(ROOT / "ssh_detector.py")],
        input="\n".join(answers) + "\n", capture_output=True, text=True, cwd=ROOT, timeout=30,
    )


def test_cli_bad_threshold_is_an_error_not_a_traceback():
    proc = run_cli("2", str(ROOT / "sample_auth.log"), "abc", "", "", "")
    assert proc.returncode == 1
    assert "Error:" in proc.stdout and "Traceback" not in proc.stderr


def test_cli_bad_whitelist_is_an_error_not_a_traceback():
    proc = run_cli("2", str(ROOT / "sample_auth.log"), "", "", "bogus", "")
    assert proc.returncode == 1
    assert "Invalid whitelist entry" in proc.stdout and "Traceback" not in proc.stderr


def test_cli_missing_log_exits_nonzero():
    proc = run_cli("2", "/definitely/not/here.log", "", "", "", "")
    assert proc.returncode == 1 and "Log file not found" in proc.stdout


def test_cli_happy_path_on_sample_log():
    proc = run_cli("2", str(ROOT / "sample_auth.log"), "2", "", "", "")
    assert proc.returncode == 0
    assert "192.168.1.101" in proc.stdout
