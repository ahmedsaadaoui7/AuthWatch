import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_cli_detects_brute_force():
    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            "data/brute_force_auth_log.csv",
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )

    assert "[ALERT] Potential Brute-Force Activity" in result.stdout
    assert "Rule ID: AUTH-BF-001" in result.stdout
    assert "Severity: high" in result.stdout
    assert "Source IP: 10.0.0.50" in result.stdout
    assert "Username: admin" in result.stdout
    assert "Failed attempts: 5" in result.stdout

def test_cli_reports_normal_activity():
    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            "data/normal_auth_log.csv",
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )

    assert "No suspicious authentication activity detected." in result.stdout


def test_cli_generates_markdown_report(tmp_path):
    output_file = tmp_path / "incident_report.md"

    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            "data/brute_force_auth_log.csv",
            "--report",
            str(output_file),
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )

    assert output_file.exists()

    content = output_file.read_text(encoding="utf-8")

    assert "# AuthWatch Incident Report" in content
    assert "Total alerts: 1" in content
    assert "Source IP: 10.0.0.50" in content
    assert "Username: admin" in content
    assert "Incident report written to:" in result.stdout


def test_cli_missing_file_returns_error():
    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            "data/does_not_exist.csv",
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "[ERROR] Authentication log not found:" in result.stderr


def test_cli_invalid_log_returns_error(tmp_path):
    invalid_file = tmp_path / "invalid_auth_log.csv"

    invalid_file.write_text(
        "timestamp,username,source_ip,result\n"
        "not-a-timestamp,admin,10.0.0.50,failure\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            str(invalid_file),
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "[ERROR]" in result.stderr
    assert "invalid timestamp" in result.stderr

def test_cli_detects_password_spray(tmp_path):
    log_file = tmp_path / "password_spray.csv"

    log_file.write_text(
        "timestamp,username,source_ip,result\n"
        "2026-08-14T09:00:00,alice,10.0.0.50,failure\n"
        "2026-08-14T09:00:10,bob,10.0.0.50,failure\n"
        "2026-08-14T09:00:20,charlie,10.0.0.50,failure\n"
        "2026-08-14T09:00:30,david,10.0.0.50,failure\n"
        "2026-08-14T09:00:40,admin,10.0.0.50,failure\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            str(log_file),
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )

    assert "[ALERT] Potential Password Spraying Activity" in result.stdout
    assert "Rule ID: AUTH-PS-001" in result.stdout
    assert "Severity: high" in result.stdout
    assert "Source IP: 10.0.0.50" in result.stdout
    assert "Unique accounts: 5" in result.stdout
    assert "Usernames: admin, alice, bob, charlie, david" in result.stdout

def test_cli_generates_password_spray_report(tmp_path):
    log_file = tmp_path / "password_spray.csv"
    output_file = tmp_path / "password_spray_report.md"

    log_file.write_text(
        "timestamp,username,source_ip,result\n"
        "2026-08-14T09:00:00,alice,10.0.0.50,failure\n"
        "2026-08-14T09:00:10,bob,10.0.0.50,failure\n"
        "2026-08-14T09:00:20,charlie,10.0.0.50,failure\n"
        "2026-08-14T09:00:30,david,10.0.0.50,failure\n"
        "2026-08-14T09:00:40,admin,10.0.0.50,failure\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            str(log_file),
            "--report",
            str(output_file),
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )

    assert output_file.exists()

    content = output_file.read_text(encoding="utf-8")

    assert "Potential Password Spraying Activity" in content
    assert "Rule ID: AUTH-PS-001" in content
    assert "Severity: high" in content
    assert "Source IP: 10.0.0.50" in content
    assert "Unique accounts: 5" in content
    assert "Usernames: admin, alice, bob, charlie, david" in content
    assert f"Incident report written to: {output_file}" in result.stdout
