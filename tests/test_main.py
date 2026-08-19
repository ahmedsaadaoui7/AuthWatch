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


def test_cli_detects_success_after_failures(tmp_path):
    input_file = tmp_path / "success_after_failures.csv"

    input_file.write_text(
        "timestamp,username,source_ip,result\n"
        "2026-08-15T09:00:00,admin,10.0.0.50,failure\n"
        "2026-08-15T09:00:10,admin,10.0.0.50,failure\n"
        "2026-08-15T09:00:20,admin,10.0.0.50,failure\n"
        "2026-08-15T09:00:30,admin,10.0.0.50,success\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [sys.executable, "main.py", str(input_file)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "Successful Login After Repeated Failures" in result.stdout
    assert "Rule ID: AUTH-SF-001" in result.stdout
    assert "Severity: high" in result.stdout
    assert "Source IP: 10.0.0.50" in result.stdout
    assert "Username: admin" in result.stdout
    assert "Failed attempts: 3" in result.stdout
    assert "First seen: 2026-08-15T09:00:00" in result.stdout
    assert "Last seen: 2026-08-15T09:00:30" in result.stdout


def test_cli_generates_success_after_failures_report(tmp_path):
    input_file = tmp_path / "success_after_failures.csv"
    output_file = tmp_path / "success_after_failures_report.md"

    input_file.write_text(
        "timestamp,username,source_ip,result\n"
        "2026-08-15T09:00:00,admin,10.0.0.50,failure\n"
        "2026-08-15T09:00:10,admin,10.0.0.50,failure\n"
        "2026-08-15T09:00:20,admin,10.0.0.50,failure\n"
        "2026-08-15T09:00:30,admin,10.0.0.50,success\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            str(input_file),
            "--report",
            str(output_file),
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert output_file.exists()

    report = output_file.read_text(encoding="utf-8")

    assert "Successful Login After Repeated Failures" in report
    assert "AUTH-SF-001" in report
    assert "Severity: high" in report
    assert "Source IP: 10.0.0.50" in report
    assert "Username: admin" in report
    assert "Failed attempts: 3" in report
    assert "First seen: 2026-08-15T09:00:00" in report
    assert "Last seen: 2026-08-15T09:00:30" in report

    assert f"Incident report written to: {output_file}" in result.stdout


def test_cli_detects_disabled_account_attempt(tmp_path):
    input_file = tmp_path / "auth_log.csv"
    disabled_file = tmp_path / "disabled_accounts.txt"

    input_file.write_text(
        "timestamp,username,source_ip,result\n"
        "2026-08-17T09:00:00,old_admin,10.0.0.50,failure\n",
        encoding="utf-8",
    )

    disabled_file.write_text(
        "old_admin\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            str(input_file),
            "--disabled-accounts",
            str(disabled_file),
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "Authentication Attempt Against Disabled Account" in result.stdout
    assert "Rule ID: AUTH-DA-001" in result.stdout
    assert "Severity: medium" in result.stdout
    assert "Source IP: 10.0.0.50" in result.stdout
    assert "Username: old_admin" in result.stdout
    assert "Result: failure" in result.stdout


def test_cli_generates_disabled_account_report(tmp_path):
    input_file = tmp_path / "auth_log.csv"
    disabled_file = tmp_path / "disabled_accounts.txt"
    output_file = tmp_path / "disabled_account_report.md"

    input_file.write_text(
        "timestamp,username,source_ip,result\n"
        "2026-08-17T09:00:00,old_admin,10.0.0.50,failure\n",
        encoding="utf-8",
    )

    disabled_file.write_text(
        "old_admin\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            str(input_file),
            "--disabled-accounts",
            str(disabled_file),
            "--report",
            str(output_file),
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert output_file.exists()

    report = output_file.read_text(encoding="utf-8")

    assert "Authentication Attempt Against Disabled Account" in report
    assert "AUTH-DA-001" in report
    assert "Severity: medium" in report
    assert "Source IP: 10.0.0.50" in report
    assert "Username: old_admin" in report
    assert "Result: failure" in report
    assert "First seen: 2026-08-17T09:00:00" in report
    assert "Last seen: 2026-08-17T09:00:00" in report

    assert f"Incident report written to: {output_file}" in result.stdout


def test_cli_missing_disabled_accounts_file_returns_error(tmp_path):
    input_file = tmp_path / "auth_log.csv"
    missing_file = tmp_path / "missing_disabled_accounts.txt"

    input_file.write_text(
        "timestamp,username,source_ip,result\n"
        "2026-08-17T09:00:00,old_admin,10.0.0.50,failure\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            str(input_file),
            "--disabled-accounts",
            str(missing_file),
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert (
        f"[ERROR] Disabled accounts file not found: {missing_file}"
        in result.stderr
    )


def test_cli_detects_one_ip_many_accounts(tmp_path):
    input_file = tmp_path / "many_accounts.csv"

    input_file.write_text(
        "timestamp,username,source_ip,result\n"
        "2026-08-17T09:00:00,alice,10.0.0.50,success\n"
        "2026-08-17T09:01:00,bob,10.0.0.50,success\n"
        "2026-08-17T09:02:00,charlie,10.0.0.50,success\n"
        "2026-08-17T09:03:00,david,10.0.0.50,success\n"
        "2026-08-17T09:04:00,admin,10.0.0.50,success\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            str(input_file),
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "One Source IP Accessing Multiple Accounts" in result.stdout
    assert "Rule ID: AUTH-MA-001" in result.stdout
    assert "Severity: medium" in result.stdout
    assert "Source IP: 10.0.0.50" in result.stdout
    assert "Unique accounts: 5" in result.stdout
    assert "Usernames: admin, alice, bob, charlie, david" in result.stdout


def test_cli_generates_one_ip_many_accounts_report(tmp_path):
    input_file = tmp_path / "many_accounts.csv"
    output_file = tmp_path / "many_accounts_report.md"

    input_file.write_text(
        "timestamp,username,source_ip,result\n"
        "2026-08-17T09:00:00,alice,10.0.0.50,success\n"
        "2026-08-17T09:01:00,bob,10.0.0.50,success\n"
        "2026-08-17T09:02:00,charlie,10.0.0.50,success\n"
        "2026-08-17T09:03:00,david,10.0.0.50,success\n"
        "2026-08-17T09:04:00,admin,10.0.0.50,success\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            str(input_file),
            "--report",
            str(output_file),
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert output_file.exists()

    report = output_file.read_text(encoding="utf-8")

    assert "One Source IP Accessing Multiple Accounts" in report
    assert "AUTH-MA-001" in report
    assert "Severity: medium" in report
    assert "Source IP: 10.0.0.50" in report
    assert "Unique accounts: 5" in report
    assert "Usernames: admin, alice, bob, charlie, david" in report
    assert "First seen: 2026-08-17T09:00:00" in report
    assert "Last seen: 2026-08-17T09:04:00" in report

    assert f"Incident report written to: {output_file}" in result.stdout


def test_cli_detects_many_ips_one_account(tmp_path):
    input_file = tmp_path / "many_ips.csv"

    input_file.write_text(
        "timestamp,username,source_ip,result\n"
        "2026-08-19T09:00:00,admin,10.0.0.10,success\n"
        "2026-08-19T09:01:00,admin,10.0.0.20,success\n"
        "2026-08-19T09:02:00,admin,10.0.0.30,success\n"
        "2026-08-19T09:03:00,admin,10.0.0.40,success\n"
        "2026-08-19T09:04:00,admin,10.0.0.50,success\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            str(input_file),
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "One Account Accessed From Multiple Source IPs" in result.stdout
    assert "Rule ID: AUTH-MI-001" in result.stdout
    assert "Severity: medium" in result.stdout
    assert "Username: admin" in result.stdout
    assert "Unique source IPs: 5" in result.stdout
    assert (
        "Source IPs: 10.0.0.10, 10.0.0.20, 10.0.0.30, "
        "10.0.0.40, 10.0.0.50"
        in result.stdout
    )


def test_cli_generates_many_ips_one_account_report(tmp_path):
    input_file = tmp_path / "many_ips.csv"
    output_file = tmp_path / "many_ips_report.md"

    input_file.write_text(
        "timestamp,username,source_ip,result\n"
        "2026-08-19T09:00:00,admin,10.0.0.10,success\n"
        "2026-08-19T09:01:00,admin,10.0.0.20,success\n"
        "2026-08-19T09:02:00,admin,10.0.0.30,success\n"
        "2026-08-19T09:03:00,admin,10.0.0.40,success\n"
        "2026-08-19T09:04:00,admin,10.0.0.50,success\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            str(input_file),
            "--report",
            str(output_file),
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert output_file.exists()

    report = output_file.read_text(encoding="utf-8")

    assert "One Account Accessed From Multiple Source IPs" in report
    assert "AUTH-MI-001" in report
    assert "Severity: medium" in report
    assert "Username: admin" in report
    assert "Unique source IPs: 5" in report
    assert (
        "Source IPs: 10.0.0.10, 10.0.0.20, 10.0.0.30, "
        "10.0.0.40, 10.0.0.50"
        in report
    )
    assert "First seen: 2026-08-19T09:00:00" in report
    assert "Last seen: 2026-08-19T09:04:00" in report

    assert f"Incident report written to: {output_file}" in result.stdout


def test_cli_uses_custom_detection_config(tmp_path):
    input_file = tmp_path / "auth.csv"
    config_file = tmp_path / "config.json"

    input_file.write_text(
        "timestamp,username,source_ip,result\n"
        "2026-08-19T09:00:00,admin,10.0.0.50,failure\n"
        "2026-08-19T09:00:10,admin,10.0.0.50,failure\n"
        "2026-08-19T09:00:20,admin,10.0.0.50,failure\n",
        encoding="utf-8",
    )

    config_file.write_text(
        """
{
    "AUTH-BF-001": {
        "threshold": 3
    }
}
""",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            str(input_file),
            "--config",
            str(config_file),
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "Potential Brute-Force Activity" in result.stdout
    assert "Rule ID: AUTH-BF-001" in result.stdout


def test_cli_missing_config_file_returns_error(tmp_path):
    input_file = tmp_path / "auth.csv"
    missing_config = tmp_path / "missing_config.json"

    input_file.write_text(
        "timestamp,username,source_ip,result\n"
        "2026-08-19T09:00:00,admin,10.0.0.50,failure\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            str(input_file),
            "--config",
            str(missing_config),
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert (
        f"[ERROR] Configuration file not found: {missing_config}"
        in result.stderr
    )


def test_cli_invalid_detection_config_returns_error(tmp_path):
    input_file = tmp_path / "auth.csv"
    config_file = tmp_path / "config.json"

    input_file.write_text(
        "timestamp,username,source_ip,result\n"
        "2026-08-19T09:00:00,admin,10.0.0.50,failure\n",
        encoding="utf-8",
    )

    config_file.write_text(
        """
{
    "AUTH-UNKNOWN-001": {
        "threshold": 3
    }
}
""",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            str(input_file),
            "--config",
            str(config_file),
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert (
        "[ERROR] Invalid detection configuration: "
        "Unknown rule ID: AUTH-UNKNOWN-001"
        in result.stderr
    )


def test_cli_malformed_detection_config_returns_error(tmp_path):
    input_file = tmp_path / "auth.csv"
    config_file = tmp_path / "config.json"

    input_file.write_text(
        "timestamp,username,source_ip,result\n"
        "2026-08-19T09:00:00,admin,10.0.0.50,failure\n",
        encoding="utf-8",
    )

    config_file.write_text(
        """
{
    "AUTH-BF-001": {
        "threshold": 3
""",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            str(input_file),
            "--config",
            str(config_file),
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "[ERROR] Invalid detection configuration:" in result.stderr


def test_cli_detects_brute_force_from_json(tmp_path):
    input_file = tmp_path / "auth.json"

    input_file.write_text(
        """
[
    {
        "timestamp": "2026-08-19T09:00:00",
        "username": "admin",
        "source_ip": "10.0.0.50",
        "result": "failure"
    },
    {
        "timestamp": "2026-08-19T09:00:10",
        "username": "admin",
        "source_ip": "10.0.0.50",
        "result": "failure"
    },
    {
        "timestamp": "2026-08-19T09:00:20",
        "username": "admin",
        "source_ip": "10.0.0.50",
        "result": "failure"
    },
    {
        "timestamp": "2026-08-19T09:00:30",
        "username": "admin",
        "source_ip": "10.0.0.50",
        "result": "failure"
    },
    {
        "timestamp": "2026-08-19T09:00:40",
        "username": "admin",
        "source_ip": "10.0.0.50",
        "result": "failure"
    }
]
""",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            str(input_file),
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "Potential Brute-Force Activity" in result.stdout
    assert "Rule ID: AUTH-BF-001" in result.stdout


def test_cli_generates_report_from_json(tmp_path):
    input_file = tmp_path / "auth.json"
    output_file = tmp_path / "json_report.md"

    input_file.write_text(
        """
[
    {
        "timestamp": "2026-08-19T09:00:00",
        "username": "admin",
        "source_ip": "10.0.0.50",
        "result": "failure"
    },
    {
        "timestamp": "2026-08-19T09:00:10",
        "username": "admin",
        "source_ip": "10.0.0.50",
        "result": "failure"
    },
    {
        "timestamp": "2026-08-19T09:00:20",
        "username": "admin",
        "source_ip": "10.0.0.50",
        "result": "failure"
    },
    {
        "timestamp": "2026-08-19T09:00:30",
        "username": "admin",
        "source_ip": "10.0.0.50",
        "result": "failure"
    },
    {
        "timestamp": "2026-08-19T09:00:40",
        "username": "admin",
        "source_ip": "10.0.0.50",
        "result": "failure"
    }
]
""",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            str(input_file),
            "--report",
            str(output_file),
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert output_file.exists()

    report = output_file.read_text(encoding="utf-8")

    assert "Potential Brute-Force Activity" in report
    assert "AUTH-BF-001" in report
    assert "Source IP: 10.0.0.50" in report
    assert "Username: admin" in report

    assert f"Incident report written to: {output_file}" in result.stdout


def test_cli_malformed_json_log_returns_error(tmp_path):
    input_file = tmp_path / "auth.json"

    input_file.write_text(
        """
[
    {
        "timestamp": "2026-08-19T09:00:00",
        "username": "admin"
""",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            str(input_file),
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "[ERROR] Invalid authentication log:" in result.stderr


def test_cli_rejects_unsupported_log_format(tmp_path):
    input_file = tmp_path / "auth.txt"

    input_file.write_text(
        "unsupported log format",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            str(input_file),
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert (
        "[ERROR] Invalid authentication log: "
        "Unsupported authentication log format: expected .csv or .json"
        in result.stderr
    )
