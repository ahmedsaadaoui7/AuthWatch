import json
import subprocess
import sys
from pathlib import Path

import main as authwatch_main


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


def test_cli_generates_json_output(tmp_path):
    input_file = "data/brute_force_auth_log.csv"
    output_file = tmp_path / "alerts.json"

    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            input_file,
            "--json-output",
            str(output_file),
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert output_file.exists()

    content = json.loads(
        output_file.read_text(encoding="utf-8")
    )

    assert content["total_alerts"] == 1
    assert len(content["alerts"]) == 1

    alert = content["alerts"][0]

    assert alert["rule_id"] == "AUTH-BF-001"
    assert alert["severity"] == "high"
    assert alert["details"]["source_ip"] == "10.0.0.50"
    assert alert["details"]["username"] == "admin"
    assert alert["details"]["failed_attempts"] == 5
    assert f"JSON alert output written to: {output_file}" in result.stdout


def test_cli_generates_empty_json_output_when_no_alerts(tmp_path):
    input_file = "data/normal_auth_log.csv"
    output_file = tmp_path / "alerts.json"

    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            input_file,
            "--json-output",
            str(output_file),
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert output_file.exists()

    content = json.loads(
        output_file.read_text(encoding="utf-8")
    )

    assert content["total_alerts"] == 0
    assert content["alerts"] == []


def test_cli_generates_markdown_and_json_outputs_together(tmp_path):
    input_file = "data/brute_force_auth_log.csv"
    markdown_file = tmp_path / "incident.md"
    json_file = tmp_path / "alerts.json"

    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            input_file,
            "--report",
            str(markdown_file),
            "--json-output",
            str(json_file),
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert markdown_file.exists()
    assert json_file.exists()

    assert (
        f"Incident report written to: {markdown_file}"
        in result.stdout
    )
    assert (
        f"JSON alert output written to: {json_file}"
        in result.stdout
    )


def test_cli_accepts_json_input_and_generates_json_output(tmp_path):
    input_file = "data/brute_force_auth_log.json"
    output_file = tmp_path / "alerts.json"

    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            input_file,
            "--json-output",
            str(output_file),
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert output_file.exists()

    content = json.loads(
        output_file.read_text(encoding="utf-8")
    )

    assert content["total_alerts"] == 1
    assert content["alerts"][0]["rule_id"] == "AUTH-BF-001"


def test_cli_missing_windows_security_file_returns_error(
    tmp_path,
):
    missing_file = tmp_path / "missing_security.evtx"

    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            "--windows-security",
            str(missing_file),
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1

    assert (
        f"[ERROR] Windows Security EVTX not found: "
        f"{missing_file}"
        in result.stderr
    )


def test_cli_processes_windows_security_events(
    monkeypatch,
    capsys,
):
    windows_events = [
        {
            "timestamp": "2026-09-05T10:00:00Z",
            "event_type": "authentication_failure",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-09-05T10:00:10Z",
            "event_type": "authentication_failure",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-09-05T10:00:20Z",
            "event_type": "authentication_failure",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-09-05T10:00:30Z",
            "event_type": "authentication_failure",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-09-05T10:00:40Z",
            "event_type": "authentication_failure",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
    ]

    monkeypatch.setattr(
        authwatch_main,
        "load_windows_security_events",
        lambda file_path: windows_events,
    )

    monkeypatch.setattr(
        authwatch_main,
        "normalize_windows_security_event",
        lambda event: event,
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "main.py",
            "--windows-security",
            "Security.evtx",
        ],
    )

    result = authwatch_main.main()

    captured = capsys.readouterr()

    assert result == 0
    assert "[ALERT] Potential Brute-Force Activity" in captured.out
    assert "Rule ID: AUTH-BF-001" in captured.out


def test_cli_missing_sysmon_file_returns_error(
    tmp_path,
):
    missing_file = tmp_path / "missing_sysmon.evtx"

    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            "--sysmon",
            str(missing_file),
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1

    assert (
        f"[ERROR] Sysmon EVTX not found: "
        f"{missing_file}"
        in result.stderr
    )


def test_cli_processes_sysmon_events(
    monkeypatch,
    capsys,
):
    raw_event = {
        "event_id": "1",
    }

    normalized_event = {
        "timestamp": "2026-09-05T10:00:00Z",
        "source": "sysmon",
        "event_id": "1",
        "event_type": "process_creation",
        "host": "WIN-PC01",
        "username": "admin",
        "process_name": "powershell.exe",
        "process_guid": "{TEST-GUID}",
    }

    received = {}

    monkeypatch.setattr(
        authwatch_main,
        "load_sysmon_events",
        lambda file_path: [raw_event],
    )

    monkeypatch.setattr(
        authwatch_main,
        "normalize_sysmon_event",
        lambda event: normalized_event,
    )

    def fake_run_detection_engine(
        events,
        disabled_accounts=None,
        config=None,
    ):
        received["events"] = events
        return []

    monkeypatch.setattr(
        authwatch_main,
        "run_detection_engine",
        fake_run_detection_engine,
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "main.py",
            "--sysmon",
            "Sysmon.evtx",
        ],
    )

    result = authwatch_main.main()

    captured = capsys.readouterr()

    assert result == 0

    assert received["events"] == [
        normalized_event,
    ]

    assert (
        "No suspicious activity or correlations detected."
        in captured.out
    )


def test_cli_linux_auth_requires_timestamp_context():
    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            "--linux-auth",
            "auth.log",
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2

    assert (
        "--linux-auth requires "
        "--linux-year and --linux-utc-offset"
        in result.stderr
    )


def test_cli_missing_linux_auth_file_returns_error(
    tmp_path,
):
    missing_file = tmp_path / "missing_auth.log"

    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            "--linux-auth",
            str(missing_file),
            "--linux-year",
            "2026",
            "--linux-utc-offset",
            "+01:00",
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1

    assert (
        f"[ERROR] Linux authentication log not found: "
        f"{missing_file}"
        in result.stderr
    )


def test_cli_processes_linux_auth_events(
    monkeypatch,
    capsys,
):
    raw_event = {
        "timestamp": "Sep 5 22:30:00",
        "event_type": "authentication_success",
        "host": "kali",
        "username": "admin",
        "source_ip": "10.0.0.8",
        "result": "success",
    }

    normalized_event = {
        "timestamp": "2026-09-05T21:30:00Z",
        "source": "linux_auth",
        "event_type": "authentication_success",
        "host": "kali",
        "username": "admin",
        "source_ip": "10.0.0.8",
        "result": "success",
    }

    received = {}

    monkeypatch.setattr(
        authwatch_main,
        "load_linux_auth_events",
        lambda file_path: [raw_event],
    )

    def fake_normalize_linux_auth_event(
        event,
        *,
        year,
        utc_offset,
    ):
        received["year"] = year
        received["utc_offset"] = utc_offset
        return normalized_event

    monkeypatch.setattr(
        authwatch_main,
        "normalize_linux_auth_event",
        fake_normalize_linux_auth_event,
    )

    def fake_run_detection_engine(
        events,
        disabled_accounts=None,
        config=None,
    ):
        received["events"] = events
        return []

    monkeypatch.setattr(
        authwatch_main,
        "run_detection_engine",
        fake_run_detection_engine,
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "main.py",
            "--linux-auth",
            "auth.log",
            "--linux-year",
            "2026",
            "--linux-utc-offset",
            "+01:00",
        ],
    )

    result = authwatch_main.main()

    captured = capsys.readouterr()

    assert result == 0

    assert received["year"] == 2026
    assert received["utc_offset"] == "+01:00"

    assert received["events"] == [
        normalized_event,
    ]

    assert (
        "No suspicious activity or correlations detected."
        in captured.out
    )


def test_cli_keeps_correlation_when_no_detections(
    monkeypatch,
    capsys,
):
    normalized_event = {
        "timestamp": "2026-09-05T10:00:00Z",
        "source": "sysmon",
        "event_id": "1",
        "event_type": "process_creation",
        "host": "WIN-PC01",
        "process_guid": "{TEST-GUID}",
    }

    correlation = {
        "correlation_id": "CORR-PROC-NET-001",
        "title": "Process to Network Activity",
        "severity": "medium",
        "first_seen": "2026-09-05T10:00:00Z",
        "last_seen": "2026-09-05T10:00:10Z",
        "details": {},
        "related_events": [],
    }

    monkeypatch.setattr(
        authwatch_main,
        "load_sysmon_events",
        lambda file_path: [normalized_event],
    )

    monkeypatch.setattr(
        authwatch_main,
        "normalize_sysmon_event",
        lambda event: event,
    )

    monkeypatch.setattr(
        authwatch_main,
        "run_detection_engine",
        lambda events, disabled_accounts=None, config=None: [],
    )

    monkeypatch.setattr(
        authwatch_main,
        "run_correlation_engine",
        lambda events: [correlation],
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "main.py",
            "--sysmon",
            "Sysmon.evtx",
        ],
    )

    result = authwatch_main.main()

    captured = capsys.readouterr()

    assert result == 0

    assert (
        "No suspicious authentication activity detected."
        not in captured.out
    )


def test_cli_applies_mitre_mappings_to_results(
    monkeypatch,
):
    alert = {
        "rule_id": "AUTH-BF-001",
        "title": "Potential Brute-Force Activity",
        "severity": "high",
        "first_seen": "2026-09-05T10:00:00Z",
        "last_seen": "2026-09-05T10:00:40Z",
        "details": {},
    }

    correlation = {
        "correlation_id": "CORR-PROC-NET-001",
        "title": "Process to Network Activity",
        "severity": "medium",
        "first_seen": "2026-09-05T10:00:00Z",
        "last_seen": "2026-09-05T10:00:10Z",
        "details": {},
        "related_events": [],
    }

    received = []

    monkeypatch.setattr(
        authwatch_main,
        "load_sysmon_events",
        lambda file_path: [],
    )

    monkeypatch.setattr(
        authwatch_main,
        "run_detection_engine",
        lambda events, disabled_accounts=None, config=None: [alert],
    )

    monkeypatch.setattr(
        authwatch_main,
        "run_correlation_engine",
        lambda events: [correlation],
    )

    monkeypatch.setattr(
        authwatch_main,
        "attach_timelines_to_correlations",
        lambda correlations: correlations,
    )

    def fake_attach_mitre_mappings(results):
        received.append(results)
        return results

    monkeypatch.setattr(
        authwatch_main,
        "attach_mitre_mappings",
        fake_attach_mitre_mappings,
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "main.py",
            "--sysmon",
            "Sysmon.evtx",
        ],
    )

    result = authwatch_main.main()

    assert result == 0

    assert received == [
        [alert],
        [correlation],
    ]


def test_cli_generates_v3_markdown_report(
    tmp_path,
    monkeypatch,
):
    output_file = tmp_path / "investigation.md"

    correlation = {
        "correlation_id": "CORR-PROC-NET-001",
        "title": "Process to Network Activity",
        "severity": "medium",
        "first_seen": "2026-09-05T10:00:00Z",
        "last_seen": "2026-09-05T10:00:10Z",
        "details": {
            "host": "WIN-PC01",
        },
        "related_events": [],
    }

    monkeypatch.setattr(
        authwatch_main,
        "load_sysmon_events",
        lambda file_path: [],
    )

    monkeypatch.setattr(
        authwatch_main,
        "run_detection_engine",
        lambda events, disabled_accounts=None, config=None: [],
    )

    monkeypatch.setattr(
        authwatch_main,
        "run_correlation_engine",
        lambda events: [correlation],
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "main.py",
            "--sysmon",
            "Sysmon.evtx",
            "--report",
            str(output_file),
        ],
    )

    result = authwatch_main.main()

    assert result == 0
    assert output_file.exists()

    content = output_file.read_text(
        encoding="utf-8"
    )

    assert "# AuthWatch V3 Investigation Report" in content
    assert "CORR-PROC-NET-001" in content


def test_cli_generates_v3_json_report(
    tmp_path,
    monkeypatch,
):
    output_file = tmp_path / "investigation.json"

    correlation = {
        "correlation_id": "CORR-PROC-NET-001",
        "title": "Process to Network Activity",
        "severity": "medium",
        "first_seen": "2026-09-05T10:00:00Z",
        "last_seen": "2026-09-05T10:00:10Z",
        "details": {
            "host": "WIN-PC01",
        },
        "related_events": [],
    }

    monkeypatch.setattr(
        authwatch_main,
        "load_sysmon_events",
        lambda file_path: [],
    )

    monkeypatch.setattr(
        authwatch_main,
        "run_detection_engine",
        lambda events, disabled_accounts=None, config=None: [],
    )

    monkeypatch.setattr(
        authwatch_main,
        "run_correlation_engine",
        lambda events: [correlation],
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "main.py",
            "--sysmon",
            "Sysmon.evtx",
            "--json-output",
            str(output_file),
        ],
    )

    result = authwatch_main.main()

    assert result == 0
    assert output_file.exists()

    content = json.loads(
        output_file.read_text(encoding="utf-8")
    )

    assert content["detection_summary"]["total"] == 0
    assert content["correlation_summary"]["total"] == 1

    assert content["related_ids"]["correlation_ids"] == [
        "CORR-PROC-NET-001",
    ]


def test_cli_generates_empty_v3_reports(
    tmp_path,
    monkeypatch,
    capsys,
):
    markdown_file = tmp_path / "investigation.md"
    json_file = tmp_path / "investigation.json"

    monkeypatch.setattr(
        authwatch_main,
        "load_sysmon_events",
        lambda file_path: [],
    )

    monkeypatch.setattr(
        authwatch_main,
        "run_detection_engine",
        lambda events, disabled_accounts=None, config=None: [],
    )

    monkeypatch.setattr(
        authwatch_main,
        "run_correlation_engine",
        lambda events: [],
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "main.py",
            "--sysmon",
            "Sysmon.evtx",
            "--report",
            str(markdown_file),
            "--json-output",
            str(json_file),
        ],
    )

    result = authwatch_main.main()

    captured = capsys.readouterr()

    assert result == 0

    assert (
        "No suspicious activity or correlations detected."
        in captured.out
    )

    assert markdown_file.exists()
    assert json_file.exists()

    markdown = markdown_file.read_text(
        encoding="utf-8"
    )

    assert "# AuthWatch V3 Investigation Report" in markdown

    content = json.loads(
        json_file.read_text(encoding="utf-8")
    )

    assert content["detection_summary"]["total"] == 0
    assert content["correlation_summary"]["total"] == 0
    assert content["detections"] == []
    assert content["correlations"] == []


def test_cli_missing_correlation_config_file_returns_error(
    tmp_path,
):
    missing_config = tmp_path / "missing_correlation.json"

    result = subprocess.run(
        [
            sys.executable,
            "main.py",
            "data/brute_force_auth_log.csv",
            "--correlation-config",
            str(missing_config),
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1

    assert (
        f"[ERROR] Correlation configuration file not found: "
        f"{missing_config}"
        in result.stderr
    )


def test_cli_uses_custom_correlation_config(
    tmp_path,
    monkeypatch,
):
    config_file = tmp_path / "correlation.json"

    config_file.write_text(
        """
{
    "CORR-PROC-NET-001": {
        "window_seconds": 120
    }
}
""",
        encoding="utf-8",
    )

    received = {}

    monkeypatch.setattr(
        authwatch_main,
        "load_sysmon_events",
        lambda file_path: [],
    )

    monkeypatch.setattr(
        authwatch_main,
        "run_detection_engine",
        lambda events, disabled_accounts=None, config=None: [],
    )

    def fake_run_correlation_engine(
        events,
        config=None,
    ):
        received["config"] = config
        return []

    monkeypatch.setattr(
        authwatch_main,
        "run_correlation_engine",
        fake_run_correlation_engine,
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "main.py",
            "--sysmon",
            "Sysmon.evtx",
            "--correlation-config",
            str(config_file),
        ],
    )

    result = authwatch_main.main()

    assert result == 0

    assert (
        received["config"]["CORR-PROC-NET-001"]["window_seconds"]
        == 120
    )


def test_cli_correlates_windows_authentication_with_sysmon_process(
    monkeypatch,
    capsys,
):
    windows_event = {
        "timestamp": "2026-09-06T10:00:00Z",
        "source": "windows_security",
        "event_id": "4624",
        "event_type": "authentication_success",
        "host": "WIN-PC01",
        "username": "admin",
        "session_id": "0x1234",
        "source_ip": "10.0.0.8",
        "result": "success",
    }

    sysmon_event = {
        "timestamp": "2026-09-06T10:00:10Z",
        "source": "sysmon",
        "event_id": "1",
        "event_type": "process_creation",
        "host": "WIN-PC01",
        "username": "admin",
        "session_id": "0x1234",
        "process_name": "powershell.exe",
        "process_id": "4321",
        "process_guid": "{TEST-GUID}",
    }

    monkeypatch.setattr(
        authwatch_main,
        "load_windows_security_events",
        lambda file_path: [windows_event],
    )

    monkeypatch.setattr(
        authwatch_main,
        "normalize_windows_security_event",
        lambda event: event,
    )

    monkeypatch.setattr(
        authwatch_main,
        "load_sysmon_events",
        lambda file_path: [sysmon_event],
    )

    monkeypatch.setattr(
        authwatch_main,
        "normalize_sysmon_event",
        lambda event: event,
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "main.py",
            "--windows-security",
            "Security.evtx",
            "--sysmon",
            "Sysmon.evtx",
        ],
    )

    result = authwatch_main.main()

    captured = capsys.readouterr()

    assert result == 0

    assert (
        "[CORRELATION] Authentication to Process Activity"
        in captured.out
    )

    assert (
        "Correlation ID: CORR-AUTH-EXEC-001"
        in captured.out
    )
