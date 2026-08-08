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

    assert "[ALERT] Potential brute-force activity detected" in result.stdout
    assert "Source IP: 10.0.0.50" in result.stdout
    assert "Username: admin" in result.stdout


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
