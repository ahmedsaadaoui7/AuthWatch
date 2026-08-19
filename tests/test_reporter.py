import json

from src.reporter import generate_json_report, generate_markdown_report


def test_generate_markdown_report(tmp_path):
    alerts = [
        {
            "rule_id": "AUTH-BF-001",
            "title": "Potential Brute-Force Activity",
            "severity": "high",
            "first_seen": "2026-08-08T09:00:00",
            "last_seen": "2026-08-08T09:00:48",
            "details": {
                "source_ip": "10.0.0.50",
                "username": "admin",
                "failed_attempts": 5,
            },
        }
    ]

    output_file = tmp_path / "incident_report.md"

    result = generate_markdown_report(alerts, output_file)

    assert result == output_file
    assert output_file.exists()

    content = output_file.read_text(encoding="utf-8")

    assert "## Alert 1: Potential Brute-Force Activity" in content
    assert "Rule ID: AUTH-BF-001" in content
    assert "Severity: high" in content
    assert "Source IP: 10.0.0.50" in content
    assert "Username: admin" in content
    assert "Failed attempts: 5" in content
    assert "First seen: 2026-08-08T09:00:00" in content
    assert "Last seen: 2026-08-08T09:00:48" in content


def test_generate_json_report(tmp_path):
    alerts = [
        {
            "rule_id": "AUTH-BF-001",
            "title": "Potential Brute-Force Activity",
            "severity": "high",
            "first_seen": "2026-08-08T09:00:00",
            "last_seen": "2026-08-08T09:00:48",
            "details": {
                "source_ip": "10.0.0.50",
                "username": "admin",
                "failed_attempts": 5,
            },
        }
    ]

    output_file = tmp_path / "alerts.json"

    result = generate_json_report(alerts, output_file)

    assert result == output_file
    assert output_file.exists()

    content = json.loads(
        output_file.read_text(encoding="utf-8")
    )

    assert content["total_alerts"] == 1
    assert len(content["alerts"]) == 1

    alert = content["alerts"][0]

    assert alert["rule_id"] == "AUTH-BF-001"
    assert alert["title"] == "Potential Brute-Force Activity"
    assert alert["severity"] == "high"
    assert alert["first_seen"] == "2026-08-08T09:00:00"
    assert alert["last_seen"] == "2026-08-08T09:00:48"

    assert alert["details"]["source_ip"] == "10.0.0.50"
    assert alert["details"]["username"] == "admin"
    assert alert["details"]["failed_attempts"] == 5
