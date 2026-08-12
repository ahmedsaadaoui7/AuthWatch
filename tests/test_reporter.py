from src.reporter import generate_markdown_report


def test_generate_markdown_report(tmp_path):
    alerts = [
        {
            "rule_id": "AUTH-BF-001",
            "title": "Potential Brute-Force Activity",
            "severity": "high",
            "source_ip": "10.0.0.50",
            "username": "admin",
            "failed_attempts": 5,
            "first_seen": "2026-08-08T09:00:00",
            "last_seen": "2026-08-08T09:00:48",
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
