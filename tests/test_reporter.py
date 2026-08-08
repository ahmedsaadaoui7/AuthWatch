from src.reporter import generate_markdown_report


def test_generate_markdown_report(tmp_path):
    alerts = [
        {
            "source_ip": "10.0.0.50",
            "username": "admin",
            "failed_attempts": 5,
            "first_failure": "2026-08-08T09:00:00",
            "last_failure": "2026-08-08T09:00:48",
        }
    ]

    output_file = tmp_path / "incident_report.md"

    result = generate_markdown_report(alerts, output_file)

    assert result == output_file
    assert output_file.exists()

    content = output_file.read_text(encoding="utf-8")

    assert "# AuthWatch Incident Report" in content
    assert "Total alerts: 1" in content
    assert "10.0.0.50" in content
    assert "admin" in content
    assert "Failed attempts: 5" in content
