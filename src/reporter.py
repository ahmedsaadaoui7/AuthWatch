import json
from pathlib import Path

from src.formatter import format_alert_details


def generate_markdown_report(alerts, output_path):
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    high_severity_count = sum(
        1 for alert in alerts
        if alert["severity"] == "high"
    )

    medium_severity_count = sum(
        1 for alert in alerts
        if alert["severity"] == "medium"
    )

    lines = [
        "# AuthWatch Incident Report",
        "",
        "## Detection Summary",
        "",
        f"- Total alerts: {len(alerts)}",
        f"- High severity: {high_severity_count}",
        f"- Medium severity: {medium_severity_count}",
        "",
    ]

    for index, alert in enumerate(alerts, start=1):
        lines.extend(
            [
                f"## Alert {index}: {alert['title']}",
                "",
                f"- Rule ID: {alert['rule_id']}",
                f"- Severity: {alert['severity']}",
            ]
        )

        for line in format_alert_details(alert["details"]):
            lines.append(f"- {line}")

        lines.extend(
            [
                f"- First seen: {alert['first_seen']}",
                f"- Last seen: {alert['last_seen']}",
                "",
            ]
        )

    output_path.write_text("\n".join(lines), encoding="utf-8")

    return output_path


def generate_json_report(alerts, output_path):
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    report = {
        "total_alerts": len(alerts),
        "alerts": alerts,
    }

    output_path.write_text(
        json.dumps(report, indent=4) + "\n",
        encoding="utf-8",
    )

    return output_path
