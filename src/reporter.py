from pathlib import Path


def generate_markdown_report(alerts, output_path):
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        "# AuthWatch Incident Report",
        "",
        "## Detection Summary",
        "",
        f"Total alerts: {len(alerts)}",
        "",
    ]

    for index, alert in enumerate(alerts, start=1):
        lines.extend(
            [
                f"## Alert {index}: {alert['title']}",
                "",
                f"- Rule ID: {alert['rule_id']}",
                f"- Severity: {alert['severity']}",
                f"- Source IP: {alert['source_ip']}",
                f"- Username: {alert['username']}",
                f"- Failed attempts: {alert['failed_attempts']}",
                f"- First seen: {alert['first_seen']}",
                f"- Last seen: {alert['last_seen']}",
                "",
            ]
        )

    output_path.write_text("\n".join(lines), encoding="utf-8")

    return output_path
