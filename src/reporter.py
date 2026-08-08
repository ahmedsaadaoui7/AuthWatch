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
                f"## Alert {index}: Potential Brute-Force Activity",
                "",
                f"- Source IP: {alert['source_ip']}",
                f"- Username: {alert['username']}",
                f"- Failed attempts: {alert['failed_attempts']}",
                f"- First failure: {alert['first_failure']}",
                f"- Last failure: {alert['last_failure']}",
                "",
            ]
        )

    output_path.write_text("\n".join(lines), encoding="utf-8")

    return output_path
