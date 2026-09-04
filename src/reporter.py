import json
from pathlib import Path

from src.formatter import format_alert_details
from src.timeline import build_timeline


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


def collect_investigation_entities(alerts, correlations):
    users = set()
    hosts = set()
    ip_addresses = set()

    results = list(alerts) + list(correlations)

    for result in results:
        details = result.get("details", {})

        username = details.get("username")
        if username:
            users.add(username)

        for username in details.get("usernames", []):
            if username:
                users.add(username)

        host = details.get("host")
        if host:
            hosts.add(host)

        source_ip = details.get("source_ip")
        if source_ip:
            ip_addresses.add(source_ip)

        for source_ip in details.get("source_ips", []):
            if source_ip:
                ip_addresses.add(source_ip)

        destination_ip = details.get("destination_ip")
        if destination_ip:
            ip_addresses.add(destination_ip)

    return {
        "users": sorted(users),
        "hosts": sorted(hosts),
        "ip_addresses": sorted(ip_addresses),
    }


def collect_mitre_mappings(alerts, correlations):
    mappings = {}

    results = list(alerts) + list(correlations)

    for result in results:
        mapping = result.get("mitre")

        if not mapping:
            continue

        technique_id = mapping.get("technique_id")

        if not technique_id:
            continue

        mappings[technique_id] = mapping

    return [
        mappings[technique_id]
        for technique_id in sorted(mappings)
    ]


def collect_supporting_evidence(alerts, correlations):
    detection_evidence = []
    correlation_evidence = []

    for alert in alerts:
        detection_evidence.append({
            "rule_id": alert.get("rule_id"),
            "details": alert.get("details", {}),
        })

    for correlation in correlations:
        event_references = []

        for event in correlation.get("related_events", []):
            event_references.append({
                "timestamp": event.get("timestamp"),
                "source": event.get("source"),
                "event_id": event.get("event_id"),
                "event_type": event.get("event_type"),
                "host": event.get("host"),
            })

        correlation_evidence.append({
            "correlation_id": correlation.get("correlation_id"),
            "details": correlation.get("details", {}),
            "event_references": event_references,
        })

    return {
        "detections": detection_evidence,
        "correlations": correlation_evidence,
    }


def collect_investigation_timeline(correlations):
    unique_events = {}

    for correlation in correlations:
        for event in correlation.get("related_events", []):
            fingerprint = json.dumps(
                event,
                sort_keys=True,
                separators=(",", ":"),
            )

            unique_events[fingerprint] = event

    return build_timeline(
        unique_events.values()
    )


def build_investigation_report(alerts, correlations):
    high_severity_alerts = sum(
        1 for alert in alerts
        if alert["severity"] == "high"
    )

    medium_severity_alerts = sum(
        1 for alert in alerts
        if alert["severity"] == "medium"
    )

    high_severity_correlations = sum(
        1 for correlation in correlations
        if correlation["severity"] == "high"
    )

    medium_severity_correlations = sum(
        1 for correlation in correlations
        if correlation["severity"] == "medium"
    )

    detection_rule_ids = sorted({
        alert["rule_id"]
        for alert in alerts
        if alert.get("rule_id")
    })

    correlation_ids = sorted({
        correlation["correlation_id"]
        for correlation in correlations
        if correlation.get("correlation_id")
    })

    affected_entities = collect_investigation_entities(
        alerts,
        correlations,
    )

    mitre_mappings = collect_mitre_mappings(
        alerts,
        correlations,
    )

    investigation_timeline = collect_investigation_timeline(
        correlations,
    )

    supporting_evidence = collect_supporting_evidence(
        alerts,
        correlations,
    )

    return {
        "detection_summary": {
            "total": len(alerts),
            "high": high_severity_alerts,
            "medium": medium_severity_alerts,
        },
        "correlation_summary": {
            "total": len(correlations),
            "high": high_severity_correlations,
            "medium": medium_severity_correlations,
        },
        "related_ids": {
            "detection_rule_ids": detection_rule_ids,
            "correlation_ids": correlation_ids,
        },
        "affected_entities": affected_entities,
        "mitre_mappings": mitre_mappings,
        "supporting_evidence": supporting_evidence,
        "timeline": investigation_timeline,
        "detections": alerts,
        "correlations": correlations,
    }


def generate_investigation_json_report(
    alerts,
    correlations,
    output_path,
):
    output_path = Path(output_path)
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    report = build_investigation_report(
        alerts,
        correlations,
    )

    output_path.write_text(
        json.dumps(report, indent=4) + "\n",
        encoding="utf-8",
    )

    return output_path


def generate_investigation_markdown_report(
    alerts,
    correlations,
    output_path,
):
    output_path = Path(output_path)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    report = build_investigation_report(
        alerts,
        correlations,
    )

    detection_summary = report["detection_summary"]
    correlation_summary = report["correlation_summary"]

    affected_entities = report["affected_entities"]
    related_ids = report["related_ids"]
    mitre_mappings = report["mitre_mappings"]
    investigation_timeline = report["timeline"]
    supporting_evidence = report["supporting_evidence"]

    lines = [
        "# AuthWatch V3 Investigation Report",
        "",
        "## Detection Summary",
        "",
        f"- Total detections: {detection_summary['total']}",
        f"- High severity: {detection_summary['high']}",
        f"- Medium severity: {detection_summary['medium']}",
        "",
        "## Correlation Summary",
        "",
        f"- Total correlations: {correlation_summary['total']}",
        f"- High severity: {correlation_summary['high']}",
        f"- Medium severity: {correlation_summary['medium']}",
        "",
    ]

    lines.extend([
        "## Affected Entities",
        "",
        "### Users",
        "",
    ])

    if affected_entities["users"]:
        for username in affected_entities["users"]:
            lines.append(f"- {username}")
    else:
        lines.append("- None")

    lines.extend([
        "",
        "### Hosts",
        "",
    ])

    if affected_entities["hosts"]:
        for host in affected_entities["hosts"]:
            lines.append(f"- {host}")
    else:
        lines.append("- None")

    lines.extend([
        "",
        "### IP Addresses",
        "",
    ])

    if affected_entities["ip_addresses"]:
        for ip_address in affected_entities["ip_addresses"]:
            lines.append(f"- {ip_address}")
    else:
        lines.append("- None")

    lines.append("")

    lines.extend([
        "## Related IDs",
        "",
        "### Detection Rule IDs",
        "",
    ])

    if related_ids["detection_rule_ids"]:
        for rule_id in related_ids["detection_rule_ids"]:
            lines.append(f"- {rule_id}")
    else:
        lines.append("- None")

    lines.extend([
        "",
        "### Correlation IDs",
        "",
    ])

    if related_ids["correlation_ids"]:
        for correlation_id in related_ids["correlation_ids"]:
            lines.append(f"- {correlation_id}")
    else:
        lines.append("- None")

    lines.append("")

    lines.extend([
        "## MITRE ATT&CK Mappings",
        "",
    ])

    if mitre_mappings:
        for mapping in mitre_mappings:
            lines.extend([
                (
                    f"### {mapping['technique_id']} — "
                    f"{mapping['technique_name']}"
                ),
                "",
                f"- Evidence: {mapping['evidence']}",
                "",
            ])
    else:
        lines.extend([
            "- None",
            "",
        ])

    lines.extend([
        "## Investigation Timeline",
        "",
    ])

    if investigation_timeline:
        for entry in investigation_timeline:
            lines.append(
                f"- {entry['timestamp']} — "
                f"{entry['description']}"
            )
    else:
        lines.append("- None")

    lines.append("")

    lines.extend([
        "## Supporting Evidence",
        "",
        "### Detection Evidence",
        "",
    ])

    if supporting_evidence["detections"]:
        for evidence in supporting_evidence["detections"]:
            lines.append(
                f"#### {evidence['rule_id']}"
            )
            lines.append("")

            details = evidence["details"]

            if details:
                for key, value in details.items():
                    lines.append(
                        f"- {key}: {value}"
                    )
            else:
                lines.append("- No additional details")

            lines.append("")
    else:
        lines.extend([
            "- None",
            "",
        ])

    lines.extend([
        "### Correlation Evidence",
        "",
    ])

    if supporting_evidence["correlations"]:
        for evidence in supporting_evidence["correlations"]:
            lines.append(
                f"#### {evidence['correlation_id']}"
            )
            lines.append("")

            details = evidence["details"]

            if details:
                for key, value in details.items():
                    lines.append(
                        f"- {key}: {value}"
                    )
            else:
                lines.append("- No additional details")

            event_references = evidence["event_references"]

            if event_references:
                lines.append("- Related source events:")

                for event in event_references:
                    lines.append(
                        "  - "
                        f"{event['timestamp']} | "
                        f"{event['source']} | "
                        f"Event {event['event_id']} | "
                        f"{event['event_type']} | "
                        f"{event['host']}"
                    )

            lines.append("")
    else:
        lines.extend([
            "- None",
            "",
        ])

    lines.extend([
        "## Detections",
        "",
    ])

    if alerts:
        for index, alert in enumerate(alerts, start=1):
            title = (
                alert.get("title")
                or "Untitled Detection"
            )

            lines.extend([
                f"### Detection {index}: {title}",
                "",
                f"- Rule ID: {alert.get('rule_id', 'Unknown')}",
                f"- Severity: {alert.get('severity', 'Unknown')}",
                f"- First seen: {alert.get('first_seen', 'Unknown')}",
                f"- Last seen: {alert.get('last_seen', 'Unknown')}",
                "",
            ])
    else:
        lines.extend([
            "- None",
            "",
        ])

    lines.extend([
        "## Correlations",
        "",
    ])

    if correlations:
        for index, correlation in enumerate(
            correlations,
            start=1,
        ):
            title = (
                correlation.get("title")
                or "Untitled Correlation"
            )

            lines.extend([
                f"### Correlation {index}: {title}",
                "",
                (
                    "- Correlation ID: "
                    f"{correlation.get('correlation_id', 'Unknown')}"
                ),
                (
                    "- Severity: "
                    f"{correlation.get('severity', 'Unknown')}"
                ),
                (
                    "- First seen: "
                    f"{correlation.get('first_seen', 'Unknown')}"
                ),
                (
                    "- Last seen: "
                    f"{correlation.get('last_seen', 'Unknown')}"
                ),
                "",
            ])
    else:
        lines.extend([
            "- None",
            "",
        ])

    output_path.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )

    return output_path
