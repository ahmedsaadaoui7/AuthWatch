import json

from src.reporter import (
    build_investigation_report,
    collect_investigation_entities,
    collect_investigation_timeline,
    collect_mitre_mappings,
    collect_supporting_evidence,
    generate_investigation_json_report,
    generate_investigation_markdown_report,
    generate_json_report,
    generate_markdown_report,
)


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

    assert "Total alerts: 1" in content
    assert "High severity: 1" in content
    assert "Medium severity: 0" in content
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


def test_markdown_report_counts_severities(tmp_path):
    alerts = [
        {
            "rule_id": "AUTH-BF-001",
            "title": "Potential Brute-Force Activity",
            "severity": "high",
            "first_seen": "2026-08-08T09:00:00",
            "last_seen": "2026-08-08T09:00:48",
            "details": {},
        },
        {
            "rule_id": "AUTH-DA-001",
            "title": "Authentication Attempt Against Disabled Account",
            "severity": "medium",
            "first_seen": "2026-08-08T10:00:00",
            "last_seen": "2026-08-08T10:00:00",
            "details": {},
        },
        {
            "rule_id": "AUTH-PS-001",
            "title": "Potential Password Spraying Activity",
            "severity": "high",
            "first_seen": "2026-08-08T11:00:00",
            "last_seen": "2026-08-08T11:00:40",
            "details": {},
        },
    ]

    output_file = tmp_path / "incident_report.md"

    generate_markdown_report(alerts, output_file)

    content = output_file.read_text(encoding="utf-8")

    assert "Total alerts: 3" in content
    assert "High severity: 2" in content
    assert "Medium severity: 1" in content


def test_build_investigation_report():
    alerts = [
        {
            "rule_id": "AUTH-BF-001",
            "title": "Potential Brute-Force Activity",
            "severity": "high",
        },
        {
            "rule_id": "AUTH-DA-001",
            "title": "Authentication Attempt Against Disabled Account",
            "severity": "medium",
        },
    ]

    correlations = [
        {
            "correlation_id": "CORR-AUTH-EXEC-001",
            "title": "Authentication to Process Activity",
            "severity": "medium",
        },
        {
            "correlation_id": "CORR-PROC-NET-001",
            "title": "Process to Network Activity",
            "severity": "medium",
        },
    ]

    report = build_investigation_report(
        alerts,
        correlations,
    )

    assert report["detection_summary"] == {
        "total": 2,
        "high": 1,
        "medium": 1,
    }

    assert report["correlation_summary"] == {
        "total": 2,
        "high": 0,
        "medium": 2,
    }

    assert report["detections"] == alerts
    assert report["correlations"] == correlations
    assert report["related_ids"] == {
        "detection_rule_ids": [
            "AUTH-BF-001",
            "AUTH-DA-001",
        ],
        "correlation_ids": [
            "CORR-AUTH-EXEC-001",
            "CORR-PROC-NET-001",
        ],
    }
    assert report["affected_entities"] == {
        "users": [],
        "hosts": [],
        "ip_addresses": [],
    }

    assert report["mitre_mappings"] == []

    assert report["supporting_evidence"] == {
        "detections": [
            {
                "rule_id": "AUTH-BF-001",
                "details": {},
            },
            {
                "rule_id": "AUTH-DA-001",
                "details": {},
            },
        ],
        "correlations": [
            {
                "correlation_id": "CORR-AUTH-EXEC-001",
                "details": {},
                "event_references": [],
            },
            {
                "correlation_id": "CORR-PROC-NET-001",
                "details": {},
                "event_references": [],
            },
        ],
    }

    assert report["timeline"] == []


def test_collect_investigation_entities():
    alerts = [
        {
            "rule_id": "AUTH-BF-001",
            "details": {
                "username": "admin",
                "source_ip": "10.0.0.8",
            },
        },
        {
            "rule_id": "AUTH-PS-001",
            "details": {
                "usernames": [
                    "admin",
                    "root",
                    "service",
                ],
                "source_ip": "10.0.0.8",
            },
        },
        {
            "rule_id": "AUTH-MI-001",
            "details": {
                "username": "admin",
                "source_ips": [
                    "10.0.0.8",
                    "10.0.0.9",
                ],
            },
        },
    ]

    correlations = [
        {
            "correlation_id": "CORR-AUTH-EXEC-001",
            "details": {
                "host": "WIN-PC01",
                "username": "admin",
                "source_ip": "10.0.0.8",
            },
        },
        {
            "correlation_id": "CORR-PROC-NET-001",
            "details": {
                "host": "WIN-PC01",
                "username": "admin",
                "source_ip": "192.168.1.10",
                "destination_ip": "10.0.0.50",
            },
        },
    ]

    entities = collect_investigation_entities(
        alerts,
        correlations,
    )

    assert entities == {
        "users": [
            "admin",
            "root",
            "service",
        ],
        "hosts": [
            "WIN-PC01",
        ],
        "ip_addresses": [
            "10.0.0.50",
            "10.0.0.8",
            "10.0.0.9",
            "192.168.1.10",
        ],
    }


def test_collect_mitre_mappings_removes_duplicates():
    brute_force_mapping = {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "evidence": "Repeated authentication failures.",
    }

    password_spray_mapping = {
        "technique_id": "T1110.003",
        "technique_name": "Password Spraying",
        "evidence": "Failures across multiple accounts.",
    }

    alerts = [
        {
            "rule_id": "AUTH-BF-001",
            "mitre": brute_force_mapping,
        },
        {
            "rule_id": "AUTH-BF-001",
            "mitre": brute_force_mapping,
        },
        {
            "rule_id": "AUTH-PS-001",
            "mitre": password_spray_mapping,
        },
    ]

    correlations = [
        {
            "correlation_id": "CORR-PROC-NET-001",
        },
    ]

    mappings = collect_mitre_mappings(
        alerts,
        correlations,
    )

    assert mappings == [
        brute_force_mapping,
        password_spray_mapping,
    ]


def test_collect_supporting_evidence():
    alerts = [
        {
            "rule_id": "AUTH-BF-001",
            "details": {
                "username": "admin",
                "source_ip": "10.0.0.8",
                "failed_attempts": 5,
            },
        },
    ]

    correlations = [
        {
            "correlation_id": "CORR-PROC-NET-001",
            "details": {
                "host": "WIN-PC01",
                "process_name": "powershell.exe",
                "destination_ip": "10.0.0.50",
            },
            "related_events": [
                {
                    "timestamp": "2026-09-04T10:00:00Z",
                    "source": "sysmon",
                    "event_id": "1",
                    "event_type": "process_creation",
                    "host": "WIN-PC01",
                },
                {
                    "timestamp": "2026-09-04T10:00:20Z",
                    "source": "sysmon",
                    "event_id": "3",
                    "event_type": "network_connection",
                    "host": "WIN-PC01",
                },
            ],
        },
    ]

    evidence = collect_supporting_evidence(
        alerts,
        correlations,
    )

    assert evidence["detections"] == [
        {
            "rule_id": "AUTH-BF-001",
            "details": {
                "username": "admin",
                "source_ip": "10.0.0.8",
                "failed_attempts": 5,
            },
        }
    ]

    assert evidence["correlations"] == [
        {
            "correlation_id": "CORR-PROC-NET-001",
            "details": {
                "host": "WIN-PC01",
                "process_name": "powershell.exe",
                "destination_ip": "10.0.0.50",
            },
            "event_references": [
                {
                    "timestamp": "2026-09-04T10:00:00Z",
                    "source": "sysmon",
                    "event_id": "1",
                    "event_type": "process_creation",
                    "host": "WIN-PC01",
                },
                {
                    "timestamp": "2026-09-04T10:00:20Z",
                    "source": "sysmon",
                    "event_id": "3",
                    "event_type": "network_connection",
                    "host": "WIN-PC01",
                },
            ],
        }
    ]


def test_generate_investigation_json_report(tmp_path):
    alerts = [
        {
            "rule_id": "AUTH-BF-001",
            "title": "Potential Brute-Force Activity",
            "severity": "high",
            "details": {
                "username": "admin",
                "source_ip": "10.0.0.8",
                "failed_attempts": 5,
            },
        },
    ]

    correlations = [
        {
            "correlation_id": "CORR-PROC-NET-001",
            "title": "Process to Network Activity",
            "severity": "medium",
            "details": {
                "host": "WIN-PC01",
                "username": "admin",
                "destination_ip": "10.0.0.50",
            },
            "related_events": [],
        },
    ]

    output_file = tmp_path / "investigation.json"

    result = generate_investigation_json_report(
        alerts,
        correlations,
        output_file,
    )

    assert result == output_file
    assert output_file.exists()

    content = json.loads(
        output_file.read_text(encoding="utf-8")
    )

    assert content["detection_summary"]["total"] == 1
    assert content["correlation_summary"]["total"] == 1

    assert content["related_ids"]["detection_rule_ids"] == [
        "AUTH-BF-001",
    ]

    assert content["related_ids"]["correlation_ids"] == [
        "CORR-PROC-NET-001",
    ]

    assert content["affected_entities"]["users"] == [
        "admin",
    ]

    assert content["affected_entities"]["hosts"] == [
        "WIN-PC01",
    ]

    assert len(content["detections"]) == 1
    assert len(content["correlations"]) == 1


def test_collect_investigation_timeline_removes_duplicates():
    authentication_event = {
        "timestamp": "2026-09-04T10:00:00Z",
        "source": "windows_security",
        "event_id": "4624",
        "event_type": "authentication_success",
        "host": "WIN-PC01",
        "username": "admin",
        "source_ip": "10.0.0.8",
    }

    process_event = {
        "timestamp": "2026-09-04T10:00:05Z",
        "source": "sysmon",
        "event_id": "1",
        "event_type": "process_creation",
        "host": "WIN-PC01",
        "username": "admin",
        "process_name": "powershell.exe",
        "process_id": "4321",
        "process_guid": "{TEST-GUID}",
    }

    network_event = {
        "timestamp": "2026-09-04T10:00:10Z",
        "source": "sysmon",
        "event_id": "3",
        "event_type": "network_connection",
        "host": "WIN-PC01",
        "process_name": "powershell.exe",
        "process_id": "4321",
        "process_guid": "{TEST-GUID}",
        "destination_ip": "10.0.0.50",
        "details": {
            "destination_port": "443",
        },
    }

    correlations = [
        {
            "correlation_id": "CORR-AUTH-EXEC-001",
            "related_events": [
                authentication_event,
                process_event,
            ],
        },
        {
            "correlation_id": "CORR-PROC-NET-001",
            "related_events": [
                process_event,
                network_event,
            ],
        },
    ]

    timeline = collect_investigation_timeline(
        correlations
    )

    assert len(timeline) == 3

    assert [
        entry["event_type"]
        for entry in timeline
    ] == [
        "authentication_success",
        "process_creation",
        "network_connection",
    ]

    assert timeline[1]["source_event"] == process_event


def test_generate_investigation_markdown_report_summaries(tmp_path):
    alerts = [
        {
            "rule_id": "AUTH-BF-001",
            "severity": "high",
        },
        {
            "rule_id": "AUTH-DA-001",
            "severity": "medium",
        },
    ]

    correlations = [
        {
            "correlation_id": "CORR-AUTH-EXEC-001",
            "severity": "high",
        },
        {
            "correlation_id": "CORR-PROC-NET-001",
            "severity": "medium",
        },
    ]

    output_file = tmp_path / "investigation.md"

    result = generate_investigation_markdown_report(
        alerts,
        correlations,
        output_file,
    )

    assert result == output_file
    assert output_file.exists()

    content = output_file.read_text(
        encoding="utf-8"
    )

    assert "# AuthWatch V3 Investigation Report" in content

    assert "## Detection Summary" in content
    assert "- Total detections: 2" in content
    assert "- High severity: 1" in content
    assert "- Medium severity: 1" in content

    assert "## Correlation Summary" in content
    assert "- Total correlations: 2" in content


def test_generate_investigation_markdown_report_affected_entities(
    tmp_path,
):
    alerts = [
        {
            "rule_id": "AUTH-BF-001",
            "severity": "high",
            "details": {
                "username": "admin",
                "source_ip": "10.0.0.8",
            },
        },
    ]

    correlations = [
        {
            "correlation_id": "CORR-PROC-NET-001",
            "severity": "medium",
            "details": {
                "host": "WIN-PC01",
                "username": "admin",
                "destination_ip": "10.0.0.50",
            },
        },
    ]

    output_file = tmp_path / "investigation.md"

    generate_investigation_markdown_report(
        alerts,
        correlations,
        output_file,
    )

    content = output_file.read_text(
        encoding="utf-8"
    )

    assert "## Affected Entities" in content

    assert "### Users" in content
    assert "- admin" in content

    assert "### Hosts" in content
    assert "- WIN-PC01" in content

    assert "### IP Addresses" in content
    assert "- 10.0.0.8" in content
    assert "- 10.0.0.50" in content


def test_generate_investigation_markdown_report_related_ids(
    tmp_path,
):
    alerts = [
        {
            "rule_id": "AUTH-BF-001",
            "severity": "high",
        },
        {
            "rule_id": "AUTH-PS-001",
            "severity": "high",
        },
    ]

    correlations = [
        {
            "correlation_id": "CORR-AUTH-EXEC-001",
            "severity": "high",
        },
        {
            "correlation_id": "CORR-PROC-NET-001",
            "severity": "medium",
        },
    ]

    output_file = tmp_path / "investigation.md"

    generate_investigation_markdown_report(
        alerts,
        correlations,
        output_file,
    )

    content = output_file.read_text(
        encoding="utf-8"
    )

    assert "## Related IDs" in content

    assert "### Detection Rule IDs" in content
    assert "- AUTH-BF-001" in content
    assert "- AUTH-PS-001" in content

    assert "### Correlation IDs" in content
    assert "- CORR-AUTH-EXEC-001" in content
    assert "- CORR-PROC-NET-001" in content


def test_generate_investigation_markdown_report_mitre_mapping(
    tmp_path,
):
    alerts = [
        {
            "rule_id": "AUTH-BF-001",
            "severity": "high",
            "mitre": {
                "technique_id": "T1110",
                "technique_name": "Brute Force",
                "evidence": (
                    "Repeated authentication failures against "
                    "the same account."
                ),
            },
        },
    ]

    output_file = tmp_path / "investigation.md"

    generate_investigation_markdown_report(
        alerts,
        [],
        output_file,
    )

    content = output_file.read_text(
        encoding="utf-8"
    )

    assert "## MITRE ATT&CK Mappings" in content
    assert "### T1110 — Brute Force" in content

    assert (
        "- Evidence: Repeated authentication failures "
        "against the same account."
    ) in content


def test_generate_investigation_markdown_report_no_mitre_mapping(
    tmp_path,
):
    alerts = [
        {
            "rule_id": "AUTH-SF-001",
            "severity": "high",
        },
    ]

    output_file = tmp_path / "investigation.md"

    generate_investigation_markdown_report(
        alerts,
        [],
        output_file,
    )

    content = output_file.read_text(
        encoding="utf-8"
    )

    assert (
        "## MITRE ATT&CK Mappings\n\n"
        "- None"
    ) in content


def test_generate_investigation_markdown_report_timeline(
    tmp_path,
):
    correlations = [
        {
            "correlation_id": "CORR-PROC-NET-001",
            "severity": "medium",
            "related_events": [
                {
                    "timestamp": "2026-09-04T10:00:10Z",
                    "source": "sysmon",
                    "event_id": "3",
                    "event_type": "network_connection",
                    "host": "WIN-PC01",
                    "process_name": "powershell.exe",
                    "destination_ip": "10.0.0.50",
                    "details": {
                        "destination_port": "443",
                    },
                },
                {
                    "timestamp": "2026-09-04T10:00:05Z",
                    "source": "sysmon",
                    "event_id": "1",
                    "event_type": "process_creation",
                    "host": "WIN-PC01",
                    "username": "admin",
                    "process_name": "powershell.exe",
                },
            ],
        },
    ]

    output_file = tmp_path / "investigation.md"

    generate_investigation_markdown_report(
        [],
        correlations,
        output_file,
    )

    content = output_file.read_text(
        encoding="utf-8"
    )

    process_line = (
        "- 2026-09-04T10:00:05Z — "
        "powershell.exe was started by admin on WIN-PC01"
    )

    network_line = (
        "- 2026-09-04T10:00:10Z — "
        "powershell.exe connected to 10.0.0.50:443"
    )

    assert "## Investigation Timeline" in content
    assert process_line in content
    assert network_line in content

    assert content.index(process_line) < content.index(
        network_line
    )


def test_generate_investigation_markdown_report_supporting_evidence(
    tmp_path,
):
    alerts = [
        {
            "rule_id": "AUTH-BF-001",
            "severity": "high",
            "details": {
                "username": "admin",
                "source_ip": "10.0.0.8",
                "failed_attempts": 5,
            },
        },
    ]

    correlations = [
        {
            "correlation_id": "CORR-PROC-NET-001",
            "severity": "medium",
            "details": {
                "host": "WIN-PC01",
                "destination_ip": "10.0.0.50",
            },
            "related_events": [
                {
                    "timestamp": "2026-09-04T10:00:05Z",
                    "source": "sysmon",
                    "event_id": "1",
                    "event_type": "process_creation",
                    "host": "WIN-PC01",
                },
                {
                    "timestamp": "2026-09-04T10:00:10Z",
                    "source": "sysmon",
                    "event_id": "3",
                    "event_type": "network_connection",
                    "host": "WIN-PC01",
                },
            ],
        },
    ]

    output_file = tmp_path / "investigation.md"

    generate_investigation_markdown_report(
        alerts,
        correlations,
        output_file,
    )

    content = output_file.read_text(
        encoding="utf-8"
    )

    assert "## Supporting Evidence" in content

    assert "### Detection Evidence" in content
    assert "#### AUTH-BF-001" in content
    assert "- username: admin" in content
    assert "- source_ip: 10.0.0.8" in content
    assert "- failed_attempts: 5" in content

    assert "### Correlation Evidence" in content
    assert "#### CORR-PROC-NET-001" in content
    assert "- host: WIN-PC01" in content
    assert "- destination_ip: 10.0.0.50" in content

    assert (
        "2026-09-04T10:00:05Z | "
        "sysmon | Event 1 | "
        "process_creation | WIN-PC01"
    ) in content

    assert (
        "2026-09-04T10:00:10Z | "
        "sysmon | Event 3 | "
        "network_connection | WIN-PC01"
    ) in content


def test_generate_investigation_markdown_report_detections(
    tmp_path,
):
    alerts = [
        {
            "rule_id": "AUTH-BF-001",
            "title": "Potential Brute-Force Activity",
            "severity": "high",
            "first_seen": "2026-09-04T10:00:00Z",
            "last_seen": "2026-09-04T10:00:45Z",
        },
    ]

    output_file = tmp_path / "investigation.md"

    generate_investigation_markdown_report(
        alerts,
        [],
        output_file,
    )

    content = output_file.read_text(
        encoding="utf-8"
    )

    assert "## Detections" in content

    assert (
        "### Detection 1: Potential Brute-Force Activity"
        in content
    )

    assert "- Rule ID: AUTH-BF-001" in content
    assert "- Severity: high" in content
    assert (
        "- First seen: 2026-09-04T10:00:00Z"
        in content
    )
    assert (
        "- Last seen: 2026-09-04T10:00:45Z"
        in content
    )


def test_generate_investigation_markdown_report_correlations(
    tmp_path,
):
    correlations = [
        {
            "correlation_id": "CORR-PROC-NET-001",
            "title": "Process to Network Activity",
            "severity": "medium",
            "first_seen": "2026-09-04T10:00:05Z",
            "last_seen": "2026-09-04T10:00:10Z",
        },
    ]

    output_file = tmp_path / "investigation.md"

    generate_investigation_markdown_report(
        [],
        correlations,
        output_file,
    )

    content = output_file.read_text(
        encoding="utf-8"
    )

    assert "## Correlations" in content

    assert (
        "### Correlation 1: Process to Network Activity"
        in content
    )

    assert (
        "- Correlation ID: CORR-PROC-NET-001"
        in content
    )

    assert "- Severity: medium" in content

    assert (
        "- First seen: 2026-09-04T10:00:05Z"
        in content
    )

    assert (
        "- Last seen: 2026-09-04T10:00:10Z"
        in content
    )


def test_generate_investigation_markdown_report_omits_missing_event_id(
    tmp_path,
):
    alerts = []

    correlations = [
        {
            "correlation_id": "CORR-SSH-SUDO-001",
            "title": "SSH Login to Privileged Execution",
            "severity": "medium",
            "first_seen": "2026-09-08T19:00:00Z",
            "last_seen": "2026-09-08T19:01:00Z",
            "details": {
                "host": "kali",
                "username": "alice",
                "source_ip": "10.0.0.120",
                "target_user": "root",
                "command_line": "/usr/bin/systemctl status ssh",
            },
            "related_events": [
                {
                    "timestamp": "2026-09-08T19:00:00Z",
                    "source": "linux_auth",
                    "event_id": None,
                    "event_type": "authentication_success",
                    "host": "kali",
                    "username": "alice",
                    "source_ip": "10.0.0.120",
                    "details": {
                        "service": "sshd",
                    },
                },
                {
                    "timestamp": "2026-09-08T19:01:00Z",
                    "source": "linux_auth",
                    "event_id": None,
                    "event_type": "sudo_execution",
                    "host": "kali",
                    "username": "alice",
                    "command_line": "/usr/bin/systemctl status ssh",
                    "details": {
                        "target_user": "root",
                    },
                },
            ],
        },
    ]

    output_file = tmp_path / "linux_investigation.md"

    generate_investigation_markdown_report(
        alerts,
        correlations,
        output_file,
    )

    content = output_file.read_text(
        encoding="utf-8"
    )

    assert "Event None" not in content

    assert (
        "2026-09-08T19:00:00Z | "
        "linux_auth | authentication_success | kali"
    ) in content

    assert (
        "2026-09-08T19:01:00Z | "
        "linux_auth | sudo_execution | kali"
    ) in content
