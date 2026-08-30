from datetime import datetime
from src.config import DEFAULT_CORRELATION_CONFIG


def parse_timestamp(event):
    timestamp = event.get("timestamp")

    if not timestamp:
        raise ValueError("Event is missing timestamp")

    try:
        return datetime.fromisoformat(
            timestamp.replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise ValueError(
            f"Invalid event timestamp: {timestamp}"
        ) from exc


def correlate_process_to_network(events, window_seconds=300):
    process_events = {}

    for event in events:
        if event.get("event_type") != "process_creation":
            continue

        process_guid = event.get("process_guid")
        host = event.get("host")

        if process_guid:
            process_events[(host, process_guid)] = event

    correlations = []

    for event in events:
        if event.get("event_type") != "network_connection":
            continue

        process_guid = event.get("process_guid")
        host = event.get("host")

        if not process_guid:
            continue

        process_event = process_events.get((host, process_guid))

        if process_event is None:
            continue

        process_time = parse_timestamp(process_event)
        network_time = parse_timestamp(event)

        time_difference = (
            network_time - process_time
        ).total_seconds()

        if time_difference < 0 or time_difference > window_seconds:
            continue

        correlations.append({
            "correlation_id": "CORR-PROC-NET-001",
            "title": "Process to Network Activity",
            "severity": "medium",
            "first_seen": process_event["timestamp"],
            "last_seen": event["timestamp"],
            "related_events": [
                process_event,
                event,
            ],
            "details": {
                "host": host,
                "username": event.get("username"),
                "process_guid": process_guid,
                "process_name": event.get("process_name"),
                "source_ip": event.get("source_ip"),
                "destination_ip": event.get("destination_ip"),
                "destination_port": event.get(
                    "details", {}
                ).get("destination_port"),
            },
        })

    return correlations


def correlate_process_to_dns(events, window_seconds=300):
    process_events = {}

    for event in events:
        if event.get("event_type") != "process_creation":
            continue

        process_guid = event.get("process_guid")
        host = event.get("host")

        if process_guid:
            process_events[(host, process_guid)] = event

    correlations = []

    for event in events:
        if event.get("event_type") != "dns_query":
            continue

        process_guid = event.get("process_guid")
        host = event.get("host")

        if not process_guid:
            continue

        process_event = process_events.get((host, process_guid))

        if process_event is None:
            continue

        process_time = parse_timestamp(process_event)
        dns_time = parse_timestamp(event)

        time_difference = (
            dns_time - process_time
        ).total_seconds()

        if time_difference < 0 or time_difference > window_seconds:
            continue

        correlations.append({
            "correlation_id": "CORR-PROC-DNS-001",
            "title": "Process to DNS Activity",
            "severity": "medium",
            "first_seen": process_event["timestamp"],
            "last_seen": event["timestamp"],
            "related_events": [
                process_event,
                event,
            ],
            "details": {
                "host": host,
                "username": event.get("username"),
                "process_guid": process_guid,
                "process_name": event.get("process_name"),
                "query_name": event.get(
                    "details", {}
                ).get("query_name"),
                "query_status": event.get(
                    "details", {}
                ).get("query_status"),
                "query_results": event.get(
                    "details", {}
                ).get("query_results"),
            },
        })

    return correlations


def correlate_authentication_to_process(events, window_seconds=300):
    authentication_events = {}

    for event in events:
        if event.get("event_type") != "authentication_success":
            continue

        session_id = event.get("session_id")
        host = event.get("host")

        if session_id:
            authentication_events[(host, session_id)] = event

    correlations = []

    for event in events:
        if event.get("event_type") != "process_creation":
            continue

        session_id = event.get("session_id")
        host = event.get("host")

        if not session_id:
            continue

        authentication_event = authentication_events.get(
            (host, session_id)
        )

        if authentication_event is None:
            continue

        authentication_time = parse_timestamp(
            authentication_event
        )
        process_time = parse_timestamp(event)

        time_difference = (
            process_time - authentication_time
        ).total_seconds()

        if time_difference < 0 or time_difference > window_seconds:
            continue

        correlations.append({
            "correlation_id": "CORR-AUTH-EXEC-001",
            "title": "Authentication to Process Activity",
            "severity": "medium",
            "first_seen": authentication_event["timestamp"],
            "last_seen": event["timestamp"],
            "related_events": [
                authentication_event,
                event,
            ],
            "details": {
                "host": host,
                "username": authentication_event.get("username"),
                "session_id": session_id,
                "source_ip": authentication_event.get("source_ip"),
                "process_guid": event.get("process_guid"),
                "process_id": event.get("process_id"),
                "process_name": event.get("process_name"),
                "command_line": event.get("command_line"),
            },
        })

    return correlations


def correlate_privileged_logon_to_process(events, window_seconds=300):
    privileged_events = {}

    for event in events:
        if event.get("event_type") != "privileged_logon":
            continue

        session_id = event.get("session_id")
        host = event.get("host")

        if session_id:
            privileged_events[(host, session_id)] = event

    correlations = []

    for event in events:
        if event.get("event_type") != "process_creation":
            continue

        session_id = event.get("session_id")
        host = event.get("host")

        if not session_id:
            continue

        privileged_event = privileged_events.get(
            (host, session_id)
        )

        if privileged_event is None:
            continue

        privileged_time = parse_timestamp(privileged_event)
        process_time = parse_timestamp(event)

        time_difference = (
            process_time - privileged_time
        ).total_seconds()

        if time_difference < 0 or time_difference > window_seconds:
            continue

        correlations.append({
            "correlation_id": "CORR-PRIV-EXEC-001",
            "title": "Privileged Logon to Process Activity",
            "severity": "medium",
            "first_seen": privileged_event["timestamp"],
            "last_seen": event["timestamp"],
            "related_events": [
                privileged_event,
                event,
            ],
            "details": {
                "host": host,
                "username": privileged_event.get("username"),
                "session_id": session_id,
                "process_guid": event.get("process_guid"),
                "process_id": event.get("process_id"),
                "process_name": event.get("process_name"),
                "command_line": event.get("command_line"),
            },
        })

    return correlations


def correlate_ssh_to_sudo(events, window_seconds=300):
    ssh_events = {}

    for event in events:
        if event.get("source") != "linux_auth":
            continue

        if event.get("event_type") != "authentication_success":
            continue

        if event.get("details", {}).get("service") != "sshd":
            continue

        host = event.get("host")
        username = event.get("username")

        if host and username:
            ssh_events.setdefault(
                (host, username),
                []
            ).append(event)

    correlations = []

    for event in events:
        if event.get("source") != "linux_auth":
            continue

        if event.get("event_type") != "sudo_execution":
            continue

        host = event.get("host")
        username = event.get("username")

        candidates = ssh_events.get(
            (host, username),
            []
        )

        sudo_time = parse_timestamp(event)

        valid_candidates = []

        for ssh_event in candidates:
            ssh_time = parse_timestamp(ssh_event)

            time_difference = (
                sudo_time - ssh_time
            ).total_seconds()

            if 0 <= time_difference <= window_seconds:
                valid_candidates.append(ssh_event)

        if not valid_candidates:
            continue

        ssh_event = max(
            valid_candidates,
            key=parse_timestamp,
        )

        correlations.append({
            "correlation_id": "CORR-SSH-SUDO-001",
            "title": "SSH Login to Privileged Execution",
            "severity": "medium",
            "first_seen": ssh_event["timestamp"],
            "last_seen": event["timestamp"],
            "related_events": [
                ssh_event,
                event,
            ],
            "details": {
                "host": host,
                "username": username,
                "source_ip": ssh_event.get("source_ip"),
                "target_user": event.get(
                    "details", {}
                ).get("target_user"),
                "command_line": event.get("command_line"),
            },
        })

    return correlations


def run_correlation_engine(events, config=None):
    correlations = []

    if config is None:
        config = {}

    correlators = (
        ("CORR-PROC-NET-001", correlate_process_to_network),
        ("CORR-PROC-DNS-001", correlate_process_to_dns),
        ("CORR-AUTH-EXEC-001", correlate_authentication_to_process),
        ("CORR-PRIV-EXEC-001", correlate_privileged_logon_to_process),
        ("CORR-SSH-SUDO-001", correlate_ssh_to_sudo),
    )

    for rule_id, correlator in correlators:
        rule_config = DEFAULT_CORRELATION_CONFIG[rule_id].copy()
        rule_config.update(config.get(rule_id, {}))

        correlations.extend(
            correlator(
                events,
                **rule_config,
            )
        )

    return correlations
