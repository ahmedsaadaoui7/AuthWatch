from datetime import datetime


def parse_timeline_timestamp(event):
    timestamp = event.get("timestamp")

    if not timestamp:
        raise ValueError("Timeline event is missing timestamp")

    try:
        return datetime.fromisoformat(
            timestamp.replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise ValueError(
            f"Invalid timeline event timestamp: {timestamp}"
        ) from exc


def sort_events_chronologically(events):
    return sorted(
        events,
        key=parse_timeline_timestamp,
    )


def build_timeline_description(event):
    event_type = event.get("event_type")

    if event_type == "process_creation":
        process_name = event.get("process_name") or "unknown process"
        username = event.get("username") or "unknown user"
        host = event.get("host") or "unknown host"

        return (
            f"{process_name} was started by "
            f"{username} on {host}"
        )

    if event_type == "network_connection":
        process_name = event.get("process_name") or "unknown process"
        destination_ip = (
            event.get("destination_ip")
            or "unknown destination"
        )
        destination_port = (
            event.get("details", {}).get("destination_port")
            or "unknown port"
        )

        return (
            f"{process_name} connected to "
            f"{destination_ip}:{destination_port}"
        )

    if event_type == "dns_query":
        process_name = event.get("process_name") or "unknown process"
        query_name = (
            event.get("details", {}).get("query_name")
            or "unknown domain"
        )

        return (
            f"{process_name} queried DNS for "
            f"{query_name}"
        )

    if event_type == "authentication_success":
        username = event.get("username") or "unknown user"
        host = event.get("host") or "unknown host"
        source_ip = event.get("source_ip") or "unknown source"

        return (
            f"{username} successfully authenticated to "
            f"{host} from {source_ip}"
        )

    if event_type == "authentication_failure":
        username = event.get("username") or "unknown user"
        host = event.get("host") or "unknown host"
        source_ip = event.get("source_ip") or "unknown source"

        return (
            f"Failed authentication for {username} to "
            f"{host} from {source_ip}"
        )

    if event_type == "privileged_logon":
        username = event.get("username") or "unknown user"
        host = event.get("host") or "unknown host"

        return (
            f"{username} received special logon privileges "
            f"on {host}"
        )

    if event_type == "sudo_execution":
        username = event.get("username") or "unknown user"
        target_user = (
            event.get("details", {}).get("target_user")
            or "unknown target user"
        )
        command_line = (
            event.get("command_line")
            or "unknown command"
        )

        return (
            f"{username} executed sudo as {target_user}: "
            f"{command_line}"
        )

    if event_type == "session_activity":
        username = event.get("username") or "unknown user"
        host = event.get("host") or "unknown host"
        session_action = (
            event.get("details", {}).get("session_action")
            or "changed"
        )

        return (
            f"Session for {username} was "
            f"{session_action} on {host}"
        )

    if event_type == "explicit_credentials":
        username = event.get("username") or "unknown user"
        host = event.get("host") or "unknown host"

        return (
            f"{username} used explicit credentials "
            f"on {host}"
        )

    if event_type == "file_creation":
        process_name = event.get("process_name") or "unknown process"
        target_filename = (
            event.get("details", {}).get("target_filename")
            or "unknown file"
        )

        return (
            f"{process_name} created file "
            f"{target_filename}"
        )

    if event_type == "registry_modification":
        process_name = event.get("process_name") or "unknown process"
        target_object = (
            event.get("details", {}).get("target_object")
            or "unknown registry object"
        )

        return (
            f"{process_name} modified registry object "
            f"{target_object}"
        )

    return "Security-relevant activity was observed"


def build_timeline_entry(event):
    return {
        "timestamp": event.get("timestamp"),
        "event_type": event.get("event_type"),
        "source": event.get("source"),
        "event_id": event.get("event_id"),
        "host": event.get("host"),
        "username": event.get("username"),
        "source_ip": event.get("source_ip"),
        "destination_ip": event.get("destination_ip"),
        "process_name": event.get("process_name"),
        "process_id": event.get("process_id"),
        "process_guid": event.get("process_guid"),
        "command_line": event.get("command_line"),
        "description": build_timeline_description(event),
        "source_event": event,
    }


def build_timeline(events):
    sorted_events = sort_events_chronologically(events)

    return [
        build_timeline_entry(event)
        for event in sorted_events
    ]


def build_correlation_timeline(correlation):
    related_events = correlation.get("related_events")

    if not related_events:
        return []

    return build_timeline(related_events)


def attach_timeline_to_correlation(correlation):
    result = correlation.copy()

    result["timeline"] = build_correlation_timeline(
        correlation
    )

    return result


def attach_timelines_to_correlations(correlations):
    return [
        attach_timeline_to_correlation(correlation)
        for correlation in correlations
    ]
