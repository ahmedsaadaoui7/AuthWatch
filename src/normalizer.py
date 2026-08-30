from datetime import datetime, timezone
def build_normalized_event(
    *,
    timestamp,
    source,
    event_id=None,
    event_type=None,
    host=None,
    username=None,
    session_id=None,
    source_ip=None,
    destination_ip=None,
    process_name=None,
    process_id=None,
    process_guid=None,
    parent_process_name=None,
    command_line=None,
    result=None,
    details=None,
):
    return {
        "timestamp": timestamp,
        "source": source,
        "event_id": event_id,
        "event_type": event_type,
        "host": host,
        "username": username,
        "session_id": session_id,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "process_name": process_name,
        "process_id": process_id,
        "process_guid": process_guid,
        "parent_process_name": parent_process_name,
        "command_line": command_line,
        "result": result,
        "details": details or {},
    }


WINDOWS_SECURITY_EVENT_TYPES = {
    "4624": "authentication_success",
    "4625": "authentication_failure",
    "4648": "explicit_credentials",
    "4672": "privileged_logon",
}


def normalize_windows_security_event(event):
    event_id = event.get("event_id")

    event_type = WINDOWS_SECURITY_EVENT_TYPES.get(event_id)

    if event_type is None:
        raise ValueError(
            f"Unsupported Windows Security Event ID: {event_id}"
        )

    result = None

    if event_id == "4624":
        result = "success"
    elif event_id == "4625":
        result = "failure"

    return build_normalized_event(
        timestamp=event.get("timestamp"),
        source="windows_security",
        event_id=event_id,
        event_type=event_type,
        host=event.get("host"),
        username=event.get("username"),
        session_id=event.get("logon_id"),
        source_ip=event.get("source_ip"),
        process_name=event.get("process_name"),
        result=result,
        details={
            key: value
            for key, value in event.items()
            if key not in {
                "event_id",
                "timestamp",
                "host",
                "username",
                "logon_id",
                "source_ip",
                "process_name",
            }
        },
    )


SYSMON_EVENT_TYPES = {
    "1": "process_creation",
    "3": "network_connection",
    "11": "file_creation",
    "13": "registry_modification",
    "22": "dns_query",
}


def normalize_sysmon_event(event):
    event_id = event.get("event_id")

    event_type = SYSMON_EVENT_TYPES.get(event_id)

    if event_type is None:
        raise ValueError(
            f"Unsupported Sysmon Event ID: {event_id}"
        )

    common_fields = {
        "event_id",
        "timestamp",
        "host",
        "username",
        "logon_id",
        "source_ip",
        "destination_ip",
        "process_name",
        "process_id",
        "process_guid",
        "parent_process_name",
        "command_line",
    }

    details = {
        key: value
        for key, value in event.items()
        if key not in common_fields
    }

    if event_id == "13" and "details" in details:
        details["registry_details"] = details.pop("details")

    return build_normalized_event(
        timestamp=event.get("timestamp"),
        source="sysmon",
        event_id=event_id,
        event_type=event_type,
        host=event.get("host"),
        username=event.get("username"),
        session_id=event.get("logon_id"),
        source_ip=event.get("source_ip"),
        destination_ip=event.get("destination_ip"),
        process_name=event.get("process_name"),
        process_id=event.get("process_id"),
        process_guid=event.get("process_guid"),
        parent_process_name=event.get("parent_process_name"),
        command_line=event.get("command_line"),
        details=details,
    )


LINUX_EVENT_TYPES = {
    "authentication_failure",
    "authentication_success",
    "sudo_execution",
    "session_activity",
}


def normalize_linux_auth_event(event, *, year, utc_offset):
    event_type = event.get("event_type")

    if event_type not in LINUX_EVENT_TYPES:
        raise ValueError(
            f"Unsupported Linux authentication event type: {event_type}"
        )

    common_fields = {
        "timestamp",
        "event_type",
        "host",
        "username",
        "source_ip",
        "process_id",
        "result",
        "command",
    }

    details = {
        key: value
        for key, value in event.items()
        if key not in common_fields
    }

    normalized_timestamp = normalize_linux_timestamp(
        event.get("timestamp"),
        year=year,
        utc_offset=utc_offset,
    )

    return build_normalized_event(
        timestamp=normalized_timestamp,
        source="linux_auth",
        event_type=event_type,
        host=event.get("host"),
        username=event.get("username"),
        source_ip=event.get("source_ip"),
        process_id=event.get("process_id"),
        command_line=event.get("command"),
        result=event.get("result"),
        details=details,
    )


def normalize_linux_timestamp(timestamp, *, year, utc_offset):
    try:
        local_time = datetime.strptime(
            f"{year} {timestamp}",
            "%Y %b %d %H:%M:%S",
        )

        timezone_info = datetime.fromisoformat(
            f"2000-01-01T00:00:00{utc_offset}"
        ).tzinfo

    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"Invalid Linux timestamp or UTC offset: "
            f"{timestamp}, {utc_offset}"
        ) from exc

    local_time = local_time.replace(tzinfo=timezone_info)

    return (
        local_time
        .astimezone(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )
