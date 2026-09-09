import xml.etree.ElementTree as ET
from src.parsers.evtx_reader import iter_evtx_xml_records


EVENT_NAMESPACE = {
    "event": "http://schemas.microsoft.com/win/2004/08/events/event"
}

SUPPORTED_EVENT_IDS = {
    "4624",
    "4625",
    "4648",
    "4672",
}


def extract_event_id(xml_record):
    root = ET.fromstring(xml_record)

    event_id_element = root.find(
        "./event:System/event:EventID",
        EVENT_NAMESPACE,
    )

    if event_id_element is None or event_id_element.text is None:
        raise ValueError("Windows Security event is missing EventID")

    return event_id_element.text.strip()


def extract_system_context(xml_record):
    root = ET.fromstring(xml_record)

    time_created = root.find(
        "./event:System/event:TimeCreated",
        EVENT_NAMESPACE,
    )

    computer = root.find(
        "./event:System/event:Computer",
        EVENT_NAMESPACE,
    )

    if time_created is None or not time_created.get("SystemTime"):
        raise ValueError("Windows Security event is missing timestamp")

    if computer is None or computer.text is None:
        raise ValueError("Windows Security event is missing computer name")

    return {
        "timestamp": time_created.get("SystemTime"),
        "host": computer.text.strip(),
    }


def extract_event_data(xml_record):
    root = ET.fromstring(xml_record)

    event_data = {}

    for data_element in root.findall(
        "./event:EventData/event:Data",
        EVENT_NAMESPACE,
    ):
        name = data_element.get("Name")

        if name:
            event_data[name] = data_element.text or ""

    return event_data


def parse_failed_logon(xml_record):
    event_id = extract_event_id(xml_record)

    if event_id != "4625":
        raise ValueError(
            f"Expected Windows Security Event ID 4625, got {event_id}"
        )

    system_context = extract_system_context(xml_record)
    event_data = extract_event_data(xml_record)

    return {
        "event_id": event_id,
        "timestamp": system_context["timestamp"],
        "host": system_context["host"],
        "username": event_data.get("TargetUserName"),
        "source_ip": event_data.get("IpAddress"),
        "logon_type": event_data.get("LogonType"),
        "failure_reason": event_data.get("FailureReason"),
        "status": event_data.get("Status"),
        "sub_status": event_data.get("SubStatus"),
    }


def parse_successful_logon(xml_record):
    event_id = extract_event_id(xml_record)

    if event_id != "4624":
        raise ValueError(
            f"Expected Windows Security Event ID 4624, got {event_id}"
        )

    system_context = extract_system_context(xml_record)
    event_data = extract_event_data(xml_record)

    return {
        "event_id": event_id,
        "timestamp": system_context["timestamp"],
        "host": system_context["host"],
        "username": event_data.get("TargetUserName"),
        "source_ip": event_data.get("IpAddress"),
        "logon_type": event_data.get("LogonType"),
        "logon_id": event_data.get("TargetLogonId"),
        "authentication_package": event_data.get(
            "AuthenticationPackageName"
        ),
    }


def parse_explicit_credentials(xml_record):
    event_id = extract_event_id(xml_record)

    if event_id != "4648":
        raise ValueError(
            f"Expected Windows Security Event ID 4648, got {event_id}"
        )

    system_context = extract_system_context(xml_record)
    event_data = extract_event_data(xml_record)

    return {
        "event_id": event_id,
        "timestamp": system_context["timestamp"],
        "host": system_context["host"],
        "username": event_data.get("TargetUserName"),
        "source_username": event_data.get("SubjectUserName"),
        "source_ip": event_data.get("IpAddress"),
        "target_server": event_data.get("TargetServerName"),
        "process_name": event_data.get("ProcessName"),
        "logon_id": event_data.get("SubjectLogonId"),
    }


def parse_privileged_logon(xml_record):
    event_id = extract_event_id(xml_record)

    if event_id != "4672":
        raise ValueError(
            f"Expected Windows Security Event ID 4672, got {event_id}"
        )

    system_context = extract_system_context(xml_record)
    event_data = extract_event_data(xml_record)

    return {
        "event_id": event_id,
        "timestamp": system_context["timestamp"],
        "host": system_context["host"],
        "username": event_data.get("SubjectUserName"),
        "logon_id": event_data.get("SubjectLogonId"),
        "privileges": event_data.get("PrivilegeList"),
    }


def parse_windows_security_event(xml_record):
    event_id = extract_event_id(xml_record)

    parsers = {
        "4624": parse_successful_logon,
        "4625": parse_failed_logon,
        "4648": parse_explicit_credentials,
        "4672": parse_privileged_logon,
    }

    parser = parsers.get(event_id)

    if parser is None:
        return None

    return parser(xml_record)


def load_windows_security_events(file_path):
    events = []

    for xml_record in iter_evtx_xml_records(file_path):
        event = parse_windows_security_event(xml_record)

        if event is not None:
            events.append(event)

    return events
