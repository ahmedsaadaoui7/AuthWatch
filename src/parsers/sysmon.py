import xml.etree.ElementTree as ET
from src.parsers.evtx_reader import iter_evtx_xml_records


EVENT_NAMESPACE = {
    "event": "http://schemas.microsoft.com/win/2004/08/events/event"
}

SUPPORTED_EVENT_IDS = {
    "1",
    "3",
    "11",
    "13",
    "22",
}


def extract_event_id(xml_record):
    root = ET.fromstring(xml_record)

    event_id_element = root.find(
        "./event:System/event:EventID",
        EVENT_NAMESPACE,
    )

    if event_id_element is None or event_id_element.text is None:
        raise ValueError("Sysmon event is missing EventID")

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
        raise ValueError("Sysmon event is missing timestamp")

    if computer is None or computer.text is None:
        raise ValueError("Sysmon event is missing computer name")

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


def parse_process_creation(xml_record):
    event_id = extract_event_id(xml_record)

    if event_id != "1":
        raise ValueError(
            f"Expected Sysmon Event ID 1, got {event_id}"
        )

    system_context = extract_system_context(xml_record)
    event_data = extract_event_data(xml_record)

    return {
        "event_id": event_id,
        "timestamp": system_context["timestamp"],
        "host": system_context["host"],
        "process_guid": event_data.get("ProcessGuid"),
        "process_id": event_data.get("ProcessId"),
        "process_name": event_data.get("Image"),
        "command_line": event_data.get("CommandLine"),
        "username": event_data.get("User"),
        "logon_id": event_data.get("LogonId"),
        "parent_process_guid": event_data.get("ParentProcessGuid"),
        "parent_process_id": event_data.get("ParentProcessId"),
        "parent_process_name": event_data.get("ParentImage"),
        "parent_command_line": event_data.get("ParentCommandLine"),
        "integrity_level": event_data.get("IntegrityLevel"),
        "hashes": event_data.get("Hashes"),
    }


def parse_network_connection(xml_record):
    event_id = extract_event_id(xml_record)

    if event_id != "3":
        raise ValueError(
            f"Expected Sysmon Event ID 3, got {event_id}"
        )

    system_context = extract_system_context(xml_record)
    event_data = extract_event_data(xml_record)

    return {
        "event_id": event_id,
        "timestamp": system_context["timestamp"],
        "host": system_context["host"],
        "process_guid": event_data.get("ProcessGuid"),
        "process_id": event_data.get("ProcessId"),
        "process_name": event_data.get("Image"),
        "username": event_data.get("User"),
        "protocol": event_data.get("Protocol"),
        "initiated": event_data.get("Initiated"),
        "source_ip": event_data.get("SourceIp"),
        "source_port": event_data.get("SourcePort"),
        "destination_ip": event_data.get("DestinationIp"),
        "destination_port": event_data.get("DestinationPort"),
        "destination_hostname": event_data.get("DestinationHostname"),
    }


def parse_file_creation(xml_record):
    event_id = extract_event_id(xml_record)

    if event_id != "11":
        raise ValueError(
            f"Expected Sysmon Event ID 11, got {event_id}"
        )

    system_context = extract_system_context(xml_record)
    event_data = extract_event_data(xml_record)

    return {
        "event_id": event_id,
        "timestamp": system_context["timestamp"],
        "host": system_context["host"],
        "process_guid": event_data.get("ProcessGuid"),
        "process_id": event_data.get("ProcessId"),
        "process_name": event_data.get("Image"),
        "target_filename": event_data.get("TargetFilename"),
        "creation_utc_time": event_data.get("CreationUtcTime"),
        "username": event_data.get("User"),
    }


def parse_registry_modification(xml_record):
    event_id = extract_event_id(xml_record)

    if event_id != "13":
        raise ValueError(
            f"Expected Sysmon Event ID 13, got {event_id}"
        )

    system_context = extract_system_context(xml_record)
    event_data = extract_event_data(xml_record)

    return {
        "event_id": event_id,
        "timestamp": system_context["timestamp"],
        "host": system_context["host"],
        "process_guid": event_data.get("ProcessGuid"),
        "process_id": event_data.get("ProcessId"),
        "process_name": event_data.get("Image"),
        "target_object": event_data.get("TargetObject"),
        "details": event_data.get("Details"),
        "username": event_data.get("User"),
    }


def parse_dns_query(xml_record):
    event_id = extract_event_id(xml_record)

    if event_id != "22":
        raise ValueError(
            f"Expected Sysmon Event ID 22, got {event_id}"
        )

    system_context = extract_system_context(xml_record)
    event_data = extract_event_data(xml_record)

    return {
        "event_id": event_id,
        "timestamp": system_context["timestamp"],
        "host": system_context["host"],
        "process_guid": event_data.get("ProcessGuid"),
        "process_id": event_data.get("ProcessId"),
        "process_name": event_data.get("Image"),
        "query_name": event_data.get("QueryName"),
        "query_status": event_data.get("QueryStatus"),
        "query_results": event_data.get("QueryResults"),
        "username": event_data.get("User"),
    }


def parse_network_connection(xml_record):
    event_id = extract_event_id(xml_record)

    if event_id != "3":
        raise ValueError(
            f"Expected Sysmon Event ID 3, got {event_id}"
        )

    system_context = extract_system_context(xml_record)
    event_data = extract_event_data(xml_record)

    return {
        "event_id": event_id,
        "timestamp": system_context["timestamp"],
        "host": system_context["host"],
        "process_guid": event_data.get("ProcessGuid"),
        "process_id": event_data.get("ProcessId"),
        "process_name": event_data.get("Image"),
        "username": event_data.get("User"),
        "protocol": event_data.get("Protocol"),
        "initiated": event_data.get("Initiated"),
        "source_ip": event_data.get("SourceIp"),
        "source_port": event_data.get("SourcePort"),
        "destination_ip": event_data.get("DestinationIp"),
        "destination_port": event_data.get("DestinationPort"),
        "destination_hostname": event_data.get("DestinationHostname"),
    }


def parse_sysmon_event(xml_record):
    event_id = extract_event_id(xml_record)

    parsers = {
        "1": parse_process_creation,
        "3": parse_network_connection,
        "11": parse_file_creation,
        "13": parse_registry_modification,
        "22": parse_dns_query,
    }

    parser = parsers.get(event_id)

    if parser is None:
        return None

    return parser(xml_record)


def load_sysmon_events(file_path):
    events = []

    for xml_record in iter_evtx_xml_records(file_path):
        event = parse_sysmon_event(xml_record)

        if event is not None:
            events.append(event)

    return events
