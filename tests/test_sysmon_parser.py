import pytest

from src.parsers.sysmon import parse_sysmon_event


def test_parse_process_creation():
    xml = """
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <EventID>1</EventID>
        <TimeCreated SystemTime="2026-08-29T08:30:00.000000Z"/>
        <Computer>WIN-PC01</Computer>
      </System>
      <EventData>
        <Data Name="ProcessGuid">{ABC-123}</Data>
        <Data Name="ProcessId">4568</Data>
        <Data Name="Image">powershell.exe</Data>
        <Data Name="CommandLine">powershell.exe -NoProfile</Data>
        <Data Name="User">WIN-PC01\\admin</Data>
      </EventData>
    </Event>
    """

    event = parse_sysmon_event(xml)

    assert event["event_id"] == "1"
    assert event["process_guid"] == "{ABC-123}"
    assert event["process_name"] == "powershell.exe"
    assert event["username"] == "WIN-PC01\\admin"


def test_parse_network_connection():
    xml = """
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <EventID>3</EventID>
        <TimeCreated SystemTime="2026-08-29T08:31:00.000000Z"/>
        <Computer>WIN-PC01</Computer>
      </System>
      <EventData>
        <Data Name="ProcessGuid">{ABC-123}</Data>
        <Data Name="ProcessId">4568</Data>
        <Data Name="Image">powershell.exe</Data>
        <Data Name="DestinationIp">10.0.0.50</Data>
        <Data Name="DestinationPort">443</Data>
        <Data Name="Protocol">tcp</Data>
      </EventData>
    </Event>
    """

    event = parse_sysmon_event(xml)

    assert event["event_id"] == "3"
    assert event["process_guid"] == "{ABC-123}"
    assert event["destination_ip"] == "10.0.0.50"
    assert event["destination_port"] == "443"


def test_parse_file_creation():
    xml = """
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <EventID>11</EventID>
        <TimeCreated SystemTime="2026-08-29T08:32:00.000000Z"/>
        <Computer>WIN-PC01</Computer>
      </System>
      <EventData>
        <Data Name="ProcessGuid">{ABC-123}</Data>
        <Data Name="ProcessId">4568</Data>
        <Data Name="Image">powershell.exe</Data>
        <Data Name="TargetFilename">C:\\Users\\admin\\Downloads\\script.ps1</Data>
      </EventData>
    </Event>
    """

    event = parse_sysmon_event(xml)

    assert event["event_id"] == "11"
    assert event["process_guid"] == "{ABC-123}"
    assert event["target_filename"] == (
        "C:\\Users\\admin\\Downloads\\script.ps1"
    )


def test_parse_registry_modification():
    xml = """
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <EventID>13</EventID>
        <TimeCreated SystemTime="2026-08-29T08:33:00.000000Z"/>
        <Computer>WIN-PC01</Computer>
      </System>
      <EventData>
        <Data Name="ProcessGuid">{ABC-123}</Data>
        <Data Name="ProcessId">4568</Data>
        <Data Name="Image">powershell.exe</Data>
        <Data Name="TargetObject">HKCU\\Software\\Example\\Setting</Data>
        <Data Name="Details">NewValue</Data>
      </EventData>
    </Event>
    """

    event = parse_sysmon_event(xml)

    assert event["event_id"] == "13"
    assert event["process_guid"] == "{ABC-123}"
    assert event["target_object"] == "HKCU\\Software\\Example\\Setting"
    assert event["details"] == "NewValue"


def test_parse_dns_query():
    xml = """
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <EventID>22</EventID>
        <TimeCreated SystemTime="2026-08-29T08:34:00.000000Z"/>
        <Computer>WIN-PC01</Computer>
      </System>
      <EventData>
        <Data Name="ProcessGuid">{ABC-123}</Data>
        <Data Name="ProcessId">4568</Data>
        <Data Name="Image">powershell.exe</Data>
        <Data Name="QueryName">example.com</Data>
        <Data Name="QueryStatus">0</Data>
        <Data Name="QueryResults">10.0.0.50</Data>
      </EventData>
    </Event>
    """

    event = parse_sysmon_event(xml)

    assert event["event_id"] == "22"
    assert event["process_guid"] == "{ABC-123}"
    assert event["query_name"] == "example.com"
    assert event["query_results"] == "10.0.0.50"


def test_unsupported_event_returns_none():
    xml = """
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <EventID>9999</EventID>
      </System>
    </Event>
    """

    assert parse_sysmon_event(xml) is None


def test_missing_event_id_raises_error():
    xml = """
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System></System>
    </Event>
    """

    with pytest.raises(ValueError):
        parse_sysmon_event(xml)
