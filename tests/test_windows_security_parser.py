import pytest

from src.parsers.windows_security import (
    parse_windows_security_event,
)


def test_parse_failed_logon():
    xml = """
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <EventID>4625</EventID>
        <TimeCreated SystemTime="2026-08-28T09:30:00.000000Z"/>
        <Computer>WIN-PC01</Computer>
      </System>
      <EventData>
        <Data Name="TargetUserName">admin</Data>
        <Data Name="IpAddress">10.0.0.8</Data>
        <Data Name="LogonType">10</Data>
        <Data Name="FailureReason">%%2313</Data>
        <Data Name="Status">0xC000006D</Data>
        <Data Name="SubStatus">0xC000006A</Data>
      </EventData>
    </Event>
    """

    event = parse_windows_security_event(xml)

    assert event["event_id"] == "4625"
    assert event["host"] == "WIN-PC01"
    assert event["username"] == "admin"
    assert event["source_ip"] == "10.0.0.8"


def test_parse_successful_logon():
    xml = """
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <EventID>4624</EventID>
        <TimeCreated SystemTime="2026-08-28T09:40:00.000000Z"/>
        <Computer>WIN-PC01</Computer>
      </System>
      <EventData>
        <Data Name="TargetUserName">admin</Data>
        <Data Name="IpAddress">10.0.0.8</Data>
        <Data Name="LogonType">10</Data>
        <Data Name="TargetLogonId">0x12345</Data>
        <Data Name="AuthenticationPackageName">NTLM</Data>
      </EventData>
    </Event>
    """

    event = parse_windows_security_event(xml)

    assert event["event_id"] == "4624"
    assert event["username"] == "admin"
    assert event["logon_id"] == "0x12345"
    assert event["authentication_package"] == "NTLM"


def test_parse_explicit_credentials():
    xml = """
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <EventID>4648</EventID>
        <TimeCreated SystemTime="2026-08-28T09:55:00.000000Z"/>
        <Computer>WIN-PC01</Computer>
      </System>
      <EventData>
        <Data Name="SubjectUserName">hawk</Data>
        <Data Name="TargetUserName">admin</Data>
        <Data Name="TargetServerName">SERVER01</Data>
        <Data Name="ProcessName">runas.exe</Data>
        <Data Name="SubjectLogonId">0x45678</Data>
      </EventData>
    </Event>
    """

    event = parse_windows_security_event(xml)

    assert event["event_id"] == "4648"
    assert event["source_username"] == "hawk"
    assert event["username"] == "admin"
    assert event["target_server"] == "SERVER01"


def test_parse_privileged_logon():
    xml = """
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <EventID>4672</EventID>
        <TimeCreated SystemTime="2026-08-28T10:00:00.000000Z"/>
        <Computer>WIN-PC01</Computer>
      </System>
      <EventData>
        <Data Name="SubjectUserName">admin</Data>
        <Data Name="SubjectLogonId">0x12345</Data>
        <Data Name="PrivilegeList">SeDebugPrivilege SeBackupPrivilege</Data>
      </EventData>
    </Event>
    """

    event = parse_windows_security_event(xml)

    assert event["event_id"] == "4672"
    assert event["username"] == "admin"
    assert event["logon_id"] == "0x12345"


def test_unsupported_event_returns_none():
    xml = """
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <EventID>9999</EventID>
      </System>
    </Event>
    """

    assert parse_windows_security_event(xml) is None


def test_missing_event_id_raises_error():
    xml = """
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System></System>
    </Event>
    """

    with pytest.raises(ValueError):
        parse_windows_security_event(xml)
