import re
from pathlib import Path



FAILED_SSH_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"sshd\[(?P<pid>\d+)\]:\s+"
    r"Failed (?P<method>\S+) for "
    r"(?:(?P<invalid_user>invalid user) )?"
    r"(?P<username>\S+) from "
    r"(?P<source_ip>\S+) port "
    r"(?P<source_port>\d+) "
    r"(?P<protocol>\S+)$"
)


def parse_failed_ssh_login(log_line):
    match = FAILED_SSH_PATTERN.match(log_line.strip())

    if match is None:
        return None

    return {
        "event_type": "authentication_failure",
        "timestamp": match.group("timestamp"),
        "host": match.group("host"),
        "service": "sshd",
        "process_id": match.group("pid"),
        "username": match.group("username"),
        "source_ip": match.group("source_ip"),
        "source_port": match.group("source_port"),
        "authentication_method": match.group("method"),
        "protocol": match.group("protocol"),
        "invalid_user": match.group("invalid_user") is not None,
        "result": "failure",
    }


SUCCESSFUL_SSH_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"sshd\[(?P<pid>\d+)\]:\s+"
    r"Accepted (?P<method>\S+) for "
    r"(?P<username>\S+) from "
    r"(?P<source_ip>\S+) port "
    r"(?P<source_port>\d+) "
    r"(?P<protocol>\S+)$"
)


def parse_successful_ssh_login(log_line):
    match = SUCCESSFUL_SSH_PATTERN.match(log_line.strip())

    if match is None:
        return None

    return {
        "event_type": "authentication_success",
        "timestamp": match.group("timestamp"),
        "host": match.group("host"),
        "service": "sshd",
        "process_id": match.group("pid"),
        "username": match.group("username"),
        "source_ip": match.group("source_ip"),
        "source_port": match.group("source_port"),
        "authentication_method": match.group("method"),
        "protocol": match.group("protocol"),
        "result": "success",
    }


SUDO_COMMAND_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"sudo(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<username>\S+)\s+:\s+"
    r"TTY=(?P<tty>[^;]+)\s*;\s*"
    r"PWD=(?P<working_directory>[^;]+)\s*;\s*"
    r"USER=(?P<target_user>[^;]+)\s*;\s*"
    r"COMMAND=(?P<command>.+)$"
)


def parse_sudo_command(log_line):
    match = SUDO_COMMAND_PATTERN.match(log_line.strip())

    if match is None:
        return None

    return {
        "event_type": "sudo_execution",
        "timestamp": match.group("timestamp"),
        "host": match.group("host"),
        "service": "sudo",
        "process_id": match.group("pid"),
        "username": match.group("username"),
        "target_user": match.group("target_user").strip(),
        "tty": match.group("tty").strip(),
        "working_directory": match.group("working_directory").strip(),
        "command": match.group("command").strip(),
        "result": "success",
    }


SSH_SESSION_OPEN_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"sshd\[(?P<pid>\d+)\]:\s+"
    r"pam_unix\(sshd:session\):\s+"
    r"session opened for user "
    r"(?P<username>[^\s(]+)"
    r"(?:\(uid=(?P<user_id>\d+)\))?"
    r"\s+by\s+"
    r"\(uid=(?P<opened_by_uid>\d+)\)$"
)


def parse_ssh_session_open(log_line):
    match = SSH_SESSION_OPEN_PATTERN.match(log_line.strip())

    if match is None:
        return None

    return {
        "event_type": "session_activity",
        "session_action": "opened",
        "timestamp": match.group("timestamp"),
        "host": match.group("host"),
        "service": "sshd",
        "process_id": match.group("pid"),
        "username": match.group("username"),
        "user_id": match.group("user_id"),
        "opened_by_uid": match.group("opened_by_uid"),
    }


SSH_SESSION_CLOSE_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"sshd\[(?P<pid>\d+)\]:\s+"
    r"pam_unix\(sshd:session\):\s+"
    r"session closed for user "
    r"(?P<username>\S+)$"
)


def parse_ssh_session_close(log_line):
    match = SSH_SESSION_CLOSE_PATTERN.match(log_line.strip())

    if match is None:
        return None

    return {
        "event_type": "session_activity",
        "session_action": "closed",
        "timestamp": match.group("timestamp"),
        "host": match.group("host"),
        "service": "sshd",
        "process_id": match.group("pid"),
        "username": match.group("username"),
    }


LINUX_AUTH_PARSERS = (
    parse_failed_ssh_login,
    parse_successful_ssh_login,
    parse_sudo_command,
    parse_ssh_session_open,
    parse_ssh_session_close,
)


def parse_linux_auth_event(log_line):
    for parser in LINUX_AUTH_PARSERS:
        event = parser(log_line)

        if event is not None:
            return event

    return None


def load_linux_auth_events(file_path):
    file_path = Path(file_path)

    if not file_path.is_file():
        raise FileNotFoundError(
            f"Linux authentication log not found: {file_path}"
        )

    events = []

    with file_path.open(
        "r",
        encoding="utf-8",
        errors="replace",
    ) as log_file:
        for log_line in log_file:
            if not log_line.strip():
                continue

            event = parse_linux_auth_event(log_line)

            if event is not None:
                events.append(event)

    return events
