from collections import defaultdict, deque
from datetime import datetime

from src.config import DEFAULT_DETECTION_CONFIG


def detect_brute_force(
    events,
    threshold=DEFAULT_DETECTION_CONFIG["AUTH-BF-001"]["threshold"],
    window_seconds=DEFAULT_DETECTION_CONFIG["AUTH-BF-001"]["window_seconds"],
):
    failure_windows = defaultdict(deque)
    alerts = []

    sorted_events = sorted(
        events,
        key=lambda event: datetime.fromisoformat(event["timestamp"])
    )

    alerted_targets = set()

    for event in sorted_events:
        if event["result"] != "failure":
            continue

        key = (event["source_ip"], event["username"])
        timestamp = datetime.fromisoformat(event["timestamp"])

        window = failure_windows[key]
        window.append(timestamp)

        while (timestamp - window[0]).total_seconds() > window_seconds:
            window.popleft()

        if len(window) >= threshold and key not in alerted_targets:
            alerts.append({
                "rule_id": "AUTH-BF-001",
                "title": "Potential Brute-Force Activity",
                "severity": "high",
                "first_seen": window[0].isoformat(),
                "last_seen": window[-1].isoformat(),
                "details": {
                    "source_ip": event["source_ip"],
                    "username": event["username"],
                    "failed_attempts": len(window),
                },
            })

            alerted_targets.add(key)

    return alerts

def detect_password_spray(
    events,
    threshold=DEFAULT_DETECTION_CONFIG["AUTH-PS-001"]["threshold"],
    window_seconds=DEFAULT_DETECTION_CONFIG["AUTH-PS-001"]["window_seconds"],
):
    spray_windows = defaultdict(deque)
    alerts = []

    sorted_events = sorted(
        events,
        key=lambda event: datetime.fromisoformat(event["timestamp"])
    )

    alerted_sources = set()

    for event in sorted_events:
        if event["result"] != "failure":
            continue

        source_ip = event["source_ip"]
        timestamp = datetime.fromisoformat(event["timestamp"])
        username = event["username"]

        window = spray_windows[source_ip]
        window.append((timestamp, username))

        while (timestamp - window[0][0]).total_seconds() > window_seconds:
            window.popleft()

        unique_accounts = {
            stored_username
            for _, stored_username in window
        }

        if (
            len(unique_accounts) >= threshold
            and source_ip not in alerted_sources
        ):
            alerts.append({
                "rule_id": "AUTH-PS-001",
                "title": "Potential Password Spraying Activity",
                "severity": "high",
                "first_seen": window[0][0].isoformat(),
                "last_seen": window[-1][0].isoformat(),
                "details": {
                    "source_ip": source_ip,
                    "unique_accounts": len(unique_accounts),
                    "usernames": sorted(unique_accounts),
                },
            })

            alerted_sources.add(source_ip)

    return alerts


def detect_success_after_failures(
    events,
    threshold=DEFAULT_DETECTION_CONFIG["AUTH-SF-001"]["threshold"],
    window_seconds=DEFAULT_DETECTION_CONFIG["AUTH-SF-001"]["window_seconds"],
):
    failure_windows = defaultdict(deque)
    alerts = []

    sorted_events = sorted(
        events,
        key=lambda event: datetime.fromisoformat(event["timestamp"])
    )

    for event in sorted_events:
        key = (event["source_ip"], event["username"])
        timestamp = datetime.fromisoformat(event["timestamp"])

        window = failure_windows[key]

        while window and (
            timestamp - window[0]
        ).total_seconds() > window_seconds:
            window.popleft()

        if event["result"] == "failure":
            window.append(timestamp)
            continue

        if event["result"] == "success":
            if len(window) >= threshold:
                alerts.append({
                    "rule_id": "AUTH-SF-001",
                    "title": "Successful Login After Repeated Failures",
                    "severity": "high",
                    "first_seen": window[0].isoformat(),
                    "last_seen": timestamp.isoformat(),
                    "details": {
                        "source_ip": event["source_ip"],
                        "username": event["username"],
                        "failed_attempts": len(window),
                    },
                })

            window.clear()

    return alerts


def detect_disabled_account_attempts(events, disabled_accounts):
    alerts = []

    for event in events:
        if event["username"] not in disabled_accounts:
            continue

        alerts.append({
            "rule_id": "AUTH-DA-001",
            "title": "Authentication Attempt Against Disabled Account",
            "severity": "medium",
            "first_seen": event["timestamp"],
            "last_seen": event["timestamp"],
            "details": {
                "source_ip": event["source_ip"],
                "username": event["username"],
                "result": event["result"],
            },
        })

    return alerts


def detect_one_ip_many_accounts(
    events,
    threshold=DEFAULT_DETECTION_CONFIG["AUTH-MA-001"]["threshold"],
    window_seconds=DEFAULT_DETECTION_CONFIG["AUTH-MA-001"]["window_seconds"],
):
    account_windows = defaultdict(deque)
    alerts = []

    sorted_events = sorted(
        events,
        key=lambda event: datetime.fromisoformat(event["timestamp"])
    )

    alerted_sources = set()

    for event in sorted_events:
        source_ip = event["source_ip"]
        timestamp = datetime.fromisoformat(event["timestamp"])
        username = event["username"]

        window = account_windows[source_ip]
        window.append((timestamp, username))

        while (
            timestamp - window[0][0]
        ).total_seconds() > window_seconds:
            window.popleft()

        unique_accounts = {
            stored_username
            for _, stored_username in window
        }

        if (
            len(unique_accounts) >= threshold
            and source_ip not in alerted_sources
        ):
            alerts.append({
                "rule_id": "AUTH-MA-001",
                "title": "One Source IP Accessing Multiple Accounts",
                "severity": "medium",
                "first_seen": window[0][0].isoformat(),
                "last_seen": window[-1][0].isoformat(),
                "details": {
                    "source_ip": source_ip,
                    "unique_accounts": len(unique_accounts),
                    "usernames": sorted(unique_accounts),
                },
            })

            alerted_sources.add(source_ip)

    return alerts


def detect_many_ips_one_account(
    events,
    threshold=DEFAULT_DETECTION_CONFIG["AUTH-MI-001"]["threshold"],
    window_seconds=DEFAULT_DETECTION_CONFIG["AUTH-MI-001"]["window_seconds"],
):
    ip_windows = defaultdict(deque)
    alerts = []

    sorted_events = sorted(
        events,
        key=lambda event: datetime.fromisoformat(event["timestamp"])
    )

    alerted_accounts = set()

    for event in sorted_events:
        username = event["username"]
        timestamp = datetime.fromisoformat(event["timestamp"])
        source_ip = event["source_ip"]

        window = ip_windows[username]
        window.append((timestamp, source_ip))

        while (
            timestamp - window[0][0]
        ).total_seconds() > window_seconds:
            window.popleft()

        unique_source_ips = {
            stored_ip
            for _, stored_ip in window
        }

        if (
            len(unique_source_ips) >= threshold
            and username not in alerted_accounts
        ):
            alerts.append({
                "rule_id": "AUTH-MI-001",
                "title": "One Account Accessed From Multiple Source IPs",
                "severity": "medium",
                "first_seen": window[0][0].isoformat(),
                "last_seen": window[-1][0].isoformat(),
                "details": {
                    "username": username,
                    "unique_source_ips": len(unique_source_ips),
                    "source_ips": sorted(unique_source_ips),
                },
            })

            alerted_accounts.add(username)

    return alerts


def run_detection_engine(events, disabled_accounts=None, config=None):
    alerts = []

    if config is None:
        config = {}

    detectors = (
        ("AUTH-BF-001", detect_brute_force),
        ("AUTH-PS-001", detect_password_spray),
        ("AUTH-SF-001", detect_success_after_failures),
        ("AUTH-MA-001", detect_one_ip_many_accounts),
        ("AUTH-MI-001", detect_many_ips_one_account),
    )

    for rule_id, detector in detectors:
        rule_config = DEFAULT_DETECTION_CONFIG[rule_id].copy()
        rule_config.update(config.get(rule_id, {}))

        alerts.extend(
            detector(
                events,
                **rule_config,
            )
        )

    if disabled_accounts is not None:
        alerts.extend(
            detect_disabled_account_attempts(
                events,
                disabled_accounts,
            )
        )

    return alerts
