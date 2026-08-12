from collections import defaultdict, deque
from datetime import datetime


def detect_brute_force(events, threshold=5, window_seconds=60):
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
                "source_ip": event["source_ip"],
                "username": event["username"],
                "failed_attempts": len(window),
                "first_seen": window[0].isoformat(),
                "last_seen": window[-1].isoformat(),
            })

            alerted_targets.add(key)

    return alerts
