import argparse
import sys

from src.detector import detect_brute_force
from src.parser import load_auth_events
from src.reporter import generate_markdown_report


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Analyze authentication logs for potential brute-force activity."
    )

    parser.add_argument(
        "log_file",
        help="Path to the authentication CSV log file.",
    )

    parser.add_argument(
        "--report",
        help="Optional path for the generated Markdown incident report.",
    )

    return parser.parse_args()


def main():
    args = parse_arguments()

    try:
        events = load_auth_events(args.log_file)
    except FileNotFoundError:
        print(
            f"[ERROR] Authentication log not found: {args.log_file}",
            file=sys.stderr,
        )
        return 1
    except ValueError as error:
        print(f"[ERROR] {error}", file=sys.stderr)
        return 1

    alerts = detect_brute_force(events)

    if not alerts:
        print("No suspicious authentication activity detected.")
        return 0

    for alert in alerts:
        details = alert["details"]

        print(f"\n[ALERT] {alert['title']}")
        print(f"Rule ID: {alert['rule_id']}")
        print(f"Severity: {alert['severity']}")
        print(f"Source IP: {details['source_ip']}")
        print(f"Username: {details['username']}")
        print(f"Failed attempts: {details['failed_attempts']}")
        print(f"First seen: {alert['first_seen']}")
        print(f"Last seen: {alert['last_seen']}")

    if args.report:
        report_path = generate_markdown_report(alerts, args.report)
        print(f"\nIncident report written to: {report_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
