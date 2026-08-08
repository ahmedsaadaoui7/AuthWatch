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
        print("\n[ALERT] Potential brute-force activity detected")
        print(f"Source IP: {alert['source_ip']}")
        print(f"Username: {alert['username']}")
        print(f"Failed attempts: {alert['failed_attempts']}")
        print(f"First failure: {alert['first_failure']}")
        print(f"Last failure: {alert['last_failure']}")

    if args.report:
        report_path = generate_markdown_report(alerts, args.report)
        print(f"\nIncident report written to: {report_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
