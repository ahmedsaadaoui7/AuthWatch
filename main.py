import argparse
import sys

from src.config import load_detection_config
from src.detector import run_detection_engine
from src.formatter import format_alert_details
from src.parser import load_auth_events, load_disabled_accounts
from src.reporter import generate_json_report, generate_markdown_report


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Analyze authentication logs for suspicious authentication activity."
    )

    parser.add_argument(
        "log_file",
        help="Path to the authentication CSV or JSON log file.",
    )

    parser.add_argument(
        "--report",
        help="Optional path for the generated Markdown incident report.",
    )

    parser.add_argument(
        "--disabled-accounts",
        help="Path to a file containing disabled account usernames",
    )

    parser.add_argument(
        "--config",
        help="Path to a JSON detection configuration file",
    )

    parser.add_argument(
        "--json-output",
        help="Optional path for the generated JSON alert output.",
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
        print(
            f"[ERROR] Invalid authentication log: {error}",
            file=sys.stderr,
        )
        return 1

    disabled_accounts = None

    if args.disabled_accounts:
        try:
            disabled_accounts = load_disabled_accounts(
                args.disabled_accounts
            )
        except FileNotFoundError:
            print(
                f"[ERROR] Disabled accounts file not found: "
                f"{args.disabled_accounts}",
                file=sys.stderr,
            )
            return 1

    detection_config = None

    if args.config:
        try:
            detection_config = load_detection_config(args.config)
        except FileNotFoundError:
            print(
                f"[ERROR] Configuration file not found: {args.config}",
                file=sys.stderr,
            )
            return 1
        except ValueError as error:
            print(
                f"[ERROR] Invalid detection configuration: {error}",
                file=sys.stderr,
            )
            return 1

    alerts = run_detection_engine(
        events,
        disabled_accounts=disabled_accounts,
        config=detection_config,
    )

    if not alerts:
        print("No suspicious authentication activity detected.")

        if args.json_output:
            json_path = generate_json_report(alerts, args.json_output)
            print(f"\nJSON alert output written to: {json_path}")

        return 0

    for alert in alerts:
        print(f"\n[ALERT] {alert['title']}")
        print(f"Rule ID: {alert['rule_id']}")
        print(f"Severity: {alert['severity']}")

        for line in format_alert_details(alert["details"]):
            print(line)

        print(f"First seen: {alert['first_seen']}")
        print(f"Last seen: {alert['last_seen']}")

    if args.report:
        report_path = generate_markdown_report(alerts, args.report)
        print(f"\nIncident report written to: {report_path}")

    if args.json_output:
        json_path = generate_json_report(alerts, args.json_output)
        print(f"\nJSON alert output written to: {json_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
