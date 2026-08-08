import argparse

from src.detector import detect_brute_force
from src.parser import load_auth_events


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Analyze authentication logs for potential brute-force activity."
    )

    parser.add_argument(
        "log_file",
        help="Path to the authentication CSV log file.",
    )

    return parser.parse_args()


def main():
    args = parse_arguments()

    events = load_auth_events(args.log_file)
    alerts = detect_brute_force(events)

    if not alerts:
        print("No suspicious authentication activity detected.")
        return

    for alert in alerts:
        print("\n[ALERT] Potential brute-force activity detected")
        print(f"Source IP: {alert['source_ip']}")
        print(f"Username: {alert['username']}")
        print(f"Failed attempts: {alert['failed_attempts']}")
        print(f"First failure: {alert['first_failure']}")
        print(f"Last failure: {alert['last_failure']}")


if __name__ == "__main__":
    main()
