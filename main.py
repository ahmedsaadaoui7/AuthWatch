import argparse
import sys

from src.config import (
    load_correlation_config,
    load_detection_config,
)
from src.detector import run_detection_engine
from src.formatter import format_alert_details
from src.parser import load_auth_events, load_disabled_accounts
from src.reporter import (
    generate_investigation_json_report,
    generate_investigation_markdown_report,
    generate_json_report,
    generate_markdown_report,
)
from src.normalizer import (
    normalize_linux_auth_event,
    normalize_sysmon_event,
    normalize_windows_security_event,
)
from src.parsers.windows_security import load_windows_security_events
from src.parsers.sysmon import load_sysmon_events
from src.parsers.linux_auth import load_linux_auth_events
from src.correlation import run_correlation_engine
from src.timeline import attach_timelines_to_correlations
from src.mitre import attach_mitre_mappings



def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Analyze authentication logs for suspicious authentication activity."
    )

    parser.add_argument(
        "log_file",
        nargs="?",
         help="Optional path to a V2 authentication CSV or JSON log file.",
    )

    parser.add_argument(
        "--windows-security",
        help="Path to a Windows Security EVTX file.",
    )

    parser.add_argument(
        "--sysmon",
        help="Path to a Sysmon EVTX file.",
    )

    parser.add_argument(
        "--linux-auth",
        help="Path to a Linux authentication log file.",
    )

    parser.add_argument(
        "--linux-year",
        type=int,
        help="Year associated with Linux authentication log timestamps.",
    )

    parser.add_argument(
        "--linux-utc-offset",
        help=(
            "UTC offset for Linux authentication log timestamps "
            "(for example +01:00 or -05:00)."
        ),
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
        "--correlation-config",
        help="Path to a JSON correlation configuration file.",
    )

    parser.add_argument(
        "--json-output",
        help="Optional path for the generated JSON alert output.",
    )

    args = parser.parse_args()

    v3_mode = any([
        args.windows_security,
        args.sysmon,
        args.linux_auth,
    ])

    if not any([
        args.log_file,
        args.windows_security,
        args.sysmon,
        args.linux_auth,
    ]):
        parser.error(
            "at least one telemetry input is required"
        )

    if args.linux_auth and (
        args.linux_year is None
        or args.linux_utc_offset is None
    ):
        parser.error(
            "--linux-auth requires "
            "--linux-year and --linux-utc-offset"
        )

    return args


def main():
    args = parse_arguments()

    v3_mode = any([
        args.windows_security,
        args.sysmon,
        args.linux_auth,
    ])

    events = []

    if args.log_file:
        try:
            auth_events = load_auth_events(
                args.log_file
            )
        except FileNotFoundError:
            print(
                f"[ERROR] Authentication log not found: "
                f"{args.log_file}",
                file=sys.stderr,
            )
            return 1
        except ValueError as error:
            print(
                f"[ERROR] Invalid authentication log: {error}",
                file=sys.stderr,
            )
            return 1

        events.extend(auth_events)

    if args.windows_security:
        try:
            windows_events = load_windows_security_events(
                args.windows_security
            )
        except FileNotFoundError:
            print(
                f"[ERROR] Windows Security EVTX not found: "
                f"{args.windows_security}",
                file=sys.stderr,
            )
            return 1

        except ValueError as error:
            print(
                f"[ERROR] Invalid Windows Security telemetry: "
                f"{error}",
                file=sys.stderr,
            )
            return 1

        normalized_windows_events = [
            normalize_windows_security_event(event)
            for event in windows_events
        ]

        events.extend(normalized_windows_events)

    if args.sysmon:
        try:
            sysmon_events = load_sysmon_events(
                args.sysmon
            )
        except FileNotFoundError:
            print(
                f"[ERROR] Sysmon EVTX not found: "
                f"{args.sysmon}",
                file=sys.stderr,
            )
            return 1
        except ValueError as error:
            print(
                f"[ERROR] Invalid Sysmon telemetry: "
                f"{error}",
                file=sys.stderr,
            )
            return 1

        normalized_sysmon_events = [
            normalize_sysmon_event(event)
            for event in sysmon_events
        ]

        events.extend(normalized_sysmon_events)

    if args.linux_auth:
        try:
            linux_events = load_linux_auth_events(
                args.linux_auth
            )

            normalized_linux_events = [
                normalize_linux_auth_event(
                    event,
                    year=args.linux_year,
                    utc_offset=args.linux_utc_offset,
                )
                for event in linux_events
            ]

        except FileNotFoundError:
            print(
                f"[ERROR] Linux authentication log not found: "
                f"{args.linux_auth}",
                file=sys.stderr,
            )
            return 1
        except ValueError as error:
            print(
                f"[ERROR] Invalid Linux authentication telemetry: "
                f"{error}",
                file=sys.stderr,
            )
            return 1

        events.extend(normalized_linux_events)

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

    detection_config = None

    if args.config:
        try:
            detection_config = load_detection_config(
                args.config
            )
        except FileNotFoundError:
            print(
                f"[ERROR] Configuration file not found: "
                f"{args.config}",
                file=sys.stderr,
            )
            return 1
        except ValueError as error:
            print(
                f"[ERROR] Invalid detection configuration: "
                f"{error}",
                file=sys.stderr,
            )
            return 1


    correlation_config = None

    if args.correlation_config:
        try:
            correlation_config = load_correlation_config(
                args.correlation_config
            )
        except FileNotFoundError:
            print(
                f"[ERROR] Correlation configuration file not found: "
                f"{args.correlation_config}",
                file=sys.stderr,
            )
            return 1
        except ValueError as error:
            print(
                f"[ERROR] Invalid correlation configuration: "
                f"{error}",
                file=sys.stderr,
            )
            return 1


    alerts = run_detection_engine(
        events,
        disabled_accounts=disabled_accounts,
        config=detection_config,
    )

    alerts = run_detection_engine(
        events,
        disabled_accounts=disabled_accounts,
        config=detection_config,
    )

    if correlation_config is None:
        correlations = run_correlation_engine(events)
    else:
        correlations = run_correlation_engine(
            events,
            config=correlation_config,
        )

    correlations = attach_timelines_to_correlations(
        correlations
    )

    alerts = attach_mitre_mappings(alerts)

    correlations = attach_mitre_mappings(
        correlations
    )

    if not alerts and not correlations:
        if v3_mode:
            print(
                "No suspicious activity or correlations detected."
            )

            if args.report:
                report_path = (
                    generate_investigation_markdown_report(
                        alerts,
                        correlations,
                        args.report,
                    )
                )
                print(
                    f"\nInvestigation report written to: "
                    f"{report_path}"
                )

            if args.json_output:
                json_path = generate_investigation_json_report(
                    alerts,
                    correlations,
                    args.json_output,
                )
                print(
                    f"\nInvestigation JSON output written to: "
                    f"{json_path}"
                )

        else:
            print(
                "No suspicious authentication activity detected."
            )

            if args.json_output:
                json_path = generate_json_report(
                    alerts,
                    args.json_output,
                )
                print(
                    f"\nJSON alert output written to: "
                    f"{json_path}"
                )

        return 0

    for alert in alerts:
        print(f"\n[ALERT] {alert['title']}")
        print(f"Rule ID: {alert['rule_id']}")
        print(f"Severity: {alert['severity']}")

        for line in format_alert_details(alert["details"]):
            print(line)

        print(f"First seen: {alert['first_seen']}")
        print(f"Last seen: {alert['last_seen']}")

    for correlation in correlations:
        print(
            f"\n[CORRELATION] "
            f"{correlation['title']}"
        )
        print(
            f"Correlation ID: "
            f"{correlation['correlation_id']}"
        )
        print(
            f"Severity: "
            f"{correlation['severity']}"
        )
        print(
            f"First seen: "
            f"{correlation['first_seen']}"
        )
        print(
            f"Last seen: "
            f"{correlation['last_seen']}"
        )

    if args.report:
        if v3_mode:
            report_path = generate_investigation_markdown_report(
                alerts,
                correlations,
                args.report,
            )
            print(
                f"\nInvestigation report written to: "
                f"{report_path}"
            )
        else:
            report_path = generate_markdown_report(
                alerts,
                args.report,
            )
            print(
                f"\nIncident report written to: "
                f"{report_path}"
            )

    if args.json_output:
        if v3_mode:
            json_path = generate_investigation_json_report(
                alerts,
                correlations,
                args.json_output,
            )
            print(
                f"\nInvestigation JSON output written to: "
                f"{json_path}"
            )
        else:
            json_path = generate_json_report(
                alerts,
                args.json_output,
            )
            print(
                f"\nJSON alert output written to: "
                f"{json_path}"
            )

    return 0


if __name__ == "__main__":
    sys.exit(main())
