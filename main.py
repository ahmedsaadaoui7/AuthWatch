import argparse
import sys

from src.analysis_engine import (
    AnalysisError,
    AnalysisRequest,
    run_analysis,
)
from src.formatter import format_alert_details
from src.reporter import (
    generate_investigation_json_report,
    generate_investigation_markdown_report,
    generate_json_report,
    generate_markdown_report,
)


def parse_arguments():
    parser = argparse.ArgumentParser(
        description=(
            "Analyze authentication and endpoint telemetry for suspicious "
            "activity and SOC investigation."
        )
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
        help="Optional path for the generated Markdown report.",
    )

    parser.add_argument(
        "--disabled-accounts",
        help="Path to a file containing disabled account usernames.",
    )

    parser.add_argument(
        "--config",
        help="Path to a JSON detection configuration file.",
    )

    parser.add_argument(
        "--correlation-config",
        help="Path to a JSON correlation configuration file.",
    )

    parser.add_argument(
        "--json-output",
        help="Optional path for the generated JSON output.",
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


def build_analysis_request(args):
    return AnalysisRequest(
        log_file=args.log_file,
        windows_security=args.windows_security,
        sysmon=args.sysmon,
        linux_auth=args.linux_auth,
        linux_year=args.linux_year,
        linux_utc_offset=args.linux_utc_offset,
        disabled_accounts=args.disabled_accounts,
        detection_config=args.config,
        correlation_config=args.correlation_config,
    )


def analyze_from_cli_args(args):
    request = build_analysis_request(args)
    return run_analysis(request)


def format_cli_analysis_error(error):
    if error.code == "DETECTION_CONFIG_NOT_FOUND":
        return (
            "Configuration file not found: "
            f"{error.path}"
        )

    return str(error)


def main():
    args = parse_arguments()

    try:
        result = analyze_from_cli_args(args)
    except AnalysisError as error:
        print(
            f"[ERROR] {format_cli_analysis_error(error)}",
            file=sys.stderr,
        )
        return 1

    alerts = result.detections
    correlations = result.correlations
    v3_mode = result.v3_mode

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
