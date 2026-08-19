# AuthWatch

AuthWatch is a defensive cybersecurity project for detecting suspicious authentication activity and supporting SOC investigation workflows.

Version 2 expands the original brute-force analyzer into a configurable multi-rule authentication detection engine. It supports CSV and JSON authentication logs, multiple detection techniques, configurable thresholds and time windows, optional disabled-account context, terminal alerts, Markdown incident reports, and structured JSON alert output.

The project is designed to evolve gradually into a larger authentication threat detection and SOC investigation platform while maintaining clear architecture, automated testing, professional documentation, safe synthetic data, and meaningful version history.

---

## Current Version

**V2 — Multi-Rule Detection Engine**

AuthWatch V2 provides a complete command-line workflow:

```text
Authentication CSV / JSON
          |
          v
        Parser
          |
          v
   Event Validation
          |
          v
 Multi-Rule Detection Engine
          |
          v
        Alerts
      /    |     \
     v     v      v
 Terminal Markdown JSON
          Report  Output
```

Optional detection context can also be supplied through:

- A JSON detection configuration file
- A disabled-account username list

---

## Features

- Parse authentication events from CSV and JSON files
- Validate required authentication fields and values
- Validate ISO-format timestamps
- Reject unsupported authentication-log formats
- Detect potential brute-force activity
- Detect potential password spraying
- Detect successful login after repeated failures
- Detect authentication attempts against disabled accounts
- Detect one source IP accessing many accounts
- Detect one account being accessed from many source IPs
- Apply configurable thresholds and time windows
- Load optional disabled-account context
- Load rule-specific JSON detection configuration
- Assign rule IDs and severity levels to alerts
- Display alerts in the terminal
- Generate Markdown incident reports
- Generate structured JSON alert output
- Generate Markdown and JSON outputs from the same analysis
- Produce valid JSON output even when no alerts are detected
- Handle missing and malformed input cleanly
- Return appropriate command-line exit codes
- Use only synthetic or sanitized authentication data
- Provide automated unit and integration tests

---

## Detection Rules

AuthWatch V2 currently implements six authentication-focused detection rules.

| Rule ID | Detection | Severity | Default threshold | Default window |
|---|---|---:|---:|---:|
| `AUTH-BF-001` | Potential Brute-Force Activity | High | 5 failed attempts | 60 seconds |
| `AUTH-PS-001` | Potential Password Spraying Activity | High | 5 unique usernames | 60 seconds |
| `AUTH-SF-001` | Successful Login After Repeated Failures | High | 3 failed attempts before success | 60 seconds |
| `AUTH-DA-001` | Authentication Attempt Against Disabled Account | Medium | Any matching attempt | Not applicable |
| `AUTH-MA-001` | One Source IP Accessing Multiple Accounts | Medium | 5 unique usernames | 300 seconds |
| `AUTH-MI-001` | One Account Accessed From Multiple Source IPs | Medium | 5 unique source IPs | 300 seconds |

### `AUTH-BF-001` — Potential Brute-Force Activity

Triggers when the same source IP targets the same username with at least five failed authentication attempts inside the configured time window.

Conceptually:

```text
same source IP
+
same username
+
5 or more failures
+
within 60 seconds
=
potential brute-force activity
```

Successful authentication events do not count toward the brute-force failure threshold.

The exact 60-second boundary is inclusive.

### `AUTH-PS-001` — Potential Password Spraying Activity

Triggers when one source IP produces failed authentication attempts against at least five different usernames inside the configured time window.

The rule counts unique usernames rather than total failed attempts. Successful authentications do not count toward the password-spray threshold.

The exact 60-second boundary is inclusive.

### `AUTH-SF-001` — Successful Login After Repeated Failures

Triggers when the same source IP and username generate at least three failed authentication attempts followed by a successful login inside the configured time window.

A successful login ends the current failure sequence for that source-IP and username pair.

The exact 60-second boundary is inclusive.

### `AUTH-DA-001` — Authentication Attempt Against Disabled Account

Triggers when an authentication event targets a username contained in the supplied disabled-account list.

Both failed and successful authentication attempts are considered relevant because either can indicate stale credentials, configuration problems, account-lifecycle issues, or suspicious activity.

This rule depends on external disabled-account context and does not use a threshold or time window.

### `AUTH-MA-001` — One Source IP Accessing Multiple Accounts

Triggers when one source IP accesses at least five unique usernames inside the configured time window.

Both successful and failed authentication events count toward the unique-account total.

The exact 300-second boundary is inclusive.

### `AUTH-MI-001` — One Account Accessed From Multiple Source IPs

Triggers when one username is accessed from at least five unique source IPs inside the configured time window.

Both successful and failed authentication events count toward the unique-source-IP total.

The exact 300-second boundary is inclusive.

---

## Detection Methodology

Authentication events are parsed into a shared internal structure and validated before detection begins.

For time-window rules, AuthWatch sorts events chronologically and maintains rule-specific sliding windows. Events that fall outside the configured window are removed before the current detection condition is evaluated.

Different rules group activity differently depending on the behavior being detected:

```text
AUTH-BF-001 -> source IP + username
AUTH-PS-001 -> source IP
AUTH-SF-001 -> source IP + username
AUTH-DA-001 -> username against disabled-account context
AUTH-MA-001 -> source IP
AUTH-MI-001 -> username
```

Each generated alert uses a common structure:

```json
{
    "rule_id": "AUTH-BF-001",
    "title": "Potential Brute-Force Activity",
    "severity": "high",
    "first_seen": "2026-08-08T09:00:00",
    "last_seen": "2026-08-08T09:00:48",
    "details": {
        "source_ip": "10.0.0.50",
        "username": "admin",
        "failed_attempts": 5
    }
}
```

This common structure allows the same detections to be displayed in the terminal, written to Markdown reports, or exported as structured JSON.

---

## Detection Configuration

V2 centralizes configurable rule defaults in `src/config.py`.

Default configuration:

```json
{
    "AUTH-BF-001": {
        "threshold": 5,
        "window_seconds": 60
    },
    "AUTH-PS-001": {
        "threshold": 5,
        "window_seconds": 60
    },
    "AUTH-SF-001": {
        "threshold": 3,
        "window_seconds": 60
    },
    "AUTH-MA-001": {
        "threshold": 5,
        "window_seconds": 300
    },
    "AUTH-MI-001": {
        "threshold": 5,
        "window_seconds": 300
    }
}
```

A custom JSON configuration can override one or more settings.

Example:

```json
{
    "AUTH-BF-001": {
        "threshold": 6,
        "window_seconds": 90
    },
    "AUTH-PS-001": {
        "threshold": 8
    }
}
```

Partial overrides are supported. Any omitted setting keeps its default value.

AuthWatch rejects configuration files containing:

- Unknown rule IDs
- Unknown settings
- Non-object rule configurations
- Non-positive values
- Incorrect value types
- Invalid JSON structure

`AUTH-DA-001` is not threshold-based and therefore is not included in the configurable threshold/window defaults.

---

## Authentication Log Format

AuthWatch V2 accepts authentication logs in either CSV or JSON format.

Supported file extensions:

```text
.csv
.json
```

Other authentication-log extensions are rejected with a clear error.

### Required Fields

Every authentication event must contain:

| Field | Description |
|---|---|
| `timestamp` | Authentication event time in ISO format |
| `username` | Account involved in the authentication attempt |
| `source_ip` | Source IP address of the authentication attempt |
| `result` | Authentication result: `success` or `failure` |

Required values must be non-empty strings.

### CSV Example

```csv
timestamp,username,source_ip,result
2026-08-08T09:00:00,admin,10.0.0.50,failure
2026-08-08T09:00:12,admin,10.0.0.50,failure
2026-08-08T09:00:24,admin,10.0.0.50,failure
2026-08-08T09:00:36,admin,10.0.0.50,failure
2026-08-08T09:00:48,admin,10.0.0.50,failure
```

### JSON Example

JSON authentication logs must contain a top-level list of event objects.

```json
[
    {
        "timestamp": "2026-08-08T09:00:00",
        "username": "admin",
        "source_ip": "10.0.0.50",
        "result": "failure"
    },
    {
        "timestamp": "2026-08-08T09:00:12",
        "username": "admin",
        "source_ip": "10.0.0.50",
        "result": "failure"
    }
]
```

AuthWatch validates both CSV and JSON events through the same shared event-validation logic.

Input is rejected when:

- Required fields are missing
- Required values are empty
- Required values are not strings
- The authentication result is not `success` or `failure`
- The timestamp cannot be parsed as ISO format
- JSON authentication data is not a top-level list
- A JSON event is not an object
- The authentication-log file format is unsupported

---

## Disabled-Account Context

The disabled-account detection rule accepts an optional text file containing one username per line.

Example:

```text
old_admin
terminated_user
disabled_service
```

Blank lines are ignored and duplicate usernames are removed.

The list is supplied with:

```bash
python3 main.py data/brute_force_auth_log.csv \
  --disabled-accounts disabled_accounts.txt
```

The file should contain only safe synthetic or sanitized usernames when used in this repository.

---

## Project Structure

```text
authwatch/
├── data/
│   ├── brute_force_auth_log.csv
│   ├── brute_force_auth_log.json
│   └── normal_auth_log.csv
│
├── reports/
│
├── src/
│   ├── config.py
│   ├── detector.py
│   ├── formatter.py
│   ├── parser.py
│   └── reporter.py
│
├── tests/
│   ├── test_config.py
│   ├── test_detector.py
│   ├── test_formatter.py
│   ├── test_main.py
│   ├── test_parser.py
│   └── test_reporter.py
│
├── CHANGELOG.md
├── LICENSE
├── README.md
├── main.py
├── pytest.ini
└── requirements.txt
```

### Component Responsibilities

| Component | Responsibility |
|---|---|
| `main.py` | Command-line interface, input orchestration, detection execution, and output selection |
| `src/config.py` | Default detection settings and custom configuration validation |
| `src/parser.py` | CSV/JSON authentication parsing, event validation, and disabled-account loading |
| `src/detector.py` | Detection rules and multi-rule detection engine |
| `src/formatter.py` | Human-readable formatting of rule-specific alert details |
| `src/reporter.py` | Markdown incident reports and structured JSON alert output |
| `tests/` | Unit and integration tests |
| `data/` | Safe synthetic sample authentication datasets |

---

## Installation

Clone the repository and enter the project directory:

```bash
git clone https://github.com/ahmedsaadaoui7/AuthWatch.git
cd AuthWatch
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the project testing dependency:

```bash
python3 -m pip install -r requirements.txt
```

AuthWatch runtime functionality uses Python standard-library modules. `pytest` is included for automated testing.

The project has been developed and tested using Python 3.13.

---

## Usage

### Analyze suspicious CSV sample activity

```bash
python3 main.py data/brute_force_auth_log.csv
```

Example output:

```text
[ALERT] Potential Brute-Force Activity
Rule ID: AUTH-BF-001
Severity: high
Source IP: 10.0.0.50
Username: admin
Failed attempts: 5
First seen: 2026-08-08T09:00:00
Last seen: 2026-08-08T09:00:48
```

### Analyze suspicious JSON sample activity

```bash
python3 main.py data/brute_force_auth_log.json
```

CSV and JSON inputs produce the same internal authentication-event structure before detection.

### Analyze normal activity

```bash
python3 main.py data/normal_auth_log.csv
```

Example:

```text
No suspicious authentication activity detected.
```

### Generate a Markdown incident report

```bash
python3 main.py data/brute_force_auth_log.csv \
  --report reports/brute_force_report.md
```

### Generate structured JSON alert output

```bash
python3 main.py data/brute_force_auth_log.csv \
  --json-output reports/alerts.json
```

### Generate Markdown and JSON outputs together

```bash
python3 main.py data/brute_force_auth_log.csv \
  --report reports/brute_force_report.md \
  --json-output reports/alerts.json
```

### Use a custom detection configuration

Create a JSON configuration file such as `detection_config.json`, then run:

```bash
python3 main.py data/brute_force_auth_log.csv \
  --config detection_config.json
```

### Supply disabled-account context

```bash
python3 main.py data/brute_force_auth_log.csv \
  --disabled-accounts disabled_accounts.txt
```

### Combine optional inputs and outputs

```bash
python3 main.py data/brute_force_auth_log.json \
  --config detection_config.json \
  --disabled-accounts disabled_accounts.txt \
  --report reports/incident.md \
  --json-output reports/alerts.json
```

### View command-line help

```bash
python3 main.py --help
```

---

## Markdown Incident Report

The Markdown reporter provides a readable SOC-style summary followed by individual alert details.

Example:

```markdown
# AuthWatch Incident Report

## Detection Summary

- Total alerts: 1
- High severity: 1
- Medium severity: 0

## Alert 1: Potential Brute-Force Activity

- Rule ID: AUTH-BF-001
- Severity: high
- Source IP: 10.0.0.50
- Username: admin
- Failed attempts: 5
- First seen: 2026-08-08T09:00:00
- Last seen: 2026-08-08T09:00:48
```

The report summary counts high- and medium-severity findings while preserving rule-specific alert details.

---

## Structured JSON Output

The `--json-output` option writes alerts in a machine-readable structure.

Example:

```json
{
    "total_alerts": 1,
    "alerts": [
        {
            "rule_id": "AUTH-BF-001",
            "title": "Potential Brute-Force Activity",
            "severity": "high",
            "first_seen": "2026-08-08T09:00:00",
            "last_seen": "2026-08-08T09:00:48",
            "details": {
                "source_ip": "10.0.0.50",
                "username": "admin",
                "failed_attempts": 5
            }
        }
    ]
}
```

When no suspicious activity is detected, JSON output remains valid:

```json
{
    "total_alerts": 0,
    "alerts": []
}
```

This makes the output suitable for later automation, ingestion, or integration work without changing the core detection logic.

---

## Testing

AuthWatch uses `pytest` for automated unit and integration testing.

Run the complete suite:

```bash
pytest -v
```

The V2 test suite covers areas including:

- Default detection configuration
- Valid custom configuration loading
- Invalid configuration handling
- Brute-force detection
- Password-spraying detection
- Successful-login-after-failures detection
- Disabled-account authentication detection
- One-IP-to-many-accounts detection
- Many-IPs-to-one-account detection
- Threshold behavior
- Sliding time-window behavior
- Exact inclusive time-window boundaries
- Unique username/source-IP counting
- Successful and failed authentication handling
- Multi-rule engine integration
- CSV authentication parsing
- JSON authentication parsing
- Shared event validation
- Invalid timestamps and authentication results
- Missing and non-string required values
- Unsupported log-format rejection
- Disabled-account list loading
- Terminal alert formatting
- Markdown report generation
- Markdown severity summaries
- Structured JSON report generation
- JSON output with zero alerts
- Simultaneous Markdown and JSON output
- JSON input to JSON output
- CLI missing-file handling
- CLI malformed-input handling

Unit tests validate individual components while integration tests verify the complete command-line workflow across multiple AuthWatch modules.

---

## False Positives and Analyst Validation

An AuthWatch alert indicates **potential suspicious activity**, not a confirmed attack.

A SOC analyst should investigate surrounding context before determining whether an alert is malicious.

### Brute Force

Potential legitimate causes include:

- A user repeatedly entering an incorrect password
- Applications using stale stored credentials
- Misconfigured services
- Automated processes using expired credentials

### Password Spraying

Potential legitimate causes include:

- Administrative testing
- Authentication traffic concentrated behind NAT, proxies, VPNs, or shared gateways
- Security testing inside an authorized lab
- Misconfigured automation attempting several accounts

### Successful Login After Repeated Failures

Potential legitimate causes include:

- A user eventually entering the correct password
- Password-reset activity
- Temporary authentication or synchronization issues
- Legitimate troubleshooting

### Disabled-Account Authentication

Potential legitimate causes include:

- Stale service configuration
- Scheduled tasks using an old account
- Delayed account deprovisioning
- Old stored credentials that were not removed

A successful authentication to an account expected to be disabled should receive particularly careful investigation.

### One Source IP Accessing Multiple Accounts

Potential legitimate causes include:

- Shared gateways
- Administrative jump hosts
- Central authentication infrastructure
- Authorized account-management or testing activity

### One Account Accessed From Multiple Source IPs

Potential legitimate causes include:

- VPN address changes
- Mobile or roaming users
- Shared or distributed infrastructure
- Proxy or network-address translation behavior

Alert thresholds should be tuned to the environment being monitored. A threshold appropriate for a small lab may be too sensitive or too permissive in a larger environment.

---

## V2 Limitations

AuthWatch V2 is intentionally focused on normalized authentication-event analysis.

It does not currently provide:

- Direct Windows Event Log ingestion
- Direct Linux authentication-log ingestion
- Sysmon ingestion or correlation
- Endpoint or process telemetry correlation
- Real-time monitoring
- Persistent databases
- Dashboards
- Threat-intelligence integration
- Case management
- User accounts or RBAC
- Advanced incident correlation
- Production SIEM integration
- Production deployment hardening
- AI or machine-learning detection

These limitations are intentional. V2 establishes a tested multi-rule detection foundation before V3 introduces more realistic security telemetry and investigation workflows.

---

## Security and Data

The repository uses only synthetic or sanitized authentication data.

Do not use or publish:

- Real credentials
- Passwords
- Access tokens
- API keys
- Private customer data
- Personally identifiable authentication logs
- Sensitive internal infrastructure information
- TryHackMe or Hack The Box flags, credentials, or restricted content
- Exam questions or restricted certification material
- Data from systems without explicit authorization

AuthWatch is intended for defensive learning, owned lab environments, sanitized datasets, and explicitly authorized security work.

---

## Development Principles

AuthWatch development follows several project principles:

- Build one version at a time
- Prefer quality and understanding over speed
- Keep detection logic explainable
- Validate behavior with automated tests
- Use meaningful Git commits and version history
- Keep development changes local until a version is professionally complete
- Use only safe synthetic or sanitized data
- Document detection methodology and limitations
- Treat false positives as an expected part of detection engineering
- Avoid unnecessary complexity
- Do not add AI merely for appearance or portfolio value

---

## Version Roadmap

### V1 — Authentication Log Analyzer

CSV authentication analysis, brute-force detection, terminal alerts, Markdown reporting, validation, automated tests, and the initial project architecture.

### V2 — Multi-Rule Detection Engine

Expanded authentication detections, configurable thresholds and windows, disabled-account context, CSV/JSON input, structured JSON output, improved validation, and richer reporting.

### V3 — Realistic Security Log Investigation

Windows, Linux, Sysmon, event correlation, timelines, ATT&CK mapping, and investigation workflows.

### V4 — Local SOC Dashboard

Visual analysis, alert investigation, case management, and report workflows.

### V5 — Secure Multi-User SOC Application

Authentication, RBAC, audit logging, analyst workflows, and application security.

### V6 — Final Portfolio Edition

Polished deployment, multiple telemetry sources, modular detection, investigation capabilities, documentation, and professional presentation.

---

## License

See the `LICENSE` file for licensing information.

---

## Project Status

**AuthWatch V2 — Multi-Rule Detection Engine**

The current version focuses on building a reliable, explainable, and testable authentication-detection foundation before expanding into realistic operating-system telemetry and broader SOC investigation workflows in V3.
