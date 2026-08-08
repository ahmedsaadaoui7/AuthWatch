# AuthWatch

AuthWatch is a defensive cybersecurity project for detecting suspicious authentication activity and supporting basic SOC investigation workflows.

Version 1 focuses on analyzing synthetic CSV authentication logs and detecting potential brute-force attacks using a configurable threshold and time window.

The project is designed to evolve gradually into a larger authentication threat detection and SOC investigation platform while maintaining clear architecture, automated testing, documentation, and version history.

---

## Current Version

**V1 — Authentication Log Analyzer**

V1 provides a complete command-line workflow:

```text
Authentication CSV
        ↓
      Parser
        ↓
 Event Validation
        ↓
 Brute-Force Detector
        ↓
      Alerts
      ↙   ↘
 Terminal   Markdown Report
```

---

## Features

- Parse authentication events from CSV files
- Validate required CSV fields
- Validate authentication event values
- Validate ISO-format timestamps
- Detect potential brute-force authentication activity
- Group activity by source IP and username
- Apply a sliding time-window detection rule
- Display alerts in the terminal
- Generate Markdown incident reports
- Handle missing or malformed input cleanly
- Return appropriate command-line exit codes
- Synthetic normal and malicious sample datasets
- Automated unit and integration tests

---

## V1 Detection Rule

AuthWatch V1 generates a potential brute-force alert when:

- The same source IP
- Targets the same username
- Produces at least 5 failed authentication attempts
- Within a 60-second window

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

The 60-second boundary is inclusive.

For example, five failures occurring between `09:00:00` and `09:01:00` meet the V1 detection condition.

---

## Detection Methodology

Authentication events are first parsed and validated.

The detector sorts events chronologically and tracks failed authentication attempts independently for each:

```text
(source_ip, username)
```

A sliding window keeps only failures that remain inside the configured detection period.

When the number of failures for the same source IP and username reaches the configured threshold, AuthWatch creates an alert.

Successful authentication events do not contribute to the brute-force failure count.

V1 defaults:

```text
Threshold:    5 failed attempts
Time window:  60 seconds
```

These values are currently defaults inside the detection function. More extensive rule configuration belongs to a later AuthWatch version.

---

## Authentication Log Format

V1 expects CSV input with the following fields:

```csv
timestamp,username,source_ip,result
```

Example:

```csv
2026-08-08T09:00:00,admin,10.0.0.50,failure
2026-08-08T09:00:12,admin,10.0.0.50,failure
2026-08-08T09:00:24,admin,10.0.0.50,failure
2026-08-08T09:00:36,admin,10.0.0.50,failure
2026-08-08T09:00:48,admin,10.0.0.50,failure
```

### Required Fields

| Field | Description |
|---|---|
| `timestamp` | Time of the authentication event in ISO format |
| `username` | Account involved in the authentication attempt |
| `source_ip` | Source of the authentication attempt |
| `result` | Authentication result: `success` or `failure` |

AuthWatch rejects input when:

- Required columns are missing
- Required values are empty
- The authentication result is invalid
- The timestamp cannot be parsed

---

## Project Structure

```text
authwatch/
├── data/
│   ├── normal_auth_log.csv
│   └── brute_force_auth_log.csv
│
├── reports/
│   └── brute_force_report.md
│
├── src/
│   ├── __init__.py
│   ├── parser.py
│   ├── detector.py
│   └── reporter.py
│
├── tests/
│   ├── test_parser.py
│   ├── test_detector.py
│   ├── test_reporter.py
│   └── test_main.py
│
├── main.py
├── pytest.ini
├── requirements.txt
├── .gitignore
├── CHANGELOG.md
├── LICENSE
└── README.md
```

### Component Responsibilities

**`parser.py`**

Loads CSV authentication events and validates input before events reach the detection engine.

**`detector.py`**

Contains the V1 brute-force detection logic and sliding-window processing.

**`reporter.py`**

Converts generated alerts into a Markdown incident report.

**`main.py`**

Acts as the command-line entry point and orchestration layer connecting the parser, detector, terminal output, and reporter.

**`tests/`**

Contains automated tests for individual components and complete CLI workflows.

---

## Installation

Clone the repository and enter the project directory:

```bash
git clone https://github.com/ahmedsaadaoui7/AuthWatch.git
cd authwatch
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

AuthWatch V1 uses only Python standard-library modules for its runtime functionality. `pytest` is included for automated testing.

The project has been developed and tested using Python 3.13.

---

## Usage

### Analyze suspicious sample activity

```bash
python3 main.py data/brute_force_auth_log.csv
```

Example output:

```text
[ALERT] Potential brute-force activity detected
Source IP: 10.0.0.50
Username: admin
Failed attempts: 5
First failure: 2026-08-08T09:00:00
Last failure: 2026-08-08T09:00:48
```

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

AuthWatch will perform the analysis and write the generated report to the requested location.

### View command-line help

```bash
python3 main.py --help
```

---

## Incident Report

A generated V1 report contains:

- Number of generated alerts
- Source IP
- Target username
- Number of failed attempts
- First observed failure
- Last observed failure

Example:

```markdown
# AuthWatch Incident Report

## Detection Summary

Total alerts: 1

## Alert 1: Potential Brute-Force Activity

- Source IP: 10.0.0.50
- Username: admin
- Failed attempts: 5
- First failure: 2026-08-08T09:00:00
- Last failure: 2026-08-08T09:00:48
```

---

## Testing

AuthWatch uses `pytest` for automated testing.

Run the complete test suite:

```bash
pytest -v
```

The V1 tests cover areas including:

- Valid CSV parsing
- Missing required CSV columns
- Empty required values
- Invalid authentication results
- Invalid timestamps
- Known brute-force activity
- Normal authentication activity
- Events outside the detection time window
- Separation of different usernames
- Separation of different source IPs
- Exact time-window boundary behavior
- Markdown report generation
- CLI malicious-log analysis
- CLI normal-log analysis
- CLI report generation
- Missing-file handling
- Invalid-log handling

Unit tests validate individual components, while integration tests verify that the command-line workflow works correctly across multiple AuthWatch modules.

---

## False Positives

An AuthWatch alert indicates **potential suspicious activity**, not a confirmed attack.

Repeated authentication failures can have legitimate causes, including:

- A user repeatedly entering an incorrect password
- Applications using outdated stored credentials
- Misconfigured services
- Automated processes using expired credentials
- Administrative or testing activity

A SOC analyst should investigate surrounding context before determining whether an alert represents malicious activity.

---

## V1 Limitations

AuthWatch V1 is intentionally limited in scope.

It does not currently provide:

- Password-spraying detection
- Multiple detection-rule types
- Windows Event Log ingestion
- Linux authentication-log ingestion
- Sysmon correlation
- Real-time monitoring
- Databases
- Dashboards
- Threat-intelligence integration
- Case management
- User accounts or RBAC
- Advanced incident correlation

These limitations are intentional. V1 establishes a small, testable, and documented foundation before more advanced detection capabilities are introduced.

---

## Security and Data

The repository uses only synthetic authentication data.

Do not use or publish:

- Real credentials
- Private organizational logs
- Personal information
- API keys or secrets
- Unauthorized target data
- Restricted lab or training-platform content

AuthWatch is intended for defensive security learning, controlled environments, and systems the user is authorized to analyze.

---

## Development Principles

AuthWatch is developed incrementally with:

- Clear component separation
- Automated testing
- Meaningful Git commits
- Versioned releases
- Documentation
- Safe synthetic data
- Detection methodology documentation
- False-positive analysis

Each major AuthWatch version is developed in the same repository so the project's evolution remains visible through Git history, tags, and releases.

---

## Version Roadmap

### V1 — Authentication Log Analyzer

CSV authentication analysis and brute-force detection.

### V2 — Multi-Rule Detection Engine

Expanded authentication detections, configurable rules, structured input/output, and improved validation.

### V3 — Realistic Security Log Investigation

Windows, Linux, Sysmon, event correlation, timelines, and investigation workflows.

### V4 — Local SOC Dashboard

Visual analysis, alert investigation, case management, and report workflows.

### V5 — Secure Multi-User SOC Application

Authentication, RBAC, audit logging, analyst workflows, and application security.

### V6 — Final Portfolio Edition

Polished deployment, multiple telemetry sources, modular detection, investigation capabilities, documentation, and presentation.

---

## License

See the `LICENSE` file for licensing information.

---

## Project Status

**AuthWatch V1 — Release preparation**
