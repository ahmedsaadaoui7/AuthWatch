# AuthWatch

AuthWatch is a defensive cybersecurity project for detecting suspicious authentication activity, correlating endpoint telemetry, and supporting structured SOC investigation workflows.

Version 4 builds a local desktop SOC workspace on top of the validated V3 telemetry, detection, correlation, timeline, MITRE ATT&CK, and reporting engine. The application keeps the analysis engine explainable while adding persistent investigations, findings, supporting evidence, analyst review, case management, and application settings.

AuthWatch remains an offline, analyst-driven tool. Telemetry is explicitly selected by the analyst and processed locally; V4 does not add automatic endpoint collection, continuous monitoring, cloud processing, or multi-user authentication.

The project is designed to evolve gradually while maintaining clear architecture, deterministic analysis, automated testing, professional documentation, safe synthetic or sanitized data, and meaningful version history.

---

## Current Version

**V4 — Local SOC Dashboard + Case Management**

AuthWatch V4 provides a local desktop investigation workflow built on the V3 engine:

```text
V2 Authentication CSV / JSON ─┐
Windows Security EVTX ─────────┤
Sysmon EVTX ───────────────────┼──> V3 Analysis Engine
Linux Authentication Logs ─────┘          |
                                           v
                                  Detection + Correlation
                                           |
                                           v
                                 Persistent Investigation
                                           |
                      ┌────────────────────┼────────────────────┐
                      v                    v                    v
                  Findings              Timeline          SOC Dashboard
                      |                                         |
                      v                                         v
             Supporting Evidence                         Analyst Workflow
                      |
                      v
               Case Management
                      |
          Notes + Activity History
```

The V4 desktop application includes:

- Local PySide6 / Qt Quick desktop interface
- SQLite persistence through SQLAlchemy and Alembic
- Security-operations dashboard with finding and case metrics
- Analyst-driven telemetry analysis using the existing V3 engine
- Persistent investigations and chronological event timelines
- Findings queue with severity filtering, analyst review status, and supporting evidence
- Finding-to-case escalation
- Case priority, status, resolution, notes, linked findings, and activity history
- Investigation Markdown/JSON export
- Persistent application settings for supported V4 behavior
- Safe analysis-worker lifecycle and shutdown handling

V4 is currently in final release validation. The complete automated suite passes on Kali Linux; Windows V4 compatibility validation is the remaining platform gate before release.

---

## Features

### V4 Desktop SOC Workspace

- Run the AuthWatch V3 engine from a local desktop application
- Review total, high-severity, medium-severity, and active-case metrics
- Inspect recent high-severity findings and affected users, hosts, and source IPs
- Persist investigations, normalized events, findings, evidence links, cases, notes, and activities in SQLite
- Review investigation context, telemetry sources, affected entities, findings, and chronological timelines
- Filter the findings queue by severity and search by title or rule ID
- Mark findings reviewed without losing escalation state
- Preserve supporting events for normal detections and correlations
- Escalate findings into analyst cases
- Track case priority, status, resolution, notes, linked findings, and activity history
- Close and reopen cases while preserving historical activity
- Export persisted investigations to Markdown or JSON
- Persist supported application settings locally
- Prevent concurrent duplicate analysis runs and handle active-worker shutdown safely

### V3 Engine Foundation

The V4 desktop workflow preserves the V3 analytical capabilities documented below.

#### Telemetry and Input

- Parse V2-compatible authentication events from CSV and JSON
- Read saved Windows Security EVTX telemetry
- Read saved Sysmon EVTX telemetry
- Parse supported Linux authentication-log entries
- Support Windows Security events `4624`, `4625`, `4648`, and `4672`
- Support Sysmon events `1`, `3`, `11`, `13`, and `22`
- Normalize Windows, Sysmon, Linux, and legacy authentication telemetry into a common event model
- Normalize traditional Linux timestamps to UTC using analyst-supplied year and UTC-offset context
- Validate supported telemetry and reject malformed or unsupported input cleanly
- Combine multiple telemetry sources into a single V3 investigation

#### Detection

- Detect potential brute-force activity
- Detect potential password spraying
- Detect successful login after repeated failures
- Detect authentication attempts against disabled accounts
- Detect one source IP accessing many accounts
- Detect one account being accessed from many source IPs
- Apply configurable detection thresholds and time windows
- Load optional disabled-account context
- Load rule-specific JSON detection configuration
- Assign stable rule IDs and severity levels

#### Correlation and Investigation

- Correlate successful authentication with process activity
- Correlate privileged logon with process activity
- Correlate process creation with network activity
- Correlate process creation with DNS activity
- Correlate Linux SSH login with subsequent sudo execution
- Use strong identifiers such as session IDs and ProcessGuids where available
- Apply configurable correlation windows
- Preserve related source events as supporting evidence
- Build chronological investigation timelines
- Identify affected users, hosts, and IP addresses
- Attach predefined MITRE ATT&CK mappings only where observed evidence supports them

#### Reporting and CLI

- Display detections and correlations in the terminal
- Generate V3 Markdown investigation reports
- Generate structured V3 JSON investigation output
- Generate Markdown and JSON outputs from the same analysis
- Produce valid V3 investigation reports when zero findings are present
- Preserve V2 command-line compatibility for authentication-only analysis
- Support mixed telemetry sources in a single V3 investigation
- Return appropriate command-line exit codes
- Handle missing files, malformed input, and invalid configuration cleanly

#### Quality and Safety

- Use only synthetic, sanitized, or explicitly authorized telemetry in the repository
- Keep real EVTX telemetry out of version control
- Provide automated unit, integration, CLI, regression, and scenario-dataset tests
- Validate false-positive conditions and exact time-window boundaries
- Produce deterministic Markdown and JSON investigation results for identical input and configuration

---

## Detection Rules

AuthWatch V3 preserves the six authentication-focused detection rules introduced by V2.

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

## Correlation Rules

AuthWatch V3 adds five deterministic event-correlation rules.

| Correlation ID | Relationship |
|---|---|
| `CORR-AUTH-EXEC-001` | Successful Authentication → Process Activity |
| `CORR-PRIV-EXEC-001` | Privileged Logon → Process Activity |
| `CORR-PROC-NET-001` | Process Creation → Network Activity |
| `CORR-PROC-DNS-001` | Process Creation → DNS Activity |
| `CORR-SSH-SUDO-001` | Linux SSH Login → Privileged Execution |

### `CORR-AUTH-EXEC-001` — Authentication to Process Activity

Connects a successful authentication event to process creation when the host and session identifier match and the process activity occurs within the configured correlation window.

### `CORR-PRIV-EXEC-001` — Privileged Logon to Process Activity

Connects privileged Windows logon activity to process creation when the host and session identifier match and the process activity occurs within the configured correlation window.

### `CORR-PROC-NET-001` — Process to Network Activity

Connects process creation to subsequent network activity when the host and ProcessGuid match and the network event occurs within the configured correlation window.

### `CORR-PROC-DNS-001` — Process to DNS Activity

Connects process creation to subsequent DNS activity when the host and ProcessGuid match and the DNS event occurs within the configured correlation window.

### `CORR-SSH-SUDO-001` — SSH Login to Privileged Execution

Connects a successful Linux SSH login to subsequent sudo execution when the host and username match and the sudo event occurs within the configured correlation window.

If multiple valid SSH logins are available, AuthWatch uses the most recent valid login before the sudo event.

Correlation does not automatically prove compromise. It connects evidence that belongs to the same investigation story so an analyst can evaluate the activity in context.

The default correlation window is 300 seconds and the exact boundary is inclusive.

---

## Detection and Correlation Methodology

Authentication events are parsed into a shared internal structure and validated before detection begins.

For time-window detection rules, AuthWatch sorts events chronologically and maintains rule-specific sliding windows. Events that fall outside the configured window are removed before the current detection condition is evaluated.

Different detection rules group activity differently depending on the behavior being detected:

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

The V3 correlation layer then evaluates normalized telemetry using source-specific evidence.

Stronger identifiers are preferred where they exist:

```text
Windows authentication/process relationships -> host + session_id
Sysmon process/network/DNS relationships      -> host + ProcessGuid
Linux SSH/sudo relationships                  -> host + username + time
```

The V3 investigation flow is:

```text
Observed telemetry
      ↓
Normalization
      ↓
Detection
      ↓
Correlation
      ↓
Timeline
      ↓
MITRE ATT&CK mapping
      ↓
Analyst investigation report
```

AuthWatch distinguishes these concepts deliberately:

- **Detection** finds suspicious behavior.
- **Correlation** connects related events.
- **Timeline** orders evidence into an investigation story.
- **MITRE ATT&CK mapping** labels supported observed behavior using a standard technique name.
- **Supporting evidence** preserves the data used to justify detections and correlations.

---

## Normalized Event Model

V3 converts supported telemetry sources into a common event structure before cross-source analysis.

The normalized model contains fields such as:

```json
{
    "timestamp": "2026-09-08T19:00:00Z",
    "source": "windows_security",
    "event_id": "4624",
    "event_type": "authentication_success",
    "host": "WIN-CLIENT01",
    "username": "alice",
    "session_id": "0x1234",
    "source_ip": "10.0.0.20",
    "destination_ip": null,
    "process_name": null,
    "process_id": null,
    "process_guid": null,
    "parent_process_name": null,
    "command_line": null,
    "result": "success",
    "details": {}
}
```

Supported normalized event types include:

```text
authentication_failure
authentication_success
explicit_credentials
privileged_logon
process_creation
network_connection
file_creation
registry_modification
dns_query
sudo_execution
session_activity
```

---

## MITRE ATT&CK Mapping

AuthWatch V3 uses predefined, evidence-based ATT&CK mappings only where the observed behavior supports them.

Current mappings:

| AuthWatch Rule | MITRE ATT&CK |
|---|---|
| `AUTH-BF-001` | `T1110` — Brute Force |
| `AUTH-PS-001` | `T1110.003` — Password Spraying |

AuthWatch does not force a MITRE mapping onto every detection or correlation.

A missing mapping means the available evidence is not strong enough for the project to make that specific ATT&CK claim.

---

## Detection and Correlation Configuration

AuthWatch V3 centralizes configurable detection and correlation defaults in `src/config.py`.

### Detection Configuration

Default detection configuration:

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

`AUTH-DA-001` is not threshold-based and therefore is not included in the configurable threshold/window defaults.

### Correlation Configuration

Default correlation configuration:

```json
{
    "CORR-PROC-NET-001": {
        "window_seconds": 300
    },
    "CORR-PROC-DNS-001": {
        "window_seconds": 300
    },
    "CORR-AUTH-EXEC-001": {
        "window_seconds": 300
    },
    "CORR-PRIV-EXEC-001": {
        "window_seconds": 300
    },
    "CORR-SSH-SUDO-001": {
        "window_seconds": 300
    }
}
```

Partial overrides are supported. AuthWatch validates configuration files and rejects unsupported rule IDs, unknown settings, malformed structures, non-positive values, incorrect value types, and invalid JSON.

---

## Telemetry Input Formats

AuthWatch V3 supports multiple offline telemetry sources. The analyst explicitly provides the files to analyze; AuthWatch does not automatically discover or collect operating-system logs.

### V2-Compatible Authentication CSV / JSON

The original authentication-event format remains supported for backward compatibility.

Supported file extensions:

```text
.csv
.json
```

Authentication events must provide the fields required by the detection engine, including:

| Field | Description |
|---|---|
| `timestamp` | Authentication event time in ISO format |
| `username` | Account involved in the authentication attempt |
| `source_ip` | Source IP address |
| `result` | Authentication result such as `success` or `failure` |

### Windows Security EVTX

Supported Windows Security event IDs:

| Event ID | Meaning |
|---|---|
| `4624` | Successful logon |
| `4625` | Failed logon |
| `4648` | Logon using explicit credentials |
| `4672` | Special privileges assigned to a new logon |

Example:

```bash
python main.py --windows-security Security.evtx
```

### Sysmon EVTX

Supported Sysmon event IDs:

| Event ID | Meaning |
|---|---|
| `1` | Process creation |
| `3` | Network connection |
| `11` | File creation |
| `13` | Registry value modification |
| `22` | DNS query |

Example:

```bash
python main.py --sysmon Sysmon.evtx
```

### Linux Authentication Logs

Supported Linux activity includes:

- Failed SSH authentication
- Successful SSH authentication
- SSH password/public-key authentication
- sudo execution
- SSH session open activity
- SSH session close activity

Example:

```bash
python main.py     --linux-auth auth.log     --linux-year 2026     --linux-utc-offset +01:00
```

Traditional Linux authentication logs may omit the year and timezone. AuthWatch therefore requires `--linux-year` and `--linux-utc-offset` with `--linux-auth` and converts the timestamp to UTC.

AuthWatch does not guess missing year or timezone information.

### Mixed Telemetry Analysis

Multiple telemetry sources can be supplied in the same V3 investigation.

```bash
python main.py     --windows-security Security.evtx     --sysmon Sysmon.evtx     --linux-auth auth.log     --linux-year 2026     --linux-utc-offset +01:00     --report investigation.md     --json-output investigation.json
```

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

```bash
python main.py data/brute_force_auth_log.csv     --disabled-accounts disabled_accounts.txt
```

The file should contain only safe synthetic or sanitized usernames when used in this repository.

---

## Project Structure

```text
authwatch/
├── data/
│   ├── brute_force_auth_log.csv
│   ├── brute_force_auth_log.json
│   ├── normal_auth_log.csv
│   └── v3/
│       ├── README.md
│       ├── boundaries/
│       ├── correlations/
│       ├── detections/
│       ├── false_positives/
│       ├── invalid/
│       ├── normal/
│       └── zero_results/
├── reports/
├── src/
│   ├── parsers/
│   │   ├── __init__.py
│   │   ├── evtx_reader.py
│   │   ├── linux_auth.py
│   │   ├── sysmon.py
│   │   └── windows_security.py
│   ├── config.py
│   ├── correlation.py
│   ├── detector.py
│   ├── formatter.py
│   ├── mitre.py
│   ├── normalizer.py
│   ├── parser.py
│   ├── reporter.py
│   └── timeline.py
├── tests/
│   ├── test_config.py
│   ├── test_correlation.py
│   ├── test_detector.py
│   ├── test_formatter.py
│   ├── test_linux_auth_parser.py
│   ├── test_main.py
│   ├── test_mitre.py
│   ├── test_normalizer.py
│   ├── test_parser.py
│   ├── test_reporter.py
│   ├── test_sysmon_parser.py
│   ├── test_timeline.py
│   ├── test_v3_datasets.py
│   └── test_windows_security_parser.py
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
| `src/app.py` | V4 desktop application bootstrap, database/session lifecycle, ViewModel wiring, QML loading, and safe shutdown |
| `src/analysis_engine.py` | Shared orchestration adapter that exposes the V3 engine to the V4 application layer |
| `src/services/` | V4 application workflows for analysis persistence, dashboard data, findings, investigations, cases, and settings |
| `src/repositories/` | SQLAlchemy persistence queries for V4 desktop data |
| `src/viewmodels/` | PySide6 QObject/ViewModel bridge between services and QML |
| `src/models/` | SQLAlchemy models for investigations, telemetry sources, events, findings, evidence links, cases, notes, activities, and settings |
| `qml/` | Qt Quick desktop shell, reusable components, and V4 SOC pages |
| `main.py` | CLI argument handling, multi-source orchestration, detection/correlation execution, enrichment, and output selection |
| `src/config.py` | Detection/correlation defaults and custom configuration validation |
| `src/parser.py` | V2 CSV/JSON authentication parsing, shared validation, and disabled-account loading |
| `src/parsers/evtx_reader.py` | Saved EVTX record iteration using `python-evtx` |
| `src/parsers/windows_security.py` | Windows Security event parsing |
| `src/parsers/sysmon.py` | Sysmon event parsing |
| `src/parsers/linux_auth.py` | Linux authentication-log parsing |
| `src/normalizer.py` | Cross-source normalization and Linux UTC timestamp normalization |
| `src/detector.py` | Authentication detection rules and detection engine |
| `src/correlation.py` | V3 event-correlation rules and correlation engine |
| `src/timeline.py` | Chronological investigation timeline construction |
| `src/mitre.py` | Evidence-based MITRE ATT&CK mapping |
| `src/formatter.py` | Human-readable detection-detail formatting |
| `src/reporter.py` | V2 reports plus V3 Markdown/JSON investigation reporting |
| `tests/` | Unit, integration, CLI, regression, and scenario-dataset tests |
| `data/v3/` | Safe reusable V3 validation scenarios |

---

## Installation

Clone the repository and enter the project directory:

```bash
git clone https://github.com/ahmedsaadaoui7/AuthWatch.git
cd AuthWatch
```

Create a virtual environment.

Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Windows PowerShell:

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

V3 EVTX support uses `python-evtx`. V4 desktop persistence uses SQLAlchemy and Alembic, and the desktop interface uses PySide6 / Qt Quick. Automated tests use `pytest`.

The current V4 Kali development environment uses Python 3.13.

---

## Usage

### V4 Desktop Application

Start the local SOC desktop application from the project virtual environment:

```bash
python -m src.app
```

The desktop workflow provides Dashboard, Analyze, Findings, Investigations, Cases, and Settings pages. Analysis still uses the V3 engine internally, so V3 detection/correlation behavior remains the analytical foundation.

### V3 CLI

View the complete CLI:

```bash
python main.py --help
```

At least one telemetry input is required.

### V2-Compatible Authentication Analysis

```bash
python main.py data/brute_force_auth_log.csv
```

or:

```bash
python main.py data/brute_force_auth_log.json
```

### Windows Security EVTX

```bash
python main.py --windows-security Security.evtx
```

### Sysmon EVTX

```bash
python main.py --sysmon Sysmon.evtx
```

### Linux Authentication Log

```bash
python main.py     --linux-auth auth.log     --linux-year 2026     --linux-utc-offset +01:00
```

### Windows Security + Sysmon Investigation

```bash
python main.py     --windows-security Security.evtx     --sysmon Sysmon.evtx     --report investigation.md     --json-output investigation.json
```

### Mixed Windows + Sysmon + Linux Investigation

```bash
python main.py     --windows-security Security.evtx     --sysmon Sysmon.evtx     --linux-auth auth.log     --linux-year 2026     --linux-utc-offset +01:00     --report investigation.md     --json-output investigation.json
```

### Custom Detection Configuration

```bash
python main.py data/brute_force_auth_log.csv     --config detection_config.json
```

### Custom Correlation Configuration

```bash
python main.py     --sysmon Sysmon.evtx     --correlation-config correlation_config.json
```

### Disabled-Account Context

```bash
python main.py data/brute_force_auth_log.csv     --disabled-accounts disabled_accounts.txt
```

### Zero Findings

In V3 mode, valid telemetry may legitimately produce no detections and no correlations. AuthWatch can still generate Markdown and JSON investigation output showing that analysis completed successfully.

---

## V3 Investigation Reports

V3 Markdown reports contain:

```text
AuthWatch V3 Investigation Report
├── Detection Summary
├── Correlation Summary
├── Affected Entities
├── Related IDs
├── MITRE ATT&CK Mappings
├── Investigation Timeline
├── Supporting Evidence
├── Detections
└── Correlations
```

Supporting evidence preserves the source-event references used by detections and correlations.

For telemetry sources without a Windows/Sysmon-style Event ID, the Markdown report omits a meaningless Event-ID label while structured JSON may preserve the missing field as `null`.

Authentication-only V2-compatible CLI usage continues to use the existing alert-focused reporting behavior.

---

## Structured V3 JSON Output

V3 JSON output contains:

```text
detection_summary
correlation_summary
related_ids
affected_entities
mitre_mappings
supporting_evidence
timeline
detections
correlations
```

This structure distinguishes a valid zero-result investigation from invalid telemetry that could not be analyzed.

---

## Testing

AuthWatch uses `pytest` for automated validation.

Run the complete suite from the project virtual environment:

```bash
python -m pytest -q
```

The current complete V4 suite contains **428 automated tests** passing on Kali Linux.

Coverage includes:

- V2 backward compatibility
- Detection and correlation configuration
- All six authentication detection rules
- Exact inclusive detection boundaries
- Windows Security parsing
- Sysmon parsing
- Linux authentication-log parsing
- Cross-source normalization
- Linux timestamp and UTC-offset validation
- Unsupported telemetry handling
- All five V3 correlation rules
- Session-ID and ProcessGuid matching
- Exact inclusive correlation boundaries
- False-positive rejection
- Timeline construction
- MITRE ATT&CK mapping
- Supporting-evidence preservation
- Markdown and JSON investigation reporting
- V2 and V3 CLI behavior
- Multi-source CLI correlation
- Missing and malformed input handling
- Zero-finding investigations
- V4 database models, migrations, repositories, and service workflows
- Analysis persistence and supporting-evidence links
- Dashboard aggregation and desktop ViewModels
- Investigation selection, context, timeline, and export workflows
- Finding review, evidence loading, related findings, and escalation state
- Case creation, linked findings, priority/status transitions, notes, closure, resolution, reopening, and activity history
- Persistent application settings and validation
- Analysis-worker lifecycle, duplicate-run prevention, exact completed-investigation navigation, and shutdown safety
- Regression behavior across the complete project

### V3 Scenario Dataset Library

`data/v3/` contains **22 reusable synthetic validation scenarios** covering:

- Normal activity
- Every detection rule
- Every correlation rule
- False-positive conditions
- Exact time-window boundaries
- Invalid telemetry
- Successful zero-result investigations

Each dataset documents its expected behavior so automated tests can compare expected findings with actual AuthWatch results.

---

## False Positives and Analyst Validation

An AuthWatch detection or correlation indicates activity that deserves context and investigation. It does not automatically prove an attack or compromise.

Potential legitimate explanations can include:

- User password mistakes
- Stale stored credentials
- Misconfigured services
- Administrative testing
- Shared gateways, NAT, proxies, or VPNs
- Authorized security testing
- Password-reset or synchronization activity
- Administrative jump hosts
- Mobile or roaming users
- Legitimate privileged administration

Correlation is deliberately conservative.

AuthWatch rejects relationships when important evidence does not match, including:

- Different Windows session IDs
- Different Sysmon ProcessGuids
- Different Linux usernames
- Events outside the configured correlation window

Time proximity alone is not treated as sufficient evidence when a stronger identifier is available.

Thresholds and correlation windows should be tuned to the environment being analyzed.

---

## Deterministic Analysis

AuthWatch V3 is designed to produce deterministic results.

For identical telemetry, configuration, and analysis context, AuthWatch should produce stable detection, correlation, Markdown, and JSON results.

V3 validation includes repeated manual analysis confirming byte-for-byte identical Markdown and JSON output for identical input and configuration.

---

## V4 Limitations

AuthWatch V4 is a local, offline SOC investigation application.

It does not currently provide:

- Automatic local log discovery or endpoint collection
- Continuous or real-time monitoring
- Background endpoint agents
- Centralized server deployment
- User accounts, authentication, or RBAC
- Multi-user analyst workflows
- Remote collaboration or synchronization
- Threat-intelligence feeds
- Production SIEM integration
- Production deployment hardening
- AI or machine-learning detection

The SQLite database is local to the workstation. V4 is intended for a single analyst operating on explicitly selected telemetry. Secure multi-user authentication and RBAC remain V5 scope.

These boundaries are intentional. V4 focuses on turning the V3 analysis engine into a professional local SOC investigation and case-management workflow without prematurely adding multi-user or production-platform complexity.

---

## Security and Data

The repository uses only synthetic, sanitized, or explicitly authorized telemetry.

Do not commit or publish:

- Real credentials
- Passwords
- Access tokens
- API keys
- `.env` secrets
- Private customer data
- Personally identifiable authentication logs
- Sensitive internal infrastructure information
- Real Windows Security or Sysmon EVTX files
- TryHackMe or Hack The Box flags, credentials, or restricted content
- Exam questions or restricted certification material
- Data from systems without explicit authorization

Real `.evtx` files are ignored by Git through `.gitignore` and should remain local during testing.

AuthWatch is intended for defensive learning, owned lab environments, sanitized datasets, and explicitly authorized security work.

---

## Development Principles

AuthWatch development follows several project principles:

- Build one version at a time
- Prefer quality and understanding over speed
- Keep detection and correlation logic explainable
- Separate observed evidence from analyst conclusions
- Prefer strong identifiers over weak time-only relationships where available
- Validate behavior with automated tests
- Validate realistic scenarios with reusable synthetic datasets
- Use meaningful Git commits and version history
- Keep development changes local until a version is professionally complete
- Use only safe synthetic, sanitized, or explicitly authorized data
- Document methodology, false positives, and limitations
- Treat correlation as supporting evidence rather than automatic proof of compromise
- Avoid unnecessary complexity
- Do not add AI merely for appearance or portfolio value

---

## Version Roadmap

### V1 — Authentication Log Analyzer

CSV authentication analysis, brute-force detection, terminal alerts, Markdown reporting, validation, automated tests, and the initial project architecture.

**Status:** Complete.

### V2 — Multi-Rule Detection Engine

Expanded authentication detections, configurable thresholds and windows, disabled-account context, CSV/JSON input, structured JSON output, improved validation, and richer reporting.

**Status:** Complete and released as `v2.0.0`.

### V3 — Endpoint Telemetry & Event Correlation

Windows Security EVTX, Sysmon EVTX, Linux authentication logs, cross-source normalization, authentication detection, event correlation, timelines, evidence-based MITRE ATT&CK mapping, supporting evidence, and professional investigation reports.

**Status:** AuthWatch v3.0.0 release state. Implementation, automated validation, Kali release validation, and Windows compatibility validation are complete.

### V4 — Local SOC Dashboard + Case Management

A local SOC investigation workspace built on the V3 engine, including dashboard metrics, telemetry analysis, persistent investigations, visual findings/evidence review, timelines, filtering, investigation export, analyst notes, case-management workflows, and persistent application settings.

**Status:** Release candidate. Implementation and the 428-test Kali validation suite are complete. Final Windows V4 compatibility validation remains before the `v4.0.0` release.

### V5 — Secure Multi-User SOC Application

Secure application authentication, accounts, RBAC, permissions, analyst workflows, audit/security controls, and multi-user operation.

### V6 — Final Professional Portfolio Edition

Final UX/UI polish, security hardening, refactoring where needed, performance review, deployment/setup quality, complete validation, professional architecture documentation, demonstration material, and final portfolio presentation.

---

## License

See the `LICENSE` file for licensing information.

---

## Project Status

**AuthWatch V4 — Local SOC Dashboard + Case Management**

V4 implementation and automated validation are complete on Kali Linux.

Current validation status:

```text
Automated test suite             428/428 passing on Kali Linux
V3 scenario dataset suite        Complete
V3 CLI compatibility             Passing
V4 desktop launch                Passing on Kali Linux
Dashboard workflow               Passing
Analysis persistence             Passing
Investigation timeline/context   Passing
Finding review/evidence          Passing
Case management workflow         Passing
Persistent settings              Passing
Investigation export             Passing
Repository diff check            Passing
Windows V4 validation            Pending
Documentation review             In progress
```

The V4 feature set is implemented and locally validated. The remaining release gates are final documentation review and Windows desktop compatibility validation before tagging `v4.0.0`.
