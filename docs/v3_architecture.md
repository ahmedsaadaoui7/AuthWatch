# AuthWatch V3 Architecture

## Version

AuthWatch v3.0.0 — Endpoint Telemetry & Event Correlation

## Purpose

AuthWatch V3 expands the V2 authentication-focused detection engine into a broader SOC-oriented telemetry analysis and event correlation platform.

V3 will ingest realistic Windows Security, Sysmon, and Linux telemetry, normalize different log formats into a common internal event model, detect suspicious activity, correlate related events, reconstruct investigation timelines, map relevant evidence to MITRE ATT&CK, and generate structured investigation reports.

## Core Objectives

- Support realistic Windows Security telemetry.
- Support Sysmon endpoint telemetry.
- Support Linux authentication and system telemetry.
- Normalize different log sources into a common event structure.
- Preserve useful original event context for investigation.
- Detect suspicious authentication and endpoint activity.
- Correlate related events across time, users, hosts, IP addresses, and processes.
- Build chronological investigation timelines.
- Map supported detections and correlations to relevant MITRE ATT&CK techniques.
- Produce professional Markdown and JSON investigation output.
- Maintain clear validation, explainable logic, and automated testing.
- Remain compatible with both Linux and Windows execution environments.

## Development Environment

V3 development, testing, and refinement will be performed on Kali Linux.

Windows Security and Sysmon telemetry will be exported from the separate Windows installation and transferred to Kali for analysis.

Direct execution on Windows will be tested only after V3 has been fully completed and validated on Kali.

## Non-Goals for V3

V3 will not include:

- Web dashboard or graphical SOC interface.
- Case-management UI.
- User authentication.
- Role-based access control.
- Multi-user functionality.
- AI-based detection or analysis.

These capabilities belong to later AuthWatch versions.

## Telemetry Sources

V3 will initially support a focused set of security-relevant telemetry. The goal is not to parse every operating-system event, but to support enough realistic data to perform useful SOC investigation and event correlation.

### Windows Security Events

Initial Windows Security support will focus on:

- Event ID 4624 — Successful logon.
- Event ID 4625 — Failed logon.
- Event ID 4648 — Logon attempt using explicit credentials.
- Event ID 4672 — Special privileges assigned to a new logon.

These events provide the main Windows authentication and privilege context required for V3 correlation.

### Sysmon Events

Initial Sysmon support will focus on:

- Event ID 1 — Process creation.
- Event ID 3 — Network connection.
- Event ID 11 — File creation.
- Event ID 13 — Registry value modification.
- Event ID 22 — DNS query.

Sysmon provides endpoint context that can be correlated with authentication activity, including processes, network activity, file activity, registry changes, and DNS requests.

### Linux Telemetry

Initial Linux support will focus on security-relevant authentication and system activity, including:

- Failed SSH authentication.
- Successful SSH authentication.
- sudo command execution.
- User/session activity when available.
- Relevant authentication events from common Linux authentication logs or exported journal data.

Linux telemetry will be parsed from saved log files rather than requiring AuthWatch to directly monitor the operating system.

## V3 Telemetry Principle

V3 will use a focused-parser approach.

Each supported telemetry source will have a parser responsible for extracting security-relevant fields from the original event.

Unsupported events may be ignored or preserved as unsupported/raw data depending on the parser design, but they must not cause the entire analysis to fail unnecessarily.

The initial V3 scope favors reliable support for a smaller set of useful events over incomplete support for many event types.

## Normalized Event Model

All supported telemetry will be converted into a common internal event structure before detection and correlation.

The normalized model allows AuthWatch to analyze events consistently without requiring correlation logic to understand every original log format.

A normalized event will conceptually contain:

```python
{
    "timestamp": "...",
    "source": "...",
    "event_id": "...",
    "event_type": "...",
    "host": "...",
    "username": "...",
    "session_id": "...",
    "source_ip": "...",
    "destination_ip": "...",
    "process_name": "...",
    "process_id": "...",
    "process_guid": "...",
    "parent_process_name": "...",
    "command_line": "...",
    "result": "...",
    "details": {...},
}
```

### Core Fields

- `timestamp` — normalized event time.
- `source` — telemetry source such as `windows_security`, `sysmon`, or `linux_auth`.
- `event_id` — original event identifier when available, such as Windows `4625` or Sysmon `1`.
- `event_type` — normalized description of what occurred.
- `host` — system where the event occurred.
- `username` — associated account when available.
- `session_id` — authentication or logon session identifier when available, such as a Windows Logon ID.
- `source_ip` — originating IP address when available.
- `destination_ip` — destination IP address when relevant.
- `process_name` — process involved in the event when relevant.
- `process_id` — process identifier when available.
- `process_guid` — stable process identifier when available, especially from Sysmon, used to correlate process activity with related events.
- `parent_process_name` — parent process when available.
- `command_line` — executed command line when available.
- `result` — normalized outcome such as `success` or `failure` when relevant.
- `details` — additional source-specific evidence that does not belong in the common fields.

Fields that are not relevant to a particular event may contain `None`.

### Normalized Event Types

Initial normalized event types may include:

- `authentication_failure`
- `authentication_success`
- `explicit_credentials`
- `privileged_logon`
- `process_creation`
- `network_connection`
- `file_creation`
- `registry_modification`
- `dns_query`
- `sudo_execution`
- `session_activity`

### Normalization Principle

Parsers are responsible for understanding raw telemetry.

Detection and correlation logic should primarily operate on normalized events rather than directly parsing raw Windows, Sysmon, or Linux formats.

Source-specific information that may be useful to an analyst should be preserved inside the `details` field rather than discarded.

## Detection and Correlation Architecture

V3 separates individual detections from multi-event correlation.

### Detection

A detection identifies suspicious or security-relevant behavior from one event or a group of similar events.

Existing V2 authentication detections will remain part of the AuthWatch detection foundation where applicable.

V3 may also introduce focused endpoint detections when they can be implemented using clear and explainable rules.

Detections produce structured alerts that can later participate in correlation.

### Correlation

Correlation connects related telemetry and detections to provide investigation context.

Correlation may use:

- Time proximity.
- Username.
- Host.
- Source IP address.
- Authentication session identifier.
- Process ID or Process GUID.
- Parent/child process relationships.
- Event type.
- Related detection alerts.

Correlation must use the strongest available identifiers.

For example, a matching `session_id` or `process_guid` is stronger correlation evidence than only matching a username within a time window.

### Initial V3 Correlation Scenarios

#### CORR-AUTH-EXEC-001 — Authentication to Process Activity

Correlate suspicious authentication activity with subsequent process creation when the events involve compatible user, host, session, and time context.

Example sequence:

1. Repeated authentication failures.
2. Successful authentication.
3. Process creation associated with the authenticated user or session.

The correlation does not automatically declare compromise. It provides evidence for analyst investigation.

#### CORR-PRIV-EXEC-001 — Privileged Logon to Process Activity

Correlate a privileged Windows logon with subsequent process execution associated with the same host, user, or session.

Example sequence:

1. Successful Windows logon.
2. Special privileges assigned to the logon.
3. Process creation associated with that session.

#### CORR-PROC-NET-001 — Process to Network Activity

Correlate process creation with subsequent network activity using the process GUID or other reliable process context when available.

Example sequence:

1. Process created.
2. Same process initiates a network connection.

#### CORR-PROC-DNS-001 — Process to DNS Activity

Correlate process creation with DNS queries associated with the same process.

Example sequence:

1. Process created.
2. Same process performs a DNS query.

#### CORR-SSH-SUDO-001 — Linux SSH to Privileged Execution

Correlate a successful SSH authentication with subsequent sudo activity for the same user and host.

Example sequence:

1. Successful SSH authentication.
2. User session established.
3. sudo command execution.

### Correlation Output

A correlation result should contain enough information for investigation, including:

- Correlation ID.
- Title.
- Severity.
- First seen.
- Last seen.
- Associated users.
- Associated hosts.
- Associated IP addresses.
- Related event identifiers.
- Related detection rule IDs.
- Chronological timeline.
- Explanation of why the events were correlated.
- MITRE ATT&CK mapping when supported by the evidence.

Correlation results should describe suspicious evidence without automatically asserting that an attack or compromise definitely occurred.

## Investigation Timeline

Every correlation result should provide a chronological timeline of the events that contributed to the correlation.

Each timeline entry should contain, when available:

- Timestamp.
- Event type.
- Telemetry source.
- Host.
- Username.
- Source or destination IP.
- Process information.
- Original event ID.
- Short description of what occurred.

Example:

```text
10:00:00 | windows_security | authentication_failure | admin | 10.0.0.8
10:00:10 | windows_security | authentication_failure | admin | 10.0.0.8
10:00:35 | windows_security | authentication_success | admin | 10.0.0.8
10:00:42 | sysmon | process_creation | admin | powershell.exe
10:00:48 | sysmon | network_connection | powershell.exe | 10.0.0.50
```

## MITRE ATT&CK Mapping

V3 will support MITRE ATT&CK mappings for detections and correlations when the observed evidence clearly supports a relevant technique.

MITRE mappings should be associated with structured detection or correlation results rather than guessed from individual raw events.

A mapping may contain:

- Technique ID.
- Technique name.
- Evidence or reason for the mapping.

MITRE ATT&CK mappings must remain explainable.

AuthWatch must not assign a technique only because a commonly used tool or process name appears in an event.

The observed behavior must provide sufficient evidence for the mapping.

## Investigation Principle

AuthWatch provides evidence and context for analysts.

It must distinguish between:

- Observed event.
- Detection.
- Correlation.
- Analyst conclusion.

A correlation can indicate suspicious activity without proving that a system was compromised.

Reports should explain what was observed and why events were connected without presenting unsupported conclusions as facts.
o

## Component Architecture

V3 will separate telemetry ingestion, normalization, detection, correlation, timeline construction, MITRE mapping, and reporting into focused components.

### Telemetry Parsers

Source-specific parsers will understand the original telemetry formats.

Planned parser responsibilities include:

- Windows Security event parsing.
- Sysmon event parsing.
- Linux authentication and system-log parsing.
- Extraction of source-specific fields.
- Basic validation of required source data.
- Passing extracted data into the normalization layer.

Parsers should not contain correlation logic.

### Normalization Layer

The normalization layer converts parsed source-specific data into the common V3 event model.

Responsibilities include:

- Mapping raw event types to normalized event types.
- Normalizing timestamps.
- Normalizing usernames, hosts, IP addresses, processes, and session identifiers.
- Filling unavailable common fields with `None`.
- Preserving useful source-specific evidence inside `details`.

### Detection Engine

The detection engine remains responsible for identifying suspicious or security-relevant patterns.

Existing V2 authentication detections should remain usable where their required data can be derived from V3 telemetry.

V3 endpoint detections should remain explainable and rule-based.

### Correlation Engine

The correlation engine receives normalized events and detection results.

Responsibilities include:

- Connecting related events using strong identifiers when available.
- Applying correlation time windows.
- Matching users, hosts, sessions, IP addresses, and processes.
- Executing V3 correlation rules.
- Producing structured correlation results.
- Avoiding duplicate correlation results where appropriate.

### Timeline Builder

The timeline builder converts the events associated with a correlation result into a chronological investigation timeline.

Responsibilities include:

- Sorting relevant events by timestamp.
- Selecting useful investigation fields.
- Producing concise timeline descriptions.
- Preserving references to the underlying events.

### MITRE ATT&CK Mapper

The MITRE mapper associates supported detections and correlations with relevant ATT&CK techniques.

Mappings must be predefined and explainable rather than inferred from weak evidence.

### Reporter

The reporting layer will extend the V2 reporting capability.

V3 reports should support:

- Detection summary.
- Correlation summary.
- Affected users and hosts.
- Relevant IP addresses.
- Investigation timeline.
- Related detection and correlation IDs.
- MITRE ATT&CK mappings.
- Supporting evidence.
- Markdown output.
- Structured JSON output.

### CLI / Application Controller

`main.py` will remain the command-line entry point and application coordinator.

Its role is to:

1. Parse user arguments.
2. Load telemetry.
3. Validate and normalize events.
4. Run detections.
5. Run correlations.
6. Build investigation timelines.
7. Apply supported MITRE mappings.
8. Display results.
9. Generate requested reports.

`main.py` should coordinate components rather than contain parser, detection, or correlation logic.

## Proposed V3 Source Structure

The exact structure may evolve during implementation, but the initial design is:

```text
src/
├── config.py
├── detector.py
├── formatter.py
├── parser.py
├── reporter.py
├── normalizer.py
├── correlation.py
├── timeline.py
├── mitre.py
└── parsers/
    ├── __init__.py
    ├── windows_security.py
    ├── sysmon.py
    └── linux_auth.py
```

## Input Formats

V3 will support a controlled set of realistic telemetry formats.

### Existing V2 Authentication Input

V2 CSV and JSON authentication-log input should remain supported for backward compatibility.

Supported formats:

- `.csv`
- `.json`

These inputs continue to use the simplified AuthWatch authentication-event model.

### Windows Security Input

Windows Security telemetry will primarily be ingested from native Windows Event Log files:

- `.evtx`

Typical source:

- Windows `Security` event log.

AuthWatch will parse only the Windows Security event IDs explicitly supported by V3.

### Sysmon Input

Sysmon telemetry will primarily be ingested from the native Sysmon Operational event log:

- `.evtx`

Typical source:

- `Microsoft-Windows-Sysmon/Operational`

Only the Sysmon event IDs explicitly supported by V3 will be normalized and analyzed.

### Linux Input

Linux authentication and security telemetry will initially be ingested from saved plain-text log data.

Examples include:

- `/var/log/auth.log` style data.
- Saved `.log` or `.txt` files.
- Text exported from `journalctl` when appropriate.

V3 will not require direct live access to the Linux journal or operating-system logging service.

### Source Selection

Because different telemetry sources may use similar file extensions, V3 should use an explicit source type when necessary rather than relying only on the filename extension.

Conceptual source types include:

- `authwatch`
- `windows-security`
- `sysmon`
- `linux-auth`

The CLI design will be finalized during implementation.

### Input Principle

Parsers must operate on saved telemetry files.

V3 will not perform live endpoint monitoring or continuous log collection.

This keeps the version focused on offline SOC analysis, investigation, and correlation.

## Time and Correlation Configuration

### Timestamp Handling

All supported timestamps must be parsed and validated before an event enters the correlation engine.

Internally, V3 should use consistent timezone-aware timestamps whenever the source provides sufficient timezone information.

Events must be sorted chronologically before timeline construction and time-based correlation.

The original timestamp value may be preserved inside source-specific details when useful for investigation.

### Correlation Windows

Correlation rules may require time windows.

For example:

- Authentication activity followed by process execution within a defined period.
- Process creation followed by network activity within a defined period.
- SSH authentication followed by sudo execution within a defined period.

Correlation windows should be centralized in configuration rather than hard-coded throughout the correlation functions.

Exact default windows will be finalized and tested during implementation using realistic synthetic and sanitized telemetry.

### Correlation Configuration

V3 should extend the existing configuration architecture so correlation rules can have validated settings.

Conceptually:

```json
{
    "CORR-AUTH-EXEC-001": {
        "window_seconds": 300
    },
    "CORR-PROC-NET-001": {
        "window_seconds": 120
    }
}
```

### Deterministic Analysis

Given the same telemetry and configuration, AuthWatch should produce the same detection and correlation results.

Correlation logic should:

- Sort events consistently.
- Use explicit matching conditions.
- Avoid unnecessary duplicate results.
- Preserve stable rule and correlation identifiers.
- Remain explainable and reproducible.

## Implementation Plan

V3 will be implemented in controlled phases so each layer can be tested before the next layer depends on it.

### Phase 1 — Preserve V2 Compatibility

- Confirm existing V2 behavior remains functional.
- Preserve CSV and JSON authentication input.
- Preserve existing detection rules and reporting where practical.
- Avoid unnecessary rewrites of working V2 components.

### Phase 2 — Telemetry Parsers

Implement focused parsers for:

- Windows Security `.evtx`.
- Sysmon `.evtx`.
- Linux authentication and system log text.

Each parser will extract only the fields required by the V3 supported event set.

### Phase 3 — Normalization Layer

Convert parsed telemetry into the V3 normalized event model.

Validate:

- Timestamp handling.
- Event type mapping.
- User and host fields.
- IP addresses.
- Session identifiers.
- Process identifiers.
- Source-specific details preservation.

### Phase 4 — Detection Integration

Ensure existing authentication detections can operate on compatible normalized telemetry where appropriate.

Add focused endpoint detections only when they are explainable and useful for V3 investigation.

### Phase 5 — Correlation Engine

Implement the initial V3 correlation rules:

- `CORR-AUTH-EXEC-001`
- `CORR-PRIV-EXEC-001`
- `CORR-PROC-NET-001`
- `CORR-PROC-DNS-001`
- `CORR-SSH-SUDO-001`

Validate correlation identifiers, time windows, matching conditions, and duplicate suppression.

### Phase 6 — Investigation Timelines

Build chronological timelines from correlated events.

Ensure timelines preserve:

- Event order.
- Relevant entities.
- Source event references.
- Concise analyst-readable descriptions.

### Phase 7 — MITRE ATT&CK Mapping

Add predefined, explainable mappings for supported detections and correlations.

Mappings must be supported by observed behavior rather than weak assumptions.

### Phase 8 — Reporting

Extend Markdown and JSON output to include:

- Detection summaries.
- Correlation summaries.
- Investigation timelines.
- Affected entities.
- Supporting evidence.
- MITRE ATT&CK mappings.

### Phase 9 — CLI Integration

Extend the command-line interface to support:

- Telemetry source selection.
- V2 authentication input.
- Windows Security input.
- Sysmon input.
- Linux input.
- Configuration.
- Markdown output.
- JSON output.

### Phase 10 — Testing and Datasets

Create realistic synthetic or sanitized datasets covering:

- Normal activity.
- Individual detections.
- Correlation scenarios.
- False-positive conditions.
- Invalid telemetry.
- Boundary conditions.
- Zero-result cases.

Automated tests will cover parsers, normalization, detection, correlation, timelines, configuration, reporting, and CLI behavior.

### Phase 11 — Kali Release Validation

Before release:

- Run the complete automated test suite.
- Perform manual end-to-end analysis.
- Verify repository hygiene.
- Review documentation.
- Confirm deterministic results.
- Confirm no sensitive telemetry is included.

### Phase 12 — Windows Compatibility Validation

Only after V3 is fully completed on Kali:

- Copy the completed V3 project to Windows.
- Install required dependencies.
- Run representative telemetry analysis.
- Verify filesystem and path behavior.
- Fix genuine cross-platform compatibility issues if found.

Windows compatibility testing is the final validation stage rather than part of routine V3 development.
