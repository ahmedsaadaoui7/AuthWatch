# Changelog

All notable changes to AuthWatch are documented in this file.

## [3.0.0] - 2026-09-09

### Added

- Windows Security EVTX ingestion for supported events `4624`, `4625`, `4648`, and `4672`
- Sysmon EVTX ingestion for supported events `1`, `3`, `11`, `13`, and `22`
- Linux authentication-log parsing for failed and successful SSH authentication, sudo execution, and session activity
- Shared normalized telemetry model for Windows Security, Sysmon, Linux, and V2-compatible authentication events
- Linux timestamp normalization to UTC using analyst-supplied year and UTC-offset context
- `--windows-security`, `--sysmon`, and `--linux-auth` command-line telemetry inputs
- `--linux-year` and `--linux-utc-offset` timestamp-context options
- V3 correlation engine with five correlation rules:
  - `CORR-AUTH-EXEC-001` authentication-to-process activity
  - `CORR-PRIV-EXEC-001` privileged-logon-to-process activity
  - `CORR-PROC-NET-001` process-to-network activity
  - `CORR-PROC-DNS-001` process-to-DNS activity
  - `CORR-SSH-SUDO-001` Linux SSH-login-to-privileged-execution activity
- Configurable correlation windows with JSON configuration support
- Investigation timeline reconstruction
- Evidence-based MITRE ATT&CK mapping
- `T1110` Brute Force mapping for `AUTH-BF-001`
- `T1110.003` Password Spraying mapping for `AUTH-PS-001`
- V3 Markdown investigation reports
- Structured V3 JSON investigation reports
- Affected-user, host, and IP-address collection
- Supporting-evidence preservation for detections and correlations
- Deterministic investigation output
- Reusable V3 scenario dataset library covering normal, detection, correlation, false-positive, boundary, invalid, and zero-result cases
- Automated Windows Security, Sysmon, Linux, normalization, correlation, timeline, MITRE, reporting, CLI, and scenario validation
- Git protection for local `.evtx` telemetry files

### Changed

- Expanded AuthWatch from an authentication-only detection engine into a multi-source endpoint telemetry and SOC investigation platform
- Integrated V2 authentication detections with the normalized V3 telemetry pipeline
- Preserved V2 CSV/JSON authentication input and reporting compatibility
- Improved command-line help for V3 endpoint telemetry and investigation workflows
- Improved Linux source-event references in human-readable reports by omitting unavailable Event IDs
- Expanded reporting from isolated alerts into structured investigation summaries containing detections, correlations, affected entities, supporting evidence, timelines, and ATT&CK context
- Updated public documentation for the V3 architecture, telemetry sources, correlation methodology, configuration, reports, testing, limitations, security guidance, and roadmap

### Validation

- Complete automated suite: 250 tests passing on Kali Linux
- Complete automated suite: 250 tests passing on Windows with Python 3.12.10
- Manual Linux SSH-to-sudo end-to-end correlation validation
- Deterministic Markdown and JSON output confirmed byte-for-byte for identical input and configuration
- Real Windows Security EVTX export and end-to-end analysis validated successfully
- Windows Markdown and JSON report generation validated
- Windows absolute-path, backslash-path, and path-with-spaces behavior validated
- V2 CSV backward compatibility validated on Windows
- Repository hygiene and sensitive-data review completed
- Real Sysmon EVTX validation was not performed because Sysmon was not installed on the Windows validation system; Sysmon parsing and correlation remain covered by automated tests

## [2.0.0] - 2026-08-19

### Added

- Multi-rule authentication detection engine
- `AUTH-PS-001` password-spraying detection
- `AUTH-SF-001` successful-login-after-repeated-failures detection
- `AUTH-DA-001` disabled-account authentication detection
- `AUTH-MA-001` one-source-IP-to-many-accounts detection
- `AUTH-MI-001` many-source-IPs-to-one-account detection
- Rule IDs, titles, severity levels, timestamps, and structured rule-specific alert details
- Centralized default detection configuration
- JSON detection configuration with rule-specific threshold and time-window overrides
- Partial configuration overrides with default-value inheritance
- Detection-configuration validation and clean CLI error handling
- Optional disabled-account username context
- Disabled-account list parsing with blank-line handling and duplicate removal
- JSON authentication-log input support
- JSON authentication-event structure and type validation
- Unsupported authentication-log format rejection
- Synthetic JSON brute-force authentication dataset
- Structured JSON alert output
- `--json-output` command-line option
- Valid JSON output for analyses with zero alerts
- Simultaneous Markdown and JSON output generation
- Markdown detection summary with total, high-severity, and medium-severity alert counts
- Expanded unit and integration tests for V2 detection, parsing, configuration, reporting, and CLI workflows

### Changed

- Expanded AuthWatch from a single brute-force detector into a six-rule authentication detection engine
- Standardized alert metadata and nested rule-specific details
- Centralized configurable thresholds and time windows
- Extended authentication-log support from CSV-only to CSV and JSON
- Improved shared authentication-event validation
- Improved command-line authentication-log error messages
- Updated command-line help for CSV and JSON input
- Generalized terminal output for multiple detection-rule types
- Improved Markdown reporting for multi-rule analysis
- Updated project documentation for the V2 architecture, rules, configuration, input/output formats, testing, false positives, limitations, and usage

## [1.0.0] - 2026-08-08

### Added

- CSV authentication log parsing
- Required-column validation
- Authentication event validation
- ISO timestamp validation
- Brute-force detection using a sliding time window
- Detection grouping by source IP and username
- Terminal alert output
- Markdown incident report generation
- Command-line log selection
- Optional report-generation argument
- Clean handling of missing and malformed input
- CLI success and error exit codes
- Synthetic normal authentication dataset
- Synthetic brute-force authentication dataset
- Unit tests for parsing, validation, detection, and reporting
- Integration tests for command-line workflows
- Detector edge-case tests
- Example generated incident report
- Project documentation for V1
