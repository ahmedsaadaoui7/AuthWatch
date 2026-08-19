# Changelog

All notable changes to AuthWatch are documented in this file.

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
