# Changelog

All notable changes to AuthWatch are documented in this file.

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
