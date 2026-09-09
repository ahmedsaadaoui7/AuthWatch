# AuthWatch V3 Test Dataset Library

This directory contains synthetic and sanitized datasets used to validate
AuthWatch V3 detection, correlation, normalization, reporting, and
false-positive behavior.

No real credentials, private logs, or third-party sensitive data should be
stored here.

## Dataset Categories

### Normal Activity

- NORM-001 — Normal authentication and endpoint activity with no expected
  detections or correlations.

### Detection Scenarios

- DET-BF-001 — Brute force.
- DET-PS-001 — Password spraying.
- DET-SF-001 — Successful login after repeated failures.
- DET-DA-001 — Disabled account authentication attempt.
- DET-MA-001 — One source IP accessing multiple accounts.
- DET-MI-001 — One account accessed from multiple source IPs.

### Correlation Scenarios

- CORR-AUTH-EXEC-001 — Authentication followed by process activity.
- CORR-PRIV-EXEC-001 — Privileged logon followed by process activity.
- CORR-PROC-NET-001 — Process creation followed by network activity.
- CORR-PROC-DNS-001 — Process creation followed by DNS activity.
- CORR-SSH-SUDO-001 — SSH login followed by sudo execution.

### False-Positive Scenarios

- FP-AUTH-EXEC-001 — Different session IDs must not correlate.
- FP-PROC-NET-001 — Different ProcessGuids must not correlate.
- FP-SSH-SUDO-001 — Different usernames must not correlate.
- FP-TIME-001 — Related-looking events outside the configured window must
  not correlate.

### Boundary Scenarios

- BOUND-DETECTION-001 — Detection exactly at its configured time boundary.
- BOUND-CORRELATION-001 — Correlation exactly at its configured time
  boundary.

### Invalid Telemetry

- INVALID-TIME-001 — Invalid timestamp.
- INVALID-EVENT-001 — Unsupported or malformed event.
- INVALID-LINUX-001 — Invalid Linux timestamp or UTC offset.

### Zero-Result Scenarios

- ZERO-001 — Valid telemetry that produces zero detections and zero
  correlations.

## Dataset Formats

V2-compatible authentication scenarios may use CSV or JSON and can be passed
directly to the AuthWatch CLI.

Linux scenarios may use synthetic Linux authentication log lines.

Windows Security and Sysmon correlation scenarios may use normalized V3 event
JSON for automated dataset testing. Real EVTX files are reserved for final
validation using telemetry exported from systems owned by the project author.

## Expected Behavior

Each dataset should have a documented expected result so the same telemetry and
configuration always produces the same deterministic AuthWatch result.
