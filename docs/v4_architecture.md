# AuthWatch V4 Architecture

## Version

AuthWatch V4 — Local SOC Dashboard & Case Management

## Objective

AuthWatch V4 transforms the validated V3 security analysis engine into a professional local SOC desktop application.

V4 preserves the existing V3 parsing, normalization, detection, correlation, timeline, MITRE ATT&CK, and reporting capabilities while adding a cross-platform analyst interface, local persistence, investigations, findings, and case management.

The normal analyst workflow moves from the command line to an installable desktop application while the existing CLI remains supported.

## Platform Goals

Development platform:

- Linux / Kali Linux

Release targets:

- Linux
- Windows

The application must remain cross-platform throughout development.

## Core Architecture

    QML UI
       |
       v
    ViewModels
       |
       v
    Services
     /    \
    v      v
    AuthWatch Engine    Repositories
          |                 |
          v                 v
      V3 Analysis         SQLite

### Layer Responsibilities

QML UI:

- displays information
- receives analyst actions
- provides navigation
- renders tables, charts, timelines, dialogs, and forms

ViewModels:

- maintain screen state
- expose application data to QML
- translate UI actions into service calls
- manage loading, filtering, selection, and error state

Services:

- coordinate application workflows
- connect the UI layer with the analysis engine and persistence layer
- enforce application-level operations consistently

AuthWatch Engine:

- parses telemetry
- normalizes events
- runs authentication detections
- correlates related events
- constructs timelines
- applies approved MITRE ATT&CK mappings
- returns structured analysis results

Repositories:

- provide controlled database access
- isolate SQL/database operations from services and the UI

SQLite:

- persists investigations
- persists normalized events
- persists findings
- persists cases
- persists analyst notes and workflow history

## Architectural Rule

Each layer must have one clear responsibility.

The QML interface must not run SQL or detection logic.

The V3 analysis engine must not know about dashboard state, QML, case management, analyst notes, or SQLite.

Application services must coordinate workflows without duplicating security detection logic.

## Reusable Analysis Engine

V4 introduces a reusable analysis entry point around the existing V3 modules.

Conceptually:

    AnalysisRequest
          |
          v
    AuthWatch Engine
          |
          v
    AnalysisResult

The CLI and desktop application should both use the same underlying analysis engine.

The desktop application must not execute main.py as a subprocess and scrape terminal output.

### AnalysisRequest

The request may contain:

- Windows Security EVTX path
- Sysmon EVTX path
- Linux authentication log path
- AuthWatch CSV/JSON path
- Linux year
- Linux UTC offset
- detection configuration
- correlation configuration
- disabled account configuration

### AnalysisResult

The result should provide structured access to:

- normalized events
- detections
- correlations
- timelines
- MITRE mappings
- affected entities
- telemetry metadata
- statistics
- analysis metadata

## Application Services

Planned services:

### AnalysisService

Responsible for:

- validating selected inputs
- calculating telemetry metadata and hashes
- building AnalysisRequest
- executing the AuthWatch engine
- receiving AnalysisResult
- storing investigations
- storing events
- storing findings

### InvestigationService

Responsible for:

- listing investigations
- loading investigation details
- filtering and searching investigations
- loading timelines
- loading affected entities
- loading related findings and cases
- exporting investigations

### FindingService

Responsible for:

- listing findings
- filtering and searching findings
- loading finding details
- marking findings reviewed
- marking findings escalated
- loading supporting evidence
- loading related findings

### CaseService

Responsible for:

- creating cases
- changing case priority
- changing case status
- linking findings
- adding notes
- closing cases
- reopening cases
- recording resolutions
- loading case history

## Persistence

V4 uses SQLite for local application persistence.

SQLAlchemy provides the database model and access layer.

Alembic provides database schema migrations.

The database should live in the operating system's application-data location rather than inside the Git repository.

Example locations:

Linux:

    ~/.local/share/AuthWatch/

Windows:

    %LOCALAPPDATA%\AuthWatch\

## Persisted Data Model

Planned entities:

- Investigation
- TelemetrySource
- Event
- Finding
- FindingEvent
- Case
- CaseFinding
- CaseNote
- CaseActivity
- ApplicationSetting

### Investigation

Represents one AuthWatch analysis run.

Stores information such as:

- public investigation ID
- name
- creation time
- completion time
- analysis status
- event count
- detection count
- correlation count
- severity statistics
- analysis configuration metadata

Public IDs should be analyst-friendly, for example:

    INV-2026-0001

### TelemetrySource

Represents an input file used by an investigation.

Stores information such as:

- investigation reference
- filename
- source type
- file size
- SHA-256 hash
- original path/reference

The hash provides reproducibility by identifying the exact input used for an analysis.

### Event

Stores normalized V3 telemetry required to reconstruct an investigation.

The model should remain compatible with the existing V3 normalized event structure, including fields such as:

- timestamp
- source
- event_id
- event_type
- host
- username
- session_id
- source_ip
- destination_ip
- process_name
- process_id
- process_guid
- parent_process_name
- command_line
- result
- details

### Finding

A Finding is the common V4 application representation of either:

- a detection
- a correlation

Example detection:

    AUTH-BF-001
    Potential Brute-Force Activity

Example correlation:

    CORR-AUTH-EXEC-001
    Authentication to Process Activity

Finding statuses:

- New
- Reviewed
- Escalated

A finding should store information such as:

- investigation reference
- finding type
- rule ID
- title
- severity
- status
- first seen
- last seen
- summary
- details
- approved MITRE information when available

### FindingEvent

Links findings to the normalized events that support them.

This allows the UI to show the evidence behind a detection or correlation.

### Case

Represents analyst-managed work.

Public case IDs should be analyst-friendly, for example:

    AW-0001

Case priorities:

- High
- Medium
- Low

Case statuses:

- Open
- Investigating
- Closed

Case resolutions:

- True Positive
- False Positive
- Benign Activity
- Other

A case stores information such as:

- public case ID
- title
- priority
- status
- resolution
- created time
- updated time
- closed time
- closing note

Finding severity and case priority remain separate concepts.

### CaseFinding

Links one or more findings to a case.

A case may contain multiple related findings.

### CaseNote

Stores append-only analyst notes.

V4 is single-user, so analyst identity is not required yet.

V5 may later associate notes with authenticated analyst accounts.

### CaseActivity

Stores important case workflow history, such as:

- case created
- status changed
- priority changed
- finding added
- note added
- case closed
- case reopened

### ApplicationSetting

Stores simple local application preferences.

Authentication credentials and RBAC configuration are not part of V4.

## Database Transactions

Operations that modify several related records should be atomic.

For example, creating a case may involve:

- creating the case
- linking a finding
- changing the finding status to Escalated
- creating a case activity record

Either the whole operation succeeds or the whole operation is rolled back.

## Desktop Technology

V4 uses:

- Python
- PySide6
- Qt Quick / QML
- SQLite
- SQLAlchemy
- Alembic

Long-running telemetry analysis must execute outside the main UI thread so the application remains responsive.

## Background Analysis

The application must not freeze while parsing or analyzing telemetry.

Conceptually:

    UI Thread
        |
        | Run Analysis
        v
    Background Worker
        |
        | Parse
        | Normalize
        | Detect
        | Correlate
        | Build Timeline
        | MITRE Mapping
        | Store Results
        v
    UI receives completed result

Progress should be stage-based rather than showing fake percentages.

Example stages:

- validating
- parsing
- normalizing
- detecting
- correlating
- building timeline
- mapping MITRE
- storing
- complete

## Application Navigation

Primary navigation:

- Dashboard
- Analyze
- Findings
- Investigations
- Cases
- Settings

Timelines are contextual and appear inside finding, investigation, and case views rather than as a separate main navigation page.

## Dashboard

The dashboard provides a fast SOC workload overview.

Primary metrics:

- total findings
- high-severity findings
- medium-severity findings
- open cases

Primary visualizations:

- findings by severity
- findings over time
- top affected users
- top affected hosts
- top source IP addresses

Operational sections:

- recent high-severity findings
- open cases

Dashboard elements should link directly to filtered findings, cases, or investigation details.

## Analyze Workflow

The desktop application supports:

- Windows Security EVTX
- Sysmon EVTX
- Linux authentication logs
- AuthWatch CSV / JSON

Mixed V3 telemetry must remain supported.

Normal analyst workflow:

    Select telemetry
          |
          v
       Validate
          |
          v
        Parse
          |
          v
      Normalize
          |
          v
       Detect
          |
          v
      Correlate
          |
          v
    Build Timeline
          |
          v
    MITRE Mapping
          |
          v
    Store Investigation
          |
          v
    Display Results

Linux-specific timestamp context is requested only when required by Linux telemetry.

Advanced configuration remains collapsed by default.

## Findings

The Findings page acts as the primary analyst finding queue.

It supports:

- search
- severity filtering
- type filtering
- status filtering
- rule filtering
- username filtering
- host filtering
- source IP filtering
- telemetry-source filtering
- date/time filtering
- investigation filtering
- sorting

The default view should prioritize recent high-severity findings.

Human-readable finding titles are displayed prominently.

Technical rule IDs remain visible but secondary.

## Finding Details

Finding Details should answer:

1. What happened?
2. How serious is it?
3. Who or what is affected?
4. When did it happen?
5. What is the timeline?
6. Why did AuthWatch detect or correlate it?
7. What evidence supports it?
8. What technical details are available?
9. What analyst action should be taken?

The page contains:

- summary
- severity
- workflow status
- affected entities
- timeline
- correlation explanation when applicable
- MITRE ATT&CK mapping when approved
- supporting evidence
- expandable technical details
- related findings
- case actions

## Investigations

An Investigation represents one complete AuthWatch analysis run.

Investigation views contain:

- investigation name and public ID
- telemetry sources
- statistics
- affected entities
- complete timeline
- correlation explanations
- findings
- related cases
- filtering
- analysis metadata
- export capability

An investigation with zero findings is still a successful investigation if analysis completed correctly.

## Cases

Cases represent analyst-managed work rather than automatic engine conclusions.

The engine must never automatically create a case merely because a detection occurred.

Normal workflow:

    Finding
       |
       v
    Analyst Review
       |
       v
    Create Case
       |
       v
    Investigate
       |
       v
    Add Notes / Findings
       |
       v
    Reach Conclusion
       |
       v
    Close Case

Cases include:

- case ID
- title
- priority
- status
- affected entities
- related investigation
- related findings
- security timeline
- analyst-action timeline
- notes
- evidence
- resolution
- export

## Analyst Notes

Notes are append-only in V4.

Historical notes should not be silently overwritten.

Corrections should be added as new notes so investigation history remains understandable.

## Case Closure

Closing a case requires:

- resolution
- closing note

Resolution options:

- True Positive
- False Positive
- Benign Activity
- Other

Closed cases may be reopened if new evidence appears.

Reopening should preserve previous workflow history.

## Timeline Design

The timeline is a major reusable V4 component.

Example:

    10:00 Login Success
          |
          | Same Session ID: 0x1234
          v
    10:01 PowerShell Started
          |
          | Same ProcessGuid: {ABC-123}
          v
    10:02 DNS Query
          |
          v
    10:03 Network Connection

Correlation connectors should explain why events were associated.

Examples:

- same Session ID
- same ProcessGuid
- same host
- same username
- configured time window

Case timelines may contain both:

- security events
- analyst actions

These should remain visually distinguishable.

## Visual Design Principles

AuthWatch V4 should look like a professional SOC desktop application rather than a terminal utility or generic website.

Design priorities:

1. clarity
2. readability
3. analyst efficiency
4. consistency
5. professional presentation

The interface uses a restrained dark enterprise design.

High severity is visually prominent, but red must not dominate the application.

Color must never be the only way severity or status is communicated.

Human-readable information appears before low-level technical details.

Technical information remains available through expandable views.

The application should remain comfortable for prolonged SOC use.

## Information Hierarchy

The interface follows these principles:

    UNDERSTAND
    before
    DECORATE

    SUMMARY
    before
    DETAILS

    HUMAN LANGUAGE
    before
    RAW TELEMETRY

    EVIDENCE
    before
    CONCLUSION

## Reusable UI Components

Planned reusable components include:

- SeverityBadge
- StatusBadge
- MetricCard
- SearchBox
- FilterBar
- FindingTable
- CaseTable
- Timeline
- TimelineEvent
- TimelineConnector
- EmptyState
- ErrorState
- LoadingState
- TechnicalDetailsPanel
- ConfirmationDialog
- ToastNotification

## Empty States

Professional empty states are required.

Examples:

Dashboard:

    No telemetry analyzed yet.
    Start your first AuthWatch investigation.

Findings:

    No findings match the current filters.

Cases:

    No cases yet.
    Cases appear here when findings are escalated.

## Error Handling

User-facing errors should explain:

- what happened
- why it happened when known
- what the analyst can do next

Python tracebacks should not be displayed as the normal analyst experience.

Technical error details may be available through an expandable section.

## Local Operation

V4 operates locally.

Normal architecture:

    Telemetry
       |
       v
    Local AuthWatch
       |
       v
    Local Analysis
       |
       v
    Local Database

Cloud services are not required.

## Telemetry Retention

V4 should store normalized events necessary to reopen and reconstruct investigations.

V4 should not automatically duplicate and permanently retain full copies of every original EVTX or log file.

Telemetry source metadata and SHA-256 hashes should be retained for reproducibility.

## Application Logging

AuthWatch application logs may record operational events such as:

- application start
- database initialization
- analysis start
- analysis completion
- unexpected application errors

Application logs should avoid unnecessarily storing:

- raw telemetry
- credentials
- secrets
- complete sensitive event records

## Cross-Platform Storage

The application should use proper operating-system application-data directories.

No runtime database or analyst-generated application state should be written into the Git repository.

## Packaging

### Linux

The final V4 release should provide an installable or portable Linux application.

An AppImage is a candidate for portable distribution.

A native package may also be evaluated.

### Windows

The final V4 release should provide a normal Windows installation experience:

    AuthWatch-Setup.exe
          |
          v
       Install
          |
          v
      Start Menu
          |
          v
       AuthWatch

The analyst should not need to install Python manually.

Packaging must be built and validated on the target operating system.

## Scope Boundaries

Included in V4:

- cross-platform local desktop application
- dashboard
- telemetry import
- reusable V3 analysis engine interface
- findings
- finding details
- investigations
- investigation timelines
- filtering
- search
- local persistence
- case management
- analyst notes
- resolution workflow
- Linux packaging
- Windows packaging

Not included in V4:

- multi-user accounts
- user authentication
- RBAC
- cloud deployment
- AI functionality

Multi-user authentication and RBAC remain V5 scope.

## Compatibility Requirement

Existing V3 functionality and CLI behavior must remain valid throughout V4 development.

The V3 automated test suite must remain green.

Baseline at V4 start:

- 250 tests passed
- Linux Python 3.13.12
- pytest 9.0.3
- V3 release tag: v3.0.0
- V3 release commit: 5829c11
- V4 development branch: v4-soc-dashboard

## Development Rule

V4 work remains local during development.

Meaningful Git commits should be created throughout implementation.

Intermediate development must not be pushed merely because a step is complete.

The branch should only be pushed and released after V4 has been fully implemented, tested, documented, validated on Linux and Windows, and professionally closed.
