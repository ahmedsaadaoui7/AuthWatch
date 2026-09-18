from dataclasses import dataclass, field

from src.config import (
    load_correlation_config,
    load_detection_config,
)

from src.detector import run_detection_engine
from src.parser import load_auth_events, load_disabled_accounts

from src.normalizer import (
    normalize_linux_auth_event,
    normalize_sysmon_event,
    normalize_windows_security_event,
)

from src.parsers.sysmon import load_sysmon_events
from src.parsers.windows_security import load_windows_security_events
from src.parsers.linux_auth import load_linux_auth_events

from src.correlation import run_correlation_engine
from src.mitre import attach_mitre_mappings
from src.timeline import attach_timelines_to_correlations


@dataclass
class AnalysisRequest:
    log_file: str | None = None
    windows_security: str | None = None
    sysmon: str | None = None
    linux_auth: str | None = None
    linux_year: int | None = None
    linux_utc_offset: str | None = None
    disabled_accounts: str | None = None
    detection_config: str | None = None
    correlation_config: str | None = None


@dataclass
class AnalysisResult:
    events: list = field(default_factory=list)
    detections: list = field(default_factory=list)
    correlations: list = field(default_factory=list)
    v3_mode: bool = False


def run_analysis(request: AnalysisRequest) -> AnalysisResult:
    events = []

    v3_mode = any([
        request.windows_security,
        request.sysmon,
        request.linux_auth,
    ])

    if request.log_file:
        events.extend(
            load_auth_events(request.log_file)
        )

    if request.windows_security:
        windows_events = load_windows_security_events(
            request.windows_security
        )

        normalized_windows_events = [
            normalize_windows_security_event(event)
            for event in windows_events
        ]

        events.extend(normalized_windows_events)

    if request.sysmon:
        sysmon_events = load_sysmon_events(
            request.sysmon
        )

        normalized_sysmon_events = [
            normalize_sysmon_event(event)
            for event in sysmon_events
        ]

        events.extend(normalized_sysmon_events)

    if request.linux_auth:
        linux_events = load_linux_auth_events(
            request.linux_auth
        )

        normalized_linux_events = [
            normalize_linux_auth_event(
                event,
                year=request.linux_year,
                utc_offset=request.linux_utc_offset,
            )
            for event in linux_events
        ]

        events.extend(normalized_linux_events)

    disabled_accounts = None

    if request.disabled_accounts:
        disabled_accounts = load_disabled_accounts(
            request.disabled_accounts
        )

    detection_config = None

    if request.detection_config:
        detection_config = load_detection_config(
            request.detection_config
        )

    correlation_config = None

    if request.correlation_config:
        correlation_config = load_correlation_config(
            request.correlation_config
        )

    detections = run_detection_engine(
        events,
        disabled_accounts=disabled_accounts,
        config=detection_config,
    )

    if correlation_config is None:
        correlations = run_correlation_engine(events)
    else:
        correlations = run_correlation_engine(
            events,
            config=correlation_config,
        )

    correlations = attach_timelines_to_correlations(
        correlations
    )

    detections = attach_mitre_mappings(
        detections
    )

    correlations = attach_mitre_mappings(
        correlations
    )

    return AnalysisResult(
        events=events,
        detections=detections,
        correlations=correlations,
        v3_mode=v3_mode,
    )
