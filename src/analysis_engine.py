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


class AnalysisError(Exception):
    def __init__(
        self,
        code: str,
        message: str,
        path: str | None = None,
    ):
        super().__init__(message)

        self.code = code
        self.path = path


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
    if request.linux_auth and (
        request.linux_year is None
        or request.linux_utc_offset is None
    ):
        raise AnalysisError(
            code="LINUX_CONTEXT_REQUIRED",
            message=(
                "Linux authentication analysis requires "
                "both a year and UTC offset."
            ),
            path=request.linux_auth,
        )

    events = []

    v3_mode = any([
        request.windows_security,
        request.sysmon,
        request.linux_auth,
    ])

    if request.log_file:
        try:
            auth_events = load_auth_events(
                request.log_file
            )
        except FileNotFoundError as error:
            raise AnalysisError(
                code="AUTH_LOG_NOT_FOUND",
                message=(
                    "Authentication log not found: "
                    f"{request.log_file}"
                ),
                path=request.log_file,
            ) from error

        events.extend(auth_events)

    if request.windows_security:
        try:
            windows_events = load_windows_security_events(
                request.windows_security
            )
        except FileNotFoundError as error:
            raise AnalysisError(
                code="WINDOWS_SECURITY_NOT_FOUND",
                message=(
                    "Windows Security EVTX not found: "
                    f"{request.windows_security}"
                ),
                path=request.windows_security,
            ) from error

        normalized_windows_events = [
            normalize_windows_security_event(event)
            for event in windows_events
        ]

        events.extend(normalized_windows_events)

    if request.sysmon:
        try:
            sysmon_events = load_sysmon_events(
                request.sysmon
            )
        except FileNotFoundError as error:
            raise AnalysisError(
                code="SYSMON_NOT_FOUND",
                message=(
                    "Sysmon EVTX not found: "
                    f"{request.sysmon}"
                ),
                path=request.sysmon,
            ) from error

        normalized_sysmon_events = [
            normalize_sysmon_event(event)
            for event in sysmon_events
        ]

        events.extend(normalized_sysmon_events)

    if request.linux_auth:
        try:
            linux_events = load_linux_auth_events(
                request.linux_auth
            )
        except FileNotFoundError as error:
            raise AnalysisError(
                code="LINUX_AUTH_NOT_FOUND",
                message=(
                    "Linux authentication log not found: "
                    f"{request.linux_auth}"
                ),
                path=request.linux_auth,
            ) from error

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
        try:
            detection_config = load_detection_config(
                request.detection_config
            )
        except FileNotFoundError as error:
            raise AnalysisError(
                code="DETECTION_CONFIG_NOT_FOUND",
                message=(
                    "Detection configuration file not found: "
                    f"{request.detection_config}"
                ),
                path=request.detection_config,
            ) from error

    correlation_config = None

    if request.correlation_config:
        try:
            correlation_config = load_correlation_config(
                request.correlation_config
            )
        except FileNotFoundError as error:
            raise AnalysisError(
                code="CORRELATION_CONFIG_NOT_FOUND",
                message=(
                    "Correlation configuration file not found: "
                    f"{request.correlation_config}"
                ),
                path=request.correlation_config,
            ) from error

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
