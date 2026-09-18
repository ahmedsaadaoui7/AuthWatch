from dataclasses import dataclass, field

from src.config import load_detection_config
from src.detector import run_detection_engine
from src.parser import load_auth_events, load_disabled_accounts


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

    if request.log_file:
        events.extend(
            load_auth_events(request.log_file)
        )

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

    detections = run_detection_engine(
        events,
        disabled_accounts=disabled_accounts,
        config=detection_config,
    )

    return AnalysisResult(
        events=events,
        detections=detections,
        correlations=[],
        v3_mode=False,
    )
