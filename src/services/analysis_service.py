from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from src.models import (
    Event,
    Finding,
    FindingEvent,
    Investigation,
    TelemetrySource,
)

from src.repositories.investigation_repository import (
    InvestigationRepository,
)

import hashlib
from pathlib import Path

from src.analysis_engine import (
    AnalysisRequest,
    AnalysisResult,
    run_analysis,
)


class AnalysisService:
    _TELEMETRY_SOURCE_TYPES = {
        "log_file": "auth_log",
        "windows_security": "windows_security",
        "sysmon": "sysmon",
        "linux_auth": "linux_auth",
    }

    def __init__(self, session):
        self.session = session
        self.investigation_repository = (
            InvestigationRepository(session)
        )

    @staticmethod
    def _calculate_sha256(path: Path) -> str:
        digest = hashlib.sha256()

        with path.open("rb") as file:
            for chunk in iter(
                lambda: file.read(1024 * 1024),
                b"",
            ):
                digest.update(chunk)

        return digest.hexdigest()

    @classmethod
    def _build_telemetry_metadata(
        cls,
        *,
        log_file: str | None = None,
        windows_security: str | None = None,
        sysmon: str | None = None,
        linux_auth: str | None = None,
    ) -> list[dict]:
        selected_inputs = {
            "log_file": log_file,
            "windows_security": windows_security,
            "sysmon": sysmon,
            "linux_auth": linux_auth,
        }

        metadata = []

        for request_field, selected_path in selected_inputs.items():
            if selected_path is None:
                continue

            path = Path(selected_path).expanduser()

            if not path.exists():
                raise ValueError(
                    f"Selected telemetry file does not exist: "
                    f"{path}"
                )

            if not path.is_file():
                raise ValueError(
                    f"Selected telemetry path is not a file: "
                    f"{path}"
                )

            resolved_path = path.resolve()

            metadata.append(
                {
                    "request_field": request_field,
                    "filename": resolved_path.name,
                    "source_type": (
                        cls._TELEMETRY_SOURCE_TYPES[
                            request_field
                        ]
                    ),
                    "file_size": resolved_path.stat().st_size,
                    "sha256": cls._calculate_sha256(
                        resolved_path
                    ),
                    "original_path": str(resolved_path),
                }
            )

        if not metadata:
            raise ValueError(
                "At least one telemetry input is required."
            )

        return metadata

    @classmethod
    def build_analysis_request(
        cls,
        *,
        log_file: str | None = None,
        windows_security: str | None = None,
        sysmon: str | None = None,
        linux_auth: str | None = None,
        linux_year: int | None = None,
        linux_utc_offset: str | None = None,
        disabled_accounts: str | None = None,
        detection_config: str | None = None,
        correlation_config: str | None = None,
    ) -> AnalysisRequest:
        cls._build_telemetry_metadata(
            log_file=log_file,
            windows_security=windows_security,
            sysmon=sysmon,
            linux_auth=linux_auth,
        )

        return cls._create_analysis_request(
            log_file=log_file,
            windows_security=windows_security,
            sysmon=sysmon,
            linux_auth=linux_auth,
            linux_year=linux_year,
            linux_utc_offset=linux_utc_offset,
            disabled_accounts=disabled_accounts,
            detection_config=detection_config,
            correlation_config=correlation_config,
        )

    @staticmethod
    def execute_analysis(
        request: AnalysisRequest,
    ) -> AnalysisResult:
        return run_analysis(request)

    @staticmethod
    def _parse_event_timestamp(event: dict) -> datetime:
        timestamp = event.get("timestamp")

        if not timestamp:
            raise ValueError(
                "Event is missing timestamp."
            )

        try:
            return datetime.fromisoformat(
                timestamp.replace("Z", "+00:00")
            )
        except ValueError as error:
            raise ValueError(
                f"Invalid event timestamp: {timestamp}"
            ) from error

    @staticmethod
    def _resolve_event_type(
        event: dict,
        source_type: str,
    ) -> str:
        event_type = event.get("event_type")

        if event_type:
            return event_type

        if source_type != "auth_log":
            raise ValueError(
                "Event is missing event_type."
            )

        result = str(
            event.get("result", "")
        ).lower()

        legacy_types = {
            "success": "authentication_success",
            "failure": "authentication_failure",
        }

        if result not in legacy_types:
            raise ValueError(
                "Unsupported auth_log result: "
                f"{event.get('result')}"
            )

        return legacy_types[result]

    def _persist_investigation_events(
        self,
        *,
        name: str,
        result: AnalysisResult,
        telemetry_metadata: list[dict],
    ) -> tuple[
        Investigation,
        dict[int, Event],
    ]:
        if not name.strip():
            raise ValueError(
                "Investigation name is required."
            )

        now = datetime.now(timezone.utc)

        finding_count = (
            len(result.detections)
            + len(result.correlations)
        )

        high_severity_count = sum(
            1
            for finding in result.detections
            if finding.get("severity") == "high"
        ) + sum(
            1
            for finding in result.correlations
            if finding.get("severity") == "high"
        )

        investigation = Investigation(
            public_id=(
                f"pending-{uuid4().hex[:16]}"
            ),
            name=name.strip(),
            status="complete",
            created_at=now,
            completed_at=now,
            event_count=len(result.events),
            finding_count=finding_count,
            high_severity_count=(
                high_severity_count
            ),
        )

        self.investigation_repository.add(
            investigation
        )

        self.session.flush()

        investigation.public_id = (
            f"INV-{now.year}-"
            f"{investigation.id:04d}"
        )

        telemetry_sources = {}

        for metadata in telemetry_metadata:
            telemetry_source = TelemetrySource(
                filename=metadata["filename"],
                source_type=metadata[
                    "source_type"
                ],
                file_size=metadata["file_size"],
                sha256=metadata["sha256"],
                original_path=metadata[
                    "original_path"
                ],
            )

            investigation.telemetry_sources.append(
                telemetry_source
            )

            telemetry_sources[
                metadata["source_type"]
            ] = telemetry_source

        event_map = {}

        for event_data in result.events:
            source_type = (
                event_data.get("source")
                or "auth_log"
            )

            telemetry_source = (
                telemetry_sources.get(source_type)
            )

            if telemetry_source is None:
                raise ValueError(
                    "No telemetry source metadata "
                    "for event source: "
                    f"{source_type}"
                )

            event = Event(
                timestamp=(
                    self._parse_event_timestamp(
                        event_data
                    )
                ),
                source=source_type,
                event_id=event_data.get(
                    "event_id"
                ),
                event_type=(
                    self._resolve_event_type(
                        event_data,
                        source_type,
                    )
                ),
                host=event_data.get("host"),
                username=event_data.get(
                    "username"
                ),
                session_id=event_data.get(
                    "session_id"
                ),
                source_ip=event_data.get(
                    "source_ip"
                ),
                destination_ip=event_data.get(
                    "destination_ip"
                ),
                process_name=event_data.get(
                    "process_name"
                ),
                process_id=event_data.get(
                    "process_id"
                ),
                process_guid=event_data.get(
                    "process_guid"
                ),
                parent_process_name=event_data.get(
                    "parent_process_name"
                ),
                command_line=event_data.get(
                    "command_line"
                ),
                result=event_data.get("result"),
                details=event_data.get(
                    "details"
                ) or {},
            )

            investigation.events.append(event)

            telemetry_source.events.append(
                event
            )

            event_map[id(event_data)] = event

        return investigation, event_map

    @staticmethod
    def _parse_optional_timestamp(
        value: str | None,
    ) -> datetime | None:
        if value is None:
            return None

        try:
            return datetime.fromisoformat(
                value.replace("Z", "+00:00")
            )
        except ValueError as error:
            raise ValueError(
                f"Invalid finding timestamp: {value}"
            ) from error

    @staticmethod
    def _comparison_timestamp(
        value: datetime,
    ) -> datetime:
        """
        Return a timezone-safe timestamp for internal comparisons.

        Legacy AuthWatch CSV/JSON timestamps may be timezone-naive,
        while Windows/Linux telemetry can be timezone-aware. For the
        evidence-window comparison only, naive values are treated as
        UTC-equivalent so mixed telemetry cannot raise a naive/aware
        datetime comparison error.
        """
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)

        return value.astimezone(timezone.utc)

    def _find_detection_supporting_events(
        self,
        *,
        detection: dict,
        result: AnalysisResult,
        event_map: dict[int, Event],
    ) -> list[Event]:
        first_seen = self._parse_optional_timestamp(
            detection.get("first_seen")
        )

        last_seen = self._parse_optional_timestamp(
            detection.get("last_seen")
        )

        # V4 must not infer supporting evidence from
        # only a broad investigation time range.
        if first_seen is None and last_seen is None:
            return []

        rule_id = detection.get("rule_id", "")
        details = detection.get("details") or {}

        source_ip = details.get("source_ip")
        username = details.get("username")
        result_value = details.get("result")

        usernames = details.get("usernames") or []
        source_ips = details.get("source_ips") or []

        first_seen_comparison = (
            self._comparison_timestamp(first_seen)
            if first_seen is not None
            else None
        )

        last_seen_comparison = (
            self._comparison_timestamp(last_seen)
            if last_seen is not None
            else None
        )

        supporting_events = []
        seen_events = set()

        for event_data in result.events:
            event_identity = id(event_data)

            if event_identity in seen_events:
                continue

            event_timestamp = (
                self._comparison_timestamp(
                    self._parse_event_timestamp(
                        event_data
                    )
                )
            )

            if (
                first_seen_comparison is not None
                and event_timestamp < first_seen_comparison
            ):
                continue

            if (
                last_seen_comparison is not None
                and event_timestamp > last_seen_comparison
            ):
                continue

            source_type = (
                event_data.get("source")
                or "auth_log"
            )

            event_type = self._resolve_event_type(
                event_data,
                source_type,
            )

            # The six current AUTH-* detection rules
            # are supported only by authentication
            # telemetry.
            if not event_type.startswith(
                "authentication_"
            ):
                continue

            matches = False

            if rule_id == "AUTH-BF-001":
                matches = (
                    event_type
                    == "authentication_failure"
                    and event_data.get("source_ip")
                    == source_ip
                    and event_data.get("username")
                    == username
                )

            elif rule_id == "AUTH-PS-001":
                matches = (
                    event_type
                    == "authentication_failure"
                    and event_data.get("source_ip")
                    == source_ip
                    and event_data.get("username")
                    in usernames
                )

            elif rule_id == "AUTH-SF-001":
                matches = (
                    event_data.get("source_ip")
                    == source_ip
                    and event_data.get("username")
                    == username
                )

            elif rule_id == "AUTH-DA-001":
                matches = (
                    event_data.get("username")
                    == username
                    and event_data.get("source_ip")
                    == source_ip
                    and event_data.get("result")
                    == result_value
                )

            elif rule_id == "AUTH-MA-001":
                matches = (
                    event_data.get("source_ip")
                    == source_ip
                    and event_data.get("username")
                    in usernames
                )

            elif rule_id == "AUTH-MI-001":
                matches = (
                    event_data.get("username")
                    == username
                    and event_data.get("source_ip")
                    in source_ips
                )

            if not matches:
                continue

            event = event_map.get(
                event_identity
            )

            if event is None:
                raise ValueError(
                    "Detection references telemetry "
                    "that was not persisted."
                )

            supporting_events.append(
                event
            )

            seen_events.add(
                event_identity
            )

        return supporting_events

    def _persist_findings(
        self,
        *,
        investigation: Investigation,
        result: AnalysisResult,
        event_map: dict[int, Event],
    ) -> list[Finding]:
        persisted_findings = []

        for detection in result.detections:
            title = detection.get("title")

            if not title:
                raise ValueError(
                    "Detection is missing title."
                )

            finding = Finding(
                finding_type="detection",
                rule_id=detection["rule_id"],
                title=title,
                severity=detection["severity"],
                status="new",
                first_seen=self._parse_optional_timestamp(
                    detection.get("first_seen")
                ),
                last_seen=self._parse_optional_timestamp(
                    detection.get("last_seen")
                ),
                summary=title,
                details=detection.get("details") or {},
                mitre=detection.get("mitre"),
            )

            investigation.findings.append(finding)

            supporting_events = (
                self._find_detection_supporting_events(
                    detection=detection,
                    result=result,
                    event_map=event_map,
                )
            )

            for event in supporting_events:
                finding.finding_events.append(
                    FindingEvent(
                        event=event,
                    )
                )

            persisted_findings.append(finding)

        for correlation in result.correlations:
            title = correlation.get("title")

            if not title:
                raise ValueError(
                    "Correlation is missing title."
                )

            finding = Finding(
                finding_type="correlation",
                rule_id=correlation[
                    "correlation_id"
                ],
                title=title,
                severity=correlation["severity"],
                status="new",
                first_seen=self._parse_optional_timestamp(
                    correlation.get("first_seen")
                ),
                last_seen=self._parse_optional_timestamp(
                    correlation.get("last_seen")
                ),
                summary=title,
                details=correlation.get("details") or {},
                mitre=correlation.get("mitre"),
            )

            investigation.findings.append(finding)

            seen_events = set()

            for related_event in correlation.get(
                "related_events",
                [],
            ):
                event_identity = id(related_event)

                if event_identity in seen_events:
                    continue

                event = event_map.get(event_identity)

                if event is None:
                    raise ValueError(
                        "Correlation references an event "
                        "that was not persisted."
                    )

                finding_event = FindingEvent(
                    event=event,
                )

                finding.finding_events.append(
                    finding_event
                )

                seen_events.add(event_identity)

            persisted_findings.append(finding)

        return persisted_findings

    @staticmethod
    def _create_analysis_request(
        *,
        log_file: str | None = None,
        windows_security: str | None = None,
        sysmon: str | None = None,
        linux_auth: str | None = None,
        linux_year: int | None = None,
        linux_utc_offset: str | None = None,
        disabled_accounts: str | None = None,
        detection_config: str | None = None,
        correlation_config: str | None = None,
    ) -> AnalysisRequest:
        return AnalysisRequest(
            log_file=log_file,
            windows_security=windows_security,
            sysmon=sysmon,
            linux_auth=linux_auth,
            linux_year=linux_year,
            linux_utc_offset=linux_utc_offset,
            disabled_accounts=disabled_accounts,
            detection_config=detection_config,
            correlation_config=correlation_config,
        )

    def analyze_and_store(
        self,
        *,
        name: str,
        log_file: str | None = None,
        windows_security: str | None = None,
        sysmon: str | None = None,
        linux_auth: str | None = None,
        linux_year: int | None = None,
        linux_utc_offset: str | None = None,
        disabled_accounts: str | None = None,
        detection_config: str | None = None,
        correlation_config: str | None = None,
    ) -> Investigation:
        telemetry_metadata = (
            self._build_telemetry_metadata(
                log_file=log_file,
                windows_security=windows_security,
                sysmon=sysmon,
                linux_auth=linux_auth,
            )
        )

        request = self._create_analysis_request(
            log_file=log_file,
            windows_security=windows_security,
            sysmon=sysmon,
            linux_auth=linux_auth,
            linux_year=linux_year,
            linux_utc_offset=linux_utc_offset,
            disabled_accounts=disabled_accounts,
            detection_config=detection_config,
            correlation_config=correlation_config,
        )

        result = self.execute_analysis(request)

        with self.session.begin_nested():
            investigation, event_map = (
                self._persist_investigation_events(
                    name=name,
                    result=result,
                    telemetry_metadata=(
                        telemetry_metadata
                    ),
                )
            )

            self._persist_findings(
                investigation=investigation,
                result=result,
                event_map=event_map,
            )

            self.session.flush()

        return investigation
