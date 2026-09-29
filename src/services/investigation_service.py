from sqlalchemy.orm import Session

from src.models.case import Case
from src.models.finding import Finding
from src.models.event import Event
from src.models.investigation import Investigation
from src.repositories.investigation_repository import (
    InvestigationRepository,
)

from pathlib import Path

from src.repositories.finding_repository import FindingRepository
from src.reporter import (
    generate_investigation_json_report,
    generate_investigation_markdown_report,
)


class InvestigationService:
    def __init__(self, session: Session):
        self.session = session
        self.investigation_repository = (
            InvestigationRepository(session)
        )
        self.finding_repository = FindingRepository(session)

    def get_investigation(
        self,
        investigation_id: int,
    ) -> Investigation:
        investigation = (
            self.investigation_repository.get_by_id(
                investigation_id
            )
        )

        if investigation is None:
            raise ValueError(
                "Investigation not found."
            )

        return investigation

    def list_investigations(
        self,
        **filters,
    ) -> list[Investigation]:
        return (
            self.investigation_repository.list_filtered(
                **filters
            )
        )

    def load_timeline(
        self,
        *,
        investigation_id: int,
    ) -> list[Event]:
        self.get_investigation(investigation_id)

        return self.investigation_repository.list_events(
            investigation_id
        )

    def load_affected_entities(
        self,
        *,
        investigation_id: int,
    ) -> dict[str, list[str]]:
        events = self.load_timeline(
            investigation_id=investigation_id,
        )

        users = {
            event.username
            for event in events
            if event.username is not None
        }

        hosts = {
            event.host
            for event in events
            if event.host is not None
        }

        source_ips = {
            event.source_ip
            for event in events
            if event.source_ip is not None
        }

        return {
            "users": sorted(users),
            "hosts": sorted(hosts),
            "source_ips": sorted(source_ips),
        }

    def load_findings(
        self,
        *,
        investigation_id: int,
    ) -> list[Finding]:
        self.get_investigation(investigation_id)

        return self.investigation_repository.list_findings(
            investigation_id
        )

    def load_related_cases(
        self,
        *,
        investigation_id: int,
    ) -> list[Case]:
        self.get_investigation(investigation_id)

        return (
            self.investigation_repository.list_related_cases(
                investigation_id
            )
        )


    @staticmethod
    def _format_datetime(value):
        if value is None:
            return None

        return value.isoformat()

    @staticmethod
    def _event_to_report_dict(
        event: Event,
    ) -> dict:
        return {
            "timestamp": event.timestamp.isoformat(),
            "source": event.source,
            "event_id": event.event_id,
            "event_type": event.event_type,
            "host": event.host,
            "username": event.username,
            "session_id": event.session_id,
            "source_ip": event.source_ip,
            "destination_ip": event.destination_ip,
            "process_name": event.process_name,
            "process_id": event.process_id,
            "process_guid": event.process_guid,
            "parent_process_name": event.parent_process_name,
            "command_line": event.command_line,
            "result": event.result,
            "details": event.details,
        }


    def _build_report_inputs(
        self,
        *,
        investigation_id: int,
    ) -> tuple[list[dict], list[dict]]:
        findings = self.load_findings(
            investigation_id=investigation_id,
        )

        alerts = []
        correlations = []

        for finding in findings:
            common = {
                "title": finding.title,
                "severity": finding.severity,
                "first_seen": self._format_datetime(
                    finding.first_seen
                ),
                "last_seen": self._format_datetime(
                    finding.last_seen
                ),
                "summary": finding.summary,
                "details": finding.details,
                "mitre": finding.mitre,
            }

            if finding.finding_type == "detection":
                alerts.append({
                    **common,
                    "rule_id": finding.rule_id,
                })

            elif finding.finding_type == "correlation":
                events = (
                    self.finding_repository
                    .list_supporting_events(finding.id)
                )

                correlations.append({
                    **common,
                    "correlation_id": finding.rule_id,
                    "related_events": [
                        self._event_to_report_dict(event)
                        for event in events
                    ],
                })

        return alerts, correlations

    def export_investigation(
        self,
        *,
        investigation_id: int,
        export_format: str,
        output_path,
    ) -> Path:
        self.get_investigation(investigation_id)

        alerts, correlations = self._build_report_inputs(
            investigation_id=investigation_id,
        )

        if export_format == "json":
            return generate_investigation_json_report(
                alerts,
                correlations,
                output_path,
            )

        if export_format == "markdown":
            return generate_investigation_markdown_report(
                alerts,
                correlations,
                output_path,
            )

        raise ValueError(
            "Unsupported investigation export format."
        )

    def export_investigation(self,*,investigation_id: int,export_format: str,output_path,) -> Path:
        self.get_investigation(investigation_id)

        alerts, correlations = self._build_report_inputs(
            investigation_id=investigation_id,
        )

        investigation_events = self.load_timeline(
            investigation_id=investigation_id,
        )

        report_events = [
            self._event_to_report_dict(event)
            for event in investigation_events
        ]

        if export_format == "json":
            return generate_investigation_json_report(
                alerts,
                correlations,
                output_path,
                events=report_events,
            )

        if export_format == "markdown":
            return generate_investigation_markdown_report(
                alerts,
                correlations,
                output_path,
                events=report_events,
            )

        raise ValueError(
            "Unsupported investigation export format."
        )
