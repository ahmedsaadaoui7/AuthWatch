from sqlalchemy import case, or_, select

from sqlalchemy.orm import Session

from datetime import datetime

from src.models.finding import Finding
from src.models.event import Event
from src.models.finding_event import FindingEvent


class FindingRepository:
    def __init__(self, session: Session):
        self.session = session

    def get_by_id(
        self,
        finding_id: int,
    ) -> Finding | None:
        return self.session.get(Finding, finding_id)

    def list_all(self) -> list[Finding]:
        statement = select(Finding).order_by(Finding.id)

        return list(
            self.session.execute(statement).scalars().all()
        )

    def list_by_status(
        self,
        status: str,
    ) -> list[Finding]:
        statement = (
            select(Finding)
            .where(Finding.status == status)
            .order_by(Finding.id)
        )

        return list(
            self.session.execute(statement).scalars().all()
        )

    def add(self, finding: Finding) -> None:
        self.session.add(finding)

    def list_by_severity(
        self,
        severity: str,
    ) -> list[Finding]:
        statement = (
            select(Finding)
            .where(Finding.severity == severity)
            .order_by(Finding.id)
        )

        return list(
            self.session.execute(statement).scalars().all()
        )

    def list_filtered(
        self,
        *,
        search: str | None = None,
        status: str | None = None,
        severity: str | None = None,
        finding_type: str | None = None,
        rule_id: str | None = None,
        investigation_id: int | None = None,
        username: str | None = None,
        host: str | None = None,
        source_ip: str | None = None,
        telemetry_source_id: int | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> list[Finding]:
        statement = select(Finding)

        if search is not None:
            search_pattern = f"%{search}%"

            statement = statement.where(
                or_(
                    Finding.title.ilike(search_pattern),
                    Finding.rule_id.ilike(search_pattern),
                    Finding.summary.ilike(search_pattern),
                )
            )

        if status is not None:
            statement = statement.where(
                Finding.status == status
            )

        if severity is not None:
            statement = statement.where(
                Finding.severity == severity
            )

        if finding_type is not None:
            statement = statement.where(
                Finding.finding_type == finding_type
            )

        if rule_id is not None:
            statement = statement.where(
                Finding.rule_id == rule_id
            )

        if investigation_id is not None:
            statement = statement.where(
                Finding.investigation_id == investigation_id
            )

        if (
            username is not None
            or host is not None
            or source_ip is not None
            or telemetry_source_id is not None
        ):
            statement = (
                statement
                .join(
                    FindingEvent,
                    FindingEvent.finding_id == Finding.id,
                )
                .join(
                    Event,
                    Event.id == FindingEvent.event_id,
                )
                .distinct()
            )

        if username is not None:
            statement = statement.where(
                Event.username == username
            )

        if host is not None:
            statement = statement.where(
                Event.host == host
            )

        if source_ip is not None:
            statement = statement.where(
                Event.source_ip == source_ip
            )

        if telemetry_source_id is not None:
            statement = statement.where(
                Event.telemetry_source_id
                == telemetry_source_id
            )

        if start_time is not None:
            statement = statement.where(
                Finding.last_seen >= start_time
            )

        if end_time is not None:
            statement = statement.where(
                Finding.first_seen <= end_time
            )

        severity_priority = case(
            (Finding.severity == "high", 1),
            (Finding.severity == "medium", 2),
            (Finding.severity == "low", 3),
            else_=4,
        )

        statement = statement.order_by(
            severity_priority,
            Finding.last_seen.desc(),
            Finding.id.desc(),
        )

        return list(
            self.session.execute(statement).scalars().all()
        )

    def list_supporting_events(
        self,
        finding_id: int,
    ) -> list[Event]:
        statement = (
            select(Event)
            .join(
                FindingEvent,
                FindingEvent.event_id == Event.id,
            )
            .where(
                FindingEvent.finding_id == finding_id
            )
            .order_by(
                Event.timestamp,
                Event.id,
            )
        )

        return list(
            self.session.execute(statement).scalars().all()
        )

    def list_related(
        self,
        *,
        investigation_id: int,
        exclude_finding_id: int,
    ) -> list[Finding]:
        statement = (
            select(Finding)
            .where(
                Finding.investigation_id
                == investigation_id
            )
            .where(
                Finding.id != exclude_finding_id
            )
            .order_by(Finding.id)
        )

        return list(
            self.session.execute(statement).scalars().all()
        )
