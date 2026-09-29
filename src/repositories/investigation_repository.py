from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from src.models.case import Case
from src.models.case_finding import CaseFinding

from src.models.finding import Finding
from src.models.investigation import Investigation
from src.models.event import Event


class InvestigationRepository:
    def __init__(self, session: Session):
        self.session = session

    def get_by_id(
        self,
        investigation_id: int,
    ) -> Investigation | None:
        return self.session.get(
            Investigation,
            investigation_id,
        )

    def get_by_public_id(
        self,
        public_id: str,
    ) -> Investigation | None:
        statement = select(Investigation).where(
            Investigation.public_id == public_id
        )

        return self.session.execute(
            statement
        ).scalar_one_or_none()

    def list_all(self) -> list[Investigation]:
        statement = select(Investigation).order_by(
            Investigation.id
        )

        return list(
            self.session.execute(statement).scalars().all()
        )

    def add(
        self,
        investigation: Investigation,
    ) -> None:
        self.session.add(investigation)

    def list_filtered(
        self,
        *,
        search: str | None = None,
        status: str | None = None,
    ) -> list[Investigation]:
        statement = select(Investigation)

        if search is not None:
            search_pattern = f"%{search}%"

            statement = statement.where(
                or_(
                    Investigation.name.ilike(
                        search_pattern
                    ),
                    Investigation.public_id.ilike(
                        search_pattern
                    ),
                )
            )

        if status is not None:
            statement = statement.where(
                Investigation.status == status
            )

        statement = statement.order_by(
            Investigation.id
        )

        return list(
            self.session.execute(statement).scalars().all()
        )

    def list_by_status(
        self,
        status: str,
    ) -> list[Investigation]:
        statement = (
            select(Investigation)
            .where(Investigation.status == status)
            .order_by(Investigation.id)
        )

        return list(
            self.session.execute(statement).scalars().all()
        )

    def search(
        self,
        query: str,
    ) -> list[Investigation]:
        search_pattern = f"%{query}%"

        statement = (
            select(Investigation)
            .where(
                or_(
                    Investigation.name.ilike(
                        search_pattern
                    ),
                    Investigation.public_id.ilike(
                        search_pattern
                    ),
                )
            )
            .order_by(Investigation.id)
        )

        return list(
            self.session.execute(statement).scalars().all()
        )

    def list_events(
        self,
        investigation_id: int,
    ) -> list[Event]:
        statement = (
            select(Event)
            .where(
                Event.investigation_id
                == investigation_id
            )
            .order_by(
                Event.timestamp,
                Event.id,
            )
        )

        return list(
            self.session.execute(statement).scalars().all()
        )

    def list_findings(
        self,
        investigation_id: int,
    ) -> list[Finding]:
        statement = (
            select(Finding)
            .where(
                Finding.investigation_id
                == investigation_id
            )
            .order_by(Finding.id)
        )

        return list(
            self.session.execute(statement).scalars().all()
        )

    def list_related_cases(
        self,
        investigation_id: int,
    ) -> list[Case]:
        statement = (
            select(Case)
            .join(
                CaseFinding,
                CaseFinding.case_id == Case.id,
            )
            .join(
                Finding,
                Finding.id == CaseFinding.finding_id,
            )
            .where(
                Finding.investigation_id
                == investigation_id
            )
            .distinct()
            .order_by(Case.id)
        )

        return list(
            self.session.execute(statement).scalars().all()
        )
