from sqlalchemy import select
from sqlalchemy.orm import Session

from src.models.case import Case
from src.models.case_activity import CaseActivity


class CaseRepository:
    def __init__(self, session: Session):
        self.session = session

    def get_by_id(self, case_id: int) -> Case | None:
        return self.session.get(Case, case_id)

    def get_by_public_id(
        self,
        public_id: str,
    ) -> Case | None:
        statement = select(Case).where(
            Case.public_id == public_id
        )

        return self.session.execute(
            statement
        ).scalar_one_or_none()

    def list_all(self) -> list[Case]:
        statement = select(Case).order_by(Case.id)

        return list(
            self.session.execute(statement).scalars().all()
        )

    def list_by_status(
        self,
        status: str,
    ) -> list[Case]:
        statement = (
            select(Case)
            .where(Case.status == status)
            .order_by(Case.id)
        )

        return list(
            self.session.execute(statement).scalars().all()
        )

    def add(self, case: Case) -> None:
        self.session.add(case)

    def list_activities(
        self,
        case_id: int,
    ) -> list[CaseActivity]:
        statement = (
            select(CaseActivity)
            .where(CaseActivity.case_id == case_id)
            .order_by(
                CaseActivity.created_at,
                CaseActivity.id,
            )
        )

        return list(
            self.session.execute(statement).scalars().all()
        )
