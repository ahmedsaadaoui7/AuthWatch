from sqlalchemy.orm import Session

from src.models.finding import Finding
from src.repositories.finding_repository import FindingRepository

from src.models.event import Event
from src.models.case_finding import CaseFinding
from src.services.case_service import CaseService


class FindingService:
    def __init__(self, session: Session):
        self.session = session
        self.finding_repository = FindingRepository(session)
        self.case_service = CaseService(session)

    def get_finding(
        self,
        finding_id: int,
    ) -> Finding:
        finding = self.finding_repository.get_by_id(
            finding_id
        )

        if finding is None:
            raise ValueError("Finding not found.")

        return finding

    def list_findings(
        self,
        **filters,
    ) -> list[Finding]:
        return self.finding_repository.list_filtered(
            **filters
        )

    def mark_reviewed(
        self,
        *,
        finding_id: int,
    ) -> Finding:
        finding = self.get_finding(finding_id)

        finding.status = "reviewed"

        return finding

    def mark_escalated(
        self,
        *,
        finding_id: int,
        case_id: int,
    ) -> CaseFinding:
        self.get_finding(finding_id)

        return self.case_service.link_finding(
            case_id=case_id,
            finding_id=finding_id,
        )

    def load_supporting_evidence(
        self,
        *,
        finding_id: int,
    ) -> list[Event]:
        self.get_finding(finding_id)

        return self.finding_repository.list_supporting_events(
            finding_id
        )

    def load_related_findings(
        self,
        *,
        finding_id: int,
    ) -> list[Finding]:
        finding = self.get_finding(finding_id)

        return self.finding_repository.list_related(
            investigation_id=finding.investigation_id,
            exclude_finding_id=finding.id,
        )
