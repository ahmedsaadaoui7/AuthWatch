from uuid import uuid4

from sqlalchemy.orm import Session

from src.models.case import Case
from src.models.case_activity import CaseActivity
from src.repositories.case_repository import CaseRepository

from src.models.case_note import CaseNote
from src.models.case_finding import CaseFinding
from src.repositories.finding_repository import FindingRepository

from datetime import datetime, timezone

class CaseService:
    def __init__(self, session: Session):
        self.session = session
        self.case_repository = CaseRepository(session)
        self.finding_repository = FindingRepository(session)

    def create_case(
        self,
        *,
        title: str,
        priority: str,
    ) -> Case:
        temporary_public_id = (
            f"pending-{uuid4()}"
        )

        case = Case(
            public_id=temporary_public_id,
            title=title,
            priority=priority,
            status="open",
        )

        self.case_repository.add(case)

        self.session.flush()

        case.public_id = f"AW-{case.id:04d}"

        activity = CaseActivity(
            activity_type="case_created",
            description=f"Case {case.public_id} created.",
            details={
                "priority": priority,
                "status": "open",
            },
        )

        case.activities.append(activity)

        return case

    def link_finding(
        self,
        *,
        case_id: int,
        finding_id: int,
    ) -> CaseFinding:
        case = self.case_repository.get_by_id(case_id)

        if case is None:
            raise ValueError("Case not found.")

        finding = self.finding_repository.get_by_id(
            finding_id
        )

        if finding is None:
            raise ValueError("Finding not found.")

        previous_status = finding.status

        case_finding = CaseFinding(
            finding=finding,
        )

        case.case_findings.append(case_finding)

        finding.status = "escalated"

        activity = CaseActivity(
            case=case,
            activity_type="finding_added",
            description=(
                f"Finding {finding.rule_id} linked to case."
            ),
            details={
                "finding_id": finding.id,
                "rule_id": finding.rule_id,
                "previous_status": previous_status,
                "new_status": "escalated",
            },
        )

        case.activities.append(activity)

        return case_finding

    def add_note(
        self,
        *,
        case_id: int,
        content: str,
    ) -> CaseNote:
        case = self.case_repository.get_by_id(case_id)

        if case is None:
            raise ValueError("Case not found.")

        note = CaseNote(
            case=case,
            content=content,
        )

        case.notes.append(note)

        activity = CaseActivity(
            activity_type="note_added",
            description="Analyst note added.",
            details={},
        )

        case.activities.append(activity)

        return note

    def change_priority(
        self,
        *,
        case_id: int,
        priority: str,
    ) -> Case:
        case = self.case_repository.get_by_id(case_id)

        if case is None:
            raise ValueError("Case not found.")

        allowed_priorities = {
            "high",
            "medium",
            "low",
        }

        if priority not in allowed_priorities:
            raise ValueError("Invalid case priority.")

        previous_priority = case.priority

        case.priority = priority

        activity = CaseActivity(
            activity_type="priority_changed",
            description=(
                f"Case priority changed from "
                f"{previous_priority} to {priority}."
            ),
            details={
                "previous_priority": previous_priority,
                "new_priority": priority,
            },
        )

        case.activities.append(activity)

        return case

    def change_status(
        self,
        *,
        case_id: int,
        status: str,
    ) -> Case:
        case = self.case_repository.get_by_id(case_id)

        if case is None:
            raise ValueError("Case not found.")

        allowed_statuses = {
            "open",
            "investigating",
        }

        if status not in allowed_statuses:
            raise ValueError(
                "Invalid case status."
            )

        if case.status == "closed":
            raise ValueError(
                "Closed cases must be reopened."
            )

        previous_status = case.status

        case.status = status

        activity = CaseActivity(
            activity_type="status_changed",
            description=(
                f"Case status changed from "
                f"{previous_status} to {status}."
            ),
            details={
                "previous_status": previous_status,
                "new_status": status,
            },
        )

        case.activities.append(activity)

        return case

    def close_case(
        self,
        *,
        case_id: int,
        resolution: str,
        closing_note: str,
    ) -> Case:
        case = self.case_repository.get_by_id(case_id)

        if case is None:
            raise ValueError("Case not found.")

        if case.status == "closed":
            raise ValueError("Case is already closed.")

        allowed_resolutions = {
            "true_positive",
            "false_positive",
            "benign_activity",
            "other",
        }

        if resolution not in allowed_resolutions:
            raise ValueError("Invalid case resolution.")

        if not closing_note.strip():
            raise ValueError("Closing note is required.")

        previous_status = case.status

        case.status = "closed"
        case.resolution = resolution
        case.closing_note = closing_note
        case.closed_at = datetime.now(timezone.utc)

        activity = CaseActivity(
            activity_type="case_closed",
            description=(
                f"Case closed with resolution "
                f"{resolution}."
            ),
            details={
                "previous_status": previous_status,
                "new_status": "closed",
                "resolution": resolution,
            },
        )

        case.activities.append(activity)

        return case

    def reopen_case(
        self,
        *,
        case_id: int,
    ) -> Case:
        case = self.case_repository.get_by_id(case_id)

        if case is None:
            raise ValueError("Case not found.")

        if case.status != "closed":
            raise ValueError("Only closed cases can be reopened.")

        previous_resolution = case.resolution
        previous_closing_note = case.closing_note
        previous_closed_at = case.closed_at

        case.status = "open"
        case.resolution = None
        case.closing_note = None
        case.closed_at = None

        activity = CaseActivity(
            activity_type="case_reopened",
            description="Case reopened.",
            details={
                "previous_status": "closed",
                "new_status": "open",
                "previous_resolution": previous_resolution,
                "previous_closing_note": previous_closing_note,
                "previous_closed_at": (
                    previous_closed_at.isoformat()
                    if previous_closed_at is not None
                    else None
                ),
            },
        )

        case.activities.append(activity)

        return case

    def load_history(
        self,
        *,
        case_id: int,
    ) -> list[CaseActivity]:
        case = self.case_repository.get_by_id(case_id)

        if case is None:
            raise ValueError("Case not found.")

        return self.case_repository.list_activities(
            case_id
        )
