from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy.orm import Session

from src.models.case import Case
from src.models.case_activity import CaseActivity
from src.models.case_finding import CaseFinding
from src.models.case_note import CaseNote
from src.repositories.case_repository import CaseRepository
from src.repositories.finding_repository import FindingRepository


class CaseService:
    def __init__(self, session: Session):
        self.session = session
        self.case_repository = CaseRepository(session)
        self.finding_repository = FindingRepository(session)

    def get_case(
        self,
        case_id: int,
    ) -> Case:
        case = self.case_repository.get_by_id(case_id)

        if case is None:
            raise ValueError("Case not found.")

        return case

    def list_cases(self) -> list[Case]:
        return self.case_repository.list_all()

    def create_case(
        self,
        *,
        title: str,
        priority: str,
    ) -> Case:
        title = title.strip()

        if not title:
            raise ValueError("Case title is required.")

        allowed_priorities = {
            "high",
            "medium",
            "low",
        }

        if priority not in allowed_priorities:
            raise ValueError("Invalid case priority.")

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

    def create_case_from_finding(
        self,
        *,
        finding_id: int,
        title: str,
        priority: str,
    ) -> Case:
        finding = self.finding_repository.get_by_id(
            finding_id
        )

        if finding is None:
            raise ValueError("Finding not found.")

        if finding.status == "escalated":
            raise ValueError(
                "Finding is already escalated."
            )

        case = self.create_case(
            title=title,
            priority=priority,
        )

        self.link_finding(
            case_id=case.id,
            finding_id=finding_id,
        )

        return case

    def link_finding(
        self,
        *,
        case_id: int,
        finding_id: int,
    ) -> CaseFinding:
        case = self.get_case(case_id)

        if case.status == "closed":
            raise ValueError(
                "Cannot add findings to a closed case."
            )

        finding = self.finding_repository.get_by_id(
            finding_id
        )

        if finding is None:
            raise ValueError("Finding not found.")

        for existing_link in case.case_findings:
            linked_id = existing_link.finding_id

            if (
                linked_id == finding_id
                or (
                    existing_link.finding is not None
                    and existing_link.finding.id
                    == finding_id
                )
            ):
                raise ValueError(
                    "Finding is already linked to this case."
                )

        previous_status = finding.status

        case_finding = CaseFinding(
            finding=finding,
        )

        case.case_findings.append(case_finding)

        finding.status = "escalated"

        activity = CaseActivity(
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
        case = self.get_case(case_id)
        content = content.strip()

        if not content:
            raise ValueError("Case note cannot be empty.")

        note = CaseNote(
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
        case = self.get_case(case_id)

        allowed_priorities = {
            "high",
            "medium",
            "low",
        }

        if priority not in allowed_priorities:
            raise ValueError("Invalid case priority.")

        previous_priority = case.priority

        if previous_priority == priority:
            return case

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
        case = self.get_case(case_id)

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

        if previous_status == status:
            return case

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
        case = self.get_case(case_id)

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

        closing_note = closing_note.strip()

        if not closing_note:
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
        case = self.get_case(case_id)

        if case.status != "closed":
            raise ValueError(
                "Only closed cases can be reopened."
            )

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

    def load_linked_findings(
        self,
        *,
        case_id: int,
    ) -> list:
        case = self.get_case(case_id)

        links = sorted(
            case.case_findings,
            key=lambda link: (
                link.id
                if link.id is not None
                else 0
            ),
        )

        return [
            link.finding
            for link in links
            if link.finding is not None
        ]

    def load_notes(
        self,
        *,
        case_id: int,
    ) -> list[CaseNote]:
        case = self.get_case(case_id)

        return sorted(
            case.notes,
            key=lambda note: (
                note.created_at,
                note.id
                if note.id is not None
                else 0,
            ),
        )

    def load_history(
        self,
        *,
        case_id: int,
    ) -> list[CaseActivity]:
        self.get_case(case_id)

        return self.case_repository.list_activities(
            case_id
        )
