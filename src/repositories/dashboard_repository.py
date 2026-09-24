from collections import Counter
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from src.models import Case, Finding


class DashboardRepository:
    def __init__(self, session: Session):
        self.session = session

    def get_primary_metrics(self) -> dict[str, int]:
        total_findings = self.session.scalar(
            select(func.count(Finding.id))
        ) or 0

        high_findings = self.session.scalar(
            select(func.count(Finding.id)).where(
                Finding.severity == "high"
            )
        ) or 0

        medium_findings = self.session.scalar(
            select(func.count(Finding.id)).where(
                Finding.severity == "medium"
            )
        ) or 0

        open_cases = self.session.scalar(
            select(func.count(Case.id)).where(
                Case.status != "closed"
            )
        ) or 0

        return {
            "total_findings": total_findings,
            "high_findings": high_findings,
            "medium_findings": medium_findings,
            "open_cases": open_cases,
        }

    def get_findings_by_severity(
        self,
    ) -> dict[str, int]:
        rows = self.session.execute(
            select(
                Finding.severity,
                func.count(Finding.id),
            )
            .group_by(Finding.severity)
        ).all()

        return {
            severity: count
            for severity, count in rows
        }

    @staticmethod
    def _extract_entity_values(
        details: dict,
        *,
        singular_key: str,
        plural_key: str | None = None,
    ) -> set[str]:
        values = set()

        singular_value = details.get(singular_key)

        if (
            isinstance(singular_value, str)
            and singular_value.strip()
        ):
            values.add(singular_value)

        if plural_key:
            plural_values = details.get(plural_key)

            if isinstance(plural_values, list):
                for value in plural_values:
                    if (
                        isinstance(value, str)
                        and value.strip()
                    ):
                        values.add(value)

        return values

    def _get_top_entities(
        self,
        *,
        singular_key: str,
        plural_key: str | None = None,
        limit: int,
    ) -> list[dict]:
        details_rows = self.session.scalars(
            select(Finding.details)
        ).all()

        counts = Counter()

        for details in details_rows:
            values = self._extract_entity_values(
                details or {},
                singular_key=singular_key,
                plural_key=plural_key,
            )

            for value in values:
                counts[value] += 1

        ranked = sorted(
            counts.items(),
            key=lambda item: (
                -item[1],
                item[0].lower(),
            ),
        )

        return [
            {
                "value": value,
                "count": count,
            }
            for value, count in ranked[:limit]
        ]

    def get_top_users(
        self,
        *,
        limit: int,
    ) -> list[dict]:
        return self._get_top_entities(
            singular_key="username",
            plural_key="usernames",
            limit=limit,
        )

    def get_top_hosts(
        self,
        *,
        limit: int,
    ) -> list[dict]:
        return self._get_top_entities(
            singular_key="host",
            limit=limit,
        )

    def get_top_source_ips(
        self,
        *,
        limit: int,
    ) -> list[dict]:
        return self._get_top_entities(
            singular_key="source_ip",
            plural_key="source_ips",
            limit=limit,
        )

    def get_recent_high_findings(
        self,
        *,
        limit: int,
    ) -> list[Finding]:
        activity_time = func.coalesce(
            Finding.last_seen,
            Finding.first_seen,
        )

        statement = (
            select(Finding)
            .where(
                Finding.severity == "high"
            )
            .order_by(
                activity_time.desc(),
                Finding.id.desc(),
            )
            .limit(limit)
        )

        return list(
            self.session.scalars(statement).all()
        )

    def get_active_cases(
        self,
        *,
        limit: int,
    ) -> list[Case]:
        statement = (
            select(Case)
            .where(
                Case.status != "closed"
            )
            .order_by(
                Case.created_at.desc(),
                Case.id.desc(),
            )
            .limit(limit)
        )

        return list(
            self.session.scalars(statement).all()
        )

    def get_findings_over_time(
        self,
        *,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> list[dict]:
        date_bucket = func.date(
            Finding.first_seen
        )

        statement = (
            select(
                date_bucket.label("date"),
                func.count(Finding.id).label(
                    "count"
                ),
            )
            .where(
                Finding.first_seen.is_not(None)
            )
        )

        if start_time is not None:
            statement = statement.where(
                Finding.first_seen >= start_time
            )

        if end_time is not None:
            statement = statement.where(
                Finding.first_seen <= end_time
            )

        statement = (
            statement
            .group_by(date_bucket)
            .order_by(date_bucket)
        )

        rows = self.session.execute(
            statement
        ).all()

        return [
            {
                "date": date,
                "count": count,
            }
            for date, count in rows
        ]
