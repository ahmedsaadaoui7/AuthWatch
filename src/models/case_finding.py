from __future__ import annotations

from sqlalchemy import ForeignKey, Integer, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import Base


class CaseFinding(Base):
    __tablename__ = "case_findings"

    __table_args__ = (
        UniqueConstraint(
            "case_id",
            "finding_id",
            name="uq_case_finding",
        ),
    )

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    case_id: Mapped[int] = mapped_column(
        ForeignKey(
            "cases.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    finding_id: Mapped[int] = mapped_column(
        ForeignKey(
            "findings.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    case: Mapped["Case"] = relationship(
        back_populates="case_findings",
    )

    finding: Mapped["Finding"] = relationship(
        back_populates="case_findings",
    )
