from __future__ import annotations

from sqlalchemy import ForeignKey, Integer, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import Base


class FindingEvent(Base):
    __tablename__ = "finding_events"

    __table_args__ = (
        UniqueConstraint(
            "finding_id",
            "event_id",
            name="uq_finding_event",
        ),
    )

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    finding_id: Mapped[int] = mapped_column(
        ForeignKey(
            "findings.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    event_id: Mapped[int] = mapped_column(
        ForeignKey(
            "events.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    finding: Mapped["Finding"] = relationship(
        back_populates="finding_events",
    )

    event: Mapped["Event"] = relationship(
        back_populates="finding_events",
    )
