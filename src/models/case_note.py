from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import Base


class CaseNote(Base):
    __tablename__ = "case_notes"

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

    content: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    case: Mapped["Case"] = relationship(
        back_populates="notes",
    )
