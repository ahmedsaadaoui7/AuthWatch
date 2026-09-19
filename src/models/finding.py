from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import Base


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    investigation_id: Mapped[int] = mapped_column(
        ForeignKey(
            "investigations.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    finding_type: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )

    rule_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    severity: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(32),
        default="new",
        nullable=False,
    )

    first_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    last_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    summary: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    details: Mapped[dict] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
    )

    mitre: Mapped[dict | None] = mapped_column(
        JSON,
        nullable=True,
    )

    investigation: Mapped["Investigation"] = relationship(
        back_populates="findings",
    )
