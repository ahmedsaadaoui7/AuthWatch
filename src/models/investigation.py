from __future__ import annotations
from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import Base


class Investigation(Base):
    __tablename__ = "investigations"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    public_id: Mapped[str] = mapped_column(
        String(32),
        unique=True,
        nullable=False,
    )

    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    event_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    finding_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    high_severity_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    telemetry_sources: Mapped[list["TelemetrySource"]] = relationship(
        back_populates="investigation",
        cascade="all, delete-orphan",
    )
