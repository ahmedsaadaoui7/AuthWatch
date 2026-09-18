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


class Event(Base):
    __tablename__ = "events"

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

    telemetry_source_id: Mapped[int] = mapped_column(
        ForeignKey(
            "telemetry_sources.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    source: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    event_id: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )

    event_type: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )

    host: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    username: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    session_id: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    source_ip: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )

    destination_ip: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )

    process_name: Mapped[str | None] = mapped_column(
        String(1024),
        nullable=True,
    )

    process_id: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )

    process_guid: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    parent_process_name: Mapped[str | None] = mapped_column(
        String(1024),
        nullable=True,
    )

    command_line: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    result: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )

    details: Mapped[dict] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
    )

    investigation: Mapped["Investigation"] = relationship(
        back_populates="events",
    )

    telemetry_source: Mapped["TelemetrySource"] = relationship(
        back_populates="events",
    )
