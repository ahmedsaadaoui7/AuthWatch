from __future__ import annotations

from sqlalchemy import BigInteger, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import Base


class TelemetrySource(Base):
    __tablename__ = "telemetry_sources"

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

    filename: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    source_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    file_size: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
    )

    sha256: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    original_path: Mapped[str] = mapped_column(
        String(2048),
        nullable=False,
    )

    investigation: Mapped["Investigation"] = relationship(
        back_populates="telemetry_sources",
    )

    events: Mapped[list["Event"]] = relationship(
        back_populates="telemetry_source",
    )
