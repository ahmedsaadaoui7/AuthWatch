from sqlalchemy import Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from src.models.base import Base


class ApplicationSetting(Base):
    __tablename__ = "application_settings"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )

    key: Mapped[str] = mapped_column(
        String(128),
        unique=True,
        nullable=False,
    )

    value: Mapped[object] = mapped_column(
        JSON,
        nullable=False,
    )
