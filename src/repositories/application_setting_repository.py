from sqlalchemy import select
from sqlalchemy.orm import Session

from src.models.application_setting import ApplicationSetting


class ApplicationSettingRepository:
    def __init__(self, session: Session):
        self.session = session

    def get_by_key(
        self,
        key: str,
    ) -> ApplicationSetting | None:
        statement = select(ApplicationSetting).where(
            ApplicationSetting.key == key
        )

        return self.session.execute(
            statement
        ).scalar_one_or_none()

    def list_all(self) -> list[ApplicationSetting]:
        statement = select(ApplicationSetting).order_by(
            ApplicationSetting.key
        )

        return list(
            self.session.execute(statement).scalars().all()
        )

    def set_value(
        self,
        *,
        key: str,
        value: object,
    ) -> ApplicationSetting:
        setting = self.get_by_key(key)

        if setting is None:
            setting = ApplicationSetting(
                key=key,
                value=value,
            )

            self.session.add(setting)

            # The application session uses autoflush=False.
            # Flush the new setting so another set_value()
            # call in the same transaction can find it.
            self.session.flush()

        else:
            setting.value = value

        return setting
