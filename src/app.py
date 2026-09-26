from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtCore import QUrl
from PySide6.QtGui import QGuiApplication, QIcon
from PySide6.QtQml import QQmlApplicationEngine

from src.database import (
    create_database_engine,
    create_session_factory,
)
from src.database_migrations import upgrade_database
from src.services.dashboard_service import DashboardService
from src.viewmodels.analysis_viewmodel import AnalysisViewModel
from src.viewmodels.dashboard_viewmodel import DashboardViewModel


PROJECT_ROOT = Path(__file__).resolve().parent.parent
MAIN_QML = PROJECT_ROOT / "qml" / "main.qml"
APP_ICON = (
    PROJECT_ROOT
    / "qml"
    / "assets"
    / "authwatch-app-icon.png"
)


def main() -> int:
    app = QGuiApplication(sys.argv)

    app.setApplicationName("AuthWatch")
    app.setApplicationDisplayName(
        "AuthWatch Security Operations"
    )
    app.setOrganizationName("AuthWatch")

    if APP_ICON.exists():
        app.setWindowIcon(
            QIcon(str(APP_ICON))
        )

    database_path = upgrade_database()

    database_engine = create_database_engine(
        database_path
    )

    SessionLocal = create_session_factory(
        database_engine
    )

    # Main-thread session used by dashboard services.
    session = SessionLocal()

    dashboard_service = DashboardService(
        session
    )

    dashboard_viewmodel = DashboardViewModel(
        dashboard_service
    )

    # AnalysisViewModel receives the session factory,
    # not the existing GUI-thread session.
    #
    # Its worker creates its own SQLAlchemy session
    # inside the analysis thread.
    analysis_viewmodel = AnalysisViewModel(
        SessionLocal
    )

    qml_engine = QQmlApplicationEngine()

    context = qml_engine.rootContext()

    context.setContextProperty(
        "dashboardViewModel",
        dashboard_viewmodel,
    )

    context.setContextProperty(
        "analysisViewModel",
        analysis_viewmodel,
    )

    qml_engine.load(
        QUrl.fromLocalFile(
            str(MAIN_QML)
        )
    )

    if not qml_engine.rootObjects():
        session.close()
        database_engine.dispose()
        return 1

    exit_code = app.exec()

    # Destroy QML objects while the Python
    # ViewModels are still alive.
    del qml_engine

    session.close()
    database_engine.dispose()

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
