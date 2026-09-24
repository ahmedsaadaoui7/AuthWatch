from src import app_paths


def test_app_data_directory_is_app_specific(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        app_paths,
        "_get_base_data_location",
        lambda: tmp_path / "data",
    )

    directory = (
        app_paths.get_app_data_directory()
    )

    assert directory == (
        tmp_path
        / "data"
        / "AuthWatch"
    )

    assert directory.exists()
    assert directory.is_dir()


def test_database_path_is_inside_app_data(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        app_paths,
        "_get_base_data_location",
        lambda: tmp_path / "data",
    )

    database_path = (
        app_paths.get_database_path()
    )

    assert database_path == (
        tmp_path
        / "data"
        / "AuthWatch"
        / "authwatch.db"
    )


def test_log_directory_is_inside_app_data(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        app_paths,
        "_get_base_data_location",
        lambda: tmp_path / "data",
    )

    log_directory = (
        app_paths.get_log_directory()
    )

    assert log_directory == (
        tmp_path
        / "data"
        / "AuthWatch"
        / "logs"
    )

    assert log_directory.exists()
