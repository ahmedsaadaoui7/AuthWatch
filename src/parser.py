import csv
import json
from datetime import datetime


REQUIRED_FIELDS = {"timestamp", "username", "source_ip", "result"}
VALID_RESULTS = {"success", "failure"}


def validate_event(event, row_number):
    for field in REQUIRED_FIELDS:
        value = event.get(field)

        if not isinstance(value, str) or not value.strip():
            raise ValueError(
                f"Row {row_number}: required field '{field}' "
                "must be a non-empty string"
            )

    if event["result"] not in VALID_RESULTS:
        raise ValueError(
            f"Row {row_number}: invalid authentication result "
            f"'{event['result']}'"
        )

    try:
        datetime.fromisoformat(event["timestamp"])
    except ValueError as error:
        raise ValueError(
            f"Row {row_number}: invalid timestamp "
            f"'{event['timestamp']}'"
        ) from error


def load_csv_auth_events(file_path):
    events = []

    with open(file_path, newline="", encoding="utf-8") as csv_file:
        reader = csv.DictReader(csv_file)

        if not REQUIRED_FIELDS.issubset(reader.fieldnames or []):
            raise ValueError(
                "CSV file is missing one or more required fields"
            )

        for row_number, row in enumerate(reader, start=2):
            validate_event(row, row_number)
            events.append(row)

    return events


def load_json_auth_events(file_path):
    events = []

    with open(file_path, encoding="utf-8") as json_file:
        data = json.load(json_file)

    if not isinstance(data, list):
        raise ValueError(
            "JSON authentication log must be a list"
        )

    for row_number, event in enumerate(data, start=1):
        if not isinstance(event, dict):
            raise ValueError(
                "JSON authentication event must be an object"
            )

        validate_event(event, row_number)
        events.append(event)

    return events


def load_auth_events(file_path):
    file_path_string = str(file_path).lower()

    if file_path_string.endswith(".json"):
        return load_json_auth_events(file_path)

    if file_path_string.endswith(".csv"):
        return load_csv_auth_events(file_path)

    raise ValueError(
        "Unsupported authentication log format: expected .csv or .json"
    )


def load_disabled_accounts(file_path):
    with open(file_path, encoding="utf-8") as account_file:
        return {
            line.strip()
            for line in account_file
            if line.strip()
        }
