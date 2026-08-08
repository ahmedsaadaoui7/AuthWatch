import csv
from datetime import datetime


REQUIRED_FIELDS = {"timestamp", "username", "source_ip", "result"}
VALID_RESULTS = {"success", "failure"}


def validate_event(event, row_number):
    for field in REQUIRED_FIELDS:
        value = event.get(field)

        if value is None or not value.strip():
            raise ValueError(
                f"Row {row_number}: required field '{field}' is empty"
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


def load_auth_events(file_path):
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
