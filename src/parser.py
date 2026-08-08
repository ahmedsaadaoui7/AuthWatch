import csv

REQUIRED_FIELDS = {"timestamp", "username", "source_ip", "result"}


def load_auth_events(file_path):
    events = []

    with open(file_path, newline="", encoding="utf-8") as csv_file:
        reader = csv.DictReader(csv_file)

        if not REQUIRED_FIELDS.issubset(reader.fieldnames or []):
            raise ValueError("CSV file is missing one or more required fields")

        for row in reader:
            events.append(row)

    return events
