def format_alert_details(details):
    lines = []

    for key, value in details.items():
        label = key.replace("_", " ").capitalize()

        if key == "source_ip":
            label = "Source IP"
        elif key == "source_ips":
            label = "Source IPs"
        elif key == "unique_source_ips":
            label = "Unique source IPs"

        if isinstance(value, list):
            value = ", ".join(str(item) for item in value)

        lines.append(f"{label}: {value}")

    return lines
