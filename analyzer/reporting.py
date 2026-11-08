
import csv
import json

from pathlib import Path


def convert_report(report):
    """Convert Counter objects into JSON-compatible dictionaries."""
    

    return {
        "total_lines": report["total_lines"],
        "parsed_lines": report["parsed_lines"],
        "malformed_lines": report["malformed_lines"],
        "total_bytes": report["total_bytes"],
        "status_counts": dict(report["status_counts"]),
        "ip_counts": dict(report["ip_counts"]),
        "endpoint_counts": dict(report["endpoint_counts"]),
        "requests_per_minute": {
            minute.strftime("%Y-%m-%d %H:%M"): count
            for minute, count in report["requests_per_minute"].items()
        },
    }


def export_json(report, output_file):
    """Export analysis results as JSON."""

    data = convert_report(report)

    with Path(output_file).open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)


def export_csv(report, output_file):
    """Export analysis results as CSV."""

    output_file = Path(output_file)

    with output_file.open(
        "w", newline="", encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        writer.writerow(["Metric", "Name", "Count"])

        writer.writerow(["Summary", "Total lines", report["total_lines"]])
        writer.writerow(["Summary", "Parsed requests", report["parsed_lines"]])
        writer.writerow(["Summary", "Malformed lines", report["malformed_lines"]])
        writer.writerow(["Summary", "Total response bytes", report["total_bytes"]])

        for status, count in report["status_counts"].items():
            writer.writerow(["HTTP Status", status, count])

        for ip, count in report["ip_counts"].items():
            writer.writerow(["IP Address", ip, count])

        for endpoint, count in report["endpoint_counts"].items():
            writer.writerow(["Endpoint", endpoint, count])

        for minute, count in report["requests_per_minute"].items():
            writer.writerow([
                "Requests per minute",
                minute.strftime("%Y-%m-%d %H:%M"),
                count,
            ])
