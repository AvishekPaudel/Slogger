
from collections import Counter

from analyzer.parser import parse_line


def analyze_log_file(logfile):
    """Read a log file and calculate access-log statistics."""

    total_lines = 0
    parsed_lines = 0
    malformed_lines = 0

    status_counts = Counter()
    ip_counts = Counter()
    endpoint_counts = Counter()

    total_bytes = 0

    with logfile.open(
        "r", encoding="utf-8", errors="replace"
    ) as log_file:

        for line in log_file:
            total_lines += 1

            data = parse_line(line)

            if data is None:
                malformed_lines += 1
                continue

            parsed_lines += 1

            status = data["status"]

            status_counts[status] += 1
            ip_counts[data["ip"]] += 1
            endpoint_counts[data["path"]] += 1

            if data["bytes"] is not None:
                total_bytes += data["bytes"]

    return {
        "total_lines": total_lines,
        "parsed_lines": parsed_lines,
        "malformed_lines": malformed_lines,
        "total_bytes": total_bytes,
        "status_counts": status_counts,
        "ip_counts": ip_counts,
        "endpoint_counts": endpoint_counts,
    }
