
import re


LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ '
    r'\[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) HTTP/[^"]+" '
    r'(?P<status>\d{3}) (?P<bytes>\d+|-)$'
)


def parse_line(line):
    """Parse one Nginx-style access log line.

    Return a dictionary when valid, or None when invalid.
    """
    match = LOG_PATTERN.match(line.rstrip("\r\n"))

    if not match:
        return None

    data = match.groupdict()

    data["status"] = int(data["status"])
    data["bytes"] = (
        int(data["bytes"]) if data["bytes"] != "-" else None
    )

    return data
