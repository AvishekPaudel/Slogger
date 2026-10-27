from collections import Counter
from pathlib import Path
import re

from django.core.management.base import BaseCommand, CommandError


LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ '
    r'\[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) HTTP/[^"]+" '
    r'(?P<status>\d{3}) (?P<bytes>\d+|-)$'
)


class Command(BaseCommand):
    help = "Analyze an Nginx-style access log."

    def add_arguments(self, parser):
        parser.add_argument(
            "logfile",
            type=Path,
            help="Path to the access log file",
        )

    def handle(self, *args, **options):
        logfile = options["logfile"]

        if not logfile.is_file():
            raise CommandError(f"Log file not found: {logfile}")

        total_lines = 0
        parsed_lines = 0
        malformed_lines = 0
        status_counts = Counter()
        ip_counts = Counter()
        endpoint_counts = Counter()
        total_bytes = 0

        try:
            with logfile.open(
                "r", encoding="utf-8", errors="replace"
            ) as log_file:
                for line in log_file:
                    total_lines += 1
                    match = LOG_PATTERN.match(line.rstrip("\r\n"))

                    if not match:
                        malformed_lines += 1
                        continue

                    parsed_lines += 1
                    data = match.groupdict()

                    status = int(data["status"])
                    status_counts[status] += 1
                    ip_counts[data["ip"]] += 1
                    endpoint_counts[data["path"]] += 1

                    if data["bytes"] != "-":
                        total_bytes += int(data["bytes"])

        except OSError as exc:
            raise CommandError(
                f"Unable to read {logfile}: {exc}"
            ) from exc

        self.stdout.write("\n========== LOG ANALYSIS ==========")
        self.stdout.write(f"File: {logfile}")
        self.stdout.write(f"Total lines: {total_lines}")
        self.stdout.write(f"Parsed requests: {parsed_lines}")
        self.stdout.write(f"Malformed lines: {malformed_lines}")
        self.stdout.write(f"Total response bytes: {total_bytes}")

        self.stdout.write("\nHTTP status groups:")
        for group, label in [
            (2, "Successful (2xx)"),
            (3, "Redirects (3xx)"),
            (4, "Client errors (4xx)"),
            (5, "Server errors (5xx)"),
        ]:
            count = sum(
                n for code, n in status_counts.items()
                if code // 100 == group
            )
            self.stdout.write(f"  {label}: {count}")

        self.stdout.write("\nStatus-code counts:")
        for status, count in sorted(status_counts.items()):
            self.stdout.write(f"  {status}: {count}")

        self.stdout.write("\nTop IP addresses:")
        for ip, count in ip_counts.most_common(5):
            self.stdout.write(f"  {ip}: {count}")

        self.stdout.write("\nTop endpoints:")
        for endpoint, count in endpoint_counts.most_common(5):
            self.stdout.write(f"  {endpoint}: {count}")

        self.stdout.write("==================================")
