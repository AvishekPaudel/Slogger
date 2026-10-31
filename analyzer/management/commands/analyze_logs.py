
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from analyzer.services import analyze_log_file


class Command(BaseCommand):
    help = "Analyze an Nginx-style access log."

    def add_arguments(self, parser):
        parser.add_argument(
            "logfile",
            type=Path,
            help="Path to the access log file",
        )

        parser.add_argument(
            "--top",
            type=int,
            default=5,
            help="Number of top IP addresses and endpoints to display",
        )

    def handle(self, *args, **options):
        logfile = options["logfile"]
        top_n = options["top"]

        if top_n < 1:
            raise CommandError("--top must be at least 1")

        if not logfile.is_file():
            raise CommandError(f"Log file not found: {logfile}")

        try:
            report = analyze_log_file(logfile)
        except OSError as exc:
            raise CommandError(
                f"Unable to read {logfile}: {exc}"
            ) from exc

        self.stdout.write("\n========== LOG ANALYSIS ==========")
        self.stdout.write(f"File: {logfile}")
        self.stdout.write(f"Total lines: {report['total_lines']}")
        self.stdout.write(f"Parsed requests: {report['parsed_lines']}")
        self.stdout.write(f"Malformed lines: {report['malformed_lines']}")
        self.stdout.write(f"Total response bytes: {report['total_bytes']}")

        self.stdout.write("\nHTTP status groups:")

        for group, label in [
            (2, "Successful (2xx)"),
            (3, "Redirects (3xx)"),
            (4, "Client errors (4xx)"),
            (5, "Server errors (5xx)"),
        ]:
            count = sum(
                n for code, n in report["status_counts"].items()
                if code // 100 == group
            )
            self.stdout.write(f"  {label}: {count}")

        self.stdout.write("\nStatus-code counts:")

        for status, count in sorted(report["status_counts"].items()):
            self.stdout.write(f"  {status}: {count}")

        self.stdout.write("\nTop IP addresses:")

        for ip, count in report["ip_counts"].most_common(top_n):
            self.stdout.write(f"  {ip}: {count}")

        self.stdout.write("\nTop endpoints:")

        for endpoint, count in report["endpoint_counts"].most_common(top_n):
            self.stdout.write(f"  {endpoint}: {count}")

        self.stdout.write("==================================")
