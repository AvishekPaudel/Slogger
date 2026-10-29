
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import SimpleTestCase


class AnalyzeLogsTests(SimpleTestCase):
    def test_analyzes_requests_correctly(self):
        sample = (
            '192.168.1.10 - - [27/Oct/2026:09:00:00 +0545] '
            '"GET / HTTP/1.1" 200 1024\n'
            '192.168.1.11 - - [27/Oct/2026:09:00:05 +0545] '
            '"GET /login HTTP/1.1" 404 512\n'
            '192.168.1.10 - - [27/Oct/2026:09:01:00 +0545] '
            '"GET /api HTTP/1.1" 500 120\n'
        )

        with TemporaryDirectory() as directory:
            log_path = Path(directory) / "access.log"
            log_path.write_text(sample, encoding="utf-8")

            output = StringIO()
            call_command("analyze_logs", str(log_path), stdout=output)

        report = output.getvalue()
        self.assertIn("Total lines: 3", report)
        self.assertIn("Parsed requests: 3", report)
        self.assertIn("Successful (2xx): 1", report)
        self.assertIn("Client errors (4xx): 1", report)
        self.assertIn("Server errors (5xx): 1", report)
        self.assertIn("Total response bytes: 1656", report)

    def test_skips_malformed_lines(self):
        with TemporaryDirectory() as directory:
            log_path = Path(directory) / "access.log"
            log_path.write_text(
                "this is not a valid access log\n",
                encoding="utf-8",
            )

            output = StringIO()
            call_command("analyze_logs", str(log_path), stdout=output)

        report = output.getvalue()
        self.assertIn("Total lines: 1", report)
        self.assertIn("Parsed requests: 0", report)
        self.assertIn("Malformed lines: 1", report)

    def test_missing_file_raises_command_error(self):
        with TemporaryDirectory() as directory:
            missing_path = Path(directory) / "missing.log"

            with self.assertRaises(CommandError):
                call_command("analyze_logs", str(missing_path))
