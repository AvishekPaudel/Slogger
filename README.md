Slogger — Log Analyzer

Slogger is a Python and Django-based log analyzer designed to extract useful statistics from web server access logs. It currently analyzes Nginx-style access logs through a custom Django management command.

The project starts with simple, single-machine log analysis and aims to evolve into a scalable, distributed logging and reporting system.

Features

Parse Nginx-style HTTP access logs.

Count total log lines and successfully parsed requests.

Detect malformed log entries.

Group HTTP responses into 2xx, 3xx, 4xx, and 5xx categories.

Count individual HTTP status codes.

Identify the most active IP addresses.

Identify the most frequently requested endpoints.

Calculate total response bytes.

Handle missing log files with a clear error message.

Process logs line by line to avoid loading the entire file into memory.

Technology Stack

Language: Python

Framework: Django 6.0.4

Log format: Nginx-style access logs

Testing: Django test framework

Project Structure

Slogger/
├── manage.py
├── Slogger/
│   ├── __init__.py
│   ├── settings.py
│   ├── urls.py
│   ├── asgi.py
│   └── wsgi.py
├── analyzer/
│   ├── __init__.py
│   ├── admin.py
│   ├── apps.py
│   ├── tests.py
│   ├── views.py
│   └── management/
│       └── commands/
│           ├── __init__.py
│           └── analyze_logs.py
├── logs/
│   └── access.log
├── reports/
├── requirements.txt
└── README.md

Note: The structure above illustrates the intended layout. Some files, including requirements.txt, may need to be created if they don't already exist.

Getting Started

1. Clone the repository

git clone https://github.com/YOUR_USERNAME/Slogger.git
cd Slogger

Replace YOUR_USERNAME with your GitHub username and use your actual repository URL.

2. Create a virtual environment

python3 -m venv .venv
source .venv/bin/activate

3. Install dependencies

If requirements.txt exists:

pip install -r requirements.txt

Otherwise, install Django:

pip install "Django==6.0.4"

You can create a dependency file for the current environment with:

pip freeze > requirements.txt

For a cleaner project, keep only the dependencies the application actually requires.

4. Run Django checks

python3 manage.py check

5. Prepare a log file

Place your Nginx-style access log at logs/access.log, or specify another supported log file path.

Example log entries:

192.168.1.10 - - [27/Oct/2026:09:00:00 +0545] "GET / HTTP/1.1" 200 1024
192.168.1.11 - - [27/Oct/2026:09:00:05 +0545] "GET /login HTTP/1.1" 404 512
192.168.1.12 - - [27/Oct/2026:09:01:00 +0545] "GET /api/users HTTP/1.1" 500 120

These are illustrative sample entries, not logs from a live server.

6. Analyze the logs

Run the analyzer using Django's custom management command:

python3 manage.py analyze_logs logs/access.log

You can also analyze a different file:

python3 manage.py analyze_logs /path/to/access.log

7. Run automated tests

python3 manage.py test analyzer

The tests cover request statistics, malformed log entries, and missing-file handling.

Example Output

========== LOG ANALYSIS ==========
File: logs/access.log
Total lines: 10
Parsed requests: 10
Malformed lines: 0
Total response bytes: 6098

HTTP status groups:
  Successful (2xx): 5
  Redirects (3xx): 1
  Client errors (4xx): 2
  Server errors (5xx): 2

Status-code counts:
  200: 5
  302: 1
  404: 2
  500: 1
  503: 1
==================================

Actual output depends on the contents of the input file.

Current Limitations

Slogger is an early-stage project. The current implementation:

Supports a specific Nginx-style access-log format.

Processes one file per command execution.

Keeps aggregation statistics in memory.

Does not yet collect logs from remote machines.

Does not yet provide a web dashboard or reporting API.

Does not yet include distributed ingestion or background workers.