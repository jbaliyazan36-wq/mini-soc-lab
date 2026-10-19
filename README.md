# Mini SOC Lab

An educational Python project that analyzes **synthetic** authentication logs and
detects suspicious security events, in the style of the work a Security Operations
Center (SOC) analyst does every day.

> **Disclaimer:** This is a learning project, not a production security tool. All
> log data is synthetic. IP addresses come from the documentation ranges reserved by
> RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), and user names are
> fictional. No real people, systems, or networks are represented.

## Learning Goals

- Read and parse raw log data into structured records.
- Recognize common authentication attack patterns.
- Translate detection logic into clear, testable Python code.
- Present findings the way a SOC analyst would report them.

## Features

- Parses `key=value` log lines and validates every required field.
- Skips malformed lines safely and reports the line number and the reason.
- Applies three time-based detection rules (see below).
- Prints a readable report in the terminal.
- Optionally writes a structured JSON report.
- Uses only the Python standard library.

## Detection Rules

Every rule uses the event **timestamps**, not line positions. An event belongs to a
window when it happens no more than `--window-minutes` after the first event of that
window.

| Rule | Severity | Triggers when | Threshold option (default) |
|------|----------|---------------|----------------------------|
| `brute_force` | MEDIUM | One source IP fails to log in to **the same user** N or more times within the window | `--brute-force-threshold` (5) |
| `password_spraying` | HIGH | One source IP fails to log in to N or more **different users** within the window | `--spray-threshold` (4) |
| `suspicious_success` | CRITICAL | A successful login follows N or more failures for the **same IP and user** within the window, which may mean the password was guessed | `--brute-force-threshold` (5) |

The time window (`--window-minutes`) defaults to **10 minutes** and applies to all
rules. After a successful login, earlier failures for the same IP and user are not
counted again.

### Limitations

- The rules use fixed thresholds. Real SOC tools also use baselines, reputation
  data, and correlation across many log sources.
- Attacks slower than the time window (for example, one attempt per hour) are not
  detected.
- Only the `LOGIN_SUCCESS` and `LOGIN_FAILURE` events are analyzed.
- Timestamps must be in UTC, in the form `YYYY-MM-DDTHH:MM:SSZ`.
- The whole log is read into memory, which is fine for small learning datasets.

## Log Format

Each line in `logs/sample_auth.log` is one event made of `key=value` fields:

```text
timestamp=2026-10-19T09:20:01Z host=vpn-01 event=LOGIN_FAILURE user=admin src_ip=203.0.113.45 reason=invalid_password
```

| Field | Required | Meaning |
|-------|----------|---------|
| `timestamp` | Yes | Event time in UTC (ISO 8601) |
| `host` | Yes | System that recorded the event |
| `event` | Yes | `LOGIN_SUCCESS` or `LOGIN_FAILURE` |
| `user` | Yes | Account name used in the attempt |
| `src_ip` | Yes | Source IP address |
| `method` / `reason` | No | Authentication method (success) or failure reason |

### Sample data

The sample log has 20 events (7 successful, 13 failed) and contains three scenarios:

1. **Brute force:** six failures for `admin` from `203.0.113.45`, followed by a
   successful login.
2. **Password spraying:** `198.51.100.23` tries five different accounts in 8 seconds.
3. **Normal activity:** users from `192.0.2.x`, including single typos followed by a
   successful login, which should not be flagged.

## Requirements

- Windows 10/11 with PowerShell
- Python 3.10 or newer (developed with Python 3.13)
- No third-party packages

## Running on Windows PowerShell

1. Open PowerShell in the project folder:

   ```powershell
   cd C:\path\to\mini-soc-lab
   ```

2. Create a virtual environment (first time only):

   ```powershell
   python -m venv .venv
   ```

3. Analyze the sample log with the default settings:

   ```powershell
   .\.venv\Scripts\python.exe main.py
   ```

   You can also run the engine directly with `.\.venv\Scripts\python.exe detector.py`.
   Both accept the same options.

### Command-line options

| Option | Default | Description |
|--------|---------|-------------|
| `--log PATH` | `logs/sample_auth.log` | Log file to analyze |
| `--brute-force-threshold N` | `5` | Failures for one user from one IP (minimum 2) |
| `--spray-threshold N` | `4` | Distinct users targeted by one IP (minimum 2) |
| `--window-minutes N` | `10` | Time window for all rules (minimum 1) |
| `--output PATH` | none | Also write a JSON report to this file |

### Example commands

```powershell
# Show all options
.\.venv\Scripts\python.exe main.py --help

# Stricter thresholds and a shorter window
.\.venv\Scripts\python.exe main.py --brute-force-threshold 3 --spray-threshold 3 --window-minutes 5

# Analyze a different log file
.\.venv\Scripts\python.exe main.py --log C:\path\to\other_auth.log
```

### Example output

```text
Log file:        logs\sample_auth.log
Events parsed:   20 (7 success, 13 failure)
Skipped lines:   0
Unique IPs:      5
Findings:        3

------------------------------------------------------------
[1] brute_force  (severity: MEDIUM)
    Source IP:   203.0.113.45
    Users:       admin
    Events:      6
    Time range:  2026-10-19T09:20:01Z -> 2026-10-19T09:20:16Z
    Details:     6 failed logins for 'admin' from 203.0.113.45 within 10 minutes (threshold: 5).
------------------------------------------------------------
```

## JSON Report

Add `--output` to save the results as JSON. The program refuses to write the report
over the input log file and prints a clear error if the file cannot be written.

```powershell
.\.venv\Scripts\python.exe main.py --output "$env:TEMP\mini-soc-report.json"

# Check that the file is valid JSON and view it
.\.venv\Scripts\python.exe -m json.tool "$env:TEMP\mini-soc-report.json"
```

Report structure (shortened):

```json
{
  "log_file": "logs\\sample_auth.log",
  "generated_at": "2026-10-19T20:39:30Z",
  "settings": {
    "brute_force_threshold": 5,
    "spray_threshold": 4,
    "window_minutes": 10
  },
  "summary": {
    "events_parsed": 20,
    "skipped_lines": 0,
    "findings": 3
  },
  "parse_errors": [],
  "findings": [
    {
      "rule": "brute_force",
      "severity": "MEDIUM",
      "src_ip": "203.0.113.45",
      "users": ["admin"],
      "event_count": 6,
      "first_seen": "2026-10-19T09:20:01Z",
      "last_seen": "2026-10-19T09:20:16Z",
      "description": "6 failed logins for 'admin' from 203.0.113.45 within 10 minutes (threshold: 5)."
    }
  ]
}
```

## Running the Tests

The tests use the built-in `unittest` module. Run them from the project root:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

They cover normal logins, each detection rule, events outside the time window,
malformed lines, empty log files, and the command-line options.

## Project Structure

```text
mini-soc-lab/
├── logs/
│   └── sample_auth.log    # Synthetic authentication events
├── tests/
│   └── test_detector.py   # Unit tests
├── detector.py            # Parser, detection rules, and reports
├── main.py                # Entry point
├── README.md
└── .gitignore
```
