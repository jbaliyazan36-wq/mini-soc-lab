# Mini SOC Lab

An educational Python project that analyzes **synthetic** authentication logs and
detects suspicious security events, in the style of the work a Security Operations
Center (SOC) analyst does every day.

> **Disclaimer:** This is a learning project. All log data is synthetic. IP addresses
> come from the documentation ranges reserved by RFC 5737 (`192.0.2.0/24`,
> `198.51.100.0/24`, `203.0.113.0/24`), and user names are fictional. No real people,
> systems, or networks are represented.

## Learning Goals

- Read and parse raw log data into structured records.
- Recognize common authentication attack patterns.
- Translate detection logic into clear, testable Python code.
- Present findings the way a SOC analyst would report them.

## Planned Capabilities

| Capability | Description |
|------------|-------------|
| Log parsing | Convert `key=value` log lines into structured records |
| Activity summary | Count logins per user and per source IP |
| Brute-force detection | Repeated failed logins from a single IP |
| Password spraying detection | One IP attempting logins against many accounts |
| Suspicious success | A successful login that follows repeated failures |
| Alert report | A readable summary of the findings |

The project is being built in stages. The current version prints an overview of
the planned stages.

## Log Format

Each line in `logs/sample_auth.log` is one event made of `key=value` fields:

```text
timestamp=2026-10-19T09:20:01Z host=vpn-01 event=LOGIN_FAILURE user=admin src_ip=203.0.113.45 reason=invalid_password
```

| Field | Meaning |
|-------|---------|
| `timestamp` | Event time in UTC (ISO 8601) |
| `host` | System that recorded the event |
| `event` | `LOGIN_SUCCESS` or `LOGIN_FAILURE` |
| `user` | Account name used in the attempt |
| `src_ip` | Source IP address |
| `method` / `reason` | Authentication method (success) or failure reason |

## Requirements

- Windows 10/11 with PowerShell
- Python 3.10 or newer (developed with Python 3.13)
- No third-party packages; only the Python standard library is used

## Running on Windows PowerShell

1. Open PowerShell in the project folder:

   ```powershell
   cd C:\path\to\mini-soc-lab
   ```

2. Create a virtual environment (first time only):

   ```powershell
   python -m venv .venv
   ```

3. Run the program with the virtual environment's Python:

   ```powershell
   .\.venv\Scripts\python.exe main.py
   ```

   Alternatively, activate the environment first and then run `python main.py`:

   ```powershell
   .\.venv\Scripts\Activate.ps1
   python main.py
   ```

   If PowerShell blocks the activation script, use the first option, which does
   not require activation.

## Project Structure

```text
mini-soc-lab/
├── logs/
│   └── sample_auth.log   # Synthetic authentication events
├── main.py               # Entry point
├── README.md
└── .gitignore
```
