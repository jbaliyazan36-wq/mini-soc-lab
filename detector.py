"""Mini SOC Lab - authentication log detection engine.

Parses synthetic `key=value` authentication logs and applies three
detection rules: brute force, password spraying, and suspicious success.
Uses only the Python standard library.
"""

import argparse
import ipaddress
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

DEFAULT_LOG = Path(__file__).parent / "logs" / "sample_auth.log"
DEFAULT_BRUTE_FORCE_THRESHOLD = 5
DEFAULT_SPRAY_THRESHOLD = 4
DEFAULT_WINDOW_MINUTES = 10

REQUIRED_FIELDS = ("timestamp", "host", "event", "user", "src_ip")
VALID_EVENTS = ("LOGIN_SUCCESS", "LOGIN_FAILURE")
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

SEVERITY = {
    "brute_force": "MEDIUM",
    "password_spraying": "HIGH",
    "suspicious_success": "CRITICAL",
}


@dataclass
class Event:
    """One valid authentication event from the log."""

    line_number: int
    timestamp: datetime
    host: str
    event: str
    user: str
    src_ip: str


@dataclass
class ParseError:
    """A log line that could not be parsed, and why."""

    line_number: int
    message: str


@dataclass
class Finding:
    """One detection result."""

    rule: str
    severity: str
    src_ip: str
    users: list
    event_count: int
    first_seen: datetime
    last_seen: datetime
    description: str

    def to_dict(self):
        return {
            "rule": self.rule,
            "severity": self.severity,
            "src_ip": self.src_ip,
            "users": self.users,
            "event_count": self.event_count,
            "first_seen": format_time(self.first_seen),
            "last_seen": format_time(self.last_seen),
            "description": self.description,
        }


def format_time(value):
    return value.strftime(TIMESTAMP_FORMAT)


def display_path(path):
    """Show a path relative to the current folder, to keep personal paths out of reports."""
    try:
        return str(Path(path).resolve().relative_to(Path.cwd()))
    except ValueError:
        return str(path)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def parse_line(line, line_number):
    """Turn one log line into an Event. Raises ValueError if it is malformed."""
    fields = {}
    for token in line.split():
        key, sep, value = token.partition("=")
        if not sep or not key or not value:
            raise ValueError(f"field '{token}' is not in key=value form")
        if key in fields:
            raise ValueError(f"field '{key}' appears more than once")
        fields[key] = value

    missing = [name for name in REQUIRED_FIELDS if name not in fields]
    if missing:
        raise ValueError(f"missing required field(s): {', '.join(missing)}")

    try:
        timestamp = datetime.strptime(fields["timestamp"], TIMESTAMP_FORMAT)
    except ValueError:
        raise ValueError(
            f"invalid timestamp '{fields['timestamp']}' "
            "(expected format YYYY-MM-DDTHH:MM:SSZ)"
        ) from None

    if fields["event"] not in VALID_EVENTS:
        raise ValueError(
            f"unknown event '{fields['event']}' "
            f"(expected one of: {', '.join(VALID_EVENTS)})"
        )

    try:
        ipaddress.ip_address(fields["src_ip"])
    except ValueError:
        raise ValueError(f"invalid IP address '{fields['src_ip']}'") from None

    return Event(
        line_number=line_number,
        timestamp=timestamp.replace(tzinfo=timezone.utc),
        host=fields["host"],
        event=fields["event"],
        user=fields["user"],
        src_ip=fields["src_ip"],
    )


def parse_lines(lines):
    """Parse many lines. Returns (events, errors); never stops on a bad line."""
    events, errors = [], []
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            events.append(parse_line(line, line_number))
        except ValueError as error:
            errors.append(ParseError(line_number, str(error)))
    events.sort(key=lambda e: (e.timestamp, e.line_number))
    return events, errors


def load_log(path):
    """Read and parse a log file. Raises OSError if the file cannot be read."""
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    return parse_lines(text.splitlines())


# ---------------------------------------------------------------------------
# Detection rules
# ---------------------------------------------------------------------------

def find_bursts(events, window, is_suspicious):
    """Slide a time window over time-ordered events.

    For each starting event, take every event that happened within `window`
    of it. When `is_suspicious` accepts that group, record it and continue
    after the group, so one burst of activity becomes one finding.
    """
    bursts = []
    start = 0
    while start < len(events):
        window_end = events[start].timestamp + window
        end = start
        while end < len(events) and events[end].timestamp <= window_end:
            end += 1
        group = events[start:end]
        if is_suspicious(group):
            bursts.append(group)
            start = end
        else:
            start += 1
    return bursts


def group_by(events, key):
    groups = {}
    for event in events:
        groups.setdefault(key(event), []).append(event)
    return groups


def detect_brute_force(events, threshold, window):
    """Many failures from one IP against one user within the window."""
    failed = [e for e in events if e.event == "LOGIN_FAILURE"]
    findings = []
    for (src_ip, user), attempts in group_by(failed, lambda e: (e.src_ip, e.user)).items():
        for burst in find_bursts(attempts, window, lambda g: len(g) >= threshold):
            findings.append(Finding(
                rule="brute_force",
                severity=SEVERITY["brute_force"],
                src_ip=src_ip,
                users=[user],
                event_count=len(burst),
                first_seen=burst[0].timestamp,
                last_seen=burst[-1].timestamp,
                description=(
                    f"{len(burst)} failed logins for '{user}' from {src_ip} "
                    f"within {describe_window(window)} (threshold: {threshold})."
                ),
            ))
    return findings


def detect_password_spraying(events, threshold, window):
    """Failures from one IP against many different users within the window."""
    failed = [e for e in events if e.event == "LOGIN_FAILURE"]
    findings = []
    for src_ip, attempts in group_by(failed, lambda e: e.src_ip).items():
        bursts = find_bursts(
            attempts, window, lambda g: len({e.user for e in g}) >= threshold
        )
        for burst in bursts:
            users = sorted({e.user for e in burst})
            findings.append(Finding(
                rule="password_spraying",
                severity=SEVERITY["password_spraying"],
                src_ip=src_ip,
                users=users,
                event_count=len(burst),
                first_seen=burst[0].timestamp,
                last_seen=burst[-1].timestamp,
                description=(
                    f"{src_ip} tried {len(users)} different accounts "
                    f"within {describe_window(window)} (threshold: {threshold})."
                ),
            ))
    return findings


def detect_suspicious_success(events, threshold, window):
    """A success that follows many recent failures for the same IP and user."""
    findings = []
    for (src_ip, user), history in group_by(events, lambda e: (e.src_ip, e.user)).items():
        failures_since_success = []
        for event in history:
            if event.event == "LOGIN_FAILURE":
                failures_since_success.append(event)
                continue
            recent = [
                f for f in failures_since_success
                if event.timestamp - f.timestamp <= window
            ]
            if len(recent) >= threshold:
                findings.append(Finding(
                    rule="suspicious_success",
                    severity=SEVERITY["suspicious_success"],
                    src_ip=src_ip,
                    users=[user],
                    event_count=len(recent) + 1,
                    first_seen=recent[0].timestamp,
                    last_seen=event.timestamp,
                    description=(
                        f"'{user}' logged in successfully from {src_ip} after "
                        f"{len(recent)} failed attempts within "
                        f"{describe_window(window)}. Possible account compromise."
                    ),
                ))
            failures_since_success = []
    return findings


def run_detections(
    events,
    brute_force_threshold=DEFAULT_BRUTE_FORCE_THRESHOLD,
    spray_threshold=DEFAULT_SPRAY_THRESHOLD,
    window_minutes=DEFAULT_WINDOW_MINUTES,
):
    """Run every rule on time-ordered events and return findings by time."""
    window = timedelta(minutes=window_minutes)
    findings = (
        detect_brute_force(events, brute_force_threshold, window)
        + detect_password_spraying(events, spray_threshold, window)
        + detect_suspicious_success(events, brute_force_threshold, window)
    )
    findings.sort(key=lambda f: (f.first_seen, f.rule))
    return findings


def describe_window(window):
    minutes = int(window.total_seconds() // 60)
    return f"{minutes} minute" + ("" if minutes == 1 else "s")


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_report(log_path, events, errors, findings):
    failures = sum(1 for e in events if e.event == "LOGIN_FAILURE")
    print(f"Log file:        {display_path(log_path)}")
    print(f"Events parsed:   {len(events)} "
          f"({len(events) - failures} success, {failures} failure)")
    print(f"Skipped lines:   {len(errors)}")
    print(f"Unique IPs:      {len({e.src_ip for e in events})}")
    print(f"Findings:        {len(findings)}")

    if errors:
        print()
        print("Skipped lines (malformed):")
        for error in errors:
            print(f"  line {error.line_number}: {error.message}")

    print()
    if not findings:
        print("No suspicious activity detected.")
        return

    for number, finding in enumerate(findings, start=1):
        print("-" * 60)
        print(f"[{number}] {finding.rule}  (severity: {finding.severity})")
        print(f"    Source IP:   {finding.src_ip}")
        print(f"    Users:       {', '.join(finding.users)}")
        print(f"    Events:      {finding.event_count}")
        print(f"    Time range:  {format_time(finding.first_seen)} -> "
              f"{format_time(finding.last_seen)}")
        print(f"    Details:     {finding.description}")
    print("-" * 60)


def build_report(log_path, settings, events, errors, findings):
    return {
        "log_file": display_path(log_path),
        "generated_at": format_time(datetime.now(timezone.utc)),
        "settings": settings,
        "summary": {
            "events_parsed": len(events),
            "skipped_lines": len(errors),
            "findings": len(findings),
        },
        "parse_errors": [
            {"line_number": e.line_number, "message": e.message} for e in errors
        ],
        "findings": [f.to_dict() for f in findings],
    }


def write_json_report(report, output_path):
    """Write the report. Raises OSError if the file cannot be written."""
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------

def int_at_least(minimum):
    def parse(text):
        try:
            value = int(text)
        except ValueError:
            raise argparse.ArgumentTypeError(f"'{text}' is not a whole number") from None
        if value < minimum:
            raise argparse.ArgumentTypeError(f"must be {minimum} or greater (got {value})")
        return value
    return parse


def build_parser(prog=None):
    parser = argparse.ArgumentParser(
        prog=prog,
        description="Detect suspicious activity in synthetic authentication logs.",
    )
    parser.add_argument(
        "--log", type=Path, default=DEFAULT_LOG, metavar="PATH",
        help="log file to analyze (default: logs/sample_auth.log)",
    )
    parser.add_argument(
        "--brute-force-threshold", type=int_at_least(2),
        default=DEFAULT_BRUTE_FORCE_THRESHOLD, metavar="N",
        help="failed logins for one user from one IP that trigger brute force "
             "and suspicious success (default: %(default)s)",
    )
    parser.add_argument(
        "--spray-threshold", type=int_at_least(2),
        default=DEFAULT_SPRAY_THRESHOLD, metavar="N",
        help="distinct users targeted by one IP that trigger password spraying "
             "(default: %(default)s)",
    )
    parser.add_argument(
        "--window-minutes", type=int_at_least(1),
        default=DEFAULT_WINDOW_MINUTES, metavar="N",
        help="time window, in minutes, used by every rule (default: %(default)s)",
    )
    parser.add_argument(
        "--output", type=Path, metavar="PATH",
        help="optional path for a JSON report",
    )
    return parser


def main(argv=None, prog=None):
    args = build_parser(prog).parse_args(argv)

    try:
        events, errors = load_log(args.log)
    except OSError as error:
        print(f"Error: could not read log file '{args.log}': {error.strerror or error}",
              file=sys.stderr)
        return 1

    settings = {
        "brute_force_threshold": args.brute_force_threshold,
        "spray_threshold": args.spray_threshold,
        "window_minutes": args.window_minutes,
    }
    findings = run_detections(events, **settings)
    print_report(args.log, events, errors, findings)

    if args.output is None:
        return 0

    if args.output.resolve() == args.log.resolve():
        print("Error: --output must not overwrite the input log file.", file=sys.stderr)
        return 1

    report = build_report(args.log, settings, events, errors, findings)
    try:
        write_json_report(report, args.output)
    except OSError as error:
        print(f"Error: could not write report to '{args.output}': "
              f"{error.strerror or error}", file=sys.stderr)
        return 1

    print(f"JSON report written to {display_path(args.output)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
