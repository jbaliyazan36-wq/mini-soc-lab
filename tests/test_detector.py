"""Unit tests for detector.py.

Run from the project root:
    python -m unittest discover -s tests -v
"""

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import detector

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_LOG = PROJECT_ROOT / "logs" / "sample_auth.log"


def make_line(time, event, user, ip, host="web-01"):
    """Build one synthetic log line. `time` is HH:MM:SS on a fixed date."""
    extra = "method=password" if event == "LOGIN_SUCCESS" else "reason=invalid_password"
    return (
        f"timestamp=2026-10-19T{time}Z host={host} event={event} "
        f"user={user} src_ip={ip} {extra}"
    )


def failures(user, ip, times):
    return [make_line(t, "LOGIN_FAILURE", user, ip) for t in times]


def detect(lines, **settings):
    events, errors = detector.parse_lines(lines)
    return detector.run_detections(events, **settings), errors


def rules(findings):
    return [finding.rule for finding in findings]


class ParsingTests(unittest.TestCase):
    def test_valid_line_is_parsed_into_event(self):
        events, errors = detector.parse_lines(
            [make_line("08:00:00", "LOGIN_SUCCESS", "alice", "192.0.2.10")]
        )

        self.assertEqual(errors, [])
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.event, "LOGIN_SUCCESS")
        self.assertEqual(event.user, "alice")
        self.assertEqual(event.src_ip, "192.0.2.10")
        self.assertEqual(event.timestamp.isoformat(), "2026-10-19T08:00:00+00:00")
        self.assertEqual(event.line_number, 1)

    def test_blank_lines_are_ignored(self):
        events, errors = detector.parse_lines(
            ["", "   ", make_line("08:00:00", "LOGIN_SUCCESS", "alice", "192.0.2.10")]
        )

        self.assertEqual(len(events), 1)
        self.assertEqual(errors, [])
        self.assertEqual(events[0].line_number, 3)


class MalformedLineTests(unittest.TestCase):
    def assert_single_error(self, line, expected_text):
        events, errors = detector.parse_lines([line])

        self.assertEqual(events, [])
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0].line_number, 1)
        self.assertIn(expected_text, errors[0].message)

    def test_field_without_equals_sign(self):
        self.assert_single_error(
            "timestamp=2026-10-19T08:00:00Z host=web-01 garbage", "garbage"
        )

    def test_missing_required_field(self):
        self.assert_single_error(
            "timestamp=2026-10-19T08:00:00Z host=web-01 event=LOGIN_FAILURE user=bob",
            "src_ip",
        )

    def test_invalid_timestamp(self):
        line = make_line("08:00:00", "LOGIN_FAILURE", "bob", "192.0.2.11").replace(
            "2026-10-19T08:00:00Z", "yesterday"
        )
        self.assert_single_error(line, "timestamp")

    def test_unknown_event_type(self):
        line = make_line("08:00:00", "LOGIN_FAILURE", "bob", "192.0.2.11").replace(
            "LOGIN_FAILURE", "LOGOUT"
        )
        self.assert_single_error(line, "LOGOUT")

    def test_invalid_ip_address(self):
        self.assert_single_error(
            make_line("08:00:00", "LOGIN_FAILURE", "bob", "999.1.1.1"), "999.1.1.1"
        )

    def test_duplicate_field(self):
        self.assert_single_error(
            make_line("08:00:00", "LOGIN_FAILURE", "bob", "192.0.2.11") + " user=eve",
            "user",
        )

    def test_malformed_line_does_not_stop_parsing(self):
        lines = [
            make_line("08:00:00", "LOGIN_SUCCESS", "alice", "192.0.2.10"),
            "this is not a log record",
            make_line("08:01:00", "LOGIN_SUCCESS", "bob", "192.0.2.11"),
        ]

        events, errors = detector.parse_lines(lines)

        self.assertEqual([e.user for e in events], ["alice", "bob"])
        self.assertEqual([e.line_number for e in errors], [2])


class NormalActivityTests(unittest.TestCase):
    def test_successful_logins_produce_no_findings(self):
        lines = [
            make_line("08:00:00", "LOGIN_SUCCESS", "alice", "192.0.2.10"),
            make_line("08:01:00", "LOGIN_SUCCESS", "bob", "192.0.2.11"),
            make_line("08:02:00", "LOGIN_SUCCESS", "carol", "192.0.2.12"),
        ]

        findings, errors = detect(lines)

        self.assertEqual(errors, [])
        self.assertEqual(findings, [])

    def test_single_typo_then_success_is_not_suspicious(self):
        lines = [
            make_line("08:00:00", "LOGIN_FAILURE", "bob", "192.0.2.11"),
            make_line("08:00:20", "LOGIN_SUCCESS", "bob", "192.0.2.11"),
        ]

        findings, _ = detect(lines)

        self.assertEqual(findings, [])


class BruteForceTests(unittest.TestCase):
    def test_repeated_failures_against_one_user_are_detected(self):
        lines = failures(
            "admin", "203.0.113.45",
            ["09:00:00", "09:00:05", "09:00:10", "09:00:15", "09:00:20"],
        )

        findings, _ = detect(lines, brute_force_threshold=5)

        self.assertEqual(rules(findings), ["brute_force"])
        finding = findings[0]
        self.assertEqual(finding.severity, "MEDIUM")
        self.assertEqual(finding.src_ip, "203.0.113.45")
        self.assertEqual(finding.users, ["admin"])
        self.assertEqual(finding.event_count, 5)
        self.assertEqual(finding.first_seen.strftime("%H:%M:%S"), "09:00:00")
        self.assertEqual(finding.last_seen.strftime("%H:%M:%S"), "09:00:20")

    def test_failures_below_threshold_are_not_detected(self):
        lines = failures("admin", "203.0.113.45", ["09:00:00", "09:00:05", "09:00:10"])

        findings, _ = detect(lines, brute_force_threshold=5)

        self.assertNotIn("brute_force", rules(findings))

    def test_failures_spread_outside_window_are_not_detected(self):
        lines = failures(
            "admin", "203.0.113.45",
            ["09:00:00", "09:04:00", "09:08:00", "09:12:00", "09:16:00"],
        )

        findings, _ = detect(lines, brute_force_threshold=5, window_minutes=10)

        self.assertNotIn("brute_force", rules(findings))

    def test_wider_window_catches_slower_attack(self):
        lines = failures(
            "admin", "203.0.113.45",
            ["09:00:00", "09:04:00", "09:08:00", "09:12:00", "09:16:00"],
        )

        findings, _ = detect(lines, brute_force_threshold=5, window_minutes=20)

        self.assertIn("brute_force", rules(findings))

    def test_failures_against_different_users_are_not_brute_force(self):
        lines = [
            make_line(f"09:00:0{i}", "LOGIN_FAILURE", user, "198.51.100.23")
            for i, user in enumerate(["alice", "bob", "carol", "dave", "erin"])
        ]

        findings, _ = detect(lines, brute_force_threshold=5)

        self.assertNotIn("brute_force", rules(findings))


class PasswordSprayingTests(unittest.TestCase):
    USERS = ["alice", "bob", "carol", "dave"]

    def test_many_users_from_one_ip_are_detected(self):
        lines = [
            make_line(f"10:00:0{i}", "LOGIN_FAILURE", user, "198.51.100.23")
            for i, user in enumerate(self.USERS)
        ]

        findings, _ = detect(lines, spray_threshold=4)

        self.assertEqual(rules(findings), ["password_spraying"])
        finding = findings[0]
        self.assertEqual(finding.severity, "HIGH")
        self.assertEqual(finding.src_ip, "198.51.100.23")
        self.assertEqual(finding.users, sorted(self.USERS))
        self.assertEqual(finding.event_count, 4)

    def test_too_few_distinct_users_are_not_detected(self):
        lines = [
            make_line(f"10:00:0{i}", "LOGIN_FAILURE", user, "198.51.100.23")
            for i, user in enumerate(["alice", "bob", "alice", "bob"])
        ]

        findings, _ = detect(lines, spray_threshold=4)

        self.assertNotIn("password_spraying", rules(findings))

    def test_users_targeted_outside_window_are_not_detected(self):
        lines = [
            make_line(time, "LOGIN_FAILURE", user, "198.51.100.23")
            for time, user in zip(["10:00:00", "10:15:00", "10:30:00", "10:45:00"], self.USERS)
        ]

        findings, _ = detect(lines, spray_threshold=4, window_minutes=10)

        self.assertNotIn("password_spraying", rules(findings))

    def test_same_users_from_different_ips_are_not_detected(self):
        lines = [
            make_line(f"10:00:0{i}", "LOGIN_FAILURE", user, f"192.0.2.{i + 1}")
            for i, user in enumerate(self.USERS)
        ]

        findings, _ = detect(lines, spray_threshold=4)

        self.assertNotIn("password_spraying", rules(findings))


class SuspiciousSuccessTests(unittest.TestCase):
    TIMES = ["09:00:00", "09:00:05", "09:00:10", "09:00:15", "09:00:20"]

    def test_success_after_repeated_failures_is_detected(self):
        lines = failures("admin", "203.0.113.45", self.TIMES) + [
            make_line("09:00:30", "LOGIN_SUCCESS", "admin", "203.0.113.45")
        ]

        findings, _ = detect(lines, brute_force_threshold=5)

        suspicious = [f for f in findings if f.rule == "suspicious_success"]
        self.assertEqual(len(suspicious), 1)
        finding = suspicious[0]
        self.assertEqual(finding.severity, "CRITICAL")
        self.assertEqual(finding.users, ["admin"])
        self.assertEqual(finding.event_count, 6)
        self.assertEqual(finding.last_seen.strftime("%H:%M:%S"), "09:00:30")

    def test_success_long_after_failures_is_not_detected(self):
        lines = failures("admin", "203.0.113.45", self.TIMES) + [
            make_line("11:00:00", "LOGIN_SUCCESS", "admin", "203.0.113.45")
        ]

        findings, _ = detect(lines, brute_force_threshold=5, window_minutes=10)

        self.assertNotIn("suspicious_success", rules(findings))

    def test_success_from_different_ip_is_not_detected(self):
        lines = failures("admin", "203.0.113.45", self.TIMES) + [
            make_line("09:00:30", "LOGIN_SUCCESS", "admin", "192.0.2.10")
        ]

        findings, _ = detect(lines, brute_force_threshold=5)

        self.assertNotIn("suspicious_success", rules(findings))

    def test_failures_before_an_earlier_success_are_not_counted_again(self):
        lines = failures("admin", "203.0.113.45", self.TIMES) + [
            make_line("09:00:30", "LOGIN_SUCCESS", "admin", "203.0.113.45"),
            make_line("09:01:00", "LOGIN_SUCCESS", "admin", "203.0.113.45"),
        ]

        findings, _ = detect(lines, brute_force_threshold=5)

        self.assertEqual(rules(findings).count("suspicious_success"), 1)


class LoadLogTests(unittest.TestCase):
    def test_empty_log_file_has_no_events_or_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "empty.log"
            log_path.write_text("", encoding="utf-8")

            events, errors = detector.load_log(log_path)

        self.assertEqual(events, [])
        self.assertEqual(errors, [])
        self.assertEqual(detector.run_detections(events), [])

    def test_sample_log_produces_one_finding_per_rule(self):
        events, errors = detector.load_log(SAMPLE_LOG)

        findings = detector.run_detections(events)

        self.assertEqual(errors, [])
        self.assertEqual(len(events), 20)
        self.assertEqual(
            sorted(rules(findings)),
            ["brute_force", "password_spraying", "suspicious_success"],
        )


class CommandLineTests(unittest.TestCase):
    def run_cli(self, args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            exit_code = detector.main(args)
        return exit_code, stdout.getvalue(), stderr.getvalue()

    def test_terminal_report_lists_findings(self):
        exit_code, out, _ = self.run_cli(["--log", str(SAMPLE_LOG)])

        self.assertEqual(exit_code, 0)
        for text in ("brute_force", "password_spraying", "suspicious_success",
                     "203.0.113.45", "198.51.100.23", "CRITICAL"):
            self.assertIn(text, out)

    def test_json_report_is_valid(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "report.json"

            exit_code, _, _ = self.run_cli(
                ["--log", str(SAMPLE_LOG), "--output", str(report_path)]
            )
            report = json.loads(report_path.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 0)
        self.assertEqual(report["summary"]["events_parsed"], 20)
        self.assertEqual(report["summary"]["findings"], 3)
        self.assertEqual(report["settings"]["window_minutes"], 10)
        first = report["findings"][0]
        for key in ("rule", "severity", "src_ip", "users", "event_count",
                    "first_seen", "last_seen", "description"):
            self.assertIn(key, first)

    def test_json_report_uses_relative_log_path(self):
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(PROJECT_ROOT)
        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "report.json"

            self.run_cli(["--log", str(SAMPLE_LOG), "--output", str(report_path)])
            report = json.loads(report_path.read_text(encoding="utf-8"))

        self.assertEqual(report["log_file"], str(Path("logs") / "sample_auth.log"))

    def test_output_cannot_overwrite_input_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "auth.log"
            original = make_line("08:00:00", "LOGIN_SUCCESS", "alice", "192.0.2.10") + "\n"
            log_path.write_text(original, encoding="utf-8")

            exit_code, _, err = self.run_cli(
                ["--log", str(log_path), "--output", str(log_path)]
            )

            self.assertEqual(log_path.read_text(encoding="utf-8"), original)
        self.assertEqual(exit_code, 1)
        self.assertIn("overwrite", err)

    def test_unwritable_output_reports_clear_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "missing-folder" / "report.json"

            exit_code, _, err = self.run_cli(
                ["--log", str(SAMPLE_LOG), "--output", str(report_path)]
            )

        self.assertEqual(exit_code, 1)
        self.assertIn("could not write report", err)

    def test_missing_log_file_reports_clear_error(self):
        exit_code, _, err = self.run_cli(["--log", "does-not-exist.log"])

        self.assertEqual(exit_code, 1)
        self.assertIn("could not read log", err)

    def test_invalid_threshold_is_rejected(self):
        with self.assertRaises(SystemExit) as raised:
            self.run_cli(["--brute-force-threshold", "0"])

        self.assertEqual(raised.exception.code, 2)

    def test_malformed_lines_are_reported_without_crashing(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "auth.log"
            log_path.write_text(
                "broken line\n"
                + make_line("08:00:00", "LOGIN_SUCCESS", "alice", "192.0.2.10") + "\n",
                encoding="utf-8",
            )

            exit_code, out, _ = self.run_cli(["--log", str(log_path)])

        self.assertEqual(exit_code, 0)
        self.assertIn("line 1", out)


if __name__ == "__main__":
    unittest.main()
