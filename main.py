"""Mini SOC Lab - entry point.

An educational tool for analyzing synthetic authentication logs
and detecting suspicious security events.
"""

from pathlib import Path

PROJECT_NAME = "Mini SOC Lab"
SAMPLE_LOG = Path(__file__).parent / "logs" / "sample_auth.log"

ROADMAP = [
    "Parse authentication log entries into structured records",
    "Summarize activity per user and per source IP",
    "Detect brute-force attempts (repeated failures from one IP)",
    "Detect password spraying (one IP targeting many users)",
    "Flag successful logins that follow repeated failures",
    "Generate a readable alert report",
]


def main() -> None:
    print("=" * 50)
    print(f"  {PROJECT_NAME}")
    print("  Educational log analysis for SOC practice")
    print("=" * 50)
    print()
    print("Note: all log data in this project is synthetic.")
    print()

    status = "found" if SAMPLE_LOG.is_file() else "missing"
    print(f"Sample log: {SAMPLE_LOG.relative_to(SAMPLE_LOG.parent.parent)} ({status})")
    print()

    print("Planned stages:")
    for number, stage in enumerate(ROADMAP, start=1):
        print(f"  {number}. {stage}")


if __name__ == "__main__":
    main()
