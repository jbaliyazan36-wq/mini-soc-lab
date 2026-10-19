"""Mini SOC Lab - entry point.

An educational tool for analyzing synthetic authentication logs
and detecting suspicious security events.

All command-line options are passed to the detection engine in
detector.py. Run `python main.py --help` to see them.
"""

import sys

import detector

PROJECT_NAME = "Mini SOC Lab"


def main(argv=None) -> int:
    print("=" * 60)
    print(f"  {PROJECT_NAME}")
    print("  Educational log analysis for SOC practice")
    print("  Note: all log data in this project is synthetic.")
    print("=" * 60)
    print()
    return detector.main(argv, prog="main.py")


if __name__ == "__main__":
    sys.exit(main())
