"""Command-line interface.

Examples::

    eventhunter Security.evtx
    eventhunter Security.evtx -o report.md
    eventhunter logs/*.evtx --format json --min-severity high
    eventhunter Security.evtx --bf-threshold 10 --bf-window 60 --ignore-account scanner_svc

Exit codes:
    0  analysis completed (with or without findings)
    1  analysis completed and ``--fail-on`` severity was reached (for CI / scripting)
    2  usage error or unreadable input
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from eventhunter import __version__
from eventhunter.detectors import DetectorConfig
from eventhunter.engine import build_detectors, relevant_event_ids, run_detectors
from eventhunter.models import Event, Severity
from eventhunter.parser import ParseStats, parse_evtx
from eventhunter.report import render_json, render_markdown

log = logging.getLogger("eventhunter")


def _severity(value: str) -> Severity:
    """argparse ``type=`` adapter that turns ValueError into a clean usage error."""
    try:
        return Severity.parse(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _positive_int(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError(f"must be a positive integer, got {value}")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="eventhunter",
        description=(
            "Hunt for indicators of compromise in Windows Event Logs (.evtx) and map "
            "them to MITRE ATT&CK."
        ),
        epilog=(
            "Detections: brute force (4625), privileged logon (4672), encoded/obfuscated "
            "PowerShell (4688), account creation (4720), audit log cleared (1102)."
        ),
    )
    parser.add_argument("evtx", nargs="+", type=Path, metavar="EVTX", help="path(s) to .evtx file(s)")
    parser.add_argument(
        "-o", "--output", type=Path, metavar="FILE", help="write the report to FILE instead of stdout"
    )
    parser.add_argument(
        "-f", "--format", choices=("markdown", "json"), default="markdown", help="report format (default: markdown)"
    )
    parser.add_argument(
        "--min-severity",
        type=_severity,
        default=Severity.LOW,
        metavar="LEVEL",
        help="only report findings at or above LEVEL: info, low, medium, high, critical (default: low)",
    )
    parser.add_argument(
        "--fail-on",
        type=_severity,
        metavar="LEVEL",
        help="exit with status 1 if any finding is at or above LEVEL (useful in pipelines)",
    )

    tuning = parser.add_argument_group("detection tuning")
    tuning.add_argument(
        "--bf-threshold",
        type=_positive_int,
        default=5,
        metavar="N",
        help="failed logons for one account needed to flag brute force (default: 5)",
    )
    tuning.add_argument(
        "--bf-window",
        type=_positive_int,
        default=300,
        metavar="SECONDS",
        help="time window for the brute-force threshold (default: 300)",
    )
    tuning.add_argument(
        "--ignore-account",
        action="append",
        default=[],
        metavar="NAME",
        help="account name to suppress findings for (repeatable), e.g. a known scanner",
    )

    parser.add_argument("-v", "--verbose", action="store_true", help="show debug logging on stderr")
    parser.add_argument("-q", "--quiet", action="store_true", help="suppress progress messages on stderr")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    level = logging.DEBUG if args.verbose else logging.ERROR if args.quiet else logging.INFO
    logging.basicConfig(level=level, format="[%(levelname)s] %(message)s", stream=sys.stderr)

    try:
        config = DetectorConfig(
            brute_force_threshold=args.bf_threshold,
            brute_force_window=args.bf_window,
            ignore_accounts=set(args.ignore_account),
        )
    except ValueError as exc:
        parser.error(str(exc))

    detectors = build_detectors(config)
    wanted_ids = relevant_event_ids(detectors)

    # Parse every input file; only events some detector needs are kept in memory.
    events: list[Event] = []
    stats = ParseStats()
    for path in args.evtx:
        log.info("Parsing %s ...", path)
        try:
            events.extend(parse_evtx(path, event_ids=wanted_ids, stats=stats))
        except (FileNotFoundError, ValueError) as exc:
            log.error("%s", exc)
            return 2
    log.info("Parsed %d relevant event(s) from %d file(s)", stats.parsed, len(args.evtx))

    detections = run_detectors(events, detectors=detectors, min_severity=args.min_severity)
    log.info("%d detection(s)", len(detections))

    render = render_json if args.format == "json" else render_markdown
    report = render(detections, events, sources=[p.name for p in args.evtx], skipped=stats.skipped)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report, encoding="utf-8")
        log.info("Report written to %s", args.output)
    else:
        sys.stdout.write(report)
        if not report.endswith("\n"):
            sys.stdout.write("\n")

    if args.fail_on is not None and any(d.severity >= args.fail_on for d in detections):
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
