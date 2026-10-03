"""Render detections as a Markdown report (for humans) or JSON (for tooling).

Everything taken from the event log is attacker-controllable - usernames,
command lines, hostnames - so all of it is escaped before being placed into
Markdown. Otherwise a crafted command line could break the report layout or
inject links into it.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Sequence
from datetime import datetime, timezone

from eventhunter import __version__
from eventhunter.mitre import Technique
from eventhunter.models import Detection, Event, Severity

SEVERITY_BADGE = {
    Severity.CRITICAL: "🔴 CRITICAL",
    Severity.HIGH: "🟠 HIGH",
    Severity.MEDIUM: "🟡 MEDIUM",
    Severity.LOW: "🔵 LOW",
    Severity.INFO: "⚪ INFO",
}

# Detail fields shown as code blocks (in this order) rather than in the details table.
_BLOCK_FIELDS = ("Command line", "Decoded payload")
_MAX_RECORD_IDS = 25
_MD_SPECIAL = re.compile(r"([\\`*_\[\]<>|#])")


def md_escape(text: str) -> str:
    """Escape Markdown control characters and flatten newlines (safe for table cells)."""
    return _MD_SPECIAL.sub(r"\\\1", str(text)).replace("\r", "").replace("\n", " ")


def code_block(text: str, lang: str = "") -> str:
    """Wrap ``text`` in a fenced code block whose fence can't be closed by the content."""
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}{lang}\n{text}\n{fence}"


def fmt_time(ts: datetime | None) -> str:
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S") if ts else "n/a"


def technique_link(t: Technique) -> str:
    return f"[{t.id}]({t.url})"


def _time_range(events: Sequence[Event]) -> str:
    if not events:
        return "n/a"
    stamps = [e.timestamp for e in events]
    return f"{fmt_time(min(stamps))} → {fmt_time(max(stamps))} UTC"


def _overall_risk(detections: Sequence[Detection]) -> Severity | None:
    return max((d.severity for d in detections), default=None)


def _render_detail(index: int, d: Detection) -> list[str]:
    lines = [f"### {index}. {SEVERITY_BADGE[d.severity]} — {md_escape(d.title)}", ""]

    when = fmt_time(d.timestamp) + " UTC"
    if d.end_time and d.end_time != d.timestamp:
        when = f"{fmt_time(d.timestamp)} → {fmt_time(d.end_time)} UTC"
    techniques = "; ".join(f"{technique_link(t)} {md_escape(t.name)}" for t in d.techniques)
    tactics = sorted({tactic for t in d.techniques for tactic in t.tactics})

    record_ids = d.record_ids
    shown = ", ".join(str(r) for r in record_ids[:_MAX_RECORD_IDS])
    if len(record_ids) > _MAX_RECORD_IDS:
        shown += f" … (+{len(record_ids) - _MAX_RECORD_IDS} more)"
    event_ids = ", ".join(str(i) for i in sorted({e.event_id for e in d.events}))

    lines += [
        f"- **When:** {when}",
        f"- **Host:** {md_escape(d.host)}",
        f"- **Rule:** `{d.rule}`",
        f"- **MITRE ATT&CK:** {techniques}",
        f"- **Tactic(s):** {', '.join(tactics)}",
        f"- **Evidence:** Event ID(s) {event_ids}; EventRecordID(s) {shown or 'n/a'}",
        "",
    ]

    table_fields = {k: v for k, v in d.details.items() if k not in _BLOCK_FIELDS}
    if table_fields:
        lines += ["| Field | Value |", "|---|---|"]
        lines += [f"| {md_escape(k)} | {md_escape(v)} |" for k, v in table_fields.items()]
        lines.append("")

    for name in _BLOCK_FIELDS:
        if name in d.details:
            lines += [f"**{name}:**", "", code_block(d.details[name], "powershell"), ""]

    if d.rationale:
        lines += [f"**Why it matters:** {d.rationale}", ""]
    if d.next_steps:
        lines += ["**Recommended next steps:**", ""]
        lines += [f"1. {step}" for step in d.next_steps]
        lines.append("")
    return lines


def render_markdown(
    detections: Sequence[Detection],
    events: Sequence[Event],
    sources: Sequence[str],
    skipped: int = 0,
    generated_at: datetime | None = None,
) -> str:
    """Build the full Markdown report.

    Args:
        detections:   Findings, already sorted (see :func:`engine.sort_detections`).
        events:       The events that were analysed (for stats and time range).
        sources:      Names of the input files.
        skipped:      Number of unreadable records/chunks skipped by the parser.
        generated_at: Report timestamp (defaults to now; injectable for reproducible output).
    """
    generated_at = generated_at or datetime.now(timezone.utc)
    counts = Counter(d.severity for d in detections)
    risk = _overall_risk(detections)

    analysed = f"{len(events):,}"
    if skipped:
        analysed += f" ({skipped:,} unreadable record(s) skipped)"

    lines = [
        "# EventHunter Report",
        "",
        "| | |",
        "|---|---|",
        f"| **Source file(s)** | {', '.join(md_escape(s) for s in sources)} |",
        f"| **Generated** | {fmt_time(generated_at)} UTC |",
        f"| **Relevant events analysed** | {analysed} |",
        f"| **Time range** | {_time_range(events)} |",
        f"| **Detections** | {len(detections)} |",
        f"| **Overall risk** | {SEVERITY_BADGE[risk] if risk is not None else '✅ No findings'} |",
        "",
    ]

    if not detections:
        lines += [
            "No suspicious activity was detected by the enabled rules.",
            "",
            "> Absence of findings is not proof of absence of compromise. Verify that the "
            "relevant audit policies (logon, process creation with command line, account "
            "management) were enabled on the source host.",
            "",
        ]
        return "\n".join(lines) + _footer()

    # --- Summary by severity --------------------------------------------------
    lines += ["## Summary", "", "| Severity | Count |", "|---|---:|"]
    for severity in sorted(Severity, reverse=True):
        if counts[severity]:
            lines.append(f"| {SEVERITY_BADGE[severity]} | {counts[severity]} |")
    lines.append("")

    # --- Findings overview table ---------------------------------------------
    lines += [
        "## Findings",
        "",
        "| # | Severity | First seen (UTC) | Detection | ATT&CK | Summary |",
        "|---:|---|---|---|---|---|",
    ]
    for i, d in enumerate(detections, 1):
        techniques = ", ".join(technique_link(t) for t in d.techniques)
        lines.append(
            f"| [{i}](#finding-{i}) | {SEVERITY_BADGE[d.severity]} | {fmt_time(d.timestamp)} | "
            f"{md_escape(d.title)} | {techniques} | {md_escape(d.summary)} |"
        )
    lines.append("")

    # --- Chronological timeline (the overview above is sorted by severity) ----
    lines += ["## Timeline", "", "| Time (UTC) | # | Severity | Event |", "|---|---:|---|---|"]
    numbered = sorted(enumerate(detections, 1), key=lambda pair: pair[1].timestamp)
    for i, d in numbered:
        lines.append(
            f"| {fmt_time(d.timestamp)} | [{i}](#finding-{i}) | {SEVERITY_BADGE[d.severity]} | {md_escape(d.title)} |"
        )
    lines.append("")

    # --- ATT&CK coverage ------------------------------------------------------
    by_technique: dict[Technique, list[int]] = {}
    for i, d in enumerate(detections, 1):
        for t in d.techniques:
            by_technique.setdefault(t, []).append(i)
    lines += [
        "## MITRE ATT&CK Coverage",
        "",
        "| Technique | Name | Tactic(s) | Findings |",
        "|---|---|---|---|",
    ]
    for t in sorted(by_technique, key=lambda t: t.id):
        refs = ", ".join(f"[#{i}](#finding-{i})" for i in by_technique[t])
        lines.append(f"| {technique_link(t)} | {t.name} | {', '.join(t.tactics)} | {refs} |")
    lines.append("")

    # --- Per-finding details --------------------------------------------------
    lines += ["## Finding Details", ""]
    for i, d in enumerate(detections, 1):
        # Explicit anchor so the overview table links work regardless of heading text.
        lines += [f'<a id="finding-{i}"></a>', ""]
        lines += _render_detail(i, d)
        lines += ["---", ""]

    return "\n".join(lines) + _footer()


def _footer() -> str:
    return (
        f"\n*Generated by EventHunter v{__version__}. Findings are leads for investigation, "
        "not verdicts — validate each against the raw events.*\n"
    )


def render_json(
    detections: Sequence[Detection],
    events: Sequence[Event],
    sources: Sequence[str],
    skipped: int = 0,
    generated_at: datetime | None = None,
) -> str:
    """Machine-readable equivalent of :func:`render_markdown` (e.g. for SIEM ingestion)."""
    generated_at = generated_at or datetime.now(timezone.utc)
    stamps = [e.timestamp for e in events]
    payload = {
        "tool": "EventHunter",
        "version": __version__,
        "generated_at": generated_at.isoformat(),
        "sources": list(sources),
        "events_analysed": len(events),
        "records_skipped": skipped,
        "time_range": {
            "start": min(stamps).isoformat() if stamps else None,
            "end": max(stamps).isoformat() if stamps else None,
        },
        "detections": [
            {
                "rule": d.rule,
                "title": d.title,
                "severity": d.severity.name,
                "timestamp": d.timestamp.isoformat(),
                "end_time": d.end_time.isoformat() if d.end_time else None,
                "host": d.host,
                "summary": d.summary,
                "mitre": [
                    {"id": t.id, "name": t.name, "tactics": list(t.tactics), "url": t.url}
                    for t in d.techniques
                ],
                "details": d.details,
                "event_ids": sorted({e.event_id for e in d.events}),
                "record_ids": d.record_ids,
            }
            for d in detections
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)
