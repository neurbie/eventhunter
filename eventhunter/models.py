"""Core data structures shared by the parser, detectors and report writers.

Keeping these as plain dataclasses (rather than passing raw XML around) means
the detectors never have to know anything about the EVTX binary format, and
can be unit tested with hand-built events.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum

from eventhunter.mitre import Technique


class Severity(IntEnum):
    """Detection severity.

    An ``IntEnum`` so severities can be compared and sorted directly
    (``Severity.HIGH > Severity.MEDIUM``).
    """

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:  # "HIGH" rather than "Severity.HIGH"
        return self.name

    @classmethod
    def parse(cls, value: str) -> "Severity":
        """Parse a case-insensitive severity name, e.g. from the CLI."""
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            valid = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity {value!r} (expected one of: {valid})") from exc


@dataclass(frozen=True)
class Event:
    """A single, normalised Windows event record.

    Attributes:
        event_id:   The numeric Event ID (e.g. 4625).
        timestamp:  When the event was generated, as a timezone-aware UTC datetime.
        record_id:  The EventRecordID - unique and monotonically increasing per log,
                    which makes it the best way to point an analyst at the raw record.
        provider:   The ETW provider that wrote the event
                    (e.g. ``Microsoft-Windows-Security-Auditing``).
        channel:    The log the event came from (e.g. ``Security``).
        computer:   The hostname recorded in the event.
        data:       Flattened ``EventData``/``UserData`` fields, keyed by field name.
        source:     The file the event was read from (useful when scanning several logs).
    """

    event_id: int
    timestamp: datetime
    record_id: int | None = None
    provider: str = ""
    channel: str = ""
    computer: str = ""
    data: dict[str, str] = field(default_factory=dict)
    source: str = ""

    def get(self, name: str, default: str = "") -> str:
        """Return an event data field, or ``default`` if it is absent or empty."""
        value = self.data.get(name)
        return value if value not in (None, "") else default


@dataclass
class Detection:
    """A single finding produced by a detector.

    A detection may summarise *many* events (e.g. a brute-force burst of 40
    failed logons) - ``events`` keeps references to all of them so the report
    can cite the exact record IDs as evidence.

    Attributes:
        rule:        Short, stable identifier of the detector (e.g. ``brute-force``).
        title:       Human-readable headline for the finding.
        severity:    How urgently an analyst should look at this.
        techniques:  MITRE ATT&CK techniques this behaviour maps to (primary first).
        timestamp:   When the activity started (first event in the finding).
        end_time:    When the activity ended, for findings that span several events.
        summary:     One-line description shown in the report's overview table.
        details:     Ordered key/value evidence shown in the detailed section.
        rationale:   Why this pattern matters to a defender.
        next_steps:  Suggested triage actions.
        events:      The underlying events that triggered the detection.
    """

    rule: str
    title: str
    severity: Severity
    techniques: list[Technique]
    timestamp: datetime
    summary: str
    end_time: datetime | None = None
    details: dict[str, str] = field(default_factory=dict)
    rationale: str = ""
    next_steps: list[str] = field(default_factory=list)
    events: list[Event] = field(default_factory=list)

    @property
    def host(self) -> str:
        """Hostname(s) involved in the detection, comma separated."""
        hosts = sorted({e.computer for e in self.events if e.computer})
        return ", ".join(hosts) if hosts else "unknown"

    @property
    def record_ids(self) -> list[int]:
        """EventRecordIDs of all evidence events, in ascending order."""
        return sorted(e.record_id for e in self.events if e.record_id is not None)
