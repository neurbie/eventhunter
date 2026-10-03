"""Anti-forensics detection: Event ID 1102 (the Security audit log was cleared).

When the Security log is cleared, Windows writes 1102 as the first record of
the new, empty log - recording who did it. There is almost never a benign
reason to clear the Security log on a production system, so every
occurrence is CRITICAL.
"""

from __future__ import annotations

from eventhunter import mitre
from eventhunter.detectors.base import EVENTLOG, Detector, qualified_name
from eventhunter.models import Detection, Event, Severity

AUDIT_LOG_CLEARED = 1102


class LogClearedDetector(Detector):
    """The Security event log was wiped."""

    rule = "audit-log-cleared"
    event_ids = frozenset({AUDIT_LOG_CLEARED})
    providers = frozenset({EVENTLOG})

    def detect(self, events: list[Event]) -> list[Detection]:
        return [self._build(event) for event in events]

    def _build(self, event: Event) -> Detection:
        actor = qualified_name(event.get("SubjectDomainName"), event.get("SubjectUserName", "unknown"))
        return Detection(
            rule=self.rule,
            title="Security audit log cleared",
            severity=Severity.CRITICAL,
            techniques=[mitre.CLEAR_WINDOWS_EVENT_LOGS],
            timestamp=event.timestamp,
            summary=f"Security log cleared by {actor}",
            details={
                "Cleared by": actor,
                "User SID": event.get("SubjectUserSid", "n/a"),
                "Logon ID": event.get("SubjectLogonId", "n/a"),
                "Channel": event.channel or "Security",
            },
            rationale=(
                "Attackers clear event logs to destroy the evidence of what they did "
                "(`wevtutil cl Security`, `Clear-EventLog`, Mimikatz `event::clear`). "
                "Because 1102 is written *after* the wipe, it is often the only surviving "
                "trace - everything before it is gone from this host. Treat it as a strong "
                "signal that an intrusion is in progress or being covered up."
            ),
            next_steps=[
                "Recover the lost history from a SIEM, Windows Event Forwarding, or backups.",
                "Determine whether the clearing account and logon session were legitimate.",
                "Check other channels (System 104, PowerShell, Sysmon) for wipes of other logs.",
                "Treat the host as compromised until proven otherwise.",
            ],
            events=[event],
        )
