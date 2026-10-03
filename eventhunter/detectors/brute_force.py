"""Brute-force detection: bursts of Event ID 4625 (failed logon) against one account.

Logic
-----
1. Group 4625 events by target account.
2. Slide a time window (default 5 minutes) over each account's failures. Any
   window holding at least ``threshold`` failures (default 5) is a burst;
   overlapping bursts are merged so one attack produces one finding.
3. If the same account then logs on *successfully* (Event ID 4624) within the
   window after the last failure, escalate to CRITICAL - the attacker may
   have guessed the password.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from eventhunter import mitre
from eventhunter.detectors.base import SECURITY_AUDITING, Detector, qualified_name
from eventhunter.models import Detection, Event, Severity

FAILED_LOGON = 4625
SUCCESSFUL_LOGON = 4624

# NTSTATUS SubStatus codes seen in 4625 events. They tell you *why* the logon
# failed - e.g. lots of "user does not exist" suggests username enumeration.
FAILURE_REASONS = {
    "0xc000006a": "wrong password",
    "0xc0000064": "user does not exist",
    "0xc0000234": "account locked out",
    "0xc0000072": "account disabled",
    "0xc000006f": "outside permitted logon hours",
    "0xc0000070": "workstation restriction",
    "0xc0000071": "password expired",
    "0xc0000193": "account expired",
    "0xc0000224": "password must change at next logon",
    "0xc0000133": "clock skew between DC and host",
    "0xc000015b": "logon type not granted",
}

LOGON_TYPES = {
    "2": "Interactive",
    "3": "Network",
    "4": "Batch",
    "5": "Service",
    "7": "Unlock",
    "8": "NetworkCleartext",
    "9": "NewCredentials",
    "10": "RemoteInteractive (RDP)",
    "11": "CachedInteractive",
}


def _distinct(values: list[str]) -> list[str]:
    """Sorted unique values, ignoring the "-" placeholder Windows uses for 'none'."""
    return sorted({v for v in values if v and v != "-"})


def find_bursts(events: list[Event], threshold: int, window: timedelta) -> list[list[Event]]:
    """Return groups of events where >= ``threshold`` occur within ``window``.

    ``events`` must be sorted by timestamp. Uses a two-pointer sliding window
    (O(n)); qualifying windows that overlap are merged into a single burst.
    """
    bursts: list[list[Event]] = []
    current_start = current_end = -1  # index range of the burst being built
    left = 0
    for right, event in enumerate(events):
        while event.timestamp - events[left].timestamp > window:
            left += 1
        if right - left + 1 < threshold:
            continue
        if current_end >= 0 and left <= current_end:
            current_end = right  # overlaps the current burst - extend it
        else:
            if current_end >= 0:
                bursts.append(events[current_start : current_end + 1])
            current_start, current_end = left, right
    if current_end >= 0:
        bursts.append(events[current_start : current_end + 1])
    return bursts


class BruteForceDetector(Detector):
    """Repeated failed logons (4625) for the same account in a short time window."""

    rule = "brute-force"
    event_ids = frozenset({FAILED_LOGON, SUCCESSFUL_LOGON})
    providers = frozenset({SECURITY_AUDITING})

    def detect(self, events: list[Event]) -> list[Detection]:
        window = timedelta(seconds=self.config.brute_force_window)
        failures: dict[str, list[Event]] = defaultdict(list)
        successes: dict[str, list[Event]] = defaultdict(list)

        for event in events:
            user = event.get("TargetUserName")
            if not user or user == "-" or self.config.is_ignored(user):
                continue
            key = user.lower()
            if event.event_id == FAILED_LOGON:
                failures[key].append(event)
            else:
                successes[key].append(event)

        detections = []
        for key, account_failures in failures.items():
            for burst in find_bursts(account_failures, self.config.brute_force_threshold, window):
                detections.append(self._build(burst, successes.get(key, []), window))
        return detections

    def _build(self, burst: list[Event], successes: list[Event], window: timedelta) -> Detection:
        first, last = burst[0], burst[-1]
        account = qualified_name(first.get("TargetDomainName"), first.get("TargetUserName"))

        # A success during the burst or shortly after it means the guessing may have worked.
        success = next(
            (s for s in successes if first.timestamp <= s.timestamp <= last.timestamp + window),
            None,
        )

        ips = _distinct([e.get("IpAddress") for e in burst])
        workstations = _distinct([e.get("WorkstationName") for e in burst])
        logon_types = _distinct([LOGON_TYPES.get(e.get("LogonType"), e.get("LogonType")) for e in burst])
        reasons = _distinct(
            [FAILURE_REASONS.get(e.get("SubStatus").lower(), e.get("SubStatus")) for e in burst]
        )
        duration = (last.timestamp - first.timestamp).total_seconds()

        details = {
            "Target account": account,
            "Failed attempts": str(len(burst)),
            "Duration": f"{duration:.0f}s",
            "Source IP(s)": ", ".join(ips) or "n/a",
            "Source workstation(s)": ", ".join(workstations) or "n/a",
            "Logon type(s)": ", ".join(logon_types) or "n/a",
            "Failure reason(s)": ", ".join(reasons) or "n/a",
        }

        evidence = list(burst)
        if success:
            severity = Severity.CRITICAL
            title = "Brute force followed by successful logon"
            details["Successful logon"] = (
                f"{success.timestamp:%Y-%m-%d %H:%M:%S} UTC from "
                f"{success.get('IpAddress', 'n/a')} (record {success.record_id})"
            )
            evidence.append(success)
        else:
            severity = Severity.HIGH
            title = "Possible brute force"

        source = f" from {', '.join(ips)}" if ips else ""
        summary = f"{len(burst)} failed logons for {account}{source} in {duration:.0f}s"
        if success:
            summary += " - then a successful logon"

        return Detection(
            rule=self.rule,
            title=title,
            severity=severity,
            techniques=[mitre.PASSWORD_GUESSING],
            timestamp=first.timestamp,
            end_time=last.timestamp,
            summary=summary,
            details=details,
            rationale=(
                "Many failed logons against a single account in a short period is the "
                "signature of an online password-guessing attack (manual, scripted with "
                "Hydra/CrackMapExec, or a misconfigured service). Successful compromise "
                "gives the attacker a valid account, which defeats most perimeter controls. "
                "A success shortly after the failures is the most important thing to rule out."
            ),
            next_steps=[
                "Check whether the source IP(s) are internal, expected, or known-bad.",
                "If a successful logon followed, treat the account as compromised: reset "
                "credentials, review its activity (4624/4672/4688) after that time.",
                "Many 'user does not exist' failures suggest username enumeration; many "
                "accounts from one IP suggest password spraying.",
                "Confirm account lockout policy is configured.",
            ],
            events=evidence,
        )
