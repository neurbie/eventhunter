"""Privileged logon detection: Event ID 4672 (special privileges assigned to new logon).

4672 is logged whenever an account with administrator-equivalent rights logs
on. On its own it is *very* noisy - SYSTEM and service accounts generate it
constantly - so this detector:

* drops built-in service identities and computer accounts (``HOST$``),
* aggregates the remaining events into **one finding per account**, and
* escalates to HIGH when the account was *created in the same log* (4720):
  a brand-new account immediately using admin rights is a classic backdoor.
"""

from __future__ import annotations

from collections import defaultdict

from eventhunter import mitre
from eventhunter.detectors.base import (
    SECURITY_AUDITING,
    Detector,
    is_system_account,
    qualified_name,
)
from eventhunter.models import Detection, Event, Severity

SPECIAL_PRIVILEGES = 4672
ACCOUNT_CREATED = 4720

# Privileges that let a holder take over the machine (debug any process, act as
# the OS, load kernel drivers, read any file, impersonate other users...).
SENSITIVE_PRIVILEGES = {
    "SeDebugPrivilege",
    "SeTcbPrivilege",
    "SeImpersonatePrivilege",
    "SeAssignPrimaryTokenPrivilege",
    "SeLoadDriverPrivilege",
    "SeTakeOwnershipPrivilege",
    "SeBackupPrivilege",
    "SeRestorePrivilege",
    "SeCreateTokenPrivilege",
}


class PrivilegeEscalationDetector(Detector):
    """Accounts that were granted special (admin-level) privileges at logon."""

    rule = "privileged-logon"
    event_ids = frozenset({SPECIAL_PRIVILEGES, ACCOUNT_CREATED})
    providers = frozenset({SECURITY_AUDITING})

    def detect(self, events: list[Event]) -> list[Detection]:
        created = {
            e.get("TargetUserName").lower(): e for e in events if e.event_id == ACCOUNT_CREATED
        }

        by_account: dict[str, list[Event]] = defaultdict(list)
        for event in events:
            if event.event_id != SPECIAL_PRIVILEGES:
                continue
            user = event.get("SubjectUserName")
            if not user or is_system_account(user) or self.config.is_ignored(user):
                continue
            by_account[user.lower()].append(event)

        return [
            self._build(account_events, created.get(key))
            for key, account_events in by_account.items()
        ]

    def _build(self, account_events: list[Event], creation: Event | None) -> Detection:
        first, last = account_events[0], account_events[-1]
        account = qualified_name(first.get("SubjectDomainName"), first.get("SubjectUserName"))

        privileges: set[str] = set()
        for event in account_events:
            # PrivilegeList is a whitespace/newline separated list of privilege constants.
            privileges.update(event.get("PrivilegeList").split())
        sensitive = sorted(privileges & SENSITIVE_PRIVILEGES)

        details = {
            "Account": account,
            "Account SID": first.get("SubjectUserSid", "n/a"),
            "Privileged logons": str(len(account_events)),
            "Distinct logon sessions": str(len({e.get("SubjectLogonId") for e in account_events})),
            "Sensitive privileges": ", ".join(sensitive) or "none",
            "All privileges": ", ".join(sorted(privileges)) or "n/a",
        }

        evidence = list(account_events)
        if creation is not None:
            severity = Severity.HIGH
            title = "Newly created account used with admin privileges"
            details["Account created"] = (
                f"{creation.timestamp:%Y-%m-%d %H:%M:%S} UTC by "
                f"{qualified_name(creation.get('SubjectDomainName'), creation.get('SubjectUserName'))} "
                f"(record {creation.record_id})"
            )
            evidence.insert(0, creation)
        elif sensitive:
            severity = Severity.MEDIUM
            title = "Special privileges assigned to logon"
        else:
            severity = Severity.LOW
            title = "Special privileges assigned to logon"

        summary = f"{account} received special privileges in {len(account_events)} logon(s)"
        if creation is not None:
            summary += " - account was created in this log"

        return Detection(
            rule=self.rule,
            title=title,
            severity=severity,
            techniques=[mitre.VALID_ACCOUNTS],
            timestamp=first.timestamp,
            end_time=last.timestamp if last is not first else None,
            summary=summary,
            details=details,
            rationale=(
                "Event 4672 means the logon received administrator-equivalent privileges such "
                "as SeDebugPrivilege (read/write any process memory - how Mimikatz dumps LSASS) "
                "or SeTcbPrivilege (act as the operating system). Attackers who escalate "
                "privileges or abuse a stolen admin account show up here. Admins also trigger "
                "it legitimately, so the value is in asking: *should this account be admin, "
                "and at this time?*"
            ),
            next_steps=[
                "Confirm the account is an expected administrator (check group membership).",
                "Correlate the SubjectLogonId with the matching 4624 to find the logon type "
                "and source IP.",
                "Review processes started in the same session (4688 with the same logon ID).",
                "Unexpected or newly created admin accounts should be disabled pending review.",
            ],
            events=evidence,
        )
