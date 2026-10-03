"""Backdoor account detection: Event ID 4720 (a user account was created).

Account creation is rare on most hosts and is exactly what an attacker does
to keep access after their initial foothold is cleaned up. Every 4720 is
reported; severity is raised to CRITICAL when the new account name ends in
``$``. Real computer accounts are created with Event ID 4741, so a *user*
account named like ``SVC01$`` is an attempt to blend in with machine
accounts, which many tools and admins filter out by default.
"""

from __future__ import annotations

from eventhunter import mitre
from eventhunter.detectors.base import SECURITY_AUDITING, Detector, qualified_name
from eventhunter.models import Detection, Event, Severity

ACCOUNT_CREATED = 4720


def is_local_account(event: Event) -> bool:
    """True if the new account lives in the host's local SAM rather than the domain.

    For local accounts, TargetDomainName is the computer's own short name.
    """
    host = event.computer.split(".", 1)[0].upper()
    return bool(host) and event.get("TargetDomainName").upper() == host


class AccountCreationDetector(Detector):
    """New user accounts - a common persistence (backdoor) technique."""

    rule = "account-created"
    event_ids = frozenset({ACCOUNT_CREATED})
    providers = frozenset({SECURITY_AUDITING})

    def detect(self, events: list[Event]) -> list[Detection]:
        return [
            self._build(event)
            for event in events
            if not self.config.is_ignored(event.get("TargetUserName"))
        ]

    def _build(self, event: Event) -> Detection:
        new_user = event.get("TargetUserName", "unknown")
        new_account = qualified_name(event.get("TargetDomainName"), new_user)
        creator = qualified_name(event.get("SubjectDomainName"), event.get("SubjectUserName", "unknown"))
        local = is_local_account(event)

        masquerading = new_user.endswith("$")
        if masquerading:
            severity = Severity.CRITICAL
            title = "User account disguised as computer account"
        else:
            severity = Severity.HIGH
            title = "User account created"

        details = {
            "New account": new_account,
            "New account SID": event.get("TargetSid", "n/a"),
            "Account scope": "local (SAM)" if local else "domain",
            "Created by": creator,
            "Creator logon ID": event.get("SubjectLogonId", "n/a"),
        }
        if masquerading:
            details["Why critical"] = (
                "Name ends in '$' like a computer account, but this is a user account (4720). "
                "Real computer accounts are created via Event ID 4741."
            )

        return Detection(
            rule=self.rule,
            title=title,
            severity=severity,
            techniques=[mitre.CREATE_LOCAL_ACCOUNT if local else mitre.CREATE_DOMAIN_ACCOUNT],
            timestamp=event.timestamp,
            summary=f"{creator} created account {new_account}",
            details=details,
            rationale=(
                "Creating an account is one of the simplest ways for an attacker to keep "
                "access: even if the original malware or stolen password is cleaned up, the "
                "backdoor account still works. Accounts created outside the normal "
                "provisioning process (HR ticket, IAM tooling) - especially at odd hours or "
                "by an unexpected user - deserve immediate review."
            ),
            next_steps=[
                "Verify the creation against a change/provisioning ticket.",
                "Check whether the account was added to a privileged group (Event IDs "
                "4728/4732/4756) and whether it has logged on (4624/4672).",
                "Investigate the creator's session (Creator logon ID) for other activity.",
                "Disable the account if it cannot be accounted for.",
            ],
            events=[event],
        )
