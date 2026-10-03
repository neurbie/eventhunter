"""Detector base class, shared configuration and helpers."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from eventhunter.models import Detection, Event

# Provider names. Event IDs are only unique *per provider*, so detectors check
# both - otherwise e.g. an unrelated application event with ID 1102 would be
# reported as "audit log cleared".
SECURITY_AUDITING = "Microsoft-Windows-Security-Auditing"
EVENTLOG = "Microsoft-Windows-Eventlog"

# Built-in Windows identities that legitimately log on with special privileges
# hundreds of times a day. Reporting them would bury real findings.
_SYSTEM_ACCOUNTS = {"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON"}
# Desktop Window Manager / User-Mode Font Driver virtual accounts: DWM-1, UMFD-0, ...
_VIRTUAL_ACCOUNT_RE = re.compile(r"^(DWM|UMFD)-\d+$", re.IGNORECASE)


def is_system_account(username: str) -> bool:
    """Return True for built-in service identities and computer accounts (``HOST$``)."""
    name = username.strip().upper()
    return (
        name in _SYSTEM_ACCOUNTS
        or name.endswith("$")
        or bool(_VIRTUAL_ACCOUNT_RE.match(name))
    )


def qualified_name(domain: str, user: str) -> str:
    """Format an account as ``DOMAIN\\user`` (or just ``user`` if there's no domain)."""
    domain = domain.strip()
    return f"{domain}\\{user}" if domain and domain != "-" else user


@dataclass
class DetectorConfig:
    """Tunable thresholds shared by all detectors.

    Attributes:
        brute_force_threshold: Failed logons for one account needed to raise an alert.
        brute_force_window:    Sliding time window, in seconds, those failures must fall in.
        ignore_accounts:       Account names (case-insensitive, no domain) to never alert on,
                               e.g. a vulnerability scanner's service account.
    """

    brute_force_threshold: int = 5
    brute_force_window: int = 300
    ignore_accounts: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        if self.brute_force_threshold < 2:
            raise ValueError("brute-force threshold (--bf-threshold) must be at least 2")
        if self.brute_force_window <= 0:
            raise ValueError("brute-force window (--bf-window) must be positive")
        self.ignore_accounts = {a.strip().lower() for a in self.ignore_accounts}

    def is_ignored(self, username: str) -> bool:
        return username.strip().lower() in self.ignore_accounts


class Detector(ABC):
    """Base class for all detection rules.

    Subclasses declare which events they care about via :attr:`event_ids` and
    :attr:`providers`, and implement :meth:`detect`. The engine pre-filters the
    event stream, so ``detect`` only ever sees relevant, time-sorted events.

    A detector receives *all* of its events at once (not one at a time) because
    several rules are stateful - brute force needs a sliding window, and
    privilege use is correlated with account creation.
    """

    #: Stable identifier shown in reports, e.g. ``brute-force``.
    rule: str = ""
    #: Event IDs this detector consumes.
    event_ids: frozenset[int] = frozenset()
    #: Accepted providers. Empty means "any provider".
    providers: frozenset[str] = frozenset()

    def __init__(self, config: DetectorConfig | None = None) -> None:
        self.config = config or DetectorConfig()

    def accepts(self, event: Event) -> bool:
        """Return True if ``event`` should be passed to :meth:`detect`.

        Events with an empty provider (e.g. hand-built test events or odd
        exports) are accepted so the ID check alone still applies.
        """
        if event.event_id not in self.event_ids:
            return False
        return not self.providers or not event.provider or event.provider in self.providers

    @abstractmethod
    def detect(self, events: list[Event]) -> list[Detection]:
        """Analyse time-ordered ``events`` and return any findings."""
