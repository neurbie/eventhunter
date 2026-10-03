"""Detection rules.

Each detector is a small class with a single responsibility. To add a new
rule, subclass :class:`~eventhunter.detectors.base.Detector`, declare its
``event_ids``, implement ``detect()``, and add it to :data:`ALL_DETECTORS`.
"""

from eventhunter.detectors.account_creation import AccountCreationDetector
from eventhunter.detectors.base import Detector, DetectorConfig
from eventhunter.detectors.brute_force import BruteForceDetector
from eventhunter.detectors.log_cleared import LogClearedDetector
from eventhunter.detectors.powershell import SuspiciousPowerShellDetector
from eventhunter.detectors.privilege import PrivilegeEscalationDetector

#: Every detector shipped with EventHunter, in report order.
ALL_DETECTORS: list[type[Detector]] = [
    BruteForceDetector,
    PrivilegeEscalationDetector,
    SuspiciousPowerShellDetector,
    AccountCreationDetector,
    LogClearedDetector,
]

__all__ = [
    "ALL_DETECTORS",
    "AccountCreationDetector",
    "BruteForceDetector",
    "Detector",
    "DetectorConfig",
    "LogClearedDetector",
    "PrivilegeEscalationDetector",
    "SuspiciousPowerShellDetector",
]
