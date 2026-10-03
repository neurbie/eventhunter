"""MITRE ATT&CK technique catalogue used by EventHunter's detectors.

Only the techniques EventHunter actually maps to are listed here. Keeping them
in one place (instead of hard-coding strings in each detector) guarantees the
report shows consistent names, tactics and links, and makes it trivial to
audit the mapping against the official ATT&CK matrix:
https://attack.mitre.org/matrices/enterprise/windows/
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Technique:
    """A MITRE ATT&CK (sub-)technique.

    Attributes:
        id:      Technique ID, e.g. ``T1110.001``.
        name:    Full technique name, including the parent for sub-techniques.
        tactics: The ATT&CK tactic(s) the technique belongs to.
    """

    id: str
    name: str
    tactics: tuple[str, ...]

    @property
    def url(self) -> str:
        """Link to the technique page on attack.mitre.org.

        Sub-technique IDs use a slash in the URL: T1110.001 -> /techniques/T1110/001/
        """
        return f"https://attack.mitre.org/techniques/{self.id.replace('.', '/')}/"

    def __str__(self) -> str:
        return f"{self.id} ({self.name})"


# --- Credential Access -------------------------------------------------------
PASSWORD_GUESSING = Technique(
    "T1110.001", "Brute Force: Password Guessing", ("Credential Access",)
)

# --- Privilege Escalation / Persistence --------------------------------------
VALID_ACCOUNTS = Technique(
    "T1078",
    "Valid Accounts",
    ("Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"),
)
CREATE_LOCAL_ACCOUNT = Technique(
    "T1136.001", "Create Account: Local Account", ("Persistence",)
)
CREATE_DOMAIN_ACCOUNT = Technique(
    "T1136.002", "Create Account: Domain Account", ("Persistence",)
)

# --- Execution ---------------------------------------------------------------
POWERSHELL = Technique(
    "T1059.001", "Command and Scripting Interpreter: PowerShell", ("Execution",)
)

# --- Defense Evasion ---------------------------------------------------------
COMMAND_OBFUSCATION = Technique(
    "T1027.010", "Obfuscated Files or Information: Command Obfuscation", ("Defense Evasion",)
)
CLEAR_WINDOWS_EVENT_LOGS = Technique(
    "T1070.001", "Indicator Removal: Clear Windows Event Logs", ("Defense Evasion",)
)
