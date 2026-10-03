"""Suspicious PowerShell detection in Event ID 4688 (process creation).

Requires the "Include command line in process creation events" audit policy,
otherwise 4688 has no ``CommandLine`` field and there is nothing to inspect.

Each command line is scored against a set of weighted indicators. The score
determines the severity, so a lone ``-NoProfile`` (common in admin scripts)
is ignored, while ``-w hidden -nop -enc <base64>`` scores very high.

Encoded commands are decoded (Base64 -> UTF-16LE, the encoding PowerShell
uses) so the analyst sees the real script, and the decoded text is scanned
with the same indicators - payloads are often hidden one layer down.
"""

from __future__ import annotations

import base64
import binascii
import ntpath
import re
from dataclasses import dataclass

from eventhunter import mitre
from eventhunter.detectors.base import SECURITY_AUDITING, Detector, qualified_name
from eventhunter.models import Detection, Event, Severity

PROCESS_CREATION = 4688

# PowerShell accepts '-', '/' and the Unicode dashes en/em/horizontal-bar as
# parameter prefixes. Attackers use the Unicode variants to slip past naive
# "-enc" string matches.
_DASH = r"[-/–—―]"


def _prefixes(word: str, minimum: int = 1) -> str:
    """Regex alternation of every prefix of ``word`` at least ``minimum`` chars long.

    PowerShell lets you abbreviate any parameter to an unambiguous prefix, so
    ``-e``, ``-enc``, ``-encodedc`` and ``-EncodedCommand`` are all equivalent.
    Longest first so the regex engine prefers the full match.
    """
    return "|".join(word[:i] for i in range(len(word), minimum - 1, -1))


_ENCODED_RE = re.compile(
    rf"(?:^|\s){_DASH}(?:{_prefixes('encodedcommand')}|ec)\s+[\"']?([A-Za-z0-9+/=]{{8,}})",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Indicator:
    """A weighted pattern that contributes to a command line's suspicion score."""

    name: str
    pattern: re.Pattern[str]
    weight: int


INDICATORS = [
    Indicator("Encoded command (-EncodedCommand)", _ENCODED_RE, 3),
    Indicator(
        "Download cradle",
        re.compile(
            r"DownloadString|DownloadFile|DownloadData|Net\.WebClient|Invoke-WebRequest|"
            r"\biwr\b|Start-BitsTransfer|Invoke-RestMethod|\birm\b",
            re.IGNORECASE,
        ),
        2,
    ),
    Indicator(
        "Dynamic code execution (Invoke-Expression)",
        re.compile(r"Invoke-Expression|\biex\b|\.Invoke\(", re.IGNORECASE),
        2,
    ),
    Indicator(
        "Inline Base64 decoding",
        re.compile(r"FromBase64String", re.IGNORECASE),
        2,
    ),
    Indicator(
        "Character-level obfuscation",
        # Lots of escape characters (`) / carets (^), or string concatenation like 'Down'+'load'.
        re.compile(r"(?:[`^][^`^]{0,10}){4,}|['\"]\s*\+\s*['\"]"),
        2,
    ),
    Indicator(
        "Hidden window",
        re.compile(rf"{_DASH}w(?:{_prefixes('indowstyle')})?\s+[\"']?(?:hidden|h|1)\b", re.IGNORECASE),
        1,
    ),
    Indicator(
        "Execution policy bypass",
        re.compile(
            rf"{_DASH}(?:ep|ex(?:{_prefixes('ecutionpolicy')})?)\s+[\"']?(?:bypass|unrestricted)\b",
            re.IGNORECASE,
        ),
        1,
    ),
    Indicator(
        "No profile (-NoProfile)",
        re.compile(rf"{_DASH}nop(?:{_prefixes('rofile')})?\b", re.IGNORECASE),
        1,
    ),
    Indicator(
        "Non-interactive (-NonInteractive)",
        re.compile(rf"{_DASH}noni(?:{_prefixes('nteractive')})?\b", re.IGNORECASE),
        1,
    ),
]

_POWERSHELL_IMAGES = ("powershell.exe", "pwsh.exe", "powershell_ise.exe")
_POWERSHELL_IN_CMDLINE = re.compile(r"\b(?:powershell|pwsh)(?:\.exe)?\b", re.IGNORECASE)

MAX_DECODED_CHARS = 400


def decode_encoded_command(payload: str) -> str | None:
    """Decode a ``-EncodedCommand`` argument (Base64 of UTF-16LE text).

    Returns None if the payload isn't valid Base64 or doesn't decode to
    mostly-printable text (i.e. we guessed wrong about what it is).
    """
    payload = payload.strip("\"'")
    payload += "=" * (-len(payload) % 4)  # tolerate stripped padding
    try:
        raw = base64.b64decode(payload, validate=True)
    except (binascii.Error, ValueError):
        return None

    for encoding in ("utf-16-le", "utf-8"):
        try:
            text = raw.decode(encoding)
        except UnicodeDecodeError:
            continue
        printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in text)
        if text and printable / len(text) > 0.9:
            return text
    return None


def score_command_line(command_line: str) -> tuple[int, list[str], str | None]:
    """Score a command line.

    Returns:
        ``(score, indicator_names, decoded_payload)``. Indicators found only
        inside the decoded payload are suffixed with ``(decoded)``.
    """
    score = 0
    hits: list[str] = []
    for indicator in INDICATORS:
        if indicator.pattern.search(command_line):
            score += indicator.weight
            hits.append(indicator.name)

    decoded = None
    match = _ENCODED_RE.search(command_line)
    if match:
        decoded = decode_encoded_command(match.group(1))
    if decoded:
        for indicator in INDICATORS:
            if indicator.name not in hits and indicator.pattern.search(decoded):
                score += indicator.weight
                hits.append(f"{indicator.name} (decoded)")
    return score, hits, decoded


def severity_for_score(score: int) -> Severity | None:
    """Map a suspicion score to a severity (None = not suspicious enough to report)."""
    if score >= 5:
        return Severity.CRITICAL
    if score >= 3:
        return Severity.HIGH
    if score >= 2:
        return Severity.MEDIUM
    return None


def is_powershell(event: Event) -> bool:
    """True if the new process is PowerShell, or the command line launches it (cmd /c powershell ...)."""
    image = event.get("NewProcessName").lower()
    return image.endswith(_POWERSHELL_IMAGES) or bool(
        _POWERSHELL_IN_CMDLINE.search(event.get("CommandLine"))
    )


class SuspiciousPowerShellDetector(Detector):
    """Encoded or obfuscated PowerShell command lines in process creation events."""

    rule = "suspicious-powershell"
    event_ids = frozenset({PROCESS_CREATION})
    providers = frozenset({SECURITY_AUDITING})

    def detect(self, events: list[Event]) -> list[Detection]:
        detections = []
        for event in events:
            command_line = event.get("CommandLine")
            if not command_line or not is_powershell(event):
                continue
            if self.config.is_ignored(event.get("SubjectUserName")):
                continue
            score, hits, decoded = score_command_line(command_line)
            severity = severity_for_score(score)
            if severity is not None:
                detections.append(self._build(event, severity, score, hits, decoded))
        return detections

    def _build(
        self, event: Event, severity: Severity, score: int, hits: list[str], decoded: str | None
    ) -> Detection:
        user = event.get("SubjectUserName", "unknown")
        image = event.get("NewProcessName", "unknown")
        details = {
            "User": qualified_name(event.get("SubjectDomainName"), user),
            "Process": image,
            "Parent process": event.get("ParentProcessName", "n/a"),
            "Indicators": ", ".join(hits),
            "Suspicion score": str(score),
            "Command line": event.get("CommandLine"),
        }
        if decoded:
            shown = decoded if len(decoded) <= MAX_DECODED_CHARS else decoded[:MAX_DECODED_CHARS] + " ..."
            details["Decoded payload"] = shown

        techniques = [mitre.POWERSHELL]
        if any(h.startswith(("Encoded", "Character-level", "Inline Base64")) for h in hits):
            techniques.append(mitre.COMMAND_OBFUSCATION)

        title = (
            "Encoded PowerShell execution"
            if decoded or any(h.startswith("Encoded") for h in hits)
            else "Suspicious PowerShell command line"
        )
        return Detection(
            rule=self.rule,
            title=title,
            severity=severity,
            techniques=techniques,
            timestamp=event.timestamp,
            summary=f"{user} ran {ntpath.basename(image)} with: {', '.join(hits)}",
            details=details,
            rationale=(
                "PowerShell is installed on every Windows host and can download and run code "
                "entirely in memory, which makes it a favourite of commodity malware and "
                "red-team frameworks alike (Empire, Cobalt Strike, Metasploit all emit "
                "`powershell -nop -w hidden -enc ...`). Base64 encoding and character "
                "obfuscation have almost no legitimate administrative use; their purpose is "
                "to hide the command from people and from signature-based tools."
            ),
            next_steps=[
                "Read the decoded payload: look for URLs, IPs, and second-stage downloads.",
                "Identify the parent process - Office apps, browsers or wscript spawning "
                "PowerShell strongly suggests initial access via phishing.",
                "Check PowerShell Operational logs (Event ID 4104 script block logging) for "
                "the full de-obfuscated script.",
                "Isolate the host if a download cradle or credential-theft tooling is present.",
            ],
            events=[event],
        )
