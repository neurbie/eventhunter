import json

from eventhunter.cli import main
from eventhunter.engine import run_detectors
from eventhunter.report import code_block, md_escape, render_json, render_markdown

from conftest import T0, make_event


def _scenario():
    events = [
        make_event(1102, 100, SubjectUserName="alice", SubjectDomainName="CORP"),
        make_event(4720, 50, TargetUserName="evil|user", TargetDomainName="CORP", SubjectUserName="alice"),
    ]
    return events, run_detectors(events)


def test_markdown_report_sections():
    events, detections = _scenario()
    md = render_markdown(detections, events, sources=["Security.evtx"], generated_at=T0)
    for heading in ("# EventHunter Report", "## Summary", "## Findings", "## Timeline", "## MITRE ATT&CK Coverage", "## Finding Details"):
        assert heading in md
    assert "[T1070.001](https://attack.mitre.org/techniques/T1070/001/)" in md
    assert "🔴 CRITICAL" in md
    assert '<a id="finding-1"></a>' in md


def test_markdown_escapes_attacker_controlled_values():
    events, detections = _scenario()
    md = render_markdown(detections, events, sources=["Security.evtx"], generated_at=T0)
    # A raw pipe would split the table cell.
    assert "evil\\|user" in md
    assert "evil|user" not in md


def test_empty_report():
    md = render_markdown([], [], sources=["clean.evtx"], generated_at=T0)
    assert "No suspicious activity" in md
    assert "## Findings" not in md


def test_json_report_is_valid():
    events, detections = _scenario()
    data = json.loads(render_json(detections, events, sources=["Security.evtx"], generated_at=T0))
    assert data["events_analysed"] == 2
    assert data["detections"][0]["mitre"][0]["id"] == "T1070.001"


def test_md_escape_and_code_block():
    assert md_escape("a|b*c\nd") == "a\\|b\\*c d"
    assert code_block("x ``` y").startswith("````")


def test_cli_missing_file_returns_2(tmp_path, capsys):
    assert main([str(tmp_path / "missing.evtx"), "-q"]) == 2


def test_cli_rejects_bad_severity(capsys):
    import pytest

    with pytest.raises(SystemExit) as exc:
        main(["x.evtx", "--min-severity", "extreme"])
    assert exc.value.code == 2
