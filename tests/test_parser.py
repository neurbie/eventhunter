from datetime import datetime, timezone

import pytest

from eventhunter.parser import parse_event_xml, parse_evtx, parse_timestamp

NS = 'xmlns="http://schemas.microsoft.com/win/2004/08/events/event"'

EVENTDATA_XML = f"""<Event {NS}><System>
<Provider Name="Microsoft-Windows-Security-Auditing"></Provider>
<EventID Qualifiers="">4625</EventID>
<TimeCreated SystemTime="2026-09-14 02:00:01.123456+00:00"></TimeCreated>
<EventRecordID>4242</EventRecordID>
<Channel>Security</Channel>
<Computer>WS01.corp.local</Computer>
</System>
<EventData><Data Name="TargetUserName">alice</Data>
<Data Name="IpAddress">10.0.0.5</Data>
<Data Name="Empty"></Data>
</EventData></Event>"""

# 1102 stores its fields under UserData with a provider-specific namespace (taken from a real log).
USERDATA_XML = f"""<Event {NS}><System>
<Provider Name="Microsoft-Windows-Eventlog"></Provider>
<EventID Qualifiers="">1102</EventID>
<TimeCreated SystemTime="2019-03-19 23:35:07.524200+00:00"></TimeCreated>
<EventRecordID>452811</EventRecordID>
<Channel>Security</Channel>
<Computer>PC01.example.corp</Computer>
</System>
<UserData><LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">
<SubjectUserName>user01</SubjectUserName>
<SubjectDomainName>EXAMPLE</SubjectDomainName>
</LogFileCleared></UserData></Event>"""


def test_parses_system_fields_and_eventdata():
    e = parse_event_xml(EVENTDATA_XML, source="Security.evtx")
    assert e.event_id == 4625
    assert e.record_id == 4242
    assert e.provider == "Microsoft-Windows-Security-Auditing"
    assert e.computer == "WS01.corp.local"
    assert e.timestamp == datetime(2026, 9, 14, 2, 0, 1, 123456, tzinfo=timezone.utc)
    assert e.get("TargetUserName") == "alice"
    assert e.get("IpAddress") == "10.0.0.5"
    assert e.get("Empty", "default") == "default"
    assert e.source == "Security.evtx"


def test_flattens_userdata():
    e = parse_event_xml(USERDATA_XML)
    assert e.event_id == 1102
    assert e.get("SubjectUserName") == "user01"
    assert e.get("SubjectDomainName") == "EXAMPLE"


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("2019-03-19 23:35:07.524200+00:00", datetime(2019, 3, 19, 23, 35, 7, 524200, tzinfo=timezone.utc)),
        ("2019-03-19T23:35:07.5242001Z", datetime(2019, 3, 19, 23, 35, 7, 524200, tzinfo=timezone.utc)),
        ("2019-03-19 23:35:07", datetime(2019, 3, 19, 23, 35, 7, tzinfo=timezone.utc)),
    ],
)
def test_parse_timestamp_formats(raw, expected):
    assert parse_timestamp(raw) == expected


@pytest.mark.parametrize("bad", ["<not xml", f"<Event {NS}></Event>"])
def test_rejects_malformed_events(bad):
    with pytest.raises(ValueError):
        parse_event_xml(bad)


def test_parse_evtx_missing_file(tmp_path):
    pytest.importorskip("Evtx")
    with pytest.raises(FileNotFoundError):
        list(parse_evtx(tmp_path / "nope.evtx"))


def test_parse_evtx_rejects_non_evtx(tmp_path):
    pytest.importorskip("Evtx")
    bogus = tmp_path / "bogus.evtx"
    bogus.write_bytes(b"this is not an event log" * 300)
    with pytest.raises(ValueError):
        list(parse_evtx(bogus))
