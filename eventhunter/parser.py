"""Turn ``.evtx`` files into normalised :class:`~eventhunter.models.Event` objects.

The EVTX format is a binary, chunked format; ``python-evtx`` decodes each
record back into the same XML you would see in Event Viewer's "XML View".
This module parses that XML and flattens it into a simple ``Event``.

Two quirks of real-world logs are handled here so detectors don't have to:

* **EventData vs. UserData** - most Security events store their fields as
  ``<EventData><Data Name="...">``, but some (notably 1102 "audit log
  cleared") use ``<UserData><SomeElement><Field>...``. Both are flattened
  into one ``{name: value}`` dict.
* **Corrupt records** - logs recovered from a compromised host are often
  damaged. A bad record is logged and skipped rather than aborting the scan.
"""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from collections.abc import Iterable, Iterator
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path

from eventhunter.models import Event

log = logging.getLogger(__name__)

# Namespace used by the <System> and <EventData> sections of every event.
_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

# Windows writes 7 fractional-second digits (100ns ticks); Python accepts at most 6.
_FRACTION_RE = re.compile(r"(\.\d{6})\d+")


class ParseStats:
    """Counters describing how a parse went, surfaced in the report header."""

    def __init__(self) -> None:
        self.parsed = 0
        self.skipped = 0

    def __repr__(self) -> str:
        return f"ParseStats(parsed={self.parsed}, skipped={self.skipped})"


def parse_timestamp(value: str) -> datetime:
    """Parse a ``TimeCreated/@SystemTime`` value into an aware UTC datetime.

    Handles the formats seen in the wild, e.g.::

        2019-03-19 23:35:07.524200+00:00   (python-evtx)
        2019-03-19T23:35:07.5242001Z       (native Windows XML export)
        2019-03-19 23:35:07                (no fraction, no zone)
    """
    text = value.strip().replace("Z", "+00:00")
    text = _FRACTION_RE.sub(r"\1", text)
    ts = datetime.fromisoformat(text)
    if ts.tzinfo is None:
        # SystemTime is always UTC; be explicit so comparisons never mix naive/aware.
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


def _local_name(tag: str) -> str:
    """Strip an XML namespace: ``{urn:x}Foo`` -> ``Foo``."""
    return tag.rsplit("}", 1)[-1]


def _extract_data(root: ET.Element) -> dict[str, str]:
    """Flatten ``EventData`` / ``UserData`` into a ``{field: value}`` dict."""
    data: dict[str, str] = {}

    event_data = root.find(f"{_NS}EventData")
    if event_data is not None:
        for index, item in enumerate(event_data):
            # Unnamed <Data> elements occur in some legacy events; give them positional keys.
            name = item.get("Name") or f"Data{index}"
            data[name] = (item.text or "").strip()

    user_data = root.find(f"{_NS}UserData")
    if user_data is not None:
        # UserData wraps its fields in a single provider-specific element, e.g. <LogFileCleared>.
        for wrapper in user_data:
            for item in wrapper:
                data[_local_name(item.tag)] = (item.text or "").strip()

    return data


def parse_event_xml(xml: str, source: str = "") -> Event:
    """Parse one event's XML (as produced by python-evtx) into an :class:`Event`.

    Raises:
        ValueError: if the XML is malformed or lacks the mandatory System fields.
    """
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        raise ValueError(f"malformed event XML: {exc}") from exc

    system = root.find(f"{_NS}System")
    if system is None:
        raise ValueError("event has no <System> element")

    event_id_el = system.find(f"{_NS}EventID")
    time_el = system.find(f"{_NS}TimeCreated")
    if event_id_el is None or not (event_id_el.text or "").strip():
        raise ValueError("event has no EventID")
    if time_el is None or not time_el.get("SystemTime"):
        raise ValueError("event has no TimeCreated/@SystemTime")

    provider_el = system.find(f"{_NS}Provider")
    record_el = system.find(f"{_NS}EventRecordID")
    record_text = (record_el.text or "").strip() if record_el is not None else ""

    return Event(
        event_id=int(event_id_el.text.strip()),
        timestamp=parse_timestamp(time_el.get("SystemTime", "")),
        record_id=int(record_text) if record_text.isdigit() else None,
        provider=provider_el.get("Name", "") if provider_el is not None else "",
        channel=(system.findtext(f"{_NS}Channel") or "").strip(),
        computer=(system.findtext(f"{_NS}Computer") or "").strip(),
        data=_extract_data(root),
        source=source,
    )


def parse_evtx(
    path: str | Path,
    event_ids: Iterable[int] | None = None,
    stats: ParseStats | None = None,
) -> Iterator[Event]:
    """Yield every event in an ``.evtx`` file as an :class:`Event`.

    Args:
        path:      Path to the ``.evtx`` file.
        event_ids: Optional allow-list of Event IDs. Records with other IDs are
                   skipped before they are parsed into an ``Event``.
        stats:     Optional :class:`ParseStats` that is updated as records are read.

    Raises:
        FileNotFoundError: if ``path`` does not exist.
        ValueError:        if the file is not a valid EVTX file.
    """
    # Imported lazily so the rest of the package (and its tests) work without python-evtx.
    import Evtx.Evtx as evtx

    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"no such file: {path}")

    wanted = {int(i) for i in event_ids} if event_ids is not None else None
    stats = stats if stats is not None else ParseStats()

    # Cheap pre-filter on the raw XML so we only build ElementTrees for interesting records.
    id_re = re.compile(r"<EventID[^>]*>\s*(\d+)\s*</EventID>")

    skipped_here = 0
    with ExitStack() as stack:
        try:
            log_file = stack.enter_context(evtx.Evtx(str(path)))
            # Touch the file header now so a non-EVTX file fails fast with a clear message.
            if not log_file.get_file_header().check_magic():
                raise ValueError("bad file signature (expected ElfFile)")
        except Exception as exc:  # python-evtx raises a variety of errors on non-EVTX input
            raise ValueError(f"{path} is not a readable EVTX file: {exc}") from exc

        # Iterate chunk by chunk so a single corrupt 64KB chunk costs us only its own
        # records instead of terminating the whole scan.
        for chunk in log_file.chunks():
            try:
                records = list(chunk.records())
            except Exception as exc:
                skipped_here += 1
                log.debug("skipping corrupt chunk in %s: %s", path, exc)
                continue

            for record in records:
                try:
                    xml = record.xml()
                    if wanted is not None:
                        match = id_re.search(xml)
                        if not match or int(match.group(1)) not in wanted:
                            continue
                    event = parse_event_xml(xml, source=path.name)
                except Exception as exc:  # bad template, bad XML, bad timestamp ...
                    skipped_here += 1
                    log.debug("skipping unreadable record in %s: %s", path, exc)
                    continue
                stats.parsed += 1
                yield event

    stats.skipped += skipped_here
    if skipped_here:
        log.warning("%s: skipped %d unreadable record(s)/chunk(s)", path.name, skipped_here)
