"""Shared test helpers.

Detectors work on :class:`Event` objects, so tests build events directly
instead of needing binary .evtx fixtures.
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

import pytest

from eventhunter.models import Event

T0 = datetime(2026, 9, 14, 2, 0, 0, tzinfo=timezone.utc)

_record_counter = iter(range(1000, 10**9))


def make_event(event_id: int, seconds: float = 0, computer: str = "WS01.corp.local", **data: str) -> Event:
    """Build an Event ``seconds`` after T0 with the given EventData fields."""
    provider = "Microsoft-Windows-Eventlog" if event_id == 1102 else "Microsoft-Windows-Security-Auditing"
    return Event(
        event_id=event_id,
        timestamp=T0 + timedelta(seconds=seconds),
        record_id=next(_record_counter),
        provider=provider,
        channel="Security",
        computer=computer,
        data=data,
        source="test.evtx",
    )


def encode_ps(script: str) -> str:
    """Encode a script the way ``powershell -EncodedCommand`` expects (UTF-16LE Base64)."""
    return base64.b64encode(script.encode("utf-16-le")).decode()


@pytest.fixture
def event():
    return make_event
