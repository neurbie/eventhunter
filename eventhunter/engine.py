"""Runs detectors over a stream of events and collects their findings."""

from __future__ import annotations

import logging
from collections.abc import Iterable

from eventhunter.detectors import ALL_DETECTORS, Detector, DetectorConfig
from eventhunter.models import Detection, Event, Severity

log = logging.getLogger(__name__)


def build_detectors(config: DetectorConfig | None = None) -> list[Detector]:
    """Instantiate every registered detector with a shared configuration."""
    return [cls(config) for cls in ALL_DETECTORS]


def relevant_event_ids(detectors: Iterable[Detector]) -> set[int]:
    """Union of Event IDs needed by ``detectors`` - used to pre-filter parsing."""
    ids: set[int] = set()
    for detector in detectors:
        ids |= detector.event_ids
    return ids


def sort_detections(detections: Iterable[Detection]) -> list[Detection]:
    """Most severe first; ties broken chronologically."""
    return sorted(detections, key=lambda d: (-d.severity, d.timestamp))


def run_detectors(
    events: Iterable[Event],
    config: DetectorConfig | None = None,
    detectors: list[Detector] | None = None,
    min_severity: Severity = Severity.INFO,
) -> list[Detection]:
    """Run ``detectors`` (default: all) over ``events``.

    Events are sorted by timestamp once, then each detector receives only the
    events it declared interest in. A detector that crashes is logged and
    skipped so one buggy rule cannot hide the output of the others.

    Returns:
        Detections at or above ``min_severity``, most severe first.
    """
    detectors = detectors if detectors is not None else build_detectors(config)
    ordered = sorted(events, key=lambda e: (e.timestamp, e.record_id or 0))

    findings: list[Detection] = []
    for detector in detectors:
        subset = [e for e in ordered if detector.accepts(e)]
        if not subset:
            continue
        try:
            results = detector.detect(subset)
        except Exception:
            log.exception("detector %r failed; its results are omitted", detector.rule)
            continue
        log.debug("%s: %d event(s) in, %d detection(s) out", detector.rule, len(subset), len(results))
        findings.extend(results)

    return sort_detections(d for d in findings if d.severity >= min_severity)
