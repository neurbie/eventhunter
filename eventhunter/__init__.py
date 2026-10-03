"""EventHunter - Windows Event Log IOC analyzer.

EventHunter parses Windows ``.evtx`` files, runs a set of behaviour-based
detectors over the events, maps every finding to a MITRE ATT&CK technique,
and renders the results as a Markdown (or JSON) report.

Typical programmatic use::

    from eventhunter.parser import parse_evtx
    from eventhunter.engine import run_detectors
    from eventhunter.report import render_markdown

    events = list(parse_evtx("Security.evtx"))
    detections = run_detectors(events)
    print(render_markdown(detections, events, sources=["Security.evtx"]))
"""

__version__ = "1.0.0"
__all__ = ["__version__"]
