"""Read and write sandpit trace files."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable


Event = dict[str, Any]


def write_trace(events: Iterable[Event], path: str | Path) -> Path:
    """Write events as JSON Lines to a .sptrace file."""

    trace_path = Path(path)
    with trace_path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, separators=(",", ":"), sort_keys=True))
            handle.write("\n")
    return trace_path


def read_trace(path: str | Path) -> list[Event]:
    """Read a JSON Lines .sptrace file."""

    events: list[Event] = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events
