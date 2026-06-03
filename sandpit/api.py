"""Programmatic API for sandpit."""

from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sandpit.policy import Policy, load_policy
from sandpit.sandbox import trace_script_with_policy
from sandpit.trace import write_trace
from sandpit.tracer import trace_script


Event = dict[str, Any]


@dataclass(frozen=True)
class Result:
    """Result from a sandpit run."""

    trace: list[Event]
    violations: list[Event]
    exit_code: int

    def save(self, path: str | Path) -> Path:
        """Write the execution trace as JSON Lines."""

        return write_trace(self.trace, path)


def run(script: str | Path, policy: str | Path | Policy | None = None) -> Result:
    """Trace a Python script and return its trace result."""

    script_path = Path(script)
    loaded_policy = load_policy(policy)
    if loaded_policy is None:
        trace = trace_script(script_path)
        violations: list[Event] = []
    else:
        trace, violations = trace_script_with_policy(script_path, loaded_policy)
    return _result(trace, violations=violations)


def run_string(code: str, policy: str | Path | Policy | None = None) -> Result:
    """Trace Python code from a temporary script and remove it afterward."""

    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            suffix=".py",
            prefix="sandpit-",
            delete=False,
        ) as handle:
            handle.write(code)
            temp_path = Path(handle.name)

        return run(temp_path, policy=policy)
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


def _result(trace: list[Event], violations: list[Event]) -> Result:
    return Result(
        trace=trace,
        violations=violations,
        exit_code=_exit_code(trace),
    )


def _exit_code(trace: list[Event]) -> int:
    for event in reversed(trace):
        if event.get("kind") == "exit":
            code = event.get("code", 1)
            return code if isinstance(code, int) else 1
    return 1

