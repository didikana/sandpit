"""Programmatic API for sandpit."""

from __future__ import annotations

import ast
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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


def run(script: str | Path, policy: str | None = None) -> Result:
    """Trace a Python script and return its trace result."""

    script_path = Path(script)
    trace = trace_script(script_path)
    source = _read_source(script_path)
    return _result(trace, policy=policy, source=source)


def run_string(code: str, policy: str | None = None) -> Result:
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

        trace = trace_script(temp_path)
        return _result(trace, policy=policy, source=code)
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


def _result(trace: list[Event], policy: str | None, source: str | None) -> Result:
    return Result(
        trace=trace,
        violations=_policy_violations(trace, policy=policy, source=source),
        exit_code=_exit_code(trace),
    )


def _exit_code(trace: list[Event]) -> int:
    for event in reversed(trace):
        if event.get("kind") == "exit":
            code = event.get("code", 1)
            return code if isinstance(code, int) else 1
    return 1


def _policy_violations(
    trace: list[Event], policy: str | None, source: str | None
) -> list[Event]:
    if policy in {None, ""}:
        return []
    if policy != "no-network":
        raise ValueError(f"unsupported policy: {policy}")

    violations = _network_import_violations(trace)
    if source is not None:
        violations.extend(_network_call_violations(source))
    return violations


def _network_import_violations(trace: list[Event]) -> list[Event]:
    violations: list[Event] = []
    for event in trace:
        if event.get("kind") != "import":
            continue

        module = str(event.get("module", ""))
        root_module = module.split(".", 1)[0]
        if root_module not in NETWORK_MODULES:
            continue

        violations.append(
            {
                "kind": "policy_violation",
                "policy": "no-network",
                "op": "network",
                "reason": f"network-related import denied: {module}",
                "module": module,
                "file": event.get("file"),
                "line": event.get("line"),
            }
        )
    return violations


def _network_call_violations(source: str) -> list[Event]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    imports = _import_aliases(tree)
    violations: list[Event] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        call_name = _call_name(node.func)
        if call_name is None or not _is_network_call(call_name, imports):
            continue

        violations.append(
            {
                "kind": "policy_violation",
                "policy": "no-network",
                "op": "network",
                "reason": f"network call denied: {call_name}",
                "call": call_name,
                "line": node.lineno,
            }
        )
    return violations


def _import_aliases(tree: ast.AST) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local_name = alias.asname or alias.name.split(".", 1)[0]
                aliases[local_name] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                local_name = alias.asname or alias.name
                aliases[local_name] = f"{node.module}.{alias.name}"
    return aliases


def _call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        if parent is None:
            return node.attr
        return f"{parent}.{node.attr}"
    return None


def _is_network_call(call_name: str, imports: dict[str, str]) -> bool:
    parts = call_name.split(".")
    resolved_root = imports.get(parts[0], parts[0])
    resolved_name = ".".join([resolved_root, *parts[1:]])
    return any(
        resolved_name == pattern or resolved_name.startswith(f"{pattern}.")
        for pattern in NETWORK_CALL_PREFIXES
    )


def _read_source(script_path: Path) -> str | None:
    try:
        return script_path.read_text(encoding="utf-8")
    except OSError:
        return None


NETWORK_MODULES = {
    "aiohttp",
    "http",
    "httpx",
    "requests",
    "socket",
    "urllib",
}

NETWORK_CALL_PREFIXES = {
    "aiohttp.ClientSession",
    "http.client.HTTPConnection",
    "http.client.HTTPSConnection",
    "httpx",
    "requests",
    "socket.create_connection",
    "socket.socket",
    "urllib.request.urlopen",
}
