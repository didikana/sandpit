from __future__ import annotations

from pathlib import Path

import sandpit
from sandpit.trace import read_trace


FIXTURES = Path(__file__).parent / "fixtures"
SCRIPT = FIXTURES / "open_and_import.py"


def test_run_returns_trace_result_and_can_save(tmp_path: Path) -> None:
    result = sandpit.run(SCRIPT)
    trace_path = tmp_path / "run.sptrace"

    written = result.save(trace_path)

    assert written == trace_path
    assert read_trace(trace_path) == result.trace
    assert result.exit_code == 0
    assert result.violations == []


def test_run_string_traces_code_from_tempfile() -> None:
    result = sandpit.run_string("value = 1\n")

    assert result.exit_code == 0
    assert any(event["kind"] == "call" for event in result.trace)
    assert result.violations == []


def test_no_network_policy_reports_network_call_from_source() -> None:
    code = "import socket\nif False:\n    socket.create_connection(('example.com', 80))\n"

    result = sandpit.run_string(code, policy="no-network")

    assert result.violations
    assert result.violations[0]["kind"] == "policy_violation"
    assert result.violations[0]["policy"] == "no-network"
    assert result.violations[0]["op"] == "network"
