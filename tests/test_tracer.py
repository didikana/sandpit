from __future__ import annotations

from pathlib import Path

from sandpit.cli import main
from sandpit.trace import read_trace, write_trace
from sandpit.tracer import trace_script


FIXTURES = Path(__file__).parent / "fixtures"
SCRIPT = FIXTURES / "open_and_import.py"


def test_tracer_captures_function_calls_file_opens_and_imports() -> None:
    events = trace_script(SCRIPT)

    assert any(event["kind"] == "call" and event["fn"] == "main" for event in events)
    assert any(
        event["kind"] == "open"
        and event["path"].endswith("sample.txt")
        and event["mode"] == "r"
        for event in events
    )
    assert any(
        event["kind"] == "import" and event["module"] == "helper_module"
        for event in events
    )
    assert events[-1]["kind"] == "exit"
    assert events[-1]["code"] == 0


def test_trace_write_and_read_round_trip(tmp_path: Path) -> None:
    events = trace_script(SCRIPT)
    trace_path = tmp_path / "run.sptrace"

    written = write_trace(events, trace_path)

    assert written == trace_path
    assert read_trace(trace_path) == events


def test_cli_run_writes_sptrace_file() -> None:
    trace_path = SCRIPT.with_suffix(".sptrace")
    trace_path.unlink(missing_ok=True)

    try:
        exit_code = main(["run", str(SCRIPT)])

        assert exit_code == 0
        events = read_trace(trace_path)
        assert any(event["kind"] == "open" for event in events)
        assert any(event["kind"] == "import" for event in events)
    finally:
        trace_path.unlink(missing_ok=True)
