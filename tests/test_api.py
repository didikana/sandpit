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
    code = "import socket\nsocket.socket()\n"

    result = sandpit.run_string(code, policy="no-network")

    assert result.violations
    assert result.violations[0]["kind"] == "policy_violation"
    assert result.violations[0]["policy"] == "no-network"
    assert result.violations[0]["rule"] == "network.allow"
    assert result.violations[0]["op"] == "network"
    assert result.exit_code == 1


def test_default_policy_blocks_denied_import() -> None:
    result = sandpit.run_string("import subprocess\n", policy="default")

    assert result.exit_code == 1
    assert result.violations
    assert result.violations[0]["rule"] == "imports.deny"
    assert result.violations[0]["module"] == "subprocess"


def test_policy_blocks_denied_file_read(tmp_path: Path) -> None:
    secret = tmp_path / "secret.txt"
    secret.write_text("secret", encoding="utf-8")
    policy_path = tmp_path / "policy.toml"
    policy_path.write_text(
        f"""
[fs]
allow_read  = ["/tmp", "{{cwd}}"]
allow_write = ["/tmp"]
deny_read   = ["{secret}"]

[network]
allow = true

[process]
allow_fork  = true
allow_exec  = true
max_cpu_ms  = 5000
max_mem_mb  = 256

[imports]
deny = []
""".strip(),
        encoding="utf-8",
    )

    result = sandpit.run_string(f"open({str(secret)!r}).read()\n", policy=policy_path)

    assert result.exit_code == 1
    assert result.violations
    assert result.violations[0]["rule"] == "fs.deny_read"
    assert result.violations[0]["path"] == str(secret)


def test_read_only_policy_blocks_file_write() -> None:
    result = sandpit.run_string("open('/tmp/sandpit-write-test.txt', 'w').write('x')\n", policy="read-only")

    assert result.exit_code == 1
    assert result.violations
    assert result.violations[0]["rule"] == "fs.allow_write"
