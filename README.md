# Run untrusted Python safely — with a full audit trace.

sandpit runs Python code under a trace layer so you can inspect what it did:
functions called, files opened, modules imported, and policy-relevant behavior.
It is built for reviewing LLM-generated Python before you trust it in a larger
workflow.

```python
import sandpit

llm_code = """
import requests

requests.get("http://example.com")
"""

result = sandpit.run_string(llm_code, policy="no-network")

print(result.exit_code)
print(result.violations)
result.save("llm-run.sptrace")
```

The `no-network` policy is observation-only for now: sandpit reports the
network-related import and call as policy violations while preserving the full
execution trace for audit.

## Python API

```python
import sandpit

result = sandpit.run("script.py", policy="no-network")
result = sandpit.run_string("print('hello')", policy="no-network")

result.trace        # list of trace events
result.violations   # list of policy violation events
result.exit_code    # process-style exit code
result.save("run.sptrace")
```

## CLI

```bash
sandpit run script.py
```

This writes `script.sptrace` as JSON Lines: one event per line.

## Status

Phase 1 is the trace layer and programmatic API. Policy enforcement,
replay/diff, and syscall-level isolation are planned but not implemented yet.
