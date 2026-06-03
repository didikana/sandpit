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

The `no-network` policy blocks the network-related import or socket operation,
reports the violated rule in `result.violations`, and preserves the full
execution trace for audit.
## How it works

sandpit enforces at two layers:

**Python layer** (`sys.settrace` + `sys.setprofile` + import hooks)
Intercepts every function call, file open, and import at the Python level.
Zero instrumentation required on the traced script. This is the trace layer —
it observes and enforces import denials and socket calls before they reach the OS.

**Syscall layer** (Linux only: `seccomp`)
Hard OS-level caps on file access and process creation. Even if a script
bypasses Python-level hooks via a C extension, seccomp catches it at the
kernel boundary.

macOS uses Python-layer enforcement only — seccomp is Linux-specific.
The trace layer works identically on both platforms.
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

## Limitations

- C extensions that bypass the Python interpreter are not traced at the 
  Python layer (seccomp handles these on Linux)
- Windows is not supported for syscall enforcement
- The trace layer adds ~2-5ms overhead per run
- sandpit is not a full VM — for untrusted code from genuinely hostile 
  sources, combine with OS-level isolation

## Status

Phase 2 adds TOML policies and Python-layer enforcement for imports, files,
network calls, and process creation. On macOS, seccomp is unavailable, so
sandpit enforces at the Python hook layer only. On Linux, optional seccomp
hardening can be enabled when a compatible `seccomp` or `pyseccomp` binding is
installed. Replay/diff are planned but not implemented yet.
