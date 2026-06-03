# AGENTS.md — sandpit

A deterministic Python sandbox with execution traces. Run any Python script in an isolated environment and get a full, structured trace of what it did — files touched, syscalls made, functions called. Replay it. Diff two runs. Assert policies.

---

## Project Philosophy

Python has no good sandboxing story. `RestrictedPython` is broken. `PyPy sandbox` is dead. Everyone either runs untrusted code naked or reaches for Docker for a one-liner.

sandpit is the missing middle layer.

Inspired by ChronicleVM's capability-sandboxed, deterministic execution model — every script run produces a structured trace you can inspect, replay, and assert against. The goal is to make Python execution as auditable as bytecode.

Two layers of enforcement:
- **Trace layer** (`sys.settrace` + `sys.setprofile`): records every function call, file open, and import at Python level, zero instrumentation required.
- **Syscall layer** (`seccomp` / `ptrace` on Linux): enforces hard OS-level caps. The trace layer observes; the syscall layer enforces.

---

## Repo Structure

```
sandpit/
├── sandpit/
│   ├── __init__.py
│   ├── tracer.py          # sys.settrace / setprofile hooks, emits events
│   ├── sandbox.py         # subprocess isolation + seccomp policy loader
│   ├── policy.py          # policy DSL parser and validator
│   ├── trace.py           # .sptrace format: schema, read, write, diff
│   ├── replay.py          # re-run with mocked syscalls from a trace
│   └── cli.py             # entry point: run / inspect / diff / replay / assert
├── policies/
│   ├── default.toml       # sensible baseline (no network, read-only fs)
│   ├── no-network.toml
│   └── read-only.toml
├── tests/
│   ├── test_tracer.py
│   ├── test_replay.py
│   └── fixtures/          # small Python scripts used as test subjects
├── examples/
│   ├── audit_llm_output.py   # run LLM-generated code, inspect what it touches
│   ├── ci_regression.py      # record a run, assert future runs match
│   └── student_grader.py     # sandbox + grade untrusted student submissions
├── docs/
│   └── trace-format.md    # .sptrace spec
├── AGENTS.md
├── README.md
└── pyproject.toml
```

---

## Core Abstractions

### `.sptrace` format

JSON Lines. One event per line. Schema:

```json
{"t": 1718000000.123, "kind": "call",    "fn": "open",        "args": ["/etc/passwd", "r"], "file": "script.py", "line": 12}
{"t": 1718000000.124, "kind": "return",  "fn": "open",        "ret": "<_io.TextIOWrapper>"}
{"t": 1718000000.125, "kind": "syscall", "name": "openat",    "path": "/etc/passwd", "flags": "O_RDONLY"}
{"t": 1718000000.200, "kind": "import",  "module": "requests"}
{"t": 1718000000.201, "kind": "network", "op": "connect",     "host": "api.example.com", "port": 443}
{"t": 1718000000.500, "kind": "exit",    "code": 0,           "duration_ms": 377}
```

### Policy DSL

TOML. Declarative, composable:

```toml
# policies/default.toml
[fs]
allow_read  = ["/usr", "/lib", "/tmp", "{cwd}"]
allow_write = ["/tmp", "{cwd}/output"]
deny_read   = ["/etc/passwd", "/etc/shadow", "{home}/.ssh"]

[network]
allow = false

[process]
allow_fork  = false
allow_exec  = false
max_cpu_ms  = 5000
max_mem_mb  = 256

[imports]
deny = ["subprocess", "ctypes", "socket"]
```

### CLI

```bash
# Run with default policy, emit trace
sandpit run script.py

# Run with custom policy
sandpit run --policy policies/no-network.toml script.py

# Inspect a trace
sandpit inspect run.sptrace
sandpit inspect run.sptrace --filter network

# Diff two traces
sandpit diff baseline.sptrace new.sptrace

# Replay (re-run with mocked syscalls from trace, no real I/O)
sandpit replay run.sptrace

# Assert a policy against an existing trace (CI use)
sandpit assert --policy policies/default.toml run.sptrace
```

---

## Implementation Phases

### Phase 1 — Trace layer (ship this)
- [ ] `tracer.py`: `sys.settrace` hook that captures calls, returns, exceptions
- [ ] `tracer.py`: `sys.setprofile` for C-level calls (builtins, file ops)
- [ ] `trace.py`: `.sptrace` writer and reader
- [ ] `cli.py`: `sandpit run` and `sandpit inspect`
- [ ] README with a working demo GIF
- [ ] Publish to PyPI

### Phase 2 — Policy enforcement
- [ ] `policy.py`: TOML policy parser
- [ ] `sandbox.py`: import hook to block denied modules pre-load
- [ ] `sandbox.py`: subprocess isolation with `seccomp` (Linux) / `sandbox-exec` (macOS)
- [ ] `cli.py`: `sandpit assert`
- [ ] Policy library: `default`, `no-network`, `read-only`

### Phase 3 — Replay + diff
- [ ] `replay.py`: replay engine with mocked I/O from trace
- [ ] `trace.py`: structured diff (not line-based — event-semantic diff)
- [ ] `cli.py`: `sandpit diff` and `sandpit replay`

### Phase 4 — Ecosystem
- [ ] `pytest-sandpit`: run each test in a sandboxed subprocess, assert no side effects
- [ ] GitHub Action: `sandpit-action` for CI enforcement
- [ ] Web viewer (mirrors ChronicleVM trace viewer): visualize `.sptrace` in browser

---

## Design Constraints

- **No model modification** — hooks only, works on any Python script with zero changes
- **Zero required deps for traced scripts** — sandpit is the runner, not a library the script imports
- **Trace first, enforce second** — Phase 1 ships with observe-only mode so it's useful before enforcement is complete
- **Portable traces** — `.sptrace` files are self-contained and sharable
- **Composable policies** — policies extend each other, projects ship their own

---

## Non-Goals (for now)

- Windows syscall enforcement (trace layer works; seccomp doesn't exist on Windows — document this clearly)
- Full VM isolation (that's Docker's job; sandpit is the auditable middle layer)
- Tracing compiled C extensions at the native level

---

## Naming & Framing

The project is named **sandpit** (lowercase). Not sandbox — that's taken everywhere. A sandpit is where you play safely: contained, observable, cleanable.

Tagline: *"Run Python. See everything. Enforce anything."*

PyPI: `sandpit` (check availability before publishing)
GitHub topics: `python`, `sandbox`, `security`, `tracing`, `deterministic`, `auditing`, `llm-safety`

---

## Relationship to ChronicleVM

ChronicleVM built capability sandboxing and deterministic replay from scratch in Rust for a custom VM. sandpit applies the same philosophy to an existing, widely-used runtime. The research thread:

> "I wanted to understand what deterministic, capability-bounded execution looks like when you control the entire stack (ChronicleVM), then explored how far you can push the same guarantees when you're working with an existing runtime you don't control (sandpit)."

That framing is useful for PhD applications, research conversations, and conference lightning talks.

## CLI UX

The terminal output style for `sandpit run` should look like this:
[sandpit] tracing fetch_data.py
policy   : no-network.toml
output   : fetch_data.sptrace
CALL     open("/tmp/cache.json", "r")          line 8
CALL     json.loads(...)                       line 9
IMPORT   requests                              line 12
BLOCKED  socket.connect("api.example.com:443") line 14
reason: network denied by policy
EXIT     code=1  duration=23ms
trace written → fetch_data.sptrace  (18 events)
1 policy violation.
✕  network.allow = false  →  socket.connect blocked

`sandpit inspect <file> --filter <kind>` groups events by kind and prints them with their policy verdict.

`sandpit diff <a> <b>` prints added/removed/changed events semantically, not line-by-line.
