"""Python-level tracing for script execution."""

from __future__ import annotations

import builtins
import io
import runpy
import sys
import time
from pathlib import Path
from types import FrameType
from typing import Any, Callable


Event = dict[str, Any]


class Tracer:
    """Collect trace events for a single script run."""

    def __init__(self, script_path: str | Path) -> None:
        self.script_path = Path(script_path).resolve()
        self.script_dir = self.script_path.parent
        self.events: list[Event] = []
        self._original_open: Callable[..., Any] | None = None
        self._original_io_open: Callable[..., Any] | None = None
        self._original_import: Callable[..., Any] | None = None
        self._previous_trace: Callable[..., Any] | None = None
        self._previous_profile: Callable[..., Any] | None = None
        self._trace_file_cache: dict[str, bool] = {}
        self._suspended = False

    def run(self, argv: list[str] | None = None) -> list[Event]:
        """Execute the configured script and return collected events."""

        old_argv = sys.argv[:]
        old_path = sys.path[:]
        started = time.perf_counter()
        exit_code = 0

        self.start()
        try:
            sys.argv = [str(self.script_path), *(argv or [])]
            sys.path.insert(0, str(self.script_dir))
            runpy.run_path(str(self.script_path), run_name="__main__")
        except SystemExit as exc:
            exit_code = _system_exit_code(exc)
        except BaseException as exc:  # noqa: BLE001 - trace runners must report failures.
            exit_code = 1
            self._record(
                {
                    "kind": "unhandled_exception",
                    "type": type(exc).__name__,
                    "message": str(exc),
                }
            )
        finally:
            self.stop()
            sys.argv = old_argv
            sys.path = old_path
            self._record(
                {
                    "kind": "exit",
                    "code": exit_code,
                    "duration_ms": int((time.perf_counter() - started) * 1000),
                }
            )

        return self.events

    def start(self) -> None:
        """Install trace/profile hooks and wrappers."""

        self._original_open = builtins.open
        self._original_io_open = io.open
        self._original_import = builtins.__import__
        self._previous_trace = sys.gettrace()
        self._previous_profile = sys.getprofile()

        builtins.open = self._open  # type: ignore[assignment]
        io.open = self._open  # type: ignore[assignment]
        builtins.__import__ = self._import  # type: ignore[assignment]
        sys.settrace(self._trace)
        sys.setprofile(self._profile)

    def stop(self) -> None:
        """Remove trace/profile hooks and restore builtins."""

        sys.settrace(self._previous_trace)
        sys.setprofile(self._previous_profile)
        if self._original_open is not None:
            builtins.open = self._original_open  # type: ignore[assignment]
        if self._original_io_open is not None:
            io.open = self._original_io_open  # type: ignore[assignment]
        if self._original_import is not None:
            builtins.__import__ = self._original_import  # type: ignore[assignment]

    def _trace(self, frame: FrameType, event: str, arg: Any) -> Callable[..., Any] | None:
        if self._suspended or event not in {"call", "return", "exception"}:
            return self._trace

        if not self._should_trace_file(frame.f_code.co_filename):
            return self._trace

        payload: Event = {
            "kind": event,
            "fn": frame.f_code.co_name,
            "file": _display_path(frame.f_code.co_filename),
            "line": frame.f_lineno,
        }
        if event == "return":
            payload["ret"] = _safe_repr(arg)
        elif event == "exception":
            exc_type, exc, _traceback = arg
            payload["type"] = getattr(exc_type, "__name__", str(exc_type))
            payload["message"] = str(exc)

        self._record(payload)
        return self._trace

    def _profile(self, frame: FrameType, event: str, arg: Any) -> None:
        if self._suspended or event not in {"c_call", "c_return", "c_exception"}:
            return

        if not self._should_trace_file(frame.f_code.co_filename):
            return

        fn = getattr(arg, "__name__", repr(arg))
        if fn not in {"open", "__import__"}:
            return

        self._record(
            {
                "kind": event,
                "fn": fn,
                "file": _display_path(frame.f_code.co_filename),
                "line": frame.f_lineno,
            }
        )

    def _open(self, file: Any, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        frame = self._traced_caller(sys._getframe(1))
        if frame is not None:
            self._record(
                {
                    "kind": "open",
                    "path": str(file),
                    "mode": mode,
                    "file": _display_path(frame.f_code.co_filename),
                    "line": frame.f_lineno,
                }
            )

        assert self._original_open is not None
        return self._original_open(file, mode, *args, **kwargs)

    def _import(
        self,
        name: str,
        globals: dict[str, Any] | None = None,
        locals: dict[str, Any] | None = None,
        fromlist: tuple[str, ...] | None = None,
        level: int = 0,
    ) -> Any:
        frame = self._traced_caller(sys._getframe(1))
        if frame is not None:
            self._record(
                {
                    "kind": "import",
                    "module": name,
                    "fromlist": list(fromlist or ()),
                    "level": level,
                    "file": _display_path(frame.f_code.co_filename),
                    "line": frame.f_lineno,
                }
            )

        assert self._original_import is not None
        return self._original_import(name, globals, locals, fromlist or (), level)

    def _traced_caller(self, frame: FrameType) -> FrameType | None:
        while frame is not None:
            if self._should_trace_file(frame.f_code.co_filename):
                return frame
            frame = frame.f_back
        return None

    def _record(self, payload: Event) -> None:
        if self._suspended:
            return

        self._suspended = True
        try:
            self.events.append({"t": time.time(), **payload})
        finally:
            self._suspended = False

    def _should_trace_file(self, filename: str) -> bool:
        if filename.startswith("<"):
            return False

        cached = self._trace_file_cache.get(filename)
        if cached is not None:
            return cached

        try:
            path = Path(filename).resolve()
            path.relative_to(self.script_dir)
        except (OSError, ValueError):
            self._trace_file_cache[filename] = False
            return False

        self._trace_file_cache[filename] = True
        return True


def trace_script(script_path: str | Path, argv: list[str] | None = None) -> list[Event]:
    """Trace a Python script and return JSON-serializable event dictionaries."""

    return Tracer(script_path).run(argv=argv)


def _system_exit_code(exc: SystemExit) -> int:
    if exc.code is None:
        return 0
    if isinstance(exc.code, int):
        return exc.code
    return 1


def _display_path(filename: str) -> str:
    try:
        return str(Path(filename).resolve())
    except OSError:
        return filename


def _safe_repr(value: Any, limit: int = 120) -> str:
    text = repr(value)
    if len(text) <= limit:
        return text
    return f"{text[: limit - 3]}..."
