"""Policy enforcement hooks for sandpit.

The sandbox installs Python-layer hooks for imports, file opens, sockets, and
process creation. On macOS this is the full enforcement layer: seccomp is a
Linux-only facility, so syscall filtering is skipped there by design.

Linux seccomp support is optional and intentionally isolated behind
``enable_seccomp=True``. If a compatible ``seccomp`` or ``pyseccomp`` binding is
installed, sandpit can add coarse syscall blocks for network and process
creation. File path policy is still enforced by Python hooks because seccomp
filters syscall numbers, not path strings.
"""

from __future__ import annotations

import builtins
import io
import os
import platform
import socket
import subprocess
import time
from pathlib import Path
from types import TracebackType
from typing import Any, Callable

from sandpit.policy import Policy, load_policy
from sandpit.tracer import trace_script


Event = dict[str, Any]


class PolicyViolation(RuntimeError):
    """Raised when a policy rule blocks an operation."""

    def __init__(self, event: Event) -> None:
        self.event = event
        super().__init__(event["reason"])


class Sandbox:
    """Install Python-level policy enforcement hooks."""

    def __init__(self, policy: str | Path | Policy, *, enable_seccomp: bool = False) -> None:
        loaded = load_policy(policy)
        if loaded is None:
            raise ValueError("sandbox requires a policy")
        self.policy = loaded
        self.enable_seccomp = enable_seccomp
        self.violations: list[Event] = []
        self.seccomp_status = "disabled"
        self._original_open: Callable[..., Any] | None = None
        self._original_io_open: Callable[..., Any] | None = None
        self._original_import: Callable[..., Any] | None = None
        self._original_socket: Callable[..., Any] | None = None
        self._original_create_connection: Callable[..., Any] | None = None
        self._original_popen: Callable[..., Any] | None = None
        self._original_fork: Callable[..., Any] | None = None
        self._original_exec: dict[str, Callable[..., Any]] = {}

    def __enter__(self) -> "Sandbox":
        self._original_open = builtins.open
        self._original_io_open = io.open
        self._original_import = builtins.__import__
        self._original_socket = socket.socket
        self._original_create_connection = socket.create_connection
        self._original_popen = subprocess.Popen
        self._original_fork = getattr(os, "fork", None)

        builtins.open = self._open  # type: ignore[assignment]
        io.open = self._open  # type: ignore[assignment]
        builtins.__import__ = self._import  # type: ignore[assignment]
        socket.socket = self._socket  # type: ignore[assignment]
        socket.create_connection = self._create_connection  # type: ignore[assignment]
        subprocess.Popen = self._popen  # type: ignore[assignment]

        if self._original_fork is not None:
            os.fork = self._fork  # type: ignore[assignment]
        for name in _EXEC_NAMES:
            original = getattr(os, name, None)
            if original is not None:
                self._original_exec[name] = original
                setattr(os, name, self._exec_wrapper(name))

        if self.enable_seccomp:
            self.seccomp_status = install_seccomp(self.policy)

        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self._original_open is not None:
            builtins.open = self._original_open  # type: ignore[assignment]
        if self._original_io_open is not None:
            io.open = self._original_io_open  # type: ignore[assignment]
        if self._original_import is not None:
            builtins.__import__ = self._original_import  # type: ignore[assignment]
        if self._original_socket is not None:
            socket.socket = self._original_socket  # type: ignore[assignment]
        if self._original_create_connection is not None:
            socket.create_connection = self._original_create_connection  # type: ignore[assignment]
        if self._original_popen is not None:
            subprocess.Popen = self._original_popen  # type: ignore[assignment]
        if self._original_fork is not None:
            os.fork = self._original_fork  # type: ignore[assignment]
        for name, original in self._original_exec.items():
            setattr(os, name, original)

    def _open(self, file: Any, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        path = Path(os.fsdecode(file)) if isinstance(file, (str, bytes, os.PathLike)) else file
        for violation in _open_violations(self.policy, path, mode):
            self._block(violation)

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
        violation = self.policy.violation_for_import(name)
        if violation is not None:
            self._block(violation)

        assert self._original_import is not None
        return self._original_import(name, globals, locals, fromlist or (), level)

    def _socket(self, *args: Any, **kwargs: Any) -> Any:
        violation = self.policy.violation_for_network("socket.socket")
        if violation is not None:
            self._block(violation)

        assert self._original_socket is not None
        return self._original_socket(*args, **kwargs)

    def _create_connection(self, *args: Any, **kwargs: Any) -> Any:
        violation = self.policy.violation_for_network("socket.create_connection")
        if violation is not None:
            self._block(violation)

        assert self._original_create_connection is not None
        return self._original_create_connection(*args, **kwargs)

    def _popen(self, *args: Any, **kwargs: Any) -> Any:
        violation = self.policy.violation_for_fork("subprocess.Popen")
        if violation is None:
            violation = self.policy.violation_for_exec("subprocess.Popen")
        if violation is not None:
            self._block(violation)

        assert self._original_popen is not None
        return self._original_popen(*args, **kwargs)

    def _fork(self, *args: Any, **kwargs: Any) -> Any:
        violation = self.policy.violation_for_fork("os.fork")
        if violation is not None:
            self._block(violation)

        assert self._original_fork is not None
        return self._original_fork(*args, **kwargs)

    def _exec_wrapper(self, name: str) -> Callable[..., Any]:
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            violation = self.policy.violation_for_exec(f"os.{name}")
            if violation is not None:
                self._block(violation)
            return self._original_exec[name](*args, **kwargs)

        return wrapped

    def _block(self, violation: Event) -> None:
        event = {
            "t": time.time(),
            "policy": self.policy.name,
            **violation,
        }
        self.violations.append(event)
        raise PolicyViolation(event)


def trace_script_with_policy(
    script_path: str | Path,
    policy: str | Path | Policy,
    *,
    argv: list[str] | None = None,
    enable_seccomp: bool = False,
) -> tuple[list[Event], list[Event]]:
    """Trace a script while enforcing a policy at the Python hook layer."""

    with Sandbox(policy, enable_seccomp=enable_seccomp) as sandbox:
        trace = trace_script(script_path, argv=argv)
        return trace, sandbox.violations


def install_seccomp(policy: Policy) -> str:
    """Install optional Linux seccomp rules if a binding is available.

    Returns a short status string. This is skipped on macOS and other non-Linux
    platforms because seccomp is Linux-specific.
    """

    if platform.system() != "Linux":
        return "skipped: seccomp is Linux-only"

    seccomp = _load_seccomp()
    if seccomp is None:
        return "skipped: seccomp/pyseccomp not installed"

    try:
        return _install_seccomp_rules(seccomp, policy)
    except Exception as exc:  # noqa: BLE001 - optional hardening must not break hooks.
        return f"skipped: seccomp setup failed: {exc}"


def _install_seccomp_rules(seccomp: Any, policy: Policy) -> str:
    default_allow = getattr(seccomp, "ALLOW", None)
    deny = getattr(seccomp, "ERRNO", None)
    if default_allow is None or deny is None:
        return "skipped: unsupported seccomp binding"

    filt = seccomp.SyscallFilter(defaction=default_allow)
    deny_action = deny(1)

    blocked: list[str] = []
    if not policy.network.allow:
        blocked.extend(["socket", "connect", "accept", "accept4", "bind", "listen", "sendto", "recvfrom"])
    if not policy.process.allow_fork:
        blocked.extend(["fork", "vfork", "clone", "clone3"])
    if not policy.process.allow_exec:
        blocked.extend(["execve", "execveat"])

    for syscall in blocked:
        try:
            filt.add_rule(deny_action, syscall)
        except Exception:
            continue

    filt.load()
    return "enabled"


def _load_seccomp() -> Any | None:
    try:
        import seccomp

        return seccomp
    except ModuleNotFoundError:
        pass

    try:
        import pyseccomp

        return pyseccomp
    except ModuleNotFoundError:
        return None


def _open_violations(policy: Policy, path: Any, mode: str) -> list[Event]:
    if not isinstance(path, Path):
        return []

    violations: list[Event] = []
    if _reads(mode):
        violation = policy.violation_for_read(path)
        if violation is not None:
            violations.append(violation)
    if _writes(mode):
        violation = policy.violation_for_write(path)
        if violation is not None:
            violations.append(violation)
    return violations


def _reads(mode: str) -> bool:
    return "r" in mode or "+" in mode


def _writes(mode: str) -> bool:
    return any(flag in mode for flag in ("w", "a", "x", "+"))


_EXEC_NAMES = (
    "execl",
    "execle",
    "execlp",
    "execlpe",
    "execv",
    "execve",
    "execvp",
    "execvpe",
)
