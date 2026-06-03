"""TOML policy loading and validation."""

from __future__ import annotations

import ast
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python 3.9/3.10.
    tomllib = None  # type: ignore[assignment]


@dataclass(frozen=True)
class FsPolicy:
    allow_read: tuple[Path, ...] = ()
    allow_write: tuple[Path, ...] = ()
    deny_read: tuple[Path, ...] = ()


@dataclass(frozen=True)
class NetworkPolicy:
    allow: bool = True


@dataclass(frozen=True)
class ProcessPolicy:
    allow_fork: bool = True
    allow_exec: bool = True
    max_cpu_ms: int | None = None
    max_mem_mb: int | None = None


@dataclass(frozen=True)
class ImportsPolicy:
    deny: tuple[str, ...] = ()


@dataclass(frozen=True)
class Policy:
    fs: FsPolicy = field(default_factory=FsPolicy)
    network: NetworkPolicy = field(default_factory=NetworkPolicy)
    process: ProcessPolicy = field(default_factory=ProcessPolicy)
    imports: ImportsPolicy = field(default_factory=ImportsPolicy)
    name: str | None = None
    path: Path | None = None

    def violation_for_read(self, path: str | Path) -> dict[str, Any] | None:
        candidate = _normalize_path(path)
        denied_by = _matching_rule(candidate, self.fs.deny_read)
        if denied_by is not None:
            return _violation("fs.deny_read", "read", path=str(candidate), rule_value=str(denied_by))

        if self.fs.allow_read and _matching_rule(candidate, self.fs.allow_read) is None:
            return _violation("fs.allow_read", "read", path=str(candidate))

        return None

    def violation_for_write(self, path: str | Path) -> dict[str, Any] | None:
        candidate = _normalize_path(path)
        if _matching_rule(candidate, self.fs.allow_write) is None:
            return _violation("fs.allow_write", "write", path=str(candidate))

        return None

    def violation_for_import(self, module: str) -> dict[str, Any] | None:
        for denied in self.imports.deny:
            if module == denied or module.startswith(f"{denied}."):
                return _violation(
                    "imports.deny",
                    "import",
                    module=module,
                    rule_value=denied,
                )
        return None

    def violation_for_network(self, call: str) -> dict[str, Any] | None:
        if self.network.allow:
            return None
        return _violation("network.allow", "network", call=call, rule_value=False)

    def violation_for_fork(self, call: str) -> dict[str, Any] | None:
        if self.process.allow_fork:
            return None
        return _violation("process.allow_fork", "process", call=call, rule_value=False)

    def violation_for_exec(self, call: str) -> dict[str, Any] | None:
        if self.process.allow_exec:
            return None
        return _violation("process.allow_exec", "process", call=call, rule_value=False)


def load_policy(policy: str | Path | Policy | None, cwd: str | Path | None = None) -> Policy | None:
    """Load a policy by name or path.

    A bare name like ``"no-network"`` resolves to ``policies/no-network.toml``.
    """

    if policy is None or policy == "":
        return None
    if isinstance(policy, Policy):
        return policy

    path = resolve_policy_path(policy)
    data = _load_toml(path)
    return parse_policy(data, name=Path(path).stem, path=path, cwd=cwd)


def resolve_policy_path(policy: str | Path) -> Path:
    candidate = Path(policy)
    if candidate.suffix or len(candidate.parts) > 1:
        path = candidate.expanduser()
        if path.exists():
            return path.resolve()
        raise FileNotFoundError(f"policy file not found: {policy}")

    filename = f"{candidate.name}.toml"
    for directory in _policy_dirs():
        path = directory / filename
        if path.exists():
            return path.resolve()

    raise FileNotFoundError(f"policy not found: {candidate.name}")


def parse_policy(
    data: dict[str, Any],
    *,
    name: str | None = None,
    path: str | Path | None = None,
    cwd: str | Path | None = None,
) -> Policy:
    allowed_sections = {"fs", "network", "process", "imports"}
    unknown_sections = set(data) - allowed_sections
    if unknown_sections:
        raise ValueError(f"unknown policy section(s): {sorted(unknown_sections)}")

    context = {
        "cwd": str(Path(cwd or Path.cwd()).resolve()),
        "home": str(Path.home().resolve()),
    }

    fs_data = _section(data, "fs")
    network_data = _section(data, "network")
    process_data = _section(data, "process")
    imports_data = _section(data, "imports")

    return Policy(
        fs=FsPolicy(
            allow_read=_path_list(fs_data, "allow_read", context),
            allow_write=_path_list(fs_data, "allow_write", context),
            deny_read=_path_list(fs_data, "deny_read", context),
        ),
        network=NetworkPolicy(allow=_bool(network_data, "allow", default=True)),
        process=ProcessPolicy(
            allow_fork=_bool(process_data, "allow_fork", default=True),
            allow_exec=_bool(process_data, "allow_exec", default=True),
            max_cpu_ms=_optional_int(process_data, "max_cpu_ms"),
            max_mem_mb=_optional_int(process_data, "max_mem_mb"),
        ),
        imports=ImportsPolicy(deny=_str_list(imports_data, "deny")),
        name=name,
        path=Path(path).resolve() if path is not None else None,
    )


def _load_toml(path: Path) -> dict[str, Any]:
    if tomllib is not None:
        with path.open("rb") as handle:
            return tomllib.load(handle)

    try:
        import tomli
    except ModuleNotFoundError:
        return _load_simple_toml(path)

    with path.open("rb") as handle:
        return tomli.load(handle)


def _load_simple_toml(path: Path) -> dict[str, Any]:
    data: dict[str, Any] = {}
    current: dict[str, Any] | None = None
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            current = data.setdefault(section, {})
            continue
        if current is None or "=" not in line:
            raise ValueError(f"invalid TOML line in {path}: {raw_line}")
        key, raw_value = line.split("=", 1)
        current[key.strip()] = _parse_simple_value(raw_value.strip())
    return data


def _parse_simple_value(raw_value: str) -> Any:
    if raw_value == "true":
        return True
    if raw_value == "false":
        return False
    try:
        return int(raw_value)
    except ValueError:
        pass
    return ast.literal_eval(raw_value)


def _section(data: dict[str, Any], name: str) -> dict[str, Any]:
    section = data.get(name, {})
    if not isinstance(section, dict):
        raise TypeError(f"policy section [{name}] must be a table")
    return section


def _str_list(section: dict[str, Any], key: str) -> tuple[str, ...]:
    values = section.get(key, [])
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        raise TypeError(f"policy field {key} must be a list of strings")
    return tuple(values)


def _path_list(section: dict[str, Any], key: str, context: dict[str, str]) -> tuple[Path, ...]:
    return tuple(_expand_template(value, context) for value in _str_list(section, key))


def _bool(section: dict[str, Any], key: str, *, default: bool) -> bool:
    value = section.get(key, default)
    if not isinstance(value, bool):
        raise TypeError(f"policy field {key} must be a boolean")
    return value


def _optional_int(section: dict[str, Any], key: str) -> int | None:
    value = section.get(key)
    if value is None:
        return None
    if not isinstance(value, int):
        raise TypeError(f"policy field {key} must be an integer")
    return value


def _expand_template(value: str, context: dict[str, str]) -> Path:
    expanded = value.format(**context)
    return _normalize_path(expanded)


def _normalize_path(path: str | Path) -> Path:
    return Path(path).expanduser().resolve(strict=False)


def _matching_rule(candidate: Path, rules: tuple[Path, ...]) -> Path | None:
    for rule in rules:
        if candidate == rule:
            return rule
        try:
            candidate.relative_to(rule)
        except ValueError:
            continue
        return rule
    return None


def _violation(rule: str, op: str, **fields: Any) -> dict[str, Any]:
    return {
        "kind": "policy_violation",
        "rule": rule,
        "op": op,
        "reason": _reason(rule, op, fields),
        **fields,
    }


def _reason(rule: str, op: str, fields: dict[str, Any]) -> str:
    if "path" in fields:
        return f"{op} denied by {rule}: {fields['path']}"
    if "module" in fields:
        return f"import denied by {rule}: {fields['module']}"
    if "call" in fields:
        return f"{op} denied by {rule}: {fields['call']}"
    return f"{op} denied by {rule}"


def _policy_dirs() -> tuple[Path, ...]:
    repo_root = Path(__file__).resolve().parent.parent
    return (
        Path.cwd() / "policies",
        repo_root / "policies",
        Path(sys.prefix) / "policies",
    )
