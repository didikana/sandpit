from __future__ import annotations

from pathlib import Path

from sandpit.policy import load_policy, parse_policy, resolve_policy_path


def test_policy_name_resolves_to_bundled_policy() -> None:
    path = resolve_policy_path("no-network")

    assert path.name == "no-network.toml"
    assert path.parent.name == "policies"


def test_policy_parser_expands_templates(tmp_path: Path) -> None:
    policy = parse_policy(
        {
            "fs": {
                "allow_read": ["{cwd}", "{home}/.cache"],
                "allow_write": [],
                "deny_read": [],
            },
            "network": {"allow": False},
            "process": {
                "allow_fork": False,
                "allow_exec": False,
                "max_cpu_ms": 5000,
                "max_mem_mb": 256,
            },
            "imports": {"deny": ["socket"]},
        },
        cwd=tmp_path,
    )

    assert tmp_path.resolve() in policy.fs.allow_read
    assert policy.network.allow is False
    assert policy.imports.deny == ("socket",)


def test_load_policy_by_name() -> None:
    policy = load_policy("default")

    assert policy is not None
    assert policy.name == "default"
    assert policy.violation_for_import("socket") is not None
