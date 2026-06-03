"""Command line interface for sandpit."""

from __future__ import annotations

import argparse
from pathlib import Path

from sandpit.trace import write_trace
from sandpit.tracer import trace_script


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sandpit")
    subcommands = parser.add_subparsers(dest="command", required=True)

    run = subcommands.add_parser("run", help="trace a Python script")
    run.add_argument("script", help="Python script to execute")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "run":
        script = Path(args.script)
        output = script.with_suffix(".sptrace")
        print(f"[sandpit] tracing {script}")
        print(f"output   : {output}")
        events = trace_script(script)
        write_trace(events, output)
        exit_code = _exit_code(events)
        print(f"EXIT     code={exit_code}")
        print(f"trace written -> {output} ({len(events)} events)")
        return exit_code

    return 2


def _exit_code(events: list[dict[str, object]]) -> int:
    for event in reversed(events):
        if event.get("kind") == "exit":
            code = event.get("code", 1)
            return code if isinstance(code, int) else 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
