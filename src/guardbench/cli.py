"""Command line interface.

    guardbench list
    guardbench run [--adapters a,b] [--suite cases.jsonl] [--format md|json]
                   [--out FILE] [--fail-under 0.85] [--max-fpr 0.15]
    guardbench verify-log FILE [--head HASH]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .adapters import REGISTRY
from .evidence import verify_chain
from .report import to_json, to_markdown
from .runner import run_benchmark
from .suite import load_suite


def _cmd_list(_: argparse.Namespace) -> int:
    for name, cls in REGISTRY.items():
        reason = cls().setup()
        print(f"{name:20} {'ready' if reason is None else 'unavailable: ' + reason}")
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    names = args.adapters.split(",") if args.adapters else list(REGISTRY)
    unknown = [n for n in names if n not in REGISTRY]
    if unknown:
        print(f"unknown adapter(s): {', '.join(unknown)}. Try: guardbench list", file=sys.stderr)
        return 2

    adapters, skipped = [], {}
    for name in names:
        adapter = REGISTRY[name]()
        reason = adapter.setup()
        if reason is None:
            adapters.append(adapter)
        else:
            skipped[name] = reason
    if not adapters:
        print("no adapter is available to run", file=sys.stderr)
        return 2

    cases = load_suite(args.suite)
    reports = run_benchmark(adapters, cases)
    text = to_json(reports, skipped) if args.format == "json" else to_markdown(reports, cases, skipped)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        print(text)

    # Regression gate for CI: the explicitly requested adapters must hold the line.
    failed = False
    for report in reports:
        if args.fail_under is not None and report.block_rate < args.fail_under:
            print(f"FAIL {report.name}: block rate {report.block_rate:.0%} < {args.fail_under:.0%}", file=sys.stderr)
            failed = True
        if args.max_fpr is not None and report.false_positive_rate > args.max_fpr:
            print(
                f"FAIL {report.name}: false positive rate {report.false_positive_rate:.0%} > {args.max_fpr:.0%}",
                file=sys.stderr,
            )
            failed = True
    return 1 if failed else 0


def _cmd_verify(args: argparse.Namespace) -> int:
    ok, message = verify_chain(args.file, args.head)
    print(("OK: " if ok else "TAMPERED: ") + message)
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="guardbench", description="Regression benchmark for LLM guardrails.")
    parser.add_argument("--version", action="version", version=f"guardbench {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="show adapters and whether each can run here").set_defaults(func=_cmd_list)

    run = sub.add_parser("run", help="run the suite against one or more guardrails")
    run.add_argument("--adapters", help="comma-separated adapter names (default: all available)")
    run.add_argument("--suite", help="path to a JSONL suite (default: built-in)")
    run.add_argument("--format", choices=("md", "json"), default="md")
    run.add_argument("--out", help="write the report to this file instead of stdout")
    run.add_argument("--fail-under", type=float, help="exit 1 if any adapter's block rate is below this (0 to 1)")
    run.add_argument("--max-fpr", type=float, help="exit 1 if any adapter's false positive rate is above this")
    run.set_defaults(func=_cmd_run)

    verify = sub.add_parser("verify-log", help="verify a hash-chained evidence log")
    verify.add_argument("file")
    verify.add_argument("--head", help="expected hash of the last record")
    verify.set_defaults(func=_cmd_verify)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
