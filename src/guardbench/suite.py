"""Test cases and the loader for the built-in suite."""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

ATTACK_CATEGORIES = (
    "direct_injection",
    "system_prompt_extraction",
    "jailbreak",
    "obfuscation",
    "indirect_injection",
    "tool_exfiltration",
    "data_leakage",
)
BENIGN = "benign"
_FIELDS = {"input", "context", "output"}


@dataclass(frozen=True)
class Case:
    id: str
    category: str
    field: str
    block: bool
    text: str
    atlas: str = ""


def load_suite(path: str | Path | None = None) -> list[Case]:
    """Load cases from a JSONL file. With no path, load the built-in suite."""
    if path is None:
        raw = resources.files("guardbench").joinpath("suite.jsonl").read_text(encoding="utf-8")
    else:
        raw = Path(path).read_text(encoding="utf-8")

    cases, seen = [], set()
    for number, line in enumerate(raw.splitlines(), start=1):
        if not line.strip():
            continue
        case = Case(**json.loads(line))
        if case.id in seen:
            raise ValueError(f"line {number}: duplicate case id {case.id!r}")
        if case.field not in _FIELDS:
            raise ValueError(f"line {number}: unknown field {case.field!r}")
        if case.category not in (*ATTACK_CATEGORIES, BENIGN):
            raise ValueError(f"line {number}: unknown category {case.category!r}")
        if case.block == (case.category == BENIGN):
            raise ValueError(f"line {number}: 'block' must be false for benign cases and true for attacks")
        seen.add(case.id)
        cases.append(case)
    return cases
