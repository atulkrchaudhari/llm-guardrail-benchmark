"""Test cases and the loader for the built-in suite."""

from __future__ import annotations

import json
import re
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
FIELDS = ("input", "context", "output")
DEFAULT_LANG = "en"
# A language tag such as "en", "hi" or "pt-BR".
_LANG = re.compile(r"[a-z]{2,3}(-[A-Za-z0-9]{2,8})*")


@dataclass(frozen=True)
class Case:
    id: str
    category: str
    field: str
    block: bool
    text: str
    atlas: str = ""
    lang: str = DEFAULT_LANG  # language of the text, "en" when the row does not say


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
        if case.field not in FIELDS:
            raise ValueError(f"line {number}: unknown field {case.field!r}")
        if case.category not in (*ATTACK_CATEGORIES, BENIGN):
            raise ValueError(f"line {number}: unknown category {case.category!r}")
        if not isinstance(case.lang, str) or not _LANG.fullmatch(case.lang):
            raise ValueError(f"line {number}: 'lang' must be a language tag such as 'en' or 'hi', got {case.lang!r}")
        if case.block == (case.category == BENIGN):
            raise ValueError(f"line {number}: 'block' must be false for benign cases and true for attacks")
        seen.add(case.id)
        cases.append(case)
    return cases
