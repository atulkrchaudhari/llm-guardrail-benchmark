"""Test cases and the loader for the built-in suite."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
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


_TOOL_CALL_KEYS = ("name", "arguments", "granted", "scope")


@dataclass(frozen=True)
class ToolCall:
    """A tool call the model proposes, with the scopes the agent was granted for the task."""

    name: str
    arguments: dict = field(default_factory=dict)
    granted: tuple[str, ...] = ()
    scope: str = ""  # the scope this call needs; the tool name when the row does not say

    def __post_init__(self) -> None:
        if not self.scope:
            object.__setattr__(self, "scope", self.name)

    @property
    def in_scope(self) -> bool:
        """True when the scope this call needs is one of the granted scopes."""
        return self.scope in self.granted

    def render(self) -> str:
        """The call as one line of text, for a guardrail that reads text only."""
        return f"{self.name}({json.dumps(self.arguments, ensure_ascii=False)})"


def _tool_call(raw: object) -> ToolCall:
    if not isinstance(raw, dict):
        raise ValueError("'tool_call' must be an object")
    unknown = sorted(set(raw) - set(_TOOL_CALL_KEYS))
    if unknown:
        raise ValueError(f"'tool_call' has unknown key(s): {', '.join(unknown)}")
    name = raw.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ValueError("'tool_call.name' must be a non-empty string")
    arguments = raw.get("arguments", {})
    if not isinstance(arguments, dict):
        raise ValueError("'tool_call.arguments' must be an object")
    if "granted" not in raw:
        raise ValueError("'tool_call.granted' is required; use [] when no scope was granted")
    granted = raw["granted"]
    if not isinstance(granted, list) or not all(isinstance(g, str) and g.strip() for g in granted):
        raise ValueError("'tool_call.granted' must be a list of non-empty strings")
    scope = raw.get("scope", name)
    if not isinstance(scope, str) or not scope.strip():
        raise ValueError("'tool_call.scope' must be a non-empty string")
    return ToolCall(name=name, arguments=arguments, granted=tuple(granted), scope=scope)


@dataclass(frozen=True)
class Case:
    id: str
    category: str
    field: str
    block: bool
    text: str = ""  # for a tool-call case, the call rendered as one line
    atlas: str = ""
    lang: str = DEFAULT_LANG  # language of the text, "en" when the row does not say
    tool_call: ToolCall | None = None


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
        row = json.loads(line)
        if "tool_call" in row:
            if "text" in row:
                raise ValueError(f"line {number}: a case has 'text' or 'tool_call', not both")
            if row.get("field") != "output":
                raise ValueError(f"line {number}: a 'tool_call' case must have field 'output'")
            try:
                call = _tool_call(row["tool_call"])
            except ValueError as error:
                raise ValueError(f"line {number}: {error}") from None
            row = {**row, "tool_call": call, "text": call.render()}
        elif not isinstance(row.get("text"), str) or not row["text"]:
            raise ValueError(f"line {number}: a case needs a non-empty 'text' or a 'tool_call'")
        case = Case(**row)
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
