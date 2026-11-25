"""Render benchmark results as Markdown or JSON."""

from __future__ import annotations

import json

from .runner import AdapterReport
from .suite import ATTACK_CATEGORIES, BENIGN, Case


def to_json(
    reports: list[AdapterReport],
    skipped: dict[str, str],
    fields: list[str] | None = None,
    langs: list[str] | None = None,
) -> str:
    data: dict = {"adapters": [r.to_dict() for r in reports], "skipped": skipped}
    if fields:
        data["fields"] = fields
    if langs:
        data["langs"] = langs
    return json.dumps(data, indent=2)


def _cell(blocked: int, total: int) -> str:
    # A field filter can leave a category with no cases, for example data_leakage without output.
    return f"{blocked}/{total}" if total else "not applicable"


def to_markdown(
    reports: list[AdapterReport],
    cases: list[Case],
    skipped: dict[str, str],
    fields: list[str] | None = None,
    langs: list[str] | None = None,
) -> str:
    attacks = sum(c.block for c in cases)
    benign_total = sum(c.category == BENIGN for c in cases)
    tool_calls = sum(c.tool_call is not None for c in cases)
    multi_turn = [c for c in cases if c.turns]
    names = [r.name for r in reports]
    lines = [
        "# guardbench results",
        "",
        f"{len(cases)} cases: {attacks} attacks, {len(cases) - attacks} benign."
        + (f" Tool calls: {tool_calls}." if tool_calls else "")
        + (f" Multi-turn: {len(multi_turn)}." if multi_turn else "")
        + (f" Fields: {', '.join(fields)}." if fields else "")
        + (f" Languages: {', '.join(langs)}." if langs else ""),
        "",
        "| Category | " + " | ".join(names) + " |",
        "|---|" + "---|" * len(names),
    ]
    for category in ATTACK_CATEGORIES:
        cells = [_cell(*r.by_category.get(category, (0, 0))) for r in reports]
        lines.append(f"| {category} | " + " | ".join(cells) + " |")
    lines += [
        "| **block rate** | "
        + " | ".join(f"**{r.attacks_blocked}/{r.attacks_total} ({r.block_rate:.0%})**" for r in reports)
        + " |",
        "| false positive rate | "
        + " | ".join(f"{len(r.false_positives)}/{benign_total} ({r.false_positive_rate:.0%})" for r in reports)
        + " |",
        "| precision | " + " | ".join(f"{r.precision:.0%}" for r in reports) + " |",
        "| mean latency per check | " + " | ".join(f"{r.mean_latency_ms:.2f} ms" for r in reports) + " |",
        "",
        "## Misses",
        "",
    ]
    for r in reports:
        lines.append(f"- **{r.name}** missed: " + (", ".join(r.missed) or "none"))
        if r.false_positives:
            lines.append(f"  - blocked benign: {', '.join(r.false_positives)}")
    languages = list(dict.fromkeys(c.lang for c in cases))
    if len(languages) > 1:
        lines += [
            "",
            "## By language",
            "",
            "Attacks blocked, then benign cases blocked.",
            "",
            "| Language | " + " | ".join(names) + " |",
            "|---|" + "---|" * len(names),
        ]
        for lang in languages:
            cells = []
            for r in reports:
                ab, at, bb, bt = r.by_language.get(lang, (0, 0, 0, 0))
                cells.append(f"{_cell(ab, at)}, {_cell(bb, bt)}")
            lines.append(f"| {lang} | " + " | ".join(cells) + " |")
    if multi_turn:
        lines += [
            "",
            "## Multi-turn",
            "",
            "The turn at which each guardrail first blocked. An attack that is blocked before its last turn"
            " and a benign conversation that is blocked at any turn are both worth reading.",
            "",
            "| Case | Expected | Turns | " + " | ".join(names) + " |",
            "|---|---|---|" + "---|" * len(names),
        ]
        for case in multi_turn:
            cells = []
            for r in reports:
                turn = r.first_block_turn.get(case.id)
                cells.append(f"turn {turn}" if turn else "not blocked")
            expected = "block" if case.block else "allow"
            lines.append(f"| {case.id} | {expected} | {len(case.turns)} | " + " | ".join(cells) + " |")
    if skipped:
        lines += ["", "## Not run", ""] + [f"- **{name}**: {why}" for name, why in skipped.items()]
    lines += ["", f"False positive rate is measured on {benign_total} benign cases."]
    return "\n".join(lines) + "\n"
