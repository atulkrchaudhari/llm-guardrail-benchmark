"""Render benchmark results as Markdown or JSON."""

from __future__ import annotations

import json

from .runner import AdapterReport
from .suite import ATTACK_CATEGORIES, BENIGN, Case


def to_json(reports: list[AdapterReport], skipped: dict[str, str], fields: list[str] | None = None) -> str:
    data: dict = {"adapters": [r.to_dict() for r in reports], "skipped": skipped}
    if fields:
        data["fields"] = fields
    return json.dumps(data, indent=2)


def _cell(blocked: int, total: int) -> str:
    # A field filter can leave a category with no cases, for example data_leakage without output.
    return f"{blocked}/{total}" if total else "not applicable"


def to_markdown(
    reports: list[AdapterReport], cases: list[Case], skipped: dict[str, str], fields: list[str] | None = None
) -> str:
    attacks = sum(c.block for c in cases)
    benign_total = sum(c.category == BENIGN for c in cases)
    names = [r.name for r in reports]
    lines = [
        "# guardbench results",
        "",
        f"{len(cases)} cases: {attacks} attacks, {len(cases) - attacks} benign."
        + (f" Fields: {', '.join(fields)}." if fields else ""),
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
    if skipped:
        lines += ["", "## Not run", ""] + [f"- **{name}**: {why}" for name, why in skipped.items()]
    lines += ["", f"False positive rate is measured on {benign_total} benign cases."]
    return "\n".join(lines) + "\n"
