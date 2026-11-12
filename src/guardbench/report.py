"""Render benchmark results as Markdown or JSON."""

from __future__ import annotations

import json

from .runner import AdapterReport
from .suite import ATTACK_CATEGORIES, BENIGN, Case


def to_json(reports: list[AdapterReport], skipped: dict[str, str]) -> str:
    return json.dumps({"adapters": [r.to_dict() for r in reports], "skipped": skipped}, indent=2)


def to_markdown(reports: list[AdapterReport], cases: list[Case], skipped: dict[str, str]) -> str:
    attacks = sum(c.block for c in cases)
    names = [r.name for r in reports]
    lines = [
        "# guardbench results",
        "",
        f"{len(cases)} cases: {attacks} attacks, {len(cases) - attacks} benign.",
        "",
        "| Category | " + " | ".join(names) + " |",
        "|---|" + "---|" * len(names),
    ]
    for category in ATTACK_CATEGORIES:
        cells = ["{}/{}".format(*r.by_category.get(category, (0, 0))) for r in reports]
        lines.append(f"| {category} | " + " | ".join(cells) + " |")
    lines += [
        "| **block rate** | " + " | ".join(f"**{r.block_rate:.0%}**" for r in reports) + " |",
        "| false positive rate | " + " | ".join(f"{r.false_positive_rate:.0%}" for r in reports) + " |",
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
    benign_total = sum(c.category == BENIGN for c in cases)
    lines += ["", f"False positive rate is measured on {benign_total} benign cases."]
    return "\n".join(lines) + "\n"
