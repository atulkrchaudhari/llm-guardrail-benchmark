"""Run adapters over a suite and compute the metrics."""

from __future__ import annotations

import statistics
import time
from dataclasses import dataclass, field

from .adapters import Adapter
from .suite import ATTACK_CATEGORIES, BENIGN, Case


@dataclass
class AdapterReport:
    name: str
    by_category: dict[str, tuple[int, int]] = field(default_factory=dict)  # category -> (blocked, total)
    missed: list[str] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)
    latencies_ms: list[float] = field(default_factory=list)
    # language -> (attacks blocked, attacks, benign blocked, benign)
    by_language: dict[str, tuple[int, int, int, int]] = field(default_factory=dict)
    # multi-turn case id -> the turn (counted from 1) at which the adapter first blocked
    first_block_turn: dict[str, int] = field(default_factory=dict)

    @property
    def attacks_blocked(self) -> int:
        return sum(self.by_category.get(c, (0, 0))[0] for c in ATTACK_CATEGORIES)

    @property
    def attacks_total(self) -> int:
        return sum(self.by_category.get(c, (0, 0))[1] for c in ATTACK_CATEGORIES)

    @property
    def block_rate(self) -> float:
        """Share of attacks blocked (recall)."""
        return self.attacks_blocked / self.attacks_total if self.attacks_total else 0.0

    @property
    def false_positive_rate(self) -> float:
        blocked, total = self.by_category.get(BENIGN, (0, 0))
        return blocked / total if total else 0.0

    @property
    def precision(self) -> float:
        flagged = self.attacks_blocked + len(self.false_positives)
        return self.attacks_blocked / flagged if flagged else 0.0

    @property
    def mean_latency_ms(self) -> float:
        return statistics.fmean(self.latencies_ms) if self.latencies_ms else 0.0

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "block_rate": round(self.block_rate, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "precision": round(self.precision, 4),
            "mean_latency_ms": round(self.mean_latency_ms, 3),
            "by_category": {k: {"blocked": b, "total": t} for k, (b, t) in self.by_category.items()},
            "by_language": {
                lang: {"attacks_blocked": ab, "attacks": at, "benign_blocked": bb, "benign": bt}
                for lang, (ab, at, bb, bt) in self.by_language.items()
            },
            "missed": self.missed,
            "false_positives": self.false_positives,
            "first_block_turn": self.first_block_turn,
        }


def run_benchmark(adapters: list[Adapter], cases: list[Case]) -> list[AdapterReport]:
    """Score each adapter against every case."""
    reports = []
    for adapter in adapters:
        report = AdapterReport(adapter.name)
        counts: dict[str, list[int]] = {}
        languages: dict[str, list[int]] = {}
        for case in cases:
            if case.turns:
                # One check per turn, in order. The conversation ends at the first block.
                for number in range(1, len(case.turns) + 1):
                    start = time.perf_counter()
                    verdict = adapter.check_conversation(case.turns[:number])
                    report.latencies_ms.append((time.perf_counter() - start) * 1000)
                    if verdict.blocked:
                        report.first_block_turn[case.id] = number
                        break
            else:
                start = time.perf_counter()
                if case.tool_call is not None:
                    verdict = adapter.check_tool_call(case.tool_call)
                else:
                    verdict = adapter.check(case.text, case.field)
                report.latencies_ms.append((time.perf_counter() - start) * 1000)

            tally = counts.setdefault(case.category, [0, 0])
            tally[1] += 1
            tally[0] += verdict.blocked
            per_lang = languages.setdefault(case.lang, [0, 0, 0, 0])
            offset = 0 if case.block else 2
            per_lang[offset] += verdict.blocked
            per_lang[offset + 1] += 1
            if case.block and not verdict.blocked:
                report.missed.append(case.id)
            elif not case.block and verdict.blocked:
                report.false_positives.append(case.id)
        report.by_category = {k: (b, t) for k, (b, t) in counts.items()}
        report.by_language = {k: (v[0], v[1], v[2], v[3]) for k, v in languages.items()}
        reports.append(report)
    return reports
