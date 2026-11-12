import json

import pytest

from guardbench import Adapter, Verdict, load_suite, run_benchmark
from guardbench.adapters import LayeredGuard, PatternBaseline
from guardbench.cli import main
from guardbench.suite import ATTACK_CATEGORIES


class BlockEverything(Adapter):
    name = "block-everything"

    def check(self, text, field):
        return Verdict(True)


class AllowEverything(Adapter):
    name = "allow-everything"

    def check(self, text, field):
        return Verdict(False)


def test_builtin_suite_is_valid_and_covers_every_category():
    cases = load_suite()
    assert len({c.id for c in cases}) == len(cases)
    assert {c.category for c in cases if c.block} == set(ATTACK_CATEGORIES)
    assert all(c.atlas.startswith("AML.T") for c in cases if c.block)


def test_metrics_at_the_extremes():
    cases = load_suite()
    block_all, allow_all = run_benchmark([BlockEverything(), AllowEverything()], cases)
    assert block_all.block_rate == 1.0 and block_all.false_positive_rate == 1.0
    assert allow_all.block_rate == 0.0 and allow_all.false_positive_rate == 0.0
    assert len(allow_all.missed) == sum(c.block for c in cases)


def test_layered_guard_beats_baseline():
    baseline, layered = run_benchmark([PatternBaseline(), LayeredGuard()], load_suite())
    assert layered.block_rate > baseline.block_rate
    assert set(layered.missed) < set(baseline.missed)


def test_suite_rejects_bad_rows(tmp_path):
    bad = tmp_path / "bad.jsonl"
    bad.write_text(json.dumps({"id": "X", "category": "benign", "field": "input", "block": True, "text": "hi"}))
    with pytest.raises(ValueError):
        load_suite(bad)


def test_cli_json_report(tmp_path):
    out = tmp_path / "report.json"
    assert main(["run", "--adapters", "layered-guard", "--format", "json", "--out", str(out)]) == 0
    report = json.loads(out.read_text())
    assert report["adapters"][0]["name"] == "layered-guard"


def test_cli_regression_gate_fails_when_threshold_not_met(capsys):
    assert main(["run", "--adapters", "pattern-baseline", "--fail-under", "0.99"]) == 1
    assert "FAIL pattern-baseline" in capsys.readouterr().err


def test_cli_rejects_unknown_adapter():
    assert main(["run", "--adapters", "nope"]) == 2
