"""guardbench: a regression benchmark for LLM guardrails."""

from .adapters import REGISTRY, Adapter, Verdict
from .evidence import EvidenceLog, verify_chain
from .normalize import normalize
from .runner import AdapterReport, run_benchmark
from .suite import Case, ToolCall, Turn, load_suite

__version__ = "0.1.0"

__all__ = [
    "REGISTRY",
    "Adapter",
    "AdapterReport",
    "Case",
    "EvidenceLog",
    "ToolCall",
    "Turn",
    "Verdict",
    "load_suite",
    "normalize",
    "run_benchmark",
    "verify_chain",
]
