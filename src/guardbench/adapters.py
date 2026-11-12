"""Guardrail adapters behind one interface.

An adapter answers one question: should this text be blocked?

    verdict = adapter.check(text, field)

``field`` says where the text came from, because the right policy differs:

* ``input``    what the user typed
* ``context``  retrieved documents, tool output, memory. Untrusted data.
* ``output``   what the model wants to send back or pass to a tool
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import ClassVar, Literal

from .normalize import normalize

Field = Literal["input", "context", "output"]


@dataclass(frozen=True)
class Verdict:
    blocked: bool
    reason: str = ""


class Adapter:
    """Base class. Subclasses set ``name`` and implement ``check``."""

    name: ClassVar[str] = "adapter"

    def setup(self) -> str | None:
        """Prepare the adapter. Return a reason string if it cannot run."""
        return None

    def check(self, text: str, field: Field) -> Verdict:
        raise NotImplementedError


# ---------------------------------------------------------------- patterns
_INJECTION = [
    r"ignore (all |any )?(the )?(previous|prior|above|earlier) (instructions|rules|prompts?)",
    r"disregard (the |all )?(user'?s? question|previous|prior|above)",
    r"forget (the |all |your )?(rules|instructions)",
    r"system override",
    r"(developer|debug|god) mode",
    r"no (restrictions|content policy|policies)",
    r"(unfiltered|uncensored) (model|ai|assistant)",
    r"(repeat|print|reveal|show|output) (everything|all|your|the) .{0,40}"
    r"(above|system prompt|instructions|hidden rules|initial configuration|password)",
    r"(previous|earlier) instructions are outdated",
    r"your new task is",
    r"note to the assistant",
    r"my instructions are",
]
_SECRETS = [
    r"\bsk-[A-Za-z0-9-]{16,}",
    r"(api[_-]?key|password|secret)\s*[=:]\s*\S+",
    r"\b[a-z][a-z0-9+.-]*://[^\s:/@]+:[^\s@/]+@",  # credentials in a URL
    r"\b(?:\d[ -]?){13,16}\b",  # card-like digit runs
]
_CONTEXT_DIRECTIVES = [
    r"\b(ai |the )?(assistants?|agents?|model|chatbot)\b.{0,60}"
    r"\b(should|must|call|email|send|append|recommend|tell|disregard|ignore|rate|never)\b",
    r"when (summari[sz]ing|reading|processing) this (document|page|file)",
    r"<!--.*?(assistant|ai|agent).*?-->",
    r"\[\[\s*(assistant|ai|agent)\s*:",
    r"(conversation|chat) history",
    r"\.env\b",
]
_HOST = re.compile(r"(?:https?://|@)([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")


def _compile(patterns: list[str]) -> list[re.Pattern]:
    return [re.compile(p, re.IGNORECASE | re.DOTALL) for p in patterns]


class PatternBaseline(Adapter):
    """Keyword and regex matching on the raw text.

    This is what many teams ship first. It is included as the floor to
    measure against, not as a recommendation.
    """

    name = "pattern-baseline"

    def __init__(self) -> None:
        self._injection = _compile(_INJECTION)
        self._secrets = _compile(_SECRETS)

    def check(self, text: str, field: Field) -> Verdict:
        if any(p.search(text) for p in self._injection):
            return Verdict(True, "injection pattern")
        if field == "output" and any(p.search(text) for p in self._secrets):
            return Verdict(True, "secret or card pattern")
        return Verdict(False)


class LayeredGuard(Adapter):
    """Reference implementation of three model-free layers.

    1. Restore obfuscated input before scanning.
    2. Treat ``context`` as untrusted data: an instruction addressed to the
       assistant inside a document is a finding in itself.
    3. Check outbound destinations in ``context`` and ``output`` against an
       allowlist.
    """

    name = "layered-guard"

    def __init__(self, allowed_hosts: tuple[str, ...] = ("example.com", "docs.example.com")) -> None:
        self._base = PatternBaseline()
        self._directives = _compile(_CONTEXT_DIRECTIVES)
        self._allowed = {h.lower() for h in allowed_hosts}

    def check(self, text: str, field: Field) -> Verdict:
        restored = normalize(text)
        verdict = self._base.check(restored, field)
        if verdict.blocked:
            return verdict
        if field == "context" and any(p.search(restored) for p in self._directives):
            return Verdict(True, "instruction inside untrusted data")
        if field in ("context", "output"):
            for host in _HOST.findall(restored):
                if host.lower() not in self._allowed:
                    return Verdict(True, f"destination not on allowlist: {host}")
        return Verdict(False)


# ------------------------------------------------------- third-party tools
class PresidioPII(Adapter):
    """Microsoft Presidio. Detects personal data in model output."""

    name = "presidio-pii"
    entities: ClassVar[list[str]] = ["CREDIT_CARD", "EMAIL_ADDRESS", "PHONE_NUMBER", "IBAN_CODE", "US_SSN"]

    def setup(self) -> str | None:
        try:
            from presidio_analyzer import AnalyzerEngine

            self._engine = AnalyzerEngine()
        except Exception as exc:  # missing package or spaCy model
            return f"presidio not usable ({type(exc).__name__})"
        return None

    def check(self, text: str, field: Field) -> Verdict:
        if field != "output":
            return Verdict(False)
        hits = self._engine.analyze(text=text, entities=self.entities, language="en", score_threshold=0.5)
        if hits:
            return Verdict(True, "PII: " + ", ".join(sorted({h.entity_type for h in hits})))
        return Verdict(False)


class LLMGuard(Adapter):
    """Protect AI's LLM Guard: a trained prompt-injection classifier."""

    name = "llm-guard"

    def setup(self) -> str | None:
        try:
            from llm_guard.input_scanners import PromptInjection
            from llm_guard.output_scanners import Sensitive

            self._injection, self._sensitive = PromptInjection(), Sensitive()
        except Exception as exc:
            return f"llm-guard not usable ({type(exc).__name__})"
        return None

    def check(self, text: str, field: Field) -> Verdict:
        if field == "output":
            _, valid, _ = self._sensitive.scan("", text)
            return Verdict(not valid, "sensitive output")
        _, valid, score = self._injection.scan(text)
        return Verdict(not valid, f"prompt injection score {score:.2f}")


class PromptGuard2(Adapter):
    """Meta's Llama Prompt Guard 2: a trained prompt-attack classifier.

    The model is gated on Hugging Face, so the account behind ``HF_TOKEN``
    must have accepted Meta's licence. The score is the probability of the
    model's last class (malicious), the same value LlamaFirewall reads.
    The text is passed to the model as is; LlamaFirewall's extra
    preprocessing step is not applied. The classifier is built for inputs
    and untrusted context, so ``output`` text is never blocked.

    Environment: ``PROMPT_GUARD_MODEL`` (default the 86M model) and
    ``PROMPT_GUARD_THRESHOLD`` (default 0.5; LlamaFirewall ships 0.9).
    """

    name = "prompt-guard-2"
    default_model: ClassVar[str] = "meta-llama/Llama-Prompt-Guard-2-86M"

    def setup(self) -> str | None:
        try:
            self._threshold = float(os.environ.get("PROMPT_GUARD_THRESHOLD", "0.5"))
        except ValueError:
            return "PROMPT_GUARD_THRESHOLD is not a number"
        if not 0.0 < self._threshold <= 1.0:
            return "PROMPT_GUARD_THRESHOLD must be in (0, 1]"
        try:
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer

            model_id = os.environ.get("PROMPT_GUARD_MODEL", self.default_model)
            self._torch = torch
            self._tokenizer = AutoTokenizer.from_pretrained(model_id)
            self._model = AutoModelForSequenceClassification.from_pretrained(model_id)
            self._model.eval()
        except Exception as exc:  # missing package, no licence, no network
            return f"prompt-guard-2 not usable ({type(exc).__name__})"
        return None

    def score(self, text: str) -> float:
        inputs = self._tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
        with self._torch.no_grad():
            logits = self._model(**inputs).logits
        return float(self._torch.softmax(logits, dim=-1)[0, -1])

    def check(self, text: str, field: Field) -> Verdict:
        if field == "output":
            return Verdict(False, "not applicable to output")
        score = self.score(text)
        return Verdict(score >= self._threshold, f"malicious score {score:.2f}")


class BedrockGuardrail(Adapter):
    """Amazon Bedrock Guardrails through the ApplyGuardrail API.

    Environment: BEDROCK_GUARDRAIL_ID, BEDROCK_GUARDRAIL_VERSION (default
    DRAFT), AWS_REGION, plus standard AWS credentials.
    """

    name = "bedrock-guardrail"

    def setup(self) -> str | None:
        self._id = os.getenv("BEDROCK_GUARDRAIL_ID")
        if not self._id:
            return "BEDROCK_GUARDRAIL_ID not set"
        try:
            import boto3

            self._client = boto3.client("bedrock-runtime", region_name=os.getenv("AWS_REGION", "us-east-1"))
        except Exception as exc:
            return f"boto3 not usable ({type(exc).__name__})"
        self._version = os.getenv("BEDROCK_GUARDRAIL_VERSION", "DRAFT")
        return None

    def check(self, text: str, field: Field) -> Verdict:
        response = self._client.apply_guardrail(
            guardrailIdentifier=self._id,
            guardrailVersion=self._version,
            source="OUTPUT" if field == "output" else "INPUT",
            content=[{"text": {"text": text}}],
        )
        return Verdict(response["action"] == "GUARDRAIL_INTERVENED", "bedrock intervened")


class HTTPGuardrail(Adapter):
    """Any guardrail service behind an HTTP endpoint.

    Environment: GUARDRAIL_URL, GUARDRAIL_KEY (optional bearer token),
    GUARDRAIL_TEXT_FIELD (request field that carries the text, default
    ``text``), GUARDRAIL_BLOCK_FIELD (response field that is true on block,
    default ``blocked``), GUARDRAIL_TIMEOUT (seconds, default 5).

    A timeout or an error is a block. A guardrail that cannot be reached
    must fail closed, and the benchmark scores it that way.
    """

    name = "http-guardrail"

    def setup(self) -> str | None:
        self._url = os.getenv("GUARDRAIL_URL")
        if not self._url:
            return "GUARDRAIL_URL not set"
        self._key = os.getenv("GUARDRAIL_KEY", "")
        self._text_field = os.getenv("GUARDRAIL_TEXT_FIELD", "text")
        self._block_field = os.getenv("GUARDRAIL_BLOCK_FIELD", "blocked")
        self._timeout = float(os.getenv("GUARDRAIL_TIMEOUT", "5"))
        return None

    def check(self, text: str, field: Field) -> Verdict:
        import requests

        headers = {"Authorization": f"Bearer {self._key}"} if self._key else {}
        try:
            response = requests.post(
                self._url, json={self._text_field: text, "field": field}, headers=headers, timeout=self._timeout
            )
            response.raise_for_status()
            return Verdict(bool(response.json().get(self._block_field)), "remote decision")
        except Exception as exc:
            return Verdict(True, f"fail closed ({type(exc).__name__})")


REGISTRY: dict[str, type[Adapter]] = {
    cls.name: cls for cls in (
        PatternBaseline,
        LayeredGuard,
        PresidioPII,
        LLMGuard,
        PromptGuard2,
        BedrockGuardrail,
        HTTPGuardrail,
    )
}
