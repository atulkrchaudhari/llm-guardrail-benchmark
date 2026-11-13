# Changelog

## Unreleased

- Suite grows to 47 cases: agent instruction file injection, tool description poisoning, memory poisoning, a Hindi direct injection, and two more benign look-alikes.
- `http-guardrail` adapter: `GUARDRAIL_TEXT_FIELD` sets the request field that carries the text.
- CI false positive gate set to the measured baseline of 25%.
- First published results for LLM Guard 0.3.16, run by the new `Third-party guardrails` workflow.
- `prompt-guard-2` adapter for Meta's Llama Prompt Guard 2, with a `Prompt Guard 2` workflow that measures it at thresholds 0.5 and 0.9. The model is gated, so the workflow needs an `HF_TOKEN` secret.
- First published results for Prompt Guard 2 (86M): 11 of 35 attacks blocked, 11 of 28 on input and context, no false positives, identical at both thresholds.
- README notes that the upstream LLM Guard project was archived in July 2026. The published result is for release 0.3.16 and is kept for reference.
- `llamafirewall-static` adapter for the two model-free scanners in Meta's LlamaFirewall (`RegexScanner`, `HiddenASCIIScanner`). First published result with llamafirewall 1.0.3: 6 of 35 attacks blocked, no false positives. PromptGuard, AlignmentCheck and CodeShield are not included.

## 0.1.0

First release.

- Adapter interface with six adapters: pattern baseline, layered reference guard, Microsoft Presidio, LLM Guard, Amazon Bedrock Guardrails, generic HTTP guardrail.
- Built-in suite of 41 cases (31 attacks, 10 benign) tagged with MITRE ATLAS v5.6.0 technique IDs.
- `guardbench run` with Markdown and JSON reports and CI gates (`--fail-under`, `--max-fpr`).
- Hash-chained evidence log with `guardbench verify-log`.
- Worked example of indirect prompt injection against a RAG agent.
- Threat model of a runtime guardrail API.
