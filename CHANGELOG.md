# Changelog

## 0.1.0

First release.

- Adapter interface with six adapters: pattern baseline, layered reference guard, Microsoft Presidio, LLM Guard, Amazon Bedrock Guardrails, generic HTTP guardrail.
- Built-in suite of 41 cases (31 attacks, 10 benign) tagged with MITRE ATLAS v5.6.0 technique IDs.
- `guardbench run` with Markdown and JSON reports and CI gates (`--fail-under`, `--max-fpr`).
- Hash-chained evidence log with `guardbench verify-log`.
- Worked example of indirect prompt injection against a RAG agent.
- Threat model of a runtime guardrail API.
