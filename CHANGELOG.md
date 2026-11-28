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
- `llamafirewall` adapter: LlamaFirewall's `PromptGuardScanner` on input and context plus the two static scanners on every field, with a `llamafirewall` job in the `Prompt Guard 2` workflow. First published result with llamafirewall 1.0.3 and transformers 4.57.6: 18 of 35 attacks blocked, 15 of 28 on input and context, one false positive (B1). AlignmentCheck and CodeShield are not included.
- The `llamafirewall` extra pins `huggingface_hub<1.0`, which llamafirewall 1.0.3 needs for its PromptGuard scanner.
- README records that the raw Prompt Guard 2 model decides six cases differently under transformers 4.57.6 than under 5.23.0.
- `guardbench run --fields input,context` scores only the cases that arrive in the named fields. The Markdown report now shows block rate and false positive rate as counts as well as percentages.
- The `Prompt Guard 2` workflow runs the raw model once per model size, 86M and 22M, and prints an input and context only table for each.
- First published results for Prompt Guard 2 (22M) next to the 86M model: 1 of 35 attacks blocked against 11 of 35, no false positives for either, 49 ms against 149 ms per check on input and context cases.
- Cases take an optional `lang` field, a language tag that defaults to `en`. The loader rejects a malformed tag, the Markdown report adds a per-language table when a suite holds more than one language, and the JSON report carries `by_language`. The Hindi case D6 is tagged `hi`. No measured figure changes (refs #3).
- `guardbench run --lang hi` scores only the cases in the named languages. It combines with `--fields`, the report names the languages it covers, and the JSON report carries them under `langs`. A tag the suite does not have is rejected with the list of tags it has (refs #3).
- Suite grows to 56 cases: five Hindi attacks (direct injection D7, jailbreak J4, indirect injection I9, exfiltration E6 and E7) and four Hindi benign look-alikes (B13 to B16). With D6 the suite has six Hindi attacks (refs #3).
- CI block rate gate set to the measured baseline of 80%. `layered-guard` blocks 32 of 40 attacks on the larger suite, against 30 of 35 before; it misses four of the six Hindi attacks.
- All published results re-measured on the 56-case suite on 18 November 2026: the built-in adapters, Presidio and LLM Guard 0.3.16 by the `Third-party guardrails` workflow, Prompt Guard 2 (86M and 22M) and both LlamaFirewall adapters by the `Prompt Guard 2` workflow.
- README adds a per-language table for every published adapter. LLM Guard blocks five of six Hindi attacks and all four Hindi benign cases. Prompt Guard 2 86M blocks two of six Hindi attacks at threshold 0.5 and one at 0.9, and no Hindi benign case.
- Tests check that every non-English language in the built-in suite has attacks in at least three categories and a benign case for each field an attack uses.
- Suite grows to 66 cases: six Spanish attacks (direct injection D8, system prompt extraction S4, jailbreak J5, indirect injection I10, exfiltration E8 and E9) and four Spanish benign look-alikes (B17 to B20), all tagged `es` (refs #3).
- CI block rate gate set to the measured baseline of 73%. `layered-guard` blocks 34 of 46 attacks on the larger suite, against 32 of 40 before; it misses four of the six Spanish attacks.
- Tests check that every host named in a built-in case is a reserved example domain.
- All published results re-measured on the 66-case suite on 19 November 2026: the built-in adapters, Presidio and LLM Guard 0.3.16 by the `Third-party guardrails` workflow, Prompt Guard 2 (86M and 22M) and both LlamaFirewall adapters by the `Prompt Guard 2` workflow.
- README per-language table gains a Spanish column. LLM Guard blocks five of six Spanish attacks and three of four Spanish benign cases. Prompt Guard 2 86M blocks two of six Spanish attacks at both thresholds and no Spanish benign case. LlamaFirewall with PromptGuard blocks one of six.
- README records that the raw Prompt Guard 2 model now decides seven cases differently under transformers 4.57.6 than under 5.23.0; the Spanish jailbreak J5 is the seventh.
- Suite grows to 76 cases: six German attacks (direct injection D9, system prompt extraction S5, jailbreak J6, indirect injection I11, exfiltration E10 and E11) and four German benign look-alikes (B21 to B24), all tagged `de` (refs #3).
- CI block rate gate set to the measured baseline of 69%. `layered-guard` blocks 36 of 52 attacks on the larger suite, against 34 of 46 before; it misses four of the six German attacks.
- All published results re-measured on the 76-case suite on 21 November 2026: the built-in adapters, Presidio and LLM Guard 0.3.16 by the `Third-party guardrails` workflow, Prompt Guard 2 (86M and 22M) and both LlamaFirewall adapters by the `Prompt Guard 2` workflow. The raw Prompt Guard 2 jobs now run under transformers 5.24.0.
- README per-language table gains a German column. LLM Guard blocks four of six German attacks and two of four German benign cases. Prompt Guard 2 86M blocks three of six German attacks at threshold 0.5 and two at 0.9, and one German benign case (B21) at both, its first false positive on this suite. LlamaFirewall with PromptGuard blocks no German attack.
- README records that the raw Prompt Guard 2 model now decides ten cases differently under transformers 4.57.6 than under 5.24.0; the German cases J6, I11 and B21 are the three new ones.
- Cases can carry a structured tool call in place of `text`: `tool_call` with `name`, `arguments`, `granted` and an optional `scope`, always in the `output` field. The loader validates the row and renders the call as one line of text. The runner passes the call to the new `Adapter.check_tool_call`, which by default scores the rendered line as `output`, so existing adapters run unchanged. The Markdown report counts tool-call cases. The built-in suite has no tool-call case yet and no measured figure changes (refs #4).
- Suite grows to 86 cases: six French attacks (direct injection D10, system prompt extraction S6, jailbreak J7, indirect injection I12, exfiltration E12 and E13) and four French benign look-alikes (B25 to B28), all tagged `fr` (refs #3).
- CI block rate gate set to the measured baseline of 65%. `layered-guard` blocks 38 of 58 attacks on the larger suite, against 36 of 52 before; it misses four of the six French attacks.
- The `--lang` error test names a tag that no planned suite language uses, so it does not depend on which languages the suite holds.
- All published results re-measured on the 86-case suite on 23 November 2026: the built-in adapters, Presidio and LLM Guard 0.3.16 by the `Third-party guardrails` workflow, Prompt Guard 2 (86M and 22M) and both LlamaFirewall adapters by the `Prompt Guard 2` workflow.
- README per-language table gains a French column. LLM Guard blocks five of six French attacks and three of four French benign cases. Prompt Guard 2 86M and 22M, `llamafirewall-static` and LlamaFirewall with PromptGuard block no French attack and no French benign case.
- Cases can carry a conversation in place of `text`: `turns`, a list of two or more turns, each with a `field` and a `text`. The loader validates the row and renders the conversation as one line per turn. The runner checks the turns in order through the new `Adapter.check_conversation`, which receives the turns so far and by default checks the newest turn alone, so existing adapters run unchanged. It stops at the first block and records the turn. The Markdown report adds a "Multi-turn" table and the JSON report carries `first_block_turn`. The built-in suite has no multi-turn case yet and no measured figure changes (refs #2).
- Suite grows to 96 cases: six Chinese attacks (direct injection D11, system prompt extraction S7, jailbreak J8, indirect injection I13, exfiltration E14 and E15) and four Chinese benign look-alikes (B29 to B32), in simplified characters and all tagged `zh` (refs #3).
- CI block rate gate set to the measured baseline of 62%. `layered-guard` blocks 40 of 64 attacks on the larger suite, against 38 of 58 before; it misses four of the six Chinese attacks.
- Tests check that every `zh` case contains Han characters and that no case in another language does, apart from a future `ja`.
- All published results re-measured on the 96-case suite on 27 November 2026: the built-in adapters, Presidio and LLM Guard 0.3.16 by the `Third-party guardrails` workflow, Prompt Guard 2 (86M and 22M) and both LlamaFirewall adapters by the `Prompt Guard 2` workflow. The raw Prompt Guard 2 jobs now run under transformers 5.24.1 and huggingface_hub 2.5.0.
- README per-language table gains a Chinese column. LLM Guard blocks all six Chinese attacks and two of four Chinese benign cases. Prompt Guard 2 86M blocks three of six Chinese attacks at both thresholds and no Chinese benign case. Prompt Guard 2 22M and LlamaFirewall with PromptGuard block one of six, the jailbreak J8. `llamafirewall-static` blocks none.
- README records that the raw Prompt Guard 2 model now decides twelve cases differently under transformers 4.57.6 than under 5.24.1; the Chinese cases S7 and I13 are the two new ones.
- Suite grows to 106 cases: six Arabic attacks (direct injection D12, system prompt extraction S8, jailbreak J9, indirect injection I14, exfiltration E16 and E17) and four Arabic benign look-alikes (B33 to B36), in Modern Standard Arabic and all tagged `ar` (refs #3).
- CI block rate gate set to the measured baseline of 60%. `layered-guard` blocks 42 of 70 attacks on the larger suite, against 40 of 64 before; it misses four of the six Arabic attacks.
- Tests check that every `ar` case contains Arabic script and that no case in another language does.
- All published results re-measured on the 106-case suite on 28 November 2026: the built-in adapters, Presidio and LLM Guard 0.3.16 by the `Third-party guardrails` workflow, Prompt Guard 2 (86M and 22M) and both LlamaFirewall adapters by the `Prompt Guard 2` workflow.
- README per-language table gains an Arabic column. LLM Guard blocks four of six Arabic attacks and one of four Arabic benign cases. Prompt Guard 2 86M blocks three of six Arabic attacks at threshold 0.5 and two at 0.9, and no Arabic benign case. LlamaFirewall with PromptGuard blocks one of six, the indirect injection I14. Prompt Guard 2 22M and `llamafirewall-static` block none.
- README records that the raw Prompt Guard 2 model now decides fifteen cases differently under transformers 4.57.6 than under 5.24.1; the Arabic cases D12, S8 and I14 are the three new ones.

## 0.1.0

First release.

- Adapter interface with six adapters: pattern baseline, layered reference guard, Microsoft Presidio, LLM Guard, Amazon Bedrock Guardrails, generic HTTP guardrail.
- Built-in suite of 41 cases (31 attacks, 10 benign) tagged with MITRE ATLAS v5.6.0 technique IDs.
- `guardbench run` with Markdown and JSON reports and CI gates (`--fail-under`, `--max-fpr`).
- Hash-chained evidence log with `guardbench verify-log`.
- Worked example of indirect prompt injection against a RAG agent.
- Threat model of a runtime guardrail API.
