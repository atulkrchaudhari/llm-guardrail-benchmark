# Threat model: a runtime guardrail API for LLM and agentic applications

Technique and mitigation IDs are from MITRE ATLAS v5.6.0. Function names are from the NIST AI Risk Management Framework (Govern, Map, Measure, Manage).

Status: working draft. Every row in the tables below must be checked against the deployed system before it is quoted to a customer or an auditor.

## 1. System in scope

A guardrail service sits between an application and its model or agent. The application sends each prompt, each piece of retrieved context, each model response and each proposed tool call to the service. The service returns allow, redact or block. A blocked tool call never runs (fail closed). Every decision is written to an evidence log.

Each evidence record carries
- the principal (the human or service the agent acts for), the agent, and the parent agent if one delegated the task
- the scope the agent requested and the scope it was granted
- the policy version and the decision
- a SHA-256 hash of the previous record, so the log is a chain

## 2. Assets

| Asset | Why it matters |
|---|---|
| System prompts and policy rules | Leaking them tells an attacker what to route around |
| Retrieved context and vector store | Untrusted data that the model reads as if it were instructions |
| Tool credentials and granted scopes | A hijacked agent acts with whatever the tool is allowed to do |
| User data in prompts and responses | Personal data and secrets, regulated under GDPR and similar law |
| The evidence log | It is the proof. If it can be edited, it proves nothing |
| The guardrail service itself | If it is down or slow, the application must not fall open |

## 3. Trust boundaries

1. User to application. Direct input is untrusted.
2. External content to retrieval. Documents, web pages, emails and tool outputs are untrusted, even when they come from a "trusted" store.
3. Model to tool. Model output is untrusted. A tool call is a request, not a command.
4. Agent to agent. A child agent inherits no more scope than its parent granted.
5. Guardrail to evidence store. Writes are append only.

## 4. Threats and controls

| # | ATLAS technique | What the attacker does | Control | ATLAS mitigation | Evidence written | Residual risk |
|---|---|---|---|---|---|---|
| 1 | AML.T0051.000 LLM Prompt Injection, Direct | Types instructions that override the system prompt | Input scan before the model call | AML.M0015 Adversarial Input Detection, AML.M0020 Generative AI Guardrails | Decision, matched policy, input hash | Novel phrasing passes pattern checks |
| 2 | AML.T0051.001 LLM Prompt Injection, Indirect | Plants instructions in a document, page or tool output the agent will read | Scan retrieved context as untrusted data, separately from user input | AML.M0030 Restrict AI Agent Tool Invocation on Untrusted Data, AML.M0033 Input and Output Validation for AI Agent Components | Source of the context, decision | Instructions split across several chunks |
| 3 | AML.T0054 LLM Jailbreak | Role play or persona framing to switch off safety behaviour | Input scan plus output scan | AML.M0020 | Both decisions, linked by request ID | Multi-turn jailbreaks that look benign per turn |
| 4 | AML.T0068 LLM Prompt Obfuscation | Encodes the payload (base64, homoglyphs, zero-width characters) | Normalise and decode before scanning | AML.M0010 Input Restoration, AML.M0015 | Normalisation steps applied | Encodings the normaliser does not know |
| 5 | AML.T0056 Extract LLM System Prompt | Asks the model to repeat its instructions | Output scan for system prompt fragments | AML.M0020 | Output decision | Paraphrased leaks |
| 6 | AML.T0057 LLM Data Leakage | Gets personal data or secrets into a response | Output scan with PII and secret detection, then redact | AML.M0020, AML.M0002 Passive AI Output Obfuscation | Entity types found, redaction applied | Entity types outside the detector's list |
| 7 | AML.T0053 AI Agent Tool Invocation | Steers the agent into calling a tool the task did not need | Compare requested scope with granted scope, block the delta | AML.M0028 AI Agent Tools Permissions Configuration, AML.M0026 Privileged AI Agent Permissions Configuration | Requested scope, granted scope, delta | Over-broad grants set by the developer |
| 8 | AML.T0086 Exfiltration via AI Agent Tool Invocation | Uses a permitted tool (fetch, email, image URL) to send data out | Destination allowlist on tool arguments, human approval for new destinations | AML.M0029 Human In-the-Loop for AI Agent Actions, AML.M0030 | Tool name, destination, approver | Exfiltration through an allowlisted destination |
| 9 | AML.T0070 RAG Poisoning | Inserts a malicious entry into the knowledge base | Scan at ingestion and again at retrieval | AML.M0033 | Document ID, ingestion decision | Poison that is only harmful in combination |
| 10 | AML.T0080.000 AI Agent Context Poisoning, Memory | Writes an instruction into long-term agent memory | Scan memory writes as untrusted | AML.M0033 | Memory write decision | Slow drift across many small writes |
| 11 | AML.T0110 AI Agent Tool Poisoning | Hides instructions in a tool's description or schema | Pin and hash tool definitions, alert on change | AML.M0028 | Tool definition hash | First use of an already poisoned tool |
| 12 | AML.T0029 Denial of AI Service | Floods or stalls the guardrail so the application skips it | Fail closed on timeout or error | AML.M0004 Restrict Number of AI Model Queries | Timeout recorded as a block | Availability loss is accepted in exchange |
| 13 | AML.T0034 Cost Harvesting | Drives token or tool spend | Per-principal rate and budget limits | AML.M0004 | Counters per principal | Abuse spread across many principals |
| 14 | AML.T0055 Unsecured Credentials | Reads API keys from prompts, logs or config | Secret detection on input and output, no secrets in evidence records | AML.M0005 Control Access to AI Models and Data at Rest | Detector hit, value never stored | Custom secret formats |
| 15 | (not in ATLAS) Evidence tampering | Edits or deletes log entries after an incident | Hash chain, append-only store, periodic external anchor of the chain head | AML.M0024 AI Telemetry Logging | The chain itself | Whoever controls the store before the first anchor |

## 5. What the guardrail does not cover

- Model and training data supply chain (AML.T0010, AML.T0020). These belong to model selection and vendor review.
- Model extraction through the inference API (AML.T0024.002). Rate limits help. A guardrail cannot see it in a single request.
- Anything the application does without calling the guardrail. Coverage is only as good as the integration.

## 6. NIST AI RMF mapping

| Function | How the system supports it |
|---|---|
| Govern | Policies are versioned. Each decision records the policy version in force. |
| Map | Sections 1 to 3 of this document: context, assets, boundaries. |
| Measure | `guardbench run` gives a block rate per attack category and a false positive rate on benign traffic. Run it on every policy change. |
| Manage | Fail-closed blocking, human approval for new destinations, and the evidence chain for incident reconstruction. |

## 7. EU AI Act link

- Article 12 (record-keeping for high-risk systems): the evidence chain is the automatic log of events.
- Article 50 (transparency): a per-interaction record can show that a disclosure or a marking was applied to a specific output.

The mapping is a design intent. Whether a given deployment meets either article depends on the system's risk class and on what is actually logged.
