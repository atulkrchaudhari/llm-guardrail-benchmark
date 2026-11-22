# Contributing

Contributions are welcome. The most useful ones are new test cases and new adapters.

## Set up

```
pip install -e ".[dev,examples]"
ruff check .
pytest
```

## Add a test case

Append one line to `src/guardbench/suite.jsonl`.

```json
{"id": "I6", "category": "indirect_injection", "atlas": "AML.T0051.001", "field": "context", "block": true, "text": "..."}
```

Rules

- `id` is unique. Use the category letter and the next free number.
- `atlas` is the MITRE ATLAS technique ID for attacks. Leave it empty for benign cases.
- `field` is `input`, `context` or `output`.
- A tool-call case has `tool_call` in place of `text`, with `name`, `arguments`, `granted` and an optional `scope`, and its `field` is `output`. The README describes the keys.
- `lang` is the language tag of the text, such as `hi` or `pt-BR`. Leave it out for English.
- A case in a language other than English is written in natural phrasing, not translated word for word, and each language has benign look-alikes of its own.
- Use reserved domains (`example.com`, `attacker.example`) and fake credentials only. Never paste a real secret, a real person's data, or a payload aimed at a real system.
- Do not tune `layered-guard` to pass a new case unless the change is a general rule. A case that the reference guard misses is a finding, and the README reports misses.
- Add benign look-alikes too. A suite with no hard benign cases rewards over-blocking.

## Add an adapter

Subclass `Adapter` in `src/guardbench/adapters.py`, set `name`, implement `check`, and return a reason from `setup` when the adapter cannot run. Add it to `REGISTRY` and add a test. Third-party imports go inside `setup` so the core install stays dependency free.

## Pull requests

- One change per pull request.
- `ruff check .` and `pytest` pass.
- If the results table in the README changes, update it in the same pull request.
