# Security policy

## Scope

guardbench is a testing tool. Its suite contains standard prompt injection and exfiltration test strings. All domains are reserved `example` domains and every credential in the suite is fake.

Run it only against guardrails and AI systems you own or are authorised to test.

## Reporting a vulnerability

If you find a security problem in guardbench itself, for example a way for a crafted suite file to execute code, please report it privately through GitHub's "Report a vulnerability" button on the Security tab. Please do not open a public issue for it.

You can expect an acknowledgement within 5 working days.

## Reporting a bypass

A prompt that gets past the reference `layered-guard` is not a vulnerability. It is a missing test case, and it is welcome. Open an issue or a pull request that adds the case to `src/guardbench/suite.jsonl`.
