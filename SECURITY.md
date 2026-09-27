# Security Policy

JevRails is alpha software. Do not rely on it as the only security boundary for production systems.

## Reporting a Vulnerability

Please report vulnerabilities privately before opening a public issue. Include:

- A minimal reproduction.
- Expected and actual behavior.
- Impact and affected version.

## Security Model

JevRails uses a hybrid model:

- Local deterministic checks handle exact matches, spans, validation, and redaction.
- Decision backends provide semantic probabilities for ambiguous checks.
- Policies decide whether findings allow, warn, redact, block, escalate, or run in shadow mode.

Recommended production defaults:

- Run new checks in shadow mode first.
- Calibrate thresholds on your own traffic.
- Keep fail-closed behavior for high-risk paths.
- Keep local PII, secrets, schema, and token-limit checks enabled.
