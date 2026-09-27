from __future__ import annotations

from .guard import Guard


class LLMGuardCompatibleScanner:
    """Adapter with the common LLM Guard scanner return shape.

    Returns `(sanitized_text, is_valid, risk_score)`.
    """

    def __init__(self, guard: Guard):
        self.guard = guard

    def scan(self, prompt: str) -> tuple[str, bool, float]:
        result = self.guard.scan(prompt)
        risk_score = max((finding.score or 0.0 for finding in result.triggered), default=0.0)
        return result.redacted_text or prompt, result.allowed, risk_score
