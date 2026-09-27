from __future__ import annotations

from typing import Any

from .base import DecisionBackend
from ..types import DecisionQuestion, DecisionResult


class FakeDecisionBackend(DecisionBackend):
    def __init__(self, scores: dict[str, float] | None = None):
        self.scores = scores or {}

    def decide(
        self,
        text: str,
        questions: list[DecisionQuestion],
        metadata: dict[str, Any] | None = None,
    ) -> list[DecisionResult]:
        return [
            DecisionResult(check_id=question.id, probability=float(self.scores.get(question.id, 0.0)), raw=None)
            for question in questions
        ]
