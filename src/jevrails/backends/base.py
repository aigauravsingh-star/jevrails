from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from ..types import DecisionQuestion, DecisionResult


class DecisionBackend(ABC):
    @abstractmethod
    def decide(
        self,
        text: str,
        questions: list[DecisionQuestion],
        metadata: dict[str, Any] | None = None,
    ) -> list[DecisionResult]:
        raise NotImplementedError


class NullDecisionBackend(DecisionBackend):
    def decide(
        self,
        text: str,
        questions: list[DecisionQuestion],
        metadata: dict[str, Any] | None = None,
    ) -> list[DecisionResult]:
        return [DecisionResult(check_id=question.id, probability=0.0, raw=None) for question in questions]
