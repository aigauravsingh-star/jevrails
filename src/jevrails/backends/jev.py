from __future__ import annotations

import json
import os
from typing import Any
from urllib import error, request

from .base import DecisionBackend
from ..types import DecisionQuestion, DecisionResult


class JevBackend(DecisionBackend):
    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = "https://api.typesafe.ai",
        endpoint: str = "/v1/systemone",
        model: str = "jev-1.13.0",
        timeout: float = 5.0,
    ):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.endpoint = endpoint if endpoint.startswith("/") else f"/{endpoint}"
        self.model = model
        self.timeout = timeout

    @classmethod
    def from_env(cls) -> "JevBackend":
        api_key = os.environ.get("JEV_API_KEY")
        if not api_key:
            raise RuntimeError("JEV_API_KEY is required for JevBackend.from_env()")
        return cls(
            api_key=api_key,
            base_url=os.environ.get("JEV_BASE_URL", "https://api.typesafe.ai"),
            endpoint=os.environ.get("JEV_ENDPOINT", "/v1/systemone"),
            model=os.environ.get("JEV_MODEL", "jev-1.13.0"),
        )

    def decide(
        self,
        text: str,
        questions: list[DecisionQuestion],
        metadata: dict[str, Any] | None = None,
    ) -> list[DecisionResult]:
        if not questions:
            return []

        payload = {
            "model": self.model,
            "state": {"text": text, "metadata": metadata or {}},
            "questions": {question.id: question.to_payload() for question in questions},
        }
        body = json.dumps(payload).encode("utf-8")
        req = request.Request(
            f"{self.base_url}{self.endpoint}",
            data=body,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "jevrails/0.1.0",
            },
            method="POST",
        )

        try:
            with request.urlopen(req, timeout=self.timeout) as response:
                data = json.loads(response.read().decode("utf-8"))
        except error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Jev backend HTTP {exc.code}: {detail}") from exc
        except error.URLError as exc:
            raise RuntimeError(f"Jev backend request failed: {exc.reason}") from exc

        return self._parse_results(data, questions)

    def _parse_results(self, data: Any, questions: list[DecisionQuestion]) -> list[DecisionResult]:
        answers = self._answers_from(data)
        results: list[DecisionResult] = []
        for question in questions:
            raw = answers.get(question.id) if isinstance(answers, dict) else None
            probability = self._probability_from(raw)
            results.append(DecisionResult(check_id=question.id, probability=probability, raw=raw))
        return results

    def _answers_from(self, data: Any) -> Any:
        if not isinstance(data, dict):
            return {}
        if "answers" in data:
            return data["answers"]
        result = data.get("result")
        if isinstance(result, dict) and "answers" in result:
            return result["answers"]
        if "decisions" in data:
            return data["decisions"]
        return data

    def _probability_from(self, raw: Any) -> float:
        if raw is None:
            return 0.0
        if isinstance(raw, bool):
            return 1.0 if raw else 0.0
        if isinstance(raw, (int, float)):
            return self._clamp(float(raw))
        if isinstance(raw, dict):
            for key in ("probability", "score", "confidence", "value"):
                value = raw.get(key)
                if isinstance(value, (int, float)):
                    return self._clamp(float(value))
            if isinstance(raw.get("answer"), bool):
                return 1.0 if raw["answer"] else 0.0
        return 0.0

    def _clamp(self, value: float) -> float:
        return max(0.0, min(1.0, value))
