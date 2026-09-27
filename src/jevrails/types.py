from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass(frozen=True)
class Span:
    start: int
    end: int
    label: str
    text: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "start": self.start,
            "end": self.end,
            "label": self.label,
            "text": self.text,
        }


@dataclass(frozen=True)
class DecisionQuestion:
    id: str
    instructions: str
    kind: str = "bool"
    criteria: dict[str, str] = field(default_factory=dict)

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "type": self.kind,
            "instructions": self.instructions,
        }
        if self.criteria:
            payload["criteria"] = self.criteria
        return payload


@dataclass(frozen=True)
class DecisionResult:
    check_id: str
    probability: float
    raw: Any = None


@dataclass(frozen=True)
class CheckFinding:
    check_id: str
    triggered: bool
    score: float | None
    threshold: float | None
    severity: Severity
    action: str
    message: str
    source: str
    spans: tuple[Span, ...] = ()
    shadow: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "triggered": self.triggered,
            "score": self.score,
            "threshold": self.threshold,
            "severity": self.severity.value,
            "action": self.action,
            "message": self.message,
            "source": self.source,
            "spans": [span.to_dict() for span in self.spans],
            "shadow": self.shadow,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class ScanResult:
    allowed: bool
    findings: tuple[CheckFinding, ...]
    redacted_text: str | None = None
    backend_error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def triggered(self) -> tuple[CheckFinding, ...]:
        return tuple(finding for finding in self.findings if finding.triggered)

    @property
    def max_severity(self) -> Severity:
        triggered = self.triggered
        if not triggered:
            return Severity.INFO
        return max(triggered, key=lambda item: SEVERITY_RANK[item.severity]).severity

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "max_severity": self.max_severity.value,
            "backend_error": self.backend_error,
            "redacted_text": self.redacted_text,
            "findings": [finding.to_dict() for finding in self.findings],
            "metadata": self.metadata,
        }
