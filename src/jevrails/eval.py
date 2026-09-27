from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from .guard import Guard


@dataclass(frozen=True)
class JsonlCase:
    id: str
    text: str
    label: bool


@dataclass(frozen=True)
class EvalRow:
    id: str
    label: bool
    predicted: bool
    score: float
    allowed: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "predicted": self.predicted,
            "score": self.score,
            "allowed": self.allowed,
        }


@dataclass(frozen=True)
class EvalReport:
    check_id: str
    precision: float
    recall: float
    f1: float
    true_positive: int
    false_positive: int
    true_negative: int
    false_negative: int
    rows: tuple[EvalRow, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "true_positive": self.true_positive,
            "false_positive": self.false_positive,
            "true_negative": self.true_negative,
            "false_negative": self.false_negative,
            "rows": [row.to_dict() for row in self.rows],
        }


def evaluate_cases(cases: Iterable[JsonlCase], guard: Guard, *, check_id: str) -> EvalReport:
    rows: list[EvalRow] = []
    tp = fp = tn = fn = 0
    for case in cases:
        result = guard.scan(case.text, metadata={"case_id": case.id})
        finding = next((item for item in result.findings if item.check_id == check_id), None)
        predicted = bool(finding and finding.triggered)
        score = float(finding.score or 0.0) if finding else 0.0

        if predicted and case.label:
            tp += 1
        elif predicted and not case.label:
            fp += 1
        elif not predicted and not case.label:
            tn += 1
        else:
            fn += 1

        rows.append(EvalRow(id=case.id, label=case.label, predicted=predicted, score=score, allowed=result.allowed))

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return EvalReport(
        check_id=check_id,
        precision=precision,
        recall=recall,
        f1=f1,
        true_positive=tp,
        false_positive=fp,
        true_negative=tn,
        false_negative=fn,
        rows=tuple(rows),
    )
