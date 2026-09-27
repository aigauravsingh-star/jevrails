from __future__ import annotations

from typing import Any

from .backends import DecisionBackend, NullDecisionBackend
from .catalog import questions_for
from .local import redact_text, run_local_checks
from .policy import Action, Policy
from .types import CheckFinding, ScanResult, Severity


class Guard:
    def __init__(self, policy: Policy | None = None, backend: DecisionBackend | None = None):
        self.policy = policy or Policy.default()
        self.backend = backend or NullDecisionBackend()

    def scan(self, text: str, *, metadata: dict[str, Any] | None = None) -> ScanResult:
        findings: list[CheckFinding] = []
        findings.extend(run_local_checks(text, self.policy))

        backend_error: str | None = None
        semantic_check_ids = [
            check_id for check_id in self.policy.checks if self.policy.enabled(check_id)
        ]
        questions = questions_for(semantic_check_ids)

        if questions:
            try:
                decisions = self.backend.decide(text, questions, metadata=metadata)
                findings.extend(self._findings_from_decisions(decisions))
            except Exception as exc:
                backend_error = str(exc)
                if self.policy.fail_closed:
                    findings.append(
                        CheckFinding(
                            check_id="backend_error",
                            triggered=True,
                            score=None,
                            threshold=None,
                            severity=Severity.HIGH,
                            action=Action.BLOCK.value,
                            message=f"Decision backend failed: {exc}",
                            source="backend",
                            shadow=False,
                        )
                    )

        redacted = redact_text(text, findings, self.policy.redact_replacement)
        allowed = self._is_allowed(findings)
        return ScanResult(
            allowed=allowed,
            findings=tuple(findings),
            redacted_text=redacted if redacted != text else None,
            backend_error=backend_error,
            metadata=metadata or {},
        )

    def _findings_from_decisions(self, decisions: list[Any]) -> list[CheckFinding]:
        findings: list[CheckFinding] = []
        for decision in decisions:
            config = self.policy.get(decision.check_id)
            if config is None or not config.enabled:
                continue
            triggered = decision.probability >= config.threshold
            findings.append(
                CheckFinding(
                    check_id=decision.check_id,
                    triggered=triggered,
                    score=decision.probability,
                    threshold=config.threshold,
                    severity=config.severity,
                    action=config.action.value,
                    message=(
                        f"{decision.check_id} probability {decision.probability:.3f} "
                        f"{'met' if triggered else 'below'} threshold {config.threshold:.3f}."
                    ),
                    source="decision",
                    shadow=config.shadow,
                    metadata={"raw": decision.raw} if decision.raw is not None else {},
                )
            )
        return findings

    def _is_allowed(self, findings: list[CheckFinding]) -> bool:
        for finding in findings:
            if not finding.triggered or finding.shadow:
                continue
            if finding.action in {Action.BLOCK.value, Action.ESCALATE.value}:
                return False
        return True
