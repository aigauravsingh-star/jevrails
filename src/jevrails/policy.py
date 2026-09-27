from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from typing import Any

from .types import Severity


class Action(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    WARN = "warn"
    REDACT = "redact"
    ESCALATE = "escalate"


@dataclass(frozen=True)
class CheckConfig:
    enabled: bool = True
    threshold: float = 0.75
    action: Action = Action.BLOCK
    severity: Severity = Severity.MEDIUM
    shadow: bool = False
    params: dict[str, Any] | None = None


@dataclass(frozen=True)
class Policy:
    checks: dict[str, CheckConfig]
    fail_closed: bool = True
    redact_replacement: str = "[REDACTED]"
    max_approx_tokens: int | None = None

    @classmethod
    def default(cls) -> "Policy":
        return cls(
            checks={
                "prompt_injection": CheckConfig(threshold=0.70, action=Action.BLOCK, severity=Severity.HIGH),
                "jailbreak": CheckConfig(threshold=0.75, action=Action.BLOCK, severity=Severity.HIGH),
                "toxicity": CheckConfig(threshold=0.85, action=Action.WARN, severity=Severity.MEDIUM),
                "hate": CheckConfig(threshold=0.85, action=Action.BLOCK, severity=Severity.HIGH),
                "self_harm": CheckConfig(threshold=0.80, action=Action.ESCALATE, severity=Severity.HIGH),
                "regulated_advice": CheckConfig(threshold=0.80, action=Action.ESCALATE, severity=Severity.MEDIUM),
                "grounding_risk": CheckConfig(threshold=0.80, action=Action.WARN, severity=Severity.MEDIUM),
                "tool_call_risk": CheckConfig(threshold=0.75, action=Action.BLOCK, severity=Severity.HIGH),
                "competitor_mention": CheckConfig(
                    enabled=False,
                    threshold=0.80,
                    action=Action.WARN,
                    severity=Severity.LOW,
                    shadow=True,
                ),
                "pii": CheckConfig(threshold=1.0, action=Action.REDACT, severity=Severity.MEDIUM),
                "secrets": CheckConfig(threshold=1.0, action=Action.REDACT, severity=Severity.HIGH),
                "local_prompt_injection": CheckConfig(threshold=1.0, action=Action.BLOCK, severity=Severity.HIGH),
                "json_valid": CheckConfig(enabled=False, threshold=1.0, action=Action.BLOCK, severity=Severity.LOW),
                "token_limit": CheckConfig(enabled=False, threshold=1.0, action=Action.BLOCK, severity=Severity.LOW),
            }
        )

    def enabled(self, check_id: str) -> bool:
        config = self.checks.get(check_id)
        return bool(config and config.enabled)

    def get(self, check_id: str) -> CheckConfig | None:
        return self.checks.get(check_id)

    def with_check(self, check_id: str, config: CheckConfig) -> "Policy":
        checks = dict(self.checks)
        checks[check_id] = config
        return replace(self, checks=checks)

    def only(self, check_ids: set[str]) -> "Policy":
        unknown = check_ids - set(self.checks)
        if unknown:
            known = ", ".join(sorted(self.checks))
            requested = ", ".join(sorted(unknown))
            raise ValueError(f"Unknown check(s): {requested}. Known checks: {known}.")
        return replace(
            self,
            checks={
                check_id: config
                for check_id, config in self.checks.items()
                if check_id in check_ids
            },
        )

    def with_fail_closed(self, fail_closed: bool) -> "Policy":
        return replace(self, fail_closed=fail_closed)

    def with_max_approx_tokens(self, max_approx_tokens: int | None) -> "Policy":
        checks = dict(self.checks)
        token_config = checks.get("token_limit", CheckConfig())
        checks["token_limit"] = replace(token_config, enabled=max_approx_tokens is not None)
        return replace(self, checks=checks, max_approx_tokens=max_approx_tokens)
