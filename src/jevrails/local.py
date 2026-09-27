from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Iterable

from .policy import Action, Policy
from .types import CheckFinding, Severity, Span


@dataclass(frozen=True)
class LocalMatch:
    check_id: str
    label: str
    start: int
    end: int
    severity: Severity
    message: str


SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b")),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("generic_api_key", re.compile(r"(?i)\b(?:api[_-]?key|secret|token)\s*[:=]\s*['\"]?[A-Za-z0-9_.\-]{20,}")),
)

PII_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("email", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("phone", re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b")),
    ("credit_card", re.compile(r"\b(?:\d[ -]*?){13,19}\b")),
)

INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\bignore (?:all )?(?:previous|prior|above) instructions\b"),
    re.compile(r"(?i)\bdisregard (?:all )?(?:previous|prior|above) instructions\b"),
    re.compile(r"(?i)\breveal (?:the )?(?:system|developer) prompt\b"),
    re.compile(r"(?i)\bprint (?:the )?(?:system|developer) (?:prompt|instructions)\b"),
    re.compile(r"(?i)\byou are now (?:in )?(?:developer|admin|root|sudo) mode\b"),
)


def run_local_checks(text: str, policy: Policy) -> list[CheckFinding]:
    findings: list[CheckFinding] = []

    if policy.enabled("secrets"):
        findings.extend(_pattern_findings(text, policy, "secrets", SECRET_PATTERNS))

    if policy.enabled("pii"):
        findings.extend(_pattern_findings(text, policy, "pii", PII_PATTERNS, validate_luhn=True))

    if policy.enabled("local_prompt_injection"):
        findings.extend(_local_injection_findings(text, policy))

    if policy.enabled("json_valid"):
        findings.append(_json_valid_finding(text, policy))

    if policy.enabled("token_limit") or policy.max_approx_tokens is not None:
        findings.append(_token_limit_finding(text, policy))

    return findings


def redact_text(text: str, findings: Iterable[CheckFinding], replacement: str) -> str:
    spans: list[Span] = []
    for finding in findings:
        if finding.triggered and finding.action == Action.REDACT.value and not finding.shadow:
            spans.extend(finding.spans)
    if not spans:
        return text

    merged = _merge_spans(sorted(spans, key=lambda span: (span.start, span.end)))
    parts: list[str] = []
    cursor = 0
    for span in merged:
        parts.append(text[cursor : span.start])
        parts.append(replacement)
        cursor = span.end
    parts.append(text[cursor:])
    return "".join(parts)


def _pattern_findings(
    text: str,
    policy: Policy,
    check_id: str,
    patterns: tuple[tuple[str, re.Pattern[str]], ...],
    *,
    validate_luhn: bool = False,
) -> list[CheckFinding]:
    config = policy.get(check_id)
    if config is None:
        return []

    spans: list[Span] = []
    labels: set[str] = set()
    for label, pattern in patterns:
        for match in pattern.finditer(text):
            value = match.group(0)
            if validate_luhn and label == "credit_card" and not _looks_like_card(value):
                continue
            labels.add(label)
            spans.append(Span(match.start(), match.end(), label=label, text=value))

    if not spans:
        return []

    return [
        CheckFinding(
            check_id=check_id,
            triggered=True,
            score=1.0,
            threshold=config.threshold,
            severity=config.severity,
            action=config.action.value,
            message=f"Detected {check_id}: {', '.join(sorted(labels))}",
            source="local",
            spans=tuple(spans),
            shadow=config.shadow,
        )
    ]


def _local_injection_findings(text: str, policy: Policy) -> list[CheckFinding]:
    config = policy.get("local_prompt_injection")
    if config is None:
        return []

    spans: list[Span] = []
    for pattern in INJECTION_PATTERNS:
        for match in pattern.finditer(text):
            spans.append(Span(match.start(), match.end(), label="prompt_injection_phrase", text=match.group(0)))

    if not spans:
        return []

    return [
        CheckFinding(
            check_id="local_prompt_injection",
            triggered=True,
            score=1.0,
            threshold=config.threshold,
            severity=config.severity,
            action=config.action.value,
            message="Detected prompt-injection language with local heuristics.",
            source="local",
            spans=tuple(spans),
            shadow=config.shadow,
        )
    ]


def _json_valid_finding(text: str, policy: Policy) -> CheckFinding:
    config = policy.get("json_valid")
    assert config is not None
    try:
        json.loads(text)
        triggered = False
        message = "Valid JSON."
    except json.JSONDecodeError as exc:
        triggered = True
        message = f"Invalid JSON: {exc.msg}."

    return CheckFinding(
        check_id="json_valid",
        triggered=triggered,
        score=1.0 if triggered else 0.0,
        threshold=config.threshold,
        severity=config.severity,
        action=config.action.value,
        message=message,
        source="local",
        shadow=config.shadow,
    )


def _token_limit_finding(text: str, policy: Policy) -> CheckFinding:
    config = policy.get("token_limit")
    threshold = policy.max_approx_tokens
    if config and config.params and config.params.get("max_approx_tokens"):
        threshold = int(config.params["max_approx_tokens"])
    if threshold is None:
        threshold = 0
    approx_tokens = max(1, len(text) // 4) if text else 0
    triggered = threshold > 0 and approx_tokens > threshold

    return CheckFinding(
        check_id="token_limit",
        triggered=triggered,
        score=float(approx_tokens),
        threshold=float(threshold),
        severity=config.severity if config else Severity.LOW,
        action=(config.action.value if config else Action.BLOCK.value),
        message=f"Approximate token count is {approx_tokens}; limit is {threshold}.",
        source="local",
        shadow=config.shadow if config else False,
    )


def _merge_spans(spans: list[Span]) -> list[Span]:
    if not spans:
        return []
    merged = [spans[0]]
    for span in spans[1:]:
        previous = merged[-1]
        if span.start <= previous.end:
            merged[-1] = Span(previous.start, max(previous.end, span.end), previous.label)
        else:
            merged.append(span)
    return merged


def _looks_like_card(value: str) -> bool:
    digits = [int(char) for char in value if char.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False

    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0
