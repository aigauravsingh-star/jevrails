from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .exceptions import GuardrailBlocked
from .guard import Guard
from .types import CheckFinding, Span


class GuardedOpenAI:
    """Small proxy for OpenAI-compatible clients.

    It scans chat message content before forwarding calls to `client.chat.completions.create`.
    The wrapped client can be the official OpenAI SDK client or any compatible object.
    """

    def __init__(self, client: Any, guard: Guard):
        self.client = client
        self.guard = guard
        self.chat = _GuardedChat(client.chat, guard)


class _GuardedChat:
    def __init__(self, chat: Any, guard: Guard):
        self.completions = _GuardedCompletions(chat.completions, guard)


class _GuardedCompletions:
    def __init__(self, completions: Any, guard: Guard):
        self._completions = completions
        self._guard = guard

    def create(self, *args: Any, **kwargs: Any) -> Any:
        messages = kwargs.get("messages")
        text = messages_to_text(messages)
        result = self._guard.scan(text, metadata={"integration": "openai.chat.completions"})
        if not result.allowed:
            raise GuardrailBlocked(result)
        if result.redacted_text and isinstance(messages, list):
            kwargs = dict(kwargs)
            kwargs["messages"] = redact_messages(messages, result.findings)
        return self._completions.create(*args, **kwargs)


def messages_to_text(messages: Any) -> str:
    text, _ = _message_segments(messages)
    return text


def redact_messages(messages: list[dict[str, Any]], findings: tuple[CheckFinding, ...]) -> list[dict[str, Any]]:
    _, segments = _message_segments(messages)
    spans = [
        span
        for finding in findings
        if finding.triggered and not finding.shadow and finding.action == "redact"
        for span in finding.spans
    ]
    if not spans:
        return messages

    redacted = [dict(message) for message in messages]
    for segment in segments:
        content = redacted[segment.message_index].get("content")
        if not isinstance(content, str):
            if isinstance(content, list):
                redacted[segment.message_index]["content"] = [
                    dict(item) if isinstance(item, dict) else item for item in content
                ]
                _redact_content_part(redacted, segment, spans)
            continue
        local_spans = _overlapping_spans(spans, segment.start, segment.end)
        if local_spans:
            redacted[segment.message_index]["content"] = _apply_local_spans(
                content,
                local_spans,
                segment.start,
            )
    return redacted


@dataclass(frozen=True)
class _TextSegment:
    message_index: int
    start: int
    end: int
    item_index: int | None = None


def _message_segments(messages: Any) -> tuple[str, list[_TextSegment]]:
    if not isinstance(messages, list):
        return "", []

    parts: list[str] = []
    segments: list[_TextSegment] = []
    cursor = 0
    for index, message in enumerate(messages):
        if not isinstance(message, dict):
            continue
        if parts:
            parts.append("\n")
            cursor += 1
        role = message.get("role", "unknown")
        prefix = f"{role}: "
        parts.append(prefix)
        cursor += len(prefix)
        content = message.get("content", "")
        if isinstance(content, str):
            start = cursor
            parts.append(content)
            cursor += len(content)
            segments.append(_TextSegment(index, start, cursor))
        elif isinstance(content, list):
            first_part = True
            for item_index, item in enumerate(content):
                if not isinstance(item, dict) or item.get("type") not in {None, "text", "input_text"}:
                    continue
                text = item.get("text", "")
                if not isinstance(text, str):
                    continue
                if not first_part:
                    parts.append(" ")
                    cursor += 1
                first_part = False
                start = cursor
                parts.append(text)
                cursor += len(text)
                segments.append(_TextSegment(index, start, cursor, item_index=item_index))
    return "".join(parts), segments


def _redact_content_part(
    redacted: list[dict[str, Any]],
    segment: _TextSegment,
    spans: list[Span],
) -> None:
    if segment.item_index is None:
        return
    content = redacted[segment.message_index].get("content")
    if not isinstance(content, list):
        return
    item = content[segment.item_index]
    if not isinstance(item, dict) or not isinstance(item.get("text"), str):
        return

    local_spans = _overlapping_spans(spans, segment.start, segment.end)
    if local_spans:
        item["text"] = _apply_local_spans(item["text"], local_spans, segment.start)


def _overlapping_spans(spans: list[Span], start: int, end: int) -> list[Span]:
    return [span for span in spans if span.start < end and span.end > start]


def _apply_local_spans(content: str, spans: list[Span], offset: int) -> str:
    local = sorted(
        (max(0, span.start - offset), min(len(content), span.end - offset))
        for span in spans
    )
    parts: list[str] = []
    cursor = 0
    for start, end in local:
        if start < cursor:
            continue
        parts.append(content[cursor:start])
        parts.append("[REDACTED]")
        cursor = end
    parts.append(content[cursor:])
    return "".join(parts)
