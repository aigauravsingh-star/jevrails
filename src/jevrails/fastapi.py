from __future__ import annotations

from collections.abc import Callable

from .guard import Guard


class JevRailsMiddleware:
    def __init__(
        self,
        app: Callable,
        *,
        guard: Guard,
        max_body_bytes: int = 1_000_000,
        block_status_code: int = 403,
    ):
        self.app = app
        self.guard = guard
        self.max_body_bytes = max_body_bytes
        self.block_status_code = block_status_code

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        body = b""
        more_body = True
        events = []
        body_too_large = False
        while more_body:
            event = await receive()
            events.append(event)
            body += event.get("body", b"")
            more_body = event.get("more_body", False)
            if len(body) > self.max_body_bytes:
                body_too_large = True
                break

        if body_too_large:
            await _send_json_error(send, status=413, error="request_body_too_large")
            return

        text = body.decode("utf-8", errors="replace")
        result = self.guard.scan(text, metadata={"path": scope.get("path"), "method": scope.get("method")})
        if not result.allowed:
            await _send_json_error(send, status=self.block_status_code, error="blocked_by_jevrails")
            return

        if result.redacted_text is not None:
            body = result.redacted_text.encode("utf-8")
            events = [{"type": "http.request", "body": body, "more_body": False}]
            scope = _with_content_length(scope, len(body))

        replay = _ReplayReceive(events)
        await self.app(scope, replay, send)


class _ReplayReceive:
    def __init__(self, events: list[dict]):
        self.events = list(events)

    async def __call__(self) -> dict:
        if self.events:
            return self.events.pop(0)
        return {"type": "http.request", "body": b"", "more_body": False}


async def _send_json_error(send: Callable, *, status: int, error: str) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"application/json")],
        }
    )
    payload = f'{{"error":"{error}"}}'.encode("utf-8")
    await send({"type": "http.response.body", "body": payload})


def _with_content_length(scope: dict, length: int) -> dict:
    headers = [
        (name, value)
        for name, value in scope.get("headers", [])
        if name.lower() != b"content-length"
    ]
    headers.append((b"content-length", str(length).encode("ascii")))
    updated = dict(scope)
    updated["headers"] = headers
    return updated
