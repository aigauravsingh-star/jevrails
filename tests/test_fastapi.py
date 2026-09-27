import asyncio

from jevrails import Guard, Policy
from jevrails.backends import FakeDecisionBackend
from jevrails.fastapi import JevRailsMiddleware


async def _app(scope, receive, send):
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


def test_fastapi_middleware_rejects_large_body():
    sent = []
    middleware = JevRailsMiddleware(
        _app,
        guard=Guard(policy=Policy.default(), backend=FakeDecisionBackend()),
        max_body_bytes=3,
    )

    async def receive():
        return {"type": "http.request", "body": b"too large", "more_body": False}

    async def send(event):
        sent.append(event)

    asyncio.run(middleware({"type": "http", "path": "/chat", "method": "POST"}, receive, send))

    assert sent[0]["status"] == 413


def test_fastapi_middleware_replays_redacted_body():
    app_body = []

    async def app(scope, receive, send):
        event = await receive()
        app_body.append(event["body"])
        app_body.append(dict(scope["headers"])[b"content-length"])
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = JevRailsMiddleware(
        app,
        guard=Guard(policy=Policy.default(), backend=FakeDecisionBackend()),
    )

    async def receive():
        return {
            "type": "http.request",
            "body": b"email person@example.com",
            "more_body": False,
        }

    async def send(event):
        pass

    asyncio.run(
        middleware(
            {
                "type": "http",
                "path": "/chat",
                "method": "POST",
                "headers": [(b"content-length", b"24")],
            },
            receive,
            send,
        )
    )

    assert app_body == [b"email [REDACTED]", b"16"]
