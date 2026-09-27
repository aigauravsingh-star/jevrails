from jevrails import Guard, GuardedOpenAI, GuardrailBlocked, LLMGuardCompatibleScanner, Policy
from jevrails.backends import FakeDecisionBackend


class _Completions:
    def __init__(self):
        self.kwargs = None

    def create(self, **kwargs):
        self.kwargs = kwargs
        return {"ok": True}


class _Client:
    def __init__(self):
        self.chat = type("Chat", (), {"completions": _Completions()})()


def test_openai_wrapper_blocks_unsafe_messages():
    client = _Client()
    wrapped = GuardedOpenAI(
        client,
        Guard(policy=Policy.default(), backend=FakeDecisionBackend({"prompt_injection": 0.95})),
    )

    try:
        wrapped.chat.completions.create(messages=[{"role": "user", "content": "hello"}])
    except GuardrailBlocked as exc:
        assert exc.result.allowed is False
    else:
        raise AssertionError("expected GuardrailBlocked")


def test_llm_guard_compatible_scanner_shape():
    scanner = LLMGuardCompatibleScanner(Guard(policy=Policy.default(), backend=FakeDecisionBackend()))

    sanitized, is_valid, risk = scanner.scan("email me at person@example.com")

    assert sanitized == "email me at [REDACTED]"
    assert is_valid is True
    assert risk == 1.0


def test_openai_wrapper_preserves_roles_when_redacting():
    client = _Client()
    wrapped = GuardedOpenAI(client, Guard(policy=Policy.default(), backend=FakeDecisionBackend()))

    wrapped.chat.completions.create(
        messages=[
            {"role": "system", "content": "be concise"},
            {"role": "user", "content": "email person@example.com"},
        ]
    )

    assert client.chat.completions.kwargs["messages"] == [
        {"role": "system", "content": "be concise"},
        {"role": "user", "content": "email [REDACTED]"},
    ]


def test_openai_wrapper_redacts_text_content_parts():
    client = _Client()
    wrapped = GuardedOpenAI(client, Guard(policy=Policy.default(), backend=FakeDecisionBackend()))

    wrapped.chat.completions.create(
        messages=[
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "email person@example.com"},
                    {"type": "input_text", "text": "phone 415-555-1212"},
                ],
            },
        ]
    )

    assert client.chat.completions.kwargs["messages"] == [
        {
            "role": "user",
            "content": [
                {"type": "text", "text": "email [REDACTED]"},
                {"type": "input_text", "text": "phone [REDACTED]"},
            ],
        },
    ]
