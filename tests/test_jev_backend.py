from jevrails.backends import JevBackend
from jevrails.types import DecisionQuestion


def test_jev_backend_parses_nested_answers():
    backend = JevBackend("test-key")
    result = backend._parse_results(
        {"result": {"answers": {"prompt_injection": {"probability": 0.82}}}},
        [DecisionQuestion(id="prompt_injection", instructions="test")],
    )

    assert result[0].check_id == "prompt_injection"
    assert result[0].probability == 0.82


def test_jev_backend_parses_boolean_answer():
    backend = JevBackend("test-key")
    result = backend._parse_results(
        {"answers": {"jailbreak": {"answer": True}}},
        [DecisionQuestion(id="jailbreak", instructions="test")],
    )

    assert result[0].probability == 1.0
