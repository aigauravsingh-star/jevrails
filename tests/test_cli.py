from jevrails.cli import _parse_label


def test_parse_label_handles_false_string():
    assert _parse_label("false", line_number=1) is False
    assert _parse_label("true", line_number=1) is True


def test_parse_label_rejects_ambiguous_strings():
    try:
        _parse_label("blocked", line_number=7)
    except ValueError as exc:
        assert "Line 7" in str(exc)
    else:
        raise AssertionError("expected ValueError")
