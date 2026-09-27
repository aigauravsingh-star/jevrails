from jevrails import Policy


def test_policy_only_rejects_unknown_checks():
    try:
        Policy.default().only({"does_not_exist"})
    except ValueError as exc:
        assert "Unknown check" in str(exc)
    else:
        raise AssertionError("expected ValueError")
