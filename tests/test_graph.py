from graph import route_after_classification


def test_route_ends_after_a_successful_validation():
    assert route_after_classification({"classification": "pass", "retry_count": 0, "max_retries": 1}) == "end"


def test_route_respects_zero_allowed_retries():
    assert route_after_classification({"classification": "fail", "retry_count": 0, "max_retries": 0}) == "end"


def test_route_retries_while_attempts_remain():
    assert route_after_classification({"classification": "fail", "retry_count": 0, "max_retries": 1}) == "retry"
