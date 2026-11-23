"""Regress cSONiC route-query failures through an absence-sensitive caller."""

import pytest

from tests.bgp.test_prefix_list import check_route_receive
from tests.common.devices.csonic import CsonicHost


PREFIX = "205.168.0.0/24"


def _check_absent_route(result):
    host = CsonicHost("csonic_test_VM0100")
    host._docker_exec = lambda command, **kwargs: result
    results = {}

    check_route_receive(
        PREFIX,
        expected_community=[],
        unexpected_community=[],
        neighbor_type="csonic",
        present=False,
        node={"host": host},
        results=results,
    )
    return results[host.hostname]


def test_prefix_list_caller_accepts_valid_route_absence():
    result = {"rc": 0, "stdout": "{}", "stderr": ""}

    assert _check_absent_route(result) is True


@pytest.mark.parametrize(
    "result, error, message",
    [
        (
            {"rc": 1, "stdout": "", "stderr": "FRR unavailable"},
            RuntimeError,
            r"get_route.*failed",
        ),
        (
            {"rc": 0, "stdout": "", "stderr": ""},
            RuntimeError,
            "returned empty stdout",
        ),
        (
            {"rc": 0, "stdout": "% Unknown command", "stderr": ""},
            ValueError,
            "returned invalid JSON",
        ),
        (
            {"rc": 0, "stdout": "[]", "stderr": ""},
            TypeError,
            "expected a JSON object",
        ),
    ],
)
def test_prefix_list_caller_does_not_accept_query_failure_as_absence(
        result, error, message):
    with pytest.raises(error, match=message):
        _check_absent_route(result)
