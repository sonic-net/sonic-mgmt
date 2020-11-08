"""
Pytest configuration used by the link flap tests.

Teardowns used by the link flap tests.
"""

import time

import pytest

from tests.platform_tests.link_flap.link_flap_utils import build_test_candidates

def pytest_addoption(parser):
    """
    Adds options to pytest that are used by the Link flap tests.
    """

    parser.addoption(
        "--orch_cpu_threshold",
        action="store",
        type=int,
        default=10,
        help="Orchagent CPU threshold",
    )


@pytest.fixture()
def bring_up_fanout_interfaces(request, duthosts, fanouthosts):
    """
    Bring up outer interfaces on the DUT.

    Args:
        request: pytest request object
        duthosts: Fixture for interacting with the DUT list.
        fanouthosts: Fixture for interacting with the fanouts.
    """
    yield
    if request.node.rep_call.failed:
        for dut in duthosts:
            candidates = build_test_candidates(dut, fanouthosts, "all_ports")
            for _, fanout, fanout_port in candidates:
                fanout.no_shutdown(fanout_port)

        time.sleep(60)
