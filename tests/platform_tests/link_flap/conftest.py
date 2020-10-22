"""
Pytest configuration used by the link flap tests.

Teardowns used by the link flap tests.
"""

import time

import pytest

from tests.platform_tests.link_flap.link_flap_utils import build_test_candidates
from tests.common import config_reload


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
def bring_up_fannout_interfaces(request, duthost, fanouthosts):
    """
    Bring up outer interfaces on the DUT.

    Args:
        request: pytest request object
        duthost: Fixture for interacting with the DUT.
        fanouthosts: Fixture for interacting with the fanouts.
    """
    yield
    if request.node.rep_call.failed:
        candidates = build_test_candidates(duthost, fanouthosts)
        for _, fanout, fanout_port in candidates:
            fanout.no_shutdown(fanout_port)

        time.sleep(60)


@pytest.fixture()
def perform_config_reload(duthost):
    """
    Perform config reload.

    Args:
        duthost: Fixture for interacting with the DUT.
    """
    yield
    config_reload(duthost)
