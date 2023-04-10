"""
Pytest configuration used by the link flap tests.

Teardowns used by the link flap tests.
"""
import pytest
import logging
from tests.common.utilities import wait_until

logger = logging.getLogger()


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


@pytest.fixture(scope='module')
def get_loop_times(pytestconfig):
    return pytestconfig.getoption("--loop_times")


@pytest.fixture()
def bgp_sessions_config(duthost):
    logger.info("Stop all bgp sessions")
    duthost.command('sudo config bgp shutdown all')
    logger.info("Wait all bgp sessions are down")
    wait_until(60, 10, 0, check_bgp_is_shutdown, duthost)
    yield
    logger.info("Start all bgp sessions")
    duthost.command('sudo config bgp startup all')


def check_bgp_is_shutdown(duthost):
    logger.info("checking bgp status")
    return not duthost.command("show ip route bgp")["stdout_lines"] and \
        not duthost.command("show ipv6 route bgp")["stdout_lines"]
