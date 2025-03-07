import pytest
import logging

logger = logging.getLogger(__name__)


@pytest.fixture(scope="session", autouse=True)
def initial_setup(duthosts, tbinfo):
    """
    Perform initial DUT configurations(T1, Fanout(if present)) for convergence tests. This runs once per test session.
    """
    if "route_conv" not in tbinfo['topo']['name']:
        return

    logger.info("Starting initial DUT setup for T2 Convergence tests")

    # PLACEHOLDER For T2 Convergence test setup
    # Configure T1 DUT: Interface IP, BGP etc: Use Connectivity details/Interface IPs/BGP Neighborship
    # details from variables.py
    # Configure Fanout DUT(if Applicable): Use connectivity details from variables.py

    logger.info("########IMP########: Please ensure the below configurations are done on DUTs before running the tests")
    logger.info("1. Ensure T1 DUT is Configured")
    logger.info("2. Ensure Fanout DUT is Configured if Applicable")

    logger.info("T2 Convergence test setup complete")
