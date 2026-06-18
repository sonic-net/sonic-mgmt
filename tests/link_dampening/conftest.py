"""
Pytest configuration and fixtures for Layer1 (Physical) tests
"""

import logging
import pytest

# from tests.common.helpers.assertions import pytest_assert as pt_assert
# from tests.link_dampening.link_event_damping_utils import get_dut_fronface_ports

from tests.common.helpers.assertions import pytest_assert
from tests.link_dampening.link_event_damping_utils import get_dut_fronface_ports

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def link_dampening_test_interface(duthosts, enum_rand_one_per_hwsku_frontend_hostname, conn_graph_facts, tbinfo):
    """
    Get a test interface that is eligible for link_dampening testing.

    Returns the first available front-facing interface on the DUT.
    """
    dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    # Get all front-facing interfaces
    front_interfaces = get_dut_fronface_ports(dut, tbinfo)

    # pytest_assert(front_interfaces, "No front-facing interfaces found on DUT")

    # Return the first interface
    return front_interfaces[0]


@pytest.fixture(scope="module")
def link_dampening_test_interfaces(duthosts, enum_rand_one_per_hwsku_frontend_hostname, conn_graph_facts, tbinfo):
    """
    Get multiple test interfaces for link_dampening testing.

    Returns up to 5 available front-facing interfaces.
    """
    dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    # Get all front-facing interfaces
    front_interfaces = get_dut_fronface_ports(dut, tbinfo)

    # pytest_assert(len(front_interfaces) >= 2, "Need at least 2 front-facing interfaces")

    # Return up to 5 interfaces
    return front_interfaces[:5]


@pytest.fixture(scope="function")
def cleanup_link_damping(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """
    Cleanup fixture that ensures link damping stats are cleared after each test.
    """
    yield

    # Cleanup code runs after test
    try:
        dut = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        # Clear link damping stats
        dut.shell("redis-cli -n 0 --scan --match 'LINK_DAMPING_STATS:*' | xargs redis-cli -n 0 DEL",
                   module_ignore_errors=True)
        logger.info("Cleaned up link damping statistics")
    except Exception as e:
        logger.warning(f"Could not cleanup link damping stats: {e}")


@pytest.fixture(scope="module")
def get_test_interface_from_graph(conn_graph_facts, tbinfo):
    """
    Get test interface information from connection graph.

    Useful for getting fanout interface information.
    """
    def _get_interface(dut_hostname, dut_interface):
        """Get fanout interface connected to DUT interface."""
        try:
            # Find the connection from graph
            for link_name, link_info in conn_graph_facts.items():
                for intf_a, intf_b in link_info.items():
                    if (intf_a[0] == dut_hostname and intf_a[1] == dut_interface):
                        return intf_b[0], intf_b[1]  # (fanout_hostname, fanout_interface)
                    elif (intf_b[0] == dut_hostname and intf_b[1] == dut_interface):
                        return intf_a[0], intf_a[1]  # (fanout_hostname, fanout_interface)
        except Exception as e:
            logger.warning(f"Could not get fanout interface for {dut_interface}: {e}")

        return None, None

    return _get_interface
