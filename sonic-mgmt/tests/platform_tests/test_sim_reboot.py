"""
Check platform status after cold reboot. 

"""
import logging
import pytest

from tests.common.fixtures.conn_graph_facts import conn_graph_facts     # noqa F401
from tests.common.utilities import wait_until
from tests.common.reboot import reboot, REBOOT_TYPE_COLD
from tests.common.platform.interface_utils import check_interface_status_of_up_ports
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]


def test_sim_cold_reboot(duthosts, enum_rand_one_per_hwsku_hostname,
                     localhost, conn_graph_facts, xcvr_skip_list):      # noqa F811
    """
    @summary: This test case is to perform cold reboot and check platform status
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    logging.info("Run cold reboot on DUT")
    reboot(duthost, localhost, reboot_type=REBOOT_TYPE_COLD, wait=90)
    pytest_assert(wait_until(30, 5, 0, check_interface_status_of_up_ports, duthost),
                          "Not all ports that are admin up on are operationally up")
    logging.info("Interfaces are up")

