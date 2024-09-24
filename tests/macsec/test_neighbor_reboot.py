'''

The test case will verify the behavior when a neighbor reboots while Macsec is Active.

Step 1: Configure Macsec between neighbor and DUT
Step 2: Save config on neighbor and reboot
Step 3: Verify macsec connection is re-established after reboot

'''

import pytest
import logging
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.macsec_required,
    pytest.mark.topology("t2")
]


def test_neighbor_reboot(duthosts, request, enum_frontend_dut_hostname, ctrl_links):
    if request.config.getoption("neighbor_type") != "sonic":
        pytest.skip("Neighbor type must be sonic")
    duthost = duthosts[enum_frontend_dut_hostname]
    if not duthost.is_macsec_capable_node():
        pytest.skip("DUT must be a MACSec enabled device.")
    pytest_assert(ctrl_links)
    dut_to_neigh_int, nbr = list(ctrl_links.items())[0]
    wait_until(120, 3, 0, lambda: duthost.iface_macsec_ok(dut_to_neigh_int) and
               nbr["host"].iface_macsec_ok(nbr["port"]))
    nbr["host"].shell("config save -y")
    nbr["host"].shell("sudo reboot")

    # macsec should be down on neighbor right after reboot
    wait_until(240, 3, 0, lambda: not nbr["host"].iface_macsec_ok(nbr["port"]))
    pytest_assert(not nbr["host"].iface_macsec_ok(nbr["port"]))

    # wait for macsec to come back up
    wait_until(240, 3, 0, lambda: duthost.iface_macsec_ok(dut_to_neigh_int) and
               nbr["host"].iface_macsec_ok(nbr["port"]))

    pytest_assert(duthost.iface_macsec_ok(dut_to_neigh_int))
    pytest_assert(nbr["host"].iface_macsec_ok(nbr["port"]))
