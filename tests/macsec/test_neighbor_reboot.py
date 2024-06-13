'''

The test case will verify a neighbor reboot while Macsec is Active.

Step 1: Configure Macsec between neighbor and DUT
Step 2: Save config on neighbor and reboot
Step 3: Verify macsec connection is re-established after reboot

'''

from time import sleep
import pytest
import logging


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.macsec_required,
    pytest.mark.topology("t2")
]


def test_neighbor_reboot(duthost, nbrhosts, request, enum_rand_one_frontend_asic_index):
    if request.config.getoption("neighbor_type") != "sonic":
        pytest.skip("Neighbor type must be sonic")
    asic_index = enum_rand_one_frontend_asic_index
    namespace = duthost.get_namespace_from_asic_id(asic_index)
    dut_lldp_table = duthost.shell("show lldp table")['stdout'].split("\n")[3].split()
    dut_to_neigh_int = dut_lldp_table[0]
    neighhost = nbrhosts[dut_lldp_table[1]]["host"]
    neighhost.shell("config save -y")
    neighhost.shell("sudo reboot")
    sleep(240)

    space_var = ""
    if namespace is not None:
        space_var = "-n {} ".format(namespace)
    macsec_status = duthost.shell("show macsec {}{}".format(space_var, dut_to_neigh_int))['stdout'].splitlines()
    assert dut_to_neigh_int in macsec_status[0]
    assert "enable" in macsec_status[3]
