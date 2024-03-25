'''This script is to test the line card reboot behavior for SONiC.

Step 1: Configure Macsec between neighbor and DUT
Step 2: Save config on DUT and reboot the line card
Step 3: Verify macsec connection is re-established after reboot

'''

import logging
import pytest
from tests.common import reboot

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t2')
]


@pytest.mark.reboot
def test_chassis_reboot(duthost, localhost):
    dut_lldp_table = duthost.shell("show lldp table")['stdout'].split("\n")[3].split()
    dut_to_neigh_int = dut_lldp_table[0]
    if duthost.is_multi_asic:
        asic_index = duthost.get_port_asic_instance(dut_to_neigh_int).asic_index
    else:
        asic_index = None
    space_var = ""
    if asic_index is not None:
        space_var = "-n {} ".format(asic_index)
    duthost.command("config save -y")
    reboot(duthost, localhost, wait=240)

    macsec_status = duthost.shell("show macsec {}{}".format(space_var, dut_to_neigh_int))['stdout'].splitlines()
    assert dut_to_neigh_int in macsec_status[0]
    assert "true" in macsec_status[3]
