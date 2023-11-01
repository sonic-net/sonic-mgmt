'''This script is to test the the chassis reboot behavior for SONiC.

Step 1: Configure Macsec between neighbor and DUT
Step 2: Save config on DUT and reboot
Step 3: Verify macsec connection is re-established after reboot

'''

import logging
import pytest
from tests.common import reboot
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t2')
]


def test_chassis_reboot(duthost, enum_rand_one_frontend_asic_index, duthosts, localhost, enum_supervisor_dut_hostname):
    rphost = duthosts[enum_supervisor_dut_hostname]
    asic_index = enum_rand_one_frontend_asic_index
    dut_lldp_table = duthost.shell("show lldp table")['stdout'].split("\n")[3].split()
    dut_to_neigh_int = dut_lldp_table[0]
    rphost.shell("config save -y")
    reboot(rphost, localhost, wait=240)

    space_var = ""
    if asic_index is not None:
        space_var = "-n {} ".format(asic_index)
    macsec_status = duthost.shell("show macsec {}{}".format(space_var, dut_to_neigh_int))['stdout'].splitlines()
    pytest_assert(dut_to_neigh_int in macsec_status[0])
    pytest_assert("enable" in macsec_status[3])
