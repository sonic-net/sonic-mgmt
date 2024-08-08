'''This script is to test the device reboot behavior for SONiC.

Test 1: Line Card
Step 1: Configure Macsec between neighbor and DUT
Step 2: Save config on DUT and reboot the line card
Step 3: Verify macsec connection is re-established after reboot

Test 2: Chassis
Step 1: Configure Macsec between neighbor and DUT
Step 2: Save config on DUT and reboot the chassis
Step 3: Verify macsec connection is re-established after reboot

'''

import logging
import pytest
# from time import sleep
from tests.common import reboot
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t2')
]


@pytest.mark.reboot
def test_lc_reboot(duthost, localhost):
    # duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dut_lldp_table = duthost.shell("show lldp table")['stdout'].split("\n")
    dut_to_neigh_int = dut_lldp_table[3].split()[0]
    if duthost.is_multi_asic:
        asic_index = duthost.get_port_asic_instance(dut_to_neigh_int).asic_index
    else:
        asic_index = None
    space_var = ""
    if asic_index is not None:
        space_var = "-n {} ".format(asic_index)
    duthost.command("config save -y")
    reboot(duthost, localhost, wait=240)
    # sleep(60)  # wait extra for macsec to establish
    wait_until(120, 5, 0, lambda: duthost.iface_macsec_ok(dut_to_neigh_int))
    logger.info(f"iface macsec: {duthost.iface_macsec_ok(dut_to_neigh_int)}")
    macsec_status = duthost.shell("show macsec {} {}".format(space_var, dut_to_neigh_int))['stdout'].splitlines()
    logger.info(f"macsec status {macsec_status}")
    assert dut_to_neigh_int in macsec_status[0]
    assert "true" in macsec_status[3]


@pytest.mark.reboot
def test_chassis_reboot(duthosts, localhost, enum_supervisor_dut_hostname,
                        duthost):
    rphost = duthosts[enum_supervisor_dut_hostname]
    dut_lldp_table = duthost.shell("show lldp table")['stdout'].split("\n")[3].split()
    dut_to_neigh_int = dut_lldp_table[0]
    if duthost.is_multi_asic:
        asic_index = duthost.get_port_asic_instance(dut_to_neigh_int).asic_index
    else:
        asic_index = None
    rphost.shell("config save -y")
    reboot(rphost, localhost, wait=240)
    # sleep(60)  # wait extra for macsec to establish
    wait_until(120, 5, 0, lambda: duthost.iface_macsec_ok(dut_to_neigh_int))
    space_var = ""
    if asic_index is not None:
        space_var = "-n {} ".format(asic_index)
    macsec_status = duthost.shell("show macsec {} {}".format(space_var, dut_to_neigh_int))['stdout'].splitlines()
    pytest_assert(dut_to_neigh_int in macsec_status[0])
    pytest_assert("enable" in macsec_status[3])
