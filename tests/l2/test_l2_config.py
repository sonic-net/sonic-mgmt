"""
Tests related to L2 configuration
"""
import logging
import pytest
import time

from tests.common.reboot import reboot
from tests.common.helpers.assertions import pytest_expect

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]


def test_l2_configure(duthosts, rand_one_dut_hostname, localhost):
    """
    @summary: Test configuring dut as a L2 switch.

    Args:
        duthosts: set of DUTs.
        localhost: localhost object.
    """
    # Setup.
    duthost = duthosts[rand_one_dut_hostname]
    hwsku = duthost.facts["hwsku"]

    # Store original config for comparison.
    orig_vlan = duthost.shell("show vlan config")["stdout"]
    orig_int = duthost.shell("show int status")["stdout"]

    # Perform L2 configuration
    l2_cfg = "sudo sonic-cfggen --preset l2 -p -H -k {}" \
        " | sudo config load /dev/stdin -y".format(hwsku)
    duthost.shell(l2_cfg)
    duthost.shell("sudo config qos reload --no-dynamic-buffer")
    time.sleep(60)

    new_vlan = duthost.shell("show vlan config")["stdout"]
    new_int = duthost.shell("show int status")["stdout"]

    pytest_expect(orig_vlan != new_vlan, "vlan config not updated.")
    pytest_expect(orig_int != new_int, "interface status not updated.")

    # Restore from L2
    reboot(duthost, localhost)