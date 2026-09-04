import logging
import pytest
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.utilities import wait_until
from tests.common.gu_utils import get_asic_name


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t2')
]


@pytest.mark.skip(reason="Simulation of Packet integrity (CRC, RQP errors) is not possible due to issue #16140")
def test_voq_drop_counter(duthosts, tbinfo, ptfadapter,
                          nbrhosts, enum_rand_one_per_hwsku_hostname, enum_rand_one_asic_index):
    """
    Skipping the Test Case as For Verification of SAI_SWITCH_STAT_PACKET_INTEGRITY_DROP
    the simulation of Packet integrity (CRC, RQP errors) is not possible
    with the issue https://github.com/sonic-net/sonic-mgmt/issues/16140
    The functionality is in https://github.com/sonic-net/sonic-utilities/pull/3322
    """


def test_voq_queue_counter(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """
    This test implicitly verifies that queue counters --voq (i.e. Credit-WD-Del/pkts)
    are working as expected by disabling the fabric ports
    For Q3D (single-ASIC), instead disable fabric messages via register setting.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    bcm_changes = False
    # Ensure the device is a Broadcom device
    pytest_require((duthost.facts.get('platform_asic') == "broadcom-dnx"),
                   "The Test Case is only supported on Broadcom-dnx ASIC")

    duthost.shell("sonic-clear queuecounters")

    asic_name = get_asic_name(duthost).lower()
    is_q3d_single_asic = ("q3d" in asic_name) and (not duthost.is_multi_asic)

    if is_q3d_single_asic:
        cmd_bcmcmd = "setreg SCH_SCHEDULER_CONFIGURATION_REGISTER DISABLE_FABRIC_MSGS"
        cmd = "show queue counters --voq --nonzero | grep -i 'VOQ7' | awk '{print $7}'"

        try:
            bcm_changes = True
            bcmcmd = f"bcmcmd '{cmd_bcmcmd}'=1"
            res = duthost.shell(bcmcmd, module_ignore_errors=True)
            if not res["stderr"] == "polling socket timeout: Success" and res["failed"]:
                pytest.fail("BCMCMD Failed to disable fabric messages")

            def queue_counter_assertion():
                out = duthost.shell(cmd)["stdout"].split("\n")
                integers = [int(item.replace(",", "")) for item in out if item.replace(",", "").strip().isdigit()]
                return any(num > 0 for num in integers)

            pytest_assert(
                wait_until(300, 5, 0, queue_counter_assertion),
                "Credit-WD-Del/pkts counter did not increment. "
                "Ref: https://github.com/sonic-net/sonic-buildimage/issues/21098",
            )
        finally:
            if bcm_changes:
                bcmcmd = f"bcmcmd '{cmd_bcmcmd}'=0"
                res = duthost.shell(bcmcmd, module_ignore_errors=True)
                if not res["stderr"] == "polling socket timeout: Success" and res["failed"]:
                    pytest.fail("BCMCMD Failed to re-enable fabric messages")
    else:
        cmd_bcmcmd_false = "'port enable sfi false'"
        cmd_bcmcmd_true = "'port enable sfi true'"
        cmd = "show queue counters --voq --nonzero| grep -i 'Ethernet-IB' |grep -i 'VOQ0' |awk '{print $7}'"
        try:
            bcm_changes = True
            for asic in duthost.asics:
                bcmcmd = "bcmcmd {} ".format("-n " + str(asic.asic_index)) + cmd_bcmcmd_false
                res = duthost.shell(bcmcmd, module_ignore_errors=True)
                if not res["stderr"] == "polling socket timeout: Success" and res["failed"]:
                    pytest.fail("BCMCMD Failed")

            def queue_counter_assertion():
                out = duthost.shell(cmd)['stdout'].split('\n')
                integers = [int(item.replace(',', '')) for item in out if item.replace(',', '').strip().isdigit()]
                return any(num > 0 for num in integers)

            pytest_assert(wait_until(300, 5, 0, queue_counter_assertion),
                          "Credit-WD-Del/pkts is not increasing "
                          "Ref: https://github.com/sonic-net/sonic-buildimage/issues/21098")
        finally:
            if bcm_changes:
                for asic in duthost.asics:
                    cmd = "bcmcmd {} ".format("-n " + str(asic.asic_index)) + cmd_bcmcmd_true
                    res = duthost.shell(cmd, module_ignore_errors=True)
                    if not res["stderr"] == "polling socket timeout: Success" and res["failed"]:
                        pytest.fail("BCMCMD Failed")
