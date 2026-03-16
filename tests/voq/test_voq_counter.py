import logging
import pytest
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.utilities import wait_until


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
    are working as expected by disabling the fabric ports (multi-asic) or
    shutting down a front panel port (single-asic)
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    bcm_changes = False
    port_changes = False
    # Ensure the device is a Broadcom device
    pytest_require((duthost.facts.get('platform_asic') == "broadcom-dnx"),
                   "The Test Case is only supported on Broadcom-dnx ASIC")

    is_multi_asic = duthost.is_multi_asic

    if is_multi_asic:
        cmd_bcmcmd_false = "'port enable sfi false'"
        cmd_bcmcmd_true = "'port enable sfi true'"
        cmd = "show queue counters --voq --nonzero| grep -i '{}' |grep -i '{}' |awk '{{print $7}}'".format(
            "Ethernet-IB", "VOQ0")
    else:
        # For single-ASIC VOQ devices, get an UP Ethernet front panel port to shutdown
        intf_status = duthost.get_interfaces_status()
        up_eth_ports = [
            intf for intf, status in intf_status.items()
            if intf.startswith("Ethernet")
            and not intf.startswith("Ethernet-IB")
            and status.get("admin") == "up"
            and status.get("oper") == "up"
        ]
        pytest_require(len(up_eth_ports) > 0,
                       "No up Ethernet ports found on single-ASIC VOQ device")
        shutdown_port = up_eth_ports[0]
        logger.info("Single-ASIC VOQ: will shutdown port {} to trigger Credit-WD-Del".format(shutdown_port))
        # For single-ASIC, check Credit-WD-Del on all non-IB Ethernet ports
        cmd = ("show queue counters --voq --nonzero| grep -v 'Ethernet-IB' "
               "|grep -i 'Ethernet' |grep -i 'VOQ0' |awk '{print $7}'")

    try:
        if is_multi_asic:
            bcm_changes = True
            for asic in duthost.asics:
                bcmcmd = "bcmcmd {} ".format("-n " + str(asic.asic_index)) + cmd_bcmcmd_false
                res = duthost.shell(bcmcmd, module_ignore_errors=True)
                if not res["stderr"] == "polling socket timeout: Success" and res["failed"]:
                    pytest.fail("BCMCMD Failed")
        else:
            port_changes = True
            duthost.shutdown_interface(shutdown_port)

        def queue_counter_assertion():
            out = duthost.shell(cmd)['stdout'].split('\n')
            integers = [int(item.replace(',', '')) for item in out if item.replace(',', '').strip().isdigit()]
            return any(num > 0 for num in integers)

        pytest_assert(wait_until(300, 0, 0, queue_counter_assertion),
                      "Credit-WD-Del/pkts is not increasing "
                      "Ref: https://github.com/sonic-net/sonic-buildimage/issues/21098")
    finally:
        if bcm_changes:
            for asic in duthost.asics:
                cmd = "bcmcmd {} ".format("-n " + str(asic.asic_index)) + cmd_bcmcmd_true
                res = duthost.shell(cmd, module_ignore_errors=True)
                if not res["stderr"] == "polling socket timeout: Success" and res["failed"]:
                    pytest.fail("BCMCMD Failed")
        elif port_changes:
            duthost.no_shutdown_interface(shutdown_port)
