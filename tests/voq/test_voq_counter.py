import logging
import pytest
import ptf.testutils as testutils
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.utilities import wait_until
from tests.common.gu_utils import get_asic_name


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t2', 't1', 't0')
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


def test_voq_queue_counter(duthosts, enum_rand_one_per_hwsku_frontend_hostname, ptfadapter, tbinfo):
    """
    This test implicitly verifies that queue counters --voq (i.e. Credit-WD-Del/pkts)
    are working as expected. For multi-ASIC systems, it disables fabric ports.
    For single-ASIC systems, it simulates congestion by disabling TX on a port.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    bcm_changes = False
    # Ensure the device is a Broadcom device
    pytest_require((duthost.facts.get('platform_asic') == "broadcom-dnx"),
                   "The Test Case is only supported on Broadcom-dnx ASIC")

    duthost.shell("sonic-clear queuecounters")

    asic_name = get_asic_name(duthost).lower()
    is_multi_asic = duthost.is_multi_asic
    is_q3d_single_asic = ("q3d" in asic_name) and (not is_multi_asic)

    if is_multi_asic:
        cmd_bcmcmd_false = "'port enable sfi false'"
        cmd_bcmcmd_true = "'port enable sfi true'"
        cmd = "show queue counters --voq --nonzero| grep -i 'Ethernet-IB' |grep -i 'VOQ0' |awk '{{print $7}}'"
        try:
            bcm_changes = True
            for asic in duthost.asics:
                bcmcmd = "bcmcmd {} ".format("-n " + str(asic.asic_index)) + cmd_bcmcmd_false
                res = duthost.shell(bcmcmd, module_ignore_errors=True)
                if res["failed"]:
                    pytest.fail("BCMCMD Failed: {}".format(res))

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
                    if res["failed"]:
                        pytest.fail("BCMCMD Failed: {}".format(res))

    elif is_q3d_single_asic:
        cmd_bcmcmd = "setreg SCH_SCHEDULER_CONFIGURATION_REGISTER DISABLE_FABRIC_MSGS"
        cmd = "show queue counters --voq --nonzero | grep -i 'VOQ7' | awk '{print $7}'"
        try:
            bcm_changes = True
            bcmcmd = "bcmcmd '{}'=1".format(cmd_bcmcmd)
            res = duthost.shell(bcmcmd, module_ignore_errors=True)
            if res["failed"]:
                pytest.fail("BCMCMD Failed to disable fabric messages: {}".format(res))

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
                bcmcmd = "bcmcmd '{}'=0".format(cmd_bcmcmd)
                res = duthost.shell(bcmcmd, module_ignore_errors=True)
                if res["failed"]:
                    pytest.fail("BCMCMD Failed to re-enable fabric messages: {}".format(res))

    else:
        # Generic approach for other single-ASIC VOQ platforms
        up_ports = [p for p in duthost.frontend_ports if duthost.is_port_up(p)]
        if not up_ports:
            pytest.skip("No UP ports found on DUT")

        test_port = up_ports[0]
        # Use bcmcmd for now as no SAI helper exists in test infra
        # Translate port name to index for bcmcmd compatibility
        mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
        port_indices = mg_facts.get("minigraph_port_indices", {})
        if test_port not in port_indices:
            pytest.skip("Port index not found for {} in minigraph facts".format(test_port))
        test_port_idx = port_indices[test_port]

        cmd_off = "bcmcmd 'port enable {} false'".format(test_port_idx)
        cmd_on = "bcmcmd 'port enable {} true'".format(test_port_idx)
        # Check all VOQs for the selected port to be more generic across platforms
        cmd = "show queue counters --voq --nonzero | grep -i '{}' | awk '{{print $7}}'".format(test_port)

        # Find an ingress port for traffic generation
        ingress_port = next((p for p in up_ports if p != test_port), None)
        if not ingress_port:
            pytest.skip("No valid ingress port found for traffic generation")

        ptf_idx = mg_facts.get('minigraph_ptf_indices', {}).get(ingress_port)
        if ptf_idx is None:
            pytest.skip("PTF index for {} not found".format(ingress_port))

        try:
            bcm_changes = True
            # Disable egress to trigger queue buildup
            res = duthost.shell(cmd_off, module_ignore_errors=True)
            if res["failed"]:
                pytest.fail("BCMCMD Failed to disable egress: {}".format(res))

            # Packet to be used for traffic generation
            pkt = testutils.simple_tcp_packet()

            def send_traffic():
                # maintain queue pressure
                for _ in range(500):
                    ptfadapter.dataplane.send(ptf_idx, pkt)

            def queue_counter_assertion():
                send_traffic()
                out = duthost.shell(cmd)["stdout"].split("\n")
                integers = [int(item.replace(",", "")) for item in out if item.replace(",", "").strip().isdigit()]
                return any(num > 0 for num in integers)

            pytest_assert(
                wait_until(300, 5, 0, queue_counter_assertion),
                "Credit-WD-Del/pkts counter did not increment for {}.".format(test_port)
            )
        finally:
            if bcm_changes:
                res = duthost.shell(cmd_on, module_ignore_errors=True)
                if res["failed"]:
                    pytest.fail("BCMCMD Failed to re-enable egress: {}".format(res))
