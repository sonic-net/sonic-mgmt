import ipaddress
import logging
import ptf.testutils as testutils
import pytest

from scapy.all import Ether, IPv6, ICMPv6ND_NA, ICMPv6NDOptSrcLLAddr
from tests.common.dualtor.control_plane_utils import verify_tor_states
from tests.common.dualtor.mux_simulator_control import (  # noqa: F401
    toggle_all_simulator_ports_to_rand_unselected_tor,
)
from tests.common.fixtures.ptfhost_utils import run_icmp_responder, run_garp_service  # noqa: F401
from tests.common.utilities import wait_until
from tests.common.dualtor.dual_tor_common import cable_type, CableType                                     # noqa F401

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology("dualtor")]

SERVER_IPV4 = "192.168.0.100"


@pytest.fixture
def neigh_learn_pkt(common_setup_teardown):
    """
    Create a packet to trigger neighbor learning on the DUT:
        - ARP reply for IPv4
        - NA for IPv6
    """
    if common_setup_teardown["ip_version"] == "ipv4":
        pkt = testutils.simple_arp_packet(
            eth_src=common_setup_teardown["server_mac"],
            hw_snd=common_setup_teardown["server_mac"],
            ip_snd=common_setup_teardown["server_ip"],
            ip_tgt=common_setup_teardown["server_ip"],
            arp_op=2,
        )
    elif common_setup_teardown["ip_version"] == "ipv6":
        pkt = (
            Ether(
                src=common_setup_teardown["server_mac"],
                dst=common_setup_teardown["vlan_mac"],
            )
            / IPv6(
                src=common_setup_teardown["server_ip"],
                dst=common_setup_teardown["vlan_ip"],
            )
            / ICMPv6ND_NA(tgt=common_setup_teardown["server_ip"], S=1, R=0, O=0)
            / ICMPv6NDOptSrcLLAddr(type=2, lladdr=common_setup_teardown["server_mac"])
        )

    return pkt


@pytest.fixture
def ip_pkt(common_setup_teardown):
    """
    A generic IPv4 or IPv6 packet used to trigger MAC moves
    """
    if common_setup_teardown["ip_version"] == "ipv4":
        pkt = testutils.simple_ipv4ip_packet(
            eth_dst=common_setup_teardown["vlan_mac"],
            eth_src=common_setup_teardown["server_mac"],
            ip_src=common_setup_teardown["server_ip"],
            ip_dst=common_setup_teardown["vlan_ip"],
        )
        pkt["IP"].proto = 4
    elif common_setup_teardown["ip_version"] == "ipv6":
        pkt = testutils.simple_ipv6ip_packet(
            eth_dst=common_setup_teardown["vlan_mac"],
            eth_src=common_setup_teardown["server_mac"],
            ipv6_src=common_setup_teardown["server_ip"],
            ipv6_dst=common_setup_teardown["vlan_ip"],
        )

    return pkt


@pytest.fixture(params=["ipv4", "ipv6"])
def common_setup_teardown(
    request, rand_selected_dut, rand_unselected_dut, config_facts, tbinfo
):
    cmds = ["sonic-clear arp", "sonic-clear ndp", "sonic-clear fdb all"]
    rand_selected_dut.shell_cmds(cmds=cmds)

    test_facts = {"server_mac": "3a:2c:62:dd:92:11", "ip_version": request.param}
    vlan = list(config_facts["VLAN"].keys())[0]
    test_facts["vlan_mac"] = config_facts["VLAN"][vlan]["mac"]
    for key in config_facts["VLAN_INTERFACE"][vlan].keys():
        try:
            vlan_interface = ipaddress.ip_interface(key)
        except ValueError:
            continue
        if (
            request.param == "ipv4"
            and vlan_interface.version == 4
            or request.param == "ipv6"
            and vlan_interface.version == 6
        ):
            test_facts["vlan_ip"] = str(vlan_interface.ip)
            break

    mux_cable_config = config_facts["MUX_CABLE"]
    if request.param == "ipv4":
        mux_cable_ip_key = "server_ipv4"
    elif request.param == "ipv6":
        mux_cable_ip_key = "server_ipv6"

    cable_ips = [
        ipaddress.ip_interface(config[mux_cable_ip_key])
        for config in mux_cable_config.values()
    ]
    max_ip = sorted(cable_ips)[-1].ip
    test_facts["server_ip"] = str(max_ip + 1)

    mg_facts = rand_selected_dut.get_extended_minigraph_facts(
        tbinfo
    )
    test_facts["intf1"], test_facts["intf2"] = (
        list(mux_cable_config.keys())[0],
        list(mux_cable_config.keys())[1],
    )
    test_facts["ptf_intf1"], test_facts["ptf_intf2"] = (
        mg_facts["minigraph_ptf_indices"][test_facts["intf1"]],
        mg_facts["minigraph_ptf_indices"][test_facts["intf2"]],
    )

    logger.info("Test facts: {}".format(test_facts))
    yield test_facts

    cmds = ["config mux mode auto all"]

    # if the test passed, we only need to clear ARP/NDP/FDB to reset the device for the next test case
    if hasattr(request.node, "rep_call") and request.node.rep_call.passed:
        cmds.append("sonic-clear arp")
        cmds.append("sonic-clear ndp")
        cmds.append("sonic-clear fdb all")

    rand_selected_dut.shell_cmds(cmds=cmds)

    # If the test was skipped then early exit from teardown
    if hasattr(request.node, "rep_call") and request.node.rep_call.skipped or \
            hasattr(request.node, "rep_setup") and request.node.rep_setup.skipped:
        return

    # if the test failed, assume linkmgrd/swss are stuck in a bad state and require a restart
    if not hasattr(request.node, "rep_call") or request.node.rep_call.failed:
        logger.warning("Test failed, restarting swss")
        rand_selected_dut.restart_service("swss")
        wait_until(60, 5, 0, rand_selected_dut.critical_services_fully_started)
        wait_until(60, 5, 0, rand_selected_dut.critical_processes_running, "swss")
        wait_until(60, 5, 0, rand_selected_dut.critical_processes_running, "mux")


@pytest.mark.enable_active_active
def test_mac_move_during_switchover(
    common_setup_teardown,
    toggle_all_simulator_ports_to_rand_unselected_tor,  # noqa: F811
    rand_selected_dut,
    rand_unselected_dut,
    ptfadapter,
    neigh_learn_pkt,
    ip_pkt,
    cable_type,                                         # noqa: F811
):
    """
    Trigger a MAC move during a switchover and verify that the switchover still completes successfully
    """
    # Learn the neighbor on the DUT
    testutils.send(ptfadapter, common_setup_teardown["ptf_intf1"], neigh_learn_pkt)

    # Pause syncd and trigger a switchover. Since syncd is paused, orchagent will hang (if the bug is present)
    # which allows us to pause orchagent mid-switchover
    rand_selected_dut.control_process("syncd", pause=True)
    if cable_type == CableType.active_standby:
        rand_selected_dut.shell(
            "config mux mode active {}".format(common_setup_teardown["intf1"])
        )
    if cable_type == CableType.active_active:
        rand_selected_dut.shell(
            "config mux mode standby {}".format(common_setup_teardown["intf1"])
        )
    rand_selected_dut.control_process("orchagent", pause=True)

    # Unpause syncd to process the MAC move
    rand_selected_dut.control_process("syncd", pause=False)
    testutils.send(ptfadapter, common_setup_teardown["ptf_intf2"], ip_pkt)

    rand_selected_dut.control_process("orchagent", pause=False)

    if cable_type == CableType.active_standby:
        verify_tor_states(
            rand_selected_dut,
            rand_unselected_dut,
            intf_names=[common_setup_teardown["intf1"]],
            cable_type=cable_type
        )

    if cable_type == CableType.active_active:
        verify_tor_states(
            expected_active_host=rand_unselected_dut,
            expected_standby_host=rand_selected_dut,
            intf_names=[common_setup_teardown["intf1"]],
            cable_type=cable_type
        )

    # recover mux conifg
    rand_selected_dut.shell("config mux mode auto all")
