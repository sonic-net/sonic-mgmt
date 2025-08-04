"""Test cases to support the Everflow Mirroring feature in SONiC."""
import logging
import time
import pytest
import os
import ptf.testutils as testutils
from scapy.layers.l2 import Ether
from scapy.contrib.mpls import MPLS
from scapy.layers.l2 import Dot1Q
from scapy.layers.vxlan import VXLAN
from . import everflow_test_utilities as everflow_utils

from .everflow_test_utilities import BaseEverflowTest, erspan_ip_ver, skip_ipv6_everflow_tests  # noqa: F401
from .everflow_test_utilities import TEMPLATE_DIR, EVERFLOW_RULE_CREATE_TEMPLATE, \
                                    DUT_RUN_DIR, EVERFLOW_RULE_CREATE_FILE, UP_STREAM
from .everflow_test_utilities import CONFIG_MODE_CLI, CONFIG_MODE_GCU
from tests.common.helpers.assertions import pytest_require

from .everflow_test_utilities import setup_info, EVERFLOW_DSCP_RULES, STABILITY_BUFFER  # noqa: F401
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor  # noqa: F401

pytestmark = [
    pytest.mark.topology("any")
]

EVERFLOW_TABLE_NAME = {
    "ipv4": "EVERFLOW",
    "ipv6": "EVERFLOWV6"
}

EVERFLOW_SESSION_NAME = "everflow_session_per_interface"

logger = logging.getLogger(__file__)


def build_candidate_ports(duthost, tbinfo, ns):
    """
    Build candidate ports for testing
    """
    candidate_ports = {}
    unselected_ports = {}
    if tbinfo['topo']['type'] in ['t0', 'mx']:
        candidate_neigh_name = 'Server'
    elif tbinfo['topo']['type'] == 'm0':
        candidate_neigh_name = 'MX'
    elif tbinfo['topo']['type'] == 't1':
        candidate_neigh_name = 'T0'
    elif tbinfo['topo']['type'] == 'm1':
        candidate_neigh_name = 'M0'
    else:
        candidate_neigh_name = 'T1'
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    i = 0
    for dut_port, neigh in list(mg_facts["minigraph_neighbors"].items()):
        if neigh['namespace'] != ns:
            continue
        ptf_idx = mg_facts["minigraph_ptf_indices"][dut_port]

        if candidate_neigh_name in neigh['name'] and len(candidate_ports) < 4:
            if candidate_neigh_name == 'T0' or i % 2:
                candidate_ports.update({dut_port: ptf_idx})
        if len(unselected_ports) < 4 and dut_port not in candidate_ports:
            unselected_ports.update({dut_port: ptf_idx})

        i = i + 1

    logger.info("Candidate testing ports are {}".format(candidate_ports))
    return candidate_ports, unselected_ports


def build_acl_rule_vars(candidate_ports, ip_ver, erspan_ip_ver):  # noqa F811
    """
    Build vars for generating ACL rule
    """
    config_vars = {}
    config_vars['acl_table_name'] = EVERFLOW_TABLE_NAME[ip_ver]
    qualifiers = {"input_interface": ','.join(list(candidate_ports.keys()))}
    # During our tests, we observed a lot of ICMPv6 neighbor solicitation packets that were sent to the DUT
    # trying to resolve link-local IPv6 addresses. All of these packets were mirrored by the DUT. This overwhelmed
    # the PTF container, causing the kernel to drop some packets. As a result, the IPv6 tests sometimes failed.
    # To prevent this issue from happening, we restrict Everflow IPv6 mirroring to TCP packets.
    if ip_ver == "ipv6" or erspan_ip_ver == 6:
        qualifiers["ip"] = {"protocol": 6}  # Only mirror TCP packets
    config_vars['rules'] = [{'qualifiers': qualifiers}]
    return config_vars


@pytest.fixture(scope='module')
def apply_mirror_session(setup_info, erspan_ip_ver):  # noqa F811
    mirror_session_info = BaseEverflowTest.mirror_session_info(
        EVERFLOW_SESSION_NAME, setup_info[UP_STREAM]['everflow_dut'].facts["asic_type"])
    logger.info("Applying mirror session to DUT")
    BaseEverflowTest.apply_mirror_config(setup_info[UP_STREAM]['everflow_dut'],
                                         mirror_session_info, erspan_ip_ver=erspan_ip_ver)
    time.sleep(10)
    yield mirror_session_info

    logger.info("Removing mirror session from DUT")
    BaseEverflowTest.remove_mirror_config(setup_info[UP_STREAM]['everflow_dut'], EVERFLOW_SESSION_NAME)


@pytest.fixture(scope='module')
def setup_mirror_session_dest_ip_route(tbinfo, setup_info, apply_mirror_session, erspan_ip_ver):  # noqa F811
    """
    Setup the route for mirror session destination ip and update monitor port list.
    Remove the route as part of cleanup.
    """
    ip = "ipv4" if erspan_ip_ver == 4 else "ipv6"
    namespace = setup_info[UP_STREAM]['remote_namespace']
    tx_port = setup_info[UP_STREAM]["dest_port"][0]
    dest_port_ptf_id_list = [setup_info[UP_STREAM]["dest_port_ptf_id"][0]]
    remote_dut = setup_info[UP_STREAM]['remote_dut']
    remote_dut.shell(remote_dut.get_vtysh_cmd_for_namespace(
        f"vtysh -c \"config\" -c \"router bgp\" -c \"address-family {ip}\" -c \"redistribute static\"", namespace))
    peer_ip = everflow_utils.get_neighbor_info(remote_dut, tx_port, tbinfo, ip_version=erspan_ip_ver)
    session_prefixes = apply_mirror_session["session_prefixes"] if erspan_ip_ver == 4 \
        else apply_mirror_session["session_prefixes_ipv6"]
    everflow_utils.add_route(remote_dut, session_prefixes[0], peer_ip, namespace)
    time.sleep(5)

    yield (apply_mirror_session, BaseEverflowTest._get_tx_port_id_list(dest_port_ptf_id_list))

    everflow_utils.remove_route(remote_dut, session_prefixes[0], peer_ip, namespace)
    remote_dut.shell(remote_dut.get_vtysh_cmd_for_namespace(
        f"vtysh -c \"config\" -c \"router bgp\" -c \"address-family {ip}\" -c \"no redistribute static\"", namespace))


@pytest.fixture(scope='module', params=['ipv4', 'ipv6'])
def ip_ver(request):
    return request.param


@pytest.fixture(scope='module')
def apply_acl_rule(setup_info, tbinfo, setup_mirror_session_dest_ip_route, ip_ver, erspan_ip_ver):  # noqa F811
    """
    Apply ACL rule for matching input_ports
    """
    # Check existence of EVERFLOW
    table_name = EVERFLOW_TABLE_NAME[ip_ver]
    output = setup_info[UP_STREAM]['everflow_dut'].shell('show acl table {}'.format(table_name))['stdout_lines']
    # Skip if EVERFLOW table doesn't exist
    pytest_require(len(output) > 2, "Skip test since {} dosen't exist".format(table_name))
    mirror_session_info, monitor_port_ptf_ids = setup_mirror_session_dest_ip_route
    # Build testing port list
    candidate_ports, unselected_ports = build_candidate_ports(setup_info[UP_STREAM]['everflow_dut'],
                                                              tbinfo, setup_info[UP_STREAM]['everflow_namespace'])
    pytest_require(len(candidate_ports) >= 1, "Not sufficient ports for testing")
    pytest_require(len(unselected_ports) >= 1, "Not sufficient ports for testing")

    # Copy and apply ACL rule
    config_vars = build_acl_rule_vars(candidate_ports, ip_ver, erspan_ip_ver)
    setup_info[UP_STREAM]['everflow_dut'].host.options["variable_manager"].extra_vars.update(config_vars)
    setup_info[UP_STREAM]['everflow_dut'].command("mkdir -p {}".format(DUT_RUN_DIR))
    setup_info[UP_STREAM]['everflow_dut'].template(src=os.path.join(TEMPLATE_DIR, EVERFLOW_RULE_CREATE_TEMPLATE),
                                                   dest=os.path.join(DUT_RUN_DIR, EVERFLOW_RULE_CREATE_FILE))
    logger.info("Applying acl rule config to DUT")
    command = "acl-loader update full {} --table_name {} --session_name {}" \
        .format(os.path.join(DUT_RUN_DIR, EVERFLOW_RULE_CREATE_FILE), table_name, EVERFLOW_SESSION_NAME)
    setup_info[UP_STREAM]['everflow_dut'].shell(cmd=command)
    ret = {
        "candidate_ports": candidate_ports,
        "unselected_ports": unselected_ports,
        "mirror_session_info": mirror_session_info,
        "monitor_port_ptf_ids": monitor_port_ptf_ids
    }
    time.sleep(2)

    yield ret

    logger.info("Removing acl rule config from DUT")
    BaseEverflowTest.remove_acl_rule_config(setup_info[UP_STREAM]['everflow_dut'], table_name)


def generate_testing_packet(ptfadapter, duthost, mirror_session_info, router_mac, setup, pkt_ip_ver,
                            erspan_ip_ver=4):  # noqa F811
    if pkt_ip_ver == 'ipv4':
        packet = testutils.simple_tcp_packet(
            eth_src=ptfadapter.dataplane.get_mac(
                *list(ptfadapter.dataplane.ports.keys())[0]
            ),
            eth_dst=router_mac
        )
    else:
        packet = testutils.simple_tcpv6_packet(
            eth_src=ptfadapter.dataplane.get_mac(
                *list(ptfadapter.dataplane.ports.keys())[0]
            ),
            eth_dst=router_mac
        )

    dec_ttl = 0
    # Only need to decrement TTL for chassis T2
    if setup['topo'].startswith('t2'):
        dec_ttl = 1
    elif duthost.is_multi_asic:
        dec_ttl = 2

    exp_packet = BaseEverflowTest.get_expected_mirror_packet(mirror_session_info, setup,
                                                             duthost, UP_STREAM, packet, dec_ttl, erspan_ip_ver)
    return packet, exp_packet


def send_and_verify_packet(ptfadapter, packet, expected_packet, tx_port, rx_ports, exp_recv):
    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, pkt=packet, port_id=tx_port)
    if exp_recv:
        testutils.verify_packet_any_port(ptfadapter, pkt=expected_packet, ports=rx_ports, timeout=5)
    else:
        testutils.verify_no_packet_any(ptfadapter, pkt=expected_packet, ports=rx_ports)


@pytest.mark.parametrize("config_method", [CONFIG_MODE_CLI, CONFIG_MODE_GCU], indirect=True)
def test_everflow_per_interface(ptfadapter, setup_info, apply_acl_rule, tbinfo,                 # noqa F811
                                toggle_all_simulator_ports_to_rand_selected_tor, ip_ver,        # noqa F811
                                skip_traffic_test):                                             # noqa F811
    """Verify packet ingress from candidate ports are captured by EVERFLOW, while packets
    ingress from unselected ports are not captured
    """
    everflow_config = apply_acl_rule
    packet, exp_packet = generate_testing_packet(ptfadapter, setup_info[UP_STREAM]['everflow_dut'],
                                                 everflow_config['mirror_session_info'],
                                                 setup_info[UP_STREAM]['ingress_router_mac'], setup_info, ip_ver,
                                                 erspan_ip_ver)
    uplink_ports = everflow_config["monitor_port_ptf_ids"]

    # Verify that packet ingressed from INPUT_PORTS (candidate ports) are mirrored
    for port, ptf_idx in list(everflow_config['candidate_ports'].items()):
        logger.info("Verifying packet ingress from {} is mirrored".format(port))
        send_and_verify_packet(ptfadapter, packet, exp_packet, ptf_idx, uplink_ports, True)

    # Verify that packet ingressed from unselected ports are not mirrored
    for port, ptf_idx in list(everflow_config['unselected_ports'].items()):
        logger.info("Verifying packet ingress from {} is not mirrored".format(port))
        send_and_verify_packet(ptfadapter, packet, exp_packet, ptf_idx, uplink_ports, False)


def test_everflow_packet_format(ptfadapter, setup_info, apply_acl_rule, tbinfo,  # noqa F811
                                toggle_all_simulator_ports_to_rand_selected_tor, ip_ver, erspan_ip_ver):  # noqa F811
    """Verify that mirrored packets do not contain VLAN tags or unexpected fields."""
    everflow_config = apply_acl_rule
    packet, exp_packet = generate_testing_packet(ptfadapter, setup_info[UP_STREAM]['everflow_dut'],
                                                 everflow_config['mirror_session_info'],
                                                 setup_info[UP_STREAM]['ingress_router_mac'], setup_info, ip_ver,
                                                 erspan_ip_ver)
    uplink_ports = everflow_config["monitor_port_ptf_ids"]

    # Send test packet
    candidate_port, ptf_idx = list(everflow_config['candidate_ports'].items())[0]
    logger.info(f"Sending test packet from candidate port {candidate_port}")
    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, pkt=packet, port_id=ptf_idx)

    # Capture mirrored packet
    logger.info("Capturing mirrored packet to verify format")
    res = testutils.verify_packet_any_port(ptfadapter,
                                           pkt=exp_packet,
                                           ports=uplink_ports,
                                           timeout=5)

    # Skip traffic test if the return value is true.
    # See tests.conftest.pytest_runtest_call and tests.common.plugins.ptfadapter.dummy_testutils.wrapped
    if res is True:
        logger.info("Skipped. Ptf.testutils is set to DummyTestUtils to skip traffic test.")
        return

    port_idx, raw_captured_packet = res
    # Ensure packet is not empty
    assert raw_captured_packet, "Captured packet is empty or None"

    captured_packet = Ether(raw_captured_packet)

    # Debugging: Print packet summary if assertions fail
    packet_summary = captured_packet.summary()

    # Ensure no VLAN tag
    assert not captured_packet.haslayer(Dot1Q), \
        f"Mirrored packet should not contain VLAN tag: {packet_summary}"

    # Check for unexpected MPLS headers
    assert not captured_packet.haslayer(MPLS), \
        f"Mirrored packet contains unexpected MPLS label: {packet_summary}"

    # Check for unexpected VXLAN encapsulation
    assert not captured_packet.haslayer(VXLAN), \
        f"Mirrored packet should not have VXLAN encapsulation: {packet_summary}"

    logger.info(f"Mirrored packet format verified: {packet_summary}")
