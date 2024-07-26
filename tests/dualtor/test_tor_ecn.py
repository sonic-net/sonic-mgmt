"""
    Test cases :
    1. Verification of DSCP -> Q mapping
        1.1. During packet encapsulation while egressing out of standby and going to T1
        1.2. During packet decapsulation while egressing out of active and going to server
    2. ECN marking
        2.1. During packet encapsulation while egressing out of standby and going to T1
        2.2. During packet decapsulation while egressing out of active and going to server
    3. Stamping of ECN marking after packet encapsulation while egressing out of standby and going to T1
"""

import logging
import pytest
import random
import time
import contextlib
import re

from ptf import mask
from ptf import testutils
from scapy.all import Ether, IP
from tests.common.dualtor.dual_tor_mock import *                                # noqa F403
from tests.common.dualtor.dual_tor_utils import get_t1_ptf_ports
from tests.common.dualtor.dual_tor_utils import rand_selected_interface         # noqa F401
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor      # noqa F401
from tests.common.dualtor.tunnel_traffic_utils import tunnel_traffic_monitor    # noqa F401
from tests.common.utilities import is_ipv4_address
from tests.common.fixtures.ptfhost_utils import run_icmp_responder              # noqa F401
from tests.common.fixtures.ptfhost_utils import run_garp_service                # noqa F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses            # noqa F401
# Temporary work around to add skip_traffic_test fixture from duthost_utils
from tests.common.fixtures.duthost_utils import skip_traffic_test               # noqa F401
from tests.common.utilities import dump_scapy_packet_show_output
from tests.common.dualtor.tunnel_traffic_utils import derive_queue_id_from_dscp, derive_out_dscp_from_inner_dscp
from tests.common.dualtor.dual_tor_utils import config_active_active_dualtor_active_standby      # noqa F401
from tests.common.dualtor.dual_tor_utils import validate_active_active_dualtor_setup             # noqa F401
from tests.common.dualtor.dual_tor_utils import is_tunnel_qos_remap_enabled

pytestmark = [
    pytest.mark.topology("dualtor")
]

# The packet number for test
PACKET_NUM = 100


@contextlib.contextmanager
def stop_garp(ptfhost):
    """Temporarily stop garp service."""
    ptfhost.shell("supervisorctl stop garp_service")
    time.sleep(3)
    yield
    ptfhost.shell("supervisorctl start garp_service")


@pytest.fixture(scope="module", autouse=True)
def mock_common_setup_teardown(
    apply_mock_dual_tor_tables,
    apply_mock_dual_tor_kernel_configs,
    cleanup_mocked_configs,
    request
):
    request.getfixturevalue("run_garp_service")


@pytest.fixture(scope="function")
def setup_dualtor_tor_active(
    tbinfo, request
):
    if is_t0_mocked_dualtor(tbinfo):        # noqa F405
        request.getfixturevalue('apply_active_state_to_orchagent')
    else:
        request.getfixturevalue('toggle_all_simulator_ports_to_rand_selected_tor')


@pytest.fixture(scope="function")
def setup_dualtor_tor_standby(
    tbinfo, request
):
    if is_t0_mocked_dualtor(tbinfo):        # noqa F405
        request.getfixturevalue('apply_standby_state_to_orchagent')
    else:
        request.getfixturevalue('toggle_all_simulator_ports_to_rand_selected_tor')


def build_encapsulated_ip_packet(
    inner_dscp,
    rand_selected_interface,        # noqa F811
    ptfadapter,
    rand_selected_dut
):
    """
    Build the encapsulated packet to be sent from T1 to ToR.
    """
    tor = rand_selected_dut
    _, server_ips = rand_selected_interface
    server_ipv4 = server_ips["server_ipv4"].split("/")[0]
    config_facts = tor.get_running_config_facts()
    try:
        peer_ipv4_address = [dut_name["address_ipv4"] for dut_name in list(config_facts["PEER_SWITCH"].values())][0]
    except IndexError:
        raise ValueError("Failed to get peer ToR address from CONFIG_DB")

    tor_ipv4_address = [addr for addr in config_facts["LOOPBACK_INTERFACE"]["Loopback0"]
                        if is_ipv4_address(addr.split("/")[0])][0]
    tor_ipv4_address = tor_ipv4_address.split("/")[0]

    inner_ttl = random.choice(list(range(3, 65)))
    inner_ecn = random.choice(list(range(0, 3)))
    outer_dscp = derive_out_dscp_from_inner_dscp(tor, inner_dscp)
    outer_ecn = inner_ecn

    logging.info("Inner DSCP: {0:06b}, Inner ECN: {1:02b}".format(inner_dscp, inner_ecn))
    logging.info("Outer DSCP: {0:06b}, Outer ECN: {1:02b}".format(outer_dscp, outer_ecn))

    inner_packet = testutils.simple_ip_packet(
        ip_src="1.1.1.1",
        ip_dst=server_ipv4,
        ip_dscp=inner_dscp,
        ip_ttl=inner_ttl,
        ip_ecn=inner_ecn
    )[IP]
    packet = testutils.simple_ipv4ip_packet(
        eth_dst=tor.facts["router_mac"],
        eth_src=ptfadapter.dataplane.get_mac(0, 0),
        ip_src=peer_ipv4_address,
        ip_dst=tor_ipv4_address,
        ip_dscp=outer_dscp,
        ip_ttl=255,
        ip_ecn=outer_ecn,
        inner_frame=inner_packet
    )
    logging.info("the encapsulated packet to send:\n%s", dump_scapy_packet_show_output(packet))

    return packet


def build_non_encapsulated_ip_packet(
    dscp,
    rand_selected_interface,        # noqa F811
    ptfadapter,
    rand_selected_dut
):
    """
    Build the regular (non encapsulated) packet to be sent from T1 to ToR.
    """
    tor = rand_selected_dut
    _, server_ips = rand_selected_interface
    server_ipv4 = server_ips["server_ipv4"].split("/")[0]
    config_facts = tor.get_running_config_facts()
    try:
        peer_ipv4_address = [dut_name["address_ipv4"]       # noqa F841
                             for dut_name in list(config_facts["PEER_SWITCH"].values())][0]
    except IndexError:
        raise ValueError("Failed to get peer ToR address from CONFIG_DB")

    tor_ipv4_address = [addr for addr in config_facts["LOOPBACK_INTERFACE"]["Loopback0"]
                        if is_ipv4_address(addr.split("/")[0])][0]
    tor_ipv4_address = tor_ipv4_address.split("/")[0]

    ttl = random.choice(list(range(3, 65)))
    ecn = random.choice(list(range(0, 3)))
    logging.info("DSCP: {0:06b}, ECN: {1:02b}".format(dscp, ecn))

    packet = testutils.simple_ip_packet(
        eth_dst=tor.facts["router_mac"],
        eth_src=ptfadapter.dataplane.get_mac(0, 0),
        ip_src="1.1.1.1",
        ip_dst=server_ipv4,
        ip_dscp=dscp,
        ip_ecn=ecn,
        ip_ttl=ttl
     )
    logging.info("the regular IP packet to send:\n%s", dump_scapy_packet_show_output(packet))

    return packet


def get_ptf_server_intf_index(
    tor,
    tbinfo,
    iface
):
    """
    Get the index of ptf ToR-facing interface on ptf.
    """
    mg_facts = tor.get_extended_minigraph_facts(tbinfo)

    return mg_facts["minigraph_ptf_indices"][iface]


def build_expected_packet_to_server(
    encapsulated_packet
):
    """
    Build packet expected to be received by server from the tunnel packet.
    """
    inner_packet = encapsulated_packet[IP].payload[IP].copy()
    # use dummy mac address that will be ignored in mask
    inner_packet = Ether(src="aa:bb:cc:dd:ee:ff", dst="aa:bb:cc:dd:ee:ff") / inner_packet
    exp_pkt = mask.Mask(inner_packet)
    exp_pkt.set_do_not_care_scapy(Ether, "dst")
    exp_pkt.set_do_not_care_scapy(Ether, "src")
    exp_pkt.set_do_not_care_scapy(IP, "tos")
    exp_pkt.set_do_not_care_scapy(IP, "ttl")
    exp_pkt.set_do_not_care_scapy(IP, "chksum")

    return exp_pkt


def check_received_packet_on_expected_queue(
    duthosts,
    rand_one_dut_hostname,
    rand_selected_interface,        # noqa F811
    expected_queue
):
    """
    Check if received expected number of packets on expected queue
    """
    duthost = duthosts[rand_one_dut_hostname]
    queue_counter = duthost.shell('show queue counters {} | grep "UC"'.format(rand_selected_interface[0]))['stdout']
    logging.info('queue_counter:\n{}'.format(queue_counter))

    """
    regex search will look for following pattern in queue_counter o/p for interface
    ----------------------------------------------------------------------------_---
    Port           TxQ    Counter/pkts     Counter/bytes     Drop/pkts    Drop/bytes
    -----------  -----  --------------  ---------------  -----------  --------------
    Ethernet124    UC1             100             1000            0             0
    """
    # In case of other noise packets
    DIFF = 0.1
    result = re.findall(r'\S+\s+UC%d\s+(\d+)+\s+\S+\s+\S+\s+\S+' % expected_queue, queue_counter)

    if result:
        for number in result:
            if int(number) <= PACKET_NUM * (1 + DIFF) and int(number) >= PACKET_NUM:
                logging.info("the expected Queue : {} received expected numbers of packet {}"
                             .format(expected_queue, number))
                return True
        logging.debug("the expected Queue : {} did not receive expected numbers of packet : {}"
                      .format(expected_queue, PACKET_NUM))
        return False
    else:
        logging.debug("Could not find expected queue counter matches.")
    return False


def verify_ecn_on_received_packet(
    ptfadapter,
    exp_pkt,
    exp_ptf_port_index,
    exp_ecn
):
    """
    Verify ECN value on the received packet w.r.t expected packet
    """
    _, rec_pkt = testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=[exp_ptf_port_index], timeout=10)
    rec_pkt = Ether(rec_pkt)
    logging.info("received packet:\n%s", dump_scapy_packet_show_output(rec_pkt))

    rec_ecn = rec_pkt[IP].tos & 3

    if rec_ecn != exp_ecn:
        pytest.fail("the expected ECN: {0:02b} not matching with received ECN: {1:02b}".format(exp_ecn, rec_ecn))
    else:
        logging.info("the expected ECN: {0:02b} matching with received ECN: {1:02b}".format(exp_ecn, rec_ecn))


def skip_inner_dscp_2_6_on_nvidia(duthost, inner_dscp):
    if inner_dscp in [2, 6] and 'mellanox' in duthost.facts['asic_type']:
        pytest.skip("Skip the test for inner dscp 2 or 6 on Nvidia platforms.")


@pytest.mark.parametrize("inner_dscp", [3, 4, 2, 6])        # lossless queue is 3 or 4 or 2 or 6.
def test_dscp_to_queue_during_decap_on_active(
    inner_dscp, ptfhost, setup_dualtor_tor_active,
    request, rand_selected_interface, ptfadapter,           # noqa F811
    tbinfo, rand_selected_dut, tunnel_traffic_monitor,      # noqa F811
    duthosts, rand_one_dut_hostname, skip_traffic_test      # noqa F811
):
    """
    Test if DSCP to Q mapping for inner header is matching with outer header during decap on active
    """
    if is_tunnel_qos_remap_enabled(rand_selected_dut):
        skip_inner_dscp_2_6_on_nvidia(rand_selected_dut, inner_dscp)
    tor = rand_selected_dut
    encapsulated_packet = build_encapsulated_ip_packet(inner_dscp, rand_selected_interface,
                                                       ptfadapter, rand_selected_dut)
    iface, _ = rand_selected_interface

    exp_ptf_port_index = get_ptf_server_intf_index(tor, tbinfo, iface)
    exp_pkt = build_expected_packet_to_server(encapsulated_packet)

    # Clear queue counters
    duthost = duthosts[rand_one_dut_hostname]
    duthost.shell('sonic-clear queuecounters')
    logging.info("Clearing queue counters before starting traffic")

    if skip_traffic_test is True:
        logging.info("Skip following test due traffic test skipped")
        return
    with stop_garp(ptfhost):
        ptfadapter.dataplane.flush()
        ptf_t1_intf = random.choice(get_t1_ptf_ports(tor, tbinfo))
        logging.info("send encapsulated packet from ptf t1 interface %s", ptf_t1_intf)
        testutils.send(ptfadapter, int(ptf_t1_intf.strip("eth")), encapsulated_packet, count=PACKET_NUM)

        exp_tos = encapsulated_packet[IP].payload[IP].tos
        exp_dscp = exp_tos >> 2
        exp_queue = derive_queue_id_from_dscp(duthost, exp_dscp, False)

        _, rec_pkt = testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=[exp_ptf_port_index], timeout=10)
        rec_pkt = Ether(rec_pkt)
        logging.info("received decap packet:\n%s", dump_scapy_packet_show_output(rec_pkt))

        time.sleep(10)
        check_result = check_received_packet_on_expected_queue(duthosts, rand_one_dut_hostname,
                                                               rand_selected_interface, exp_queue)

        if not check_result:
            pytest.fail("the expected Queue : {} did not receive expected numbers of packet : {}"
                        .format(exp_queue, PACKET_NUM))
        else:
            logging.info("the expected Queue : {} received expected numbers of packet {}"
                         .format(exp_queue, PACKET_NUM))


@pytest.fixture(scope='module')
def write_standby(rand_selected_dut):
    file = "/usr/local/bin/write_standby.py"

    def runcmd():
        rand_selected_dut.shell(file)

    try:
        rand_selected_dut.shell("ls %s" % file)
        return runcmd
    except Exception:
        pytest.skip('file {} not found'.format(file))


@pytest.mark.parametrize("dscp", [3, 4, 2, 6])      # lossless queue is 3 or 4 or 2 or 6.
def test_dscp_to_queue_during_encap_on_standby(
    dscp,
    setup_dualtor_tor_standby,
    rand_selected_interface, ptfadapter,            # noqa F811
    tbinfo,
    rand_selected_dut,                              # noqa F811
    tunnel_traffic_monitor,                         # noqa F811
    duthosts,
    rand_one_dut_hostname,
    write_standby,
    setup_standby_ports_on_rand_selected_tor,       # noqa F811
    skip_traffic_test                               # noqa F811
):
    """
    Test if DSCP to Q mapping for outer header is matching with inner header during encap on standby
    """
    if is_tunnel_qos_remap_enabled(rand_selected_dut):
        skip_inner_dscp_2_6_on_nvidia(rand_selected_dut, dscp)
    write_standby()

    tor = rand_selected_dut
    non_encapsulated_packet = build_non_encapsulated_ip_packet(dscp, rand_selected_interface,
                                                               ptfadapter, rand_selected_dut)

    # Clear queue counters
    duthost = duthosts[rand_one_dut_hostname]
    duthost.shell('sonic-clear queuecounters')
    logging.info("Clearing queue counters before starting traffic")

    ptfadapter.dataplane.flush()
    ptf_t1_intf = random.choice(get_t1_ptf_ports(tor, tbinfo))
    logging.info("send IP packet from ptf t1 interface %s", ptf_t1_intf)
    if skip_traffic_test is True:
        logging.info("Skip following test due traffic test skipped")
        return
    with tunnel_traffic_monitor(tor, existing=True, packet_count=PACKET_NUM):
        testutils.send(ptfadapter, int(ptf_t1_intf.strip("eth")), non_encapsulated_packet, count=PACKET_NUM)


@pytest.mark.parametrize("inner_dscp", [3, 4, 2, 6])        # lossless queue is 3 or 4 or 2 or 6.
def test_ecn_during_decap_on_active(
    inner_dscp, ptfhost, setup_dualtor_tor_active,
    request, rand_selected_interface, ptfadapter,           # noqa F811
    tbinfo, rand_selected_dut, tunnel_traffic_monitor,      # noqa F811
    skip_traffic_test                                       # noqa F811
):
    """
    Test if the ECN stamping on inner header is matching with outer during decap on active
    """
    if is_tunnel_qos_remap_enabled(rand_selected_dut):
        skip_inner_dscp_2_6_on_nvidia(rand_selected_dut, inner_dscp)
    tor = rand_selected_dut
    encapsulated_packet = build_encapsulated_ip_packet(inner_dscp, rand_selected_interface,
                                                       ptfadapter, rand_selected_dut)
    iface, _ = rand_selected_interface

    exp_ptf_port_index = get_ptf_server_intf_index(tor, tbinfo, iface)
    exp_pkt = build_expected_packet_to_server(encapsulated_packet)

    ptf_t1_intf = random.choice(get_t1_ptf_ports(tor, tbinfo))
    logging.info("send encapsulated packet from ptf t1 interface %s", ptf_t1_intf)

    exp_tos = encapsulated_packet[IP].payload[IP].tos
    exp_ecn = exp_tos & 3

    if skip_traffic_test is True:
        logging.info("Skip following test due traffic test skipped")
        return
    with stop_garp(ptfhost):
        tor.shell("portstat -c")
        tor.shell("show arp")
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, int(ptf_t1_intf.strip("eth")), encapsulated_packet, count=PACKET_NUM)
        tor.shell("portstat -j")
        verify_ecn_on_received_packet(ptfadapter, exp_pkt, exp_ptf_port_index, exp_ecn)


@pytest.mark.parametrize("dscp", [3, 4, 2, 6])      # lossless queue is 3 or 4 or 2 or 6.
def test_ecn_during_encap_on_standby(
    dscp,
    setup_dualtor_tor_standby,
    rand_selected_interface, ptfadapter,                    # noqa F811
    tbinfo, rand_selected_dut, tunnel_traffic_monitor,      # noqa F811
    write_standby,
    setup_standby_ports_on_rand_selected_tor,               # noqa F811
    skip_traffic_test                                       # noqa F811
):
    """
    Test if the ECN stamping on outer header is matching with inner during encap on standby
    """
    if is_tunnel_qos_remap_enabled(rand_selected_dut):
        skip_inner_dscp_2_6_on_nvidia(rand_selected_dut, dscp)
    write_standby()

    tor = rand_selected_dut
    non_encapsulated_packet = build_non_encapsulated_ip_packet(dscp, rand_selected_interface,
                                                               ptfadapter, rand_selected_dut)

    ptf_t1_intf = random.choice(get_t1_ptf_ports(tor, tbinfo))
    logging.info("send IP packet from ptf t1 interface %s", ptf_t1_intf)
    if skip_traffic_test is True:
        logging.info("Skip following test due traffic test skipped")
        return
    with tunnel_traffic_monitor(tor, existing=True, packet_count=PACKET_NUM):
        testutils.send(ptfadapter, int(ptf_t1_intf.strip("eth")), non_encapsulated_packet, count=PACKET_NUM)
