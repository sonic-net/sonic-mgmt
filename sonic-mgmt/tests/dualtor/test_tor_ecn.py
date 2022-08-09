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

from ptf import mask
from ptf import testutils
from scapy.all import Ether, IP
from tests.common.dualtor.dual_tor_mock import *
from tests.common.dualtor.dual_tor_utils import get_t1_ptf_ports
from tests.common.dualtor.dual_tor_utils import rand_selected_interface
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor
from tests.common.dualtor.tunnel_traffic_utils import tunnel_traffic_monitor
from tests.common.utilities import is_ipv4_address
from tests.common.fixtures.ptfhost_utils import run_icmp_responder
from tests.common.fixtures.ptfhost_utils import run_garp_service
from tests.common.fixtures.ptfhost_utils import change_mac_addresses
from tests.common.utilities import dump_scapy_packet_show_output
from tests.common.dualtor.tunnel_traffic_utils import derive_queue_id_from_dscp

pytestmark = [
    pytest.mark.topology("t0")
]

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
    if is_t0_mocked_dualtor(tbinfo):
        request.getfixturevalue('apply_active_state_to_orchagent')
    else:
        request.getfixturevalue('toggle_all_simulator_ports_to_rand_selected_tor')

@pytest.fixture(scope="function")
def setup_dualtor_tor_standby(
    tbinfo, request
):
    if is_t0_mocked_dualtor(tbinfo):
        request.getfixturevalue('apply_standby_state_to_orchagent')
    else:
        request.getfixturevalue('toggle_all_simulator_ports_to_rand_selected_tor')

@pytest.fixture(scope="function")
def build_encapsulated_ip_packet(
    rand_selected_interface, 
    ptfadapter, 
    rand_selected_dut, 
    tunnel_traffic_monitor
):
    """
    Build the encapsulated packet to be sent from T1 to ToR.
    """
    tor = rand_selected_dut
    _, server_ips = rand_selected_interface
    server_ipv4 = server_ips["server_ipv4"].split("/")[0]
    config_facts = tor.get_running_config_facts()
    try:
        peer_ipv4_address = [dut_name["address_ipv4"] for dut_name in config_facts["PEER_SWITCH"].values()][0]
    except IndexError:
        raise ValueError("Failed to get peer ToR address from CONFIG_DB")

    tor_ipv4_address = [addr for addr in config_facts["LOOPBACK_INTERFACE"]["Loopback0"]
                        if is_ipv4_address(addr.split("/")[0])][0]
    tor_ipv4_address = tor_ipv4_address.split("/")[0]

    inner_dscp = random.choice(range(0, 33))
    inner_ttl = random.choice(range(3, 65))
    inner_ecn = random.choice(range(0,3))

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
        ip_dscp=inner_dscp,
        ip_ttl=255,
        ip_ecn=inner_ecn,
        inner_frame=inner_packet
    )
    logging.info("the encapsulated packet to send:\n%s", dump_scapy_packet_show_output(packet))

    return packet

@pytest.fixture(scope="function")
def build_non_encapsulated_ip_packet(
    rand_selected_interface, 
    ptfadapter, 
    rand_selected_dut, 
    tunnel_traffic_monitor
):
    """
    Build the regular (non encapsulated) packet to be sent from T1 to ToR.
    """
    tor = rand_selected_dut
    _, server_ips = rand_selected_interface
    server_ipv4 = server_ips["server_ipv4"].split("/")[0]
    config_facts = tor.get_running_config_facts()
    try:
        peer_ipv4_address = [dut_name["address_ipv4"] for dut_name in config_facts["PEER_SWITCH"].values()][0]
    except IndexError:
        raise ValueError("Failed to get peer ToR address from CONFIG_DB")

    tor_ipv4_address = [addr for addr in config_facts["LOOPBACK_INTERFACE"]["Loopback0"]
                        if is_ipv4_address(addr.split("/")[0])][0]
    tor_ipv4_address = tor_ipv4_address.split("/")[0]

    dscp = random.choice(range(0, 33))
    ttl = random.choice(range(3, 65))
    ecn = random.choice(range(0,3))

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

def get_queue_id_of_received_packet(
    duthosts, 
    rand_one_dut_hostname, 
    rand_selected_interface
):
    """
    Get queue id of the packet received on destination
    """
    duthost = duthosts[rand_one_dut_hostname]
    queue_counter = duthost.shell('show queue counters {} | grep "UC"'.format(rand_selected_interface[0]))['stdout']
    logging.info('queue_counter:\n{}'.format(queue_counter))

    """ 
    regex search will look for following pattern in queue_counter o/p for interface
    ----------------------------------------------------------------------------_---
    Port           TxQ    Counter/pkts     Counter/bytes     Drop/pkts    Drop/bytes
    -----------  -----  --------------  ---------------  -----------  --------------
    Ethernet124    UC1              10             1000            0             0
    """
    result = re.search(r'\S+\s+UC\d\s+10+\s+\S+\s+\S+\s+\S+', queue_counter)

    if result is not None:
        output = result.group(0)
        output_list = output.split()
        queue = int(output_list[1][2])
    else:
        logging.info("Error occured while fetching queue counters from DUT")
        return None

    return queue

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

    rec_dscp = rec_pkt[IP].tos >> 2
    rec_ecn = rec_pkt[IP].tos & 3

    if rec_ecn != exp_ecn:
        pytest.fail("the expected ECN: {0:02b} not matching with received ECN: {0:02b}".format(exp_ecn, rec_ecn))
    else:
        logging.info("the expected ECN: {0:02b} matching with received ECN: {0:02b}".format(exp_ecn, rec_ecn))

def test_dscp_to_queue_during_decap_on_active(
    ptfhost, setup_dualtor_tor_active,
    build_encapsulated_ip_packet, request,
    rand_selected_interface, ptfadapter,
    tbinfo, rand_selected_dut, tunnel_traffic_monitor, 
    duthosts, rand_one_dut_hostname
):
    """
    Test if DSCP to Q mapping for inner header is matching with outer header during decap on active
    """
    tor = rand_selected_dut
    encapsulated_packet = build_encapsulated_ip_packet
    iface, _ = rand_selected_interface

    exp_ptf_port_index = get_ptf_server_intf_index(tor, tbinfo, iface)
    exp_pkt = build_expected_packet_to_server(encapsulated_packet)

    # Clear queue counters
    duthost = duthosts[rand_one_dut_hostname]
    duthost.shell('sonic-clear queuecounters')
    logging.info("Clearing queue counters before starting traffic")

    with stop_garp(ptfhost):
        ptfadapter.dataplane.flush()
        ptf_t1_intf = random.choice(get_t1_ptf_ports(tor, tbinfo))
        logging.info("send encapsulated packet from ptf t1 interface %s", ptf_t1_intf)
        testutils.send(ptfadapter, int(ptf_t1_intf.strip("eth")), encapsulated_packet, count=10)

        exp_tos = encapsulated_packet[IP].payload[IP].tos
        exp_dscp = exp_tos >> 2
        exp_queue = derive_queue_id_from_dscp(exp_dscp)

        _, rec_pkt = testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=[exp_ptf_port_index], timeout=10)
        rec_pkt = Ether(rec_pkt)
        logging.info("received decap packet:\n%s", dump_scapy_packet_show_output(rec_pkt))

        time.sleep(10)
        rec_queue = get_queue_id_of_received_packet(duthosts, rand_one_dut_hostname, rand_selected_interface)

        if rec_queue == None or rec_queue != exp_queue:
            pytest.fail("the expected Queue : {} not matching with received Queue : {}".format(exp_queue, rec_queue))
        else:
            logging.info("the expected Queue : {} matching with received Queue : {}".format(exp_queue, rec_queue))

@pytest.fixture(scope='module')
def write_standby(rand_selected_dut):
    file = "/usr/local/bin/write_standby.py"
    def runcmd():
        rand_selected_dut.shell(file)

    try:
        rand_selected_dut.shell("ls %s" % file)
        return runcmd
    except:
        pytest.skip('file {} not found'.format(file))

def test_dscp_to_queue_during_encap_on_standby(
    setup_dualtor_tor_standby,
    build_non_encapsulated_ip_packet,
    rand_selected_interface, ptfadapter,
    tbinfo, 
    rand_selected_dut, 
    tunnel_traffic_monitor, 
    duthosts, 
    rand_one_dut_hostname,
    write_standby
):
    """
    Test if DSCP to Q mapping for outer header is matching with inner header during encap on standby
    """
    write_standby()

    tor = rand_selected_dut
    non_encapsulated_packet = build_non_encapsulated_ip_packet
    iface, _ = rand_selected_interface

    exp_ptf_port_index = get_ptf_server_intf_index(tor, tbinfo, iface)

    # Clear queue counters
    duthost = duthosts[rand_one_dut_hostname]
    duthost.shell('sonic-clear queuecounters')
    logging.info("Clearing queue counters before starting traffic")

    ptfadapter.dataplane.flush()
    ptf_t1_intf = random.choice(get_t1_ptf_ports(tor, tbinfo))
    logging.info("send IP packet from ptf t1 interface %s", ptf_t1_intf)
    with tunnel_traffic_monitor(tor, existing=True):
       testutils.send(ptfadapter, int(ptf_t1_intf.strip("eth")), non_encapsulated_packet, count=10)

def test_ecn_during_decap_on_active(
    ptfhost, setup_dualtor_tor_active,
    build_encapsulated_ip_packet, request,
    rand_selected_interface, ptfadapter,
    tbinfo, rand_selected_dut, tunnel_traffic_monitor
):
    """
    Test if the ECN stamping on inner header is matching with outer during decap on active
    """
    tor = rand_selected_dut
    encapsulated_packet = build_encapsulated_ip_packet
    iface, _ = rand_selected_interface

    exp_ptf_port_index = get_ptf_server_intf_index(tor, tbinfo, iface)
    exp_pkt = build_expected_packet_to_server(encapsulated_packet)

    ptf_t1_intf = random.choice(get_t1_ptf_ports(tor, tbinfo))
    logging.info("send encapsulated packet from ptf t1 interface %s", ptf_t1_intf)

    exp_tos = encapsulated_packet[IP].payload[IP].tos
    exp_ecn = exp_tos & 3
    with stop_garp(ptfhost):
        tor.shell("portstat -c")
        tor.shell("show arp")
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, int(ptf_t1_intf.strip("eth")), encapsulated_packet, count=10)
        tor.shell("portstat -j")
        verify_ecn_on_received_packet(ptfadapter, exp_pkt, exp_ptf_port_index, exp_ecn)

def test_ecn_during_encap_on_standby(
    setup_dualtor_tor_standby,
    build_non_encapsulated_ip_packet,
    rand_selected_interface, ptfadapter,
    tbinfo, rand_selected_dut, tunnel_traffic_monitor,
    write_standby
):
    """
    Test if the ECN stamping on outer header is matching with inner during encap on standby
    """
    write_standby()

    tor = rand_selected_dut
    non_encapsulated_packet = build_non_encapsulated_ip_packet
    iface, _ = rand_selected_interface

    exp_ptf_port_index = get_ptf_server_intf_index(tor, tbinfo, iface)

    ptf_t1_intf = random.choice(get_t1_ptf_ports(tor, tbinfo))
    logging.info("send IP packet from ptf t1 interface %s", ptf_t1_intf)
    with tunnel_traffic_monitor(tor, existing=True):
        testutils.send(ptfadapter, int(ptf_t1_intf.strip("eth")), non_encapsulated_packet, count=10)
