import logging
import pytest
import time
from tests.common.helpers.assertions import pytest_require, pytest_assert
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_lower_tor # lgtm[py/unused-import]
from tests.common.dualtor.dual_tor_utils import upper_tor_host, lower_tor_host, dualtor_info, get_t1_active_ptf_ports, is_tunnel_qos_remap_enabled
from tests.common.fixtures.ptfhost_utils import change_mac_addresses, run_icmp_responder, run_garp_service # lgtm[py/unused-import]
import ptf.packet as scapy
from ptf.mask import Mask
from ptf import testutils
from ptf.testutils import simple_tcp_packet, simple_ipv4ip_packet

pytestmark = [
    pytest.mark.topology('t0')
]

logger = logging.getLogger(__name__)

SERVER_IP = "192.168.0.2"
DUMMY_IP = "1.1.1.1"
DUMMY_MAC = "aa:aa:aa:aa:aa:aa"

@pytest.fixture(scope='module', autouse=True)
def check_running_condition(tbinfo, duthost):
    """
    The test can only be running on tunnel_qos_remap enabled dualtor testbed
    """
    # Check dualtor topo
    pytest_require("dualtor" in tbinfo["topo"]["name"], "Only run on dualtor testbed.", True)
    
    # Check tunnel_qos_remap is enabled
    pytest_require(is_tunnel_qos_remap_enabled(duthost), "Only run when tunnel_qos_remap is enabled", True)


def _build_testing_packet(src_ip, dst_ip, active_tor_mac, standby_tor_mac, active_tor_ip, standby_tor_ip, inner_dscp, outer_dscp, ecn=1):
    pkt = simple_tcp_packet(
                eth_dst=standby_tor_mac,
                ip_src=src_ip,
                ip_dst=dst_ip,
                ip_dscp=inner_dscp,
                ip_ecn=ecn,
                ip_ttl=64
            )
    # The ttl of inner_frame is decreased by 1
    pkt.ttl -= 1
    ipinip_packet = simple_ipv4ip_packet(
                eth_dst=active_tor_mac,
                eth_src=standby_tor_mac,
                ip_src=standby_tor_ip,
                ip_dst=active_tor_ip,
                ip_dscp=outer_dscp,
                ip_ecn=ecn,
                inner_frame=pkt[IP]
            )
    pkt.ttl += 1
    exp_tunnel_pkt = Mask(ipinip_packet)
    exp_tunnel_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
    exp_tunnel_pkt.set_do_not_care_scapy(scapy.Ether, "src")
    exp_tunnel_pkt.set_do_not_care_scapy(scapy.IP, "id") # since src and dst changed, ID would change too
    exp_tunnel_pkt.set_do_not_care_scapy(scapy.IP, "ttl") # ttl in outer packet is set to 255
    exp_tunnel_pkt.set_do_not_care_scapy(scapy.IP, "chksum") # checksum would differ as the IP header is not the same

    return pkt, exp_tunnel_pkt


def test_encap_dscp_rewrite(ptfhost, upper_tor_host, lower_tor_host, toggle_all_simulator_ports_to_lower_tor, tbinfo, ptfadapter):
    """
    The test is to verify the dscp rewriting of encapped packets.
    Test steps
    1. Toggle mux to lower tor, so all mux ports are standby on upper_tor
    2. Generate packets with certain DSCP value
    3. Send the generated packets via portchannels
    4. Verify the packets are encapped with expected DSCP value 
    """
    DSCP_COMBINATIONS = [
        # DSCP in generated packets, expected DSCP in encapped packets
        (8, 8),
        (0, 0),
        (33, 33),
        (3, 2),
        (4, 6),
        (46, 46),
        (48, 48)
    ]
    dualtor_meta = dualtor_info(ptfhost, upper_tor_host, lower_tor_host, tbinfo)
    active_tor_mac = lower_tor_host.facts['router_mac']
    
    t1_ports = get_t1_active_ptf_ports(upper_tor_host, tbinfo)
    # Always select the first port in first LAG as src_port
    src_port = list(t1_ports.values())[0][0]
    dst_ports = []
    for ports in t1_ports.values():
        dst_ports.extend(ports)

    for dscp_combination in DSCP_COMBINATIONS:
        pkt, expected_pkt = _build_testing_packet(src_ip=DUMMY_IP,
                                                  dst_ip=SERVER_IP,
                                                  active_tor_mac=active_tor_mac,
                                                  standby_tor_mac=dualtor_meta['standby_tor_mac'],
                                                  active_tor_ip=dualtor_meta['active_tor_ip'],
                                                  standby_tor_ip=dualtor_meta['standby_tor_ip'],
                                                  inner_dscp=dscp_combination[0],
                                                  outer_dscp=dscp_combination[1],
                                                  ecn=1)
        ptfadapter.dataplane.flush()
        # Send original packet
        testutils.send(ptfadapter, src_port, pkt)
        # Verify encaped packet
        testutils.verify_packet_any_port(ptfadapter, expected_pkt, dst_ports)

def _check_queue_counter(duthost, intfs, queue, counter):
    output = duthost.shell('show queue counters')['stdout_lines']

    for intf in intfs:
        for line in output:
            fields = line.split()
            if len(fields) == 6 and fields[0] == intf and fields[1] == 'UC{}'.format(queue):
                if int(fields[2]) >= counter:
                    return True
    
    return False

def test_bounced_back_traffic_in_expected_queue(ptfhost, upper_tor_host, lower_tor_host, toggle_all_simulator_ports_to_lower_tor, tbinfo, ptfadapter):
    """
    The test case is to verify the encapped packet is mapped to the correct queue
    Test steps:
    1. Toggle mux to lower tor, so all mux ports are standby on upper_tor
    2. Generate packets with certain DSCP value
    3. Send the generated packets via portchannels
    4. Verify the packets are outgoing from expected queue 
    """
    TEST_DATA = [
        #DSCP QUEUE
        (8, 0),
        (0, 1),
        (33, 1),
        (3, 2),
        (4, 6),
        (46, 5),
        (48, 7)
    ]
    dualtor_meta = dualtor_info(ptfhost, upper_tor_host, lower_tor_host, tbinfo)
    active_tor_mac = lower_tor_host.facts['router_mac']
    t1_ports = get_t1_active_ptf_ports(upper_tor_host, tbinfo)
    # Always select the first port in first LAG as src_port
    src_port = list(t1_ports.values())[0][0]
    mg_facts = upper_tor_host.get_extended_minigraph_facts(tbinfo)
    portchannel_info = mg_facts['minigraph_portchannels']
    tor_pc_intfs = list()
    for pc in portchannel_info.values():
        for member in pc['members']:
            tor_pc_intfs.append(member)
    PKT_NUM = 100

    for dscp, queue in TEST_DATA:
        pkt, _ = _build_testing_packet(src_ip=DUMMY_IP,
                                        dst_ip=SERVER_IP,
                                        active_tor_mac=active_tor_mac,
                                        standby_tor_mac=dualtor_meta['standby_tor_mac'],
                                        active_tor_ip=dualtor_meta['active_tor_ip'],
                                        standby_tor_ip=dualtor_meta['standby_tor_ip'],
                                        inner_dscp=dscp,
                                        outer_dscp=0,
                                        ecn=1)
        # Clear queuecounters before sending traffic
        upper_tor_host.shell('sonic-clear queuecounters')
        # Send original packet
        testutils.send_packet(ptfadapter, src_port, pkt, PKT_NUM)
        # Verify queue counters in all possible interfaces
        time.sleep(15)

        pytest_assert(_check_queue_counter(upper_tor_host, tor_pc_intfs, queue, PKT_NUM),
                         "The queue counter for DSCP {} Queue {} is not as expected".format(dscp, queue))

