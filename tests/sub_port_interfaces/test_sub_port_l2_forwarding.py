import pytest
import random
import logging
import contextlib
import time
import tempfile

from scapy.layers.l2 import Dot1Q
from scapy.all import Ether
from ptf import testutils
from scapy.all import sniff
from tests.common import constants
from tests.common import utilities
from tests.common.helpers.assertions import pytest_assert


pytestmark = [
    pytest.mark.topology("t0")
]


PTF_PORT_MAPPING_MODE = "use_orig_interface"
PACKET_PAYLOAD_FINGERPRINT = "SUBPORTL2TESTING"
PACKET_SAVE_PATH = "/tmp/eth_packets.pcap"
PACKET_COUNT = 1000
TIME_WAIT_AFTER_SENDING_PACKET = 10


@pytest.fixture
def testbed_params(define_sub_ports_configuration, duthosts, rand_one_dut_hostname, tbinfo):
    """Collect test params."""
    testbed_params = define_sub_ports_configuration["sub_ports"].copy()
    duthost = duthosts[rand_one_dut_hostname]
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    for sub_port, config in list(testbed_params.items()):
        port, vlanid = sub_port.split(constants.VLAN_SUB_INTERFACE_SEPARATOR)
        config["port"] = port
        config["vlanid"] = vlanid
        config["neighbor_ptf_index"] = mg_facts["minigraph_ptf_indices"][port]
    return testbed_params


@pytest.fixture
def test_sub_port(testbed_params):
    """Select a test sub port."""
    test_sub_port = random.choice(list(testbed_params.keys()))
    logging.info("Select test sub port %s", test_sub_port)
    return test_sub_port


@pytest.fixture
def generate_eth_packets(test_sub_port, testbed_params, ptfadapter):
    """Generate Ethernet packets that will be sent to test sub port to verify L2 forwarding."""

    def _simple_tagged_eth_packet(eth_dst, eth_src, vlanid):
        pkt = Ether(src=eth_src, dst=eth_dst)
        pkt /= Dot1Q(vlan=vlanid)
        pkt /= ("0" * (60 - len(pkt)) + PACKET_PAYLOAD_FINGERPRINT)
        return pkt

    # first packet has a dummy MAC dst MAC, second packet has a broadcast dst MAC
    eth_dsts = ["00:01:02:03:04:05", "ff:ff:ff:ff:ff:ff"]

    # select the MAC address of a different sub port's neighbor server port as third packet dst MAC
    dst_sub_port = [_ for _ in testbed_params if testbed_params[test_sub_port]["port"] not in _][0]
    dst_port_neighbor_ptf_index = testbed_params[dst_sub_port]["neighbor_ptf_index"]
    dst_port_ptf_mac = ptfadapter.dataplane.get_mac(0, dst_port_neighbor_ptf_index)
    eth_dsts.append(dst_port_ptf_mac)

    # generate test packets
    test_port_neighbor_ptf_index = testbed_params[test_sub_port]["neighbor_ptf_index"]
    test_port_vlan_id = testbed_params[test_sub_port]["vlanid"]
    eth_src = ptfadapter.dataplane.get_mac(0, test_port_neighbor_ptf_index)

    packets = []
    for eth_dst in eth_dsts:
        packets.append(_simple_tagged_eth_packet(eth_src, eth_dst, int(test_port_vlan_id)))

    return packets


def test_sub_port_l2_forwarding(apply_config_on_the_dut, duthosts, rand_one_dut_hostname, test_sub_port,
                                generate_eth_packets, testbed_params, ptfadapter):
    """Verify sub port doesn't have L2 forwarding capability."""

    @contextlib.contextmanager
    def check_no_cpu_packets(duthost, port, packet_fingerprint):
        start_pcap = "tcpdump -i %s -w %s" % (port, PACKET_SAVE_PATH)
        stop_pcap = "pkill -f '%s'" % start_pcap
        start_pcap = "nohup %s &" % start_pcap

        duthost.shell(start_pcap)
        try:
            yield
        finally:
            time.sleep(1.0)
            duthost.shell(stop_pcap, module_ignore_errors=True)

        with tempfile.NamedTemporaryFile() as tmp_pcap:
            duthost.fetch(src=PACKET_SAVE_PATH, dest=tmp_pcap.name, flat=True)
            received_packets = sniff(offline=tmp_pcap.name)

        logging.debug("Packets received from port %s:", port)
        for i, pkt in enumerate(received_packets):
            logging.debug("%d: %s" % (i, utilities.dump_scapy_packet_show_output(pkt)))

        packets_with_fingerprint = [_ for _ in received_packets if packet_fingerprint in str(_)]
        pytest_assert(len(packets_with_fingerprint) == 0, "Received packets with fingerprint %s" % packet_fingerprint)

    def verify_no_packet_received(ptfadapter, ports, packet_fingerprint):
        for port in ports:
            for packet, _ in ptfadapter.dataplane.packet_queues[(0, port)]:
                if packet_fingerprint in packet:
                    logging.error("Received packet with fingerprint '%s' on port %s: %s\n", port, packet_fingerprint,
                                  packet)
                    pytest.fail("Received packet on port %s" % port)

    duthost = duthosts[rand_one_dut_hostname]
    packets = generate_eth_packets
    ptf_ports_to_check = list(set(_["neighbor_ptf_index"] for _ in list(testbed_params.values())))
    ptfadapter.dataplane.flush()
    for packet in packets:
        with check_no_cpu_packets(duthost, test_sub_port, PACKET_PAYLOAD_FINGERPRINT):
            testutils.send(ptfadapter, testbed_params[test_sub_port]["neighbor_ptf_index"], packet, count=PACKET_COUNT)
            time.sleep(TIME_WAIT_AFTER_SENDING_PACKET)
            verify_no_packet_received(ptfadapter, ptf_ports_to_check, PACKET_PAYLOAD_FINGERPRINT)
