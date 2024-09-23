import pprint
import logging
import pytest
import random

from ptf import testutils
from tests.common.dualtor.dual_tor_mock import *                                # noqa F403
from tests.common.dualtor.dual_tor_utils import mux_cable_server_ip
from tests.common.dualtor.tunnel_traffic_utils import tunnel_traffic_monitor    # noqa F401
from tests.common.fixtures.ptfhost_utils import run_icmp_responder              # noqa F401
from tests.common.fixtures.ptfhost_utils import run_garp_service                # noqa F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses            # noqa F401
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import dump_scapy_packet_show_output
from ptf.testutils import simple_icmp_packet


pytestmark = [
    pytest.mark.topology("dualtor")
]


ZERO_MAC_ADDR = "00:00:00:00:00:00"


@pytest.fixture(scope="function")
def send_zero_mac_packets(ptfadapter, rand_selected_dut, tbinfo):
    """Utility fixture to send packets with zero source mac address from multiple ports."""

    def _send_zero_mac_packets(test_ports):
        dut_to_ptf_intf_map = rand_selected_dut.get_extended_minigraph_facts(tbinfo)['minigraph_ptf_indices']
        for dut_iface in test_ports:
            ptf_iface = dut_to_ptf_intf_map[dut_iface]
            dut_mac = rand_selected_dut.get_dut_iface_mac(dut_iface)
            icmp_pkt = simple_icmp_packet(
                eth_dst=dut_mac,
                eth_src=ZERO_MAC_ADDR,
                ip_src="10.0.0.1",
                ip_dst="10.0.0.2",
                icmp_type=8,
                icmp_code=0,
                ip_ttl=64
            )
            logging.info("Send ICMP packet with zero source MAC from port %s:\n%s",
                         dut_iface, dump_scapy_packet_show_output(icmp_pkt))
            testutils.send(ptfadapter, int(ptf_iface), icmp_pkt, count=5)
            # let the generator stops here to allow the caller to execute testings
            yield

    return _send_zero_mac_packets


def test_zero_src_mac_handling(send_zero_mac_packets, apply_active_state_to_orchagent,
                               conn_graph_facts, ptfadapter, ptfhost, rand_selected_dut,
                               set_crm_polling_interval, tbinfo, tunnel_traffic_monitor, vmhost):
    tor = rand_selected_dut
    # select two random mux ports for testing
    mux_configs = mux_cable_server_ip(tor)
    test_ports = random.sample(list(mux_configs.keys()),2)
    logging.info("Selected test ports: %s", pprint.pformat(test_ports))
    # send zero source MAC ICMP packets from the selected ports
    zero_mac_packet_sender = send_zero_mac_packets(test_ports)
    next(zero_mac_packet_sender)  # Call the generator to send packets
    # verify MAC table doesn't contain zero MAC
    mac_table = tor.shell("show mac")
    logging.info("MAC table: %s", pprint.pformat(mac_table))
    pytest_assert(ZERO_MAC_ADDR not in mac_table["stdout"], "MAC table contains zero source MAC address")
    logging.info("Zero source MAC handling test completed.")


