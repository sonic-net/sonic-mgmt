import time
import logging
import pytest
import ptf.packet as scapy
import json
from tests.common.helpers.assertions import pytest_assert
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_upper_tor  # noqa F401
from tests.common.dualtor.mux_simulator_control import toggle_simulator_port_to_lower_tor  # noqa F401
from tests.common.dualtor.dual_tor_utils import \
    upper_tor_host, lower_tor_host, dualtor_info, check_muxcable_status  # noqa F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses, run_icmp_responder, run_garp_service  # noqa F401
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor # noqa F401
from ptf.mask import Mask
from ptf import testutils
from tests.common.utilities import wait_until
from ptf.testutils import simple_tcp_packet, simple_ipv4ip_packet
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure

pytestmark = [
    pytest.mark.topology('dualtor')
]

logger = logging.getLogger(__name__)

PKT_NUM = 2000
PKT_COUNTER_MARGIN_PERCENT = 0.1  # The margin is used to ignore the background packets.
COUNTER_RANGE = [PKT_NUM * 2, PKT_NUM * 2 * (1 + PKT_COUNTER_MARGIN_PERCENT)]
COUNTER_ZERO = [0, PKT_NUM * PKT_COUNTER_MARGIN_PERCENT]

# Nvidia uses egress drop instead of ingress drop for the upstream traffic when the port is standby.
# These two test cases are to cover the test gap introduced by the egress drop.


@pytest.fixture(scope="module", autouse=True)
def skip_non_nvidia_platforms(lower_tor_host): # noqa F811
    if "mellanox" != lower_tor_host.facts["asic_type"]:
        pytest.skip("This test is only for Nvidia platforms.")

def test_egress_drop_standby_server_to_active_server(ptfhost, upper_tor_host, lower_tor_host, # noqa F811
                                 toggle_all_simulator_ports_to_upper_tor, # noqa F811
                                 toggle_simulator_port_to_lower_tor, tbinfo, ptfadapter): # noqa F811
    """
    This test case covers the validation of egress drop rule in active-standby dualtor scenario when server A is active
    on the upper tor and standby on the lower tor, server B is standby on the upper tor and active on the lower tor, and
    the upstream traffic is sent from server A to server B.

    When the upstream traffic from server A to server B is sent, the traffic on the upper tor will be bounced
    back to the lower tor and then sent to the server B through the active port.

    And the traffic on the lower tor should be dropped by the egress drop acl rule because the server A port
    on the lower tor is standby.
    """
    with allure.step("Prepare test parameters"):
        dualtor_meta = dualtor_info(ptfhost, upper_tor_host, lower_tor_host, tbinfo)
        lower_tor_mg_facts = lower_tor_host.get_extended_minigraph_facts(tbinfo)
        vlan_interface = list(lower_tor_mg_facts['minigraph_vlans'].keys())[0]
        # use the last port as the active port on lower tor
        lower_tor_active_port = lower_tor_mg_facts['minigraph_vlans'][vlan_interface]['members'][-1]
        lower_tor_active_server = lower_tor_mg_facts['minigraph_neighbors'][lower_tor_active_port]['name']
        lower_tor_active_server_ip = lower_tor_mg_facts['minigraph_devices'][lower_tor_active_server]['lo_addr']
        lower_tor_active_server_ptf_port = lower_tor_mg_facts['minigraph_ptf_indices'][lower_tor_active_port]

        lower_tor_t1_ptf_ports = []
        lower_tor_vlan_ptf_ports = []
        for portchannel in lower_tor_mg_facts['minigraph_portchannels'].values():
            for member in portchannel['members']:
                ptf_indice = lower_tor_mg_facts['minigraph_ptf_indices'][member]
                lower_tor_t1_ptf_ports.append(ptf_indice)
        # use the first standby server on lower tor
        lower_tor_vlan_ports = lower_tor_mg_facts['minigraph_vlans'][vlan_interface]['members']
        for vlan_port in lower_tor_vlan_ports:
            lower_tor_vlan_ptf_ports.append(lower_tor_mg_facts['minigraph_ptf_indices'][vlan_port])
        lower_tor_standby_port = lower_tor_mg_facts['minigraph_vlans'][vlan_interface]['members'][0]
        lower_tor_standby_server_ptf_port = lower_tor_mg_facts['minigraph_ptf_indices'][lower_tor_standby_port]

    with allure.step("Switch the last server on the lower tor to active"):
        toggle_simulator_port_to_lower_tor(lower_tor_active_port)
        wait_until(10, 5, 0, check_muxcable_status, upper_tor_host, lower_tor_active_port, "standby")
        wait_until(10, 5, 0, check_muxcable_status, lower_tor_host, lower_tor_active_port, "active")

    with allure.step("Clear port counters"):
        upper_tor_host.command("sonic-clear counters")
        lower_tor_host.command("sonic-clear counters")

    with allure.step("Start the traffic test, "
                     "check the traffic received by the last server is the bounced back traffic from the upper tor"):
        pkt = simple_tcp_packet(
            eth_dst=dualtor_meta['vlan_mac'],
            ip_src='1.1.1.1',
            ip_dst=lower_tor_active_server_ip,
            ip_ttl=64
        )
        # Send packets
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, lower_tor_standby_server_ptf_port, pkt, PKT_NUM)
        # The ttl of the bounced back packet should be decreased by 2
        pkt.ttl -= 2
        expected_packet = get_masked_packet(pkt)
        # Check the bounced back packet is received by the last server ptf port
        testutils.verify_packet(ptfadapter, expected_packet, lower_tor_active_server_ptf_port)
        pkt.ttl += 2

        # Send the packets again
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, lower_tor_standby_server_ptf_port, pkt, PKT_NUM)
        # The ttl of the packet directly forwarded by the lower tor should be decreased by 1
        pkt.ttl -= 1
        not_expected_packet = get_masked_packet(pkt)
        # Check there is no such packet received by any ptf ports
        testutils.verify_no_packet_any(
            ptfadapter, not_expected_packet, lower_tor_t1_ptf_ports + lower_tor_vlan_ptf_ports)

    with allure.step("Check the port counters to make sure the drop on lower tor happened"):
        # There are in total 2 * PKT_NUM packets sent, the tx counter value of the last server port on the lower tor
        # should be slightly lager than 2 * PKT_NUM, which means no duplicated packets are received by the server.

        def _check_counters():
            upper_tor_port_counters = json.loads(upper_tor_host.get_port_counters(in_json=True))
            lower_tor_port_counters = json.loads(lower_tor_host.get_port_counters(in_json=True))
            upper_tor_active_port_rx_counter = int(
                upper_tor_port_counters[lower_tor_standby_port]['RX_OK'].replace(',', ''))
            upper_tor_standby_port_tx_counter = int(
                upper_tor_port_counters[lower_tor_active_port]['TX_OK'].replace(',', ''))
            lower_tor_standby_port_rx_counter = int(
                lower_tor_port_counters[lower_tor_standby_port]['RX_OK'].replace(',', ''))
            lower_tor_active_port_tx_counter = int(
                lower_tor_port_counters[lower_tor_active_port]['TX_OK'].replace(',', ''))
            logger.info(
                f'upper_tor_active_port_rx_counter: {upper_tor_active_port_rx_counter}, '
                f'upper_tor_standby_port_tx_counter: {upper_tor_standby_port_tx_counter}, '
                f'lower_tor_standby_port_rx_counter: {lower_tor_standby_port_rx_counter}, '
                f'lower_tor_active_port_tx_counter: {lower_tor_active_port_tx_counter}')
            return (COUNTER_RANGE[0] <= upper_tor_active_port_rx_counter < COUNTER_RANGE[1]
                    and COUNTER_ZERO[0] <= upper_tor_standby_port_tx_counter < COUNTER_ZERO[1]
                    and COUNTER_RANGE[0] <= lower_tor_standby_port_rx_counter < COUNTER_RANGE[1]
                    and COUNTER_RANGE[0] <= lower_tor_active_port_tx_counter < COUNTER_RANGE[1])
        pytest_assert(wait_until(15, 5, 0, _check_counters), "The port counters are not as expected.")

def test_egress_drop_standby_server_to_standby_server(ptfhost, upper_tor_host, lower_tor_host, # noqa F811
                                 toggle_all_simulator_ports_to_upper_tor, tbinfo, ptfadapter): # noqa F811
    """
    This test case covers the validation of egress drop rule in active-standby dualtor scenario when server A and
    server B are active on the upper tor, and standby on the lower tor, and the upstream traffic is sent from
    server A to server B.

    When the upstream traffic from server A to server B is sent, the traffic on the upper tor will be directly forwarded
    to server B. The traffic on the lower tor should be dropped by the egress drop acl rule.
    """
    with allure.step("Prepare test parameters"):
        dualtor_meta = dualtor_info(ptfhost, upper_tor_host, lower_tor_host, tbinfo)
        upper_tor_mg_facts = upper_tor_host.get_extended_minigraph_facts(tbinfo)
        lower_tor_mg_facts = lower_tor_host.get_extended_minigraph_facts(tbinfo)
        vlan_interface = list(lower_tor_mg_facts['minigraph_vlans'].keys())[0]
        # Use the first standby server on lower tor as the source server
        lower_tor_source_port = lower_tor_mg_facts['minigraph_vlans'][vlan_interface]['members'][0]
        lower_tor_source_server_ptf_port = lower_tor_mg_facts['minigraph_ptf_indices'][lower_tor_source_port]
        # use the last port as the target port on lower tor
        lower_tor_target_port = lower_tor_mg_facts['minigraph_vlans'][vlan_interface]['members'][-1]
        lower_tor_target_server = lower_tor_mg_facts['minigraph_neighbors'][lower_tor_target_port]['name']
        lower_tor_target_server_ip = lower_tor_mg_facts['minigraph_devices'][lower_tor_target_server]['lo_addr']
        lower_tor_target_server_ptf_port = lower_tor_mg_facts['minigraph_ptf_indices'][lower_tor_target_port]
        upper_tor_host_name = upper_tor_mg_facts['inventory_hostname']
        lower_tor_host_name = lower_tor_mg_facts['inventory_hostname']
        upper_tor_loopback0_ip = upper_tor_mg_facts['minigraph_devices'][upper_tor_host_name]['lo_addr']
        lower_tor_loopback0_ip = lower_tor_mg_facts['minigraph_devices'][lower_tor_host_name]['lo_addr']
        lower_tor_uplink_ports = []
        lower_tor_uplink_ptf_ports = []
        for portchannel in lower_tor_mg_facts['minigraph_portchannels'].values():
            for member in portchannel['members']:
                lower_tor_uplink_ports.append(member)
                ptf_indice = lower_tor_mg_facts['minigraph_ptf_indices'][member]
                lower_tor_uplink_ptf_ports.append(ptf_indice)
        lower_tor_vlan_ports = lower_tor_mg_facts['minigraph_vlans'][vlan_interface]['members']

    with allure.step("Clear port counters"):
        lower_tor_host.command("sonic-clear counters")

    with allure.step("Start the traffic test"):
        pkt = simple_tcp_packet(
            eth_dst=dualtor_meta['vlan_mac'],
            ip_src='1.1.1.1',
            ip_dst=lower_tor_target_server_ip,
            ip_ttl=64
        )
        # Send packets
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, lower_tor_source_server_ptf_port, pkt, PKT_NUM)
        # The packets can be forwarded by the upper tor to the target server
        pkt.ttl -= 1
        expected_packet = get_masked_packet(pkt)
        # Check the expected packets are received by the server ptf port
        testutils.verify_packet(ptfadapter, expected_packet, lower_tor_target_server_ptf_port)

        # There should not be any tunnel traffic sent by the lower tor uplink ports
        tunnel_pkt = simple_ipv4ip_packet(
            eth_dst=upper_tor_host.facts['router_mac'],
            eth_src=lower_tor_host.facts['router_mac'],
            ip_src=lower_tor_loopback0_ip,
            ip_dst=upper_tor_loopback0_ip,
            inner_frame=pkt[IP])  # noqa F821
        not_expected_tunnel_pkt = get_masked_packet(tunnel_pkt, is_tunnel_packet=True)
        # Send packets again
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, lower_tor_source_server_ptf_port, pkt, PKT_NUM)
        # Check the tunnel packets are not received by any uplink ptf ports of the lower tor
        testutils.verify_no_packet_any(ptfadapter, not_expected_tunnel_pkt, lower_tor_uplink_ptf_ports)

    with allure.step("Check the port counters to make sure the drop on lower tor happened"):
        # There are in total 2 * PKT_NUM packets sent, the rx counter value of the source port on the lower tors
        # should be slightly lager than 2 * PKT_NUM.
        # And all the port tx counters on the lower tor should be slightly lager than zero.

        def _check_counters():
            res = True
            lower_tor_port_counters = json.loads(lower_tor_host.get_port_counters(in_json=True))
            # Check there is RX counter on the lower tor source port
            lower_tor_source_port_rx_counter = int(
                lower_tor_port_counters[lower_tor_source_port]["RX_OK"].replace(',', ''))
            logger.info("The RX_OK counter of port {} on lower tor is {} .".format(
                lower_tor_source_port, lower_tor_source_port_rx_counter))
            if not COUNTER_RANGE[0] <= lower_tor_source_port_rx_counter < COUNTER_RANGE[1]:
                res = False
            # There should not be TX counters on any lower tor port
            # wait a few seconds to make sure the counters are updated
            time.sleep(2)
            for port in lower_tor_vlan_ports + lower_tor_uplink_ports:
                tx_counter = int(lower_tor_port_counters[port]['TX_OK'].replace(',', ''))
                logger.info("The TX_OK counter of port {} on lower tor is {}.".format(
                    port, tx_counter))
                if not COUNTER_ZERO[0] <= tx_counter < COUNTER_ZERO[1]:
                    res = False
            return res
        pytest_assert(wait_until(15, 5, 0, _check_counters), "The port counters are not as expected.")


def get_masked_packet(packet, is_tunnel_packet=False):
    masked_packet = Mask(packet)
    if not is_tunnel_packet:
        masked_packet.set_do_not_care_scapy(scapy.Ether, "dst")
        masked_packet.set_do_not_care_scapy(scapy.Ether, "src")
        masked_packet.set_do_not_care_scapy(scapy.IP, "chksum")  # checksum would differ as the ttl is not the same
    else:
        masked_packet.set_do_not_care_scapy(scapy.Ether, "dst")
        masked_packet.set_do_not_care_scapy(scapy.Ether, "src")
        masked_packet.set_do_not_care_scapy(scapy.IP, "id")  # since src and dst changed, ID would change too
        masked_packet.set_do_not_care_scapy(scapy.IP, "ttl")  # ttl in outer packet is set to 255
        masked_packet.set_do_not_care_scapy(scapy.IP, "tos")
        masked_packet.set_do_not_care_scapy(scapy.IP,
                                            "chksum")  # checksum would differ as the IP header is not the same
        masked_packet.set_do_not_care_scapy(scapy.IP, "flags")  # don't fragment flag will be set on NVidia platforms
    return masked_packet
