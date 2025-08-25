import logging
import pytest
import random
import ptf.packet as scapy
from tests.common.helpers.assertions import pytest_assert
from tests.common.dualtor.nic_simulator_control import toggle_ports
from tests.common.dualtor.dual_tor_utils import dualtor_info  # noqa F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses, run_icmp_responder, run_garp_service  # noqa F401
from tests.common.dualtor.dual_tor_utils import toggle_all_aa_ports_to_rand_selected_tor, \
    toggle_all_aa_ports_to_rand_unselected_tor  # noqa F401
from ptf.mask import Mask
from ptf import testutils
from tests.common.utilities import wait_until
from ptf.testutils import simple_tcp_packet, simple_ipv4ip_packet
from tests.qos.tunnel_qos_remap_base import check_queue_counter
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure

pytestmark = [
    pytest.mark.topology('dualtor')
]

logger = logging.getLogger(__name__)

PKT_NUM = 100


@pytest.fixture(scope='module', autouse=True)
def config_counter_poll_interval(rand_selected_dut, rand_unselected_dut):  # noqa F811
    """
    Fixture to set the counterpoll intervals to 1s during the test, so we can save some time.
    """
    origin_queue_interval = rand_selected_dut.get_counter_poll_status()['QUEUE_STAT']['interval']
    rand_selected_dut.set_counter_poll_interval('QUEUE_STAT', 1000)
    rand_unselected_dut.set_counter_poll_interval('QUEUE_STAT', 1000)
    yield
    rand_selected_dut.set_counter_poll_interval('QUEUE_STAT', origin_queue_interval)
    rand_unselected_dut.set_counter_poll_interval('QUEUE_STAT', origin_queue_interval)


def test_active_tor_normal_traffic(ptfhost, rand_selected_dut, rand_unselected_dut, # noqa F811
                                   toggle_all_aa_ports_to_rand_selected_tor, # noqa F811
                                   tbinfo, ptfadapter):
    """
    The test is to verify the dscp of normal traffic(not bounced back traffic) on active tor is not remapped, and the
    traffic goes to the correct queue according to the dscp.
    """
    up_link_test_data = {
        # DSCP, Expected queue
        (0, 1),
        (3, 3),
        (4, 4),
        (8, 0),
        (33, 1),
        (46, 5),
        (48, 7),
        (63, 1)
    }
    down_link_test_data = {
        # DSCP, Expected queue
        (0, 1),
        (2, 1),
        (3, 3),
        (4, 4),
        (6, 1),
        (8, 0),
        (33, 1),
        (46, 5),
        (48, 7),
        (63, 1)
    }
    with allure.step("Prepare test parameters"):
        dualtor_meta = dualtor_info(ptfhost, rand_selected_dut, rand_unselected_dut, tbinfo)
        mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)
        active_tor_mac = rand_selected_dut.facts['router_mac']
        uplink_interfaces = {}
        t1_ptf_ports = []
        for portchannel in mg_facts['minigraph_portchannels'].values():
            for member in portchannel['members']:
                ptf_indice = mg_facts['minigraph_ptf_indices'][member]
                t1_ptf_ports.append(ptf_indice)
                uplink_interfaces[ptf_indice] = member
        # Always select the last port in the last LAG as src_port
        last_t1_ptf_port = sorted(t1_ptf_ports)[-1]
        # Randomly select a server to receive the traffic
        vlan_interface = list(mg_facts['minigraph_vlans'].keys())[0]
        downlink_interface = random.choice(mg_facts['minigraph_vlans'][vlan_interface]['members'])
        server = mg_facts['minigraph_neighbors'][downlink_interface]['name']
        server_ip = mg_facts['minigraph_devices'][server]['lo_addr']
        server_ptf_port = mg_facts['minigraph_ptf_indices'][downlink_interface]

    def _generate_packet(eth_dst, ip_src, ip_dst, ip_dscp):
        pkt = simple_tcp_packet(
            eth_dst=eth_dst,
            ip_src=ip_src,
            ip_dst=ip_dst,
            ip_dscp=ip_dscp,
            ip_ecn=1,
            ip_ttl=64
        )
        exp_pkt = Mask(pkt)
        exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
        exp_pkt.set_do_not_care_scapy(scapy.IP, "id")  # since src and dst changed, ID would change too
        exp_pkt.set_do_not_care_scapy(scapy.IP, "ttl")  # ttl in outer packet is kept default (64)
        exp_pkt.set_do_not_care_scapy(
            scapy.IP, "chksum")  # checksum would differ as the IP header is not the same
        return pkt, exp_pkt

    with allure.step("Start the uplink test"):
        for dscp, queue in up_link_test_data:
            pkt, expected_pkt = _generate_packet(active_tor_mac, '1.1.1.1', server_ip, dscp)
            # Clear queue counters before sending traffic
            rand_selected_dut.shell('sonic-clear queuecounters')
            logger.info("Sending normal traffic from t1 to server {} with dscp {}".format(server_ip, dscp))
            logger.info("The expected queue for the traffic is {}".format(queue))
            testutils.send(ptfadapter, last_t1_ptf_port, pkt, PKT_NUM)
            testutils.verify_packet(ptfadapter, expected_pkt, server_ptf_port)
            pytest_assert(wait_until(
                5, 1, 0, check_queue_counter, rand_selected_dut, [downlink_interface], queue, PKT_NUM),
                "The queue counter for DSCP: {}, Queue: {} is not as expected: >= {}. "
                "Please check the output of cmd 'show queue counters' in the test log.".format(dscp, queue, PKT_NUM))

    with allure.step("Start the downlink test"):
        for dscp, queue in down_link_test_data:
            pkt, expected_pkt = _generate_packet(dualtor_meta['vlan_mac'], server_ip, '1.1.1.1', dscp)
            # Clear queue counters before sending traffic
            rand_selected_dut.shell('sonic-clear queuecounters')
            # Send packets
            logger.info("Sending normal traffic from server {} to t1 with dscp {}".format(server_ip, dscp))
            logger.info("The expected queue for the traffic is {}".format(queue))
            ptfadapter.dataplane.flush()
            testutils.send(ptfadapter, server_ptf_port, pkt, PKT_NUM)
            receive_port_index, _ = testutils.verify_packet_any_port(ptfadapter, expected_pkt, t1_ptf_ports)
            receive_ptf_port = t1_ptf_ports[receive_port_index]
            pytest_assert(wait_until(
                5, 1, 0, check_queue_counter, rand_selected_dut,
                [uplink_interfaces[receive_ptf_port]], queue, PKT_NUM),
                "The queue counter for DSCP: {}, Queue: {} is not as expected: >= {}. "
                "Please check the output of cmd 'show queue counters' in the test log.".format(dscp, queue, PKT_NUM))


def test_traffic_between_servers(ptfhost, rand_selected_dut, rand_unselected_dut,  # noqa F811
                                 toggle_all_aa_ports_to_rand_selected_tor,  # noqa F811
                                 tbinfo, ptfadapter): # noqa F811
    """
    The test case is to verify on a same tor, the traffic from an active server to a standby server should be
    forwarded by the tunnel, and enter the correct queue.
    """
    # For the MSFT preserved dscp, 3/4 will be remapped, others will be copied to the outer.
    dscp_to_queue_mapping = [
        # DSCP, Outer DSCP, Expected queue
        (8, 8, 0),
        (0, 0, 1),
        (33, 33, 1),
        (3, 2, 2),
        (4, 6, 6),
        (46, 46, 5),
        (48, 48, 7)
    ]
    with allure.step("Prepare test parameters and switch one server on the lower tor to active"):
        dualtor_meta = dualtor_info(ptfhost, rand_selected_dut, rand_unselected_dut, tbinfo)
        lower_tor_mg_facts = rand_unselected_dut.get_extended_minigraph_facts(tbinfo)
        upper_tor_mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)
        vlan_interface = list(lower_tor_mg_facts['minigraph_vlans'].keys())[0]
        # use the last interface as the active interface on lower tor
        lower_tor_active_interface = lower_tor_mg_facts['minigraph_vlans'][vlan_interface]['members'][-1]
        lower_tor_active_server_ptf_port = lower_tor_mg_facts['minigraph_ptf_indices'][lower_tor_active_interface]
        logger.info("Toggle the interface {} to active on the lower tor.".format(lower_tor_active_interface))
        toggle_ports(rand_unselected_dut, [lower_tor_active_interface], "active")
        toggle_ports(rand_selected_dut, [lower_tor_active_interface], "standby")
        lower_tor_uplink_interfaces = {}
        t1_ptf_ports = []
        for portchannel in lower_tor_mg_facts['minigraph_portchannels'].values():
            for member in portchannel['members']:
                ptf_indice = lower_tor_mg_facts['minigraph_ptf_indices'][member]
                t1_ptf_ports.append(ptf_indice)
                lower_tor_uplink_interfaces[ptf_indice] = member
        # randomly choose a standby server on lower tor
        lower_tor_standby_interface = random.choice(
            lower_tor_mg_facts['minigraph_vlans'][vlan_interface]['members'][:-1])
        lower_tor_standby_server = lower_tor_mg_facts['minigraph_neighbors'][lower_tor_standby_interface]['name']
        lower_tor_standby_server_ip = lower_tor_mg_facts['minigraph_devices'][lower_tor_standby_server]['lo_addr']

        rand_selected_dut_name = upper_tor_mg_facts['inventory_hostname']
        rand_unselected_dut_name = lower_tor_mg_facts['inventory_hostname']
        upper_tor_loopback0_ip = upper_tor_mg_facts['minigraph_devices'][rand_selected_dut_name]['lo_addr']
        lower_tor_loopback0_ip = lower_tor_mg_facts['minigraph_devices'][rand_unselected_dut_name]['lo_addr']

    with allure.step("Start the traffic test"):
        for dscp, outer_dscp, queue in dscp_to_queue_mapping:
            pkt = simple_tcp_packet(
                eth_dst=dualtor_meta['vlan_mac'],
                ip_src='1.1.1.1',
                ip_dst=lower_tor_standby_server_ip,
                ip_dscp=dscp,
                ip_ecn=1,
                ip_ttl=64
            )
            # The ttl of inner_frame is decreased by 1
            pkt.ttl -= 1
            ipinip_packet = simple_ipv4ip_packet(
                eth_dst=rand_selected_dut.facts['router_mac'],
                eth_src=rand_unselected_dut.facts['router_mac'],
                ip_src=lower_tor_loopback0_ip,
                ip_dst=upper_tor_loopback0_ip,
                ip_dscp=outer_dscp,
                ip_ecn=1,
                inner_frame=pkt[IP])  # noqa F821
            pkt.ttl += 1
            exp_tunnel_pkt = Mask(ipinip_packet)
            exp_tunnel_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
            exp_tunnel_pkt.set_do_not_care_scapy(scapy.Ether, "src")
            exp_tunnel_pkt.set_do_not_care_scapy(scapy.IP, "id")  # since src and dst changed, ID would change too
            exp_tunnel_pkt.set_do_not_care_scapy(scapy.IP, "ttl")  # ttl in outer packet is set to 255
            exp_tunnel_pkt.set_do_not_care_scapy(
                scapy.IP, "chksum")  # checksum would differ as the IP header is not the same
            exp_tunnel_pkt.set_do_not_care_scapy(
                scapy.IP, "flags")  # don't fragment flag will be set on NVidia platforms

            # Clear queue counters before sending traffic
            rand_unselected_dut.shell('sonic-clear queuecounters')
            ptfadapter.dataplane.flush()
            testutils.send(ptfadapter, lower_tor_active_server_ptf_port, pkt, PKT_NUM)
            receive_port_index, _ = testutils.verify_packet_any_port(ptfadapter, exp_tunnel_pkt, t1_ptf_ports)
            receive_ptf_port = t1_ptf_ports[receive_port_index]
            # Verify queue counters in all possible interfaces
            pytest_assert(wait_until(
                10, 2, 0, check_queue_counter, rand_unselected_dut,
                [lower_tor_uplink_interfaces[receive_ptf_port]], queue, PKT_NUM),
                "The queue counter for DSCP: {}, Queue: {} is not as expected: >= {}. "
                "Please check the output of cmd 'show queue counters' in the test log.".format(dscp, queue, PKT_NUM))
