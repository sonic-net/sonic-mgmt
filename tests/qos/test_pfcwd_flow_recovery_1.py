import logging
import pytest
import time
import random

from ptf import mask
import ptf.packet as scapy
import ptf.testutils as testutils
from scapy.all import Ether, IP

from tests.common.helpers.pfc_storm import PFCStorm
from tests.common.fixtures.conn_graph_facts import enum_fanout_graph_facts
from tests.common.helpers.assertions import pytest_assert
from tests.pfcwd.files.pfcwd_helper import start_wd_on_ports
from tests.common.helpers.ptf_tests_helper import downstream_links, upstream_links, select_random_link,\
    get_stream_ptf_ports, get_dut_pair_port_from_ptf_port, apply_dscp_cfg_setup, apply_dscp_cfg_teardown # noqa F401
from tests.common.utilities import get_ipv4_loopback_ip, get_dscp_to_queue_value, find_egress_queue,\
    get_egress_queue_pkt_count_all_prio, wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]

class TestPfcwdRecoveryTraffic:
    
    @pytest.fixture()
    def setup_test_params(self, duthost, downstream_links, upstream_links):
        # Implement the setup logic here
        test_params = {}
        downlink = select_random_link(downstream_links)
        uplink_ptf_ports = get_stream_ptf_ports(upstream_links)
        loopback_ip = get_ipv4_loopback_ip(duthost)
        router_mac = duthost.facts["router_mac"]

        pytest_assert(downlink is not None, "No downlink found")
        pytest_assert(uplink_ptf_ports is not None, "No uplink found")
        pytest_assert(loopback_ip is not None, "No loopback IP found")
        pytest_assert(router_mac is not None, "No router MAC found")

        test_params["ptf_downlink_port"] = downlink.get("ptf_port_id")
        test_params["ptf_uplink_ports"] = uplink_ptf_ports
        test_params["outer_src_ip"] = '8.8.8.8'
        test_params["outer_dst_ip"] = loopback_ip
        test_params["router_mac"] = router_mac

        return test_params


    def create_packet(self):
        # Create regular IPv4 packet
        pkt = testutils.simple_tcp_packet(
            eth_dst=self.router_mac,
            eth_src=self.ptf_mac,
            ip_src=self.test_params['src_ip'],
            ip_dst=self.test_params['dst_ip'],
            ip_ttl=64,
        )

        # Create expected packet
        exp_pkt = mask.Mask(exp_pkt)
        exp_pkt.set_do_not_care_scapy(Ether, 'src')
        exp_pkt.set_do_not_care_scapy(Ether, 'dst')
        exp_pkt.set_do_not_care_scapy(IP, 'id')
        exp_pkt.set_do_not_care_scapy(IP, 'ttl')
        exp_pkt.set_do_not_care_scapy(IP, 'chksum')

        exp_pkt = mask.Mask(exp_pkt)
        exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")

        return pkt, exp_pkt

    def send_traffic_burst(self, ptfadapter, pkt, exp_pkt, src_port, dst_ports, pkt_count=1000):
        ptfadapter.dataplane.flush()
        logger.info("Send packet burst from port {} to ports {}".format(src_port, dst_ports))
        
        for _ in range(pkt_count):
            testutils.send(ptfadapter, src_port, pkt)
        
        received_ports = []
        for dst_port in dst_ports:
            (rcv_device, rcv_port, rcv_pkt, pkt_time) = ptfadapter.dataplane.poll(device_number=0, port_number=dst_port, timeout=2)
            if rcv_port is not None:
                received_ports.append(dst_port)
                logger.info("Packet received on port {}".format(dst_port))
        
        if received_ports:
            return received_ports
        else:
            logger.error("Packet not received on any of the expected ports")
            return None

    def check_pfc_counters(self, duthost, port):
        # Implement PFC counter checking logic here
        pass

    # @pytest.fixture(scope="class", autouse=True)
    # def setup_pfcwd(self, duthosts, rand_one_dut_hostname):
    #     duthost = duthosts[rand_one_dut_hostname]
    #     logger.info("--- Stop Pfcwd ---")
    #     duthost.command("pfcwd stop")
    #     yield
    #     logger.info("--- Cleanup ---")
    #     duthost.command("pfcwd stop")

    @pytest.mark.parametrize("pfc_queue_index", [3, 4])
    def test_pfcwd_recovery_traffic(self, duthosts, rand_one_dut_hostname, ptfhost, 
                                    setup_pfc_test, enum_fanout_graph_facts, 
                                    downstream_links, upstream_links, pfc_queue_index):
        duthost = duthosts[rand_one_dut_hostname]
        setup_info = setup_pfc_test
        fanout_graph_facts = enum_fanout_graph_facts

        # Select a random egress port
        egress_port = random.choice(setup_info['port_list'])

        # Set up PFCStorm
        peer_info = {
            'peerdevice': setup_info['neighbors'][egress_port]['peerdevice'],
            'pfc_fanout_interface': setup_info['neighbors'][egress_port]['peerport'],
            'hwsku': fanout_graph_facts[setup_info['neighbors'][egress_port]['peerdevice']]['device_info']['HwSku']
        }
        
        pfc_storm = PFCStorm(duthost, fanout_graph_facts, setup_info['fanout_hosts'], 
                             pfc_queue_index=pfc_queue_index, peer_info=peer_info)

        # Start PFC Watchdog
        start_wd_on_ports(duthost, [egress_port], 200, 200)

        try:
            # Trigger PFCWD
            pfc_storm.start_storm()

            # Wait for PFCWD to detect the storm
            time.sleep(5)

            # Send traffic bursts
            for _ in range(5):
                pkt, exp_pkt = self.create_packet()
                self.send_traffic_burst(ptfhost, pkt, exp_pkt, setup_info['port_list'][0], [egress_port])
                time.sleep(1)

            # Stop PFC storm
            pfc_storm.stop_storm()

            # Wait for PFCWD to recover
            time.sleep(10)

            # Send more traffic bursts
            for _ in range(5):
                pkt, exp_pkt = self.create_packet()
                self.send_traffic_burst(ptfhost, pkt, exp_pkt, setup_info['port_list'][0], [egress_port])
                time.sleep(1)

            # Check PFC counters
            pytest_assert(wait_until(30, 1, 0, self.check_pfc_counters, duthost, egress_port),
                          "PFC counters did not stabilize after PFCWD recovery")

        finally:
            pfc_storm.stop_storm()
            duthost.command("pfcwd stop")
