import logging
import pytest
import time
import random
import os

from ptf import mask
import ptf.packet as scapy
import ptf.testutils as testutils
from scapy.all import Ether, IP

from tests.common.helpers.pfc_storm import PFCStorm, PFCMultiStorm
from tests.common.fixtures.conn_graph_facts import enum_fanout_graph_facts
from tests.common.helpers.assertions import pytest_assert
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer
from tests.pfcwd.files.pfcwd_helper import start_wd_on_ports
from tests.common.helpers.ptf_tests_helper import downstream_links, upstream_links, select_random_link,\
    get_stream_ptf_ports, get_dut_pair_port_from_ptf_port, apply_dscp_cfg_setup, apply_dscp_cfg_teardown # noqa F401
from tests.common.utilities import get_ipv4_loopback_ip, get_dscp_to_queue_value, find_egress_queue,\
    get_egress_queue_pkt_count_all_prio, wait_until
from .files.pfcwd_helper import EXPECT_PFC_WD_DETECT_RE, EXPECT_PFC_WD_RESTORE_RE, fetch_vendor_specific_diagnosis_re

TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "templates")

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]

@pytest.fixture(scope='class', autouse=True)
def stop_pfcwd(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """
    Fixture that stops PFC Watchdog before each test run

    Args:
        duthost (AnsibleHost): DUT instance
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    logger.info("--- Stop Pfcwd --")
    duthost.command("pfcwd stop")


@pytest.fixture(scope='class', autouse=True)
def storm_test_setup_restore(setup_pfc_test, enum_fanout_graph_facts, duthosts,     # noqa F811
                             enum_rand_one_per_hwsku_frontend_hostname, fanouthosts,
                             request, tbinfo, downstream_links, upstream_links,
                             num_peers=2):
    """
    Fixture that inits the test vars, start PFCwd on ports and cleans up after the test run

    Args:
        setup_pfc_test (fixture): module scoped, autouse PFC fixture
        enum_fanout_graph_facts (fixture): fanout graph info
        duthost (AnsibleHost): DUT instance
        fanouthosts (AnsibleHost): fanout instance

    Yields:
        storm_handle (PFCStorm): class PFCStorm instance
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    setup_info = setup_pfc_test
    neighbors = setup_info['neighbors']
    port_list = setup_info['port_list']
    ports = (" ").join(port_list)
    pfc_queue_index = request.param
    pfc_frames_number = 10000000
    pfc_wd_detect_time = 200
    pfc_wd_restore_time = 200
    peer_params = populate_peer_info(port_list, neighbors, pfc_queue_index, pfc_frames_number)
    random.sample(peer_params['bjw-can-slx-8']['intfs'].split(","), 2)
    # peer_params = random.sample(peer_params, num_peers)
    storm_handle = set_storm_params(duthost, enum_fanout_graph_facts, fanouthosts, peer_params)
    start_wd_on_ports(duthost, ports, pfc_wd_restore_time, pfc_wd_detect_time)

    yield storm_handle

    logger.info("--- Storm test cleanup ---")
    storm_handle.stop_pfc_storm()


def populate_peer_info(port_list, neighbors, q_idx, frames_cnt):
    """
    Build the peer_info map which will be used by the storm generation class

    Args:
        port_list (list): set of ports on which the PFC storm needs to be generated
        neighbors (dict): fanout info for each DUT port
        q_idx (int): queue on which PFC frames need to be generated
        frames_cnt (int): Number of PFC frames to generate

    Returns:
        peer_params (dict): all PFC params needed for each fanout for storm generation
    """
    peer_port_map = dict()
    for port in port_list:
        peer_dev = neighbors[port]['peerdevice']
        peer_port = neighbors[port]['peerport']
        peer_port_map.setdefault(peer_dev, []).append(peer_port)

    peer_params = dict()
    for peer_dev in peer_port_map:
        peer_port_map[peer_dev] = (',').join(peer_port_map[peer_dev])
        peer_params[peer_dev] = {'pfc_frames_number': frames_cnt,
                                 'pfc_queue_index': q_idx,
                                 'intfs': peer_port_map[peer_dev]
                                 }
    return peer_params


def set_storm_params(duthost, fanout_graph, fanouthosts, peer_params):
    """
    Setup storm parameters

    Args:
        duthost (AnsibleHost): DUT instance
        fanout_graph (fixture): fanout info
        fanouthosts (AnsibleHost): fanout instance
        peer_params (dict): all PFC params needed for each fanout for storm generation

    Returns:
        storm_handle (PFCMultiStorm): class PFCMultiStorm intance
    """
    storm_handle = PFCMultiStorm(duthost, fanout_graph, fanouthosts, peer_params)
    storm_handle.set_storm_params()
    return storm_handle

@pytest.mark.usefixtures('stop_pfcwd', 'storm_test_setup_restore', 'start_background_traffic')
@pytest.mark.parametrize('storm_test_setup_restore', [[3, 4]], indirect=True)
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
    
    def run_test(self, duthost, storm_handle, expect_regex, syslog_marker, action):
        """
        Storm generation/restoration on all ports and verification

        Args:
            duthost (AnsibleHost): DUT instance
            storm_handle (PFCMultiStorm): class PFCMultiStorm intance
            expect_regex (list): list of expect regexs to be matched in the syslog
            syslog_marker (string): marker prefix written to the syslog
            action (string): storm/restore action
        """
        loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix=syslog_marker)
        ignore_file = os.path.join(TEMPLATES_DIR, "ignore_pfc_wd_messages")
        reg_exp = loganalyzer.parse_regexp_file(src=ignore_file)
        loganalyzer.ignore_regex.extend(reg_exp)

        loganalyzer.expect_regex = []
        loganalyzer.expect_regex.extend(expect_regex)

        loganalyzer.match_regex = []

        with loganalyzer:
            if action == "storm":
                storm_handle.start_pfc_storm()
            elif action == "restore":
                storm_handle.stop_pfc_storm()
            time.sleep(5)
            
        # try:
        #     # Trigger PFCWD
        #     pfc_storm.start_storm()

        #     # Wait for PFCWD to detect the storm
        #     time.sleep(5)

        #     # Send traffic bursts
        #     for _ in range(5):
        #         pkt, exp_pkt = self.create_packet()
        #         self.send_traffic_burst(ptfhost, pkt, exp_pkt, setup_info['port_list'][0], [egress_port])
        #         time.sleep(1)

        #     # Stop PFC storm
        #     pfc_storm.stop_storm()

        #     # Wait for PFCWD to recover
        #     time.sleep(10)

        #     # Send more traffic bursts
        #     for _ in range(5):
        #         pkt, exp_pkt = self.create_packet()
        #         self.send_traffic_burst(ptfhost, pkt, exp_pkt, setup_info['port_list'][0], [egress_port])
        #         time.sleep(1)

        #     # Check PFC counters
        #     pytest_assert(wait_until(30, 1, 0, self.check_pfc_counters, duthost, egress_port),
        #                   "PFC counters did not stabilize after PFCWD recovery")

        # finally:
        #     pfc_storm.stop_storm()
        #     duthost.command("pfcwd stop")


    def test_pfcwd_recovery_traffic(self,  duthosts, enum_rand_one_per_hwsku_frontend_hostname, ptfhost, 
                                    setup_pfc_test, enum_fanout_graph_facts, 
                                    downstream_links, upstream_links, pfc_queue_index,
                                    storm_test_setup_restore):
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        setup_info = setup_pfc_test
        fanout_graph_facts = enum_fanout_graph_facts
        storm_handle = storm_test_setup_restore

        logger.info("--- Testing if PFC storm is detected on all ports ---")
        self.run_test(duthost,
                      storm_handle,
                      expect_regex=[EXPECT_PFC_WD_DETECT_RE + fetch_vendor_specific_diagnosis_re(duthost)],
                      syslog_marker="all_port_storm",
                      action="storm")
        logger.info("--- Testing if PFC storm is restored on all ports ---")
        self.run_test(duthost, storm_handle, expect_regex=[EXPECT_PFC_WD_RESTORE_RE],
                      syslog_marker="all_port_storm_restore", action="restore")
        
