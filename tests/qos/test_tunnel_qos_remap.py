import logging
import pytest
import sys
import time
from ptf.mask import Mask
import ptf.packet as scapy
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import copy_saitests_directory   # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import run_icmp_responder        # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import run_garp_service          # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import set_ptf_port_mapping_mode # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import ptf_portmap_file_module   # lgtm[py/unused-import]
from tests.common.fixtures.duthost_utils import dut_qos_maps_module       # lgtm[py/unused-import]
from tests.common.fixtures.duthost_utils import separated_dscp_to_tc_map_on_uplink
from tests.common.helpers.assertions import pytest_require, pytest_assert
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_lower_tor,\
    toggle_all_simulator_ports_to_rand_selected_tor, toggle_all_simulator_ports_to_rand_unselected_tor  # noqa F401
from tests.common.dualtor.dual_tor_utils import upper_tor_host, lower_tor_host, dualtor_info,\
    get_t1_active_ptf_ports, mux_cable_server_ip, is_tunnel_qos_remap_enabled                           # noqa F401
from .tunnel_qos_remap_base import build_testing_packet, check_queue_counter,\
    dut_config, qos_config, tunnel_qos_maps, run_ptf_test, toggle_mux_to_host,\
    setup_module, update_docker_services, swap_syncd, counter_poll_config                               # noqa F401
from tunnel_qos_remap_base import leaf_fanout_peer_info, start_pfc_storm, \
    stop_pfc_storm, get_queue_counter, disable_packet_aging                                             # noqa F401
from ptf import testutils
from ptf.testutils import simple_tcp_packet
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts
from tests.common.helpers.pfc_storm import PFCStorm


pytestmark = [
    pytest.mark.topology('t0')
]

logger = logging.getLogger(__name__)

SERVER_IP = "192.168.0.2"
DUMMY_IP = "1.1.1.1"
DUMMY_MAC = "aa:aa:aa:aa:aa:aa"
VLAN_MAC = "00:aa:bb:cc:dd:ee"
DEFAULT_RPC_PORT = "9092"

PFC_PKT_COUNT = 10000000 # Cost 32 seconds
PFC_PAUSE_TEST_RETRY_MAX = 5


@pytest.fixture(scope='module', autouse=True)
def check_running_condition(tbinfo, duthost):
    """
    The test can only be running on tunnel_qos_remap enabled dualtor testbed
    """
    # Check dualtor topo
    pytest_require("dualtor" in tbinfo["topo"]["name"], "Only run on dualtor testbed.", True)
    
    # Check tunnel_qos_remap is enabled
    pytest_require(is_tunnel_qos_remap_enabled(duthost), "Only run when tunnel_qos_remap is enabled", True)


def _last_port_in_last_lag(lags):
    """
    A helper function to get the last LAG member in the last portchannel
    """
    last_lag = sorted(list(lags.keys()))[-1]
    return lags[last_lag][-1]


def test_encap_dscp_rewrite(ptfhost, upper_tor_host, lower_tor_host,                            # noqa F811
                            toggle_all_simulator_ports_to_lower_tor, tbinfo, ptfadapter, tunnel_qos_maps):       # noqa F811
    """
    The test is to verify the dscp rewriting of encapped packets.
    Test steps
    1. Toggle mux to lower tor, so all mux ports are standby on upper_tor
    2. Generate packets with certain DSCP value
    3. Send the generated packets via portchannels
    4. Verify the packets are encapped with expected DSCP value 
    """
    REQUIRED_DSCP_COMBINATIONS = [
        # DSCP in generated packets, expected DSCP in encapped packets
        (8, 8),
        (0, 0),
        (33, 33),
        (3, 2),
        (4, 6),
        (46, 46),
        (48, 48)
    ]
    if "cisco-8000" in ptfhost.duthost.facts["asic_type"]:
        DSCP_COMBINATIONS = list(tunnel_qos_maps['inner_dscp_to_outer_dscp_map'].items())
        for dscp_combination in REQUIRED_DSCP_COMBINATIONS:
            assert dscp_combination in DSCP_COMBINATIONS, \
                "Required DSCP combination {} not in inner_dscp_to_outer_dscp_map".format(dscp_combination)
    else:
        DSCP_COMBINATIONS = REQUIRED_DSCP_COMBINATIONS
    dualtor_meta = dualtor_info(ptfhost, upper_tor_host, lower_tor_host, tbinfo)
    active_tor_mac = lower_tor_host.facts['router_mac']
    
    t1_ports = get_t1_active_ptf_ports(upper_tor_host, tbinfo)
    # Always select the last port in the last LAG as src_port
    src_port = _last_port_in_last_lag(t1_ports)
    dst_ports = []
    for ports in t1_ports.values():
        dst_ports.extend(ports)

    success = True
    for dscp_combination in DSCP_COMBINATIONS:
        pkt, expected_pkt = build_testing_packet(src_ip=DUMMY_IP,
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
        try:
            testutils.verify_packet_any_port(ptfadapter, expected_pkt, dst_ports)
            print("Verified DSCP combination {}".format(str(dscp_combination)))
        except AssertionError:
            print("Failed to verify packet on DSCP combination {}".format(str(dscp_combination)))
            success = False
    assert success, "Failed inner->outer DSCP verification"
    print("Verified {} DSCP inner->outer combinations".format(len(DSCP_COMBINATIONS)))


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
    # Always select the last port in the last LAG as src_port
    src_port = _last_port_in_last_lag(t1_ports)
    mg_facts = upper_tor_host.get_extended_minigraph_facts(tbinfo)
    portchannel_info = mg_facts['minigraph_portchannels']
    tor_pc_intfs = list()
    for pc in portchannel_info.values():
        for member in pc['members']:
            tor_pc_intfs.append(member)
    PKT_NUM = 100

    for dscp, queue in TEST_DATA:
        pkt, _ = build_testing_packet(src_ip=DUMMY_IP,
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

        pytest_assert(check_queue_counter(upper_tor_host, tor_pc_intfs, queue, PKT_NUM),
                         "The queue counter for DSCP {} Queue {} is not as expected".format(dscp, queue))


def test_tunnel_decap_dscp_to_queue_mapping(ptfhost, rand_selected_dut, rand_unselected_dut,
                                            toggle_all_simulator_ports_to_rand_selected_tor, # noqa F811
                                            tbinfo, ptfadapter, tunnel_qos_maps): # noqa F811
    """
    The test case is to verify the decapped packet on active ToR are egressed to server from expected queue.
    Test steps:
    1. Toggle mux to the randomly selected ToR
    2. Generate IPinIP packets with different DSCP combination (inner and outer)
    3. Send the generated packets via portchannels
    4. Verify the packets are decapped, and outgoing from the expected queue 
    """
    dualtor_meta = dualtor_info(ptfhost, rand_unselected_dut, rand_selected_dut, tbinfo)
    t1_ports = get_t1_active_ptf_ports(rand_selected_dut, tbinfo)
    # Always select the last port in the last LAG as src_port
    src_port = _last_port_in_last_lag(t1_ports)
    active_tor_mac = rand_selected_dut.facts['router_mac']
    # Set queue counter polling interval to 1 second to speed up the test
    counter_poll_config(rand_selected_dut, 'queue', 1000)
    PKT_NUM = 100
    try:
        # Walk through all DSCP values
        for inner_dscp in range(0, 64):
            outer_dscp = tunnel_qos_maps['inner_dscp_to_outer_dscp_map'][inner_dscp]
            _, exp_packet = build_testing_packet(src_ip=DUMMY_IP,
                                                    dst_ip=dualtor_meta['target_server_ip'],
                                                    active_tor_mac=active_tor_mac,
                                                    standby_tor_mac=dualtor_meta['standby_tor_mac'],
                                                    active_tor_ip=dualtor_meta['active_tor_ip'],
                                                    standby_tor_ip=dualtor_meta['standby_tor_ip'],
                                                    inner_dscp=inner_dscp,
                                                    outer_dscp=outer_dscp,
                                                    ecn=1)
            tunnel_packet = exp_packet.exp_pkt
            # Clear queuecounters before sending traffic
            rand_selected_dut.shell('sonic-clear queuecounters')
            time.sleep(1)
            # Send tunnel packets
            testutils.send(ptfadapter, src_port, tunnel_packet, PKT_NUM)
            # Wait 2 seconds for queue counter to be refreshed
            time.sleep(2)
            # Verify counter at expected queue at the server facing port
            pytest_assert(check_queue_counter(rand_selected_dut, [dualtor_meta['selected_port']],
                                              tunnel_qos_maps['inner_dscp_to_queue_map'][inner_dscp], PKT_NUM),
                          "The queue counter for DSCP {} Queue {} is not as expected"
                          .format(inner_dscp, tunnel_qos_maps['inner_dscp_to_queue_map'][inner_dscp]))

    finally:
        counter_poll_config(rand_selected_dut, 'queue', 10000)


def test_separated_qos_map_on_tor(ptfhost, rand_selected_dut, rand_unselected_dut, toggle_all_simulator_ports_to_rand_selected_tor, tbinfo, ptfadapter, dut_qos_maps_module):
    """
    The test case is to verify separated DSCP_TO_TC_MAP/TC_TO_QUEUE_MAP on uplink and downlink ports of dualtor
    Test steps
    1. Build IPinIP encapsulated packet with dummy src ip and dst ip (must not be the loopback address of dualtor)
    2. Ingress the packet from uplink port, verify the packets egressed from expected queue
    3. Build regular packet with dst_ip = dummy IP (routed by default route)
    4. Ingress the packet from downlink port, verify the packets egressed from expected queue 
    """
    pytest_require(separated_dscp_to_tc_map_on_uplink(dut_qos_maps_module), 
                    "Skip test because separated QoS map is not applied")
    dualtor_meta = dualtor_info(ptfhost, rand_unselected_dut, rand_selected_dut, tbinfo)
    t1_ports = get_t1_active_ptf_ports(rand_selected_dut, tbinfo)
    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)
    portchannel_info = mg_facts['minigraph_portchannels']
    tor_pc_intfs = list()
    for pc in portchannel_info.values():
        for member in pc['members']:
            tor_pc_intfs.append(member)
    active_tor_mac = rand_selected_dut.facts['router_mac']
    # Set queue counter polling interval to 1 second to speed up the test
    counter_poll_config(rand_selected_dut, 'queue', 1000)
    PKT_NUM = 100
    # DSCP 2/6 are mapped to lossless queue 2/6 on uplink ports
    UP_LINK_TEST_DATA = {
        # Inner DSCP, Outer DSCP, Expected queue
        (3, 2, 2),
        (4, 6, 6)
    }
    # DSCP 2/6 are mapped to lossy queue 1 on downlink ports
    DOWN_LINK_TEST_DATA = {
        # DSCP, Expected queue
        (2, 1),
        (6, 1) 
    }
    try:
        # uplink port test
        # Always select the last port in the last LAG as src_port
        src_port = _last_port_in_last_lag(t1_ports)
        for inner_dscp, outer_dscp, queue in UP_LINK_TEST_DATA:
            # We use the IPinIP packet only
            _, exp_packet = build_testing_packet(src_ip=DUMMY_IP, 
                                              dst_ip=dualtor_meta['target_server_ip'],
                                              active_tor_mac=active_tor_mac,
                                              standby_tor_mac=dualtor_meta['standby_tor_mac'],
                                              active_tor_ip='20.2.0.22', # The active/standby tor ip must be fake value so that the pack is not decaped 
                                              standby_tor_ip='20.2.0.21',
                                              inner_dscp=inner_dscp,
                                              outer_dscp=outer_dscp)
            ipinip_packet = exp_packet.exp_pkt
            # Clear queuecounters before sending traffic
            rand_selected_dut.shell('sonic-clear queuecounters')
            time.sleep(1)
            # Send tunnel packets
            testutils.send(ptfadapter, src_port, ipinip_packet, PKT_NUM)
            # Wait 2 seconds for queue counter to be refreshed
            time.sleep(2)
            # Since the packet will not be decaped by active ToR, we expected to see the packet egress from any uplink ports
            pytest_assert(check_queue_counter(rand_selected_dut, tor_pc_intfs, queue, PKT_NUM),
                         "Uplink test: the queue counter for DSCP {} Queue {} is not as expected".format(outer_dscp, queue))
        
        # downlink port test
        src_port = dualtor_meta['target_server_port']
        for dscp, queue in DOWN_LINK_TEST_DATA:
            pkt = simple_tcp_packet(eth_dst=VLAN_MAC,
                                    ip_src=dualtor_meta['target_server_ip'],
                                    ip_dst=DUMMY_IP, # A dummy IP that will hit default route,
                                    ip_dscp=dscp)
            
            # Clear queuecounters before sending traffic
            rand_selected_dut.shell('sonic-clear queuecounters')
            time.sleep(1)
            # Send tunnel packets
            testutils.send(ptfadapter, src_port, pkt, PKT_NUM)
            # Wait 2 seconds for queue counter to be refreshed
            time.sleep(2)
            # We expected to see the packet egress from any uplink ports since the dst IP will hit the default route
            pytest_assert(check_queue_counter(rand_selected_dut, tor_pc_intfs, queue, PKT_NUM),
                         "Downlink test: the queue counter for DSCP {} Queue {} is not as expected".format(dscp, queue))
    finally:
        counter_poll_config(rand_selected_dut, 'queue', 10000)


def pfc_pause_test(storm_handler, peer_info, prio, ptfadapter, dut, port, queue, pkt, src_port, exp_pkt, dst_ports):
    try:
        # Start PFC storm from leaf fanout switch
        start_pfc_storm(storm_handler, peer_info, prio)
        ptfadapter.dataplane.flush()
        # Record the queue counter before sending test packet
        base_queue_count = get_queue_counter(dut, port, queue, True)
        # Send testing packet again
        testutils.send_packet(ptfadapter, src_port, pkt, 1)
        # The packet should be paused
        testutils.verify_no_packet_any(ptfadapter, exp_pkt, dst_ports)
        # Check the queue counter didn't increase
        queue_count = get_queue_counter(dut, port, queue, False)
        assert base_queue_count == queue_count
        return True
    except AssertionError:
        logger.info('assert {}'.format(sys.exc_info()))
        return False
    except Exception:
        logger.info('exception {}'.format(sys.exc_info()))
        return False
    finally:
        stop_pfc_storm(storm_handler)


def test_pfc_pause_extra_lossless_standby(ptfhost, fanouthosts, rand_selected_dut, rand_unselected_dut, toggle_all_simulator_ports_to_rand_unselected_tor, tbinfo, ptfadapter, conn_graph_facts, fanout_graph_facts):
    """
    The test case is to verify PFC pause frame can pause extra lossless queues in dualtor deployment.
    Test steps:
    1. Toggle mux ports to rand_unselected_dut, so all mux ports are standby on the selected ToR
    2. Generate packets with different DSCPs, ingress to standby ToR. The traffic will be bounced back to T1
    3. Generate PFC pause on fanout switch (T1 ports)
    4. Verify lossless traffic are paused
    """
    TEST_DATA = {
        # Inner DSCP, Outer DSCP, Priority
        (3, 2, 2, 2),
        (4, 6, 6, 6)
    }
    dualtor_meta = dualtor_info(ptfhost, rand_selected_dut, rand_unselected_dut, tbinfo)
    t1_ports = get_t1_active_ptf_ports(rand_selected_dut, tbinfo)
    # Always select the last port in the last LAG as src_port
    src_port = _last_port_in_last_lag(t1_ports)
    # The encapsulated packets can egress from any uplink port
    dst_ports = []
    for ports in t1_ports.values():
        dst_ports.extend(ports)
    active_tor_mac = rand_unselected_dut.facts['router_mac']
    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)
    ptfadapter.dataplane.flush()
    for inner_dscp, outer_dscp, prio, queue in TEST_DATA:
        pkt, exp_pkt = build_testing_packet(src_ip=DUMMY_IP,
                                            dst_ip=SERVER_IP,
                                            active_tor_mac=active_tor_mac,
                                            standby_tor_mac=dualtor_meta['standby_tor_mac'],
                                            active_tor_ip=dualtor_meta['active_tor_ip'],
                                            standby_tor_ip=dualtor_meta['standby_tor_ip'],
                                            inner_dscp=inner_dscp,
                                            outer_dscp=outer_dscp,
                                            ecn=1)
        # Ingress packet from uplink port
        testutils.send(ptfadapter, src_port, pkt, 1)
        # Get the actual egress port
        result = testutils.verify_packet_any_port(ptfadapter, exp_pkt, dst_ports)
        actual_port = dst_ports[result[0]]
        # Get the port name from mgfacts
        for port_name, idx in mg_facts['minigraph_ptf_indices'].items():
            if idx == actual_port:
                actual_port_name = port_name
                break
        pytest_assert(actual_port_name)
        peer_info = leaf_fanout_peer_info(rand_selected_dut, conn_graph_facts, mg_facts, actual_port)
        storm_handler = PFCStorm(rand_selected_dut, fanout_graph_facts, fanouthosts,
                                    pfc_queue_idx=prio,
                                    pfc_frames_number=PFC_PKT_COUNT,
                                    peer_info=peer_info)
        
        retry = 0
        while retry < PFC_PAUSE_TEST_RETRY_MAX:
            try:
                if pfc_pause_test(storm_handler, peer_info, prio, ptfadapter, rand_selected_dut, actual_port_name,
                                  queue, pkt, src_port, exp_pkt, dst_ports):
                    break
            except AssertionError:
                retry += 1
                if retry == PFC_PAUSE_TEST_RETRY_MAX:
                    pytest_assert(False, "The queue {} for port {} counter increased unexpectedly".format(
                        queue, actual_port_name))
            except Exception:
                retry += 1
                if retry == PFC_PAUSE_TEST_RETRY_MAX:
                    pytest_assert(False, "The queue {} for port {} counter increased unexpectedly".format(
                        queue, actual_port_name))
            time.sleep(5)


def test_pfc_pause_extra_lossless_active(ptfhost, fanouthosts, rand_selected_dut, rand_unselected_dut, toggle_all_simulator_ports_to_rand_selected_tor, tbinfo, ptfadapter, conn_graph_facts, fanout_graph_facts):
    """
    The test case is to verify PFC pause frame can pause extra lossless queues in dualtor deployment.
    Test steps:
    1. Toggle mux ports to rand_selected_dut, so all mux ports are standby on the unselected ToR
    2. Generate IPinIP packets with different DSCP combinations, ingress to active ToR.
    3. Generate PFC pause on fanout switch (Server facing ports)
    4. Verify lossless traffic are paused
    """
    TEST_DATA = {
        # Inner DSCP, Outer DSCP, Priority, Queue
        (3, 2, 3, 3),
        (4, 6, 4, 4)
    }
    dualtor_meta = dualtor_info(ptfhost, rand_unselected_dut, rand_selected_dut, tbinfo)
    t1_ports = get_t1_active_ptf_ports(rand_selected_dut, tbinfo)
    # Always select the last port in the last LAG as src_port
    src_port = _last_port_in_last_lag(t1_ports)
    active_tor_mac = rand_selected_dut.facts['router_mac']
    mg_facts = rand_unselected_dut.get_extended_minigraph_facts(tbinfo)
    ptfadapter.dataplane.flush()
    for inner_dscp, outer_dscp, prio, queue in TEST_DATA:
        pkt, tunnel_pkt = build_testing_packet(src_ip=DUMMY_IP,
                                            dst_ip=dualtor_meta['target_server_ip'],
                                            active_tor_mac=active_tor_mac,
                                            standby_tor_mac=dualtor_meta['standby_tor_mac'],
                                            active_tor_ip=dualtor_meta['active_tor_ip'],
                                            standby_tor_ip=dualtor_meta['standby_tor_ip'],
                                            inner_dscp=inner_dscp,
                                            outer_dscp=outer_dscp,
                                            ecn=1)
        # Ingress packet from uplink port
        testutils.send(ptfadapter, src_port, tunnel_pkt.exp_pkt, 1)
        pkt.ttl -= 2 # TTL is decreased by 1 at tunnel forward and decap,
        exp_pkt = Mask(pkt)
        exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
        exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
        exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
        # Verify packet is decapsulated and egress to server
        testutils.verify_packet(ptfadapter, exp_pkt, dualtor_meta['target_server_port'])
        peer_info = leaf_fanout_peer_info(rand_selected_dut, conn_graph_facts, mg_facts, dualtor_meta['target_server_port'])
        storm_handler = PFCStorm(rand_selected_dut, fanout_graph_facts, fanouthosts,
                                    pfc_queue_idx=prio,
                                    pfc_frames_number=PFC_PKT_COUNT,
                                    peer_info=peer_info)

        retry = 0
        while retry < PFC_PAUSE_TEST_RETRY_MAX:
            try:
                if pfc_pause_test(storm_handler, peer_info, prio, ptfadapter, rand_selected_dut,
                                  dualtor_meta['selected_port'], queue, tunnel_pkt.exp_pkt, src_port, exp_pkt,
                                  [dualtor_meta['target_server_port']]):
                    break
            except AssertionError:
                retry += 1
                if retry == PFC_PAUSE_TEST_RETRY_MAX:
                    pytest_assert(False, "The queue {} for port {} counter increased unexpectedly".format(
                        queue, dualtor_meta['selected_port']))
            except Exception:
                retry += 1
                if retry == PFC_PAUSE_TEST_RETRY_MAX:
                    pytest_assert(False, "The queue {} for port {} counter increased unexpectedly".format(
                        queue, dualtor_meta['selected_port']))
            time.sleep(5)


@pytest.mark.disable_loganalyzer
def test_tunnel_decap_dscp_to_pg_mapping(rand_selected_dut, ptfhost, dut_config, setup_module, tunnel_qos_maps):     # noqa F811
    """
    Test steps:
    1. Toggle all ports to active on randomly selected ToR
    2. Populate ARP table by GARP service
    3. Disable Tx on target port
    4. Send encapsulated packets from T1 to Active ToR
    5. Verify the watermark increased as expected
    """
    toggle_mux_to_host(rand_selected_dut)
    asic = rand_selected_dut.get_asic_name()
    pytest_assert(asic != 'unknown', 'Get unknown asic name')
    # TODO: Get the cell size for other ASIC
    packet_size = 64
    if asic == 'th2':
        cell_size = 208
    elif 'spc' in asic:
        cell_size = 144
    elif dut_config["asic_type"] == "cisco-8000":
        cell_size = 384
        packet_size = 1350
    else:
        cell_size = 256
    test_params = dict()
    test_params.update({
            "src_port_id": dut_config["lag_port_ptf_id"],
            "dst_port_id": dut_config["server_port_ptf_id"],
            "dst_port_ip": dut_config["server_ip"],
            "active_tor_mac": dut_config["selected_tor_mac"],
            "active_tor_ip": dut_config["selected_tor_loopback"],
            "standby_tor_mac": dut_config["unselected_tor_mac"],
            "standby_tor_ip": dut_config["unselected_tor_loopback"],
            "src_server": dut_config["selected_tor_mgmt"] + ":" + DEFAULT_RPC_PORT,
            "inner_dscp_to_pg_map": tunnel_qos_maps["inner_dscp_to_pg_map"],
            "inner_dscp_to_queue_map": tunnel_qos_maps["inner_dscp_to_queue_map"],
            "port_map_file_ini": dut_config["port_map_file_ini"],
            "sonic_asic_type": dut_config["asic_type"],
            "platform_asic": dut_config["platform_asic"],
            "packet_size": packet_size,
            "cell_size": cell_size
        })

    run_ptf_test(
        ptfhost,
        test_case="sai_qos_tests.TunnelDscpToPgMapping",
        test_params=test_params
    )


@pytest.mark.disable_loganalyzer
@pytest.mark.parametrize("xoff_profile", ["pcbb_xoff_1", "pcbb_xoff_2", "pcbb_xoff_3", "pcbb_xoff_4"])
def test_xoff_for_pcbb(rand_selected_dut, ptfhost, dut_config, qos_config, xoff_profile, setup_module):
    """
    The test is to verify xoff threshold for PCBB (Priority Control for Bounced Back traffic)
    Test steps
    1. Toggle all ports to active on randomly selected ports
    2. Populate ARP table by GARP service
    3. Disable Tx on egress port
    4. Verify bounced back traffic (tunnel traffic, IPinIP) can trigger PFC at expected queue
    5. Verify regular traffic can trigger PFC at expected queue
    """
    toggle_mux_to_host(rand_selected_dut)
    # Delay 5 seconds between each test run
    time.sleep(5)
    test_params = dict()
    test_params.update({
            "src_port_id": dut_config["lag_port_ptf_id"],
            "dst_port_id": dut_config["server_port_ptf_id"],
            "dst_port_ip": dut_config["server_ip"],
            "active_tor_mac": dut_config["selected_tor_mac"],
            "active_tor_ip": dut_config["selected_tor_loopback"],
            "standby_tor_mac": dut_config["unselected_tor_mac"],
            "standby_tor_ip": dut_config["unselected_tor_loopback"],
            "src_server": dut_config["selected_tor_mgmt"] + ":" + DEFAULT_RPC_PORT,
            "port_map_file_ini": dut_config["port_map_file_ini"],
            "platform_asic": dut_config["platform_asic"],
            "sonic_asic_type": dut_config["asic_type"],
        })
    if dut_config["asic_type"] == 'mellanox':
        test_params.update({'cell_size': 144, 'packet_size': 300})
    # Update qos config into test_params
    test_params.update(qos_config[xoff_profile])
    # Run test on ptfhost
    run_ptf_test(
        ptfhost,
        test_case="sai_qos_tests.PCBBPFCTest",
        test_params=test_params
    )
