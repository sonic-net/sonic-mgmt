import logging
import pytest
import time
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import copy_saitests_directory   # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import run_icmp_responder        # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import run_garp_service          # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import set_ptf_port_mapping_mode # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import ptf_portmap_file_module   # lgtm[py/unused-import]
from tests.common.helpers.assertions import pytest_require, pytest_assert
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_lower_tor # lgtm[py/unused-import]
from tests.common.dualtor.dual_tor_utils import upper_tor_host, lower_tor_host, dualtor_info, get_t1_active_ptf_ports, mux_cable_server_ip, is_tunnel_qos_remap_enabled
from tunnel_qos_remap_base import build_testing_packet, check_queue_counter, dut_config, run_ptf_test, toggle_mux_to_host, setup_module, update_docker_services, swap_syncd
from ptf import testutils


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
        testutils.verify_packet_any_port(ptfadapter, expected_pkt, dst_ports)


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


def test_tunnel_decap_dscp_to_pg_mapping(rand_selected_dut, ptfhost, dut_config, setup_module):
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
    # TODO: Get the cell size for other ASIC
    if asic == 'th2':
        cell_size = 208
    else: 
        cell_size = 256

    test_params = dict()
    test_params.update({
            "tunnel_qos_map": dut_config["tunnel_qos_map"],
            "src_port_id": dut_config["lag_port_ptf_id"],
            "dst_port_id": dut_config["server_port_ptf_id"],
            "dst_port_ip": dut_config["server_ip"],
            "active_tor_mac": dut_config["selected_tor_mac"],
            "active_tor_ip": dut_config["selected_tor_loopback"],
            "standby_tor_mac": dut_config["unselected_tor_mac"],
            "standby_tor_ip": dut_config["unselected_tor_loopback"],
            "server": dut_config["selected_tor_mgmt"],
            "port_map_file": dut_config["port_map_file"],
            "sonic_asic_type": dut_config["asic_type"],
            "cell_size": cell_size
        })
    
    run_ptf_test(
        ptfhost,
        test_case="sai_qos_tests.TunnelDscpToPgMapping",
        test_params=test_params
    )
