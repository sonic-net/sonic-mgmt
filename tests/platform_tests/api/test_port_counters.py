import re
import time
import logging
import random

import ipaddress
import ptf.testutils as testutils
import pytest
from ptf import mask, packet

from collections import defaultdict
from tests.common.helpers.assertions import pytest_assert
from tests.common.portstat_utilities import parse_column_positions
from tests.common.portstat_utilities import parse_portstat
from tests.drop_packets.drop_packets import is_mellanox_fanout

pytestmark = [
    pytest.mark.topology('any')
]

logger = logging.getLogger(__name__)

@pytest.fixture(scope="module")
def common_param(duthosts, enum_rand_one_per_hwsku_frontend_hostname, tbinfo):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    
    peer_ip_pc_pair = [(pc["peer_addr"], pc["attachto"]) for pc in mg_facts["minigraph_portchannel_interfaces"]
                        if ipaddress.ip_address(pc['peer_addr']).version == 4]
    
    pc_ports_map = {pair[1]: mg_facts["minigraph_portchannels"][pair[1]]["members"] for pair in
                    peer_ip_pc_pair}

    router_port_peer_ip_ifaces_pair = \
        [(intf["peer_addr"], [intf["attachto"]],  mg_facts["minigraph_neighbors"][intf["attachto"]]['namespace'])
            for intf in mg_facts["minigraph_interfaces"] if ipaddress.ip_address(intf['peer_addr']).version == 4]

    port_channel_peer_ip_ifaces_pair = \
        [(pair[0], mg_facts["minigraph_portchannels"][pair[1]]["members"],
            mg_facts["minigraph_neighbors"][mg_facts["minigraph_portchannels"][pair[1]]["members"][0]]['namespace'])
            for pair in peer_ip_pc_pair]

    namespace_with_min_two_ip_interface = None
    peer_ip_ifaces_pair_list = [router_port_peer_ip_ifaces_pair, port_channel_peer_ip_ifaces_pair]
    namespace_neigh_cnt_map = defaultdict(list)
    for idx, peer_ip_ifaces in enumerate(peer_ip_ifaces_pair_list):
        for peer_idx, peer_info in enumerate(peer_ip_ifaces):
            namespace_neigh_cnt_map[peer_info[2]].append((idx, peer_idx))
            if len(namespace_neigh_cnt_map[peer_info[2]]) == 2:
                namespace_with_min_two_ip_interface = peer_info[2]
                break
        if namespace_with_min_two_ip_interface is not None:
            break

    else:
        pytest.skip("Skip test as not enough neighbors/ports.")

    ptf_port_idx = mg_facts["minigraph_ptf_indices"][selected_peer_ip_ifaces_pairs[0][1][0]]
    ptf_port_idx_namespace = namespace_with_min_two_ip_interface
    asic_id = duthost.get_asic_id_from_namespace(ptf_port_idx_namespace)
    ingress_router_mac = duthost.asic_instance(asic_id).get_router_mac()

    yield selected_peer_ip_ifaces_pairs, \
        ptf_port_idx, pc_ports_map, mg_facts["minigraph_ptf_indices"], ingress_router_mac


def parse_packet_stats(duthost, interface_name):
    interface_name = "Ethernet0"
    text = duthost.command(f'show int counters  detailed Ethernet0')["stdout_lines"][1:]

    # Initialize dictionaries for received and transmitted packets
    stats = {
        'received': {},
        'transmitted': {}
    }

    # Split the text into lines and process each line
    lines = text

    current_section = None
    for line in lines:
        # Skip empty lines
        if not line.strip():
            continue

        # Look for lines containing packet size information
        if 'Packets' in line and 'Octets' in line:
            # Extract the key components
            parts = line.split('.')
            if parts:
                # Clean up the key text
                key_text = parts[0].strip()

                # Extract the value, handling N/A and comma-formatted numbers
                value_text = parts[-1].strip()

                # Convert value to integer, handle N/A
                try:
                    # Remove commas and convert to int
                    value = int(value_text.replace(',', ''))
                except ValueError:
                    value = None if value_text == 'N/A' else value_text

                # Determine if this is received or transmitted
                if 'Received' in key_text:
                    # Extract the size range
                    range_text = key_text.replace('Packets Received ', '')
                    stats['received'][range_text] = value
                elif 'Transmitted' in key_text:
                    # Extract the size range
                    range_text = key_text.replace('Packets Transmitted ', '')
                    stats['transmitted'][range_text] = value

    return stats


def test_packet_counter_stat_ranges(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                                      ptfadapter, tbinfo, common_param):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asic_id = 0 
    int_name = "Ethernet0"
    frame_sizes = [63, 63, 63, 63, 63, 63, 63, 63, 63, 64, 70, 200, 400, 700, 1300, 3000, 7000]
    asic_type = duthost.facts["asic_type"]
    (peer_ip_ifaces_pair, ptf_port_idx, pc_ports_map, 
    ptf_indices, ingress_router_mac) = common_param
    ingress_router_mac = duthost.asic_instance(asic_id).get_router_mac() 
    
    duthost.command("sonic-clear counters")
    old_cntrs = parse_packet_stats(duthost, int_name)
    for pktlen in frame_sizes:
        pkt = testutils.simple_ip_packet(
                pktlen=pktlen,
                eth_dst=ingress_router_mac,
                eth_src=ptfadapter.dataplane.get_mac(0, ptf_port_idx),
                ip_src=peer_ip_ifaces_pair[0][0],
                ip_dst=peer_ip_ifaces_pair[1][0])
        testutils.send(ptfadapter, ptf_port_idx, pkt, 5000)
    time.sleep(3)
    new_cntrs = parse_packet_stats(duthost, int_name)
    for key in ["received"]:
        for ctr_range in new_cntrs[key].keys(): 
            if new_cntrs[key] == "None":
                continue
            pytest_assert(new_cntrs[key][ctr_range] - old_cntrs[key][ctr_range] >= 5000)      
