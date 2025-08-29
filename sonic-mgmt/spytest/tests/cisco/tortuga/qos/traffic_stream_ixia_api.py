import os
import sys
import pytest
import pprint
from spytest import st, tgapi, SpyTestDict
import tortuga_common_utils as common_util

module_dir = os.path.join(os.path.dirname(__file__), '../../', 'common')
sys.path.insert(0, os.path.abspath(module_dir))
from traffic_stream_api import (get_tc_to_dscp_map)

global tgen_handle

# Note on reading link information in the dictionaries below.
# D1D2P1 means an interface on node D1 that connects to an
# interface on node D2. P1 refers to first such link
#
# D2D1P1 means an interface on node D2 that connects to an
# interface on node D1. P1 refers to first such link

# Each leaf has 2 links going to the spine
# Each leaf has 4 links going to traffic generator
one_spine_three_leaf_map = {
    # Links between spine and 3 leaves
    'D1D2P1' : '35.1.1.1',
    'D2D1P1' : '35.1.1.2',

    'D1D2P2' : '37.1.1.1',
    'D2D1P2' : '37.1.1.2',

    'D1D3P1' : '39.1.1.1',
    'D3D1P1' : '39.1.1.2',

    'D1D3P2' : '41.1.1.1',
    'D3D1P2' : '41.1.1.2',

    'D1D4P1' : '43.1.1.1',
    'D4D1P1' : '43.1.1.2',

    'D1D4P2' : '45.1.1.1',
    'D4D1P2' : '45.1.1.2',


    # Links from leaves to traffic generator
    'D2T1P1' : '11.1.1.1',
    'D2T1P2' : '13.1.1.1',
    'D2T1P3' : '15.1.1.1',
    'D2T1P4' : '17.1.1.1',

    'D3T1P1' : '19.1.1.1',
    'D3T1P2' : '21.1.1.1',
    'D3T1P3' : '23.1.1.1',
    'D3T1P4' : '25.1.1.1',

    'D4T1P1' : '27.1.1.1',
    'D4T1P2' : '29.1.1.1',
    'D4T1P3' : '31.1.1.1',
    'D4T1P4' : '33.1.1.1'
}

# Each leaf has 2 links to each pine
# Each leaf has 4 links to traffic generator
two_spine_two_leaf_map = {
    # Links between spines and leaves
    'D1D3P1' : '11.1.1.1',
    'D3D1P1' : '11.1.1.2',

    'D1D3P2' : '13.1.1.1',
    'D3D1P2' : '13.1.1.2',

    'D1D4P1' : '15.1.1.1',
    'D4D1P1' : '15.1.1.2',

    'D1D4P2' : '17.1.1.1',
    'D4D1P2' : '17.1.1.2',

    'D2D3P1' : '19.1.1.1',
    'D3D2P1' : '19.1.1.2',

    'D2D3P2' : '21.1.1.1',
    'D3D2P2' : '21.1.1.2',

    'D2D4P1' : '23.1.1.1',
    'D4D2P1' : '23.1.1.2',

    'D2D4P2' : '25.1.1.1',
    'D4D2P2' : '25.1.1.2',

    # Links from leaves to traffic generator
    'D3T1P1' : '27.1.1.1',
    'D3T1P2' : '29.1.1.1',
    'D3T1P3' : '31.1.1.1',
    'D3T1P4' : '33.1.1.1',

    'D4T1P1' : '35.1.1.1',
    'D4T1P2' : '37.1.1.1',
    'D4T1P3' : '39.1.1.1',
    'D4T1P4' : '41.1.1.1'
}

# A given tgen port can be used multiple times to create traffic streams.
# We track the usage count here to generate unique IP addresses for each
# such instance
tgen_port_usage_cnt = {
    'T1D2P1' : 0,
    'T1D2P2' : 0,
    'T1D2P3' : 0,
    'T1D2P4' : 0,
    'T1D3P1' : 0,
    'T1D3P2' : 0,
    'T1D3P3' : 0,
    'T1D3P4' : 0,
    'T1D4P1' : 0,
    'T1D4P2' : 0,
    'T1D4P3' : 0,
    'T1D4P4' : 0
}

def ip_to_net(value):
    return value[:-1] + '0'

def config_one_spine_three_leaf_topo(tb_dict):
    global net_map

    net_map = one_spine_three_leaf_map
    cfg_dut1 = ''
    cfg_dut2 = ''
    cfg_dut3 = ''
    cfg_dut4 = ''
    ping_dut1 = ''
    ping_dut2 = ''
    ping_dut3 = ''
    ping_dut4 = ''
    cfg_route_dut1 = ''
    cfg_route_dut2 = ''
    cfg_route_dut3 = ''
    cfg_route_dut4 = ''
    for key, value in net_map.items():
        cfg_str = 'config interface ip add {} {}/24\n'.format(tb_dict[key],
                                                              value) 
        p1 = key[0:2]
        p2 = key[2:4]
        if p1 == 'D1':
            cfg_dut1 += cfg_str
            continue

        net = ip_to_net(value)
        if p1 == 'D2':
            cfg_dut2 += cfg_str
            if p2 == 'D1':
                continue
            cfg_route_dut1 += 'ip route add {}/24 via {}\n'.format(net, net_map['D2D1P1'])
            ping_dut1 += 'ping -c 3 {}\n'.format(net_map['D2D1P1'])
            cfg_route_dut3 += 'ip route add {}/24 via {}\n'.format(net, net_map['D1D3P1'])
            ping_dut3 += 'ping -c 3 {}\n'.format(net_map['D1D3P1'])
            cfg_route_dut4 += 'ip route add {}/24 via {}\n'.format(net, net_map['D1D4P1'])
            ping_dut4 += 'ping -c 3 {}\n'.format(net_map['D1D4P1'])
        elif p1 == 'D3':
            cfg_dut3 += cfg_str
            if p2 == 'D1':
                continue
            cfg_route_dut1 += 'ip route add {}/24 via {}\n'.format(net, net_map['D3D1P1'])
            ping_dut1 += 'ping -c 3 {}\n'.format(net_map['D3D1P1'])
            cfg_route_dut2 += 'ip route add {}/24 via {}\n'.format(net, net_map['D1D2P1'])
            ping_dut2 += 'ping -c 3 {}\n'.format(net_map['D1D2P1'])
            cfg_route_dut4 += 'ip route add {}/24 via {}\n'.format(net, net_map['D1D4P1'])
            ping_dut4 += 'ping -c 3 {}\n'.format(net_map['D1D4P1'])
        else:
            cfg_dut4 += cfg_str
            if p2 == 'D1':
                continue
            cfg_route_dut1 += 'ip route add {}/24 via {}\n'.format(net, net_map['D4D1P1'])
            ping_dut1 += 'ping -c 3 {}\n'.format(net_map['D4D1P1'])
            cfg_route_dut2 += 'ip route add {}/24 via {}\n'.format(net, net_map['D1D2P1'])
            ping_dut2 += 'ping -c 3 {}\n'.format(net_map['D1D2P1'])
            cfg_route_dut3 += 'ip route add {}/24 via {}\n'.format(net, net_map['D1D3P1'])
            ping_dut3 += 'ping -c 3 {}\n'.format(net_map['D1D3P1'])

    st.config(tb_dict.D1, cfg_dut1, skip_tmpl=True)
    st.config(tb_dict.D2, cfg_dut2, skip_tmpl=True)
    st.config(tb_dict.D3, cfg_dut3, skip_tmpl=True)
    st.config(tb_dict.D4, cfg_dut4, skip_tmpl=True)
    st.config(tb_dict.D1, ping_dut1, skip_tmpl=True)
    st.config(tb_dict.D2, ping_dut2, skip_tmpl=True)
    st.config(tb_dict.D3, ping_dut3, skip_tmpl=True)
    st.config(tb_dict.D4, ping_dut4, skip_tmpl=True)
    st.wait(2)
    st.config(tb_dict.D1, cfg_route_dut1, skip_tmpl=True)
    st.config(tb_dict.D2, cfg_route_dut2, skip_tmpl=True)
    st.config(tb_dict.D3, cfg_route_dut3, skip_tmpl=True)
    st.config(tb_dict.D4, cfg_route_dut4, skip_tmpl=True)

def config_two_spine_two_leaf_topo(tb_dict):
    global net_map 

    net_map = two_spine_two_leaf_map
    cfg_dut1 = ''
    cfg_dut2 = ''
    cfg_dut3 = ''
    cfg_dut4 = ''
    ping_dut1 = ''
    ping_dut2 = ''
    ping_dut3 = ''
    ping_dut4 = ''
    cfg_route_dut1 = ''
    cfg_route_dut2 = ''
    cfg_route_dut3 = ''
    cfg_route_dut4 = ''
    for key, value in net_map.items():
        cfg_str = 'config interface ip add {} {}/24\n'.format(tb_dict[key],
                                                              value) 
        p1 = key[0:2]
        if p1 == 'D1':
            cfg_dut1 += cfg_str
            continue
        if p1 == 'D2':
            cfg_dut2 += cfg_str
            continue

        p2 = key[2:4]
        net = ip_to_net(value)
        if p1 == 'D3':
            cfg_dut3 += cfg_str
            if p2 == 'D1' or p2 == 'D2':
                continue
            cfg_route_dut1 += 'ip route add {}/24 via {}\n'.format(net, net_map['D3D1P1'])
            ping_dut1 += 'ping -c 3 {}\n'.format(net_map['D3D1P1'])
            cfg_route_dut2 += 'ip route add {}/24 via {}\n'.format(net, net_map['D3D2P1'])
            ping_dut2 += 'ping -c 3 {}\n'.format(net_map['D3D2P1'])
            cfg_route_dut4 += 'ip route add {}/24 via {}\n'.format(net, net_map['D2D4P1'])
            ping_dut4 += 'ping -c 3 {}\n'.format(net_map['D2D4P1'])
        else:
            cfg_dut4 += cfg_str
            if p2 == 'D1' or p2 == 'D2':
                continue
            cfg_route_dut1 += 'ip route add {}/24 via {}\n'.format(net, net_map['D4D1P1'])
            ping_dut1 += 'ping -c 3 {}\n'.format(net_map['D4D1P1'])
            cfg_route_dut2 += 'ip route add {}/24 via {}\n'.format(net, net_map['D4D2P1'])
            ping_dut2 += 'ping -c 3 {}\n'.format(net_map['D4D2P1'])
            cfg_route_dut3 += 'ip route add {}/24 via {}\n'.format(net, net_map['D1D3P1'])
            ping_dut3 += 'ping -c 3 {}\n'.format(net_map['D1D3P1'])

    st.config(tb_dict.D1, cfg_dut1, skip_tmpl=True)
    st.config(tb_dict.D2, cfg_dut2, skip_tmpl=True)
    st.config(tb_dict.D3, cfg_dut3, skip_tmpl=True)
    st.config(tb_dict.D4, cfg_dut4, skip_tmpl=True)
    st.config(tb_dict.D1, ping_dut1, skip_tmpl=True)
    st.config(tb_dict.D2, ping_dut2, skip_tmpl=True)
    st.config(tb_dict.D3, ping_dut3, skip_tmpl=True)
    st.config(tb_dict.D4, ping_dut4, skip_tmpl=True)
    st.wait(2)
    st.config(tb_dict.D1, cfg_route_dut1, skip_tmpl=True)
    st.config(tb_dict.D2, cfg_route_dut2, skip_tmpl=True)
    st.config(tb_dict.D3, cfg_route_dut3, skip_tmpl=True)
    st.config(tb_dict.D4, cfg_route_dut4, skip_tmpl=True)
    st.wait(2)
    st.show(tb_dict.D1, "show ip interfaces\n", skip_tmpl=True)
    st.show(tb_dict.D1, "show ip route\n", skip_tmpl=True)
    st.show(tb_dict.D2, "show ip interfaces\n", skip_tmpl=True)
    st.show(tb_dict.D2, "show ip route\n", skip_tmpl=True)
    st.show(tb_dict.D3, "show ip interfaces\n", skip_tmpl=True)
    st.show(tb_dict.D3, "show ip route\n", skip_tmpl=True)
    st.show(tb_dict.D4, "show ip interfaces\n", skip_tmpl=True)
    st.show(tb_dict.D4, "show ip route\n", skip_tmpl=True)

def parse_tgen_port(tb_dict, port):
    if port.startswith('T1D2'):
        dut = tb_dict.D2
        rtr_key = 'D2T1'
    elif port.startswith('T1D3'):
        dut = tb_dict.D3
        rtr_key = 'D3T1'
    elif port.startswith('T1D4'):
        dut = tb_dict.D4
        rtr_key = 'D4T1'
    else:
        assert(0)
    return dut, (rtr_key + port[4:])

def generate_tgen_ip(tgen_key, rtr_key):
    tgen_port_usage_cnt[tgen_key] += 1
    if tgen_port_usage_cnt[tgen_key] > 64:
        st.error('Cannot generate over 64 streams on a tgen port')
        return None
    return net_map[rtr_key][:-1] + str(tgen_port_usage_cnt[tgen_key] + 1)

def create_traffic_stream(tb_dict, tgen_src_port, tgen_dst_port, frame_size, pps, tc=None):

    # stream creation assumes a 4 device setup with 1 spine node, 3 leaf nodes 
    # and 1 TGEN 4 tgen ports doing to each leaf

    src_dut, s_key = parse_tgen_port(tb_dict, tgen_src_port)
    dst_dut, d_key = parse_tgen_port(tb_dict, tgen_dst_port)
    _, src_port_h = tgapi.get_handle_byname(tgen_src_port)
    _, dst_port_h = tgapi.get_handle_byname(tgen_dst_port)

    # tgen_src_port is like 'T1D2P1'
    src_leaf_port = tb_dict[s_key]
    src_interface_config = {
        'mode': 'config',
        'port_handle': src_port_h,
        'gateway': net_map[s_key],
        'netmask': '255.255.255.0',
        'arp_send_req': 1,
        'enable_ping_response': 1,
        'resolve_gateway_mac': 1,
        'intf_ip_addr' : generate_tgen_ip(tgen_src_port, s_key)
    }
    if src_interface_config['intf_ip_addr'] == None:
        return None

    st.banner(src_interface_config)
    # Configure source interface
    result = tgen_handle.tg_interface_config(**src_interface_config)
    if result['status'] != '1':
        st.error('src if cfg failed {}'.format(result))
        return None

    src_handle = result['handle']
    # tgen_dst_port is like T1D3P1
    dst_interface_config = {
        'mode': 'config',
        'port_handle': dst_port_h,
        'gateway': net_map[d_key],
        'netmask': '255.255.255.0',
        'arp_send_req': 1,
        'enable_ping_response': 1,
        'resolve_gateway_mac': 1,
        'intf_ip_addr' : generate_tgen_ip(tgen_dst_port, d_key)
    }
    if dst_interface_config['intf_ip_addr'] == None:
        return None

    st.banner(dst_interface_config)
    # Configure destination interface
    result = tgen_handle.tg_interface_config(**dst_interface_config)
    if result['status'] != '1':
        st.error('dst if cfg failed {}'.format(result))
        return None

    dst_handle = result['handle']
    traffic_config = {
        'mode': 'create',
        # Traffic parameters
        'transmit_mode': 'continuous',
        'frame_size': frame_size,
        
        # Layer 3 configuration
        'l3_protocol': 'ipv4',
        
        # Enable flow tracking for statistics
        'track_by': 'traffic_item',
        'enable_pgid': 1,
        'rate_pps' : pps 
    }

    if tc != None:
        map = get_tc_to_dscp_map(dst_dut)
        if tc in map:
            if tc in [3, 4]:
                ecn = 1
            else:
                ecn = 0
            # TODO: Figure out how to incorporate ecn in traffic_config
            traffic_config['ip_dscp'] = map[tc]
        else:
            st.error('tc {} not present on DUT {}'.format(tc, dst_dut))
    # Configure traffic stream
    traffic_config['emulation_src_handle'] = src_handle
    traffic_config['emulation_dst_handle'] = dst_handle
    traffic_config['ip_src_addr'] = src_interface_config['intf_ip_addr']
    traffic_config['ip_dst_addr'] = dst_interface_config['intf_ip_addr']
    traffic_config['mac_dst'] = common_util.get_if_mac(src_dut, src_leaf_port)
    traffic_config['port_handle'] = src_port_h
    st.banner(traffic_config)
    result = tgen_handle.tg_traffic_config(**traffic_config)
    if result['status'] != '1':
        st.error('traffic cfg failed {}'.format(result))
        return None

    return (result['stream_id'], src_handle, dst_handle)

def start_traffic_stream(stream_info):
    tgen_handle.tg_topology_test_control(action='start_all_protocols')
    tgen_handle.tg_traffic_control(action='apply')
    tgen_handle.tg_traffic_control(action='run', stream_handle=stream_info[0])

def stop_traffic_stream(stream_info):
    tgen_handle.tg_traffic_control(action='stop', stream_handle=[stream_info[0]])

def collect_traffic_stream_stats():
    # Wait upto 30 seconds to collect statistics
    # import pdb;pdb.set_trace()
    stats = tgen_handle.tg_traffic_stats(mode='traffic_item')
    if 'waiting_for_stats' in stats and stats['waiting_for_stats']:
        st.wait(30)
        stats = tgen_handle.tg_traffic_stats(mode='traffic_item')
    st.banner('DEBUG STATS')
    pprint.pprint(stats)
    if 'traffic_item' in stats:
        return stats['traffic_item']
    if 'aggregate' in stats:
        return stats['aggregate']
    st.report_fail('msg', "stats collection failed")
    return None

def check_stats_dict(stats):
    for key, value in stats.items():
        # Go thru each traffic item and check statistics
        tx_pkts = value['tx']['total_pkts']
        rx_pkts = value['rx']['total_pkts']
        if type(tx_pkts) != type(rx_pkts):
            st.report_fail('msg', 'Unexpected data rx_pkts {} tx_pkts {}'.format(rx_pkts, tx_pkts))
        elif type(tx_pkts) == dict:
            tx_pkts = tx_pkts['sum']
            rx_pkts = rx_pkts['sum']

        if rx_pkts == tx_pkts: 
            st.report_pass('msg',
                '{}: Pkt count match : Rx {} Tx {}'.format(key, rx_pkts, tx_pkts))
        else:
            st.report_fail('msg',
                '{}: Pkt count mismatch : Rx {} Tx {}'.format(key, rx_pkts, tx_pkts))

def clear_all_stats():
    tgen_handle.tg_traffic_control(action='clear_stats')

# Gigabits per second to packets per second with given frame size
def gbps_to_pps(gbps, frame_size):
    return int((gbps * 1000000000) / (8 * frame_size))

def delete_traffic_stream(stream_info):
    tgen_handle.tg_traffic_config(mode='remove', stream_id=stream_info[0])
    tgen_handle.tg_interface_config(mode='destroy', handle=stream_info[1])
    tgen_handle.tg_interface_config(mode='destroy', handle=stream_info[2])
