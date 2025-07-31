import time
import sys
import json
import pytest
import pprint

from spytest import st, tgapi, SpyTestDict

import apis.system.port as papi
import apis.system.interface as intapi
import apis.routing.ip as ip_obj
import apis.system.basic as basic_obj

# List to keep track of PFC streams
pfc_streams = []
all_streams = []

# Table of PFC traffic class patterns (hex strings for each TC)
# The API is intelligent enough to ignore spaces
pfc_tc_table = [\
'0101 0001 ffff 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000',
'0101 0002 0000 ffff 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000',
'0101 0004 0000 0000 ffff 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000',
'0101 0008 0000 0000 0000 ffff 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000',
'0101 0010 0000 0000 0000 0000 ffff 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000',
'0101 0020 0000 0000 0000 0000 0000 ffff 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000',
'0101 0040 0000 0000 0000 0000 0000 0000 ffff 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000',
'0101 0080 0000 0000 0000 0000 0000 0000 0000 ffff 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000',
]

tc_to_dscp_map = {}
# Build a mapping from traffic class (TC) to DSCP value using device output
# This is used to set the correct DSCP for each traffic class in test streams
def get_tc_to_dscp_map(dut, asic_str):

    if dut in tc_to_dscp_map:
        return

    tc_to_dscp_map[dut] = {}

    # Get json output for dscp to tc map and reverse it to create 
    # the dictionary we need for DSCP values
    dscp_to_tc_map = st.show(dut, \
        "sonic-cfggen -d --var-json DSCP_TO_TC_MAP " + asic_str, skip_tmpl=True)
    idx = dscp_to_tc_map.rfind('}')
    if idx == -1:
        print("Bad format of dscp to tc map")
        return

    dscp_to_tc_map = json.loads(dscp_to_tc_map[:idx + 1])
    dscp_to_tc_map = dscp_to_tc_map['AZURE']
    for k,v in dscp_to_tc_map.items():
        if int(v) not in tc_to_dscp_map[dut]:
            tc_to_dscp_map[dut][int(v)] = int(k)
            if len(tc_to_dscp_map[dut]) == 8:
                break
    if len(tc_to_dscp_map[dut]) < 8:
        st.warn("Some traffic classes are unavailable in DSCP_TO_TC_MAP")

# Check if a stream_id corresponds to a PFC stream
def is_pfc_stream(stream_id):
    for stream in pfc_streams:
        if stream['stream_id'] == stream_id:
            return True
    return False

# Print traffic stream statistics and check for packet loss
def print_stream_stats(dev_handle, port_handle):
    stats = dev_handle.tg_traffic_stats(port_handle=port_handle, mode='streams')
    stats = stats[port_handle]['stream']
    print("{} Stats {}".format(port_handle, stats));
    for key in stats:
        tx_pkts = stats[key]['tx']['total_pkts']
        rx_pkts = stats[key]['rx']['total_pkts']
        if is_pfc_stream(key):
            print("PFC Stream {} : Rx {} Tx {}".format(key, rx_pkts, tx_pkts))
        elif rx_pkts != tx_pkts:
            print("Stream {} test FAILED: Rx {} Tx {}".format(key, rx_pkts, tx_pkts))
            return key
        else:
            print("Stream {} test PASSED: Rx {} Tx {}".format(key, rx_pkts, tx_pkts))
    return None

# Configure a router interface on the traffic generator
def tgen_port_config(dev_handle, p_handle, ip_addr, nmask, gw):
    dev_handle.tg_interface_config(mode='config', port_handle=p_handle,\
            intf_ip_addr=ip_addr, netmask=nmask, gateway=gw)

# Create a PFC (Priority Flow Control) stream for a given traffic class
def create_pfc_stream(dev_handle, p_handle, tc_num, src_mac, pps):
    if tc_num < 0 or tc_num > 7:
        print("Bad traffic class {}".format(tc_num))
        return

    new_stream = \
        dev_handle.tg_traffic_config(mode='create', port_handle=p_handle,\
            l2_encap='ethernet_ii', mac_src=src_mac, \
            mac_dst='01:80:C2:00:00:01', ether_type='8808',\
            custom_pattern=pfc_tc_table[tc_num],\
            rate_pps=pps, transmit_mode='continuous', \
            high_speed_result_analysis=1)
    pfc_streams.append(new_stream)
    all_streams.append(new_stream)
    return (len(all_streams) - 1)

# Create a regular traffic stream for a given traffic class and DSCP
def create_traffic_stream(dut, dev_handle, p_handle, tc_num, ip_src, ip_dst, dst_mac, pkt_size, percnt):

    if dut not in tc_to_dscp_map or tc_num >= len(tc_to_dscp_map[dut]):
        st.warn("Traffic class {} unavailable".format(tc_num))
        return -1

    new_stream = \
        dev_handle.tg_traffic_config(mode='create', \
            port_handle=p_handle, l3_protocol='ipv4', \
            ip_src_addr=ip_src, ip_dst_addr=ip_dst,\
            mac_dst=dst_mac, ip_dscp=tc_to_dscp_map[dut][tc_num],\
            ip_ecn='01', frame_size=pkt_size, rate_percent=percnt,\
            transmit_mode='continuous', high_speed_result_analysis=1)
    all_streams.append(new_stream)
    return (len(all_streams) - 1)

def start_stream(dev_handle, idx):
    dev_handle.tg_traffic_control(action='run', handle=all_streams[idx]['stream_id'])

def stop_stream(dev_handle, idx):
    dev_handle.tg_traffic_control(action='stop', handle=all_streams[idx]['stream_id'])

def stop_all_streams(dev_handle, p_handle):
    dev_handle.tg_traffic_control(action='stop', port_handle=p_handle)

def remove_stream(dev_handle, idx):
    dev_handle.tg_traffic_config(mode='remove', handle=all_streams[idx]['stream_id'])

def remove_all_streams(dev_handle, p_handle):
    dev_handle.tg_traffic_config(mode='remove', port_handle=p_handle)

def traffic_gen_init(dut, asic_str=''):
    get_tc_to_dscp_map(dut, asic_str)

