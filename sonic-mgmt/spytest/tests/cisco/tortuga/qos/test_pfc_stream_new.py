import time
import sys
import json
import pytest
import pprint
from spytest import st, tgapi, SpyTestDict

LOSSLESS_TC = 3

# Table of PFC traffic class patterns (hex strings for each TC)
# The API is intelligent enough to ignore spaces
pfc_tc_table = [\
'0101 0001 ffff 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000',
'0101 0002 0000 ffff 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000',
'0101 0004 0000 0000 ffff 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000',
'0101 0008 0000 0000 0000 fff3 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000',
'0101 0010 0000 0000 0000 0000 ffff 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000',
'0101 0020 0000 0000 0000 0000 0000 ffff 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000',
'0101 0040 0000 0000 0000 0000 0000 0000 ffff 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000',
'0101 0080 0000 0000 0000 0000 0000 0000 0000 ffff 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000',
]

def get_pfc_rx_count(dut, port, priority):
    """
    Get PFC Rx frame count for given port and priority.
    
    Args:
        dut: DUT handle
        port: Interface name
        priority: Priority/TC value (0-7)
        
    Returns:
        Integer count of PFC frames received
    """
    priority = int(priority)  # Ensure priority is an integer
    cmd = f"show pfc counters | sed -n '/Port Rx/,/^$/p' | grep {port}"
    st.log(f"Reading PFC Rx counters: DUT={dut}, port={port}, priority={priority}")
    st.log(f"Command: {cmd}")
    try:
        output = st.show(dut, cmd, skip_tmpl=True)
        st.log(f"Raw PFC Rx output: {output}")
        # Output can be a string or list; normalize to get the line with port data
        if isinstance(output, list):
            # Find the line containing the port name
            line = next((l for l in output if port in l), None)
        else:
            # String output - find the line with port name
            lines = output.strip().split('\n')
            line = next((l for l in lines if port in l), None)
        
        if line:
            parts = line.split()
            st.log(f"Parsed parts: {parts}")
            # Format: PortName  PFC0  PFC1  PFC2  PFC3  PFC4  PFC5  PFC6  PFC7
            if len(parts) > priority + 1:
                count = int(parts[priority + 1].replace(',', ''))
                st.log(f"PFC Rx count for port={port}, priority={priority}: {count}")
                return count
    except Exception as e:
        st.log(f"Error reading PFC Rx counters: {e}")
    st.log(f"PFC Rx count for port={port}, priority={priority}: 0 (default)")
    return 0


# Create a PFC (Priority Flow Control) stream for a given traffic class
def create_pfc_stream(tgen_src_port, tc_num, src_mac, pps):
    if tc_num < 0 or tc_num > 7:
        print("Bad traffic class {}".format(tc_num))
        return

    _, port_handle = tgapi.get_handle_byname(tgen_src_port)
    new_stream = tgen_handle.tg_traffic_config(
        mode='create', 
        port_handle=port_handle,
        l2_encap='ethernet_ii', 
        mac_src=src_mac,
        # frame_size=60,
        mac_dst='01:80:C2:00:00:01', 
        ether_type='8808',
        data_pattern=pfc_tc_table[tc_num],
        data_pattern_mode='fixed',
        rate_pps=pps, 
        transmit_mode='continuous',
        high_speed_result_analysis=1)
    return new_stream['stream_id']

def ignore_pfc_stream():
    global tgen_handle

    vars = st.get_testbed_vars()
    tgen_handle, port_handle = tgapi.get_handle_byname('T1D4P1')

    # Configure MAC address on the IXIA port
    result = tgen_handle.tg_interface_config(
        mode='config',
        port_handle=port_handle,
        src_mac_addr='00:11:22:33:44:01'
    )

    # Create a PFC stream for Lossless TC at 40k pps
    str1 = create_pfc_stream('T1D4P1', LOSSLESS_TC, '00:11:22:33:44:01', 40000)
    pre_cnt =  get_pfc_rx_count(vars.D4, vars.D4T1P1, LOSSLESS_TC)

    tgen_handle.tg_traffic_control(action='apply')
    tgen_handle.tg_topology_test_control(action='start_all_protocols')
    tgen_handle.tg_traffic_control(action='run')
    st.wait(30)
    tgen_handle.tg_traffic_control(action='stop')
    pfc_delta =  get_pfc_rx_count(vars.D4, vars.D4T1P1, LOSSLESS_TC) - pre_cnt
    tgen_handle.tg_traffic_config(mode='remove', stream_id=str1)
    if pfc_delta >= (30 * 40000):
        st.report_pass('msg', f'{pfc_delta} PFC frames generated')
    else:
        st.report_fail('msg', f'{pfc_delta} PFC frames generated')


def ignore_compare_three_streams():
    """
    Compare three different stream creation approaches:
    1. Original PFC stream (mac_src, mac_dst, ether_type params)
    2. Raw PFC with full L2 header embedded in data_pattern
    3. NGPF-based IPv6 stream (like in L2VNI ECN test)
    
    Use breakpoint to inspect all three in IXIA UI.
    """
    global tgen_handle

    vars = st.get_testbed_vars()
    tgen_handle, port_handle = tgapi.get_handle_byname('T1D4P1')

    PFC_DST_MAC = '01:80:C2:00:00:01'
    SRC_MAC = '00:11:22:33:44:01'
    PFC_ETHERTYPE = '8808'
    TC3_PAYLOAD = '0101 0008 0000 0000 0000 ffff 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000'

    # ========================================================================
    # STREAM 1: Original approach (mac_src, mac_dst, ether_type as params)
    # ========================================================================
    st.banner("STREAM 1: Original PFC approach (L2 params)")
    
    # Configure interface first
    tgen_handle.tg_interface_config(
        mode='config',
        port_handle=port_handle,
        src_mac_addr=SRC_MAC
    )
    
    stream1 = tgen_handle.tg_traffic_config(
        mode='create',
        port_handle=port_handle,
        l2_encap='ethernet_ii',
        mac_src=SRC_MAC,
        mac_dst=PFC_DST_MAC,
        ether_type=PFC_ETHERTYPE,
        data_pattern=TC3_PAYLOAD,
        data_pattern_mode='fixed',
        rate_pps=1000,
        transmit_mode='continuous',
        high_speed_result_analysis=1
    )
    st.log(f"Stream 1 (Original): {stream1}")

    # ========================================================================
    # STREAM 2: Raw frame with FULL L2 header embedded in data_pattern
    # ========================================================================
    st.banner("STREAM 2: Raw frame with full L2 header in data_pattern")
    
    # Full Ethernet frame: DST MAC (6) + SRC MAC (6) + EtherType (2) + PFC payload
    # DST: 01:80:C2:00:00:01 -> 0180 C200 0001
    # SRC: 00:11:22:33:44:01 -> 0011 2233 4401
    # EtherType: 8808
    # Payload: TC3 pattern
    RAW_FRAME_WITH_L2 = '0180 C200 0001 0011 2233 4401 8808 0101 0008 0000 0000 0000 ffff 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000'
    
    stream2 = tgen_handle.tg_traffic_config(
        mode='create',
        port_handle=port_handle,
        l2_encap='ethernet_ii',
        data_pattern=RAW_FRAME_WITH_L2,
        data_pattern_mode='fixed',
        rate_pps=1000,
        transmit_mode='continuous',
        high_speed_result_analysis=1
    )
    st.log(f"Stream 2 (Raw L2 in data_pattern): {stream2}")

    # ========================================================================
    # STREAM 3: NGPF-based IPv6 stream (like L2VNI ECN test)
    # ========================================================================
    st.banner("STREAM 3: NGPF IPv6 stream (like L2VNI test)")
    
    # Create NGPF topology with IPv6 endpoint
    ngpf_result = tgen_handle.tg_interface_config(
        port_handle=port_handle,
        mode='config',
        ipv6_intf_addr='2001::2',
        ipv6_prefix_length='64',
        ipv6_gateway='2001::254',
        src_mac_addr=SRC_MAC,
        arp_send_req='1'
    )
    st.log(f"NGPF interface config result: {ngpf_result}")
    
    # Get topology handle for NGPF traffic
    topology_handle = ngpf_result.get('ipv6_handle', ngpf_result.get('handle'))
    st.log(f"NGPF topology handle: {topology_handle}")
    
    # Create IPv6 traffic using NGPF (emulation handles)
    # This simulates what L2VNI test does with config_traffic_item
    stream3 = tgen_handle.tg_traffic_config(
        mode='create',
        port_handle=port_handle,
        l3_protocol='ipv6',
        ipv6_src_addr='2001::2',
        ipv6_dst_addr='2001::1',
        mac_src=SRC_MAC,
        mac_dst='00:AA:BB:CC:DD:EE',  # dummy dst MAC
        ipv6_traffic_class=14,  # DSCP 3 << 2 + ECN bits
        frame_size=128,
        rate_percent=10,
        transmit_mode='continuous',
        high_speed_result_analysis=1
    )
    st.log(f"Stream 3 (NGPF IPv6): {stream3}")

    # ========================================================================
    # STREAM 4: PFC stream AFTER NGPF setup (problem case)
    # ========================================================================
    st.banner("STREAM 4: PFC stream AFTER NGPF (problem case)")
    
    stream4 = tgen_handle.tg_traffic_config(
        mode='create',
        port_handle=port_handle,
        l2_encap='ethernet_ii',
        mac_src=SRC_MAC,
        mac_dst=PFC_DST_MAC,
        ether_type=PFC_ETHERTYPE,
        data_pattern=TC3_PAYLOAD,
        data_pattern_mode='fixed',
        rate_pps=1000,
        transmit_mode='continuous',
        high_speed_result_analysis=1
    )
    st.log(f"Stream 4 (PFC after NGPF): {stream4}")

    # Apply all streams
    st.banner("Applying all 4 streams - check in IXIA UI")
    tgen_handle.tg_traffic_control(action='apply')

    # Breakpoint to inspect all streams in IXIA UI
    st.log("="*60)
    st.log("CHECK IXIA UI NOW:")
    st.log("  Stream 1: Original PFC (should work)")
    st.log("  Stream 2: Raw L2 in data_pattern")
    st.log("  Stream 3: NGPF IPv6")
    st.log("  Stream 4: PFC after NGPF (problem case)")
    st.log("="*60)
    #import pdb; pdb.set_trace()

    # Cleanup
    st.banner("Test complete - cleaning up streams")
    for s in [stream1, stream2, stream3, stream4]:
        if s and 'stream_id' in s:
            tgen_handle.tg_traffic_config(mode='remove', stream_id=s['stream_id'])

    st.report_pass('msg', 'Stream comparison complete - check IXIA UI')
