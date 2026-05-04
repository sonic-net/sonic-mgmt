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
'0101 0008 0000 0000 0000 ffff 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000',
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
        mode='create', port_handle=port_handle,
        l2_encap='ethernet_ii', mac_src=src_mac,
        # frame_size=60,
        mac_dst='01:80:C2:00:00:01', ether_type='8808',
        data_pattern=pfc_tc_table[tc_num],
        data_pattern_mode='fixed',
        rate_pps=pps, transmit_mode='continuous',
        high_speed_result_analysis=1)
    return new_stream['stream_id']

def ignore_pfc_stream():
    global tgen_handle

    vars = st.get_testbed_vars()
    tgen_handle, port_handle = tgapi.get_handle_byname('T1D3P1')

    # Configure MAC address on the IXIA port
    result = tgen_handle.tg_interface_config(
        mode='config',
        port_handle=port_handle,
        src_mac_addr='00:11:22:33:44:01'
    )

    # Create a PFC stream for Lossless TC at 40k pps
    str1 = create_pfc_stream('T1D3P1', LOSSLESS_TC, '00:11:22:33:44:01', 40000)
    pre_cnt =  get_pfc_rx_count(vars.D3, vars.D3T1P1, LOSSLESS_TC)

    tgen_handle.tg_traffic_control(action='apply')
    tgen_handle.tg_topology_test_control(action='start_all_protocols')
    tgen_handle.tg_traffic_control(action='run')
    st.wait(30)
    tgen_handle.tg_traffic_control(action='stop')
    pfc_delta =  get_pfc_rx_count(vars.D3, vars.D3T1P1, LOSSLESS_TC) - pre_cnt
    tgen_handle.tg_traffic_config(mode='remove', stream_id=str1)
    if pfc_delta >= (30 * 40000):
        st.report_pass('msg', f'{pfc_delta} PFC frames generated')
    else:
        st.report_fail('msg', f'{pfc_delta} PFC frames generated')
