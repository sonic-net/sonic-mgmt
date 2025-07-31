import time
import sys
import json
import pytest
import pprint
from traffic_stream_api import (
    traffic_gen_init, print_stream_stats, tgen_port_config, create_pfc_stream, 
    create_traffic_stream, start_stream, stop_stream, remove_stream,
    stop_all_streams, remove_all_streams
)

from spytest import st, tgapi, SpyTestDict

import apis.system.port as papi
import apis.system.interface as intapi
import apis.routing.ip as ip_obj
import apis.system.basic as basic_obj
from apis.common.sonic_hooks import SonicHooks

SPIRENT_12_1_MAC = '00:10:94:00:00:0B'
SPIRENT_12_9_MAC = '00:10:94:00:00:0C'


'''
    See testbed file for more details
    Spirent 12/1 <--> Ethernet104
    Spirent 12/9 <--> Ethernet120
'''

@pytest.fixture(scope="module", autouse=True)
def setup_topo():
    global tesbed_dict
    global is_multi_asic
    global dut1
    global tg1_d1_p1, tg1_d1_p1_port 
    global tg1_d1_p2, tg1_d1_p2_port
    global pfc_ids
    global p1_ids
    global p2_ids

    st.log("setup topology Started")
    sonichooks = SonicHooks()
    testbed_dict = st.ensure_min_topology("D1")
    pprint.pprint(testbed_dict)
    dut1 = testbed_dict.D1
    # Assume both DUT1 and DUT2 are multi asic or single asic
    is_multi_asic = sonichooks.is_multi_asic(dut1)
    tg1_d1_p1, tg1_d1_p1_port = tgapi.get_handle_byname("T1D1P1")
    tg1_d1_p2, tg1_d1_p2_port = tgapi.get_handle_byname("T1D1P2")
    st.log("setup topology Done")
    pfc_ids = []
    p1_ids = []
    p2_ids = []
    traffic_gen_init(dut1, '-n asic1')
    yield

def test_two_device_traffic():
    # Access DUT and ports
    st.config(dut1, "config interface -n asic1 ip add Ethernet104 104.1.1.1/24")
    st.config(dut1, "config interface -n asic1 ip add Ethernet120 120.1.1.1/24")
    st.config(dut1, "ip netns exec asic1 arp -s 104.1.1.10" + SPIRENT_12_1_MAC) 
    st.config(dut1, "ip netns exec asic1 arp -s 120.1.1.10" + SPIRENT_12_9_MAC) 

    # shut/no shut the Sonic interfaces
    st.config(dut1, "config platform cisco interface Ethernet104 tx disable")
    st.config(dut1, "config platform cisco interface Ethernet120 tx disable")
    time.sleep(1)
    st.config(dut1, "config platform cisco interface Ethernet104 tx enable")
    st.config(dut1, "config platform cisco interface Ethernet120 tx enable")

    # Configure IP address and subnet mask on Traffic generator ports
    tgen_port_config(tg1_d1_p1, tg1_d1_p1_port, '104.1.1.10', '255.255.255.0', \
            '104.1.1.1')
    tgen_port_config(tg1_d1_p2, tg1_d1_p2_port, '120.1.1.10', '255.255.255.0', \
            '120.1.1.1')

    # Create PFC3 frame stream on P1
    pfc_ids.append(create_pfc_stream(tg1_d1_p1, tg1_d1_p1_port, 3, \
                       SPIRENT_12_1_MAC, 9000))
    # Create PFC4 frame stream on P1
    pfc_ids.append(create_pfc_stream(tg1_d1_p1, tg1_d1_p1_port, 4, \
                       SPIRENT_12_1_MAC, 9000))

    # Configure 8 traffic streams on P2 and P1
    for i in range(8):
        id = create_traffic_stream(dut1, tg1_d1_p2, tg1_d1_p2_port,\
               i, '120.1.1.10', '104.1.1.10', '44:b6:be:46:48:d3', 128, 10)
        if id != -1:
            p2_ids.append(id)

        id = create_traffic_stream(dut1, tg1_d1_p1, tg1_d1_p1_port,\
               i, '104.1.1.10', '120.1.1.10', '44:b6:be:46:48:d3', 128, 10)
        if id != -1:
            p1_ids.append(id)

    # Run traffic on 8 streams
    for id in p1_ids:
        start_stream(tg1_d1_p1, id)
    for id in p2_ids:
        start_stream(tg1_d1_p2, id)

    time.sleep(5)

    # Stop traffic on 8 streams
    for id in p1_ids:
        stop_stream(tg1_d1_p1, id)
    for id in p2_ids:
        stop_stream(tg1_d1_p2, id)

    # Print the stream statistics
    rv1 = print_stream_stats(tg1_d1_p1, tg1_d1_p1_port)
    rv2 = print_stream_stats(tg1_d1_p2, tg1_d1_p2_port)

    # Remove all streams on ports P1 and P2
    remove_all_streams(tg1_d1_p1, tg1_d1_p1_port);
    remove_all_streams(tg1_d1_p2, tg1_d1_p2_port);

    tg1_d1_p1.local_stc_tapi_call(f'stc::perform DetachPorts -PortList port1')
    tg1_d1_p1.local_stc_tapi_call(f'stc::apply')
    tg1_d1_p2.local_stc_tapi_call(f'stc::perform DetachPorts -PortList port2')
    tg1_d1_p2.local_stc_tapi_call(f'stc::apply')

    if rv1 is None and rv2 is None:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("Test failed")
