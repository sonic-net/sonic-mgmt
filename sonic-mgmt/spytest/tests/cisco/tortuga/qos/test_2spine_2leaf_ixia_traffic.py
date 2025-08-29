import time
import os
import sys
import pytest
import pprint
import tortuga_common_utils as common_util
import traffic_stream_ixia_api as stream_api

from spytest import st, tgapi, SpyTestDict
module_dir = os.path.join(os.path.dirname(__file__), '../../', 'common')
sys.path.insert(0, os.path.abspath(module_dir))

from traffic_stream_api import (get_tc_to_dscp_map)


@pytest.fixture(scope="module", autouse=True)
def setup_topo():
    global tb_dict

    st.log("setup topology Started")
    # 4 tgen ports to D3 and 4 tgen ports to D4
    tb_dict = st.ensure_min_topology("T1D3:4", "T1D4:4")
    st.banner('Print testbed dict')
    pprint.pprint(tb_dict)
    stream_api.tgen_handle, _ = tgapi.get_handle_byname('T1D3P1')

    for dut in tb_dict['dut_list']:
        common_op = '''
            sonic-clear counters\nsonic-clear dropcounters\n
            sonic-clear queuecounters\nconfig qos reload\n
            '''
        result = st.show(dut, "show int count | awk '{print $1}' | grep Eth",
                         skip_tmpl=True)
        lines = result.splitlines()
        for i in lines:
            if 'Eth' not in i:
                continue
            common_op +=\
                'ip addr flush dev {}\nip route flush dev {}\n'.format(i, i)
        st.config(dut, '{}'.format(common_op), skip_tmpl=True)

    stream_api.config_two_spine_two_leaf_topo(tb_dict)
    st.log("setup topology Done")
    yield

def test_2spine_2leaf_traffic():
    # Test assumes a 4 device setup with 2 spine nodes, 2 leaf nodes and 1 TGEN
    # 4 tgen ports doing to each leaf and 2 connections from each leaf to 
    # each spine
    st.banner('Test STARTED')
    stream_table = []

    # The frame sizes, packets per second(pps) and traffic class are 
    # arbitrarily chosen below
    for i in range(1):
        s = stream_api.create_traffic_stream(tb_dict, 'T1D3P1', 'T1D4P1',
                                             256, 100000, 3)
        if s != None:
            stream_table.append(s)

        s = stream_api.create_traffic_stream(tb_dict, 'T1D4P4', 'T1D3P4',
                                             512, 100000, 4)
        if s != None:
            stream_table.append(s)
        s = stream_api.create_traffic_stream(tb_dict, 'T1D3P2', 'T1D4P2',
                                             64, 100000, 0)
        if s != None:
            stream_table.append(s)
        s = stream_api.create_traffic_stream(tb_dict, 'T1D3P1', 'T1D4P1',
                                             128, 100000, 6)
        if s != None:
            stream_table.append(s)

    for s in stream_table:
        stream_api.start_traffic_stream(s)
    st.wait(30)
    for s in stream_table:
        stream_api.stop_traffic_stream(s)
    st.wait(30)

    stats = stream_api.collect_traffic_stream_stats()
    for s in stream_table:
        stream_api.delete_traffic_stream(s)
    stream_api.check_stats_dict(stats)
