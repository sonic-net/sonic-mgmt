import pytest
from spytest import st, SpyTestDict

import tortuga_common_utils as common_obj
from spytest.utils import poll_wait

#####################
#                   #
#    D1 = spine0    #
#    D2 = spine1    #
#    D3 = leaf0     #
#    D4 = leaf1     #
#                   #
#####################

@pytest.fixture(scope='module', autouse=True)
def setup_teardown_basic():
    global vars
    global data_glob
    st.ensure_min_topology("D1D3:2", "D1D4:2", "D2D3:2", "D2D4:2")
    vars = st.get_testbed_vars()

    data_glob = SpyTestDict()
    data_glob.spine0 = vars.D1
    data_glob.spine1 = vars.D2
    data_glob.leaf0 = vars.D3
    data_glob.leaf1 = vars.D4
    data_glob.nodes = [vars.D1, vars.D2, vars.D3, vars.D4]

    yield 'setup_teardown_basic'

def test_qos_with_dpb():
    result = True 
    st.banner("Configure DPB on D3D1P1")
    if common_obj.configure_dynamic_breakout(data_glob.leaf0, {vars.D3D1P1 : '4x100G'}):
        st.log("Successfully configured DPB on D3D1P1.")
    else:
        st.report_fail("Failed to configure DPB on D3D1P1.")

    st.wait(10)

    if common_obj.verify_queue_counters(data_glob.leaf0, vars.D3D1P1, "UC1", ['counter_pkts', 'drop_pkts'], ['0','0'],['0','0']):
        result=False
        st.error("Expected Port entry to not exist")

    new_intfs = [vars.D3D1P1 + '_' + str(index) for index in range(1,5)]
    st.banner("Verify counters on breakout links")
    for new_intf in new_intfs:
        param_list = ['counter_pkts', 'drop_pkts']
        if not poll_wait(common_obj.verify_queue_counters, 60, data_glob.leaf0, new_intf, "UC1", param_list, ['0','0'],['0','0']):
            st.error("Queue Counter Verification failed for breakout intf {}".format(new_intf))
            result=False
        param_list = ['UC0', 'UC1', 'UC2', 'UC3', 'UC4', 'UC5', 'UC6', 'UC7']
        if not poll_wait(common_obj.verify_queue_and_priority_grp_counters, 60, data_glob.leaf0, new_intf, "unicast", param_list, ['0']*8,['0']*8, priority_group=None):
            st.error("Queue Watermark Verification for Unicast failed for breakout intf {}".format(new_intf))
            result=False
        param_list = ['MC8', 'MC9', 'MC10', 'MC11', 'MC12', 'MC13', 'MC14', 'MC15']
        if not poll_wait(common_obj.verify_queue_and_priority_grp_counters, 60, data_glob.leaf0, new_intf, "multicast", param_list, ['0']*8,['0']*8, priority_group=None):
            st.error("Queue Watermark Verification for Multicast failed for breakout intf {}".format(new_intf))
            result=False
        param_list = ['PG0', 'PG1', 'PG2', 'PG3', 'PG4', 'PG5', 'PG6', 'PG7']
        if not poll_wait(common_obj.verify_queue_and_priority_grp_counters, 60, data_glob.leaf0, new_intf, "counters", param_list, ['0']*8,['0']*8, priority_group="drop"):
            st.error("Priority-group Verification for Drop Counters failed for breakout intf {}".format(new_intf))
            result=False
        if not poll_wait(common_obj.verify_queue_and_priority_grp_counters, 60, data_glob.leaf0, new_intf, "headroom", param_list, ['N/A']*8,['N/A']*8, priority_group="watermark", check_NA=True):
            st.error("Priority-group Watermark Verification for Headroom failed for breakout intf {}".format(new_intf))
            result=False
        if not poll_wait(common_obj.verify_queue_and_priority_grp_counters, 60, data_glob.leaf0, new_intf, "shared", param_list, ['0']*8,['0']*8, priority_group="watermark"):
            st.error("Priority-group Watermark Verification for Shared failed for breakout intf {}".format(new_intf))
            result=False

    st.banner("Undo DPB on D3D1P1")
    if common_obj.configure_dynamic_breakout(data_glob.leaf0, {vars.D3D1P1 : '1x400G'}, undo=True):
        st.log("Successfully Undo DPB on D3D1P1.")
    else:
        st.report_fail("Failed to Undo DPB on D3D1P1.")

    st.banner("Verify counters after removing breakout")
    param_list = ['counter_pkts', 'drop_pkts']
    if not poll_wait(common_obj.verify_queue_counters, 60, data_glob.leaf0, vars.D3D1P1, "UC1", param_list, ['0','0'],['0','0']):
        st.error("Queue Counter Verification failed for intf {}".format(vars.D3D1P1))
        result=False
    param_list = ['UC0', 'UC1', 'UC2', 'UC3', 'UC4', 'UC5', 'UC6', 'UC7']
    if not poll_wait(common_obj.verify_queue_and_priority_grp_counters, 60, data_glob.leaf0, vars.D3D1P1, "unicast", param_list, ['0']*8,['0']*8, priority_group=None):
        st.error("Queue Watermark Verification for Unicast failed for intf {}".format(vars.D3D1P1))
        result=False
    param_list = ['MC8', 'MC9', 'MC10', 'MC11', 'MC12', 'MC13', 'MC14', 'MC15']
    if not poll_wait(common_obj.verify_queue_and_priority_grp_counters, 60, data_glob.leaf0, vars.D3D1P1, "multicast", param_list, ['0']*8,['0']*8, priority_group=None):
        st.error("Queue Watermark Verification for Multicast failed for intf {}".format(vars.D3D1P1))
        result=False
    param_list = ['PG0', 'PG1', 'PG2', 'PG3', 'PG4', 'PG5', 'PG6', 'PG7']
    if not poll_wait(common_obj.verify_queue_and_priority_grp_counters, 60, data_glob.leaf0, vars.D3D1P1, "counters", param_list, ['0']*8,['0']*8, priority_group="drop"):
        st.error("Priority-group Verification for Drop Counters failed for intf {}".format(vars.D3D1P1))
        result=False
    if not poll_wait(common_obj.verify_queue_and_priority_grp_counters, 60, data_glob.leaf0, vars.D3D1P1, "headroom", param_list, ['N/A']*8,['N/A']*8, priority_group="watermark", check_NA=True):
        st.error("Priority-group Watermark Verification for Headroom failed for intf {}".format(vars.D3D1P1))
        result=False
    if not poll_wait(common_obj.verify_queue_and_priority_grp_counters, 60, data_glob.leaf0, vars.D3D1P1, "shared", param_list, ['0']*8,['0']*8, priority_group="watermark"):
        st.error("Priority-group Watermark Verification for Shared failed for intf {}".format(vars.D3D1P1))
        result=False
    
    if not result:
        st.report_fail('test_case_failed')
    else:
        st.report_pass('test_case_passed')
