import pytest

from tests.common.helpers.assertions import pytest_require
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts
from tests.common.ixia.ixia_fixtures import ixia_api_serv_ip, ixia_api_serv_port,\
    ixia_api_serv_user, ixia_api_serv_passwd, ixia_api, ixia_t0_testbed
from tests.common.ixia.qos_fixtures import prio_dscp_map, all_prio_list, lossless_prio_list,\
    lossy_prio_list

from files.helper import run_pfc_test

@pytest.mark.topology("tgen")
@pytest.mark.disable_loganalyzer

def test_pfc_pause_single_lossy_prio(ixia_api,
                                     ixia_t0_testbed,
                                     conn_graph_facts,
                                     fanout_graph_facts,
                                     duthosts,
                                     enum_dut_hostname, 
                                     enum_dut_portname_oper_up, 
                                     enum_dut_lossy_prio, 
                                     all_prio_list,
                                     prio_dscp_map):
    """
    Test if PFC will impact a single lossy priority

    Args:
        ixia_api (pytest fixture): IXIA session 
        ixia_t0_testbed (pytest fixture): L2/L3 config of a T0 testbed
        conn_graph_facts (pytest fixture): connection graph  
        fanout_graph_facts (pytest fixture): fanout graph 
        duthosts (pytest fixture): list of DUTs
        enum_dut_hostname (str): hostname of DUT
        enum_dut_portname_oper_up (str): name of port to test, e.g., 's6100-1|Ethernet0'
        enum_dut_lossy_prio (str): name of lossy priority to test, e.g., 's6100-1|2'
        all_prio_list (pytest fixture): list of all the priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).

    Returns:
        None
    """

    dut_hostname, dut_port = enum_dut_portname_oper_up.split('|')
    dut_hostname2, lossy_prio = enum_dut_lossy_prio.split('|')
    pytest_require(enum_dut_hostname == dut_hostname == dut_hostname2, 
                   "Priority and port are not mapped to the expected DUT")

    duthost = duthosts[enum_dut_hostname]
    lossy_prio = int(lossy_prio)    

    pause_prio_list = [lossy_prio]
    test_prio_list = [lossy_prio]
    bg_prio_list = [p for p in all_prio_list]
    bg_prio_list.remove(lossy_prio)

    run_pfc_test(api=ixia_api,
                 testbed_config=ixia_t0_testbed,
                 conn_data=conn_graph_facts,
                 fanout_data=fanout_graph_facts,
                 duthost=duthost,
                 dut_port=dut_port,
                 global_pause=False,
                 pause_prio_list=pause_prio_list,
                 test_prio_list=test_prio_list,
                 bg_prio_list=bg_prio_list,
                 prio_dscp_map=prio_dscp_map,
                 test_traffic_pause=False)


def test_pfc_pause_multi_lossy_prio(ixia_api,
                                    ixia_t0_testbed,
                                    conn_graph_facts,
                                    fanout_graph_facts,
                                    duthosts, 
                                    enum_dut_hostname, 
                                    enum_dut_portname_oper_up, 
                                    lossless_prio_list, 
                                    lossy_prio_list,
                                    prio_dscp_map):
    """
    Test if PFC will impact multiple lossy priorities

    Args:
        ixia_api (pytest fixture): IXIA session 
        ixia_t0_testbed (pytest fixture): L2/L3 config of a T0 testbed
        conn_graph_facts (pytest fixture): connection graph  
        fanout_graph_facts (pytest fixture): fanout graph 
        duthosts (pytest fixture): list of DUTs
        enum_dut_hostname (str): hostname of DUT
        enum_dut_portname_oper_up (str): name of port to test, e.g., 's6100-1|Ethernet0'
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        lossy_prio_list (pytest fixture): list of all the lossy priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).

    Returns:
        None
    """

    dut_hostname, dut_port = enum_dut_portname_oper_up.split('|')
    pytest_require(enum_dut_hostname == dut_hostname, 
                   "Port is not mapped to the expected DUT")

    duthost = duthosts[enum_dut_hostname]
    pause_prio_list = lossy_prio_list
    test_prio_list = lossy_prio_list
    bg_prio_list = lossless_prio_list
    
    run_pfc_test(api=ixia_api,
                 testbed_config=ixia_t0_testbed,
                 conn_data=conn_graph_facts,
                 fanout_data=fanout_graph_facts,
                 duthost=duthost,
                 dut_port=dut_port,
                 global_pause=False,
                 pause_prio_list=pause_prio_list,
                 test_prio_list=test_prio_list,
                 bg_prio_list=bg_prio_list,
                 prio_dscp_map=prio_dscp_map,
                 test_traffic_pause=False)
