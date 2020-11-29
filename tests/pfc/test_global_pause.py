import logging
import time
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

def test_global_pause(ixia_api,
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
    Test if IEEE 802.3X pause (a.k.a., global pause) will impact any priority

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
    test_prio_list = lossless_prio_list
    bg_prio_list = lossy_prio_list
    
    run_pfc_test(api=ixia_api,
                 testbed_config=ixia_t0_testbed,
                 conn_data=conn_graph_facts,
                 fanout_data=fanout_graph_facts,
                 duthost=duthost,
                 dut_port=dut_port,
                 global_pause=True,
                 pause_prio_list=None,
                 test_prio_list=test_prio_list,
                 bg_prio_list=bg_prio_list,
                 prio_dscp_map=prio_dscp_map,
                 test_traffic_pause=False)
