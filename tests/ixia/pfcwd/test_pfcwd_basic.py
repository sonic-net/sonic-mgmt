import pytest

from tests.common.helpers.assertions import pytest_require, pytest_assert
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts
from tests.common.ixia.ixia_fixtures import ixia_api_serv_ip, ixia_api_serv_port,\
    ixia_api_serv_user, ixia_api_serv_passwd, ixia_api, ixia_testbed
from tests.common.ixia.qos_fixtures import prio_dscp_map, lossless_prio_list,\
    start_pfcwd_default

from files.pfcwd_basic_helper import run_pfcwd_basic_test

@pytest.mark.topology("tgen")

@pytest.mark.parametrize("trigger_pfcwd", [True, False])
def test_pfcwd_basic_single_lossless_prio(ixia_api,
                                          ixia_testbed,
                                          conn_graph_facts,
                                          fanout_graph_facts,
                                          duthosts,
                                          rand_one_dut_hostname,
                                          enum_dut_portname_oper_up,
                                          enum_dut_lossless_prio,
                                          prio_dscp_map,
                                          trigger_pfcwd,
                                          start_pfcwd_default):
    """
    Run PFC watchdog basic test on a single lossless priority

    Args:
        ixia_api (pytest fixture): IXIA session
        ixia_testbed (pytest fixture): L2/L3 config of a T0 testbed
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_hostname (str): hostname of DUT
        enum_dut_portname_oper_up (str): name of port to test, e.g., 's6100-1|Ethernet0'
        enum_dut_lossless_prio (str): name of lossless priority to test, e.g., 's6100-1|3'
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority)
        trigger_pfcwd (bool): if PFC watchdog is expected to be triggered
        start_pfcwd_default (pytest fixture): start PFC watchdog with the default setting

    Returns:
        N/A
    """
    dut_hostname, dut_port = enum_dut_portname_oper_up.split('|')
    dut_hostname2, lossless_prio = enum_dut_lossless_prio.split('|')
    pytest_require(rand_one_dut_hostname == dut_hostname == dut_hostname2,
                   "Priority and port are not mapped to the expected DUT")

    duthost = duthosts[rand_one_dut_hostname]
    lossless_prio = int(lossless_prio)

    run_pfcwd_basic_test(api=ixia_api,
                         testbed_config=ixia_testbed,
                         conn_data=conn_graph_facts,
                         fanout_data=fanout_graph_facts,
                         duthost=duthost,
                         dut_port=dut_port,
                         prio_list=[lossless_prio],
                         prio_dscp_map=prio_dscp_map,
                         trigger_pfcwd=trigger_pfcwd)


@pytest.mark.parametrize("trigger_pfcwd", [True, False])
def test_pfcwd_basic_multi_lossless_prio(ixia_api,
                                         ixia_testbed,
                                         conn_graph_facts,
                                         fanout_graph_facts,
                                         duthosts,
                                         rand_one_dut_hostname,
                                         enum_dut_portname_oper_up,
                                         lossless_prio_list,
                                         prio_dscp_map,
                                         trigger_pfcwd,
                                         start_pfcwd_default):
    """
    Run PFC watchdog basic test on multiple lossless priorities

    Args:
        ixia_api (pytest fixture): IXIA session
        ixia_testbed (pytest fixture): L2/L3 config of a T0 testbed
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_hostname (str): hostname of DUT
        enum_dut_portname_oper_up (str): name of port to test, e.g., 's6100-1|Ethernet0'
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority)
        trigger_pfcwd (bool): if PFC watchdog is expected to be triggered
        start_pfcwd_default (pytest fixture): start PFC watchdog with the default setting

    Returns:
        N/A
    """
    dut_hostname, dut_port = enum_dut_portname_oper_up.split('|')
    pytest_require(rand_one_dut_hostname == dut_hostname,
                   "Port is not mapped to the expected DUT")

    duthost = duthosts[rand_one_dut_hostname]

    run_pfcwd_basic_test(api=ixia_api,
                         testbed_config=ixia_testbed,
                         conn_data=conn_graph_facts,
                         fanout_data=fanout_graph_facts,
                         duthost=duthost,
                         dut_port=dut_port,
                         prio_list=lossless_prio_list,
                         prio_dscp_map=prio_dscp_map,
                         trigger_pfcwd=trigger_pfcwd)
