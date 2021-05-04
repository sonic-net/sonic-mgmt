import pytest

from tests.common.helpers.assertions import pytest_require, pytest_assert
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts
from tests.common.ixia.ixia_fixtures import ixia_api_serv_ip, ixia_api_serv_port,\
    ixia_api_serv_user, ixia_api_serv_passwd, ixia_api, ixia_testbed_config
from tests.common.ixia.qos_fixtures import prio_dscp_map, all_prio_list

from files.pfcwd_runtime_traffic_helper import run_pfcwd_runtime_traffic_test

pytestmark = [ pytest.mark.topology('tgen') ]

def test_pfcwd_runtime_traffic(ixia_api,
                               ixia_testbed_config,
                               conn_graph_facts,
                               fanout_graph_facts,
                               duthosts,
                               rand_one_dut_hostname,
                               rand_one_dut_portname_oper_up,
                               all_prio_list,
                               prio_dscp_map):
    """
    Test PFC watchdog's impact on runtime traffic

    Args:
        ixia_api (pytest fixture): IXIA session
        ixia_testbed_config (pytest fixture): testbed configuration information
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_hostname (str): hostname of DUT
        rand_one_dut_portname_oper_up (str): port to test, e.g., 's6100-1|Ethernet0'
        all_prio_list (pytest fixture): list of all the priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority)

    Returns:
        N/A
    """
    dut_hostname, dut_port = rand_one_dut_portname_oper_up.split('|')
    pytest_require(rand_one_dut_hostname == dut_hostname,
                   "Port is not mapped to the expected DUT")

    duthost = duthosts[rand_one_dut_hostname]
    testbed_config, port_config_list = ixia_testbed_config

    run_pfcwd_runtime_traffic_test(api=ixia_api,
                                   testbed_config=testbed_config,
                                   port_config_list=port_config_list,
                                   conn_data=conn_graph_facts,
                                   fanout_data=fanout_graph_facts,
                                   duthost=duthost,
                                   dut_port=dut_port,
                                   prio_list=all_prio_list,
                                   prio_dscp_map=prio_dscp_map)
