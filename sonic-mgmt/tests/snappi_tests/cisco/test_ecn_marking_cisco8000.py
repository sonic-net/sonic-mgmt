import logging
import pytest

from tests.snappi_tests.cisco.files.ecnhelper import run_ecn_test_cisco8000
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port,\
    snappi_api, snappi_testbed_config
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map, all_prio_list, lossless_prio_list,\
    lossy_prio_list
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [ pytest.mark.topology('tgen') ]

# ecn counter is per TC
# Two streams are started for the indicated line rate.
#  first stream from first tx port is for TC 3
#  second stream from second tx port is for TC 4
#  each TC has same dwrr weight. 
# line rate percent for TC 3, 4 from tx two ports, respectively 
#test_flow_percent_list=[[90, 15]]
test_flow_percent_list=[[90, 15], [53, 49], [15, 90], [49, 49], [50,50]]

@pytest.mark.parametrize("test_flow_percent", test_flow_percent_list)
def test_ecn_multi_lossless_prio(snappi_api,
                                 snappi_testbed_config,
                                 conn_graph_facts,
                                 fanout_graph_facts,
                                 duthosts,
                                 rand_one_dut_hostname,
                                 rand_one_dut_portname_oper_up,
                                 lossless_prio_list,
                                 lossy_prio_list,
                                 prio_dscp_map,
                                 test_flow_percent):
    """
    Test if PFC can pause multiple lossless priorities

    Args:
        snappi_api (pytest fixture): SNAPPI session
        snappi_testbed_config (pytest fixture): testbed configuration information
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_hostname (str): hostname of DUT
        rand_one_dut_portname_oper_up (str): port to test, e.g., 's6100-1|Ethernet0'
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        lossy_prio_list (pytest fixture): list of all the lossy priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).

    Returns:
        N/A
    """

    dut_hostname, dut_port = rand_one_dut_portname_oper_up.split('|')
    pytest_require(rand_one_dut_hostname == dut_hostname,
                   "Port is not mapped to the expected DUT")

    testbed_config, port_config_list = snappi_testbed_config
    duthost = duthosts[rand_one_dut_hostname]
    pause_prio_list = lossless_prio_list
    test_prio_list = lossless_prio_list
    bg_prio_list = lossy_prio_list

    run_ecn_test_cisco8000(api=snappi_api,
                 testbed_config=testbed_config,
                 port_config_list=port_config_list,
                 conn_data=conn_graph_facts,
                 fanout_data=fanout_graph_facts,
                 duthost=duthost,
                 dut_port=dut_port,
                 global_pause=False,
                 pause_prio_list=pause_prio_list,
                 test_prio_list=test_prio_list,
                 bg_prio_list=bg_prio_list,
                 prio_dscp_map=prio_dscp_map,
                 test_traffic_pause=False,
                 test_flow_percent=test_flow_percent)

