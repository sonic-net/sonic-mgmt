import pytest
import logging

from tests.common.helpers.assertions import pytest_require
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts
from tests.common.snappi.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port,\
    snappi_api, snappi_testbed_config
from tests.common.snappi.qos_fixtures import prio_dscp_map
from files.pfcwd_burst_storm_helper import run_pfcwd_burst_storm_test

logger = logging.getLogger(__name__)

pytestmark = [ pytest.mark.topology('tgen') ]

def test_pfcwd_burst_storm_single_lossless_prio(snappi_api,
                                                snappi_testbed_config,
                                                conn_graph_facts,
                                                fanout_graph_facts,
                                                duthosts,
                                                rand_one_dut_hostname,
                                                rand_one_dut_portname_oper_up,
                                                rand_one_dut_lossless_prio,
                                                prio_dscp_map):

    """
    Test PFC watchdog under bursty PFC storms on a single lossless priority

    Args:
        snappi_api (pytest fixture): SNAPPI session
        snappi_testbed_config (pytest fixture): testbed configuration information
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_hostname (str): hostname of DUT
        rand_one_dut_portname_oper_up (str): port to test, e.g., 's6100-1|Ethernet0'
        rand_one_dut_lossless_prio (str): name of lossless priority to test, e.g., 's6100-1|3'
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority)

    Returns:
        N/A
    """
    dut_hostname, dut_port = rand_one_dut_portname_oper_up.split('|')
    dut_hostname2, lossless_prio = rand_one_dut_lossless_prio.split('|')
    pytest_require(rand_one_dut_hostname == dut_hostname == dut_hostname2,
                   "Priority and port are not mapped to the expected DUT")

    duthost = duthosts[rand_one_dut_hostname]

    testbed_config, port_config_list = snappi_testbed_config
    lossless_prio = int(lossless_prio)

    run_pfcwd_burst_storm_test(api=snappi_api,
                               testbed_config=testbed_config,
                               port_config_list=port_config_list,
                               conn_data=conn_graph_facts,
                               fanout_data=fanout_graph_facts,
                               duthost=duthost,
                               dut_port=dut_port,
                               prio_list=[lossless_prio],
                               prio_dscp_map=prio_dscp_map)
