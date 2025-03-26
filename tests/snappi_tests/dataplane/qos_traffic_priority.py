import logging
import pytest
from re import search

from tests.snappi_tests.qos.files.qos_priority_helper import run_qos_priority_test
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts                      # noqa F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port,\
    snappi_api, snappi_testbed_config, get_snappi_ports, get_snappi_ports_single_dut, get_snappi_ports_multi_dut       # noqa F401
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map, all_prio_list, lossless_prio_list,\
   lossy_prio_list                         # noqa F401
from tests.common.reboot import reboot
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology('tgen')]

def test_qos_traffic_priorities(snappi_api,                 # noqa F811
                                snappi_testbed_config,      # noqa F811
                                conn_graph_facts,           # noqa F811
                                fanout_graph_facts,         # noqa F811
                                duthosts,
                                rand_one_dut_hostname,
                                rand_one_dut_portname_oper_up,
                                get_snappi_ports
                                ):
    """
    Test if PFC can pause a single lossless priority

    Args:
        snappi_api (pytest fixture): SNAPPI session
        snappi_testbed_config (pytest fixture): testbed configuration information
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_hostname (str): hostname of DUT
        rand_one_dut_portname_oper_up (str): port to test, e.g., 's6100-1|Ethernet0'
        enum_dut_lossless_prio (str): lossless priority to test, e.g., 's6100-1|3'
        all_prio_list (pytest fixture): list of all the priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).

    Returns:
        N/A
    """
    # Get Sonic port names: Ethernet64, Etherenet68, etc
    dut_test_ports = get_snappi_ports
    sonic_ethernet_port_list = []
    for ethernetPort in dut_test_ports:
        sonic_ethernet_port_list.append(ethernetPort["peer_port"])   

    dut_hostname, dut_port = rand_one_dut_portname_oper_up.split('|')
    
    # pytest_require(rand_one_dut_hostname == dut_hostname == dut_hostname2,
    #                "Priority and port are not mapped to the expected DUT")

    testbed_config, port_config_list = snappi_testbed_config
    duthost = duthosts[rand_one_dut_hostname]

    run_qos_priority_test(snappi_api,
                          testbed_config,
                          port_config_list,
                          duthost,
                          dut_port,
                          sonic_ethernet_port_list,
                          conn_graph_facts,
                          fanout_graph_facts)
