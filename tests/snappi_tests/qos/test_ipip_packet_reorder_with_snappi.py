import logging
import pytest

from tests.snappi_tests.qos.files.packet_reorder_helper import run_ipip_packet_reorder_test
from tests.common.helpers.assertions import pytest_require
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts # noqa F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port,\
    snappi_api, snappi_testbed_config # noqa F401
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map # noqa F401

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology('tgen')]


def test_ip_in_ip_packet_reorder(snappi_api, # noqa F811
                                 snappi_testbed_config, # noqa F811
                                 conn_graph_facts, # noqa F811
                                 fanout_graph_facts, # noqa F811
                                 duthosts,
                                 rand_one_dut_hostname,
                                 rand_one_dut_portname_oper_up,
                                 enum_dut_all_prio,
                                 prio_dscp_map): # noqa F811
    """
    Validate that IPinIP RDMA packets are not being reordered on a single lossless priority

    Args:
        snappi_api (pytest fixture): SNAPPI session
        snappi_testbed_config (pytest fixture): testbed configuration information
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_hostname (str): hostname of DUT
        rand_one_dut_portname_oper_up (str): port to test, e.g., 's6100-1|Ethernet0'
        enum_dut_all_prio (str): priority (lossy and lossless) to test, e.g., 's6100-1|3'
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).

    Returns:
        N/A
    """

    dut_hostname, dut_port = rand_one_dut_portname_oper_up.split('|')
    dut_hostname2, prio = enum_dut_all_prio.split('|')
    pytest_require(rand_one_dut_hostname == dut_hostname == dut_hostname2,
                   "Priority and port are not mapped to the expected DUT")

    testbed_config, port_config_list = snappi_testbed_config
    duthost = duthosts[rand_one_dut_hostname]
    test_prio = int(prio)
    flow_prio_list = [test_prio]

    run_ipip_packet_reorder_test(api=snappi_api,
                                 testbed_config=testbed_config,
                                 port_config_list=port_config_list,
                                 conn_data=conn_graph_facts,
                                 fanout_data=fanout_graph_facts,
                                 duthost=duthost,
                                 dut_port=dut_port,
                                 flow_prio_list=flow_prio_list,
                                 prio_dscp_map=prio_dscp_map)
