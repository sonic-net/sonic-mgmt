import pytest

from tests.common.helpers.assertions import pytest_require, pytest_assert
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts
from tests.common.snappi.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port,\
    snappi_api, snappi_testbed_config
from tests.common.snappi.qos_fixtures import prio_dscp_map, lossless_prio_list

from files.helper import run_ecn_test, is_ecn_marked

pytestmark = [ pytest.mark.topology('tgen') ]

def test_dequeue_ecn(request,
                     snappi_api,
                     snappi_testbed_config,
                     conn_graph_facts,
                     fanout_graph_facts,
                     duthosts,
                     rand_one_dut_hostname,
                     rand_one_dut_portname_oper_up,
                     rand_one_dut_lossless_prio,
                     prio_dscp_map):
    """
    Test if the device under test (DUT) performs ECN marking at the egress

    Args:
        request (pytest fixture): pytest request object
        snappi_api (pytest fixture): SNAPPI session
        snappi_testbed_config (pytest fixture): testbed configuration information
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_hostname (str): hostname of DUT
        rand_one_dut_portname_oper_up (str): name of port to test, e.g., 's6100-1|Ethernet0'
        rand_one_dut_lossless_prio (str): name of lossless priority to test, e.g., 's6100-1|3'
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).

    Returns:
        N/A
    """
    disable_test = request.config.getoption("--disable_ecn_snappi_test")
    if disable_test:
        pytest.skip("test_dequeue_ecn is disabled")

    dut_hostname, dut_port = rand_one_dut_portname_oper_up.split('|')
    dut_hostname2, lossless_prio = rand_one_dut_lossless_prio.split('|')
    pytest_require(rand_one_dut_hostname == dut_hostname == dut_hostname2,
                   "Priority and port are not mapped to the expected DUT")

    testbed_config, port_config_list = snappi_testbed_config
    duthost = duthosts[rand_one_dut_hostname]
    lossless_prio = int(lossless_prio)

    kmin = 50000
    kmax = 51000
    pmax = 100
    pkt_size = 1024
    pkt_cnt = 100

    ip_pkts = run_ecn_test(api=snappi_api,
                           testbed_config=testbed_config,
                           port_config_list=port_config_list,
                           conn_data=conn_graph_facts,
                           fanout_data=fanout_graph_facts,
                           duthost=duthost,
                           dut_port=dut_port,
                           kmin=kmin,
                           kmax=kmax,
                           pmax=pmax,
                           pkt_size=pkt_size,
                           pkt_cnt=pkt_cnt,
                           lossless_prio=lossless_prio,
                           prio_dscp_map=prio_dscp_map,
                           iters=1)[0]


    """ Check if we capture all the packets """
    pytest_assert(len(ip_pkts) == pkt_cnt,
                  'Only capture {}/{} IP packets'.format(len(ip_pkts), pkt_cnt))

    """ Check if the first packet is marked """
    pytest_assert(is_ecn_marked(ip_pkts[0]), "The first packet should be marked")

    """ Check if the last packet is not marked """
    pytest_assert(not is_ecn_marked(ip_pkts[-1]),
                  "The last packet should not be marked")
