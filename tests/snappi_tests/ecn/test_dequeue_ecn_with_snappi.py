import pytest
import logging

from tests.common.helpers.assertions import pytest_require, pytest_assert
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts                          # noqa F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port,\
    snappi_api, snappi_testbed_config           # noqa F401
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map, lossless_prio_list      # noqa F401
from tests.snappi_tests.ecn.files.helper import run_ecn_test
from tests.common.snappi_tests.read_pcap import is_ecn_marked
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.common.snappi_tests.common_helpers import packet_capture
from tests.snappi_tests.files.helper import skip_ecn_tests
from tests.common.config_reload import config_reload

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology('tgen')]


def test_dequeue_ecn(request,
                     snappi_api,                        # noqa F811
                     snappi_testbed_config,             # noqa F811
                     conn_graph_facts,                  # noqa F811
                     fanout_graph_facts,                # noqa F811
                     duthosts,
                     rand_one_dut_hostname,
                     rand_one_dut_portname_oper_up,
                     rand_one_dut_lossless_prio,
                     prio_dscp_map):                    # noqa F811
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
    dut_hostname, dut_port = rand_one_dut_portname_oper_up.split('|')
    dut_hostname2, lossless_prio = rand_one_dut_lossless_prio.split('|')
    pytest_require(rand_one_dut_hostname == dut_hostname == dut_hostname2,
                   "Priority and port are not mapped to the expected DUT")

    testbed_config, port_config_list = snappi_testbed_config
    duthost = duthosts[rand_one_dut_hostname]
    skip_ecn_tests(duthost)
    lossless_prio = int(lossless_prio)

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.packet_capture_type = packet_capture.IP_CAPTURE
    snappi_extra_params.is_snappi_ingress_port_cap = True
    snappi_extra_params.ecn_params = {'kmin': 50000, 'kmax': 51000, 'pmax': 100}
    data_flow_pkt_size = 1024
    data_flow_pkt_count = 101
    logger.info("Running ECN dequeue test with params: {}".format(snappi_extra_params.ecn_params))

    snappi_extra_params.traffic_flow_config.data_flow_config = {
            "flow_pkt_size": data_flow_pkt_size,
            "flow_pkt_count": data_flow_pkt_count
        }

    ip_pkts = run_ecn_test(api=snappi_api,
                           testbed_config=testbed_config,
                           port_config_list=port_config_list,
                           conn_data=conn_graph_facts,
                           fanout_data=fanout_graph_facts,
                           duthost=duthost,
                           dut_port=dut_port,
                           lossless_prio=lossless_prio,
                           prio_dscp_map=prio_dscp_map,
                           iters=1,
                           snappi_extra_params=snappi_extra_params)[0]

    logger.info("Running verification for ECN dequeue test")
    # Check if all the packets are captured
    pytest_assert(len(ip_pkts) == data_flow_pkt_count,
                  'Only capture {}/{} IP packets'.format(len(ip_pkts), data_flow_pkt_count))

    # Check if the first packet is ECN marked
    pytest_assert(is_ecn_marked(ip_pkts[0]), "The first packet should be marked")

    # Check if the last packet is not ECN marked
    pytest_assert(not is_ecn_marked(ip_pkts[-1]),
                  "The last packet should not be marked")

    # Teardown ECN config through a reload
    logger.info("Reloading config to teardown ECN config")
    config_reload(sonic_host=duthost, config_source='config_db', safe_reload=True)
