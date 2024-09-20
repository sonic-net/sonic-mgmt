import pytest
import collections
import random
import logging
from tabulate import tabulate # noqa F401
from tests.common.helpers.assertions import pytest_assert, pytest_require    # noqa: F401
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts_multidut         # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
    snappi_api, snappi_dut_base_config, get_snappi_ports, get_snappi_ports_for_rdma, cleanup_config      # noqa: F401
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map, \
    lossless_prio_list   # noqa F401
from tests.snappi_tests.variables import MULTIDUT_PORT_INFO, MULTIDUT_TESTBED
from tests.snappi_tests.files.helper import skip_ecn_tests
from tests.common.snappi_tests.read_pcap import is_ecn_marked
from tests.snappi_tests.multidut.ecn.files.multidut_helper import run_ecn_test
from tests.common.snappi_tests.common_helpers import packet_capture # noqa F401
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
logger = logging.getLogger(__name__)
pytestmark = [pytest.mark.topology('multidut-tgen')]


@pytest.mark.parametrize("multidut_port_info", MULTIDUT_PORT_INFO[MULTIDUT_TESTBED])
def test_red_accuracy(request,
                      snappi_api,                       # noqa: F811
                      conn_graph_facts,                 # noqa: F811
                      fanout_graph_facts_multidut,               # noqa: F811
                      duthosts,
                      lossless_prio_list,     # noqa: F811
                      get_snappi_ports,     # noqa: F811
                      tbinfo,      # noqa: F811
                      multidut_port_info,     # noqa: F811
                      prio_dscp_map):                    # noqa: F811
    """
    Measure RED/ECN marking accuracy of the device under test (DUT).
    Dump queue length vs. ECN marking probability results into a file.

    Args:
        request (pytest fixture): pytest request object
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        tbinfo (pytest fixture): fixture provides information about testbed
        get_snappi_ports (pytest fixture): gets snappi ports and connected DUT port info and returns as a list
    Returns:
        N/A
    """
    # disable_test = request.config.getoption("--disable_ecn_snappi_test")
    # if disable_test:
    #     pytest.skip("test_red_accuracy is disabled")

    for testbed_subtype, rdma_ports in multidut_port_info.items():
        tx_port_count = 1
        rx_port_count = 1
        snappi_port_list = get_snappi_ports
        pytest_assert(MULTIDUT_TESTBED == tbinfo['conf-name'],
                      "The testbed name from testbed file doesn't match with MULTIDUT_TESTBED in variables.py ")
        pytest_assert(len(snappi_port_list) >= tx_port_count + rx_port_count,
                      "Need Minimum of 2 ports defined in ansible/files/*links.csv file")

        pytest_assert(len(rdma_ports['tx_ports']) >= tx_port_count,
                      'MULTIDUT_PORT_INFO doesn\'t have the required Tx ports defined for \
                      testbed {}, subtype {} in variables.py'.
                      format(MULTIDUT_TESTBED, testbed_subtype))

        pytest_assert(len(rdma_ports['rx_ports']) >= rx_port_count,
                      'MULTIDUT_PORT_INFO doesn\'t have the required Rx ports defined for \
                      testbed {}, subtype {} in variables.py'.
                      format(MULTIDUT_TESTBED, testbed_subtype))
        logger.info('Running test for testbed subtype: {}'.format(testbed_subtype))
        snappi_ports = get_snappi_ports_for_rdma(snappi_port_list, rdma_ports,
                                                 tx_port_count, rx_port_count, MULTIDUT_TESTBED)
        testbed_config, port_config_list, snappi_ports = snappi_dut_base_config(duthosts,
                                                                                snappi_ports,
                                                                                snappi_api)

    skip_ecn_tests(snappi_ports[0]['duthost']) or skip_ecn_tests(snappi_ports[1]['duthost'])
    lossless_prio = random.sample(lossless_prio_list, 1)

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    snappi_extra_params.packet_capture_type = packet_capture.IP_CAPTURE
    snappi_extra_params.is_snappi_ingress_port_cap = True
    snappi_extra_params.ecn_params = {'kmin': 500000, 'kmax': 900000, 'pmax': 5}
    data_flow_pkt_size = 1024
    data_flow_pkt_count = 910
    num_iterations = 1

    logger.info("Running ECN red accuracy test with ECN params: {}".format(snappi_extra_params.ecn_params))
    logger.info("Running ECN red accuracy test for {} iterations".format(num_iterations))

    snappi_extra_params.traffic_flow_config.data_flow_config = {
            "flow_pkt_size": data_flow_pkt_size,
            "flow_pkt_count": data_flow_pkt_count
        }

    ip_pkts_list = run_ecn_test(api=snappi_api,
                                testbed_config=testbed_config,
                                port_config_list=port_config_list,
                                conn_data=conn_graph_facts,
                                fanout_data=fanout_graph_facts_multidut,
                                dut_port=snappi_ports[0]['peer_port'],
                                lossless_prio=lossless_prio,
                                prio_dscp_map=prio_dscp_map,
                                iters=num_iterations,
                                snappi_extra_params=snappi_extra_params)

    # Check if we capture packets of all the rounds
    pytest_assert(len(ip_pkts_list) == num_iterations,
                  'Only capture {}/{} rounds of packets'.format(len(ip_pkts_list), num_iterations))

    logger.info("Instantiating a queue length vs. ECN marking probability dictionary")
    queue_mark_cnt = {}
    for i in range(data_flow_pkt_count):
        queue_len = (data_flow_pkt_count - i) * data_flow_pkt_size
        queue_mark_cnt[queue_len] = 0

    logger.info("Check that all packets are captured for each iteration")
    for i in range(num_iterations):
        ip_pkts = ip_pkts_list[i]
        # Check if we capture all the packets in each round
        pytest_assert(len(ip_pkts) == data_flow_pkt_count,
                      'Only capture {}/{} packets in round {}'.format(len(ip_pkts), data_flow_pkt_count, i))

        for j in range(data_flow_pkt_count):
            ip_pkt = ip_pkts[j]
            queue_len = (data_flow_pkt_count - j) * data_flow_pkt_size

            if is_ecn_marked(ip_pkt):
                queue_mark_cnt[queue_len] += 1

    # Dump queue length vs. ECN marking probability into logger file
    logger.info("------- Dumping queue length vs. ECN marking probability data ------")
    output_table = []
    queue_mark_cnt = collections.OrderedDict(sorted(queue_mark_cnt.items()))
    for queue, mark_cnt in list(queue_mark_cnt.items()):
        output_table.append([queue, float(mark_cnt)/num_iterations])
    logger.info(tabulate(output_table, headers=['Queue Length', 'ECN Marking Probability']))
    cleanup_config(duthosts, snappi_ports)
