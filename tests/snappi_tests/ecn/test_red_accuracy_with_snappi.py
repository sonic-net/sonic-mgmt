import pytest
import collections
import random
import logging
from tabulate import tabulate
from tests.common.helpers.assertions import pytest_assert
from tests.common.snappi_tests.read_pcap import is_ecn_marked
from tests.snappi_tests.ecn.files.helper import run_ecn_test
from tests.common.snappi_tests.common_helpers import packet_capture
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.common.snappi_tests.snappi_fixtures import cleanup_config
logger = logging.getLogger(__name__)
pytestmark = [pytest.mark.topology('multidut-tgen', 'tgen')]


@pytest.fixture(autouse=True, scope="module")
def number_of_tx_rx_ports():
    yield (1, 1)


def test_red_accuracy(request,
                      snappi_api,
                      conn_graph_facts,
                      fanout_graph_facts_multidut,
                      duthosts,
                      lossless_prio_list,
                      tgen_port_info,
                      tbinfo,
                      prio_dscp_map):
    """
    Measure RED/ECN marking accuracy of the device under test (DUT).
    Dump queue length vs. ECN marking probability results into a file.

    Args:
        request (pytest fixture): pytest request object
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        tgen_port_info (pytest fixture): Snappi testbed and port details
        tbinfo (pytest fixture): fixture provides information about testbed
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority)
    Returns:
        N/A
    """
    # disable_test = request.config.getoption("--disable_ecn_snappi_test")
    # if disable_test:
    #     pytest.skip("test_red_accuracy is disabled")

    testbed_config, port_config_list, snappi_ports = tgen_port_info

    lossless_prio = random.sample(lossless_prio_list, 1)
    lossless_prio = int(lossless_prio[0])

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
