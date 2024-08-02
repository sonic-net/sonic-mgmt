import pytest
import random
import logging

from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, \
    fanout_graph_facts                                                                  # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
    snappi_api, snappi_dut_base_config, get_tgen_peer_ports, get_multidut_snappi_ports, \
    get_multidut_tgen_peer_port_set, cleanup_config                                       # noqa: F401
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map, lossless_prio_list      # noqa F401

from tests.snappi_tests.variables import config_set, line_card_choice
from tests.snappi_tests.multidut.ecn.files.multidut_helper import run_ecn_test
from tests.common.snappi_tests.read_pcap import is_ecn_marked
from tests.snappi_tests.files.helper import skip_ecn_tests
from tests.common.snappi_tests.common_helpers import packet_capture
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
logger = logging.getLogger(__name__)
pytestmark = [pytest.mark.topology('multidut-tgen')]


@pytest.mark.parametrize('line_card_choice', [line_card_choice])
@pytest.mark.parametrize('linecard_configuration_set', [config_set])
def test_dequeue_ecn(request,
                     snappi_api,                    # noqa: F811
                     conn_graph_facts,              # noqa: F811
                     fanout_graph_facts,            # noqa: F811
                     duthosts,
                     rand_one_dut_lossless_prio,
                     line_card_choice,
                     linecard_configuration_set,
                     get_multidut_snappi_ports,      # noqa: F811
                     prio_dscp_map):                # noqa: F811
    """
    Test if the device under test (DUT) performs ECN marking at the egress

    Args:
        request (pytest fixture): pytest request object
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_lossless_prio (str): name of lossless priority to test, e.g., 's6100-1|3'
        line_card_choice: Line card choice to be mentioned in the variable.py file
        linecard_configuration_set : Line card classification, (min 1 or max 2  hostnames and asics to be given)
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).

    Returns:
        N/A
    """

    if line_card_choice not in linecard_configuration_set.keys():
        pytest_require(False, "Invalid line_card_choice value passed in parameter")

    if (len(linecard_configuration_set[line_card_choice]['hostname']) == 2):
        dut_list = random.sample(duthosts.frontend_nodes, 2)
        duthost1, duthost2 = dut_list
    elif (len(linecard_configuration_set[line_card_choice]['hostname']) == 1):
        dut_list = [dut for dut in duthosts.frontend_nodes if
                    linecard_configuration_set[line_card_choice]['hostname'] == [dut.hostname]]
        duthost1, duthost2 = dut_list[0], dut_list[0]
    else:
        pytest_require(False, "Hostname can't be an empty list")

    snappi_port_list = get_multidut_snappi_ports(line_card_choice=line_card_choice,
                                                 line_card_info=linecard_configuration_set[line_card_choice])
    if len(snappi_port_list) < 2:
        pytest_require(False, "Need Minimum of 2 ports for the test")

    snappi_ports = get_multidut_tgen_peer_port_set(line_card_choice, snappi_port_list, config_set, 2)

    testbed_config, port_config_list, snappi_ports = snappi_dut_base_config(dut_list,
                                                                            snappi_ports,
                                                                            snappi_api)

    _, lossless_prio = rand_one_dut_lossless_prio.split('|')
    skip_ecn_tests(duthost1)
    skip_ecn_tests(duthost2)
    lossless_prio = int(lossless_prio)
    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.duthost1 = duthost1
    snappi_extra_params.multi_dut_params.duthost2 = duthost2
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports
    snappi_extra_params.packet_capture_type = packet_capture.IP_CAPTURE
    snappi_extra_params.is_snappi_ingress_port_cap = True
    snappi_extra_params.ecn_params = {'kmin': 50000, 'kmax': 51000, 'pmax': 100}
    data_flow_pkt_size = 1024
    data_flow_pkt_count = 101
    num_iterations = 1
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
                           dut_port=snappi_ports[0]['peer_port'],
                           lossless_prio=lossless_prio,
                           prio_dscp_map=prio_dscp_map,
                           iters=num_iterations,
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
