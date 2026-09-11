import pytest
import random
import logging


from tests.common.helpers.assertions import pytest_assert
from tests.snappi_tests.ecn.files.helper import run_ecn_test
from tests.common.snappi_tests.read_pcap import is_ecn_marked
from tests.common.snappi_tests.common_helpers import packet_capture
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.common.snappi_tests.snappi_fixtures import cleanup_config
logger = logging.getLogger(__name__)
pytestmark = [pytest.mark.topology('multidut-tgen', 'tgen')]


# Per-ASIC ECN dequeue test parameters.
# Broadcom devices have a different queue kmin and require more packets to be
# sent to see the marked packets at the end of the flow.
ECN_PARAMS_BY_ASIC = {
    'default':  {'ecn_params': {'kmin': 50000, 'kmax': 51000, 'pmax': 100}, 'pkt_count': 101},
    'broadcom': {'ecn_params': {'kmin': 40000, 'kmax': 168000, 'pmax': 100}, 'pkt_count': 301},
}


def test_dequeue_ecn(request,
                     snappi_api,
                     conn_graph_facts,
                     fanout_graph_facts_multidut,
                     duthosts,
                     lossless_prio_list,
                     get_snappi_ports,
                     tbinfo,
                     tgen_port_info,
                     prio_dscp_map):
    """
    Test if the device under test (DUT) performs ECN marking at the egress

    Args:
        request (pytest fixture): pytest request object
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        get_snappi_ports (pytest fixture): Snappi port fixture
        tbinfo (pytest fixture): fixture provides information about testbed
        tgen_port_info (pytest fixture): Snappi testbed and port details
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
    Returns:
        N/A
    """
    def _get_ecn_test_params(duthost):
        asic_type = duthost.facts['asic_type']
        return ECN_PARAMS_BY_ASIC.get(asic_type, ECN_PARAMS_BY_ASIC['default'])

    testbed_config, port_config_list, snappi_ports = tgen_port_info

    lossless_prio = random.sample(lossless_prio_list, 1)
    lossless_prio = int(lossless_prio[0])
    snappi_extra_params = SnappiTestParams()

    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports
    snappi_extra_params.packet_capture_type = packet_capture.IP_CAPTURE
    snappi_extra_params.is_snappi_ingress_port_cap = True

    data_flow_pkt_size = 1024
    ecn_test_params = _get_ecn_test_params(duthosts[0])
    snappi_extra_params.ecn_params = ecn_test_params['ecn_params']
    data_flow_pkt_count = ecn_test_params['pkt_count']

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
                           fanout_data=fanout_graph_facts_multidut,
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
    cleanup_config(duthosts, snappi_ports)
