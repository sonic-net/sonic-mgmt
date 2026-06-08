import pytest
import random
import logging

from tests.common.helpers.assertions import pytest_assert, pytest_require    # noqa: F401
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts, \
    fanout_graph_facts_multidut     # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
    get_snappi_ports_single_dut, snappi_testbed_config, \
    get_snappi_ports_multi_dut, is_snappi_multidut, \
    snappi_api, snappi_dut_base_config, get_snappi_ports, get_snappi_ports_for_rdma, cleanup_config      # noqa: F401
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map, lossless_prio_list      # noqa: F401

from tests.snappi_tests.variables import MULTIDUT_PORT_INFO, MULTIDUT_TESTBED
from tests.snappi_tests.ecn.files.helper import run_ecn_test
from tests.common.snappi_tests.read_pcap import is_ecn_marked
from tests.snappi_tests.files.helper import skip_ecn_tests
from tests.common.snappi_tests.common_helpers import packet_capture
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
logger = logging.getLogger(__name__)
pytestmark = [pytest.mark.topology('multidut-tgen', 'tgen')]

# Per-ASIC egress buffer cell size (bytes). WRED kmin/kmax are quantized to
# this granularity by the ASIC, so test thresholds must be multiples of it.
_BRCM_CELL_SIZE = {'td2': 208, 'td3': 256, 'td4': 256,
                   'th': 208, 'th2': 208, 'th3': 208, 'th4': 208, 'th5': 254}
_MLNX_CELL_SIZE = 144  # conservative default across spc1..spc5 (96/144/192)
_CISCO_CELL_SIZE = 384


def _get_cell_size(duthost):
    asic_type = duthost.facts['asic_type']
    if asic_type == 'cisco-8000':
        return _CISCO_CELL_SIZE
    if asic_type == 'mellanox':
        return _MLNX_CELL_SIZE
    asic = duthost.get_asic_name()
    if asic in _BRCM_CELL_SIZE:
        return _BRCM_CELL_SIZE[asic]
    # Fallback: 256 is a safe upper bound for unknown Broadcom-class ASICs.
    return 256


@pytest.mark.parametrize("multidut_port_info", MULTIDUT_PORT_INFO[MULTIDUT_TESTBED])
def test_dequeue_ecn(request,
                     snappi_api,                    # noqa: F811
                     conn_graph_facts,              # noqa: F811
                     fanout_graph_facts_multidut,            # noqa: F811
                     duthosts,
                     lossless_prio_list,   # noqa: F811
                     get_snappi_ports,  # noqa: F811
                     tbinfo,      # noqa: F811
                     multidut_port_info,     # noqa: F811
                     prio_dscp_map):                # noqa: F811
    """
    Test if the device under test (DUT) performs ECN marking at the egress

    Args:
        request (pytest fixture): pytest request object
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        rand_one_dut_lossless_prio (str): name of lossless priority to test, e.g., 's6100-1|3'
        line_card_choice: Line card choice to be mentioned in the variable.py file
        linecard_configuration_set : Line card classification, (min 1 or max 2  hostnames and asics to be given)
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        tbinfo (pytest fixture): fixture provides information about testbed
        get_snappi_ports (pytest fixture): gets snappi ports and connected DUT port info and returns as a list
    Returns:
        N/A
    """

    skip_ecn_tests(duthosts[0])
    for testbed_subtype, rdma_ports in multidut_port_info.items():
        tx_port_count = 1
        rx_port_count = 1
        snappi_port_list = get_snappi_ports
        pytest_require(len(snappi_port_list) >= tx_port_count + rx_port_count,
                       "Need Minimum of 2 ports defined in ansible/files/*links.csv file")

        pytest_require(len(rdma_ports['tx_ports']) >= tx_port_count,
                       'MULTIDUT_PORT_INFO doesn\'t have the required Tx ports defined for \
                       testbed {}, subtype {} in variables.py'.
                       format(MULTIDUT_TESTBED, testbed_subtype))

        pytest_require(len(rdma_ports['rx_ports']) >= rx_port_count,
                       'MULTIDUT_PORT_INFO doesn\'t have the required Rx ports defined for \
                       testbed {}, subtype {} in variables.py'.
                       format(MULTIDUT_TESTBED, testbed_subtype))
        logger.info('Running test for testbed subtype: {}'.format(testbed_subtype))
        if is_snappi_multidut(duthosts):
            snappi_ports = get_snappi_ports_for_rdma(snappi_port_list, rdma_ports,
                                                     tx_port_count, rx_port_count, MULTIDUT_TESTBED)
        else:
            snappi_ports = get_snappi_ports
        testbed_config, port_config_list, snappi_ports = snappi_dut_base_config(duthosts,
                                                                                snappi_ports,
                                                                                snappi_api)

    lossless_prio = random.sample(lossless_prio_list, 1)
    lossless_prio = int(lossless_prio[0])
    snappi_extra_params = SnappiTestParams()

    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports
    snappi_extra_params.packet_capture_type = packet_capture.IP_CAPTURE
    snappi_extra_params.is_snappi_ingress_port_cap = True
    data_flow_pkt_size = 1024
    num_iterations = 1

    # Derive packet count from the platform's buffer cell size so the
    # dequeue window is long enough for the queue to deterministically
    # start above kmax and drain below kmin despite PFC-release /
    # first-packet timing jitter. The [kmin, kmax] band spans 60% of
    # burst_bytes; require it to be at least MIN_BAND_CELLS cells wide.
    cell_size = _get_cell_size(duthosts[0])
    cell_per_pkt = (data_flow_pkt_size + cell_size - 1) // cell_size
    MIN_BAND_CELLS = 300
    SAFETY_MARGIN = 1.5
    min_pkt_count = int(SAFETY_MARGIN * MIN_BAND_CELLS / (0.60 * cell_per_pkt)) + 1
    data_flow_pkt_count = min_pkt_count

    # Scale WRED thresholds to the data burst, aligned to the buffer cell
    # size, so the egress queue depth straddles [kmin, kmax] across the
    # dequeue window: starts above kmax (first packet 100% marked) and
    # drops below kmin before the last packet (last packet not marked).
    burst_bytes = data_flow_pkt_count * cell_per_pkt * cell_size
    kmax = (int(burst_bytes * 0.80) // cell_size) * cell_size
    kmin = (int(burst_bytes * 0.20) // cell_size) * cell_size
    pytest_assert(kmax - kmin >= MIN_BAND_CELLS * cell_size,
                  "Burst too small for cell_size={}: kmin={}, kmax={}".format(
                      cell_size, kmin, kmax))
    snappi_extra_params.ecn_params = {'kmin': kmin, 'kmax': kmax, 'pmax': 100}
    logger.info("Running ECN dequeue test with params: {} (cell_size={}, pkt_count={})".format(
        snappi_extra_params.ecn_params, cell_size, data_flow_pkt_count))

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
