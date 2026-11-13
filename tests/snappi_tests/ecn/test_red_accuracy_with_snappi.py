import pytest
import random
import logging
from itertools import zip_longest
from tabulate import tabulate
from tests.common.helpers.assertions import pytest_assert, pytest_require    # noqa: F401
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts, \
    fanout_graph_facts_multidut     # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
    get_snappi_ports_single_dut, snappi_testbed_config, \
    get_snappi_ports_multi_dut, is_snappi_multidut, \
    snappi_api, snappi_dut_base_config, get_snappi_ports, get_snappi_ports_for_rdma, cleanup_config,  \
    tgen_port_info, snappi_port_selection   # noqa: F401
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map, \
    lossless_prio_list   # noqa: F401
from tests.common.snappi_tests.read_pcap import is_ecn_marked
from tests.snappi_tests.ecn.files.helper import run_ecn_test
from tests.common.snappi_tests.common_helpers import packet_capture
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.common.broadcom_data import is_broadcom_q3d_device

logger = logging.getLogger(__name__)
pytestmark = [pytest.mark.topology('multidut-tgen', 'tgen')]


ECN_PARAMS = {
    "default": {"kmin": 500000, "kmax": 900000, "pmax": 5, "frame_size": 1024},
    # Q3D: 3950 B ~= one 4096 B DRAM cell so each histogram step maps to a cell.
    "q3d": {"kmin": 1000000, "kmax": 8000000, "pmax": 5, "frame_size": 3950},
}
PKT_COUNT_MARGIN = 50      # extra packets sent past kmax to guarantee overshoot
NUM_ITERATIONS = 1         # traffic rounds; increase to average ECN marking over multiple runs


@pytest.fixture(autouse=True, scope='module')
def number_of_tx_rx_ports():
    yield (1, 1)


def test_red_accuracy(request,
                      snappi_api,                       # noqa: F811
                      conn_graph_facts,                 # noqa: F811
                      fanout_graph_facts_multidut,               # noqa: F811
                      duthosts,
                      lossless_prio_list,     # noqa: F811
                      tgen_port_info,                            # noqa: F811
                      tbinfo,      # noqa: F811
                      prio_dscp_map):                    # noqa: F811
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
        tgen_port_info (pytest fixture): testbed config, port config list, and snappi ports
        tbinfo (pytest fixture): fixture provides information about testbed
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
    Returns:
        N/A
    """
    testbed_config, port_config_list, snappi_ports = tgen_port_info
    lossless_prio = random.sample(lossless_prio_list, 1)
    lossless_prio = int(lossless_prio[0])

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    snappi_extra_params.packet_capture_type = packet_capture.IP_CAPTURE
    snappi_extra_params.is_snappi_ingress_port_cap = True
    # Select ECN params by ASIC: Q3D needs cell-aligned frames + wider RED thresholds.
    param_key = "q3d" if is_broadcom_q3d_device(duthosts[0]) else "default"
    params = ECN_PARAMS[param_key]
    kmin, kmax, pmax, frame_size = params["kmin"], params["kmax"], params["pmax"], params["frame_size"]
    logger.info("Selected ECN params (key '%s'): %s", param_key, params)
    snappi_extra_params.ecn_params = {'kmin': kmin, 'kmax': kmax, 'pmax': pmax}
    # ceil(kmax/frame_size) packets fill the queue to kmax (the "+frame_size-1" rounds up only on
    # a leftover), plus PKT_COUNT_MARGIN packets to overshoot kmax and sample the marking plateau.
    data_flow_pkt_count = (kmax + frame_size - 1) // frame_size + PKT_COUNT_MARGIN
    num_iterations = NUM_ITERATIONS

    logger.info("Running ECN red accuracy test with ECN params: {}".format(snappi_extra_params.ecn_params))
    logger.info("Running ECN red accuracy test for {} iterations".format(num_iterations))

    snappi_extra_params.traffic_flow_config.data_flow_config = {
            "flow_pkt_size": frame_size,
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
                                snappi_extra_params=snappi_extra_params,
                                lossless_prio_list=lossless_prio_list)
    # Check if we capture packets of all the rounds
    pytest_assert(len(ip_pkts_list) == num_iterations,
                  'Only capture {}/{} rounds of packets'.format(len(ip_pkts_list), num_iterations))

    # Skip the first egress_offset packets: VOQ slip-through, never marking candidates.
    egress_offset = snappi_extra_params.egress_offset
    if egress_offset:
        logger.info("Dropping first %d egress-resident (slip-through) packets from the ECN histogram",
                    egress_offset)
    logger.info("Building queue length vs. ECN marking count histogram")

    pkt_mark_cnt = {j: 0 for j in range(egress_offset, data_flow_pkt_count)}

    for i, ip_pkts in enumerate(ip_pkts_list):
        # Check if we capture all the packets in each round
        pytest_assert(len(ip_pkts) == data_flow_pkt_count,
                      'Only capture {}/{} packets in round {}'.format(len(ip_pkts), data_flow_pkt_count, i))
        for j in range(egress_offset, data_flow_pkt_count):
            if is_ecn_marked(ip_pkts[j]):
                pkt_mark_cnt[j] += 1

    # Marking is decided at dequeue (from the ingress VOQ on DNX), so judge each packet by the queue
    # depth on departure, including itself. Marks below kmin on this axis are flagged.
    cells = []
    below_min_marks = []
    above_max_misses = []
    for j, mark_cnt in sorted(pkt_mark_cnt.items()):
        qlen = (data_flow_pkt_count - j) * frame_size
        cells.append([qlen, float(mark_cnt) / num_iterations])
        if mark_cnt and qlen < kmin:
            below_min_marks.append((j, qlen))
        if mark_cnt < num_iterations and qlen > kmax:
            above_max_misses.append((j, qlen))
    cells.sort(key=lambda cell: cell[0])

    if below_min_marks:
        qlens = [qlen for _, qlen in below_min_marks]
        logger.warning("ANOMALY: %d packet(s) were ECN-marked below kmin=%d at the platform's marking "
                       "point (queue depth %d..%d, pkt idx %d..%d)", len(below_min_marks), kmin,
                       min(qlens), max(qlens), below_min_marks[0][0], below_min_marks[-1][0])
    else:
        logger.info("No packet was marked below kmin=%d at the platform's marking point", kmin)

    if above_max_misses:
        qlens = [qlen for _, qlen in above_max_misses]
        logger.warning("ANOMALY: %d packet(s) were NOT ECN-marked in every iteration above kmax=%d at the "
                       "platform's marking point (queue depth %d..%d, pkt idx %d..%d)", len(above_max_misses),
                       kmax, min(qlens), max(qlens), above_max_misses[0][0], above_max_misses[-1][0])
    else:
        logger.info("All packets above kmax=%d were marked at the platform's marking point", kmax)

    # Pack into NUM_COLS columns side-by-side to reduce vertical scrolling.
    logger.info("------- Dumping queue length vs. ECN marking probability data ------")
    NUM_COLS = 6
    if not cells:
        logger.warning("No packets left to plot after dropping %d egress-resident (slip-through) "
                       "packets of %d; skipping ECN marking histogram dump", egress_offset, data_flow_pkt_count)
    else:
        rows_per_col = -(-len(cells) // NUM_COLS)
        columns = [cells[i:i + rows_per_col] for i in range(0, len(cells), rows_per_col)]
        output_table = [
            [v for cell in row for v in (cell or ('', ''))]
            for row in zip_longest(*columns)
        ]
        headers = ['Queue', 'Probability'] * NUM_COLS
        logger.info("\n%s", tabulate(output_table, headers=headers, tablefmt='psql'))
    cleanup_config(duthosts, snappi_ports)
