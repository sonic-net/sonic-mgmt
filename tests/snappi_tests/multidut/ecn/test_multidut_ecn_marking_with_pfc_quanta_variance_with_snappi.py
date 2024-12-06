import pytest
import logging
from tabulate import tabulate # noqa F401
from tests.common.helpers.assertions import pytest_assert     # noqa: F401
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts, \
                fanout_graph_facts_multidut         # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
    snappi_api, snappi_dut_base_config, get_snappi_ports, get_snappi_ports_for_rdma, cleanup_config, \
    is_snappi_multidut, get_snappi_ports_multi_dut, get_snappi_ports_single_dut   # noqa: F401
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map, \
    lossless_prio_list, disable_pfcwd   # noqa F401
from tests.snappi_tests.files.helper import multidut_port_info, setup_ports_and_dut  # noqa: F401
from tests.snappi_tests.multidut.ecn.files.multidut_helper import run_ecn_marking_with_pfc_quanta_variance
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
logger = logging.getLogger(__name__)
pytestmark = [pytest.mark.topology('multidut-tgen', 'tgen')]


@pytest.fixture(autouse=True)
def number_of_tx_rx_ports():
    yield (1, 1)


def test_ecn_marking_with_pfc_quanta_variance(
                                snappi_api,                       # noqa: F811
                                conn_graph_facts,                 # noqa: F811
                                fanout_graph_facts_multidut,               # noqa: F811
                                duthosts,
                                lossless_prio_list,     # noqa: F811
                                get_snappi_ports,     # noqa: F811
                                tbinfo,      # noqa: F811
                                disable_pfcwd,     # noqa: F811
                                prio_dscp_map,  # noqa: F811
                                setup_ports_and_dut):                    # noqa: F811
    """
    Verify ECN marking on lossless prio with varying XOFF quanta

    Args:
        request (pytest fixture): pytest request object
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        tbinfo (pytest fixture): fixture provides information about testbed
        test_flow_percent: Percentage of flow rate used for the two lossless prio
        get_snappi_ports (pytest fixture): gets snappi ports and connected DUT port info and returns as a list
    Returns:
        N/A
    """

    testbed_config, port_config_list, snappi_ports = setup_ports_and_dut

    logger.info("Snappi Ports : {}".format(snappi_ports))
    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    try:
        run_ecn_marking_with_pfc_quanta_variance(
                                api=snappi_api,
                                testbed_config=testbed_config,
                                port_config_list=port_config_list,
                                dut_port=snappi_ports[0]['peer_port'],
                                test_prio_list=lossless_prio_list,
                                prio_dscp_map=prio_dscp_map,
                                snappi_extra_params=snappi_extra_params)
    finally:
        cleanup_config(duthosts, snappi_ports)
