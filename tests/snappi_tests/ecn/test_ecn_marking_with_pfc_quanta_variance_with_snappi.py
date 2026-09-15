import pytest
import logging
import os
from tests.snappi_tests.ecn.files.helper import run_ecn_marking_with_pfc_quanta_variance
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
logger = logging.getLogger(__name__)
pytestmark = [pytest.mark.topology('multidut-tgen', 'tgen')]


@pytest.fixture(autouse=True, scope="module")
def number_of_tx_rx_ports():
    yield (1, 1)


# tuple of -gmin in MB, -gmax in MB and -gdrop in percentage
test_ecn_config = [(1, 4, 5), (1, 4, 10), (2, 4, 5), (2, 4, 10)]


@pytest.mark.parametrize("test_ecn_config", test_ecn_config)
def test_ecn_marking_with_pfc_quanta_variance(
                                request,
                                snappi_api,
                                conn_graph_facts,
                                fanout_graph_facts_multidut,
                                duthosts,
                                lossless_prio_list,
                                tbinfo,
                                test_ecn_config,
                                prio_dscp_map,
                                tgen_port_info):

    """
    Verify ECN marking on lossless prio with varying XOFF quanta

    Args:
        request (pytest fixture): pytest request object
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        tbinfo (pytest fixture): fixture provides information about testbed
        test_ecn_config (tuple): ECN config tuple of (gmin MB, gmax MB, gdrop %)
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority)
        tgen_port_info (pytest fixture): Snappi testbed and port details
    Returns:
        N/A
    """

    testbed_config, port_config_list, snappi_ports = tgen_port_info
    log_file_path = request.config.getoption("--log-file", default=None)

    logger.info("Snappi Ports : {}".format(snappi_ports))
    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    run_ecn_marking_with_pfc_quanta_variance(
                            api=snappi_api,
                            testbed_config=testbed_config,
                            port_config_list=port_config_list,
                            dut_port=snappi_ports[0]['peer_port'],
                            test_prio_list=lossless_prio_list,
                            prio_dscp_map=prio_dscp_map,
                            log_dir=os.path.dirname(log_file_path) if log_file_path else None,
                            test_ecn_config=test_ecn_config,
                            snappi_extra_params=snappi_extra_params)
