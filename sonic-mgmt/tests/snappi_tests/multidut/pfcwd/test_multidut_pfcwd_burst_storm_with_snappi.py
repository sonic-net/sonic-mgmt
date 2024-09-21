import pytest
import random
import logging
from tests.common.helpers.assertions import pytest_require, pytest_assert                               # noqa: F401
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts_multidut         # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
    snappi_api, snappi_dut_base_config, get_snappi_ports, get_snappi_ports_for_rdma, cleanup_config      # noqa: F401
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map, all_prio_list,\
    lossless_prio_list, lossy_prio_list     # noqa F401
from tests.snappi_tests.variables import MULTIDUT_PORT_INFO, MULTIDUT_TESTBED
from tests.snappi_tests.multidut.pfcwd.files.pfcwd_multidut_burst_storm_helper import run_pfcwd_burst_storm_test
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
logger = logging.getLogger(__name__)
pytestmark = [pytest.mark.topology('multidut-tgen')]


@pytest.mark.parametrize("multidut_port_info", MULTIDUT_PORT_INFO[MULTIDUT_TESTBED])
def test_pfcwd_burst_storm_single_lossless_prio(snappi_api,             # noqa: F811
                                                conn_graph_facts,       # noqa: F811
                                                fanout_graph_facts_multidut,     # noqa: F811
                                                duthosts,
                                                lossless_prio_list,    # noqa: F811
                                                get_snappi_ports,    # noqa: F811
                                                tbinfo,      # noqa: F811
                                                multidut_port_info,
                                                prio_dscp_map,               # noqa: F811
                                                ):

    """
    Test PFC watchdog under bursty PFC storms on a single lossless priority

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_lossless_prio (str): name of lossless priority to test, e.g., 's6100-1|3'
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority)
        lossy_prio_list (pytest fixture): list of lossy priorities
        tbinfo (pytest fixture): fixture provides information about testbed
        get_snappi_ports (pytest fixture): gets snappi ports and connected DUT port info and returns as a list

    Returns:
        N/A
    """
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

    lossless_prio = random.sample(lossless_prio_list, 1)
    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    run_pfcwd_burst_storm_test(api=snappi_api,
                               testbed_config=testbed_config,
                               port_config_list=port_config_list,
                               conn_data=conn_graph_facts,
                               fanout_data=fanout_graph_facts_multidut,
                               dut_port=snappi_ports[0]['peer_port'],
                               prio_list=[lossless_prio],
                               prio_dscp_map=prio_dscp_map,
                               snappi_extra_params=snappi_extra_params)

    cleanup_config(duthosts, snappi_ports)
