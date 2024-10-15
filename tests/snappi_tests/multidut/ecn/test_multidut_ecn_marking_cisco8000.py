import pytest
import logging
from tabulate import tabulate # noqa F401
from tests.common.helpers.assertions import pytest_assert, pytest_require    # noqa: F401
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts_multidut         # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
    snappi_api, snappi_dut_base_config, get_snappi_ports, get_snappi_ports_for_rdma, cleanup_config, \
    is_snappi_multidut, get_snappi_ports_multi_dut   # noqa: F401
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map, \
    lossless_prio_list   # noqa F401
from tests.snappi_tests.variables import MULTIDUT_PORT_INFO, MULTIDUT_TESTBED
from tests.snappi_tests.multidut.ecn.files.multidut_helper import run_ecn_test_cisco8000
from tests.common.snappi_tests.common_helpers import packet_capture # noqa F401
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
logger = logging.getLogger(__name__)
pytestmark = [pytest.mark.topology('multidut-tgen')]


@pytest.mark.parametrize("multidut_port_info", MULTIDUT_PORT_INFO[MULTIDUT_TESTBED])
def test_ecn_marking_port_toggle(
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
    Verify ECN marking both pre and post port shut/no shut toggle

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

    for testbed_subtype, rdma_ports in multidut_port_info.items():
        tx_port_count = 2
        rx_port_count = 1
        snappi_port_list = get_snappi_ports
        pytest_assert(MULTIDUT_TESTBED == tbinfo['conf-name'],
                      "The testbed name from testbed file doesn't match with MULTIDUT_TESTBED in variables.py ")
        pytest_assert(len(snappi_port_list) >= tx_port_count + rx_port_count,
                      "Need Minimum of {} ports defined in ansible/files/*links.csv file".
                      format(tx_port_count + rx_port_count))

        pytest_assert(len(rdma_ports['tx_ports']) >= tx_port_count,
                      'MULTIDUT_PORT_INFO doesn\'t have the required Tx ports defined for \
                      testbed {}, subtype {} in variables.py'.
                      format(MULTIDUT_TESTBED, testbed_subtype))

        pytest_assert(len(rdma_ports['rx_ports']) >= rx_port_count,
                      'MULTIDUT_PORT_INFO doesn\'t have the required Rx ports defined for \
                      testbed {}, subtype {} in variables.py'.
                      format(MULTIDUT_TESTBED, testbed_subtype))

        # Collect port names from rx_ports and tx_ports into a set for uniqueness
        all_ports_set = set(port['port_name'] for port in rdma_ports['rx_ports'] + rdma_ports['tx_ports'])
        pytest_assert(len(all_ports_set) >= tx_port_count + rx_port_count,
                      'MULTIDUT_PORT_INFO doesn\'t have at least {} unique ports for \
                      testbed {}, subtype {} in variables.py'.
                      format(tx_port_count + rx_port_count, MULTIDUT_TESTBED, testbed_subtype))

        logger.info('Running test for testbed subtype: {}'.format(testbed_subtype))

        if is_snappi_multidut(duthosts):
            snappi_ports = get_snappi_ports_for_rdma(snappi_port_list, rdma_ports,
                                                     tx_port_count, rx_port_count, MULTIDUT_TESTBED)
        else:
            snappi_ports = snappi_port_list

        testbed_config, port_config_list, snappi_ports = snappi_dut_base_config(duthosts,
                                                                                snappi_ports,
                                                                                snappi_api)

    logger.info("Snappi Ports : {}".format(snappi_ports))
    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    run_ecn_test_cisco8000(
                            api=snappi_api,
                            testbed_config=testbed_config,
                            port_config_list=port_config_list,
                            conn_data=conn_graph_facts,
                            fanout_data=fanout_graph_facts_multidut,
                            dut_port=snappi_ports[0]['peer_port'],
                            test_prio_list=lossless_prio_list,
                            prio_dscp_map=prio_dscp_map,
                            snappi_extra_params=snappi_extra_params)

    cleanup_config(duthosts, snappi_ports)
