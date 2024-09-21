import pytest
import logging
from tests.common.helpers.assertions import pytest_require, pytest_assert                               # noqa: F401
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts_multidut         # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port,\
    snappi_api, snappi_dut_base_config, get_snappi_ports, get_snappi_ports_for_rdma, cleanup_config      # noqa: F401
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map                                        # noqa: F401
from tests.snappi_tests.variables import MULTIDUT_PORT_INFO, MULTIDUT_TESTBED
from tests.snappi_tests.multidut.pfcwd.files.\
    pfcwd_multidut_runtime_traffic_helper import run_pfcwd_runtime_traffic_test
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology('multidut-tgen')]


@pytest.mark.parametrize("multidut_port_info", MULTIDUT_PORT_INFO[MULTIDUT_TESTBED])
def test_pfcwd_runtime_traffic(snappi_api,                  # noqa: F811
                               conn_graph_facts,            # noqa: F811
                               fanout_graph_facts_multidut,          # noqa: F811
                               duthosts,
                               prio_dscp_map,               # noqa: F811
                               get_snappi_ports,     # noqa: F811
                               tbinfo,      # noqa: F811
                               multidut_port_info,   # noqa: F811
                               ):
    """
    Test PFC watchdog's impact on runtime traffic

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority)
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

    all_prio_list = prio_dscp_map.keys()

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.rx_port = snappi_ports[0]
    snappi_extra_params.rx_port_id = snappi_ports[0]["port_id"]
    snappi_extra_params.tx_port = snappi_ports[1]
    snappi_extra_params.tx_port_id = snappi_ports[1]["port_id"]

    run_pfcwd_runtime_traffic_test(api=snappi_api,
                                   testbed_config=testbed_config,
                                   port_config_list=port_config_list,
                                   conn_data=conn_graph_facts,
                                   fanout_data=fanout_graph_facts_multidut,
                                   dut_port=snappi_ports[0]['peer_port'],
                                   prio_list=all_prio_list,
                                   prio_dscp_map=prio_dscp_map,
                                   snappi_extra_params=snappi_extra_params)

    cleanup_config(duthosts, snappi_ports)
