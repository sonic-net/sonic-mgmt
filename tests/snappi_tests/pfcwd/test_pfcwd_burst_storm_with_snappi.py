import pytest
import random
import logging
from tests.common.helpers.assertions import pytest_require                                              # noqa: F401
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts, \
    fanout_graph_facts_multidut                                                                         # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
    get_snappi_ports_single_dut, snappi_testbed_config, \
    get_snappi_ports_multi_dut, is_snappi_multidut, snappi_port_selection, tgen_port_info, \
    snappi_api, get_snappi_ports, get_snappi_ports_for_rdma, cleanup_config                             # noqa: F401
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map, all_prio_list, \
    lossless_prio_list, lossy_prio_list                                                                 # noqa: F401
from tests.snappi_tests.pfcwd.files.pfcwd_burst_storm_helper import run_pfcwd_burst_storm_test
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
logger = logging.getLogger(__name__)
pytestmark = [pytest.mark.topology('multidut-tgen', 'tgen')]


@pytest.fixture(autouse=True, scope='module')
def number_of_tx_rx_ports():
    yield (1, 1)


def test_pfcwd_burst_storm_single_lossless_prio(snappi_api,                     # noqa: F811
                                                conn_graph_facts,               # noqa: F811
                                                fanout_graph_facts_multidut,    # noqa: F811
                                                duthosts,
                                                lossless_prio_list,             # noqa: F811
                                                get_snappi_ports,               # noqa: F811
                                                tbinfo,                         # noqa: F811
                                                tgen_port_info,                 # noqa: F811
                                                number_of_tx_rx_ports,          # noqa: F811
                                                prio_dscp_map,                  # noqa: F811
                                                ):

    """
    Test PFC watchdog under bursty PFC storms on a single lossless priority.
    PFC storms are sent for duration of half of the PFCWD detection interval.
    PFC storms are spaced at twice the PFCWD detection interval.
    Expectation is that PFCWD Storm will not be set as PFC duration is less than detection interval.
    Packets of lossless priorities will be queued on DUT due to PFCs and sent to egress once PFC storm stops.

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        lossless_prio_list (pytest fixture): list of lossless priorities.
        get_snappi_ports (pytest fixture): gets snappi ports and connected DUT port info and returns as a list
        tbinfo (pytest fixture): fixture provides information about testbed
        tgen_port_info (pytest fixture): fixture provides list of interfaces of appropriate speed and sub-type.
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority)

    Returns:
        N/A
    """
    testbed_config, port_config_list, snappi_ports = tgen_port_info
    for port in snappi_ports:
        logger.info('Snappi ports selected for test:{}'.format(port['peer_port']))

    lossless_prio = random.sample(lossless_prio_list, 1)
    lossless_prio = int(lossless_prio[0])
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
