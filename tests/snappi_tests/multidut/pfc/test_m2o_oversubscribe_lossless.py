import pytest
import logging
from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts, \
    fanout_graph_facts_multidut     # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
    get_snappi_ports_single_dut, snappi_testbed_config, \
    get_snappi_ports_multi_dut, is_snappi_multidut, \
    snappi_api, snappi_dut_base_config, get_snappi_ports, get_snappi_ports_for_rdma, cleanup_config  # noqa: F401
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map, \
    lossless_prio_list                                                                          # noqa: F401
from tests.snappi_tests.variables import MULTIDUT_PORT_INFO, MULTIDUT_TESTBED
from tests.snappi_tests.multidut.pfc.files.m2o_oversubscribe_lossless_helper import (
     run_m2o_oversubscribe_lossless_test
    )
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
logger = logging.getLogger(__name__)
pytestmark = [pytest.mark.topology('multidut-tgen', 'tgen')]


@pytest.mark.parametrize("multidut_port_info", MULTIDUT_PORT_INFO[MULTIDUT_TESTBED])
def test_m2o_oversubscribe_lossless(snappi_api,                              # noqa: F811
                                    conn_graph_facts,                        # noqa: F811
                                    fanout_graph_facts_multidut,                      # noqa: F811
                                    duthosts,
                                    prio_dscp_map,                           # noqa: F811
                                    lossless_prio_list,                      # noqa: F811
                                    get_snappi_ports,             # noqa: F811
                                    tbinfo,
                                    multidut_port_info):             # noqa: F811

    """
    Run PFC oversubsription lossless for many to one traffic pattern

    Args:
        snappi_api (pytest fixture): SNAPPI session
        snappi_testbed_config (pytest fixture): testbed configuration information
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        lossy_prio_list (pytest fixture): list of lossy priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority)
        tbinfo (pytest fixture): fixture provides information about testbed
        get_snappi_ports (pytest fixture): gets snappi ports and connected DUT port info and returns as a list

    Brief Description:
        This test uses the m2o_oversubscribe_lossless_helper.py file and generates 2 Background traffic and
        2 Test flow traffic. The test data traffic will include two lossless traffic streams, with the SONiC default
        lossless priorities of 3 and 4, for one stream to be at 25% while the other is at 30% bandwidth.
        The background traffic will consist of two lossy traffic streams, each with randomly chosen priorities
        (0..2, 5..7), and each having 25% bandwidth. The __gen_traffic() generates the flows. run_traffic()
        starts the flows and returns the flows stats. The verify_m2o_oversubscribtion_results() takes in the
        flows stats and verifies the loss criteria mentioned in the flag. Ex: 'loss': '16' means the flows to
        have 16% loss, 'loss': '0' means there shouldn't be any loss

    Returns:
        N/A
    """
    for testbed_subtype, rdma_ports in multidut_port_info.items():
        tx_port_count = 2
        rx_port_count = 1
        snappi_port_list = get_snappi_ports
        pytest_assert(len(snappi_port_list) >= tx_port_count + rx_port_count,
                      "Need Minimum of 3 ports defined in ansible/files/*links.csv file")

        pytest_assert(len(rdma_ports['tx_ports']) >= tx_port_count,
                      'MULTIDUT_PORT_INFO doesn\'t have the required Tx ports defined for \
                      testbed {}, subtype {} in variables.py'.
                      format(MULTIDUT_TESTBED, testbed_subtype))

        pytest_assert(len(rdma_ports['rx_ports']) >= rx_port_count,
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

    all_prio_list = prio_dscp_map.keys()
    test_prio_list = lossless_prio_list
    pause_prio_list = test_prio_list
    bg_prio_list = [x for x in all_prio_list if x not in pause_prio_list]

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    run_m2o_oversubscribe_lossless_test(api=snappi_api,
                                        testbed_config=testbed_config,
                                        port_config_list=port_config_list,
                                        conn_data=conn_graph_facts,
                                        fanout_data=fanout_graph_facts_multidut,
                                        dut_port=snappi_ports[0]['peer_port'],
                                        pause_prio_list=pause_prio_list,
                                        test_prio_list=test_prio_list,
                                        bg_prio_list=bg_prio_list,
                                        prio_dscp_map=prio_dscp_map,
                                        snappi_extra_params=snappi_extra_params)
    cleanup_config(duthosts, snappi_ports)
