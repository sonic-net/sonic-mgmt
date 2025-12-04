import pytest
import logging
from tests.common.helpers.assertions import pytest_require
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts_multidut, fanout_graph_facts                      # noqa F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port,\
    snappi_api, get_snappi_ports, is_snappi_multidut, \
    get_snappi_ports_single_dut, snappi_testbed_config, \
    get_snappi_ports_multi_dut, snappi_dut_base_config, cleanup_config, get_snappi_ports_for_rdma  # noqa: F401
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map, all_prio_list, lossless_prio_list,\
    lossy_prio_list                         # noqa F401
from tests.snappi_tests.variables import MULTIDUT_PORT_INFO, MULTIDUT_TESTBED
from tests.snappi_tests.pfc.files.helper import run_pfc_response_time_test

pytestmark = [pytest.mark.topology('tgen')]
logger = logging.getLogger(__name__)


@pytest.mark.parametrize('intf_type', ['IP'])
@pytest.mark.parametrize("multidut_port_info", MULTIDUT_PORT_INFO[MULTIDUT_TESTBED])
def test_response_time(snappi_api,                   # noqa F811
                       conn_graph_facts,                             # noqa: F811
                       fanout_graph_facts_multidut,                # noqa: F811
                       get_snappi_ports,                           # noqa: F811
                       enum_one_dut_lossless_prio,
                       duthosts,
                       lossless_prio_list,           # noqa F811
                       lossy_prio_list,              # noqa F811
                       prio_dscp_map,
                       multidut_port_info,
                       tbinfo,
                       intf_type):               # noqa F811
    """
    Test if IEEE 802.3X pause (a.k.a., global pause) will impact any priority

    Args:
        snappi_api (pytest fixture): SNAPPI session
        snappi_testbed_config (pytest fixture): testbed configuration information
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        lossy_prio_list (pytest fixture): list of all the lossy priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        intf_type (pytest paramenter): IP or VLAN interface type
    Returns:
        N/A
    """

    snappi_port_list = get_snappi_ports

    tbname = tbinfo.get('conf-name', None)

    tx_port_count = 1
    rx_port_count = 1

    pytest_require(len(snappi_port_list) >= tx_port_count + rx_port_count,
                   "Need Minimum of 2 ports defined in ansible/files/*links.csv file")

    for testbed_subtype, rdma_ports in multidut_port_info.items():
        pytest_require(len(rdma_ports['tx_ports']) >= tx_port_count,
                       'MULTIDUT_PORT_INFO doesn\'t have the required Tx ports defined for \
                      testbed {}, subtype {} in variables.py'.
                       format(MULTIDUT_TESTBED, testbed_subtype))

        pytest_require(len(rdma_ports['rx_ports']) >= rx_port_count,
                       'MULTIDUT_PORT_INFO doesn\'t have the required Rx ports defined for \
                      testbed {}, subtype {} in variables.py'.
                       format(tbname, testbed_subtype))
        logger.info('Running test for testbed subtype: {}'.format(testbed_subtype))
        if is_snappi_multidut(duthosts):
            snappi_ports = get_snappi_ports_for_rdma(snappi_port_list, rdma_ports,
                                                     tx_port_count, rx_port_count, MULTIDUT_TESTBED)
        else:
            snappi_ports = snappi_port_list
        testbed_config, port_config_list, snappi_ports = snappi_dut_base_config(duthosts,
                                                                                snappi_ports,
                                                                                snappi_api)

    _, lossless_prio = enum_one_dut_lossless_prio.split('|')
    lossless_prio = int(lossless_prio)
    test_prio_list = [lossless_prio]
    bg_prio_list = [p for p in all_prio_list]
    bg_prio_list.remove(lossless_prio)

    run_pfc_response_time_test(api=snappi_api,
                               testbed_config=testbed_config,
                               port_config_list=port_config_list,
                               conn_data=conn_graph_facts,
                               fanout_data=fanout_graph_facts,
                               duthost=duthosts[0],
                               global_pause=False,
                               pause_prio_list=test_prio_list,
                               test_prio_list=test_prio_list,
                               bg_prio_list=bg_prio_list,
                               prio_dscp_map=prio_dscp_map,
                               test_traffic_pause=False,
                               intf_type=intf_type,)
