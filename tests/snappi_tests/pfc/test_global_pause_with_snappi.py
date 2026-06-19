import pytest
import logging
from tests.common.helpers.assertions import pytest_require, pytest_assert                               # noqa: F401
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts, \
    fanout_graph_facts_multidut                                                                         # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
    snappi_api, snappi_dut_base_config, get_snappi_ports_for_rdma, cleanup_config, \
    snappi_testbed_config, get_snappi_ports_single_dut, snappi_port_selection, \
    get_snappi_ports, tgen_port_info, is_snappi_multidut, get_snappi_ports_multi_dut                    # noqa: F401
from tests.common.snappi_tests.qos_fixtures import lossless_prio_list, prio_dscp_map, disable_pfcwd     # noqa: F401
from tests.snappi_tests.pfc.files.helper import run_pfc_test                                            # noqa: F401
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.snappi_tests.cisco.helper import disable_voq_watchdog                                        # noqa: F401

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology('multidut-tgen', 'tgen')]


@pytest.fixture(autouse=True, scope='module')
def number_of_tx_rx_ports():
    yield (1, 1)


def test_global_pause(snappi_api,                           # noqa: F811
                      conn_graph_facts,                     # noqa: F811
                      fanout_graph_facts_multidut,          # noqa: F811
                      duthosts,
                      prio_dscp_map,                        # noqa: F811
                      lossless_prio_list,                   # noqa: F811
                      tbinfo,                               # noqa: F811
                      tgen_port_info,                       # noqa: F811
                      disable_pfcwd):                       # noqa: F811
    """
    Test if IEEE 802.3X pause (a.k.a., global pause) will impact any priority

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph for multiple duts
        get_snappi_ports (pytest fixture): list of snappi port and duthost information
        duthosts (pytest fixture): list of DUTs
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        tbinfo (pytest fixture): fixture provides information about testbed
        tgen_port_info (pytest fixture): fixtures returns port_config_list, snappi_ports and testbed_config
    Returns:
        N/A
    """
    testbed_config, port_config_list, snappi_ports = tgen_port_info

    logger.info("Snappi Ports : {}".format(snappi_ports))

    all_prio_list = prio_dscp_map.keys()
    test_prio_list = lossless_prio_list
    bg_prio_list = [x for x in all_prio_list if x not in test_prio_list]

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports
    run_pfc_test(api=snappi_api,
                 testbed_config=testbed_config,
                 port_config_list=port_config_list,
                 conn_data=conn_graph_facts,
                 fanout_data=fanout_graph_facts_multidut,
                 global_pause=True,
                 pause_prio_list=None,
                 test_prio_list=test_prio_list,
                 bg_prio_list=bg_prio_list,
                 prio_dscp_map=prio_dscp_map,
                 test_traffic_pause=False,
                 snappi_extra_params=snappi_extra_params)
