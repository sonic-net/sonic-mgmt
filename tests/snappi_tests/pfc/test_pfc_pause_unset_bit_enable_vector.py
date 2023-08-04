import logging
import pytest

from tests.snappi_tests.pfc.files.helper import run_pfc_test
from tests.common.helpers.assertions import pytest_require
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts # noqa F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port,\
    snappi_api, snappi_testbed_config # noqa F401
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map, all_prio_list, lossless_prio_list,\
    lossy_prio_list # noqa F401
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology('tgen')]


def test_pfc_unset_cev_single_prio(snappi_api, # noqa F811
                                   snappi_testbed_config, # noqa F811
                                   conn_graph_facts, # noqa F811
                                   fanout_graph_facts, # noqa F811
                                   duthosts,
                                   rand_one_dut_hostname,
                                   rand_one_dut_portname_oper_up,
                                   enum_dut_lossless_prio,
                                   all_prio_list, # noqa F811
                                   prio_dscp_map): # noqa F811
    """
    Test if PFC frames with no bit set in the class enable vector are ignored by the DUT
    for a single lossless priority
    Args:
        snappi_api (pytest fixture): SNAPPI session
        snappi_testbed_config (pytest fixture): testbed configuration information
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_hostname (str): hostname of DUT
        rand_one_dut_portname_oper_up (str): port to test, e.g., 's6100-1|Ethernet0'
        enum_dut_lossless_prio (str): lossless priority to test, e.g., 's6100-1|3'
        all_prio_list (pytest fixture): list of all the priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
    Returns:
        N/A
    """
    dut_hostname, dut_port = rand_one_dut_portname_oper_up.split('|')
    dut_hostname2, lossless_prio = enum_dut_lossless_prio.split('|')
    pytest_require(rand_one_dut_hostname == dut_hostname == dut_hostname2,
                   "Priority and port are not mapped to the expected DUT")

    testbed_config, port_config_list = snappi_testbed_config
    duthost = duthosts[rand_one_dut_hostname]
    lossless_prio = int(lossless_prio)

    pause_prio_list = [lossless_prio]
    test_prio_list = [lossless_prio]
    bg_prio_list = [p for p in all_prio_list]
    bg_prio_list.remove(lossless_prio)

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.set_pfc_class_enable_vec = False

    run_pfc_test(api=snappi_api,
                 testbed_config=testbed_config,
                 port_config_list=port_config_list,
                 conn_data=conn_graph_facts,
                 fanout_data=fanout_graph_facts,
                 duthost=duthost,
                 dut_port=dut_port,
                 global_pause=False,
                 pause_prio_list=pause_prio_list,
                 test_prio_list=test_prio_list,
                 bg_prio_list=bg_prio_list,
                 prio_dscp_map=prio_dscp_map,
                 test_traffic_pause=False,
                 snappi_extra_params=snappi_extra_params)


def test_pfc_unset_cev_multi_prio(snappi_api, # noqa F811
                                  snappi_testbed_config, # noqa F811
                                  conn_graph_facts, # noqa F811
                                  fanout_graph_facts, # noqa F811
                                  duthosts,
                                  rand_one_dut_hostname,
                                  rand_one_dut_portname_oper_up,
                                  lossless_prio_list, # noqa F811
                                  lossy_prio_list, # noqa F811
                                  prio_dscp_map): # noqa F811
    """
    Test if PFC frames with no bit set in the class enable vector are ignored by the DUT
    for multiple lossless priorities
    Args:
        snappi_api (pytest fixture): SNAPPI session
        snappi_testbed_config (pytest fixture): testbed configuration information
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_hostname (str): hostname of DUT
        rand_one_dut_portname_oper_up (str): port to test, e.g., 's6100-1|Ethernet0'
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        lossy_prio_list (pytest fixture): list of all the lossy priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
    Returns:
        N/A
    """
    dut_hostname, dut_port = rand_one_dut_portname_oper_up.split('|')
    pytest_require(rand_one_dut_hostname == dut_hostname,
                   "Port is not mapped to the expected DUT")

    testbed_config, port_config_list = snappi_testbed_config
    duthost = duthosts[rand_one_dut_hostname]

    pause_prio_list = lossless_prio_list
    test_prio_list = lossless_prio_list
    bg_prio_list = lossy_prio_list

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.set_pfc_class_enable_vec = False

    run_pfc_test(api=snappi_api,
                 testbed_config=testbed_config,
                 port_config_list=port_config_list,
                 conn_data=conn_graph_facts,
                 fanout_data=fanout_graph_facts,
                 duthost=duthost,
                 dut_port=dut_port,
                 global_pause=False,
                 pause_prio_list=pause_prio_list,
                 test_prio_list=test_prio_list,
                 bg_prio_list=bg_prio_list,
                 prio_dscp_map=prio_dscp_map,
                 test_traffic_pause=False,
                 snappi_extra_params=snappi_extra_params)
