import pytest
from tests.common.helpers.assertions import pytest_require, pytest_assert                   # noqa: F401
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts, \
    fanout_graph_facts_multidut     # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
    snappi_api, snappi_dut_base_config, get_snappi_ports_for_rdma, cleanup_config, \
    get_snappi_ports_single_dut, snappi_testbed_config, \
    get_snappi_ports_multi_dut, is_snappi_multidut, \
    get_snappi_ports                                         # noqa: F401
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map, all_prio_list, lossless_prio_list,\
    lossy_prio_list                         # noqa F401
from tests.snappi_tests.variables import MULTIDUT_PORT_INFO, MULTIDUT_TESTBED   # noqa: F401
from tests.snappi_tests.multidut.pfc.files.multidut_helper import run_pfc_test
import logging
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.snappi_tests.files.helper import reboot_duts, setup_ports_and_dut, multidut_port_info  # noqa: F401
logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology('multidut-tgen', 'tgen')]


@pytest.fixture(autouse=True)
def number_of_tx_rx_ports():
    yield (1, 1)


def test_pfc_pause_single_lossy_prio(snappi_api,                # noqa: F811
                                     conn_graph_facts,          # noqa: F811
                                     fanout_graph_facts_multidut,        # noqa: F811
                                     duthosts,
                                     enum_dut_lossy_prio,
                                     prio_dscp_map,             # noqa: F811
                                     lossy_prio_list,           # noqa: F811
                                     all_prio_list,             # noqa: F811
                                     lossless_prio_list,        # noqa: F811
                                     get_snappi_ports,          # noqa: F811
                                     tbinfo,                    # noqa: F811
                                     setup_ports_and_dut        # noqa: F811
                                     ):
    """
    Test if PFC will impact a single lossy priority in multidut setup

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        enum_dut_lossy_prio (str): name of lossy priority to test, e.g., 's6100-1|2'
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        lossy_prio_list (pytest fixture): list of all the lossy priorities
        all_prio_list (pytest fixture): list of all the priorities
        lossy_prio_list (pytest fixture): list of all the lossy priorities


    Returns:
        N/A
    """
    testbed_config, port_config_list, snappi_ports = setup_ports_and_dut

    _, lossy_prio = enum_dut_lossy_prio.split('|')
    lossy_prio = int(lossy_prio)
    pause_prio_list = [lossy_prio]
    test_prio_list = [lossy_prio]
    bg_prio_list = [p for p in all_prio_list]
    bg_prio_list.remove(lossy_prio)

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    flow_factor = 1

    if snappi_ports[0]['asic_type'] == 'cisco-8800' and int(snappi_ports[0]['speed']) > 200000:
        flow_factor = int(snappi_ports[0]['speed']) / 200000

    run_pfc_test(api=snappi_api,
                 testbed_config=testbed_config,
                 port_config_list=port_config_list,
                 conn_data=conn_graph_facts,
                 fanout_data=fanout_graph_facts_multidut,
                 global_pause=False,
                 pause_prio_list=pause_prio_list,
                 test_prio_list=test_prio_list,
                 bg_prio_list=bg_prio_list,
                 prio_dscp_map=prio_dscp_map,
                 test_traffic_pause=False,
                 test_flow_is_lossless=False,
                 snappi_extra_params=snappi_extra_params,
                 flow_factor=flow_factor)


def test_pfc_pause_multi_lossy_prio(snappi_api,             # noqa: F811
                                    conn_graph_facts,       # noqa: F811
                                    fanout_graph_facts_multidut,     # noqa: F811
                                    duthosts,
                                    prio_dscp_map,                   # noqa: F811
                                    lossy_prio_list,              # noqa: F811
                                    lossless_prio_list,              # noqa: F811
                                    get_snappi_ports,         # noqa: F811
                                    tbinfo,                # noqa: F811
                                    setup_ports_and_dut):                 # noqa: F811
    """
    Test if PFC will impact multiple lossy priorities in multidut setup

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        lossy_prio_list (pytest fixture): list of all the lossy priorities
        tbinfo (pytest fixture): fixture provides information about testbed
        get_snappi_ports (pytest fixture): gets snappi ports and connected DUT port info and returns as a list
    Returns:
        N/A
    """
    testbed_config, port_config_list, snappi_ports = setup_ports_and_dut

    pause_prio_list = lossy_prio_list
    test_prio_list = lossy_prio_list
    bg_prio_list = lossless_prio_list

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    flow_factor = 1

    if snappi_ports[0]['asic_type'] == 'cisco-8800' and int(snappi_ports[0]['speed']) > 200000:
        flow_factor = int(snappi_ports[0]['speed']) / 200000

    run_pfc_test(api=snappi_api,
                 testbed_config=testbed_config,
                 port_config_list=port_config_list,
                 conn_data=conn_graph_facts,
                 fanout_data=fanout_graph_facts_multidut,
                 global_pause=False,
                 pause_prio_list=pause_prio_list,
                 test_prio_list=test_prio_list,
                 bg_prio_list=bg_prio_list,
                 prio_dscp_map=prio_dscp_map,
                 test_traffic_pause=False,
                 test_flow_is_lossless=False,
                 snappi_extra_params=snappi_extra_params,
                 flow_factor=flow_factor)


@pytest.mark.disable_loganalyzer
def test_pfc_pause_single_lossy_prio_reboot(snappi_api,             # noqa: F811
                                            conn_graph_facts,       # noqa: F811
                                            fanout_graph_facts_multidut,     # noqa: F811
                                            duthosts,
                                            localhost,
                                            enum_dut_lossy_prio_with_completeness_level,
                                            prio_dscp_map,          # noqa: F811
                                            lossy_prio_list,        # noqa: F811
                                            all_prio_list,          # noqa: F811
                                            lossless_prio_list,     # noqa: F811
                                            get_snappi_ports,       # noqa: F811
                                            tbinfo,                 # noqa: F811
                                            setup_ports_and_dut,    # noqa: F811
                                            reboot_duts):           # noqa: F811
    """
    Test if PFC will impact a single lossy priority after various kinds of reboots in multidut setup

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        localhost (pytest fixture): localhost handle
        enum_dut_lossy_prio_with_completeness_level (str): name of lossy priority to test, e.g., 's6100-1|2'
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        lossy_prio_list (pytest fixture): list of all the lossy priorities
        all_prio_list (pytest fixture): list of all the priorities
        reboot_type (str): reboot type to be issued on the DUT
        tbinfo (pytest fixture): fixture provides information about testbed
        get_snappi_ports (pytest fixture): gets snappi ports and connected DUT port info and returns as a list
    Returns:
        N/A
    """
    testbed_config, port_config_list, snappi_ports = setup_ports_and_dut

    _, lossy_prio = enum_dut_lossy_prio_with_completeness_level.split('|')
    lossy_prio = int(lossy_prio)
    pause_prio_list = [lossy_prio]
    test_prio_list = [lossy_prio]
    bg_prio_list = [p for p in all_prio_list]
    bg_prio_list.remove(lossy_prio)

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    flow_factor = 1

    if snappi_ports[0]['asic_type'] == 'cisco-8800' and int(snappi_ports[0]['speed']) > 200000:
        flow_factor = int(snappi_ports[0]['speed']) / 200000

    run_pfc_test(api=snappi_api,
                 testbed_config=testbed_config,
                 port_config_list=port_config_list,
                 conn_data=conn_graph_facts,
                 fanout_data=fanout_graph_facts_multidut,
                 global_pause=False,
                 pause_prio_list=pause_prio_list,
                 test_prio_list=test_prio_list,
                 bg_prio_list=bg_prio_list,
                 prio_dscp_map=prio_dscp_map,
                 test_traffic_pause=False,
                 test_flow_is_lossless=False,
                 snappi_extra_params=snappi_extra_params,
                 flow_factor=flow_factor)


@pytest.mark.disable_loganalyzer
def test_pfc_pause_multi_lossy_prio_reboot(snappi_api,          # noqa: F811
                                           conn_graph_facts,    # noqa: F811
                                           fanout_graph_facts_multidut,  # noqa: F811
                                           duthosts,
                                           localhost,
                                           prio_dscp_map,        # noqa: F811
                                           lossy_prio_list,      # noqa: F811
                                           lossless_prio_list,   # noqa: F811
                                           get_snappi_ports,     # noqa: F811
                                           tbinfo,               # noqa: F811
                                           setup_ports_and_dut,  # noqa: F811
                                           reboot_duts):         # noqa: F811
    """
    Test if PFC will impact multiple lossy priorities after various kinds of reboots

    Args:
        snappi_api (pytest fixture): SNAPPI session
        snappi_testbed_config (pytest fixture): testbed configuration information
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
        localhost (pytest fixture): localhost handle
        duthosts (pytest fixture): list of DUTs
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        lossy_prio_list (pytest fixture): list of all the lossy priorities
        reboot_type (str): reboot type to be issued on the DUT
        tbinfo (pytest fixture): fixture provides information about testbed
        get_snappi_ports (pytest fixture): gets snappi ports and connected DUT port info and returns as a list
    Returns:
        N/A
    """
    testbed_config, port_config_list, snappi_ports = setup_ports_and_dut

    pause_prio_list = lossy_prio_list
    test_prio_list = lossy_prio_list
    bg_prio_list = lossless_prio_list

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    flow_factor = 1

    if snappi_ports[0]['asic_type'] == 'cisco-8800' and int(snappi_ports[0]['speed']) > 200000:
        flow_factor = int(snappi_ports[0]['speed']) / 200000

    run_pfc_test(api=snappi_api,
                 testbed_config=testbed_config,
                 port_config_list=port_config_list,
                 conn_data=conn_graph_facts,
                 fanout_data=fanout_graph_facts_multidut,
                 global_pause=False,
                 pause_prio_list=pause_prio_list,
                 test_prio_list=test_prio_list,
                 bg_prio_list=bg_prio_list,
                 prio_dscp_map=prio_dscp_map,
                 test_traffic_pause=False,
                 test_flow_is_lossless=False,
                 snappi_extra_params=snappi_extra_params,
                 flow_factor=flow_factor)
