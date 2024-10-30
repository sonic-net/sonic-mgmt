import pytest
from tests.common.helpers.assertions import pytest_require, pytest_assert                   # noqa: F401
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts, \
    fanout_graph_facts_multidut     # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
    snappi_api, snappi_dut_base_config, get_snappi_ports_for_rdma, cleanup_config, get_snappi_ports_multi_dut, \
    snappi_testbed_config, get_snappi_ports_single_dut, \
    get_snappi_ports, is_snappi_multidut                                        # noqa: F401
from tests.snappi_tests.files.helper import multidut_port_info, setup_ports_and_dut, reboot_duts  # noqa: F401
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map, all_prio_list, lossless_prio_list,\
    lossy_prio_list, disable_pfcwd          # noqa F401
from tests.snappi_tests.multidut.pfc.files.multidut_helper import run_pfc_test
import logging
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams


logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology('multidut-tgen', 'tgen')]


@pytest.fixture(autouse=True)
def number_of_tx_rx_ports():
    yield (1, 1)


def test_pfc_pause_single_lossless_prio(snappi_api,                     # noqa: F811
                                        conn_graph_facts,               # noqa: F811
                                        fanout_graph_facts_multidut,    # noqa: F811
                                        duthosts,
                                        enum_dut_lossless_prio,
                                        prio_dscp_map,                  # noqa: F811
                                        lossless_prio_list,             # noqa: F811
                                        all_prio_list,                  # noqa: F811
                                        get_snappi_ports,               # noqa: F811
                                        tbinfo,                         # noqa: F811
                                        disable_pfcwd,                  # noqa: F811
                                        setup_ports_and_dut):           # noqa: F811

    """
    Test if PFC can pause a single lossless priority in multidut setup

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        enum_dut_lossless_prio (str): lossless priority to test, e.g., 's6100-1|3'
        all_prio_list (pytest fixture): list of all the priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        tbinfo (pytest fixture): fixture provides information about testbed
        get_snappi_ports (pytest fixture): gets snappi ports and connected DUT port info and returns as a list

    Returns:
        N/A
    """

    testbed_config, port_config_list, snappi_ports = setup_ports_and_dut

    _, lossless_prio = enum_dut_lossless_prio.split('|')
    lossless_prio = int(lossless_prio)
    pause_prio_list = [lossless_prio]
    test_prio_list = [lossless_prio]
    bg_prio_list = [p for p in all_prio_list]
    bg_prio_list.remove(lossless_prio)

    logger.info("Snappi Ports : {}".format(snappi_ports))

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

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
                 test_traffic_pause=True,
                 snappi_extra_params=snappi_extra_params)


def test_pfc_pause_multi_lossless_prio(snappi_api,                   # noqa: F811
                                       conn_graph_facts,             # noqa: F811
                                       fanout_graph_facts_multidut,  # noqa: F811
                                       duthosts,
                                       prio_dscp_map,                # noqa: F811
                                       lossy_prio_list,              # noqa: F811
                                       lossless_prio_list,           # noqa: F811
                                       get_snappi_ports,             # noqa: F811
                                       tbinfo,
                                       setup_ports_and_dut):         # noqa: F811

    """
    Test if PFC can pause multiple lossless priorities in multidut setup

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

    pause_prio_list = lossless_prio_list
    test_prio_list = lossless_prio_list
    bg_prio_list = lossy_prio_list
    logger.info("Snappi Ports : {}".format(snappi_ports))

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

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
                 test_traffic_pause=True,
                 snappi_extra_params=snappi_extra_params)


@pytest.mark.disable_loganalyzer
def test_pfc_pause_single_lossless_prio_reboot(snappi_api,                   # noqa: F811
                                               conn_graph_facts,             # noqa: F811
                                               fanout_graph_facts_multidut,  # noqa: F811
                                               duthosts,
                                               localhost,
                                               enum_dut_lossless_prio,       # noqa: F811
                                               prio_dscp_map,                # noqa: F811
                                               lossless_prio_list,           # noqa: F811
                                               all_prio_list,                # noqa: F811
                                               get_snappi_ports,             # noqa: F811
                                               tbinfo,
                                               setup_ports_and_dut,          # noqa: F811
                                               disable_pfcwd,                # noqa: F811
                                               reboot_duts):                 # noqa: F811
    """
    Test if PFC can pause a single lossless priority even after various types of reboot in multidut setup

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        localhost (pytest fixture): localhost handle
        all_prio_list (pytest fixture): list of all the priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        tbinfo (pytest fixture): fixture provides information about testbed
        get_snappi_ports (pytest fixture): gets snappi ports and connected DUT port info and returns as a list
    Returns:
        N/A
    """
    testbed_config, port_config_list, snappi_ports = setup_ports_and_dut

    _, lossless_prio = enum_dut_lossless_prio.split('|')
    lossless_prio = int(lossless_prio)
    pause_prio_list = [lossless_prio]
    test_prio_list = [lossless_prio]
    bg_prio_list = [p for p in all_prio_list]
    bg_prio_list.remove(lossless_prio)
    logger.info("Snappi Ports : {}".format(snappi_ports))

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

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
                 test_traffic_pause=True,
                 snappi_extra_params=snappi_extra_params)


@pytest.mark.disable_loganalyzer
def test_pfc_pause_multi_lossless_prio_reboot(snappi_api,                   # noqa: F811
                                              conn_graph_facts,             # noqa: F811
                                              fanout_graph_facts_multidut,  # noqa: F811
                                              duthosts,
                                              localhost,
                                              prio_dscp_map,                # noqa: F811
                                              lossy_prio_list,              # noqa: F811
                                              lossless_prio_list,           # noqa: F811
                                              get_snappi_ports,             # noqa: F811
                                              tbinfo,                       # noqa: F811
                                              setup_ports_and_dut,          # noqa: F811
                                              disable_pfcwd,                # noqa: F811
                                              reboot_duts):                 # noqa: F811
    """
    Test if PFC can pause multiple lossless priorities even after various types of reboot in multidut setup

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        localhost (pytest fixture): localhost handle
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        lossy_prio_list (pytest fixture): list of all the lossy priorities
        tbinfo (pytest fixture): fixture provides information about testbed
        get_snappi_ports (pytest fixture): gets snappi ports and connected DUT port info and returns as a list
    Returns:
        N/A
    """
    testbed_config, port_config_list, snappi_ports = setup_ports_and_dut

    pause_prio_list = lossless_prio_list
    test_prio_list = lossless_prio_list
    bg_prio_list = lossy_prio_list
    logger.info("Snappi Ports : {}".format(snappi_ports))

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

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
                 test_traffic_pause=True,
                 snappi_extra_params=snappi_extra_params)
