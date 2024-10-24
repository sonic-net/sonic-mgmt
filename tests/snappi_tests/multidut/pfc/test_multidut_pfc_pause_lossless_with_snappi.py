import pytest
from tests.common.helpers.assertions import pytest_require, pytest_assert                   # noqa: F401
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts, \
    fanout_graph_facts_multidut     # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
    snappi_api, snappi_dut_base_config, is_snappi_multidut, \
    get_snappi_ports_for_rdma, cleanup_config, get_snappi_ports                              # noqa: F401
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map, all_prio_list, lossless_prio_list,\
    lossy_prio_list                         # noqa F401
from tests.snappi_tests.variables import MULTIDUT_PORT_INFO, MULTIDUT_TESTBED  # noqa F401
from tests.snappi_tests.multidut.pfc.files.multidut_helper import run_pfc_test  # noqa F401
from tests.common.reboot import reboot  # noqa F401
from tests.common.utilities import wait_until # noqa F401
from tests.common.platform.processes_utils import wait_critical_processes # noqa F401
import logging
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.snappi_tests.files.helper import skip_warm_reboot
logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology('multidut-tgen', 'tgen')]


@pytest.mark.parametrize("multidut_port_info", MULTIDUT_PORT_INFO[MULTIDUT_TESTBED])
def test_pfc_pause_single_lossless_prio(snappi_api,                     # noqa: F811
                                        conn_graph_facts,               # noqa: F811
                                        fanout_graph_facts_multidut,             # noqa: F811
                                        duthosts,
                                        rand_one_dut_lossless_prio,
                                        prio_dscp_map,                   # noqa: F811
                                        lossless_prio_list,              # noqa: F811
                                        all_prio_list,                   # noqa: F811
                                        get_snappi_ports,                 # noqa: F811
                                        tbinfo,                           # noqa: F811
                                        multidut_port_info):

    """
    Test if PFC can pause a single lossless priority in multidut setup

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_lossless_prio (str): lossless priority to test, e.g., 's6100-1|3'
        all_prio_list (pytest fixture): list of all the priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        tbinfo (pytest fixture): fixture provides information about testbed
        get_snappi_ports (pytest fixture): gets snappi ports and connected DUT port info and returns as a list

    Returns:
        N/A
    """
    snappi_port_list = get_snappi_ports
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
        if is_snappi_multidut(duthosts):
            snappi_ports = get_snappi_ports_for_rdma(snappi_port_list, rdma_ports,
                                                     tx_port_count, rx_port_count, MULTIDUT_TESTBED)
        else:
            snappi_ports = get_snappi_ports
        testbed_config, port_config_list, snappi_ports = snappi_dut_base_config(duthosts,
                                                                                snappi_ports,
                                                                                snappi_api)

    _, lossless_prio = rand_one_dut_lossless_prio.split('|')
    lossless_prio = int(lossless_prio)
    pause_prio_list = [lossless_prio]
    test_prio_list = [lossless_prio]
    bg_prio_list = [p for p in all_prio_list]
    bg_prio_list.remove(lossless_prio)

    logger.info("Snappi Ports : {}".format(snappi_ports))

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports
    try:
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
    finally:
        cleanup_config(duthosts, snappi_ports)


@pytest.mark.parametrize("multidut_port_info", MULTIDUT_PORT_INFO[MULTIDUT_TESTBED])
def test_pfc_pause_multi_lossless_prio(snappi_api,                  # noqa: F811
                                       conn_graph_facts,            # noqa: F811
                                       fanout_graph_facts_multidut,          # noqa: F811
                                       duthosts,
                                       prio_dscp_map,                # noqa: F811
                                       lossy_prio_list,              # noqa: F811
                                       lossless_prio_list,       # noqa: F811
                                       get_snappi_ports,            # noqa: F811
                                       tbinfo,          # noqa: F811
                                       multidut_port_info):    # noqa: F811

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
        if is_snappi_multidut(duthosts):
            snappi_ports = get_snappi_ports_for_rdma(snappi_port_list, rdma_ports,
                                                     tx_port_count, rx_port_count, MULTIDUT_TESTBED)
        else:
            snappi_ports = get_snappi_ports
        testbed_config, port_config_list, snappi_ports = snappi_dut_base_config(duthosts,
                                                                                snappi_ports,
                                                                                snappi_api)

    pause_prio_list = lossless_prio_list
    test_prio_list = lossless_prio_list
    bg_prio_list = lossy_prio_list
    logger.info("Snappi Ports : {}".format(snappi_ports))

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports
    try:
        run_pfc_test(api=snappi_api,
                     testbed_config=testbed_config,
                     conn_data=conn_graph_facts,
                     fanout_data=fanout_graph_facts_multidut,
                     global_pause=False,
                     pause_prio_list=pause_prio_list,
                     test_prio_list=test_prio_list,
                     bg_prio_list=bg_prio_list,
                     prio_dscp_map=prio_dscp_map,
                     test_traffic_pause=True,
                     snappi_extra_params=snappi_extra_params)
    finally:
        cleanup_config(duthosts, snappi_ports)


@pytest.mark.disable_loganalyzer
@pytest.mark.parametrize('reboot_type', ['warm', 'cold', 'fast'])
@pytest.mark.parametrize("multidut_port_info", MULTIDUT_PORT_INFO[MULTIDUT_TESTBED])
def test_pfc_pause_single_lossless_prio_reboot(snappi_api,                  # noqa: F811
                                               conn_graph_facts,            # noqa: F811
                                               fanout_graph_facts_multidut,          # noqa: F811
                                               duthosts,
                                               localhost,
                                               rand_one_dut_lossless_prio,    # noqa: F811
                                               prio_dscp_map,            # noqa: F811
                                               lossless_prio_list,         # noqa: F811
                                               all_prio_list,        # noqa: F811
                                               reboot_type,
                                               get_snappi_ports,         # noqa: F811
                                               tbinfo,              # noqa: F811
                                               multidut_port_info):
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
        reboot_type (str): reboot type to be issued on the DUT
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
        if is_snappi_multidut(duthosts):
            snappi_ports = get_snappi_ports_for_rdma(snappi_port_list, rdma_ports,
                                                     tx_port_count, rx_port_count, MULTIDUT_TESTBED)
        else:
            snappi_ports = get_snappi_ports
        testbed_config, port_config_list, snappi_ports = snappi_dut_base_config(duthosts,
                                                                                snappi_ports,
                                                                                snappi_api)

    skip_warm_reboot(snappi_ports[0]['duthost'], reboot_type)
    skip_warm_reboot(snappi_ports[1]['duthost'], reboot_type)

    _, lossless_prio = rand_one_dut_lossless_prio.split('|')
    lossless_prio = int(lossless_prio)
    pause_prio_list = [lossless_prio]
    test_prio_list = [lossless_prio]
    bg_prio_list = [p for p in all_prio_list]
    bg_prio_list.remove(lossless_prio)
    logger.info("Snappi Ports : {}".format(snappi_ports))

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports
    try:
        for duthost in set([snappi_ports[0]['duthost'], snappi_ports[1]['duthost']]):
            logger.info("Issuing a {} reboot on the dut {}".format(reboot_type, duthost.hostname))
            reboot(duthost, localhost, reboot_type=reboot_type, safe_reboot=True)
            logger.info("Wait until the system is stable")
            wait_critical_processes(duthost)
            pytest_assert(wait_until(300, 20, 0, duthost.critical_services_fully_started),
                          "Not all critical services are fully started")

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
    finally:
        cleanup_config(duthosts, snappi_ports)


@pytest.mark.disable_loganalyzer
@pytest.mark.parametrize('reboot_type', ['warm', 'cold', 'fast'])
@pytest.mark.parametrize("multidut_port_info", MULTIDUT_PORT_INFO[MULTIDUT_TESTBED])
def test_pfc_pause_multi_lossless_prio_reboot(snappi_api,                  # noqa: F811
                                              conn_graph_facts,            # noqa: F811
                                              fanout_graph_facts_multidut,          # noqa: F811
                                              duthosts,
                                              localhost,
                                              prio_dscp_map,                 # noqa: F811
                                              lossy_prio_list,               # noqa: F811
                                              lossless_prio_list,             # noqa: F811
                                              reboot_type,
                                              get_snappi_ports,         # noqa: F811
                                              tbinfo,         # noqa: F811
                                              multidut_port_info):
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
        reboot_type (str): reboot type to be issued on the DUT
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
        if is_snappi_multidut(duthosts):
            snappi_ports = get_snappi_ports_for_rdma(snappi_port_list, rdma_ports,
                                                     tx_port_count, rx_port_count, MULTIDUT_TESTBED)
        else:
            snappi_ports = get_snappi_ports
        testbed_config, port_config_list, snappi_ports = snappi_dut_base_config(duthosts,
                                                                                snappi_ports,
                                                                                snappi_api)
    skip_warm_reboot(snappi_ports[0]['duthost'], reboot_type)
    skip_warm_reboot(snappi_ports[1]['duthost'], reboot_type)
    pause_prio_list = lossless_prio_list
    test_prio_list = lossless_prio_list
    bg_prio_list = lossy_prio_list
    logger.info("Snappi Ports : {}".format(snappi_ports))

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports
    try:
        for duthost in set([snappi_ports[0]['duthost'], snappi_ports[1]['duthost']]):
            logger.info("Issuing a {} reboot on the dut {}".format(reboot_type, duthost.hostname))
            reboot(duthost, localhost, reboot_type=reboot_type, safe_reboot=True)
            logger.info("Wait until the system is stable")
            wait_critical_processes(duthost)
            pytest_assert(wait_until(300, 20, 0, duthost.critical_services_fully_started),
                          "Not all critical services are fully started")

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
    finally:
        cleanup_config(duthosts, snappi_ports)
