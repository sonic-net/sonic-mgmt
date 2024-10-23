import pytest
from tests.common.helpers.assertions import pytest_require, pytest_assert                   # noqa: F401
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts_multidut, \
    fanout_graph_facts   # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
    snappi_api, snappi_dut_base_config, get_snappi_ports_for_rdma, cleanup_config, \
    get_snappi_ports, is_snappi_multidut, \
    get_snappi_ports_single_dut, get_snappi_ports_multi_dut  # noqa F401
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map, all_prio_list, lossless_prio_list,\
    lossy_prio_list                         # noqa F401
from tests.snappi_tests.variables import MULTIDUT_PORT_INFO, MULTIDUT_TESTBED   # noqa F401
from tests.snappi_tests.multidut.pfc.files.multidut_helper import run_pfc_test
from tests.common.reboot import reboot   # noqa F401
from tests.common.utilities import wait_until   # noqa F401
from tests.common.platform.processes_utils import wait_critical_processes   # noqa F401
import logging
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.snappi_tests.files.helper import skip_warm_reboot
logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology('multidut-tgen')]


@pytest.mark.parametrize("multidut_port_info", MULTIDUT_PORT_INFO[MULTIDUT_TESTBED])
def test_pfc_pause_single_lossy_prio(snappi_api,                # noqa: F811
                                     conn_graph_facts,          # noqa: F811
                                     fanout_graph_facts_multidut,        # noqa: F811
                                     duthosts,
                                     enum_dut_lossy_prio,
                                     prio_dscp_map,                   # noqa: F811
                                     lossy_prio_list,              # noqa: F811
                                     all_prio_list,                   # noqa: F811
                                     get_snappi_ports,             # noqa: F811
                                     tbinfo,           # noqa: F811
                                     multidut_port_info):        # noqa: F811
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

    _, lossy_prio = enum_dut_lossy_prio.split('|')
    lossy_prio = int(lossy_prio)
    pause_prio_list = [lossy_prio]
    test_prio_list = [lossy_prio]
    bg_prio_list = [p for p in all_prio_list]
    bg_prio_list.remove(lossy_prio)

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
                     test_traffic_pause=False,
                     snappi_extra_params=snappi_extra_params)
    finally:
        cleanup_config(duthosts, snappi_ports)


@pytest.mark.parametrize("multidut_port_info", MULTIDUT_PORT_INFO[MULTIDUT_TESTBED])
def test_pfc_pause_multi_lossy_prio(snappi_api,             # noqa: F811
                                    conn_graph_facts,       # noqa: F811
                                    fanout_graph_facts,     # noqa: F811
                                    duthosts,
                                    prio_dscp_map,                   # noqa: F811
                                    lossy_prio_list,              # noqa: F811
                                    lossless_prio_list,              # noqa: F811
                                    get_snappi_ports,         # noqa: F811
                                    tbinfo,                # noqa: F811
                                    multidut_port_info):                 # noqa: F811
    """
    Test if PFC will impact multiple lossy priorities in multidut setup

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
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

    pause_prio_list = lossy_prio_list
    test_prio_list = lossy_prio_list
    bg_prio_list = lossless_prio_list

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports
    try:
        run_pfc_test(api=snappi_api,
                     testbed_config=testbed_config,
                     port_config_list=port_config_list,
                     conn_data=conn_graph_facts,
                     fanout_data=fanout_graph_facts,
                     global_pause=False,
                     pause_prio_list=pause_prio_list,
                     test_prio_list=test_prio_list,
                     bg_prio_list=bg_prio_list,
                     prio_dscp_map=prio_dscp_map,
                     test_traffic_pause=False,
                     snappi_extra_params=snappi_extra_params)
    finally:
        cleanup_config(duthosts, snappi_ports)


@pytest.mark.disable_loganalyzer
@pytest.mark.parametrize('reboot_type', ['warm', 'cold', 'fast'])
@pytest.mark.parametrize("multidut_port_info", MULTIDUT_PORT_INFO[MULTIDUT_TESTBED])
def test_pfc_pause_single_lossy_prio_reboot(snappi_api,             # noqa: F811
                                            conn_graph_facts,       # noqa: F811
                                            fanout_graph_facts_multidut,     # noqa: F811
                                            duthosts,
                                            localhost,
                                            enum_dut_lossy_prio,
                                            prio_dscp_map,                   # noqa: F811
                                            lossy_prio_list,              # noqa: F811
                                            all_prio_list,                   # noqa: F811
                                            get_snappi_ports,         # noqa: F811
                                            tbinfo,                 # noqa: F811
                                            reboot_type,
                                            multidut_port_info):
    """
    Test if PFC will impact a single lossy priority after various kinds of reboots in multidut setup

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        localhost (pytest fixture): localhost handle
        enum_dut_lossy_prio (str): name of lossy priority to test, e.g., 's6100-1|2'
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        lossy_prio_list (pytest fixture): list of all the lossy priorities
        all_prio_list (pytest fixture): list of all the priorities
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

    _, lossy_prio = enum_dut_lossy_prio.split('|')
    lossy_prio = int(lossy_prio)
    pause_prio_list = [lossy_prio]
    test_prio_list = [lossy_prio]
    bg_prio_list = [p for p in all_prio_list]
    bg_prio_list.remove(lossy_prio)
    try:
        for duthost in set([snappi_ports[0]['duthost'], snappi_ports[1]['duthost']]):
            logger.info("Issuing a {} reboot on the dut {}".format(reboot_type, duthost.hostname))
            reboot(duthost, localhost, reboot_type=reboot_type, safe_reboot=True)
            logger.info("Wait until the system is stable")
            wait_critical_processes(duthost)
            pytest_assert(wait_until(300, 20, 0, duthost.critical_services_fully_started),
                          "Not all critical services are fully started")

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
                     test_traffic_pause=False,
                     snappi_extra_params=snappi_extra_params)
    finally:
        cleanup_config(duthosts, snappi_ports)


@pytest.mark.disable_loganalyzer
@pytest.mark.parametrize('reboot_type', ['warm', 'cold', 'fast'])
@pytest.mark.parametrize("multidut_port_info", MULTIDUT_PORT_INFO[MULTIDUT_TESTBED])
def test_pfc_pause_multi_lossy_prio_reboot(snappi_api,          # noqa: F811
                                           conn_graph_facts,    # noqa: F811
                                           fanout_graph_facts,  # noqa: F811
                                           duthosts,
                                           localhost,
                                           prio_dscp_map,       # noqa: F811
                                           lossy_prio_list,     # noqa: F811
                                           lossless_prio_list,  # noqa: F811
                                           get_snappi_ports,     # noqa: F811
                                           tbinfo,              # noqa: F811
                                           reboot_type,
                                           multidut_port_info):
    """
    Test if PFC will impact multiple lossy priorities after various kinds of reboots

    Args:
        snappi_api (pytest fixture): SNAPPI session
        snappi_testbed_config (pytest fixture): testbed configuration information
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
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

    pause_prio_list = lossy_prio_list
    test_prio_list = lossy_prio_list
    bg_prio_list = lossless_prio_list
    try:
        for duthost in set([snappi_ports[0]['duthost'], snappi_ports[1]['duthost']]):
            logger.info("Issuing a {} reboot on the dut {}".format(reboot_type, duthost.hostname))
            reboot(duthost, localhost, reboot_type=reboot_type, safe_reboot=True)
            logger.info("Wait until the system is stable")
            wait_critical_processes(duthost)
            pytest_assert(wait_until(300, 20, 0, duthost.critical_services_fully_started),
                          "Not all critical services are fully started")

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
                     test_traffic_pause=False,
                     snappi_extra_params=snappi_extra_params)
    finally:
        cleanup_config(duthosts, snappi_ports)
