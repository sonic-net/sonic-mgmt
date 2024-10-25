import pytest
import random
import logging
import re
from collections import defaultdict
from tests.common.helpers.assertions import pytest_require, pytest_assert                               # noqa: F401
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts, \
    fanout_graph_facts_multidut     # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
    get_snappi_ports_single_dut, snappi_testbed_config, \
    get_snappi_ports_multi_dut, is_snappi_multidut, \
    snappi_api, snappi_dut_base_config, get_snappi_ports, get_snappi_ports_for_rdma, cleanup_config      # noqa: F401
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map, lossless_prio_list      # noqa F401
from tests.snappi_tests.variables import MULTIDUT_PORT_INFO, MULTIDUT_TESTBED
from tests.common.reboot import reboot                              # noqa: F401
from tests.common.utilities import wait_until                       # noqa: F401
from tests.snappi_tests.multidut.pfcwd.files.pfcwd_multidut_basic_helper import run_pfcwd_basic_test
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.snappi_tests.files.helper import skip_warm_reboot, skip_pfcwd_test  # noqa: F401
logger = logging.getLogger(__name__)
pytestmark = [pytest.mark.topology('multidut-tgen', 'tgen')]


@pytest.mark.parametrize("trigger_pfcwd", [True, False])
@pytest.mark.parametrize("multidut_port_info", MULTIDUT_PORT_INFO[MULTIDUT_TESTBED])
def test_pfcwd_basic_single_lossless_prio(snappi_api,                   # noqa: F811
                                          conn_graph_facts,             # noqa: F811
                                          fanout_graph_facts_multidut,           # noqa: F811
                                          duthosts,
                                          lossless_prio_list,    # noqa: F811
                                          get_snappi_ports,      # noqa: F811
                                          tbinfo,      # noqa: F811
                                          multidut_port_info,
                                          prio_dscp_map,            # noqa F811
                                          trigger_pfcwd):
    """
    Run PFC watchdog basic test on a single lossless priority

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority)
        trigger_pfcwd (bool): if PFC watchdog is expected to be triggered

    Returns:
        N/A
    """
    for testbed_subtype, rdma_ports in multidut_port_info.items():
        tx_port_count = 1
        rx_port_count = 1
        snappi_port_list = get_snappi_ports
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
    skip_pfcwd_test(duthost=snappi_ports[0]['duthost'], trigger_pfcwd=trigger_pfcwd)
    skip_pfcwd_test(duthost=snappi_ports[1]['duthost'], trigger_pfcwd=trigger_pfcwd)

    lossless_prio = random.sample(lossless_prio_list, 1)
    lossless_prio = int(lossless_prio[0])

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    run_pfcwd_basic_test(api=snappi_api,
                         testbed_config=testbed_config,
                         port_config_list=port_config_list,
                         conn_data=conn_graph_facts,
                         fanout_data=fanout_graph_facts_multidut,
                         dut_port=snappi_ports[0]['peer_port'],
                         prio_list=[lossless_prio],
                         prio_dscp_map=prio_dscp_map,
                         trigger_pfcwd=trigger_pfcwd,
                         snappi_extra_params=snappi_extra_params)

    cleanup_config(duthosts, snappi_ports)


@pytest.mark.parametrize("trigger_pfcwd", [True, False])
@pytest.mark.parametrize("multidut_port_info", MULTIDUT_PORT_INFO[MULTIDUT_TESTBED])
def test_pfcwd_basic_multi_lossless_prio(snappi_api,                # noqa F811
                                         conn_graph_facts,          # noqa F811
                                         fanout_graph_facts_multidut,        # noqa F811
                                         duthosts,
                                         lossless_prio_list,    # noqa: F811
                                         get_snappi_ports,    # noqa: F811
                                         tbinfo,      # noqa: F811
                                         multidut_port_info,
                                         prio_dscp_map,             # noqa F811
                                         trigger_pfcwd):
    """
    Run PFC watchdog basic test on multiple lossless priorities

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority)
        trigger_pfcwd (bool): if PFC watchdog is expected to be triggered

    Returns:
        N/A
    """
    for testbed_subtype, rdma_ports in multidut_port_info.items():
        tx_port_count = 1
        rx_port_count = 1
        snappi_port_list = get_snappi_ports
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

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    run_pfcwd_basic_test(api=snappi_api,
                         testbed_config=testbed_config,
                         port_config_list=port_config_list,
                         conn_data=conn_graph_facts,
                         fanout_data=fanout_graph_facts_multidut,
                         dut_port=snappi_ports[0]['peer_port'],
                         prio_list=lossless_prio_list,
                         prio_dscp_map=prio_dscp_map,
                         trigger_pfcwd=trigger_pfcwd,
                         snappi_extra_params=snappi_extra_params)

    cleanup_config(duthosts, snappi_ports)


@pytest.mark.disable_loganalyzer
@pytest.mark.parametrize('reboot_type', ['warm', 'cold', 'fast'])
@pytest.mark.parametrize("trigger_pfcwd", [True, False])
@pytest.mark.parametrize("multidut_port_info", MULTIDUT_PORT_INFO[MULTIDUT_TESTBED])
def test_pfcwd_basic_single_lossless_prio_reboot(snappi_api,                # noqa F811
                                                 conn_graph_facts,          # noqa F811
                                                 fanout_graph_facts_multidut,        # noqa F811
                                                 localhost,
                                                 duthosts,
                                                 lossless_prio_list,   # noqa: F811
                                                 get_snappi_ports,   # noqa: F811
                                                 tbinfo,      # noqa: F811
                                                 multidut_port_info,
                                                 prio_dscp_map,             # noqa F811
                                                 reboot_type,
                                                 trigger_pfcwd):
    """
    Verify PFC watchdog basic test works on a single lossless priority after various types of reboot

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
        localhost (pytest fixture): localhost handle
        duthosts (pytest fixture): list of DUTs
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority)
        reboot_type (str): reboot type to be issued on the DUT
        trigger_pfcwd (bool): if PFC watchdog is expected to be triggered

    Returns:
        N/A
    """

    for testbed_subtype, rdma_ports in multidut_port_info.items():
        tx_port_count = 1
        rx_port_count = 1
        snappi_port_list = get_snappi_ports
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

    lossless_prio = random.sample(lossless_prio_list, 1)
    lossless_prio = int(lossless_prio[0])
    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    for duthost in [snappi_ports[0]['duthost'], snappi_ports[1]['duthost']]:
        logger.info("Issuing a {} reboot on the dut {}".format(reboot_type, duthost.hostname))
        reboot(duthost, localhost, reboot_type=reboot_type, safe_reboot=True)
        logger.info("Wait until the system is stable")
        pytest_assert(wait_until(300, 20, 0, duthost.critical_services_fully_started),
                      "Not all critical services are fully started")

    run_pfcwd_basic_test(api=snappi_api,
                         testbed_config=testbed_config,
                         port_config_list=port_config_list,
                         conn_data=conn_graph_facts,
                         fanout_data=fanout_graph_facts_multidut,
                         dut_port=snappi_ports[0]['peer_port'],
                         prio_list=[lossless_prio],
                         prio_dscp_map=prio_dscp_map,
                         trigger_pfcwd=trigger_pfcwd,
                         snappi_extra_params=snappi_extra_params)

    cleanup_config(duthosts, snappi_ports)


@pytest.mark.disable_loganalyzer
@pytest.mark.parametrize('reboot_type', ['warm', 'cold', 'fast'])
@pytest.mark.parametrize("trigger_pfcwd", [True, False])
@pytest.mark.parametrize("multidut_port_info", MULTIDUT_PORT_INFO[MULTIDUT_TESTBED])
def test_pfcwd_basic_multi_lossless_prio_reboot(snappi_api,                 # noqa F811
                                                conn_graph_facts,           # noqa F811
                                                fanout_graph_facts_multidut,         # noqa F811
                                                localhost,
                                                duthosts,
                                                lossless_prio_list,   # noqa: F811
                                                get_snappi_ports,    # noqa: F811
                                                tbinfo,      # noqa: F811
                                                multidut_port_info,
                                                prio_dscp_map,              # noqa F811
                                                reboot_type,
                                                trigger_pfcwd):
    """
    Verify PFC watchdog basic test works on multiple lossless priorities after various kinds of reboots

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
        localhost (pytest fixture): localhost handle
        duthosts (pytest fixture): list of DUTs
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority)
        reboot_type (str): reboot type to be issued on the DUT
        trigger_pfcwd (bool): if PFC watchdog is expected to be triggered

    Returns:
        N/A
    """
    for testbed_subtype, rdma_ports in multidut_port_info.items():
        tx_port_count = 1
        rx_port_count = 1
        snappi_port_list = get_snappi_ports
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

    for duthost in [snappi_ports[0]['duthost'], snappi_ports[1]['duthost']]:
        logger.info("Issuing a {} reboot on the dut {}".format(reboot_type, duthost.hostname))
        reboot(duthost, localhost, reboot_type=reboot_type, safe_reboot=True)
        logger.info("Wait until the system is stable")
        pytest_assert(wait_until(300, 20, 0, duthost.critical_services_fully_started),
                      "Not all critical services are fully started")

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    run_pfcwd_basic_test(api=snappi_api,
                         testbed_config=testbed_config,
                         port_config_list=port_config_list,
                         conn_data=conn_graph_facts,
                         fanout_data=fanout_graph_facts_multidut,
                         dut_port=snappi_ports[0]['peer_port'],
                         prio_list=lossless_prio_list,
                         prio_dscp_map=prio_dscp_map,
                         trigger_pfcwd=trigger_pfcwd,
                         snappi_extra_params=snappi_extra_params)

    cleanup_config(duthosts, snappi_ports)


@pytest.mark.disable_loganalyzer
@pytest.mark.parametrize('restart_service', ['swss'])
@pytest.mark.parametrize("trigger_pfcwd", [True, False])
@pytest.mark.parametrize("multidut_port_info", MULTIDUT_PORT_INFO[MULTIDUT_TESTBED])
def test_pfcwd_basic_single_lossless_prio_service_restart(snappi_api,               # noqa F811
                                                          conn_graph_facts,         # noqa F811
                                                          fanout_graph_facts_multidut,       # noqa F811
                                                          duthosts,
                                                          lossless_prio_list,   # noqa: F811
                                                          get_snappi_ports,    # noqa: F811
                                                          tbinfo,      # noqa: F811
                                                          multidut_port_info,
                                                          prio_dscp_map,            # noqa F811
                                                          restart_service,
                                                          trigger_pfcwd):
    """
    Verify PFC watchdog basic test works on a single lossless priority after various service restarts

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority)
        restart_service (str): service to restart on the DUT. Only 'swss' affects pfcwd currently
        trigger_pfcwd (bool): if PFC watchdog is expected to be triggered

    Returns:
        N/A
    """
    for testbed_subtype, rdma_ports in multidut_port_info.items():
        tx_port_count = 1
        rx_port_count = 1
        snappi_port_list = get_snappi_ports
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
    lossless_prio = random.sample(lossless_prio_list, 1)
    lossless_prio = int(lossless_prio[0])

    if (snappi_ports[0]['duthost'].is_multi_asic):
        ports_dict = defaultdict(list)
        for port in snappi_ports:
            ports_dict[port['peer_device']].append(port['asic_value'])

        for k in ports_dict.keys():
            ports_dict[k] = list(set(ports_dict[k]))

        logger.info('Port dictionary:{}'.format(ports_dict))
        for duthost in [snappi_ports[0]['duthost'], snappi_ports[1]['duthost']]:
            asic_list = ports_dict[duthost.hostname]
            for asic in asic_list:
                asic_id = re.match(r"(asic)(\d+)", asic).group(2)
                proc = 'swss@' + asic_id
                logger.info("Issuing a restart of service {} on the dut {}".format(proc, duthost.hostname))
                duthost.command("sudo systemctl reset-failed {}".format(proc))
                duthost.command("sudo systemctl restart {}".format(proc))
                logger.info("Wait until the system is stable")
                pytest_assert(wait_until(300, 20, 0, duthost.critical_services_fully_started),
                              "Not all critical services are fully started")
    else:
        for duthost in [snappi_ports[0]['duthost'], snappi_ports[1]['duthost']]:
            logger.info("Issuing a restart of service {} on the dut {}".format(restart_service, duthost.hostname))
            duthost.command("systemctl reset-failed {}".format(restart_service))
            duthost.command("systemctl restart {}".format(restart_service))
            logger.info("Wait until the system is stable")
            pytest_assert(wait_until(300, 20, 0, duthost.critical_services_fully_started),
                          "Not all critical services are fully started")

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    run_pfcwd_basic_test(api=snappi_api,
                         testbed_config=testbed_config,
                         port_config_list=port_config_list,
                         conn_data=conn_graph_facts,
                         fanout_data=fanout_graph_facts_multidut,
                         dut_port=snappi_ports[0]['peer_port'],
                         prio_list=[lossless_prio],
                         prio_dscp_map=prio_dscp_map,
                         trigger_pfcwd=trigger_pfcwd,
                         snappi_extra_params=snappi_extra_params)

    cleanup_config(duthosts, snappi_ports)


@pytest.mark.disable_loganalyzer
@pytest.mark.parametrize('restart_service', ['swss'])
@pytest.mark.parametrize("trigger_pfcwd", [True, False])
@pytest.mark.parametrize("multidut_port_info", MULTIDUT_PORT_INFO[MULTIDUT_TESTBED])
def test_pfcwd_basic_multi_lossless_prio_restart_service(snappi_api,                # noqa F811
                                                         conn_graph_facts,          # noqa F811
                                                         fanout_graph_facts_multidut,        # noqa F811
                                                         duthosts,
                                                         lossless_prio_list,    # noqa: F811
                                                         get_snappi_ports,   # noqa: F811
                                                         tbinfo,      # noqa: F811
                                                         multidut_port_info,
                                                         prio_dscp_map,             # noqa F811
                                                         restart_service,
                                                         trigger_pfcwd):
    """
    Verify PFC watchdog basic test works on multiple lossless priorities after various service restarts

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts_multidut (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority)
        restart_service (str): service to restart on the DUT. Only 'swss' affects pfcwd currently
        trigger_pfcwd (bool): if PFC watchdog is expected to be triggered

    Returns:
        N/A
    """
    for testbed_subtype, rdma_ports in multidut_port_info.items():
        tx_port_count = 1
        rx_port_count = 1
        snappi_port_list = get_snappi_ports
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

    if (snappi_ports[0]['duthost'].is_multi_asic):
        ports_dict = defaultdict(list)
        for port in snappi_ports:
            ports_dict[port['peer_device']].append(port['asic_value'])

        for k in ports_dict.keys():
            ports_dict[k] = list(set(ports_dict[k]))

        logger.info('Port dictionary:{}'.format(ports_dict))
        for duthost in [snappi_ports[0]['duthost'], snappi_ports[1]['duthost']]:
            asic_list = ports_dict[duthost.hostname]
            for asic in asic_list:
                asic_id = re.match(r"(asic)(\d+)", asic).group(2)
                proc = 'swss@' + asic_id
                logger.info("Issuing a restart of service {} on the dut {}".format(proc, duthost.hostname))
                duthost.command("sudo systemctl reset-failed {}".format(proc))
                duthost.command("sudo systemctl restart {}".format(proc))
                logger.info("Wait until the system is stable")
                pytest_assert(wait_until(300, 20, 0, duthost.critical_services_fully_started),
                              "Not all critical services are fully started")
    else:
        for duthost in [snappi_ports[0]['duthost'], snappi_ports[1]['duthost']]:
            logger.info("Issuing a restart of service {} on the dut {}".format(restart_service, duthost.hostname))
            duthost.command("systemctl reset-failed {}".format(restart_service))
            duthost.command("systemctl restart {}".format(restart_service))
            logger.info("Wait until the system is stable")
            pytest_assert(wait_until(300, 20, 0, duthost.critical_services_fully_started),
                          "Not all critical services are fully started")

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports
    run_pfcwd_basic_test(api=snappi_api,
                         testbed_config=testbed_config,
                         port_config_list=port_config_list,
                         conn_data=conn_graph_facts,
                         fanout_data=fanout_graph_facts_multidut,
                         dut_port=snappi_ports[0]['peer_port'],
                         prio_list=lossless_prio_list,
                         prio_dscp_map=prio_dscp_map,
                         trigger_pfcwd=trigger_pfcwd,
                         snappi_extra_params=snappi_extra_params)

    cleanup_config(duthosts, snappi_ports)
