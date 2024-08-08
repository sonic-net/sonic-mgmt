import pytest
import random
import logging
import re
from collections import defaultdict
from tests.common.helpers.assertions import pytest_require, pytest_assert
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts     # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
    snappi_api, snappi_dut_base_config, get_tgen_peer_ports, get_multidut_snappi_ports, \
    get_multidut_tgen_peer_port_set, cleanup_config                                         # noqa: F401
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map, lossless_prio_list      # noqa F401
from tests.snappi_tests.variables import config_set, line_card_choice
from tests.common.reboot import reboot                              # noqa: F401
from tests.common.utilities import wait_until                       # noqa: F401
from tests.snappi_tests.multidut.pfcwd.files.pfcwd_multidut_basic_helper import run_pfcwd_basic_test
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.snappi_tests.files.helper import skip_warm_reboot, skip_pfcwd_test
from tests.common.config_reload import config_reload

logger = logging.getLogger(__name__)
pytestmark = [pytest.mark.topology('multidut-tgen')]


@pytest.mark.parametrize("trigger_pfcwd", [True, False])
@pytest.mark.parametrize('line_card_choice', [line_card_choice])
@pytest.mark.parametrize('linecard_configuration_set', [config_set])
def test_pfcwd_basic_single_lossless_prio(snappi_api,                   # noqa: F811
                                          conn_graph_facts,             # noqa: F811
                                          fanout_graph_facts,           # noqa: F811
                                          duthosts,
                                          line_card_choice,
                                          linecard_configuration_set,
                                          get_multidut_snappi_ports,    # noqa: F811
                                          enum_dut_lossless_prio,
                                          prio_dscp_map,            # noqa F811
                                          trigger_pfcwd):
    """
    Run PFC watchdog basic test on a single lossless priority

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        enum_dut_lossless_prio (str): name of lossless priority to test, e.g., 's6100-1|3'
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority)
        trigger_pfcwd (bool): if PFC watchdog is expected to be triggered
        line_card_choice: Line card choice to be mentioned in the variable.py file
        linecard_configuration_set : Line card classification, (min 1 or max 2  hostnames and asics to be given)
        get_multidut_snappi_ports: Populates tgen and connected DUT ports info of T0 testbed and returns as a list

    Returns:
        N/A
    """
    if line_card_choice not in linecard_configuration_set.keys():
        pytest_require(False, "Invalid line_card_choice value passed in parameter")

    if (len(linecard_configuration_set[line_card_choice]['hostname']) == 2):
        dut_list = random.sample(duthosts.frontend_nodes, 2)
        duthost1, duthost2 = dut_list
    elif (len(linecard_configuration_set[line_card_choice]['hostname']) == 1):
        dut_list = [dut for dut in duthosts.frontend_nodes if
                    linecard_configuration_set[line_card_choice]['hostname'] == [dut.hostname]]
        duthost1, duthost2 = dut_list[0], dut_list[0]
    else:
        pytest_require(False, "Hostname can't be an empty list")

    snappi_port_list = get_multidut_snappi_ports(line_card_choice=line_card_choice,
                                                 line_card_info=linecard_configuration_set[line_card_choice])
    pytest_assert(len(snappi_port_list) >= 2, "Need Minimum of 2 ports for the test")
    snappi_ports = get_multidut_tgen_peer_port_set(line_card_choice, snappi_port_list, config_set, 2)

    testbed_config, port_config_list, snappi_ports = snappi_dut_base_config(dut_list,
                                                                            snappi_ports,
                                                                            snappi_api)
    skip_pfcwd_test(duthost=duthost1, trigger_pfcwd=trigger_pfcwd)
    skip_pfcwd_test(duthost=duthost2, trigger_pfcwd=trigger_pfcwd)

    _, lossless_prio = enum_dut_lossless_prio.split('|')
    lossless_prio = int(lossless_prio)

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.duthost1 = duthost1
    snappi_extra_params.multi_dut_params.duthost2 = duthost2
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    run_pfcwd_basic_test(api=snappi_api,
                         testbed_config=testbed_config,
                         port_config_list=port_config_list,
                         conn_data=conn_graph_facts,
                         fanout_data=fanout_graph_facts,
                         dut_port=snappi_ports[0]['peer_port'],
                         prio_list=[lossless_prio],
                         prio_dscp_map=prio_dscp_map,
                         trigger_pfcwd=trigger_pfcwd,
                         snappi_extra_params=snappi_extra_params)

    cleanup_config(dut_list, snappi_ports)


@pytest.mark.parametrize("trigger_pfcwd", [True, False])
@pytest.mark.parametrize('line_card_choice', [line_card_choice])
@pytest.mark.parametrize('linecard_configuration_set', [config_set])
def test_pfcwd_basic_multi_lossless_prio(snappi_api,                # noqa F811
                                         conn_graph_facts,          # noqa F811
                                         fanout_graph_facts,        # noqa F811
                                         duthosts,
                                         line_card_choice,
                                         linecard_configuration_set,
                                         get_multidut_snappi_ports, # noqa F811
                                         lossless_prio_list,        # noqa F811
                                         prio_dscp_map,             # noqa F811
                                         trigger_pfcwd):
    """
    Run PFC watchdog basic test on multiple lossless priorities

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority)
        trigger_pfcwd (bool): if PFC watchdog is expected to be triggered
        line_card_choice: Line card choice to be mentioned in the variable.py file
        linecard_configuration_set : Line card classification, (min 1 or max 2  hostnames and asics to be given)
        get_multidut_snappi_ports: Populates tgen and connected DUT ports info of T0 testbed and returns as a list

    Returns:
        N/A
    """
    if line_card_choice not in linecard_configuration_set.keys():
        pytest_require(False, "Invalid line_card_choice value passed in parameter")

    if (len(linecard_configuration_set[line_card_choice]['hostname']) == 2):
        dut_list = random.sample(duthosts.frontend_nodes, 2)
        duthost1, duthost2 = dut_list
    elif (len(linecard_configuration_set[line_card_choice]['hostname']) == 1):
        dut_list = [dut for dut in duthosts.frontend_nodes if
                    linecard_configuration_set[line_card_choice]['hostname'] == [dut.hostname]]
        duthost1, duthost2 = dut_list[0], dut_list[0]
    else:
        pytest_require(False, "Hostname can't be an empty list")

    snappi_port_list = get_multidut_snappi_ports(line_card_choice=line_card_choice,
                                                 line_card_info=linecard_configuration_set[line_card_choice])
    pytest_assert(len(snappi_port_list) >= 2, "Need Minimum of 2 ports for the test")

    snappi_ports = get_multidut_tgen_peer_port_set(line_card_choice, snappi_port_list, config_set, 2)

    testbed_config, port_config_list, snappi_ports = snappi_dut_base_config(dut_list,
                                                                            snappi_ports,
                                                                            snappi_api)

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.duthost1 = duthost1
    snappi_extra_params.multi_dut_params.duthost2 = duthost2
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    run_pfcwd_basic_test(api=snappi_api,
                         testbed_config=testbed_config,
                         port_config_list=port_config_list,
                         conn_data=conn_graph_facts,
                         fanout_data=fanout_graph_facts,
                         dut_port=snappi_ports[0]['peer_port'],
                         prio_list=lossless_prio_list,
                         prio_dscp_map=prio_dscp_map,
                         trigger_pfcwd=trigger_pfcwd,
                         snappi_extra_params=snappi_extra_params)

    cleanup_config(dut_list, snappi_ports)


@pytest.mark.disable_loganalyzer
@pytest.mark.parametrize('reboot_type', ['warm', 'cold', 'fast'])
@pytest.mark.parametrize("trigger_pfcwd", [True, False])
@pytest.mark.parametrize('line_card_choice', [line_card_choice])
@pytest.mark.parametrize('linecard_configuration_set', [config_set])
def test_pfcwd_basic_single_lossless_prio_reboot(snappi_api,                # noqa F811
                                                 conn_graph_facts,          # noqa F811
                                                 fanout_graph_facts,        # noqa F811
                                                 localhost,
                                                 duthosts,
                                                 rand_one_dut_lossless_prio,
                                                 line_card_choice,
                                                 linecard_configuration_set,
                                                 get_multidut_snappi_ports, # noqa F811
                                                 prio_dscp_map,             # noqa F811
                                                 reboot_type,
                                                 trigger_pfcwd):
    """
    Verify PFC watchdog basic test works on a single lossless priority after various types of reboot

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        localhost (pytest fixture): localhost handle
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_lossless_prio (str): name of lossless priority to test, e.g., 's6100-1|3'
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority)
        reboot_type (str): reboot type to be issued on the DUT
        trigger_pfcwd (bool): if PFC watchdog is expected to be triggered
        line_card_choice: Line card choice to be mentioned in the variable.py file
        linecard_configuration_set : Line card classification, (min 1 or max 2  hostnames and asics to be given)
        get_multidut_snappi_ports: Populates tgen and connected DUT ports info of T0 testbed and returns as a list

    Returns:
        N/A
    """

    if line_card_choice not in linecard_configuration_set.keys():
        pytest_require(False, "Invalid line_card_choice value passed in parameter")

    if (len(linecard_configuration_set[line_card_choice]['hostname']) == 2):
        dut_list = random.sample(duthosts.frontend_nodes, 2)
        duthost1, duthost2 = dut_list
    elif (len(linecard_configuration_set[line_card_choice]['hostname']) == 1):
        dut_list = [dut for dut in duthosts.frontend_nodes if
                    linecard_configuration_set[line_card_choice]['hostname'] == [dut.hostname]]
        duthost1, duthost2 = dut_list[0], dut_list[0]
    else:
        pytest_require(False, "Hostname can't be an empty list")

    skip_warm_reboot(duthost=duthost1, reboot_type=reboot_type)
    skip_warm_reboot(duthost=duthost2, reboot_type=reboot_type)
    snappi_port_list = get_multidut_snappi_ports(line_card_choice=line_card_choice,
                                                 line_card_info=linecard_configuration_set[line_card_choice])
    pytest_assert(len(snappi_port_list) >= 2, "Need Minimum of 2 ports for the test")
    snappi_ports = get_multidut_tgen_peer_port_set(line_card_choice, snappi_port_list, config_set, 2)
    testbed_config, port_config_list, snappi_ports = snappi_dut_base_config(dut_list,
                                                                            snappi_ports,
                                                                            snappi_api)

    _, lossless_prio = rand_one_dut_lossless_prio.split('|')
    lossless_prio = int(lossless_prio)
    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.duthost1 = duthost1
    snappi_extra_params.multi_dut_params.duthost2 = duthost2
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    for duthost in dut_list:
        logger.info("Issuing a {} reboot on the dut {}".format(reboot_type, duthost.hostname))
        reboot(duthost, localhost, reboot_type=reboot_type, safe_reboot=True)
        logger.info("Wait until the system is stable")
        pytest_assert(wait_until(300, 20, 0, duthost.critical_services_fully_started),
                      "Not all critical services are fully started")

    run_pfcwd_basic_test(api=snappi_api,
                         testbed_config=testbed_config,
                         port_config_list=port_config_list,
                         conn_data=conn_graph_facts,
                         fanout_data=fanout_graph_facts,
                         dut_port=snappi_ports[0]['peer_port'],
                         prio_list=[lossless_prio],
                         prio_dscp_map=prio_dscp_map,
                         trigger_pfcwd=trigger_pfcwd,
                         snappi_extra_params=snappi_extra_params)

    cleanup_config(dut_list, snappi_ports)


@pytest.mark.disable_loganalyzer
@pytest.mark.parametrize('reboot_type', ['warm', 'cold', 'fast'])
@pytest.mark.parametrize("trigger_pfcwd", [True, False])
@pytest.mark.parametrize('line_card_choice', [line_card_choice])
@pytest.mark.parametrize('linecard_configuration_set', [config_set])
def test_pfcwd_basic_multi_lossless_prio_reboot(snappi_api,                 # noqa F811
                                                conn_graph_facts,           # noqa F811
                                                fanout_graph_facts,         # noqa F811
                                                localhost,
                                                duthosts,
                                                line_card_choice,
                                                linecard_configuration_set,
                                                get_multidut_snappi_ports, # noqa F811
                                                lossless_prio_list,         # noqa F811
                                                prio_dscp_map,              # noqa F811
                                                reboot_type,
                                                trigger_pfcwd):
    """
    Verify PFC watchdog basic test works on multiple lossless priorities after various kinds of reboots

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        localhost (pytest fixture): localhost handle
        duthosts (pytest fixture): list of DUTs
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority)
        reboot_type (str): reboot type to be issued on the DUT
        trigger_pfcwd (bool): if PFC watchdog is expected to be triggered
        line_card_choice: Line card choice to be mentioned in the variable.py file
        linecard_configuration_set : Line card classification, (min 1 or max 2  hostnames and asics to be given)
        get_multidut_snappi_ports: Populates tgen and connected DUT ports info of T0 testbed and returns as a list

    Returns:
        N/A
    """
    if line_card_choice not in linecard_configuration_set.keys():
        pytest_require(False, "Invalid line_card_choice value passed in parameter")

    if (len(linecard_configuration_set[line_card_choice]['hostname']) == 2):
        dut_list = random.sample(duthosts.frontend_nodes, 2)
        duthost1, duthost2 = dut_list
    elif (len(linecard_configuration_set[line_card_choice]['hostname']) == 1):
        dut_list = [dut for dut in duthosts.frontend_nodes if
                    linecard_configuration_set[line_card_choice]['hostname'] == [dut.hostname]]
        duthost1, duthost2 = dut_list[0], dut_list[0]
    else:
        pytest_require(False, "Hostname can't be an empty list")

    skip_warm_reboot(duthost=duthost1, reboot_type=reboot_type)
    skip_warm_reboot(duthost=duthost2, reboot_type=reboot_type)

    snappi_port_list = get_multidut_snappi_ports(line_card_choice=line_card_choice,
                                                 line_card_info=linecard_configuration_set[line_card_choice])
    pytest_assert(len(snappi_port_list) >= 2, "Need Minimum of 2 ports for the test")
    snappi_ports = get_multidut_tgen_peer_port_set(line_card_choice, snappi_port_list, config_set, 2)

    testbed_config, port_config_list, snappi_ports = snappi_dut_base_config(dut_list,
                                                                            snappi_ports,
                                                                            snappi_api)

    for duthost in dut_list:
        logger.info("Issuing a {} reboot on the dut {}".format(reboot_type, duthost.hostname))
        reboot(duthost, localhost, reboot_type=reboot_type, safe_reboot=True)
        logger.info("Wait until the system is stable")
        pytest_assert(wait_until(300, 20, 0, duthost.critical_services_fully_started),
                      "Not all critical services are fully started")

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.duthost1 = duthost1
    snappi_extra_params.multi_dut_params.duthost2 = duthost2
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    run_pfcwd_basic_test(api=snappi_api,
                         testbed_config=testbed_config,
                         port_config_list=port_config_list,
                         conn_data=conn_graph_facts,
                         fanout_data=fanout_graph_facts,
                         dut_port=snappi_ports[0]['peer_port'],
                         prio_list=lossless_prio_list,
                         prio_dscp_map=prio_dscp_map,
                         trigger_pfcwd=trigger_pfcwd,
                         snappi_extra_params=snappi_extra_params)

    cleanup_config(dut_list, snappi_ports)


@pytest.mark.disable_loganalyzer
@pytest.mark.parametrize('restart_service', ['swss'])
@pytest.mark.parametrize("trigger_pfcwd", [True, False])
@pytest.mark.parametrize('line_card_choice', [line_card_choice])
@pytest.mark.parametrize('linecard_configuration_set', [config_set])
def test_pfcwd_basic_single_lossless_prio_service_restart(snappi_api,               # noqa F811
                                                          conn_graph_facts,         # noqa F811
                                                          fanout_graph_facts,       # noqa F811
                                                          duthosts,
                                                          line_card_choice,
                                                          linecard_configuration_set,
                                                          get_multidut_snappi_ports, # noqa F811
                                                          rand_one_dut_lossless_prio,
                                                          prio_dscp_map,            # noqa F811
                                                          restart_service,
                                                          trigger_pfcwd):
    """
    Verify PFC watchdog basic test works on a single lossless priority after various service restarts

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_lossless_prio (str): name of lossless priority to test, e.g., 's6100-1|3'
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority)
        restart_service (str): service to restart on the DUT. Only 'swss' affects pfcwd currently
        trigger_pfcwd (bool): if PFC watchdog is expected to be triggered
        line_card_choice: Line card choice to be mentioned in the variable.py file
        linecard_configuration_set : Line card classification, (min 1 or max 2  hostnames and asics to be given)
        get_multidut_snappi_ports: Populates tgen and connected DUT ports info of T0 testbed and returns as a list

    Returns:
        N/A
    """
    if line_card_choice not in linecard_configuration_set.keys():
        pytest_require(False, "Invalid line_card_choice value passed in parameter")

    if (len(linecard_configuration_set[line_card_choice]['hostname']) == 2):
        dut_list = random.sample(duthosts.frontend_nodes, 2)
        duthost1, duthost2 = dut_list
    elif (len(linecard_configuration_set[line_card_choice]['hostname']) == 1):
        dut_list = [dut for dut in duthosts.frontend_nodes if
                    linecard_configuration_set[line_card_choice]['hostname'] == [dut.hostname]]
        duthost1, duthost2 = dut_list[0], dut_list[0]
    else:
        pytest_require(False, "Hostname can't be an empty list")

    snappi_port_list = get_multidut_snappi_ports(line_card_choice=line_card_choice,
                                                 line_card_info=linecard_configuration_set[line_card_choice])
    pytest_assert(len(snappi_port_list) >= 2, "Need Minimum of 2 ports for the test")
    snappi_ports = get_multidut_tgen_peer_port_set(line_card_choice, snappi_port_list, config_set, 2)

    testbed_config, port_config_list, snappi_ports = snappi_dut_base_config(dut_list,
                                                                            snappi_ports,
                                                                            snappi_api)
    _, lossless_prio = rand_one_dut_lossless_prio.split('|')
    lossless_prio = int(lossless_prio)

    if (duthost1.is_multi_asic):
        ports_dict = defaultdict(list)
        for port in snappi_ports:
            ports_dict[port['peer_device']].append(port['asic_value'])

        for k in ports_dict.keys():
            ports_dict[k] = list(set(ports_dict[k]))

        logger.info('Line Card Choice:{}'.format(line_card_choice))
        logger.info('Port dictionary:{}'.format(ports_dict))
        for duthost in dut_list:
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
        for duthost in dut_list:
            logger.info("Issuing a restart of service {} on the dut {}".format(restart_service, duthost.hostname))
            duthost.command("systemctl reset-failed {}".format(restart_service))
            duthost.command("systemctl restart {}".format(restart_service))
            logger.info("Wait until the system is stable")
            pytest_assert(wait_until(300, 20, 0, duthost.critical_services_fully_started),
                          "Not all critical services are fully started")

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.duthost1 = duthost1
    snappi_extra_params.multi_dut_params.duthost2 = duthost2
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    run_pfcwd_basic_test(api=snappi_api,
                         testbed_config=testbed_config,
                         port_config_list=port_config_list,
                         conn_data=conn_graph_facts,
                         fanout_data=fanout_graph_facts,
                         dut_port=snappi_ports[0]['peer_port'],
                         prio_list=[lossless_prio],
                         prio_dscp_map=prio_dscp_map,
                         trigger_pfcwd=trigger_pfcwd,
                         snappi_extra_params=snappi_extra_params)

    config_reload(sonic_host=duthost, config_source='config_db', safe_reload=True)


@pytest.mark.disable_loganalyzer
@pytest.mark.parametrize('restart_service', ['swss'])
@pytest.mark.parametrize("trigger_pfcwd", [True, False])
@pytest.mark.parametrize('line_card_choice', [line_card_choice])
@pytest.mark.parametrize('linecard_configuration_set', [config_set])
def test_pfcwd_basic_multi_lossless_prio_restart_service(snappi_api,                # noqa F811
                                                         conn_graph_facts,          # noqa F811
                                                         fanout_graph_facts,        # noqa F811
                                                         duthosts,
                                                         line_card_choice,
                                                         linecard_configuration_set,
                                                         get_multidut_snappi_ports, # noqa F811
                                                         lossless_prio_list,        # noqa F811
                                                         prio_dscp_map,             # noqa F811
                                                         restart_service,
                                                         trigger_pfcwd):
    """
    Verify PFC watchdog basic test works on multiple lossless priorities after various service restarts

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority)
        restart_service (str): service to restart on the DUT. Only 'swss' affects pfcwd currently
        trigger_pfcwd (bool): if PFC watchdog is expected to be triggered
        line_card_choice: Line card choice to be mentioned in the variable.py file
        linecard_configuration_set : Line card classification, (min 1 or max 2  hostnames and asics to be given)
        get_multidut_snappi_ports: Populates tgen and connected DUT ports info of T0 testbed and returns as a list

    Returns:
        N/A
    """
    if line_card_choice not in linecard_configuration_set.keys():
        pytest_require(False, "Invalid line_card_choice value passed in parameter")

    if (len(linecard_configuration_set[line_card_choice]['hostname']) == 2):
        dut_list = random.sample(duthosts.frontend_nodes, 2)
        duthost1, duthost2 = dut_list
    elif (len(linecard_configuration_set[line_card_choice]['hostname']) == 1):
        dut_list = [dut for dut in duthosts.frontend_nodes if
                    linecard_configuration_set[line_card_choice]['hostname'] == [dut.hostname]]
        duthost1, duthost2 = dut_list[0], dut_list[0]
    else:
        pytest_require(False, "Hostname can't be an empty list")

    snappi_port_list = get_multidut_snappi_ports(line_card_choice=line_card_choice,
                                                 line_card_info=linecard_configuration_set[line_card_choice])
    pytest_assert(len(snappi_port_list) >= 2, "Need Minimum of 2 ports for the test")
    snappi_ports = get_multidut_tgen_peer_port_set(line_card_choice, snappi_port_list, config_set, 2)

    testbed_config, port_config_list, snappi_ports = snappi_dut_base_config(dut_list,
                                                                            snappi_ports,
                                                                            snappi_api)

    if (duthost1.is_multi_asic):
        ports_dict = defaultdict(list)
        for port in snappi_ports:
            ports_dict[port['peer_device']].append(port['asic_value'])

        for k in ports_dict.keys():
            ports_dict[k] = list(set(ports_dict[k]))

        logger.info('Line Card Choice:{}'.format(line_card_choice))
        logger.info('Port dictionary:{}'.format(ports_dict))
        for duthost in dut_list:
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
        for duthost in dut_list:
            logger.info("Issuing a restart of service {} on the dut {}".format(restart_service, duthost.hostname))
            duthost.command("systemctl reset-failed {}".format(restart_service))
            duthost.command("systemctl restart {}".format(restart_service))
            logger.info("Wait until the system is stable")
            pytest_assert(wait_until(300, 20, 0, duthost.critical_services_fully_started),
                          "Not all critical services are fully started")

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.duthost1 = duthost1
    snappi_extra_params.multi_dut_params.duthost2 = duthost2
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports
    run_pfcwd_basic_test(api=snappi_api,
                         testbed_config=testbed_config,
                         port_config_list=port_config_list,
                         conn_data=conn_graph_facts,
                         fanout_data=fanout_graph_facts,
                         dut_port=snappi_ports[0]['peer_port'],
                         prio_list=lossless_prio_list,
                         prio_dscp_map=prio_dscp_map,
                         trigger_pfcwd=trigger_pfcwd,
                         snappi_extra_params=snappi_extra_params)

    config_reload(sonic_host=duthost, config_source='config_db', safe_reload=True)
