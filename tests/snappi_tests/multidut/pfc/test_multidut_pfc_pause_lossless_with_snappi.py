import pytest
import random
from tests.common.helpers.assertions import pytest_require, pytest_assert                   # noqa: F401
from tests.common.fixtures.conn_graph_facts import conn_graph_facts, fanout_graph_facts     # noqa: F401
from tests.common.snappi_tests.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port, \
    snappi_api, snappi_dut_base_config, get_tgen_peer_ports, get_multidut_snappi_ports, \
    get_multidut_tgen_peer_port_set, cleanup_config                                         # noqa: F401
from tests.common.snappi_tests.qos_fixtures import prio_dscp_map, all_prio_list, lossless_prio_list,\
    lossy_prio_list                         # noqa F401
from tests.snappi_tests.variables import config_set, line_card_choice
from tests.snappi_tests.multidut.pfc.files.multidut_helper import run_pfc_test
from tests.common.reboot import reboot
from tests.common.utilities import wait_until
import logging
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.snappi_tests.files.helper import skip_warm_reboot
logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology('multidut-tgen')]


@pytest.mark.parametrize('line_card_choice', [line_card_choice])
@pytest.mark.parametrize('linecard_configuration_set', [config_set])
def test_pfc_pause_single_lossless_prio(snappi_api,                     # noqa: F811
                                        conn_graph_facts,               # noqa: F811
                                        fanout_graph_facts,             # noqa: F811
                                        duthosts,
                                        enum_dut_lossless_prio,
                                        prio_dscp_map,                   # noqa: F811
                                        lossless_prio_list,              # noqa: F811
                                        all_prio_list,                   # noqa: F811
                                        line_card_choice,
                                        linecard_configuration_set,
                                        get_multidut_snappi_ports):       # noqa: F811

    """
    Test if PFC can pause a single lossless priority in multidut setup

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        enum_dut_lossless_prio (str): lossless priority to test, e.g., 's6100-1|3'
        all_prio_list (pytest fixture): list of all the priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        line_card_choice: Line card choice to be mentioned in the variable.py file
        linecard_configuration_set : Line card classification, (min 1 or max 2  hostnames and asics to be given)
        get_multidut_snappi_ports: Populates tgen and connected DUT ports info of T0 testbed and returns as a list

    Returns:
        N/A
    """
    pytest_assert(line_card_choice in linecard_configuration_set.keys(), "Invalid line_card_choice in parameter")
    pytest_require(len(linecard_configuration_set[line_card_choice]['hostname']) != 0,
                   "Hostname can't be an empty list")
    if (len(linecard_configuration_set[line_card_choice]['hostname']) >= 2):
        dut_list = random.sample(duthosts.frontend_nodes, 2)
        duthost1, duthost2 = dut_list
    elif (len(linecard_configuration_set[line_card_choice]['hostname']) == 1):
        dut_list = [dut for dut in duthosts.frontend_nodes
                    if linecard_configuration_set[line_card_choice]['hostname'] == [dut.hostname]]
        duthost1 = duthost2 = dut_list[0]

    snappi_port_list = get_multidut_snappi_ports(line_card_choice=line_card_choice,
                                                 line_card_info=linecard_configuration_set[line_card_choice])
    pytest_require(len(snappi_port_list) >= 2, "Need Minimum of 2 ports for the test")

    snappi_ports = get_multidut_tgen_peer_port_set(line_card_choice, snappi_port_list, config_set, 2)
    testbed_config, port_config_list, snappi_ports = snappi_dut_base_config(dut_list,
                                                                            snappi_ports,
                                                                            snappi_api)

    _, lossless_prio = enum_dut_lossless_prio.split('|')
    lossless_prio = int(lossless_prio)
    pause_prio_list = [lossless_prio]
    test_prio_list = [lossless_prio]
    bg_prio_list = [p for p in all_prio_list]
    bg_prio_list.remove(lossless_prio)

    logger.info("Snappi Ports : {}".format(snappi_ports))

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.duthost1 = duthost1
    snappi_extra_params.multi_dut_params.duthost2 = duthost2
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

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
                 test_traffic_pause=True,
                 snappi_extra_params=snappi_extra_params)
    cleanup_config(dut_list, snappi_ports)


@pytest.mark.parametrize('line_card_choice', [line_card_choice])
@pytest.mark.parametrize('linecard_configuration_set', [config_set])
def test_pfc_pause_multi_lossless_prio(snappi_api,                  # noqa: F811
                                       conn_graph_facts,            # noqa: F811
                                       fanout_graph_facts,          # noqa: F811
                                       duthosts,
                                       prio_dscp_map,                # noqa: F811
                                       lossy_prio_list,              # noqa: F811
                                       lossless_prio_list,            # noqa: F811
                                       line_card_choice,
                                       linecard_configuration_set,
                                       get_multidut_snappi_ports):    # noqa: F811

    """
    Test if PFC can pause multiple lossless priorities in multidut setup

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        lossy_prio_list (pytest fixture): list of all the lossy priorities
        line_card_choice: Line card choice to be mentioned in the variable.py file
        linecard_configuration_set : Line card classification, (min 1 or max 2  hostnames and asics to be given)
        get_multidut_snappi_ports: Populates tgen and connected DUT ports info of T0 testbed and returns as a list
    Returns:
        N/A
    """
    pytest_assert(line_card_choice in linecard_configuration_set.keys(), "Invalid line_card_choice in parameter")
    pytest_require(len(linecard_configuration_set[line_card_choice]['hostname']) != 0,
                   "Hostname can't be an empty list")
    if (len(linecard_configuration_set[line_card_choice]['hostname']) >= 2):
        dut_list = random.sample(list(duthosts), 2)
        duthost1, duthost2 = dut_list
    elif (len(linecard_configuration_set[line_card_choice]['hostname']) == 1):
        dut_list = [dut for dut in duthosts
                    if linecard_configuration_set[line_card_choice]['hostname'] == [dut.hostname]]
        duthost1 = duthost2 = dut_list[0]

    snappi_port_list = get_multidut_snappi_ports(line_card_choice=line_card_choice,
                                                 line_card_info=linecard_configuration_set[line_card_choice])
    pytest_require(len(snappi_port_list) >= 2, "Need Minimum of 2 ports for the test")

    snappi_ports = get_multidut_tgen_peer_port_set(line_card_choice, snappi_port_list, config_set, 2)

    testbed_config, port_config_list, snappi_ports = snappi_dut_base_config(dut_list,
                                                                            snappi_ports,
                                                                            snappi_api)

    pause_prio_list = lossless_prio_list
    test_prio_list = lossless_prio_list
    bg_prio_list = lossy_prio_list
    logger.info("Snappi Ports : {}".format(snappi_ports))

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.duthost1 = duthost1
    snappi_extra_params.multi_dut_params.duthost2 = duthost2
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

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
                 test_traffic_pause=True,
                 snappi_extra_params=snappi_extra_params)
    cleanup_config(dut_list, snappi_ports)


@pytest.mark.disable_loganalyzer
@pytest.mark.parametrize('reboot_type', ['warm', 'cold', 'fast'])
@pytest.mark.parametrize('line_card_choice', [line_card_choice])
@pytest.mark.parametrize('linecard_configuration_set', [config_set])
def test_pfc_pause_single_lossless_prio_reboot(snappi_api,                  # noqa: F811
                                               conn_graph_facts,            # noqa: F811
                                               fanout_graph_facts,          # noqa: F811
                                               duthosts,
                                               localhost,
                                               enum_dut_lossless_prio,    # noqa: F811
                                               prio_dscp_map,            # noqa: F811
                                               lossless_prio_list,         # noqa: F811
                                               all_prio_list,        # noqa: F811
                                               line_card_choice,
                                               linecard_configuration_set,
                                               get_multidut_snappi_ports,   # noqa: F811
                                               reboot_type):
    """
    Test if PFC can pause a single lossless priority even after various types of reboot in multidut setup

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        localhost (pytest fixture): localhost handle
        all_prio_list (pytest fixture): list of all the priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        reboot_type (str): reboot type to be issued on the DUT
        line_card_choice: Line card choice to be mentioned in the variable.py file
        linecard_configuration_set : Line card classification, (min 1 or max 2  hostnames and asics to be given)
        get_multidut_snappi_ports: Populates tgen and connected DUT ports info of T0 testbed and returns as a list
    Returns:
        N/A
    """
    pytest_assert(line_card_choice in linecard_configuration_set.keys(), "Invalid line_card_choice in parameter")
    pytest_require(len(linecard_configuration_set[line_card_choice]['hostname']) != 0,
                   "Hostname can't be an empty list")
    if (len(linecard_configuration_set[line_card_choice]['hostname']) >= 2):
        dut_list = random.sample(list(duthosts), 2)
        duthost1, duthost2 = dut_list
    elif (len(linecard_configuration_set[line_card_choice]['hostname']) == 1):
        dut_list = [dut for dut in duthosts
                    if linecard_configuration_set[line_card_choice]['hostname'] == [dut.hostname]]
        duthost1 = duthost2 = dut_list[0]

    snappi_port_list = get_multidut_snappi_ports(line_card_choice=line_card_choice,
                                                 line_card_info=linecard_configuration_set[line_card_choice])
    pytest_require(len(snappi_port_list) >= 2, "Need Minimum of 2 ports for the test")

    snappi_ports = get_multidut_tgen_peer_port_set(line_card_choice, snappi_port_list, config_set, 2)
    testbed_config, port_config_list, snappi_ports = snappi_dut_base_config(dut_list,
                                                                            snappi_ports,
                                                                            snappi_api)

    skip_warm_reboot(duthost1, reboot_type)
    skip_warm_reboot(duthost2, reboot_type)

    _, lossless_prio = enum_dut_lossless_prio.split('|')
    lossless_prio = int(lossless_prio)
    pause_prio_list = [lossless_prio]
    test_prio_list = [lossless_prio]
    bg_prio_list = [p for p in all_prio_list]
    bg_prio_list.remove(lossless_prio)
    logger.info("Snappi Ports : {}".format(snappi_ports))

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.duthost1 = duthost1
    snappi_extra_params.multi_dut_params.duthost2 = duthost2
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    for duthost in dut_list:
        duthost.shell("sudo config save -y")
        logger.info("Issuing a {} reboot on the dut {}".format(reboot_type, duthost.hostname))
        reboot(duthost, localhost, reboot_type=reboot_type)
        logger.info("Wait until the system is stable")
        wait_until(180, 20, 0, duthost.critical_services_fully_started)

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
                 test_traffic_pause=True,
                 snappi_extra_params=snappi_extra_params)

    cleanup_config(dut_list, snappi_ports)


@pytest.mark.disable_loganalyzer
@pytest.mark.parametrize('reboot_type', ['warm', 'cold', 'fast'])
@pytest.mark.parametrize('line_card_choice', [line_card_choice])
@pytest.mark.parametrize('linecard_configuration_set', [config_set])
def test_pfc_pause_multi_lossless_prio_reboot(snappi_api,                  # noqa: F811
                                              conn_graph_facts,            # noqa: F811
                                              fanout_graph_facts,          # noqa: F811
                                              duthosts,
                                              localhost,
                                              prio_dscp_map,                 # noqa: F811
                                              lossy_prio_list,               # noqa: F811
                                              lossless_prio_list,            # noqa: F811
                                              line_card_choice,
                                              linecard_configuration_set,
                                              get_multidut_snappi_ports,   # noqa: F811
                                              reboot_type):
    """
    Test if PFC can pause multiple lossless priorities even after various types of reboot in multidut setup

    Args:
        snappi_api (pytest fixture): SNAPPI session
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        localhost (pytest fixture): localhost handle
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        lossy_prio_list (pytest fixture): list of all the lossy priorities
        reboot_type (str): reboot type to be issued on the DUT
        line_card_choice: Line card choice to be mentioned in the variable.py file
        linecard_configuration_set : Line card classification, (min 1 or max 2  hostnames and asics to be given)
        get_multidut_snappi_ports: Populates tgen and connected DUT ports info of T0 testbed and returns as a list

    Returns:
        N/A
    """

    pytest_assert(line_card_choice in linecard_configuration_set.keys(), "Invalid line_card_choice in parameter")
    pytest_require(len(linecard_configuration_set[line_card_choice]['hostname']) != 0,
                   "Hostname can't be an empty list")
    if (len(linecard_configuration_set[line_card_choice]['hostname']) >= 2):
        dut_list = random.sample(list(duthosts), 2)
        duthost1, duthost2 = dut_list
    elif (len(linecard_configuration_set[line_card_choice]['hostname']) == 1):
        dut_list = [dut for dut in duthosts
                    if linecard_configuration_set[line_card_choice]['hostname'] == [dut.hostname]]
        duthost1 = duthost2 = dut_list[0]

    snappi_port_list = get_multidut_snappi_ports(line_card_choice=line_card_choice,
                                                 line_card_info=linecard_configuration_set[line_card_choice])
    pytest_require(len(snappi_port_list) >= 2, "Need Minimum of 2 ports for the test")

    snappi_ports = get_multidut_tgen_peer_port_set(line_card_choice, snappi_port_list, config_set, 2)

    testbed_config, port_config_list, snappi_ports = snappi_dut_base_config(dut_list,
                                                                            snappi_ports,
                                                                            snappi_api)
    skip_warm_reboot(duthost1, reboot_type)
    skip_warm_reboot(duthost2, reboot_type)
    pause_prio_list = lossless_prio_list
    test_prio_list = lossless_prio_list
    bg_prio_list = lossy_prio_list
    logger.info("Snappi Ports : {}".format(snappi_ports))

    snappi_extra_params = SnappiTestParams()
    snappi_extra_params.multi_dut_params.duthost1 = duthost1
    snappi_extra_params.multi_dut_params.duthost2 = duthost2
    snappi_extra_params.multi_dut_params.multi_dut_ports = snappi_ports

    for duthost in dut_list:
        duthost.shell("sudo config save -y")
        logger.info("Issuing a {} reboot on the dut {}".format(reboot_type, duthost.hostname))
        reboot(duthost, localhost, reboot_type=reboot_type)
        logger.info("Wait until the system is stable")
        wait_until(180, 20, 0, duthost.critical_services_fully_started)

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
                 test_traffic_pause=True,
                 snappi_extra_params=snappi_extra_params)

    cleanup_config(dut_list, snappi_ports)
