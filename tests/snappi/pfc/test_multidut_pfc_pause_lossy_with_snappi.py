import pytest
from tests.common.helpers.assertions import pytest_require, pytest_assert
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts
from tests.common.snappi.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port,\
    snappi_api, snappi_dut_base_config, get_tgen_peer_ports, get_multidut_snappi_ports,\
    get_multidut_tgen_peer_port_set, cleanup_config
from tests.common.snappi.qos_fixtures import lossy_prio_list, prio_dscp_map_dut_base,\
    lossless_prio_list_dut_base
from tests.snappi.variables import config_set, line_card_choice
from files.multidut_helper import run_pfc_test
from tests.common.reboot import reboot
from tests.common.utilities import wait_until
import logging
import random
logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology('snappi')]


@pytest.mark.parametrize('line_card_choice', [line_card_choice])
@pytest.mark.parametrize('linecard_configuration_set', [config_set])
def test_pfc_pause_single_lossy_prio(snappi_api,
                                     conn_graph_facts,
                                     fanout_graph_facts,
                                     duthosts,
                                     rand_select_two_dut,
                                     line_card_choice,
                                     linecard_configuration_set,
                                     get_multidut_snappi_ports,):
    """
    Test if PFC will impact a single lossy priority

    Args:
        snappi_api (pytest fixture): SNAPPI session
        snappi_testbed_config (pytest fixture): testbed configuration information
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_hostname (str): hostname of DUT
        rand_one_dut_portname_oper_up (str): port to test, e.g., 's6100-1|Ethernet0'
        enum_dut_lossy_prio (str): name of lossy priority to test, e.g., 's6100-1|2'
        all_prio_list (pytest fixture): list of all the priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        line_card_choice: Line card choice to be mentioned in the variable.py file
        linecard_configuration_set : Line card classification, (min 1 or max 2  hostnames and asics to be given)

    Returns:
        N/A
    """
    if line_card_choice not in linecard_configuration_set.keys():
        assert False, "Invalid line_card_choice value passed in parameter"

    duts = rand_select_two_dut
    if (len(linecard_configuration_set[line_card_choice]['hostname']) == 2):
        duthost1 = duts[0]
        duthost2 = duts[1]
        dut_list = [duthost1, duthost2]
    elif (len(linecard_configuration_set[line_card_choice]['hostname']) == 1):
        for dut in duts:
            if linecard_configuration_set[line_card_choice]['hostname'] == [dut.hostname]:
                duthost1 = dut
                duthost2 = dut
                dut_list = [duthost1]
    else:
        assert False, "Hostname can't be an empty list"

    snappi_port_list = get_multidut_snappi_ports(line_card_choice=line_card_choice, 
                                                 line_card_info=linecard_configuration_set[line_card_choice])
    if len(snappi_port_list) < 2:
        assert False, "Need Minimum of 2 ports for the test"

    tgen_snappi_ports = get_multidut_tgen_peer_port_set(line_card_choice, snappi_port_list, config_set)
    port_set = tgen_snappi_ports[0]
    port_set1 = port_set[0]
    port_set2 = port_set[1]
    snappi_ports = tgen_snappi_ports[1]
    tgen_ports = [port_set1[0], port_set2[0]]
    testbed_config, port_config_list, snappi_ports = snappi_dut_base_config(dut_list,
                                                                            tgen_ports,
                                                                            snappi_ports,
                                                                            snappi_api)
    prio_dscp_map = prio_dscp_map_dut_base(duthost1)
    all_prio_list = prio_dscp_map.keys()
    lossless_prio_list = lossless_prio_list_dut_base(duthost1)
    lossy_prio_list = [x for x in all_prio_list if x not in lossless_prio_list]
    lossy_prio = int(random.sample(lossy_prio_list, 1)[0])
    pause_prio_list = [lossy_prio]
    test_prio_list = pause_prio_list
    bg_prio_list = [p for p in all_prio_list]
    bg_prio_list.remove(lossy_prio)

    run_pfc_test(api=snappi_api,
                 testbed_config=testbed_config,
                 port_config_list=port_config_list,
                 conn_data=conn_graph_facts,
                 fanout_data=fanout_graph_facts,
                 duthost1=duthost1,
                 rx_port=snappi_ports[0],
                 rx_port_id=snappi_ports[0]["port_id"],
                 duthost2=duthost2,
                 tx_port=snappi_ports[1],
                 tx_port_id=snappi_ports[1]["port_id"],
                 global_pause=False,
                 pause_prio_list=pause_prio_list,
                 test_prio_list=test_prio_list,
                 bg_prio_list=bg_prio_list,
                 prio_dscp_map=prio_dscp_map,
                 test_traffic_pause=False)

    cleanup_config(dut_list, snappi_ports)


def test_pfc_pause_multi_lossy_prio(snappi_api,
                                    conn_graph_facts,
                                    fanout_graph_facts,
                                    duthosts,
                                    rand_select_two_dut,
                                    line_card_choice,
                                    linecard_configuration_set,
                                    get_multidut_snappi_ports,):
    """
    Test if PFC will impact multiple lossy priorities

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
        line_card_choice: Line card choice to be mentioned in the variable.py file
        linecard_configuration_set : Line card classification, (min 1 or max 2  hostnames and asics to be given)

    Returns:
        N/A
    """
    if line_card_choice not in linecard_configuration_set.keys():
        assert False, "Invalid line_card_choice value passed in parameter"

    duts = rand_select_two_dut
    if (len(linecard_configuration_set[line_card_choice]['hostname']) == 2):
        duthost1 = duts[0]
        duthost2 = duts[1]
        dut_list = [duthost1, duthost2]
    elif (len(linecard_configuration_set[line_card_choice]['hostname']) == 1):
        for dut in duts:
            if linecard_configuration_set[line_card_choice]['hostname'] == [dut.hostname]:
                duthost1 = dut
                duthost2 = dut
                dut_list = [duthost1]
    else:
        assert False, "Hostname can't be an empty list"

    snappi_port_list = get_multidut_snappi_ports(line_card_choice=line_card_choice, 
                                                 line_card_info=linecard_configuration_set[line_card_choice])
    if len(snappi_port_list) < 2:
        assert False, "Need Minimum of 2 ports for the test"

    tgen_snappi_ports = get_multidut_tgen_peer_port_set(line_card_choice, snappi_port_list, config_set)
    port_set = tgen_snappi_ports[0]
    port_set1 = port_set[0]
    port_set2 = port_set[1]
    snappi_ports = tgen_snappi_ports[1]
    tgen_ports = [port_set1[0], port_set2[0]]
    testbed_config, port_config_list, snappi_ports = snappi_dut_base_config(dut_list,
                                                                            tgen_ports,
                                                                            snappi_ports,
                                                                            snappi_api)
    prio_dscp_map = prio_dscp_map_dut_base(duthost1)
    all_prio_list = prio_dscp_map.keys()
    lossless_prio_list = lossless_prio_list_dut_base(duthost1)
    lossy_prio_list = [x for x in all_prio_list if x not in lossless_prio_list]
    pause_prio_list = lossy_prio_list
    test_prio_list = lossy_prio_list
    bg_prio_list = lossless_prio_list

    run_pfc_test(api=snappi_api,
                 testbed_config=testbed_config,
                 port_config_list=port_config_list,
                 conn_data=conn_graph_facts,
                 fanout_data=fanout_graph_facts,
                 duthost1=duthost1,
                 rx_port=snappi_ports[0],
                 rx_port_id=snappi_ports[0]["port_id"],
                 duthost2=duthost2,
                 tx_port=snappi_ports[1],
                 tx_port_id=snappi_ports[1]["port_id"],
                 global_pause=False,
                 pause_prio_list=pause_prio_list,
                 test_prio_list=test_prio_list,
                 bg_prio_list=bg_prio_list,
                 prio_dscp_map=prio_dscp_map,
                 test_traffic_pause=False)

    cleanup_config(dut_list, snappi_ports)


@pytest.mark.disable_loganalyzer
@pytest.mark.parametrize('reboot_type', ['warm', 'cold', 'fast'])
@pytest.mark.parametrize('line_card_choice', [line_card_choice])
@pytest.mark.parametrize('linecard_configuration_set', [config_set])
def test_pfc_pause_single_lossy_prio_reboot(snappi_api,
                                            conn_graph_facts,
                                            fanout_graph_facts,
                                            duthosts,
                                            localhost,
                                            rand_select_two_dut,
                                            line_card_choice,
                                            linecard_configuration_set,
                                            get_multidut_snappi_ports,
                                            reboot_type):
    """
    Test if PFC will impact a single lossy priority after various kinds of reboots

    Args:
        snappi_api (pytest fixture): SNAPPI session
        snappi_testbed_config (pytest fixture): testbed configuration information
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        localhost (pytest fixture): localhost handle
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_hostname (str): hostname of DUT
        rand_one_dut_portname_oper_up (str): port to test, e.g., 's6100-1|Ethernet0'
        rand_lossy_prio (str): lossy priority to test, e.g., 's6100-1|2'
        all_prio_list (pytest fixture): list of all the priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        reboot_type (str): reboot type to be issued on the DUT
        line_card_choice: Line card choice to be mentioned in the variable.py file
        linecard_configuration_set : Line card classification, (min 1 or max 2  hostnames and asics to be given)

    Returns:
        N/A
    """
    if line_card_choice not in linecard_configuration_set.keys():
        assert False, "Invalid line_card_choice value passed in parameter"

    duts = rand_select_two_dut
    if (len(linecard_configuration_set[line_card_choice]['hostname']) == 2):
        duthost1 = duts[0]
        duthost2 = duts[1]
        dut_list = [duthost1, duthost2]
    elif (len(linecard_configuration_set[line_card_choice]['hostname']) == 1):
        for dut in duts:
            if linecard_configuration_set[line_card_choice]['hostname'] == [dut.hostname]:
                duthost1 = dut
                duthost2 = dut
                dut_list = [duthost1]
    else:
        assert False, "Hostname can't be an empty list"

    snappi_port_list = get_multidut_snappi_ports(line_card_choice=line_card_choice, 
                                                 line_card_info=linecard_configuration_set[line_card_choice])
    if len(snappi_port_list) < 2:
        assert False, "Need Minimum of 2 ports for the test"

    tgen_snappi_ports = get_multidut_tgen_peer_port_set(line_card_choice, snappi_port_list, config_set)
    port_set = tgen_snappi_ports[0]
    port_set1 = port_set[0]
    port_set2 = port_set[1]
    snappi_ports = tgen_snappi_ports[1]
    tgen_ports = [port_set1[0], port_set2[0]]
    testbed_config, port_config_list, snappi_ports = snappi_dut_base_config(dut_list,
                                                                            tgen_ports,
                                                                            snappi_ports,
                                                                            snappi_api)
    prio_dscp_map = prio_dscp_map_dut_base(duthost1)
    all_prio_list = prio_dscp_map.keys()
    lossless_prio_list = lossless_prio_list_dut_base(duthost1)
    lossy_prio_list = [x for x in all_prio_list if x not in lossless_prio_list]
    lossy_prio = int(random.sample(lossy_prio_list, 1)[0])
    pause_prio_list = [lossy_prio]
    test_prio_list = pause_prio_list
    bg_prio_list = [p for p in all_prio_list]
    bg_prio_list.remove(lossy_prio)

    logger.info("Issuing a {} reboot on the dut {}".format(reboot_type, duthost.hostname))
    reboot(duthost1, localhost, reboot_type=reboot_type)
    logger.info("Wait until the system is stable")
    pytest_assert(wait_until(300, 20, 0, duthost1.critical_services_fully_started),
                  "Not all critical services are fully started")

    run_pfc_test(api=snappi_api,
                 testbed_config=testbed_config,
                 port_config_list=port_config_list,
                 conn_data=conn_graph_facts,
                 fanout_data=fanout_graph_facts,
                 duthost1=duthost1,
                 rx_port=snappi_ports[0],
                 rx_port_id=snappi_ports[0]["port_id"],
                 duthost2=duthost2,
                 tx_port=snappi_ports[1],
                 tx_port_id=snappi_ports[1]["port_id"],
                 global_pause=False,
                 pause_prio_list=pause_prio_list,
                 test_prio_list=test_prio_list,
                 bg_prio_list=bg_prio_list,
                 prio_dscp_map=prio_dscp_map,
                 test_traffic_pause=False)

    cleanup_config(dut_list, snappi_ports)

@pytest.mark.disable_loganalyzer
@pytest.mark.parametrize('reboot_type', ['warm', 'cold', 'fast'])
@pytest.mark.parametrize('line_card_choice', [line_card_choice])
@pytest.mark.parametrize('linecard_configuration_set', [config_set])
def test_pfc_pause_multi_lossy_prio_reboot(snappi_api,
                                           conn_graph_facts,
                                           fanout_graph_facts,
                                           duthosts,
                                           localhost,
                                           rand_select_two_dut,
                                           line_card_choice,
                                           linecard_configuration_set,
                                           get_multidut_snappi_ports,
                                           reboot_type):
    """
    Test if PFC will impact multiple lossy priorities after various kinds of reboots

    Args:
        snappi_api (pytest fixture): SNAPPI session
        snappi_testbed_config (pytest fixture): testbed configuration information
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        localhost (pytest fixture): localhost handle
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_hostname (str): hostname of DUT
        rand_one_dut_portname_oper_up (str): port to test, e.g., 's6100-1|Ethernet0'
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        lossy_prio_list (pytest fixture): list of all the lossy priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        reboot_type (str): reboot type to be issued on the DUT
        line_card_choice: Line card choice to be mentioned in the variable.py file
        linecard_configuration_set : Line card classification, (min 1 or max 2  hostnames and asics to be given)

    Returns:
        N/A
    """

    if line_card_choice not in linecard_configuration_set.keys():
        assert False, "Invalid line_card_choice value passed in parameter"

    duts = rand_select_two_dut
    if (len(linecard_configuration_set[line_card_choice]['hostname']) == 2):
        duthost1 = duts[0]
        duthost2 = duts[1]
        dut_list = [duthost1, duthost2]
    elif (len(linecard_configuration_set[line_card_choice]['hostname']) == 1):
        for dut in duts:
            if linecard_configuration_set[line_card_choice]['hostname'] == [dut.hostname]:
                duthost1 = dut
                duthost2 = dut
                dut_list = [duthost1]
    else:
        assert False, "Hostname can't be an empty list"

    snappi_port_list = get_multidut_snappi_ports(line_card_choice=line_card_choice, 
                                                 line_card_info=linecard_configuration_set[line_card_choice])
    if len(snappi_port_list) < 2:
        assert False, "Need Minimum of 2 ports for the test"

    tgen_snappi_ports = get_multidut_tgen_peer_port_set(line_card_choice, snappi_port_list, config_set)
    port_set = tgen_snappi_ports[0]
    port_set1 = port_set[0]
    port_set2 = port_set[1]
    snappi_ports = tgen_snappi_ports[1]
    tgen_ports = [port_set1[0], port_set2[0]]
    testbed_config, port_config_list, snappi_ports = snappi_dut_base_config(dut_list,
                                                                            tgen_ports,
                                                                            snappi_ports,
                                                                            snappi_api)
    prio_dscp_map = prio_dscp_map_dut_base(duthost1)
    all_prio_list = prio_dscp_map.keys()
    lossless_prio_list = lossless_prio_list_dut_base(duthost1)
    lossy_prio_list = [x for x in all_prio_list if x not in lossless_prio_list]
    pause_prio_list = lossy_prio_list
    test_prio_list = lossy_prio_list
    bg_prio_list = lossless_prio_list

    logger.info("Issuing a {} reboot on the dut {}".format(reboot_type, duthost1.hostname))
    reboot(duthost1, localhost, reboot_type=reboot_type)
    logger.info("Wait until the system is stable")
    pytest_assert(wait_until(300, 20, 0, duthost1.critical_services_fully_started),
                  "Not all critical services are fully started")

    run_pfc_test(api=snappi_api,
                 testbed_config=testbed_config,
                 port_config_list=port_config_list,
                 conn_data=conn_graph_facts,
                 fanout_data=fanout_graph_facts,
                 duthost1=duthost1,
                 rx_port=snappi_ports[0],
                 rx_port_id=snappi_ports[0]["port_id"],
                 duthost2=duthost2,
                 tx_port=snappi_ports[1],
                 tx_port_id=snappi_ports[1]["port_id"],
                 global_pause=False,
                 pause_prio_list=pause_prio_list,
                 test_prio_list=test_prio_list,
                 bg_prio_list=bg_prio_list,
                 prio_dscp_map=prio_dscp_map,
                 test_traffic_pause=False)

    cleanup_config(dut_list, snappi_ports)
