import logging
import pytest

from files.helper import run_pfc_test
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts
from tests.common.ixia.ixia_fixtures import ixia_api_serv_ip, ixia_api_serv_port,\
    ixia_api_serv_user, ixia_api_serv_passwd, ixia_api, ixia_testbed
from tests.common.ixia.qos_fixtures import prio_dscp_map, all_prio_list, lossless_prio_list,\
    lossy_prio_list
from tests.common.reboot import reboot
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

@pytest.mark.topology("tgen")

def test_pfc_pause_single_lossy_prio(ixia_api,
                                     ixia_testbed,
                                     conn_graph_facts,
                                     fanout_graph_facts,
                                     duthosts,
                                     rand_one_dut_hostname,
                                     rand_one_dut_portname_oper_up,
                                     enum_dut_lossy_prio,
                                     all_prio_list,
                                     prio_dscp_map):
    """
    Test if PFC will impact a single lossy priority

    Args:
        ixia_api (pytest fixture): IXIA session
        ixia_testbed (pytest fixture): L2/L3 config of a T0 testbed
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_hostname (str): hostname of DUT
        rand_one_dut_portname_oper_up (str): port to test, e.g., 's6100-1|Ethernet0'
        enum_dut_lossy_prio (str): name of lossy priority to test, e.g., 's6100-1|2'
        all_prio_list (pytest fixture): list of all the priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).

    Returns:
        N/A
    """

    dut_hostname, dut_port = rand_one_dut_portname_oper_up.split('|')
    dut_hostname2, lossy_prio = enum_dut_lossy_prio.split('|')
    pytest_require(rand_one_dut_hostname == dut_hostname == dut_hostname2,
                   "Priority and port are not mapped to the expected DUT")

    duthost = duthosts[rand_one_dut_hostname]
    lossy_prio = int(lossy_prio)

    pause_prio_list = [lossy_prio]
    test_prio_list = [lossy_prio]
    bg_prio_list = [p for p in all_prio_list]
    bg_prio_list.remove(lossy_prio)

    run_pfc_test(api=ixia_api,
                 testbed_config=ixia_testbed,
                 conn_data=conn_graph_facts,
                 fanout_data=fanout_graph_facts,
                 duthost=duthost,
                 dut_port=dut_port,
                 global_pause=False,
                 pause_prio_list=pause_prio_list,
                 test_prio_list=test_prio_list,
                 bg_prio_list=bg_prio_list,
                 prio_dscp_map=prio_dscp_map,
                 test_traffic_pause=False)

def test_pfc_pause_multi_lossy_prio(ixia_api,
                                    ixia_testbed,
                                    conn_graph_facts,
                                    fanout_graph_facts,
                                    duthosts,
                                    rand_one_dut_hostname,
                                    rand_one_dut_portname_oper_up,
                                    lossless_prio_list,
                                    lossy_prio_list,
                                    prio_dscp_map):
    """
    Test if PFC will impact multiple lossy priorities

    Args:
        ixia_api (pytest fixture): IXIA session
        ixia_testbed (pytest fixture): L2/L3 config of a T0 testbed
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

    duthost = duthosts[rand_one_dut_hostname]
    pause_prio_list = lossy_prio_list
    test_prio_list = lossy_prio_list
    bg_prio_list = lossless_prio_list

    run_pfc_test(api=ixia_api,
                 testbed_config=ixia_testbed,
                 conn_data=conn_graph_facts,
                 fanout_data=fanout_graph_facts,
                 duthost=duthost,
                 dut_port=dut_port,
                 global_pause=False,
                 pause_prio_list=pause_prio_list,
                 test_prio_list=test_prio_list,
                 bg_prio_list=bg_prio_list,
                 prio_dscp_map=prio_dscp_map,
                 test_traffic_pause=False)

@pytest.mark.parametrize('reboot_type', ['warm', 'cold', 'fast'])
def test_pfc_pause_single_lossy_prio_reboot(ixia_api,
                                            ixia_testbed,
                                            conn_graph_facts,
                                            fanout_graph_facts,
                                            localhost,
                                            duthosts,
                                            rand_one_dut_hostname,
                                            rand_one_dut_portname_oper_up,
                                            rand_lossy_prio,
                                            all_prio_list,
                                            prio_dscp_map,
                                            reboot_type):
    """
    Test if PFC will impact a single lossy priority after various kinds of reboots

    Args:
        ixia_api (pytest fixture): IXIA session
        ixia_testbed (pytest fixture): L2/L3 config of a T0 testbed
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

    Returns:
        N/A
    """

    dut_hostname, dut_port = rand_one_dut_portname_oper_up.split('|')
    dut_hostname2, lossy_prio = rand_lossy_prio.split('|')
    pytest_require(rand_one_dut_hostname == dut_hostname == dut_hostname2,
                   "Priority and port are not mapped to the expected DUT")

    duthost = duthosts[rand_one_dut_hostname]
    lossy_prio = int(lossy_prio)

    pause_prio_list = [lossy_prio]
    test_prio_list = [lossy_prio]
    bg_prio_list = [p for p in all_prio_list]
    bg_prio_list.remove(lossy_prio)

    logger.info("Issuing a {} reboot on the dut {}".format(reboot_type, duthost.hostname))
    reboot(duthost, localhost, reboot_type=reboot_type)
    logger.info("Wait until the system is stable")
    pytest_assert(wait_until(300, 20, duthost.critical_services_fully_started),
                  "Not all critical services are fully started")

    run_pfc_test(api=ixia_api,
                 testbed_config=ixia_testbed,
                 conn_data=conn_graph_facts,
                 fanout_data=fanout_graph_facts,
                 duthost=duthost,
                 dut_port=dut_port,
                 global_pause=False,
                 pause_prio_list=pause_prio_list,
                 test_prio_list=test_prio_list,
                 bg_prio_list=bg_prio_list,
                 prio_dscp_map=prio_dscp_map,
                 test_traffic_pause=False)

@pytest.mark.parametrize('reboot_type', ['warm', 'cold', 'fast'])
def test_pfc_pause_multi_lossy_prio_reboot(ixia_api,
                                           ixia_testbed,
                                           conn_graph_facts,
                                           fanout_graph_facts,
                                           localhost,
                                           duthosts,
                                           rand_one_dut_hostname,
                                           rand_one_dut_portname_oper_up,
                                           lossless_prio_list,
                                           lossy_prio_list,
                                           prio_dscp_map,
                                           reboot_type):
    """
    Test if PFC will impact multiple lossy priorities after various kinds of reboots

    Args:
        ixia_api (pytest fixture): IXIA session
        ixia_testbed (pytest fixture): L2/L3 config of a T0 testbed
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

    Returns:
        N/A
    """

    dut_hostname, dut_port = rand_one_dut_portname_oper_up.split('|')
    pytest_require(rand_one_dut_hostname == dut_hostname,
                   "Port is not mapped to the expected DUT")

    duthost = duthosts[rand_one_dut_hostname]
    pause_prio_list = lossy_prio_list
    test_prio_list = lossy_prio_list
    bg_prio_list = lossless_prio_list

    logger.info("Issuing a {} reboot on the dut {}".format(reboot_type, duthost.hostname))
    reboot(duthost, localhost, reboot_type=reboot_type)
    logger.info("Wait until the system is stable")
    pytest_assert(wait_until(300, 20, duthost.critical_services_fully_started),
                  "Not all critical services are fully started")

    run_pfc_test(api=ixia_api,
                 testbed_config=ixia_testbed,
                 conn_data=conn_graph_facts,
                 fanout_data=fanout_graph_facts,
                 duthost=duthost,
                 dut_port=dut_port,
                 global_pause=False,
                 pause_prio_list=pause_prio_list,
                 test_prio_list=test_prio_list,
                 bg_prio_list=bg_prio_list,
                 prio_dscp_map=prio_dscp_map,
                 test_traffic_pause=False)
