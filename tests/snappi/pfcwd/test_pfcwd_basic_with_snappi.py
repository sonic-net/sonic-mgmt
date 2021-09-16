import pytest

from tests.common.helpers.assertions import pytest_require, pytest_assert
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts
from tests.common.snappi.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port,\
    snappi_api, snappi_testbed_config
from tests.common.snappi.qos_fixtures import prio_dscp_map, lossless_prio_list
from tests.common.reboot import reboot
from tests.common.utilities import wait_until
from files.pfcwd_basic_helper import run_pfcwd_basic_test
from files.helper import skip_pfcwd_test

logger = logging.getLogger(__name__)

pytestmark = [ pytest.mark.topology('snappi') ]

@pytest.mark.parametrize("trigger_pfcwd", [True, False])
def test_pfcwd_basic_single_lossless_prio(snappi_api,
                                          snappi_testbed_config,
                                          conn_graph_facts,
                                          fanout_graph_facts,
                                          duthosts,
                                          rand_one_dut_hostname,
                                          rand_one_dut_portname_oper_up,
                                          enum_dut_lossless_prio,
                                          prio_dscp_map,
                                          trigger_pfcwd):
    """
    Run PFC watchdog basic test on a single lossless priority

    Args:
        snappi_api (pytest fixture): SNAPPI session
        snappi_testbed_config (pytest fixture): testbed configuration information
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_hostname (str): hostname of DUT
        rand_one_dut_portname_oper_up (str): port to test, e.g., 's6100-1|Ethernet0'
        enum_dut_lossless_prio (str): name of lossless priority to test, e.g., 's6100-1|3'
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority)
        trigger_pfcwd (bool): if PFC watchdog is expected to be triggered

    Returns:
        N/A
    """
    dut_hostname, dut_port = rand_one_dut_portname_oper_up.split('|')
    dut_hostname2, lossless_prio = enum_dut_lossless_prio.split('|')
    pytest_require(rand_one_dut_hostname == dut_hostname == dut_hostname2,
                   "Priority and port are not mapped to the expected DUT")

    duthost = duthosts[rand_one_dut_hostname]
    skip_pfcwd_test(duthost=duthost, trigger_pfcwd=trigger_pfcwd)

    testbed_config, port_config_list = snappi_testbed_config
    lossless_prio = int(lossless_prio)

    run_pfcwd_basic_test(api=snappi_api,
                         testbed_config=testbed_config,
                         port_config_list=port_config_list,
                         conn_data=conn_graph_facts,
                         fanout_data=fanout_graph_facts,
                         duthost=duthost,
                         dut_port=dut_port,
                         prio_list=[lossless_prio],
                         prio_dscp_map=prio_dscp_map,
                         trigger_pfcwd=trigger_pfcwd)


@pytest.mark.parametrize("trigger_pfcwd", [True, False])
def test_pfcwd_basic_multi_lossless_prio(snappi_api,
                                         snappi_testbed_config,
                                         conn_graph_facts,
                                         fanout_graph_facts,
                                         duthosts,
                                         rand_one_dut_hostname,
                                         rand_one_dut_portname_oper_up,
                                         lossless_prio_list,
                                         prio_dscp_map,
                                         trigger_pfcwd):
    """
    Run PFC watchdog basic test on multiple lossless priorities

    Args:
        snappi_api (pytest fixture): SNAPPI session
        snappi_testbed_config (pytest fixture): testbed configuration information
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_hostname (str): hostname of DUT
        rand_one_dut_portname_oper_up (str): port to test, e.g., 's6100-1|Ethernet0'
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority)
        trigger_pfcwd (bool): if PFC watchdog is expected to be triggered

    Returns:
        N/A
    """
    dut_hostname, dut_port = rand_one_dut_portname_oper_up.split('|')
    pytest_require(rand_one_dut_hostname == dut_hostname,
                   "Port is not mapped to the expected DUT")

    duthost = duthosts[rand_one_dut_hostname]
    skip_pfcwd_test(duthost=duthost, trigger_pfcwd=trigger_pfcwd)

    testbed_config, port_config_list = snappi_testbed_config

    run_pfcwd_basic_test(api=snappi_api,
                         testbed_config=testbed_config,
                         port_config_list=port_config_list,
                         conn_data=conn_graph_facts,
                         fanout_data=fanout_graph_facts,
                         duthost=duthost,
                         dut_port=dut_port,
                         prio_list=lossless_prio_list,
                         prio_dscp_map=prio_dscp_map,
                         trigger_pfcwd=trigger_pfcwd)

@pytest.mark.disable_loganalyzer
@pytest.mark.parametrize('reboot_type', ['warm', 'cold', 'fast'])
@pytest.mark.parametrize("trigger_pfcwd", [True, False])
def test_pfcwd_basic_single_lossless_prio_reboot(snappi_api,
                                                 snappi_testbed_config,
                                                 conn_graph_facts,
                                                 fanout_graph_facts,
                                                 localhost,
                                                 duthosts,
                                                 rand_one_dut_hostname,
                                                 rand_one_dut_portname_oper_up,
                                                 rand_one_dut_lossless_prio,
                                                 prio_dscp_map,
                                                 reboot_type,
                                                 trigger_pfcwd):
    """
    Verify PFC watchdog basic test works on a single lossless priority after various types of reboot

    Args:
        snappi_api (pytest fixture): SNAPPI session
        snappi_testbed_config (pytest fixture): testbed configuration information
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        localhost (pytest fixture): localhost handle
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_hostname (str): hostname of DUT
        rand_one_dut_portname_oper_up (str): name of port to test, e.g., 's6100-1|Ethernet0'
        rand_one_dut_lossless_prio (str): name of lossless priority to test, e.g., 's6100-1|3'
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority)
        reboot_type (str): reboot type to be issued on the DUT
        trigger_pfcwd (bool): if PFC watchdog is expected to be triggered

    Returns:
        N/A
    """
    dut_hostname, dut_port = rand_one_dut_portname_oper_up.split('|')
    dut_hostname2, lossless_prio = rand_one_dut_lossless_prio.split('|')
    pytest_require(rand_one_dut_hostname == dut_hostname == dut_hostname2,
                   "Priority and port are not mapped to the expected DUT")

    duthost = duthosts[rand_one_dut_hostname]
    skip_pfcwd_test(duthost=duthost, trigger_pfcwd=trigger_pfcwd)

    testbed_config, port_config_list = snappi_testbed_config
    lossless_prio = int(lossless_prio)

    logger.info("Issuing a {} reboot on the dut {}".format(reboot_type, duthost.hostname))
    reboot(duthost, localhost, reboot_type=reboot_type)
    logger.info("Wait until the system is stable")
    pytest_assert(wait_until(300, 20, duthost.critical_services_fully_started),
                  "Not all critical services are fully started")

    run_pfcwd_basic_test(api=snappi_api,
                         testbed_config=testbed_config,
                         port_config_list=port_config_list,
                         conn_data=conn_graph_facts,
                         fanout_data=fanout_graph_facts,
                         duthost=duthost,
                         dut_port=dut_port,
                         prio_list=[lossless_prio],
                         prio_dscp_map=prio_dscp_map,
                         trigger_pfcwd=trigger_pfcwd)


@pytest.mark.disable_loganalyzer
@pytest.mark.parametrize('reboot_type', ['warm', 'cold', 'fast'])
@pytest.mark.parametrize("trigger_pfcwd", [True, False])
def test_pfcwd_basic_multi_lossless_prio_reboot(snappi_api,
                                                snappi_testbed_config,
                                                conn_graph_facts,
                                                fanout_graph_facts,
                                                localhost,
                                                duthosts,
                                                rand_one_dut_hostname,
                                                rand_one_dut_portname_oper_up,
                                                lossless_prio_list,
                                                prio_dscp_map,
                                                reboot_type,
                                                trigger_pfcwd):
    """
    Verify PFC watchdog basic test works on multiple lossless priorities after various kinds of reboots

    Args:
        snappi_api (pytest fixture): SNAPPI session
        snappi_testbed_config (pytest fixture): testbed configuration information
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        localhost (pytest fixture): localhost handle
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_hostname (str): hostname of DUT
        rand_one_dut_portname_oper_up (str): name of port to test, e.g., 's6100-1|Ethernet0'
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority)
        reboot_type (str): reboot type to be issued on the DUT
        trigger_pfcwd (bool): if PFC watchdog is expected to be triggered

    Returns:
        N/A
    """
    dut_hostname, dut_port = rand_one_dut_portname_oper_up.split('|')
    pytest_require(rand_one_dut_hostname == dut_hostname,
                   "Port is not mapped to the expected DUT")

    duthost = duthosts[rand_one_dut_hostname]
    skip_pfcwd_test(duthost=duthost, trigger_pfcwd=trigger_pfcwd)

    testbed_config, port_config_list = snappi_testbed_config

    logger.info("Issuing a {} reboot on the dut {}".format(reboot_type, duthost.hostname))
    reboot(duthost, localhost, reboot_type=reboot_type)
    logger.info("Wait until the system is stable")
    pytest_assert(wait_until(300, 20, duthost.critical_services_fully_started),
                  "Not all critical services are fully started")

    run_pfcwd_basic_test(api=snappi_api,
                         testbed_config=testbed_config,
                         port_config_list=port_config_list,
                         conn_data=conn_graph_facts,
                         fanout_data=fanout_graph_facts,
                         duthost=duthost,
                         dut_port=dut_port,
                         prio_list=lossless_prio_list,
                         prio_dscp_map=prio_dscp_map,
                         trigger_pfcwd=trigger_pfcwd)

@pytest.mark.disable_loganalyzer
@pytest.mark.parametrize('restart_service', ['swss'])
@pytest.mark.parametrize("trigger_pfcwd", [True, False])
def test_pfcwd_basic_single_lossless_prio_service_restart(snappi_api,
                                                          snappi_testbed_config,
                                                          conn_graph_facts,
                                                          fanout_graph_facts,
                                                          duthosts,
                                                          rand_one_dut_hostname,
                                                          rand_one_dut_portname_oper_up,
                                                          rand_one_dut_lossless_prio,
                                                          prio_dscp_map,
                                                          restart_service,
                                                          trigger_pfcwd):
    """
    Verify PFC watchdog basic test works on a single lossless priority after various service restarts

    Args:
        snappi_api (pytest fixture): SNAPPI session
        snappi_testbed_config (pytest fixture): testbed configuration information
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_hostname (str): hostname of DUT
        rand_one_dut_portname_oper_up (str): name of port to test, e.g., 's6100-1|Ethernet0'
        rand_one_dut_lossless_prio (str): name of lossless priority to test, e.g., 's6100-1|3'
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority)
        restart_service (str): service to restart on the DUT. Only 'swss' affects pfcwd currently
        trigger_pfcwd (bool): if PFC watchdog is expected to be triggered

    Returns:
        N/A
    """
    dut_hostname, dut_port = rand_one_dut_portname_oper_up.split('|')
    dut_hostname2, lossless_prio = rand_one_dut_lossless_prio.split('|')
    pytest_require(rand_one_dut_hostname == dut_hostname == dut_hostname2,
                   "Priority and port are not mapped to the expected DUT")

    duthost = duthosts[rand_one_dut_hostname]
    skip_pfcwd_test(duthost=duthost, trigger_pfcwd=trigger_pfcwd)

    testbed_config, port_config_list = snappi_testbed_config
    lossless_prio = int(lossless_prio)

    logger.info("Issuing a restart of service {} on the dut {}".format(restart_service, duthost.hostname))
    duthost.command("systemctl reset-failed {}".format(restart_service))
    duthost.command("systemctl restart {}".format(restart_service))
    logger.info("Wait until the system is stable")
    pytest_assert(wait_until(300, 20, duthost.critical_services_fully_started),
                  "Not all critical services are fully started")

    run_pfcwd_basic_test(api=snappi_api,
                         testbed_config=testbed_config,
                         port_config_list=port_config_list,
                         conn_data=conn_graph_facts,
                         fanout_data=fanout_graph_facts,
                         duthost=duthost,
                         dut_port=dut_port,
                         prio_list=[lossless_prio],
                         prio_dscp_map=prio_dscp_map,
                         trigger_pfcwd=trigger_pfcwd)


@pytest.mark.disable_loganalyzer
@pytest.mark.parametrize('restart_service', ['swss'])
@pytest.mark.parametrize("trigger_pfcwd", [True, False])
def test_pfcwd_basic_multi_lossless_prio_restart_service(snappi_api,
                                                         snappi_testbed_config,
                                                         conn_graph_facts,
                                                         fanout_graph_facts,
                                                         duthosts,
                                                         rand_one_dut_hostname,
                                                         rand_one_dut_portname_oper_up,
                                                         lossless_prio_list,
                                                         prio_dscp_map,
                                                         restart_service,
                                                         trigger_pfcwd):
    """
    Verify PFC watchdog basic test works on multiple lossless priorities after various service restarts

    Args:
        snappi_api (pytest fixture): SNAPPI session
        snappi_testbed_config (pytest fixture): testbed configuration information
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_hostname (str): hostname of DUT
        rand_one_dut_portname_oper_up (str): name of port to test, e.g., 's6100-1|Ethernet0'
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority)
        restart_service (str): service to restart on the DUT. Only 'swss' affects pfcwd currently
        trigger_pfcwd (bool): if PFC watchdog is expected to be triggered

    Returns:
        N/A
    """
    dut_hostname, dut_port = rand_one_dut_portname_oper_up.split('|')
    pytest_require(rand_one_dut_hostname == dut_hostname,
                   "Port is not mapped to the expected DUT")

    duthost = duthosts[rand_one_dut_hostname]
    skip_pfcwd_test(duthost=duthost, trigger_pfcwd=trigger_pfcwd)

    testbed_config, port_config_list = snappi_testbed_config

    logger.info("Issuing a restart of service {} on the dut {}".format(restart_service, duthost.hostname))
    duthost.command("systemctl reset-failed {}".format(restart_service))
    duthost.command("systemctl restart {}".format(restart_service))
    logger.info("Wait until the system is stable")
    pytest_assert(wait_until(300, 20, duthost.critical_services_fully_started),
                  "Not all critical services are fully started")

    run_pfcwd_basic_test(api=snappi_api,
                         testbed_config=testbed_config,
                         port_config_list=port_config_list,
                         conn_data=conn_graph_facts,
                         fanout_data=fanout_graph_facts,
                         duthost=duthost,
                         dut_port=dut_port,
                         prio_list=lossless_prio_list,
                         prio_dscp_map=prio_dscp_map,
                         trigger_pfcwd=trigger_pfcwd)
