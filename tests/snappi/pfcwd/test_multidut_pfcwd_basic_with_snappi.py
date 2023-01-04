import pytest

from tests.common.helpers.assertions import pytest_require, pytest_assert
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts
from tests.common.snappi.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port,\
    snappi_api, snappi_dut_base_config, get_tgen_peer_ports, get_multidut_snappi_ports
from tests.common.snappi.qos_fixtures import prio_dscp_map_dut_base,\
             lossless_prio_list_dut_base
#from tests.common.snappi.common_helpers import get_asic_count
import random
from tests.common.reboot import reboot
from tests.common.utilities import wait_until
from files.pfcwd_multidut_basic_helper import run_pfcwd_basic_test
from files.helper import skip_pfcwd_test

logger = logging.getLogger(__name__)

pytestmark = [ pytest.mark.topology('snappi') ]

@pytest.mark.parametrize("trigger_pfcwd", [True])
def test_pfcwd_basic_single_lossless_prio(snappi_api,
                                            conn_graph_facts,
                                            fanout_graph_facts,
                                            duthosts,
                                            rand_select_two_dut,
                                            get_multidut_snappi_ports,
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
    #duts = rand_select_two_dut
    duthost1 = duthosts[0]
    duthost2 = duthosts[1]
    snappi_ports = get_multidut_snappi_ports
    port_set1 = random.sample(get_tgen_peer_ports(snappi_ports, duthost1.hostname), 1)[0]
    port_set2 = get_tgen_peer_ports(snappi_ports, duthost2.hostname)
    tgen_ports = [port_set1[0], port_set2[1][0]]
    dut_port = port_set1[1]
    testbed_config, port_config_list, snappi_ports = snappi_dut_base_config([duthost1, duthost2],
                                                              tgen_ports,
                                                              snappi_ports,
                                                              snappi_api)
    skip_pfcwd_test(duthost=duthost1, trigger_pfcwd=trigger_pfcwd)
    skip_pfcwd_test(duthost=duthost2, trigger_pfcwd=trigger_pfcwd)
    prio_dscp_map = prio_dscp_map_dut_base(duthost1)

    run_pfcwd_basic_test(api=snappi_api,
                         testbed_config=testbed_config,
                         port_config_list=port_config_list,
                         conn_data=conn_graph_facts,
                         fanout_data=fanout_graph_facts,
                         duthost1=duthost1,
                         rx_port_id=snappi_ports[0]["port_id"],
                         duthost2=duthost2,
                         tx_port_id=snappi_ports[1]["port_id"],
                         dut_port=dut_port,
                         prio_list=[lossless_prio_list_dut_base(duthost1)[0]],
                         prio_dscp_map=prio_dscp_map,
                         trigger_pfcwd=trigger_pfcwd)


# @pytest.mark.parametrize("trigger_pfcwd", [True, False])
# def test_pfcwd_basic_multi_lossless_prio(snappi_api,
#                                         conn_graph_facts,
#                                         fanout_graph_facts,
#                                         duthosts,
#                                         rand_select_two_dut,
#                                         get_multidut_snappi_ports,
#                                         trigger_pfcwd):
#     """
#     Run PFC watchdog basic test on multiple lossless priorities

#     Args:
#         snappi_api (pytest fixture): SNAPPI session
#         snappi_testbed_config (pytest fixture): testbed configuration information
#         conn_graph_facts (pytest fixture): connection graph
#         fanout_graph_facts (pytest fixture): fanout graph
#         duthosts (pytest fixture): list of DUTs
#         rand_one_dut_hostname (str): hostname of DUT
#         rand_one_dut_portname_oper_up (str): port to test, e.g., 's6100-1|Ethernet0'
#         lossless_prio_list (pytest fixture): list of all the lossless priorities
#         prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority)
#         trigger_pfcwd (bool): if PFC watchdog is expected to be triggered

#     Returns:
#         N/A
#     """
#     #duts = rand_select_two_dut
#     duthost1 = duthosts[0]
#     duthost2 = duthosts[1]
#     snappi_ports = get_multidut_snappi_ports
#     port_set1 = random.sample(get_tgen_peer_ports(snappi_ports, duthost1.hostname), 1)[0]
#     port_set2 = get_tgen_peer_ports(snappi_ports, duthost2.hostname)
#     tgen_ports = [port_set1[0], port_set2[1][0]]
#     dut_port = port_set1[1]
#     testbed_config, port_config_list, snappi_ports = snappi_dut_base_config([duthost1, duthost2],
#                                                               tgen_ports,
#                                                               snappi_ports,
#                                                               snappi_api)

#     skip_pfcwd_test(duthost=duthost1, trigger_pfcwd=trigger_pfcwd)
#     skip_pfcwd_test(duthost=duthost2, trigger_pfcwd=trigger_pfcwd)

#     run_pfcwd_basic_test(api=snappi_api,
#                          testbed_config=testbed_config,
#                          port_config_list=port_config_list,
#                          conn_data=conn_graph_facts,
#                          fanout_data=fanout_graph_facts,
#                          duthost1=duthost1,
#                          rx_port_id=snappi_ports[0]["port_id"],
#                          duthost2=duthost2,
#                          tx_port_id=snappi_ports[1]["port_id"],
#                          dut_port=dut_port,
#                          prio_list=lossless_prio_list_dut_base(duthost1),
#                          prio_dscp_map=prio_dscp_map_dut_base(duthost1),
#                          trigger_pfcwd=trigger_pfcwd)

# @pytest.mark.disable_loganalyzer
# @pytest.mark.parametrize('reboot_type', ['warm', 'cold', 'fast'])
# @pytest.mark.parametrize("trigger_pfcwd", [True, False])
# def test_pfcwd_basic_single_lossless_prio_reboot(snappi_api,
#                                                 conn_graph_facts,
#                                                 fanout_graph_facts,
#                                                 duthosts,
#                                                 rand_select_two_dut,
#                                                 get_multidut_snappi_ports,
#                                                 localhost,
#                                                 reboot_type,
#                                                 trigger_pfcwd):
#     """
#     Verify PFC watchdog basic test works on a single lossless priority after various types of reboot

#     Args:
#         snappi_api (pytest fixture): SNAPPI session
#         snappi_testbed_config (pytest fixture): testbed configuration information
#         conn_graph_facts (pytest fixture): connection graph
#         fanout_graph_facts (pytest fixture): fanout graph
#         localhost (pytest fixture): localhost handle
#         duthosts (pytest fixture): list of DUTs
#         rand_one_dut_hostname (str): hostname of DUT
#         rand_one_dut_portname_oper_up (str): name of port to test, e.g., 's6100-1|Ethernet0'
#         rand_one_dut_lossless_prio (str): name of lossless priority to test, e.g., 's6100-1|3'
#         prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority)
#         reboot_type (str): reboot type to be issued on the DUT
#         trigger_pfcwd (bool): if PFC watchdog is expected to be triggered

#     Returns:
#         N/A
#     """
#     #duts = rand_select_two_dut
#     duthost1 = duthosts[0]
#     duthost2 = duthosts[1]
#     snappi_ports = get_multidut_snappi_ports
#     port_set1 = random.sample(get_tgen_peer_ports(snappi_ports, duthost1.hostname), 1)[0]
#     port_set2 = get_tgen_peer_ports(snappi_ports, duthost2.hostname)
#     tgen_ports = [port_set1[0], port_set2[1][0]]
#     dut_port = port_set1[1]
#     testbed_config, port_config_list, snappi_ports = snappi_dut_base_config([duthost1, duthost2],
#                                                               tgen_ports,
#                                                               snappi_ports,
#                                                               snappi_api)
#     skip_pfcwd_test(duthost=duthost1, trigger_pfcwd=trigger_pfcwd)
#     skip_pfcwd_test(duthost=duthost2, trigger_pfcwd=trigger_pfcwd)
#     prio_dscp_map = prio_dscp_map_dut_base(duthost1)

#     logger.info("Issuing a {} reboot on the dut {}".format(reboot_type, duthost1.hostname))
#     reboot(duthost1, localhost, reboot_type=reboot_type)
#     logger.info("Wait until the system is stable")
#     wait_until(300, 20, 0, duthost1.critical_services_fully_started)

#     run_pfcwd_basic_test(api=snappi_api,
#                          testbed_config=testbed_config,
#                          port_config_list=port_config_list,
#                          conn_data=conn_graph_facts,
#                          fanout_data=fanout_graph_facts,
#                          duthost1=duthost1,
#                          rx_port_id=snappi_ports[0]["port_id"],
#                          duthost2=duthost2,
#                          tx_port_id=snappi_ports[1]["port_id"],
#                          dut_port=dut_port,
#                          prio_list=[lossless_prio_list_dut_base(duthost1)[0]],
#                          prio_dscp_map=prio_dscp_map,
#                          trigger_pfcwd=trigger_pfcwd)


# @pytest.mark.disable_loganalyzer
# @pytest.mark.parametrize('reboot_type', ['warm', 'cold', 'fast'])
# @pytest.mark.parametrize("trigger_pfcwd", [True, False])
# def test_pfcwd_basic_multi_lossless_prio_reboot(snappi_api,
#                                                 conn_graph_facts,
#                                                 fanout_graph_facts,
#                                                 duthosts,
#                                                 rand_select_two_dut,
#                                                 get_multidut_snappi_ports,
#                                                 localhost,
#                                                 reboot_type,
#                                                 trigger_pfcwd):
#     """
#     Verify PFC watchdog basic test works on multiple lossless priorities after various kinds of reboots

#     Args:
#         snappi_api (pytest fixture): SNAPPI session
#         snappi_testbed_config (pytest fixture): testbed configuration information
#         conn_graph_facts (pytest fixture): connection graph
#         fanout_graph_facts (pytest fixture): fanout graph
#         localhost (pytest fixture): localhost handle
#         duthosts (pytest fixture): list of DUTs
#         rand_one_dut_hostname (str): hostname of DUT
#         rand_one_dut_portname_oper_up (str): name of port to test, e.g., 's6100-1|Ethernet0'
#         lossless_prio_list (pytest fixture): list of all the lossless priorities
#         prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority)
#         reboot_type (str): reboot type to be issued on the DUT
#         trigger_pfcwd (bool): if PFC watchdog is expected to be triggered

#     Returns:
#         N/A
#     """
#     #duts = rand_select_two_dut
#     duthost1 = duthosts[0]
#     duthost2 = duthosts[1]
#     snappi_ports = get_multidut_snappi_ports
#     port_set1 = random.sample(get_tgen_peer_ports(snappi_ports, duthost1.hostname), 1)[0]
#     port_set2 = get_tgen_peer_ports(snappi_ports, duthost2.hostname)
#     tgen_ports = [port_set1[0], port_set2[1][0]]
#     dut_port = port_set1[1]
#     testbed_config, port_config_list, snappi_ports = snappi_dut_base_config([duthost1, duthost2],
#                                                               tgen_ports,
#                                                               snappi_ports,
#                                                               snappi_api)
#     skip_pfcwd_test(duthost=duthost1, trigger_pfcwd=trigger_pfcwd)
#     skip_pfcwd_test(duthost=duthost2, trigger_pfcwd=trigger_pfcwd)
#     prio_dscp_map = prio_dscp_map_dut_base(duthost1)

#     logger.info("Issuing a {} reboot on the dut {}".format(reboot_type, duthost1.hostname))
#     reboot(duthost1, localhost, reboot_type=reboot_type)
#     logger.info("Wait until the system is stable")
#     wait_until(300, 20, 0, duthost1.critical_services_fully_started)

#     run_pfcwd_basic_test(api=snappi_api,
#                          testbed_config=testbed_config,
#                          port_config_list=port_config_list,
#                          conn_data=conn_graph_facts,
#                          fanout_data=fanout_graph_facts,
#                          duthost1=duthost1,
#                          rx_port_id=snappi_ports[0]["port_id"],
#                          duthost2=duthost2,
#                          tx_port_id=snappi_ports[1]["port_id"],
#                          dut_port=dut_port,
#                          prio_list=lossless_prio_list_dut_base(duthost1),
#                          prio_dscp_map=prio_dscp_map,
#                          trigger_pfcwd=trigger_pfcwd)

# @pytest.mark.disable_loganalyzer
# @pytest.mark.parametrize('restart_service', ['swss'])
# @pytest.mark.parametrize("trigger_pfcwd", [True, False])
# def test_pfcwd_basic_single_lossless_prio_service_restart(snappi_api,
#                                                           conn_graph_facts,
#                                                           fanout_graph_facts,
#                                                           duthosts,
#                                                           rand_select_two_dut,
#                                                           get_multidut_snappi_ports,
#                                                           restart_service,
#                                                           trigger_pfcwd):
#     """
#     Verify PFC watchdog basic test works on a single lossless priority after various service restarts

#     Args:
#         snappi_api (pytest fixture): SNAPPI session
#         snappi_testbed_config (pytest fixture): testbed configuration information
#         conn_graph_facts (pytest fixture): connection graph
#         fanout_graph_facts (pytest fixture): fanout graph
#         duthosts (pytest fixture): list of DUTs
#         rand_one_dut_hostname (str): hostname of DUT
#         rand_one_dut_portname_oper_up (str): name of port to test, e.g., 's6100-1|Ethernet0'
#         rand_one_dut_lossless_prio (str): name of lossless priority to test, e.g., 's6100-1|3'
#         prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority)
#         restart_service (str): service to restart on the DUT. Only 'swss' affects pfcwd currently
#         trigger_pfcwd (bool): if PFC watchdog is expected to be triggered

#     Returns:
#         N/A
#     """
#     #duts = rand_select_two_dut
#     duthost1 = duthosts[0]
#     duthost2 = duthosts[1]
#     snappi_ports = get_multidut_snappi_ports
#     port_set1 = random.sample(get_tgen_peer_ports(snappi_ports, duthost1.hostname), 1)[0]
#     port_set2 = get_tgen_peer_ports(snappi_ports, duthost2.hostname)
#     tgen_ports = [port_set1[0], port_set2[1][0]]
#     dut_port = port_set1[1]
#     testbed_config, port_config_list, snappi_ports = snappi_dut_base_config([duthost1, duthost2],
#                                                               tgen_ports,
#                                                               snappi_ports,
#                                                               snappi_api)
#     skip_pfcwd_test(duthost=duthost1, trigger_pfcwd=trigger_pfcwd)
#     skip_pfcwd_test(duthost=duthost2, trigger_pfcwd=trigger_pfcwd)
#     prio_dscp_map = prio_dscp_map_dut_base(duthost1)

#     logger.info("Issuing a restart of service {} on the dut {}".format(restart_service, duthost1.hostname))
#     duthost1.command("systemctl reset-failed {}".format(restart_service))
#     duthost1.command("systemctl restart {}".format(restart_service))
#     logger.info("Wait until the system is stable")
#     wait_until(300, 20, 0, duthost1.critical_services_fully_started)

#     run_pfcwd_basic_test(api=snappi_api,
#                          testbed_config=testbed_config,
#                          port_config_list=port_config_list,
#                          conn_data=conn_graph_facts,
#                          fanout_data=fanout_graph_facts,
#                          duthost1=duthost1,
#                          rx_port_id=snappi_ports[0]["port_id"],
#                          duthost2=duthost2,
#                          tx_port_id=snappi_ports[1]["port_id"],
#                          dut_port=dut_port,
#                          prio_list=[lossless_prio_list_dut_base(duthost1)[0]],
#                          prio_dscp_map=prio_dscp_map,
#                          trigger_pfcwd=trigger_pfcwd)


# @pytest.mark.disable_loganalyzer
# @pytest.mark.parametrize('restart_service', ['swss'])
# @pytest.mark.parametrize("trigger_pfcwd", [True, False])
# def test_pfcwd_basic_multi_lossless_prio_restart_service(snappi_api,
#                                                         conn_graph_facts,
#                                                         fanout_graph_facts,
#                                                         duthosts,
#                                                         rand_select_two_dut,
#                                                         get_multidut_snappi_ports,
#                                                         restart_service,
#                                                         trigger_pfcwd):
#     """
#     Verify PFC watchdog basic test works on multiple lossless priorities after various service restarts

#     Args:
#         snappi_api (pytest fixture): SNAPPI session
#         snappi_testbed_config (pytest fixture): testbed configuration information
#         conn_graph_facts (pytest fixture): connection graph
#         fanout_graph_facts (pytest fixture): fanout graph
#         duthosts (pytest fixture): list of DUTs
#         rand_one_dut_hostname (str): hostname of DUT
#         rand_one_dut_portname_oper_up (str): name of port to test, e.g., 's6100-1|Ethernet0'
#         lossless_prio_list (pytest fixture): list of all the lossless priorities
#         prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority)
#         restart_service (str): service to restart on the DUT. Only 'swss' affects pfcwd currently
#         trigger_pfcwd (bool): if PFC watchdog is expected to be triggered

#     Returns:
#         N/A
#     """
#     #duts = rand_select_two_dut
#     duthost1 = duthosts[0]
#     duthost2 = duthosts[1]
#     snappi_ports = get_multidut_snappi_ports
#     port_set1 = random.sample(get_tgen_peer_ports(snappi_ports, duthost1.hostname), 1)[0]
#     port_set2 = get_tgen_peer_ports(snappi_ports, duthost2.hostname)
#     tgen_ports = [port_set1[0], port_set2[1][0]]
#     dut_port = port_set1[1]
#     testbed_config, port_config_list, snappi_ports = snappi_dut_base_config([duthost1, duthost2],
#                                                               tgen_ports,
#                                                               snappi_ports,
#                                                               snappi_api)
#     skip_pfcwd_test(duthost=duthost1, trigger_pfcwd=trigger_pfcwd)
#     skip_pfcwd_test(duthost=duthost2, trigger_pfcwd=trigger_pfcwd)
#     prio_dscp_map = prio_dscp_map_dut_base(duthost1)

#     logger.info("Issuing a restart of service {} on the dut {}".format(restart_service, duthost1.hostname))
#     duthost1.command("systemctl reset-failed {}".format(restart_service))
#     duthost1.command("systemctl restart {}".format(restart_service))
#     logger.info("Wait until the system is stable")
#     wait_until(300, 20, 0, duthost1.critical_services_fully_started)

#     run_pfcwd_basic_test(api=snappi_api,
#                          testbed_config=testbed_config,
#                          port_config_list=port_config_list,
#                          conn_data=conn_graph_facts,
#                          fanout_data=fanout_graph_facts,
#                          duthost1=duthost1,
#                          rx_port_id=snappi_ports[0]["port_id"],
#                          duthost2=duthost2,
#                          tx_port_id=snappi_ports[1]["port_id"],
#                          dut_port=dut_port,
#                          prio_list=lossless_prio_list_dut_base(duthost1),
#                          prio_dscp_map=prio_dscp_map,
#                          trigger_pfcwd=trigger_pfcwd)