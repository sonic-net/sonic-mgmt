import pytest

from tests.common.helpers.assertions import pytest_require, pytest_assert
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts
from tests.common.snappi.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port,\
    snappi_api, snappi_dut_base_config, get_tgen_peer_ports, get_multidut_snappi_ports
from tests.common.snappi.qos_fixtures import prio_dscp_map_dut_base,\
             lossless_prio_list_dut_base
import random

from files.pfcwd_multidut_multi_node_helper import run_pfcwd_multi_node_test
from files.helper import skip_pfcwd_test

pytestmark = [ pytest.mark.topology('snappi') ]

#@pytest.mark.parametrize("trigger_pfcwd", [True, False])
@pytest.mark.parametrize("trigger_pfcwd", [True])
def test_pfcwd_many_to_one(snappi_api,
                          conn_graph_facts,
                          fanout_graph_facts,
                          duthosts,
                          rand_select_two_dut,
                          get_multidut_snappi_ports,
                           trigger_pfcwd):

    """
    Run PFC watchdog test under many to one traffic pattern

    Args:
        snappi_api (pytest fixture): SNAPPI session
        snappi_testbed_config (pytest fixture): testbed configuration information
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_hostname (str): hostname of DUT
        rand_one_dut_portname_oper_up (str): port to test, e.g., 's6100-1|Ethernet0'
        rand_one_dut_lossless_prio (str): lossless priority to test, e.g., 's6100-1|3'
        lossy_prio_list (pytest fixture): list of lossy priorities
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
    tgen_ports = [port_set1[0], port_set2[1][0], port_set2[0][0] ]
    dut_port = port_set1[1]
    testbed_config, port_config_list, snappi_ports = snappi_dut_base_config([duthost1, duthost2],
                                                              tgen_ports,
                                                              snappi_ports,
                                                              snappi_api)

    prio_dscp_map = prio_dscp_map_dut_base(duthost1)
    all_prio_list = prio_dscp_map.keys()
    test_prio_list = [lossless_prio_list_dut_base(duthost1)[0]]
    pause_prio_list = test_prio_list
    bg_prio_list = [x for x in all_prio_list if x not in pause_prio_list]
    skip_pfcwd_test(duthost=duthost1, trigger_pfcwd=trigger_pfcwd)
    skip_pfcwd_test(duthost=duthost2, trigger_pfcwd=trigger_pfcwd)

    run_pfcwd_multi_node_test(api=snappi_api,
                              testbed_config=testbed_config,
                              port_config_list=port_config_list,
                              conn_data=conn_graph_facts,
                              fanout_data=fanout_graph_facts,
                              duthost1=duthost1,
                              rx_port_id_list=[snappi_ports[0]["port_id"]],
                              duthost2=duthost2,
                              tx_port_id_list=[snappi_ports[1]["port_id"],snappi_ports[2]["port_id"]],
                              dut_port=dut_port,
                              pause_prio_list=pause_prio_list,
                              test_prio_list=test_prio_list,
                              bg_prio_list=bg_prio_list,
                              prio_dscp_map=prio_dscp_map,
                              trigger_pfcwd=trigger_pfcwd,
                              pattern="many to one")