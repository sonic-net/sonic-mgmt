import pytest
import logging
from tests.common.helpers.assertions import pytest_require
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts
from tests.common.snappi.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port,\
    snappi_api, snappi_dut_base_config, get_tgen_peer_ports, get_multidut_snappi_ports
from tests.common.snappi.qos_fixtures import prio_dscp_map_dut_base,\
             lossless_prio_list_dut_base
import random
from files.multidut_helper import run_pfc_test
logger = logging.getLogger(__name__)
pytestmark = [ pytest.mark.topology('snappi') ]

def test_global_pause(snappi_api,
                      conn_graph_facts,
                      fanout_graph_facts,
                      duthosts,
                      rand_select_two_dut,
                      get_multidut_snappi_ports
                      ):
    """
    Test if IEEE 802.3X pause (a.k.a., global pause) will impact any priority

    Args:
        snappi_api (pytest fixture): SNAPPI session
        snappi_testbed_config (pytest fixture): testbed configuration information
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_hostname (str): hostname of DUT
        rand_one_dut_portname_oper_up (str): name of port to test, e.g., 's6100-1|Ethernet0'
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        lossy_prio_list (pytest fixture): list of all the lossy priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).

    Returns:
        N/A
    """
    
    duts = rand_select_two_dut
    duthost1 = duts[0]
    duthost2 = duts[1]
    snappi_ports = get_multidut_snappi_ports
    #port_set1 = random.sample(get_tgen_peer_ports(snappi_ports, duthost1.hostname), 1)[0]
    #port_set2 = random.sample(get_tgen_peer_ports(snappi_ports, duthost2.hostname), 1)[0]
    port_set1 = get_tgen_peer_ports(snappi_ports, duthost1.hostname)[0]
    port_set2 = get_tgen_peer_ports(snappi_ports, duthost2.hostname)[0]
    logger.info(port_set1)
    logger.info(port_set2)
    tgen_ports = [port_set1[0], port_set2[0]]
    
    testbed_config, port_config_list, snappi_ports = snappi_dut_base_config([duthost1, duthost2],
                                                              tgen_ports,
                                                              snappi_ports,
                                                              snappi_api)
    prio_dscp_map = prio_dscp_map_dut_base(duthost1)
    all_prio_list = prio_dscp_map.keys()
    test_prio_list = lossless_prio_list_dut_base(duthost1)
    bg_prio_list = [x for x in all_prio_list if x not in test_prio_list]
    
    run_pfc_test(api=snappi_api,
                 testbed_config=testbed_config,
                 port_config_list=port_config_list,
                 conn_data=conn_graph_facts,
                 fanout_data=fanout_graph_facts,
                 duthost1=duthost1,
                 rx_port_id=snappi_ports[0]["port_id"],
                 duthost2=duthost2,
                 tx_port_id=snappi_ports[1]["port_id"],
                 global_pause=True,
                 pause_prio_list=None,
                 test_prio_list=test_prio_list,
                 bg_prio_list=bg_prio_list,
                 prio_dscp_map=prio_dscp_map,
                 test_traffic_pause=False)