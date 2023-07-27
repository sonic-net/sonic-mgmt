'''
   Tests pfc Pause storms on all Ports 
''' 

import pytest

from files.pfcwd_all_ports_storm_helper import run_pfcwd_pause_storm_test

pytestmark = [pytest.mark.topology('tgen')]


def test_pfcwd_all_ports_pause_storm(ixia_api,
                                     ixia_testbed_config,
                                     conn_graph_facts,
                                     fanout_graph_facts,
                                     duthosts,
                                     rand_one_dut_hostname,
                                     setup_cgm_alpha_cisco,
                                     rand_one_dut_portname_oper_up,
                                     rand_one_dut_lossless_prio,
                                     lossy_prio_list,
                                     prio_dscp_map): 

    """
    Run PFC PAUSE Storm on all ports 

    Args:
        ixia_api (pytest fixture): IXIA session
        ixia_testbed_config (pytest fixture): testbed configuration information
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_hostname (str): hostname of DUT
        rand_one_dut_portname_oper_up (str): port to test, e.g., 's6100-1|Ethernet0'
        rand_one_dut_lossless_prio (str): lossless priority to test, e.g., 's6100-1|3'
        lossy_prio_list (pytest fixture): list of lossy priorities

    Returns:
        N/A
    """
    dut_hostname, dut_port = rand_one_dut_portname_oper_up.split('|')
    dut_hostname, lossless_prio = rand_one_dut_lossless_prio.split('|')

    duthost = duthosts[dut_hostname]

    testbed_config, port_config_list = ixia_testbed_config
    lossless_prio = int(lossless_prio)

    dut_ports_list = conn_graph_facts["device_conn"][dut_hostname].keys() 

    run_pfcwd_pause_storm_test(api=ixia_api,
                               testbed_config=testbed_config,
                               port_config_list=port_config_list,
                               conn_data=conn_graph_facts,
                               fanout_data=fanout_graph_facts,
                               duthost=duthost,
                               dut_ports_list=dut_ports_list,
                               pause_prio_list=[lossless_prio],
                               prio_dscp_map=prio_dscp_map)
