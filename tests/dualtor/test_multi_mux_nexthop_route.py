import logging
import pytest

from ptf import testutils
from tests.common.dualtor.dual_tor_mock import *
from tests.common.dualtor.dual_tor_utils import rand_selected_interface
from tests.common.dualtor.dual_tor_utils import add_nexthop_routes
from tests.common.dualtor.dual_tor_utils import check_nexthops_balance
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports


TEST_ROUTE_PFX="2.3.4.0/24"


pytestmark = [
    pytest.mark.topology('dualtor'),
    pytest.mark.usefixtures('apply_mock_dual_tor_tables',
                            'apply_mock_dual_tor_kernel_configs',
                            'run_garp_service',
                            'run_icmp_responder')
]


@pytest.fixture(autouse=True)
def cleanup_arp(duthosts):
    """Cleanup arp entries after test."""
    yield
    for duthost in duthosts:
        duthost.shell("sonic-clear arp")


@pytest.fixture(autouse=True)
def enable_garp(duthost):
    """Enable creating arp table entry for gratuitous ARP."""
    vlan_intf = duthost.get_running_config_facts()["VLAN_MEMBER"].keys()[0]
    cmd = "echo %s > /proc/sys/net/ipv4/conf/" + vlan_intf + "/arp_accept"
    duthost.shell(cmd % 1)
    yield
    duthost.shell(cmd % 0)


def test_multi_nexthop_route(
    announce_new_neighbor, apply_active_state_to_orchagent,
    conn_graph_facts, ptfadapter, ptfhost,
    rand_selected_dut, set_crm_polling_interval,
    tbinfo, tunnel_traffic_monitor, vmhost
):
    tor = rand_selected_dut

    # Find 2 random neighbors with different interfaces
    iface1, nexthop_neigh1 = rand_selected_interface(rand_selected_dut)
    iface2, nexthop_neigh2 = rand_selected_interface(rand_selected_dut)
    count_timeout = 20
    # try to find 2 different neighbors from 2 different interfaces
    while nexthop_neigh1 == nexthop_neigh2 and \
          iface1 == iface2 and \
          count_timeout > 0:
        iface2, nexthop_neigh2 = rand_selected_interface(rand_selected_dut)
        count_timeout = count_timeout - 1
    logging.info("create neighbors %s on %s and %s on %s", \
                 )
    
    # set interface states to active
    mux_states = ['active', 'standby', 'active']
    for if1_state in mux_states:
        for if2_state in mux_states:
            set_mux_state(rand_selected_dut, tbinfo, if1_state, iface1, toggle_all_simulator_ports)
            set_mux_state(rand_selected_dut, tbinfo, if2_state, iface2, toggle_all_simulator_ports)
            # program the route to dut
            add_nexthop_routes(rand_selected_dut, TEST_ROUTE_PFX, nexthops=[nexthop_neigh1, nexthop_neigh2])
            if_list = []
            if if1_state == 'active':
                if_list.append(iface1)
            if if2_state =='active':
                if_list.append(iface2)
            # verify route works
            check_nexthops_balance(rand_selected_dut, ptfadapter, TEST_ROUTE_PFX,
                                tbinfo, if_list, len(if_list))



    