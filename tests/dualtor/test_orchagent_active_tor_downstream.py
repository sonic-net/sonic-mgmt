import contextlib
import logging
import pytest
import random
from ptf import testutils
from tests.common.dualtor.dual_tor_mock import *
from tests.common.dualtor.dual_tor_utils import dualtor_info
from tests.common.dualtor.dual_tor_utils import flush_neighbor
from tests.common.dualtor.dual_tor_utils import get_t1_ptf_ports
from tests.common.dualtor.dual_tor_utils import crm_neighbor_checker
from tests.common.dualtor.dual_tor_utils import build_packet_to_server
from tests.common.dualtor.dual_tor_utils import get_interface_server_map
from tests.common.dualtor.dual_tor_utils import check_nexthops_balance
from tests.common.dualtor.dual_tor_utils import add_nexthop_routes, remove_static_routes
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports
from tests.common.dualtor.server_traffic_utils import ServerTrafficMonitor
from tests.common.dualtor.tunnel_traffic_utils import tunnel_traffic_monitor
from tests.common.fixtures.ptfhost_utils import run_icmp_responder
from tests.common.fixtures.ptfhost_utils import run_garp_service
from tests.common.fixtures.ptfhost_utils import change_mac_addresses


pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.usefixtures('apply_mock_dual_tor_tables',
                            'apply_mock_dual_tor_kernel_configs',
                            'apply_active_state_to_orchagent',
                            'run_garp_service',
                            'run_icmp_responder')
]


def test_active_tor_remove_neighbor_downstream_active(
    conn_graph_facts, ptfadapter, ptfhost,
    rand_selected_dut, rand_unselected_dut, tbinfo,
    require_mocked_dualtor, set_crm_polling_interval,
    tunnel_traffic_monitor, vmhost
):
    """
    @Verify those two scenarios:
    If the neighbor entry of a server is present on active ToR,
    all traffic to server should be directly forwarded.
    If the neighbor entry of a server is removed, all traffic to server
    should be dropped and no tunnel traffic.
    """
    @contextlib.contextmanager
    def stop_garp(ptfhost):
        """Temporarily stop garp service."""
        ptfhost.shell("supervisorctl stop garp_service")
        yield
        ptfhost.shell("supervisorctl start garp_service")

    tor = rand_selected_dut
    test_params = dualtor_info(ptfhost, rand_selected_dut, rand_unselected_dut, tbinfo)
    server_ipv4 = test_params["target_server_ip"]

    pkt, exp_pkt = build_packet_to_server(tor, ptfadapter, server_ipv4)
    ptf_t1_intf = random.choice(get_t1_ptf_ports(tor, tbinfo))
    logging.info("send traffic to server %s from ptf t1 interface %s", server_ipv4, ptf_t1_intf)
    server_traffic_monitor = ServerTrafficMonitor(
        tor, ptfhost, vmhost, tbinfo, test_params["selected_port"],
        conn_graph_facts, exp_pkt, existing=True, is_mocked=is_mocked_dualtor(tbinfo)
    )
    tunnel_monitor = tunnel_traffic_monitor(tor, existing=False)
    with crm_neighbor_checker(tor), tunnel_monitor, server_traffic_monitor:
        testutils.send(ptfadapter, int(ptf_t1_intf.strip("eth")), pkt, count=10)

    logging.info("send traffic to server %s after removing neighbor entry", server_ipv4)
    server_traffic_monitor = ServerTrafficMonitor(
        tor, ptfhost, vmhost, tbinfo, test_params["selected_port"],
        conn_graph_facts, exp_pkt, existing=False, is_mocked=is_mocked_dualtor(tbinfo)
    )    # for real dualtor testbed, leave the neighbor restoration to garp service
    flush_neighbor_ct = flush_neighbor(tor, server_ipv4, restore=is_t0_mocked_dualtor)
    with crm_neighbor_checker(tor), stop_garp(ptfhost), flush_neighbor_ct, tunnel_monitor, server_traffic_monitor:
        testutils.send(ptfadapter, int(ptf_t1_intf.strip("eth")), pkt, count=10)

    logging.info("send traffic to server %s after neighbor entry is restored", server_ipv4)
    server_traffic_monitor = ServerTrafficMonitor(
        tor, ptfhost, vmhost, tbinfo, test_params["selected_port"],
        conn_graph_facts, exp_pkt, existing=True, is_mocked=is_mocked_dualtor(tbinfo)
    )
    with crm_neighbor_checker(tor), tunnel_monitor, server_traffic_monitor:
        testutils.send(ptfadapter, int(ptf_t1_intf.strip("eth")), pkt, count=10)


def test_downstream_ecmp_nexthops(
    ptfadapter, rand_selected_dut, tbinfo,
    require_mocked_dualtor, toggle_all_simulator_ports,
    tor_mux_intfs
    ):
    dst_server_ipv4 = "1.1.1.2"
    nexthops_count = 4
    set_mux_state(rand_selected_dut, tbinfo, 'active', tor_mux_intfs, toggle_all_simulator_ports)

    iface_server_map = get_interface_server_map(rand_selected_dut, nexthops_count)
    interface_to_server = dict()
    for interface, servers in iface_server_map.items():
        interface_to_server[interface] = servers['server_ipv4'].split("/")[0]

    nexthop_servers = list(interface_to_server.values())
    nexthop_interfaces = list(interface_to_server.keys())

    logging.info("Add route with four nexthops, where four muxes are active")
    add_nexthop_routes(rand_selected_dut, dst_server_ipv4, nexthops=nexthop_servers[0:nexthops_count])

    logging.info("Verify traffic to this route destination is distributed to four server ports")
    check_nexthops_balance(rand_selected_dut, ptfadapter, dst_server_ipv4, tbinfo,
        nexthop_interfaces, nexthops_count)

    ### Sequentially set four mux states to standby
    for index, interface in enumerate(nexthop_interfaces):
        uplink_ports_active = index + 1
        logging.info("Simulate {} mux state change to Standby".format(nexthop_servers[index]))
        set_mux_state(rand_selected_dut, tbinfo, 'standby', [interface], toggle_all_simulator_ports)
        logging.info("Verify traffic to this route destination is distributed to"\
            " {} server ports and {} tunnel nexthop".format(
                nexthops_count-uplink_ports_active, uplink_ports_active))
        check_nexthops_balance(rand_selected_dut, ptfadapter, dst_server_ipv4, tbinfo,
            nexthop_interfaces[uplink_ports_active:nexthops_count], nexthops_count)

    ### Revert two mux states to active
    for index, interface in reversed(list(enumerate(nexthop_interfaces))):
        logging.info("Simulate {} mux state change back to Active".format(nexthop_servers[index]))
        set_mux_state(rand_selected_dut, tbinfo, 'active', [interface], toggle_all_simulator_ports)
        logging.info("Verify traffic to this route destination is distributed to"\
            " {} server ports and {} tunnel nexthop".format(nexthops_count-index, index))
        check_nexthops_balance(rand_selected_dut, ptfadapter, dst_server_ipv4, tbinfo,
            nexthop_interfaces[index:nexthops_count], nexthops_count)
    ### Remove the nexthop route
    remove_static_routes(rand_selected_dut, dst_server_ipv4)
