'''
Send packets to route destinations with ECMP nexthops.

Step	Goal	Expected results
Add route with four nexthops, where four muxes are active	ECMP	Verify traffic to this route destination is distributed to four server ports
Simulate nexthop1 mux state change to Standby	ECMP	Verify traffic to this route destination is distributed to three server ports and one tunnel nexthop
Simulate nexthop2 mux state change to Standby	ECMP	Verify traffic to this route destination is distributed to two server ports and two tunnel nexthop
Simulate nexthop3 mux state change to Standby	ECMP	Verify traffic to this route destination is distributed to one server port and three tunnel nexthop
Simulate nexthop4 mux state change to Standby	ECMP	Verify traffic to this route destination is distributed to four tunnel nexthops
Simulate nexthop4 mux state change to Active	ECMP	Verify traffic to this route destination is distributed to one server port and three tunnel nexthop
Simulate nexthop3 mux state change to Active	ECMP	Verify traffic to this route destination is distributed to two server ports and two tunnel nexthop
'''
import pytest
import random
import time
import logging
import ipaddress
import contextlib
import time
from ptf import testutils

from tests.common.dualtor.dual_tor_mock import *
from tests.common.dualtor.dual_tor_utils import build_packet_to_server
from tests.common.dualtor.dual_tor_utils import dualtor_info
from tests.common.dualtor.dual_tor_utils import check_tunnel_balance
from tests.common.dualtor.dual_tor_utils import get_t1_ptf_ports
from tests.common.dualtor.dual_tor_utils import build_packet_to_server
from tests.common.dualtor.dual_tor_utils import mux_cable_server_ip

from tests.common.helpers.assertions import pytest_require as pt_require
from tests.common.dualtor.tunnel_traffic_utils import tunnel_traffic_monitor
from tests.common.dualtor.server_traffic_utils import ServerTrafficMonitor
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.usefixtures('apply_mock_dual_tor_tables',
                            'apply_mock_dual_tor_kernel_configs',
                            'apply_standby_state_to_orchagent',
                            'run_garp_service',
                            'run_icmp_responder')
]

logger = logging.getLogger(__file__)


def add_nexthop_routes(standby_tor, route_dst, nexthop=None):
    """
    Add static routes to reach route_dst via nexthop.
    The function is similar with fixture apply_dual_tor_peer_switch_route, but we can't use the fixture directly
    """
    logger.info("Applying route on {} to dst {}".format(standby_tor.hostname, route_dst))
    bgp_neighbors = standby_tor.bgp_facts()['ansible_facts']['bgp_neighbors'].keys()

    ipv4_neighbors = []

    for neighbor in bgp_neighbors:
        if ipaddress.ip_address(neighbor).version == 4:
            ipv4_neighbors.append(neighbor)

    nexthop_str = ''
    if nexthop is None:
        for neighbor in ipv4_neighbors:
            nexthop_str += 'nexthop via {} '.format(neighbor)
    else:
        nexthop_str += 'nexthop via {} '.format(nexthop)

    # Use `ip route replace` in case a rule already exists for this IP
    # If there are no pre-existing routes, equivalent to `ip route add`
    route_cmd = 'ip route replace {}/32 {}'.format(route_dst, nexthop_str)
    standby_tor.shell(route_cmd)
    logger.info("Route added to {}: {}".format(standby_tor.hostname, route_cmd))

def remove_static_routes(standby_tor, active_tor_loopback_ip):
    """
    Remove static routes for active tor
    """
    logger.info("Removing dual ToR peer switch static route")
    standby_tor.shell('ip route del {}/32'.format(active_tor_loopback_ip), module_ignore_errors=True)


def get_random_interfaces(torhost, count):
    server_ips = mux_cable_server_ip(torhost)
    interfaces = [str(_) for _ in random.sample(server_ips.keys(), count)]
    iface_server_map = {_: server_ips[_] for _ in interfaces}
    logging.info("select DUT interface %s to test.", iface_server_map)
    return iface_server_map


def test_downstream_ecmp_nexthops(
    conn_graph_facts, ptfadapter, ptfhost,
    rand_selected_dut, rand_unselected_dut, tbinfo,
    tunnel_traffic_monitor, vmhost, toggle_all_simulator_ports,
    tor_mux_intfs
    ):
    # set rand_selected_dut as standby and rand_unselected_dut to active tor
    # params = dualtor_info(ptfhost, rand_selected_dut, rand_unselected_dut, tbinfo)
    tor = rand_selected_dut
    test_params = dualtor_info(ptfhost, tor, rand_unselected_dut, tbinfo)
    server_ipv4 = test_params["target_server_ip"]
    random_dst_ip = server_ipv4

    pkt, exp_pkt = build_packet_to_server(tor, ptfadapter, random_dst_ip)
    ptf_t1_intf = random.choice(get_t1_ptf_ports(tor, tbinfo))

    def monitor_tunnel_and_server_traffic(torhost, expect_tunnel_traffic=True, expect_server_traffic=True):
        tunnel_monitor = tunnel_traffic_monitor(tor, existing=True)
        server_traffic_monitor = ServerTrafficMonitor(
            torhost, vmhost, test_params["selected_port"],
            conn_graph_facts, exp_pkt, existing=False
        )
        tunnel_monitor.existing = expect_tunnel_traffic
        server_traffic_monitor.existing = expect_server_traffic
        with tunnel_monitor, server_traffic_monitor:
            testutils.send(ptfadapter, int(ptf_t1_intf.strip("eth")), pkt, count=10)

    set_mux_state(rand_selected_dut, tbinfo, 'active', tor_mux_intfs, toggle_all_simulator_ports)
    iface_server_map = get_random_interfaces(rand_selected_dut, 4)
    interfaces = iface_server_map.keys()

    logger.info("Add route with four nexthops, where four muxes are active")
    for _, servers in iface_server_map.items():
        add_nexthop_routes(rand_selected_dut, servers[0], nexthop=servers[0])

    logger.info("Verify traffic to this route destination is distributed to four server ports")
    check_tunnel_balance(**test_params)

    logger.info("Simulate nexthop1 mux state change to Standby")
    set_mux_state(rand_selected_dut, tbinfo, 'standby', [interfaces[0]], toggle_all_simulator_ports)
    logger.info("Verify traffic to this route destination is distributed to three server ports and one tunnel nexthop")

    logger.info("Simulate nexthop2 mux state change to Standby")
    set_mux_state(rand_selected_dut, tbinfo, 'standby', [interfaces[1]], toggle_all_simulator_ports)
    logger.info("Verify traffic to this route destination is distributed to two server ports and two tunnel nexthop")

    logger.info("Simulate nexthop3 mux state change to Standby")
    set_mux_state(rand_selected_dut, tbinfo, 'standby', [interfaces[2]], toggle_all_simulator_ports)
    logger.info("Verify traffic to this route destination is distributed to one server port and three tunnel nexthop")

    logger.info("Simulate nexthop4 mux state change to Standby")
    set_mux_state(rand_selected_dut, tbinfo, 'standby', [interfaces[3]], toggle_all_simulator_ports)
    logger.info("Verify traffic to this route destination is distributed to four tunnel nexthops")

    logger.info("Simulate nexthop4 mux state change to Active")
    set_mux_state(rand_selected_dut, tbinfo, 'active', [interfaces[3]], toggle_all_simulator_ports)
    logger.info("Verify traffic to this route destination is distributed to one server port and three tunnel nexthop")

    logger.info("Simulate nexthop3 mux state change to Active")
    set_mux_state(rand_selected_dut, tbinfo, 'active', [interfaces[2]], toggle_all_simulator_ports)
    logger.info("Verify traffic to this route destination is distributed to two server ports and two tunnel nexthop")


