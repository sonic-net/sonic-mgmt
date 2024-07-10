import contextlib
import logging
import pytest
import random

from ipaddress import ip_address
from ptf import testutils
from tests.common.dualtor.dual_tor_mock import *        # noqa F403
from tests.common.dualtor.dual_tor_utils import dualtor_info
from tests.common.dualtor.dual_tor_utils import flush_neighbor
from tests.common.dualtor.dual_tor_utils import get_t1_ptf_ports
from tests.common.dualtor.dual_tor_utils import crm_neighbor_checker
from tests.common.dualtor.dual_tor_utils import build_packet_to_server
from tests.common.dualtor.dual_tor_utils import get_interface_server_map
from tests.common.dualtor.dual_tor_utils import check_nexthops_single_downlink
from tests.common.dualtor.dual_tor_utils import add_nexthop_routes, remove_static_routes
from tests.common.dualtor.dual_tor_mock import set_mux_state
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports   # noqa F401
from tests.common.dualtor.server_traffic_utils import ServerTrafficMonitor
from tests.common.dualtor.tunnel_traffic_utils import tunnel_traffic_monitor        # noqa F401
from tests.common.fixtures.ptfhost_utils import run_icmp_responder                  # noqa F401
from tests.common.fixtures.ptfhost_utils import run_garp_service                    # noqa F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses                # noqa F401
# from tests.common.fixtures.ptfhost_utils import skip_traffic_test                   # noqa F401
# Temporary work around to add skip_traffic_test fixture from duthost_utils
from tests.common.fixtures.duthost_utils import skip_traffic_test                   # noqa F401
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until


pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.usefixtures('apply_mock_dual_tor_tables',
                            'apply_mock_dual_tor_kernel_configs',
                            'apply_active_state_to_orchagent',
                            'run_garp_service',
                            'run_icmp_responder')
]


@pytest.fixture(params=['ipv4', 'ipv6'])
def ip_version(request):
    """Traffic IP version to test."""
    return request.param


@pytest.fixture
def testbed_setup(ip_version, ptfhost, rand_selected_dut, rand_unselected_dut, tbinfo, request):
    testbed_params = dualtor_info(ptfhost, rand_selected_dut, rand_unselected_dut, tbinfo)
    test_port = testbed_params["selected_port"]
    if ip_version == "ipv4":
        server_ip = testbed_params["target_server_ip"]
        request.getfixturevalue("run_arp_responder")
    elif ip_version == "ipv6":
        server_ip = testbed_params["target_server_ipv6"]
        # setup arp_responder to answer ipv6 neighbor solicitation messages
        request.getfixturevalue("run_arp_responder_ipv6")
    else:
        raise ValueError("Unknown IP version '%s'" % ip_version)
    return test_port, server_ip, ip_version


def neighbor_reachable(duthost, neighbor_ip):
    neigh_table = duthost.switch_arptable()['ansible_facts']['arptable']
    ip_version = 'v4' if ip_address(neighbor_ip).version == 4 else 'v6'
    neigh_status = neigh_table[ip_version][neighbor_ip]['state'].lower()
    return "reachable" in neigh_status or "permanent" in neigh_status


def test_active_tor_remove_neighbor_downstream_active(
    conn_graph_facts, ptfadapter, ptfhost, testbed_setup,
    rand_selected_dut, tbinfo, set_crm_polling_interval,
    tunnel_traffic_monitor, vmhost, skip_traffic_test      # noqa F811
):
    """
    @Verify those two scenarios:
    If the neighbor entry of a server is present on active ToR,
    all traffic to server should be directly forwarded.
    If the neighbor entry of a server is removed, all traffic to server
    should be dropped and no tunnel traffic.
    """

    @contextlib.contextmanager
    def remove_neighbor(ptfhost, duthost, server_ip, ip_version, neighbor_details):
        # restore ipv4 neighbor since it is statically configured
        flush_neighbor_ct = flush_neighbor(duthost, server_ip, restore=ip_version == "ipv4" or "ipv6")
        try:
            ptfhost.shell("supervisorctl stop arp_responder", module_ignore_errors=True)
            # stop garp_service since there is no equivalent in production
            ptfhost.shell("supervisorctl stop garp_service")
            with flush_neighbor_ct as flushed_neighbor:
                neighbor_details.update(flushed_neighbor)
                yield
        finally:
            ptfhost.shell("supervisorctl start arp_responder")
            duthost.shell("docker exec -t swss supervisorctl restart arp_update")

    try:
        removed_neighbor = {}
        tor = rand_selected_dut
        test_port, server_ip, ip_version = testbed_setup

        pkt, exp_pkt = build_packet_to_server(tor, ptfadapter, server_ip)
        ptf_t1_intf = random.choice(get_t1_ptf_ports(tor, tbinfo))
        logging.info("send traffic to server %s from ptf t1 interface %s", server_ip, ptf_t1_intf)
        server_traffic_monitor = ServerTrafficMonitor(
            tor, ptfhost, vmhost, tbinfo, test_port, conn_graph_facts, exp_pkt,
            existing=True, is_mocked=is_mocked_dualtor(tbinfo), skip_traffic_test=skip_traffic_test       # noqa F405
        )
        tunnel_monitor = tunnel_traffic_monitor(tor, existing=False, skip_traffic_test=skip_traffic_test)
        with crm_neighbor_checker(tor, ip_version, expect_change=ip_version == "ipv6"), \
                tunnel_monitor, server_traffic_monitor:
            testutils.send(ptfadapter, int(ptf_t1_intf.strip("eth")), pkt, count=10)

        logging.info("send traffic to server %s after removing neighbor entry", server_ip)
        server_traffic_monitor = ServerTrafficMonitor(
            tor, ptfhost, vmhost, tbinfo, test_port, conn_graph_facts, exp_pkt,
            existing=False, is_mocked=is_mocked_dualtor(tbinfo), skip_traffic_test=skip_traffic_test      # noqa F405
        )
        remove_neighbor_ct = remove_neighbor(ptfhost, tor, server_ip, ip_version, removed_neighbor)
        with crm_neighbor_checker(tor, ip_version, expect_change=ip_version == "ipv6"), \
                remove_neighbor_ct, tunnel_monitor, server_traffic_monitor:
            testutils.send(ptfadapter, int(ptf_t1_intf.strip("eth")), pkt, count=10)
        # wait up to a minute for the neighbor entry to become reachable
        # due to performance limitation on some testbeds/lab servers
        pytest_assert(wait_until(60, 5, 0, lambda: neighbor_reachable(tor, server_ip)))

        logging.info("send traffic to server %s after neighbor entry is restored", server_ip)
        server_traffic_monitor = ServerTrafficMonitor(
            tor, ptfhost, vmhost, tbinfo, test_port, conn_graph_facts, exp_pkt,
            existing=True, is_mocked=is_mocked_dualtor(tbinfo), skip_traffic_test=skip_traffic_test       # noqa F405
        )
        with crm_neighbor_checker(tor, ip_version, expect_change=ip_version == "ipv6"), \
                tunnel_monitor, server_traffic_monitor:
            testutils.send(ptfadapter, int(ptf_t1_intf.strip("eth")), pkt, count=10)
    finally:
        # try to recover the removed neighbor so test_downstream_ecmp_nexthops could have a healthy mocked device
        if removed_neighbor:
            if ip_version == "ipv4":
                cmd = 'ip -4 neigh replace {} lladdr {} dev {}'\
                      .format(server_ip, removed_neighbor['lladdr'], removed_neighbor['dev'])
            else:
                cmd = 'ip -6 neigh replace {} lladdr {} dev {}'\
                      .format(server_ip, removed_neighbor['lladdr'], removed_neighbor['dev'])
            tor.shell(cmd)
        ptfhost.shell("supervisorctl start garp_service")


def test_downstream_ecmp_nexthops(
    ptfadapter, rand_selected_dut, tbinfo,
    toggle_all_simulator_ports, tor_mux_intfs, ip_version, skip_traffic_test   # noqa F811
):
    nexthops_count = 4
    set_mux_state(rand_selected_dut, tbinfo, 'active', tor_mux_intfs, toggle_all_simulator_ports)        # noqa F405
    iface_server_map = get_interface_server_map(rand_selected_dut, nexthops_count)

    if ip_version == "ipv4":
        dst_server_addr = "1.1.1.2"
        interface_to_server = {intf: servers["server_ipv4"].split("/")[0]
                               for intf, servers in list(iface_server_map.items())}
    elif ip_version == "ipv6":
        dst_server_addr = "fc10:2020::f"
        interface_to_server = {intf: servers["server_ipv6"].split("/")[0]
                               for intf, servers in list(iface_server_map.items())}
    else:
        raise ValueError("Unknown IP version '%s'" % ip_version)

    nexthop_servers = list(interface_to_server.values())
    nexthop_interfaces = list(interface_to_server.keys())

    logging.info("Add route with four nexthops, where four muxes are active")
    add_nexthop_routes(rand_selected_dut, dst_server_addr, nexthops=nexthop_servers)

    try:
        logging.info("Verify traffic to this route destination is sent to single downlink or uplink")
        check_nexthops_single_downlink(rand_selected_dut, ptfadapter, dst_server_addr,
                                       tbinfo, nexthop_interfaces, skip_traffic_test)

        nexthop_interfaces_copy = nexthop_interfaces.copy()

        # Sequentially set four mux states to standby
        for index, interface in enumerate(nexthop_interfaces):
            logging.info("Simulate {} mux state change to Standby".format(nexthop_servers[index]))
            set_mux_state(rand_selected_dut, tbinfo, 'standby', [interface], toggle_all_simulator_ports)
            nexthop_interfaces_copy.remove(interface)
            logging.info("Verify traffic to this route destination is sent to single downlink or uplink")
            check_nexthops_single_downlink(rand_selected_dut, ptfadapter, dst_server_addr,
                                           tbinfo, nexthop_interfaces_copy, skip_traffic_test)

        # Revert two mux states to active
        for index, interface in reversed(list(enumerate(nexthop_interfaces))):
            logging.info("Simulate {} mux state change back to Active".format(nexthop_servers[index]))
            set_mux_state(rand_selected_dut, tbinfo, 'active', [interface], toggle_all_simulator_ports)
            nexthop_interfaces_copy.append(interface)
            logging.info("Verify traffic to this route destination is sent to single downlink or uplink")
            check_nexthops_single_downlink(rand_selected_dut, ptfadapter, dst_server_addr,
                                           tbinfo, nexthop_interfaces_copy, skip_traffic_test)
    finally:
        # Remove the nexthop route
        remove_static_routes(rand_selected_dut, dst_server_addr)
