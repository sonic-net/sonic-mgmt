import pytest
import random
import time
import logging
import ipaddress
import contextlib
import time
import scapy.all as scapyall

from ptf import testutils, mask
from tests.common.dualtor.dual_tor_mock import *
from tests.common.dualtor.dual_tor_utils import dualtor_info, check_tunnel_balance, flush_neighbor, get_t1_ptf_ports
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory, change_mac_addresses, run_garp_service, run_icmp_responder   # lgtm[py/unused-import]
from tests.common.helpers.assertions import pytest_require as pt_require
from tests.common.dualtor.tunnel_traffic_utils import tunnel_traffic_monitor
from tests.common.dualtor.server_traffic_utils import ServerTrafficMonitor

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.usefixtures('apply_mock_dual_tor_tables',
                            'apply_mock_dual_tor_kernel_configs',
                            'apply_standby_state_to_orchagent',
                            'run_garp_service',
                            'run_icmp_responder')
]

logger = logging.getLogger(__file__)


def shutdown_random_one_t1_link(dut):
    """
    Shutdown a random t1 link
    """
    port_channels = dut.get_running_config_facts()['PORTCHANNEL'].keys()
    if not port_channels:
        return None
    link_to_shutdown = random.choice(port_channels)
    logger.info("Shutting down interface {}".format(link_to_shutdown))
    dut.shutdown(link_to_shutdown)
    return link_to_shutdown


def no_shutdown_t1_link(dut, link_to_up):
    """
    Bring back a down link
    """
    if link_to_up:
        logger.info("Bring back interface {}".format(link_to_up))
        dut.no_shutdown(link_to_up)


@pytest.fixture
def shutdown_one_uplink(rand_selected_dut):
    link_to_shutdown = shutdown_random_one_t1_link(rand_selected_dut)
    yield
    no_shutdown_t1_link(rand_selected_dut, link_to_shutdown)


def shutdown_random_one_bgp_session(dut):
    """
    Shutdown a random BGP session
    """
    bgp_facts = dut.get_bgp_neighbors()
    up_bgp_neighbors = []
    for k, v in bgp_facts.items():
        if v['state'] == 'established' and ipaddress.ip_address(k).version == 4:
            up_bgp_neighbors.append(k)
    if not up_bgp_neighbors:
        return None
    bgp_to_shutdown = random.choice(up_bgp_neighbors)
    logger.info("Shutting down bgp session with {}".format(bgp_to_shutdown))
    dut.shell("config bgp shutdown neighbor {}".format(bgp_to_shutdown))
    return bgp_to_shutdown


def startup_bgp_session(dut, bgp_to_up):
    """
    Startup a BGP session
    """
    if bgp_to_up:
        logger.info("Bring back bgp session with {}".format(bgp_to_up))
        dut.shell("config bgp startup neighbor {}".format(bgp_to_up))


@pytest.fixture
def shutdown_one_bgp_session(rand_selected_dut):
    bgp_shutdown = shutdown_random_one_bgp_session(rand_selected_dut)
    yield
    startup_bgp_session(rand_selected_dut, bgp_shutdown)


def add_loopback_routes(standby_tor, active_tor_loopback_ip):
    """
    Add static routes to reach the peer's loopback.
    The function is similar with fixture apply_dual_tor_peer_switch_route, but we can't use the fixture directly
    """
    logger.info("Applying dual ToR peer switch loopback route")
    bgp_neighbors = standby_tor.bgp_facts()['ansible_facts']['bgp_neighbors'].keys()

    ipv4_neighbors = []

    for neighbor in bgp_neighbors:
        if ipaddress.ip_address(neighbor).version == 4:
            ipv4_neighbors.append(neighbor)

    nexthop_str = ''
    for neighbor in ipv4_neighbors:
        nexthop_str += 'nexthop via {} '.format(neighbor)

    # Use `ip route replace` in case a rule already exists for this IP
    # If there are no pre-existing routes, equivalent to `ip route add`
    standby_tor.shell('ip route replace {}/32 {}'.format(active_tor_loopback_ip, nexthop_str))


def remove_loopback_routes(standby_tor, active_tor_loopback_ip):
    """
    Remove static routes for active tor's loopback
    """
    logger.info("Removing dual ToR peer switch loopback route")
    standby_tor.shell('ip route del {}/32'.format(active_tor_loopback_ip), module_ignore_errors=True)


def test_standby_tor_downstream(ptfhost, rand_selected_dut, rand_unselected_dut, tbinfo):
    """
    Verify tunnel traffic to active ToR is distributed equally across nexthops, and
    no traffic is forwarded to server from standby ToR
    """
    params = dualtor_info(ptfhost, rand_selected_dut, rand_unselected_dut, tbinfo)
    check_tunnel_balance(**params)


def test_standby_tor_downstream_t1_link_recovered(ptfhost, rand_selected_dut, rand_unselected_dut, verify_crm_nexthop_counter_not_increased, tbinfo):
    """
    Verify traffic is distributed evenly after t1 link is recovered;
    Verify CRM that no new nexthop created
    """
    PAUSE_TIME = 30

    down_link = shutdown_random_one_t1_link(rand_selected_dut)
    time.sleep(PAUSE_TIME)
    params = dualtor_info(ptfhost, rand_selected_dut, rand_unselected_dut, tbinfo)
    try:
        check_tunnel_balance(**params)
    except Exception as e:
        no_shutdown_t1_link(rand_selected_dut, down_link)
        raise e

    no_shutdown_t1_link(rand_selected_dut, down_link)
    time.sleep(PAUSE_TIME)
    params = dualtor_info(ptfhost, rand_selected_dut, rand_unselected_dut, tbinfo)
    # For mocked dualtor, we should update static route manually after link recovered
    if 't0' in tbinfo['topo']['name']:
        remove_loopback_routes(rand_selected_dut, params['active_tor_ip'])
        add_loopback_routes(rand_selected_dut, params['active_tor_ip'])
    check_tunnel_balance(**params)


def test_standby_tor_downstream_bgp_recovered(ptfhost, rand_selected_dut, rand_unselected_dut, verify_crm_nexthop_counter_not_increased, tbinfo):
    """
    Verify traffic is shifted to the active links and no traffic drop observed;
    Verify traffic is distributed evenly after BGP session is recovered;
    Verify CRM that no new nexthop created
    """
    PAUSE_TIME = 30

    down_bgp = shutdown_random_one_bgp_session(rand_selected_dut)
    time.sleep(PAUSE_TIME)
    params = dualtor_info(ptfhost, rand_selected_dut, rand_unselected_dut, tbinfo)
    try:
        check_tunnel_balance(**params)
    except Exception as e:
        startup_bgp_session(rand_selected_dut, down_bgp)
        raise e

    startup_bgp_session(rand_selected_dut, down_bgp)
    time.sleep(PAUSE_TIME)
    params = dualtor_info(ptfhost, rand_selected_dut, rand_unselected_dut, tbinfo)
    check_tunnel_balance(**params)


def test_standby_tor_downstream_loopback_route_readded(ptfhost, rand_selected_dut, rand_unselected_dut, tbinfo):
    """
    Verify traffic is equally distributed via loopback route
    """
    pt_require('dualtor' in tbinfo['topo']['name'], "Only run on dualtor testbed")
    params = dualtor_info(ptfhost, rand_selected_dut, rand_unselected_dut, tbinfo)
    active_tor_loopback0 = params['active_tor_ip']

    # Remove loopback routes and verify traffic is equally distributed
    remove_loopback_routes(rand_selected_dut, active_tor_loopback0)
    check_tunnel_balance(**params)

    # Readd loopback routes and verify traffic is equally distributed
    add_loopback_routes(rand_selected_dut, active_tor_loopback0)
    check_tunnel_balance(**params)


def test_standby_tor_remove_neighbor_downstream_standby(
    conn_graph_facts, ptfadapter, ptfhost,
    rand_selected_dut, rand_unselected_dut, tbinfo,
    set_crm_polling_interval,
    tunnel_traffic_monitor, vmhost
):
    """
    @summary: Verify that after removing neighbor entry for a server over standby
    ToR, the packets sent to the server will be dropped(neither passed to the server
    or redirected to the active ToR).
    """
    def build_packet_to_server(tor, ptfadapter, target_server_ip, tunnel_traffic_monitor):
        """Build packet destinated to server."""
        pkt_dscp = random.choice(range(0, 33))
        pkt_ttl = random.choice(range(3, 65))
        pkt = testutils.simple_ip_packet(
            eth_dst=tor.facts["router_mac"],
            eth_src=ptfadapter.dataplane.get_mac(0, 0),
            ip_src="1.1.1.1",
            ip_dst=target_server_ip,
            ip_dscp=pkt_dscp,
            ip_ttl=pkt_ttl
        )
        logging.info(
            "the packet destinated to server %s:\n%s", target_server_ip,
            tunnel_traffic_monitor._dump_show_str(pkt)
        )
        return pkt

    def build_expected_packet_to_server(packet):
        """Build expected mask packet downstream to server."""
        exp_pkt = mask.Mask(packet)
        exp_pkt.set_do_not_care_scapy(scapyall.Ether, "dst")
        exp_pkt.set_do_not_care_scapy(scapyall.Ether, "src")
        exp_pkt.set_do_not_care_scapy(scapyall.IP, "tos")
        exp_pkt.set_do_not_care_scapy(scapyall.IP, "ttl")
        exp_pkt.set_do_not_care_scapy(scapyall.IP, "chksum")
        return exp_pkt

    @contextlib.contextmanager
    def crm_neighbor_checker(duthost):
        crm_facts_before = duthost.get_crm_facts()
        ipv4_neighbor_before = crm_facts_before["resources"]["ipv4_neighbor"]["used"]
        logging.info("ipv4 neighbor before test: %s", ipv4_neighbor_before)
        yield
        time.sleep(crm_facts_before["polling_interval"])
        crm_facts_after = duthost.get_crm_facts()
        ipv4_neighbor_after = crm_facts_after["resources"]["ipv4_neighbor"]["used"]
        logging.info("ipv4 neighbor after test: %s", ipv4_neighbor_after)
        if ipv4_neighbor_after != ipv4_neighbor_before:
            raise ValueError("ipv4 neighbor differs, before %s, after %s", ipv4_neighbor_before, ipv4_neighbor_after)

    tor = rand_selected_dut
    test_params = dualtor_info(ptfhost, rand_selected_dut, rand_unselected_dut, tbinfo)
    server_ipv4 = test_params["target_server_ip"]

    pkt = build_packet_to_server(tor, ptfadapter, server_ipv4, tunnel_traffic_monitor)
    exp_pkt = build_expected_packet_to_server(pkt)
    ptf_t1_intf = random.choice(get_t1_ptf_ports(tor, tbinfo))
    logging.info("send traffic to server %s from ptf t1 interface %s", server_ipv4, ptf_t1_intf)
    tunnel_monitor = tunnel_traffic_monitor(tor, existing=True)
    with tunnel_monitor:
        testutils.send(ptfadapter, int(ptf_t1_intf.strip("eth")), pkt, count=10)

    logging.info("send traffic to server %s after removing neighbor entry", server_ipv4)
    tunnel_monitor.existing = False
    server_traffic_monitor = ServerTrafficMonitor(
        tor, vmhost, test_params["selected_port"],
        conn_graph_facts, exp_pkt, existing=False
    )
    with crm_neighbor_checker(tor), flush_neighbor(tor, server_ipv4), tunnel_monitor, server_traffic_monitor:
        testutils.send(ptfadapter, int(ptf_t1_intf.strip("eth")), pkt, count=10)

    logging.info("send traffic to server %s after neighbor entry is restored", server_ipv4)
    tunnel_monitor.existing = True
    with crm_neighbor_checker(tor), tunnel_monitor:
        testutils.send(ptfadapter, int(ptf_t1_intf.strip("eth")), pkt, count=10)
