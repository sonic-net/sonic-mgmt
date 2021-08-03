import pytest
import random
import time
import logging
import ipaddress
import contextlib
import time

from ptf import testutils
from tests.common.dualtor.dual_tor_mock import *
from tests.common.dualtor.dual_tor_utils import dualtor_info
from tests.common.dualtor.dual_tor_utils import check_tunnel_balance
from tests.common.dualtor.dual_tor_utils import flush_neighbor
from tests.common.dualtor.dual_tor_utils import get_t1_ptf_ports
from tests.common.dualtor.dual_tor_utils import build_packet_to_server
from tests.common.dualtor.dual_tor_utils import crm_neighbor_checker
from tests.common.dualtor.dual_tor_utils import add_nexthop_routes, remove_static_routes
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory
from tests.common.fixtures.ptfhost_utils import change_mac_addresses
from tests.common.fixtures.ptfhost_utils import run_garp_service
from tests.common.fixtures.ptfhost_utils import run_icmp_responder   # lgtm[py/unused-import]
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


def test_standby_tor_downstream(ptfhost, rand_selected_dut, rand_unselected_dut,
    tbinfo, require_mocked_dualtor):
    """
    Verify tunnel traffic to active ToR is distributed equally across nexthops, and
    no traffic is forwarded to server from standby ToR
    """
    params = dualtor_info(ptfhost, rand_selected_dut, rand_unselected_dut, tbinfo)
    check_tunnel_balance(**params)


def test_standby_tor_downstream_t1_link_recovered(ptfhost, rand_selected_dut, rand_unselected_dut,
    require_mocked_dualtor, verify_crm_nexthop_counter_not_increased, tbinfo):
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
        remove_static_routes(rand_selected_dut, params['active_tor_ip'])
        add_nexthop_routes(rand_selected_dut, params['active_tor_ip'])
    check_tunnel_balance(**params)


def test_standby_tor_downstream_bgp_recovered(ptfhost, rand_selected_dut, rand_unselected_dut,
    require_mocked_dualtor, verify_crm_nexthop_counter_not_increased, tbinfo):
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
    remove_static_routes(rand_selected_dut, active_tor_loopback0)
    check_tunnel_balance(**params)

    # Readd loopback routes and verify traffic is equally distributed
    add_nexthop_routes(rand_selected_dut, active_tor_loopback0)
    check_tunnel_balance(**params)


def test_standby_tor_remove_neighbor_downstream_standby(
    conn_graph_facts, ptfadapter, ptfhost,
    rand_selected_dut, rand_unselected_dut, tbinfo,
    require_mocked_dualtor, set_crm_polling_interval,
    tunnel_traffic_monitor, vmhost
):
    """
    @summary: Verify that after removing neighbor entry for a server over standby
    ToR, the packets sent to the server will be dropped(neither passed to the server
    or redirected to the active ToR).
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
    tunnel_monitor = tunnel_traffic_monitor(tor, existing=True)
    with tunnel_monitor:
        testutils.send(ptfadapter, int(ptf_t1_intf.strip("eth")), pkt, count=10)

    logging.info("send traffic to server %s after removing neighbor entry", server_ipv4)
    tunnel_monitor.existing = False
    server_traffic_monitor = ServerTrafficMonitor(
        tor, ptfhost, vmhost, tbinfo, test_params["selected_port"],
        conn_graph_facts, exp_pkt, existing=False, is_mocked=is_mocked_dualtor(tbinfo)
    )
    # for real dualtor testbed, leave the neighbor restoration to garp service
    flush_neighbor_ct = flush_neighbor(tor, server_ipv4, restore=is_t0_mocked_dualtor)
    with crm_neighbor_checker(tor), stop_garp(ptfhost), flush_neighbor_ct, tunnel_monitor, server_traffic_monitor:
        testutils.send(ptfadapter, int(ptf_t1_intf.strip("eth")), pkt, count=10)

    logging.info("send traffic to server %s after neighbor entry is restored", server_ipv4)
    tunnel_monitor.existing = True
    with crm_neighbor_checker(tor), tunnel_monitor:
        testutils.send(ptfadapter, int(ptf_t1_intf.strip("eth")), pkt, count=10)


def test_downstream_standby_mux_toggle_active(
    conn_graph_facts, ptfadapter, ptfhost,
    rand_selected_dut, rand_unselected_dut, tbinfo,
    require_mocked_dualtor, tunnel_traffic_monitor,
    vmhost, toggle_all_simulator_ports, tor_mux_intfs
    ):
    # set rand_selected_dut as standby and rand_unselected_dut to active tor
    test_params = dualtor_info(ptfhost, rand_selected_dut, rand_unselected_dut, tbinfo)
    server_ipv4 = test_params["target_server_ip"]
    random_dst_ip = "1.1.1.2"
    pkt, exp_pkt = build_packet_to_server(rand_selected_dut, ptfadapter, random_dst_ip)
    ptf_t1_intf = random.choice(get_t1_ptf_ports(rand_selected_dut, tbinfo))

    def monitor_tunnel_and_server_traffic(torhost, expect_tunnel_traffic=True, expect_server_traffic=True):
        tunnel_monitor = tunnel_traffic_monitor(rand_selected_dut, existing=True)
        server_traffic_monitor = ServerTrafficMonitor(
            torhost, ptfhost, vmhost, tbinfo, test_params["selected_port"],
            conn_graph_facts, exp_pkt, existing=False, is_mocked=is_mocked_dualtor(tbinfo)
        )
        tunnel_monitor.existing = expect_tunnel_traffic
        server_traffic_monitor.existing = expect_server_traffic
        with tunnel_monitor, server_traffic_monitor:
            testutils.send(ptfadapter, int(ptf_t1_intf.strip("eth")), pkt, count=10)

    logger.info("Stage 1: Verify Standby Forwarding")
    logger.info("Step 1.1: Add route to a nexthop which is a standby Neighbor")
    set_mux_state(rand_selected_dut, tbinfo, 'standby', tor_mux_intfs, toggle_all_simulator_ports)
    add_nexthop_routes(rand_selected_dut, random_dst_ip, nexthops=[server_ipv4])
    logger.info("Step 1.2: Verify traffic to this route dst is forwarded to Active ToR and equally distributed")
    check_tunnel_balance(**test_params)
    monitor_tunnel_and_server_traffic(rand_selected_dut, expect_server_traffic=False, expect_tunnel_traffic=True)

    logger.info("Stage 2: Verify Active Forwarding")
    logger.info("Step 2.1: Simulate Mux state change to active")
    set_mux_state(rand_selected_dut, tbinfo, 'active', tor_mux_intfs, toggle_all_simulator_ports)
    logger.info("Step 2.2: Verify traffic to this route dst is forwarded directly to server")
    monitor_tunnel_and_server_traffic(rand_selected_dut, expect_server_traffic=True, expect_tunnel_traffic=False)

    logger.info("Stage 3: Verify Standby Forwarding Again")
    logger.info("Step 3.1: Simulate Mux state change to standby")
    set_mux_state(rand_selected_dut, tbinfo, 'standby', tor_mux_intfs, toggle_all_simulator_ports)
    logger.info("Step 3.2: Verify traffic to this route dst is now redirected back to Active ToR and equally distributed")
    monitor_tunnel_and_server_traffic(rand_selected_dut, expect_server_traffic=False, expect_tunnel_traffic=True)
    check_tunnel_balance(**test_params)

    remove_static_routes(rand_selected_dut, random_dst_ip)
