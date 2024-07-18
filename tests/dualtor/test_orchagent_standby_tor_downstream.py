import pytest
import random
import time
import logging
import ipaddress
import contextlib

from ptf import testutils
from tests.common.dualtor.dual_tor_mock import *        # noqa F403
from tests.common.dualtor.dual_tor_mock import set_mux_state, is_t0_mocked_dualtor, is_mocked_dualtor
from tests.common.dualtor.dual_tor_utils import dualtor_info
from tests.common.dualtor.dual_tor_utils import check_tunnel_balance
from tests.common.dualtor.dual_tor_utils import flush_neighbor
from tests.common.dualtor.dual_tor_utils import get_t1_ptf_ports
from tests.common.dualtor.dual_tor_utils import build_packet_to_server
from tests.common.dualtor.dual_tor_utils import crm_neighbor_checker
from tests.common.dualtor.dual_tor_utils import add_nexthop_routes, remove_static_routes
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory             # noqa: F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses                # noqa: F401
from tests.common.fixtures.ptfhost_utils import run_garp_service                    # noqa: F401
from tests.common.fixtures.ptfhost_utils import run_icmp_responder                  # noqa: F401
# from tests.common.fixtures.ptfhost_utils import skip_traffic_test                   # noqa F401
# Temporary work around to add skip_traffic_test fixture from duthost_utils
from tests.common.fixtures.duthost_utils import skip_traffic_test                   # noqa F401
from tests.common.helpers.assertions import pytest_assert as pt_assert
from tests.common.dualtor.tunnel_traffic_utils import tunnel_traffic_monitor        # noqa: F401
from tests.common.dualtor.server_traffic_utils import ServerTrafficMonitor
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports   # noqa: F401
from tests.common.dualtor.tor_failure_utils import shutdown_bgp_sessions            # noqa: F401
from tests.common.utilities import wait_until


pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.usefixtures('apply_mock_dual_tor_tables',
                            'apply_mock_dual_tor_kernel_configs',
                            'apply_standby_state_to_orchagent',
                            'run_garp_service',
                            'run_icmp_responder',
                            'run_arp_responder_ipv6'
                            )
]

logger = logging.getLogger(__file__)


@pytest.fixture(params=['ipv4', 'ipv6'])
def ip_version(request):
    """Traffic IP version to test."""
    return request.param


@pytest.fixture
def setup_testbed_ipv6(ip_version, request):
    """Setup the testbed for ipv6 traffic test."""
    if ip_version == "ipv6":
        request.getfixturevalue("run_arp_responder_ipv6")


@pytest.fixture(scope='module')
def get_function_completeness_level(pytestconfig):
    return pytestconfig.getoption("--completeness_level")


@pytest.fixture
def get_testbed_params(ptfhost, rand_selected_dut, rand_unselected_dut, tbinfo,
                       ip_version, setup_testbed_ipv6, get_function_completeness_level, skip_traffic_test): # noqa F811
    """Return a function to get testbed params."""
    def _get_testbed_params():
        params = dualtor_info(ptfhost, rand_selected_dut, rand_unselected_dut,
                              tbinfo, get_function_completeness_level)
        params["check_ipv6"] = (ip_version == "ipv6")
        params["skip_traffic_test"] = skip_traffic_test
        return params

    return _get_testbed_params


def shutdown_random_one_t1_link(dut):
    """
    Shutdown a random t1 link
    """
    port_channels = list(dut.get_running_config_facts()['PORTCHANNEL'].keys())
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
    for k, v in list(bgp_facts.items()):
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


def test_standby_tor_downstream(rand_selected_dut, get_testbed_params):
    """
    Verify tunnel traffic to active ToR is distributed equally across nexthops, and
    no traffic is forwarded to server from standby ToR
    """
    params = get_testbed_params()
    check_tunnel_balance(**params)


def test_standby_tor_downstream_t1_link_recovered(
    rand_selected_dut, verify_crm_nexthop_counter_not_increased,
    tbinfo, get_testbed_params
):
    """
    Verify traffic is distributed evenly after t1 link is recovered;
    Verify CRM that no new nexthop created
    """
    PAUSE_TIME = 30

    down_link = shutdown_random_one_t1_link(rand_selected_dut)
    time.sleep(PAUSE_TIME)
    params = get_testbed_params()
    try:
        check_tunnel_balance(**params)
    except Exception as e:
        no_shutdown_t1_link(rand_selected_dut, down_link)
        raise e

    no_shutdown_t1_link(rand_selected_dut, down_link)
    time.sleep(PAUSE_TIME)
    params = get_testbed_params()
    # For mocked dualtor, we should update static route manually after link recovered
    if 't0' in tbinfo['topo']['name']:
        remove_static_routes(rand_selected_dut, params['active_tor_ip'])
        add_nexthop_routes(rand_selected_dut, params['active_tor_ip'])
    check_tunnel_balance(**params)


def test_standby_tor_downstream_bgp_recovered(
    rand_selected_dut, verify_crm_nexthop_counter_not_increased,
    get_testbed_params, tbinfo
):
    """
    Verify traffic is shifted to the active links and no traffic drop observed;
    Verify traffic is distributed evenly after BGP session is recovered;
    Verify CRM that no new nexthop created
    """
    PAUSE_TIME = 30

    down_bgp = shutdown_random_one_bgp_session(rand_selected_dut)
    time.sleep(PAUSE_TIME)
    params = get_testbed_params()
    try:
        check_tunnel_balance(**params)
    except Exception as e:
        startup_bgp_session(rand_selected_dut, down_bgp)
        raise e

    startup_bgp_session(rand_selected_dut, down_bgp)
    time.sleep(PAUSE_TIME)
    params = get_testbed_params()
    check_tunnel_balance(**params)


def route_matches_expected_state(duthost, route_ip, expect_route):
    get_route_cmd = "ip route | grep -w {}".format(route_ip)
    rc = int(duthost.shell(get_route_cmd, module_ignore_errors=True)['rc'])
    return rc == 0 if expect_route else 1


@pytest.fixture
def remove_peer_loopback_route(rand_selected_dut, rand_unselected_dut,
                               shutdown_bgp_sessions, get_testbed_params):      # noqa F811
    """
    Remove routes to peer ToR loopback IP by shutting down BGP sessions on the peer
    """

    def _remove_peer_loopback_route():
        if rand_unselected_dut is None:
            # mocked testbed, remove the static route installed by
            # apply_dual_tor_peer_switch_route from kernel
            remove_static_routes(rand_selected_dut, active_tor_loopback0)
        else:
            shutdown_bgp_sessions(rand_unselected_dut)
            # We need to maintain the expected active/standby state for the test
            rand_unselected_dut.shell("config mux mode active all")

    active_tor_loopback0 = get_testbed_params()['active_tor_ip']

    yield _remove_peer_loopback_route

    if rand_unselected_dut is None:
        # mocked testbed, need to add back the static route to kernel
        add_nexthop_routes(rand_selected_dut, active_tor_loopback0)
    else:
        # The `shutdown_bgp_sessions` fixture already restores BGP sessions during teardown so we
        # don't need to do it here
        rand_unselected_dut.shell("config mux mode auto all")


def test_standby_tor_downstream_loopback_route_readded(
    rand_selected_dut, rand_unselected_dut, get_testbed_params,
    tbinfo, remove_peer_loopback_route
):
    """
    Verify traffic is equally distributed via loopback route
    """
    params = get_testbed_params()
    active_tor_loopback0 = params['active_tor_ip']

    remove_peer_loopback_route()
    pt_assert(
        wait_until(
            10, 1, 0,
            lambda: route_matches_expected_state(rand_selected_dut, active_tor_loopback0, expect_route=False)),
        "Unexpected route {} found on {}".format(active_tor_loopback0, rand_selected_dut)
    )
    # Verify traffic is equally distributed
    check_tunnel_balance(**params)

    # Readd loopback routes and verify traffic is equally distributed
    if rand_unselected_dut is None:
        # mocked testbed, need to add back the static route to kernel
        add_nexthop_routes(rand_selected_dut, active_tor_loopback0)
    else:
        rand_unselected_dut.shell("config bgp start all")
    pt_assert(
        wait_until(
            10, 1, 0,
            lambda: route_matches_expected_state(rand_selected_dut, active_tor_loopback0, expect_route=True)),
        "Expected route {} not found on {}".format(active_tor_loopback0, rand_selected_dut)
    )
    check_tunnel_balance(**params)


def test_standby_tor_remove_neighbor_downstream_standby(
    conn_graph_facts, ptfadapter, ptfhost,
    rand_selected_dut, rand_unselected_dut, tbinfo,
    set_crm_polling_interval, tunnel_traffic_monitor,   # noqa: F811
    vmhost, get_testbed_params,
    ip_version, skip_traffic_test                       # noqa: F811
):
    """
    @summary: Verify that after removing neighbor entry for a server over standby
    ToR, the packets sent to the server will be dropped(neither passed to the server
    or redirected to the active ToR).
    """

    @contextlib.contextmanager
    def stop_neighbor_advertiser(ptfhost, ip_version):
        """Temporarily stop garp_service or arp_responder."""
        if ip_version == "ipv4":
            ptfhost.shell("supervisorctl stop garp_service")
        else:
            ptfhost.shell("supervisorctl stop arp_responder", module_ignore_errors=True)
        yield
        if ip_version == "ipv4":
            ptfhost.shell("supervisorctl start garp_service")
        else:
            ptfhost.shell("supervisorctl start arp_responder")

    tor = rand_selected_dut
    test_params = get_testbed_params()
    if ip_version == "ipv4":
        target_server = test_params["target_server_ip"]
    else:
        target_server = test_params["target_server_ipv6"]

    pkt, exp_pkt = build_packet_to_server(tor, ptfadapter, target_server)
    ptf_t1_intf = random.choice(get_t1_ptf_ports(tor, tbinfo))
    logging.info("send traffic to server %s from ptf t1 interface %s", target_server, ptf_t1_intf)
    tunnel_monitor = tunnel_traffic_monitor(tor, existing=True, skip_traffic_test=skip_traffic_test)
    with tunnel_monitor:
        testutils.send(ptfadapter, int(ptf_t1_intf.strip("eth")), pkt, count=10)

    logging.info("send traffic to server %s after removing neighbor entry", target_server)
    tunnel_monitor.existing = False
    server_traffic_monitor = ServerTrafficMonitor(
        tor, ptfhost, vmhost, tbinfo, test_params["selected_port"], conn_graph_facts, exp_pkt,
        existing=False, is_mocked=is_mocked_dualtor(tbinfo), skip_traffic_test=skip_traffic_test
    )
    # for real dualtor testbed, leave the neighbor restoration to garp service
    flush_neighbor_ct = flush_neighbor(tor, target_server, restore=is_t0_mocked_dualtor)
    with crm_neighbor_checker(tor), stop_neighbor_advertiser(ptfhost, ip_version), \
            flush_neighbor_ct, tunnel_monitor, server_traffic_monitor:
        testutils.send(ptfadapter, int(ptf_t1_intf.strip("eth")), pkt, count=10)

    logging.info("send traffic to server %s after neighbor entry is restored", target_server)
    tunnel_monitor.existing = True
    with crm_neighbor_checker(tor), tunnel_monitor:
        testutils.send(ptfadapter, int(ptf_t1_intf.strip("eth")), pkt, count=10)


def test_downstream_standby_mux_toggle_active(
    conn_graph_facts, ptfadapter, ptfhost,
    rand_selected_dut, rand_unselected_dut, tbinfo,
    tunnel_traffic_monitor, vmhost,                         # noqa: F811
    toggle_all_simulator_ports, tor_mux_intfs,              # noqa: F811
    ip_version, get_testbed_params, skip_traffic_test       # noqa: F811
):
    # set rand_selected_dut as standby and rand_unselected_dut to active tor
    test_params = get_testbed_params()
    if ip_version == "ipv4":
        target_server = test_params["target_server_ip"]
        random_dst_ip = "1.1.1.2"
    else:
        target_server = test_params["target_server_ipv6"]
        random_dst_ip = "20D0:FFFF:01:01::FFFF"

    pkt, exp_pkt = build_packet_to_server(rand_selected_dut, ptfadapter, random_dst_ip)
    ptf_t1_intf = random.choice(get_t1_ptf_ports(rand_selected_dut, tbinfo))

    def monitor_tunnel_and_server_traffic(torhost, expect_tunnel_traffic=True,
                                          expect_server_traffic=True, skip_traffic_test=False):
        if skip_traffic_test is True:
            return
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
    add_nexthop_routes(rand_selected_dut, random_dst_ip, nexthops=[target_server])
    time.sleep(30)
    logger.info("Step 1.2: Verify traffic to this route dst is forwarded to Active ToR and equally distributed")
    check_tunnel_balance(**test_params)
    monitor_tunnel_and_server_traffic(rand_selected_dut, expect_server_traffic=False,
                                      expect_tunnel_traffic=True, skip_traffic_test=skip_traffic_test)

    logger.info("Stage 2: Verify Active Forwarding")
    logger.info("Step 2.1: Simulate Mux state change to active")
    set_mux_state(rand_selected_dut, tbinfo, 'active', tor_mux_intfs, toggle_all_simulator_ports)
    time.sleep(30)
    logger.info("Step 2.2: Verify traffic to this route dst is forwarded directly to server")
    monitor_tunnel_and_server_traffic(rand_selected_dut, expect_server_traffic=True,
                                      expect_tunnel_traffic=False, skip_traffic_test=skip_traffic_test)

    logger.info("Stage 3: Verify Standby Forwarding Again")
    logger.info("Step 3.1: Simulate Mux state change to standby")
    set_mux_state(rand_selected_dut, tbinfo, 'standby', tor_mux_intfs, toggle_all_simulator_ports)
    time.sleep(30)
    logger.info("Step 3.2: Verify traffic to this route dst \
                is now redirected back to Active ToR and equally distributed")
    monitor_tunnel_and_server_traffic(rand_selected_dut, expect_server_traffic=False,
                                      expect_tunnel_traffic=True, skip_traffic_test=skip_traffic_test)
    check_tunnel_balance(**test_params)

    remove_static_routes(rand_selected_dut, random_dst_ip)
