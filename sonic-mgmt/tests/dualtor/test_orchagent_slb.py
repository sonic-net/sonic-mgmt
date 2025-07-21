import ipaddress
import logging
import os.path
import pytest
import random
import time
import scapy.all as scapyall

from ptf import testutils

from tests.common.dualtor.dual_tor_utils import build_packet_to_server
from tests.common.dualtor.dual_tor_utils import upper_tor_host                                      # noqa: F401
from tests.common.dualtor.dual_tor_utils import lower_tor_host                                      # noqa: F401
from tests.common.dualtor.dual_tor_utils import get_t1_ptf_ports
from tests.common.dualtor.dual_tor_utils import force_active_tor                                    # noqa: F401
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_upper_tor      # noqa: F401
from tests.common.dualtor.dual_tor_common import cable_type                                         # noqa: F401
from tests.common.dualtor.server_traffic_utils import ServerTrafficMonitor
from tests.common.dualtor.tunnel_traffic_utils import tunnel_traffic_monitor                        # noqa: F401
from tests.common.fixtures.ptfhost_utils import run_icmp_responder                                  # noqa: F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses                                # noqa: F401
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until


pytestmark = [
    pytest.mark.topology("dualtor")
]

ANNOUNCED_SUBNET_IPV4 = "10.10.100.0/27"
ANNOUNCED_SUBNET_IPV6 = "fc00:10::/64"


@pytest.fixture(scope="module", autouse=True)
def save_slb_exabgp_logfiles(ptfhost, pytestconfig, request):
    """Save slb exabgp log files to the log directory."""
    # remove log files before test
    log_files_before = ptfhost.shell("ls /tmp/exabgp-slb_*.log*",
                                     module_ignore_errors=True)["stdout"].split()
    for log_file in log_files_before:
        ptfhost.file(path=log_file, state="absent")

    yield

    test_log_file = pytestconfig.getoption("log_file", None)
    if test_log_file:
        log_dir = os.path.dirname(os.path.abspath(test_log_file))
        log_files = ptfhost.shell("ls /tmp/exabgp-slb_*.log*",
                                  module_ignore_errors=True)["stdout"].split()
        for log_file in log_files:
            logging.debug("Save slb exabgp log %s to %s", log_file, log_dir)
            ptfhost.fetch(src=log_file, dest=log_dir + os.path.sep, fail_on_missing=False, flat=True)
    else:
        logging.info("Skip saving slb exabgp log files to log directory as log directory not set.")


@pytest.fixture(params=['ipv4', 'ipv6'])
def ip_version(request):
    """Traffic IP version to test."""
    return request.param


@pytest.fixture(autouse=True)
def testbed_setup(ip_version, request):
    """Setup the testbed."""
    if ip_version == "ipv6":
        request.getfixturevalue("run_arp_responder_ipv6")


@pytest.fixture
def constants(setup_interfaces, ip_version):
    class _C(object):
        """Dummy class to save test constants."""
        pass

    connections = setup_interfaces
    assert connections["upper_tor"]["neighbor_addr"] == connections["lower_tor"]["neighbor_addr"], (
        "Mismatch in server neighbor IP addresses between upper and lower ToR.\n"
        "- Upper ToR neighbor_addr: {}\n"
        "- Lower ToR neighbor_addr: {}"
    ).format(connections["upper_tor"]["neighbor_addr"], connections["lower_tor"]["neighbor_addr"])

    assert connections["upper_tor"]["neighbor_addr_ipv6"] == connections["lower_tor"]["neighbor_addr_ipv6"], (
        "Mismatch in server neighbor IPv6 addresses between upper and lower ToR.\n"
        "- Upper ToR neighbor_addr_ipv6: {}\n"
        "- Lower ToR neighbor_addr_ipv6: {}"
    ).format(connections["upper_tor"]["neighbor_addr_ipv6"], connections["lower_tor"]["neighbor_addr_ipv6"])

    _constants = _C()
    if ip_version == "ipv4":
        nexthop = connections["upper_tor"]["neighbor_addr"].split("/")[0]
        _constants.route = dict(prefix=ANNOUNCED_SUBNET_IPV4, nexthop=nexthop)
    elif ip_version == "ipv6":
        nexthop = connections["upper_tor"]["neighbor_addr_ipv6"].split("/")[0]
        _constants.route = dict(prefix=ANNOUNCED_SUBNET_IPV6, nexthop=nexthop)
    else:
        raise ValueError("Unrecognized IP version %s" % ip_version)

    _constants.bgp_establish_sleep_interval = 30
    _constants.bgp_update_sleep_interval = 10
    _constants.mux_state_change_sleep_interval = 5
    _constants.ip_version = ip_version
    return _constants


@pytest.mark.parametrize("test_device_interface", ["Loopback3"], indirect=True)
def test_orchagent_slb(
    bgp_neighbors, constants, conn_graph_facts,
    force_active_tor, upper_tor_host, lower_tor_host,       # noqa: F811
    ptfadapter, ptfhost, setup_interfaces,
    toggle_all_simulator_ports_to_upper_tor, tbinfo,        # noqa: F811
    tunnel_traffic_monitor, vmhost                          # noqa: F811
):

    def verify_bgp_session(duthost, bgp_neighbor):
        """Verify the bgp session to the DUT is established."""
        bgp_facts = duthost.bgp_facts()["ansible_facts"]
        assert bgp_neighbor.ip in bgp_facts["bgp_neighbors"], (
            "BGP neighbor IP '{}' not found in DUT's BGP neighbor list."
        ).format(bgp_neighbor.ip)

        assert bgp_facts["bgp_neighbors"][bgp_neighbor.ip]["state"] == "established", (
            "BGP session state is not 'established' for neighbor '{}'. Got: '{}'."
        ).format(
            bgp_neighbor.ip,
            bgp_facts["bgp_neighbors"][bgp_neighbor.ip]["state"]
        )

    def verify_route(duthost, route, existing=True):
        """Verify the route's existence in the DUT."""
        prefix = ipaddress.ip_network(route["prefix"])
        existing_route = duthost.get_ip_route_info(dstip=prefix)
        if existing:
            return route["nexthop"] in [str(_[0]) for _ in existing_route["nexthops"]]
        else:
            return len(existing_route["nexthops"]) == 0

    def verify_traffic(duthost, connection, route, is_duthost_active=True, is_route_existed=True):

        prefix = ipaddress.ip_network(route["prefix"])
        dst_host = str(next(prefix.hosts()))
        pkt, exp_pkt = build_packet_to_server(duthost, ptfadapter, dst_host)
        ptf_t1_intf = random.choice(get_t1_ptf_ports(duthost, tbinfo))
        ptf_t1_intf_index = int(ptf_t1_intf.strip("eth"))
        is_tunnel_traffic_existed = is_route_existed and not is_duthost_active
        is_server_traffic_existed = is_route_existed and is_duthost_active

        if isinstance(prefix, ipaddress.IPv4Network):
            tunnel_innner_pkt = pkt[scapyall.IP].copy()
            tunnel_innner_pkt[scapyall.IP].ttl -= 1
        else:
            tunnel_innner_pkt = pkt[scapyall.IPv6].copy()
            tunnel_innner_pkt[scapyall.IPv6].hlim -= 1
        tunnel_monitor = tunnel_traffic_monitor(
            duthost,
            existing=is_tunnel_traffic_existed,
            inner_packet=tunnel_innner_pkt,
            check_items=["ttl", "queue"]
        )
        server_traffic_monitor = ServerTrafficMonitor(
            duthost, ptfhost, vmhost, tbinfo, connection["test_intf"],
            conn_graph_facts, exp_pkt, existing=is_server_traffic_existed
        )
        with tunnel_monitor, server_traffic_monitor:
            testutils.send(ptfadapter, ptf_t1_intf_index, pkt, count=10)
            time.sleep(5)

    connections = setup_interfaces

    upper_tor_bgp_neighbor = bgp_neighbors["upper_tor"]
    lower_tor_bgp_neighbor = bgp_neighbors["lower_tor"]

    try:
        # STEP 1: create peer sessions with both ToRs
        lower_tor_bgp_neighbor.start_session()
        upper_tor_bgp_neighbor.start_session()

        time.sleep(constants.bgp_establish_sleep_interval)

        verify_bgp_session(upper_tor_host, upper_tor_bgp_neighbor)
        verify_bgp_session(lower_tor_host, lower_tor_bgp_neighbor)

        # STEP 2: announce a route to both ToRs
        upper_tor_bgp_neighbor.announce_route(constants.route)
        lower_tor_bgp_neighbor.announce_route(constants.route)

        time.sleep(constants.bgp_update_sleep_interval)

        pytest_assert(
            verify_route(upper_tor_host, constants.route, existing=True),
            (
                "Route is not present on the upper ToR. "
                "Expected route: {}. "
                "Upper ToR host: {}"
            ).format(
                constants.route,
                upper_tor_host
            )
        )
        pytest_assert(
            verify_route(lower_tor_host, constants.route, existing=True),
            (
                "Route is not present on the lower ToR. "
                "Expected route: {}. "
                "Lower ToR host: {}. "
            ).format(
                constants.route,
                lower_tor_host,
            )
        )

        # STEP 3: verify the route by sending some downstream traffic
        verify_traffic(
            upper_tor_host, connections["upper_tor"], constants.route,
            is_duthost_active=True, is_route_existed=True
        )
        verify_traffic(
            lower_tor_host, connections["lower_tor"], constants.route,
            is_duthost_active=False, is_route_existed=True
        )

        # STEP 4: withdraw the announced route to both ToRs
        upper_tor_bgp_neighbor.withdraw_route(constants.route)
        lower_tor_bgp_neighbor.withdraw_route(constants.route)

        time.sleep(constants.bgp_update_sleep_interval)

        pytest_assert(
            wait_until(10, 5, 0, verify_route, upper_tor_host, constants.route, existing=False),
            (
                "Route is not withdrawn from the upper ToR. "
                "Expected route to be withdrawn. "
                "Upper ToR host: {}. "
                "Route: {}"
            ).format(
                upper_tor_host,
                constants.route
            )
        )
        pytest_assert(
            wait_until(10, 5, 0, verify_route, lower_tor_host, constants.route, existing=False),
            (
                "Route is not withdrawn from the lower ToR. "
                "Expected route to be withdrawn. "
                "Lower ToR host: {}. "
                "Route: {}"
            ).format(
                lower_tor_host,
                constants.route
            )
        )

        # STEP 5: verify the route is removed by verifying that downstream traffic is dropped
        verify_traffic(
            upper_tor_host, connections["upper_tor"], constants.route,
            is_duthost_active=True, is_route_existed=False
        )
        verify_traffic(
            lower_tor_host, connections["lower_tor"], constants.route,
            is_duthost_active=False, is_route_existed=False
        )

        # STEP 6: toggle mux state change
        force_active_tor(lower_tor_host, 'all')

        time.sleep(constants.mux_state_change_sleep_interval)

        verify_bgp_session(upper_tor_host, upper_tor_bgp_neighbor)
        verify_bgp_session(lower_tor_host, lower_tor_bgp_neighbor)

        # STEP 7: announce the route to both ToRs after mux state change
        upper_tor_bgp_neighbor.announce_route(constants.route)
        lower_tor_bgp_neighbor.announce_route(constants.route)

        time.sleep(constants.bgp_update_sleep_interval)

        pytest_assert(
            verify_route(upper_tor_host, constants.route, existing=True),
            (
                "Route is not present on the upper ToR. "
                "Expected route to exist. "
                "Upper ToR host: {}. "
                "Route: {}"
            ).format(
                upper_tor_host,
                constants.route
            )
        )
        pytest_assert(
            verify_route(lower_tor_host, constants.route, existing=True),
            (
                "Route is not present on the lower ToR. "
                "Expected route to exist. "
                "Lower ToR host: {}. "
                "Route: {}"
            ).format(
                lower_tor_host,
                constants.route
            )
        )
        # STEP 8: verify the route by sending some downstream traffic
        verify_traffic(
            upper_tor_host, connections["upper_tor"], constants.route,
            is_duthost_active=False, is_route_existed=True
        )
        verify_traffic(
            lower_tor_host, connections["lower_tor"], constants.route,
            is_duthost_active=True, is_route_existed=True
        )

        # STEP 9: verify teardown
        upper_tor_bgp_neighbor.stop_session()

        verify_bgp_session(lower_tor_host, lower_tor_bgp_neighbor)
        pytest_assert(
            verify_route(lower_tor_host, constants.route, existing=True),
            (
                "Route is not present on the lower ToR. "
                "Expected route to exist. "
                "Lower ToR host: {}. "
                "Route: {}"
            ).format(
                lower_tor_host,
                constants.route
            )
        )

        lower_tor_bgp_neighbor.stop_session()

    finally:
        upper_tor_bgp_neighbor.stop_session()
        lower_tor_bgp_neighbor.stop_session()
        upper_tor_host.shell("ip route flush %s" % constants.route["prefix"])
        lower_tor_host.shell("ip route flush %s" % constants.route["prefix"])
