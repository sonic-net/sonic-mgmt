import logging
import random
import ipaddress
import pytest
import ptf.testutils as testutils
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.flow_counter import flow_counter_utils
from tests.common.flow_counter.flow_counter_utils import is_route_flow_counter_supported   # noqa F401
from tests.common.utilities import wait_until, get_neighbor_ptf_port_list
from tests.common.helpers.constants import UPSTREAM_NEIGHBOR_MAP

logger = logging.getLogger(__name__)
allure.logger = logger

pytestmark = [
    pytest.mark.topology("any")
]

TRAFFIC_COUNT = 10
FLOW_COUNTER_INTERVAL = 1000


def send_traffic_to_prefix(duthost, ptfadapter, tbinfo, prefix, ipv6=False, count=TRAFFIC_COUNT):
    """Send traffic matching the given route prefix through the DUT.

    Args:
        duthost: DUT host object
        ptfadapter: PTF adapter
        tbinfo: Testbed info
        prefix: Route prefix (e.g. '1.1.1.0/24')
        ipv6: True for IPv6 traffic
        count: Number of packets to send
    """
    # prefix.split('|') is needed due to bug in `parse_route_flow_counter_stats` - to create github issue
    ip_dst = str(ipaddress.ip_network(prefix.split('|')[-1])[1])
    router_mac = duthost.facts["router_mac"]
    src_mac = ptfadapter.dataplane.get_mac(*list(ptfadapter.dataplane.ports.keys())[0])

    if ipv6:
        pkt = testutils.simple_tcpv6_packet(
            eth_dst=router_mac,
            eth_src=src_mac,
            ipv6_dst=ip_dst,
            ipv6_src='2001:db8:85a3::8a2e:370:7334',
            ipv6_hlim=64,
            tcp_sport=1234,
            tcp_dport=4321)
    else:
        pkt = testutils.simple_tcp_packet(
            eth_dst=router_mac,
            eth_src=src_mac,
            ip_dst=ip_dst,
            ip_src='10.255.255.1',
            ip_ttl=64,
            tcp_sport=1234,
            tcp_dport=4321)

    topo_type = tbinfo["topo"]["type"]
    upstream_name = UPSTREAM_NEIGHBOR_MAP[topo_type]
    ptf_port_list = get_neighbor_ptf_port_list(duthost, upstream_name, tbinfo)
    ptf_intf = random.choice(ptf_port_list)
    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, ptf_intf, pkt, count=count)


def get_packet_count(duthost, prefix):
    """Get the current packet count for a route flow counter prefix.

    Args:
        duthost: DUT host object
        prefix: Route prefix to check

    Returns:
        int: Packet count for the prefix

    Raises:
        AssertionError: If prefix is not found in route flow counter stats
    """
    stats = flow_counter_utils.parse_route_flow_counter_stats(duthost)
    pytest_assert(prefix in stats, 'Expected route flow counter for {}, not found in stats: {}'.format(prefix, stats))
    return int(stats[prefix]['packets'].replace(',', ''))


def verify_counter_incremented_by_traffic(duthost, ptfadapter, tbinfo, prefix, ipv6=False):
    """Send traffic to a prefix and assert the route flow counter increments.

    Captures the packet count before and after sending traffic, asserts
    that the counter increased, and logs the delta.

    Args:
        duthost: DUT host object
        ptfadapter: PTF adapter
        tbinfo: Testbed info
        prefix: Route prefix (may include VRF prefix from stats, e.g. 'Vrf1|1.1.1.0/24')
        ipv6: True for IPv6 traffic
    """
    # Neighbor name needed to map PTF port list for sending traffic
    pytest_assert(tbinfo["topo"]["type"] in UPSTREAM_NEIGHBOR_MAP,
                  "Neighbor name is needed to map PTF port list for sending traffic. "
                  "No known upstream neighbor for topo '{}'".format(tbinfo["topo"]["type"]))
    count_before = get_packet_count(duthost, prefix)
    logger.info('Packet count before traffic for %s: %d', prefix, count_before)
    send_traffic_to_prefix(duthost, ptfadapter, tbinfo, prefix, ipv6=ipv6)
    # Ensure the counter increments after sending traffic.
    pytest_assert(wait_until(10, 1, 0, lambda: get_packet_count(duthost, prefix) > count_before),
                  'Packet counter for {} did not increment after sending traffic'.format(prefix))
    count_after = get_packet_count(duthost, prefix)
    logger.info('Packet count after traffic for %s: %d (delta: %d)',
                prefix, count_after, count_after - count_before)


test_update_route_pattern_para = [
    {
        'is_ipv6': False,
        'route_pattern_a': '1.1.0.0/16',
        'route_pattern_b': '1.2.0.0/16',
        'prefix_a': '1.1.1.0/24',
        'prefix_b': '1.2.1.0/24',
    },
    {
        'is_ipv6': True,
        'route_pattern_a': '1234:0:0:1::/64',
        'route_pattern_b': '1234:0:0:2::/64',
        'prefix_a': '1234:0:0:1::/64',
        'prefix_b': '1234:0:0:2::/64',
    }
]

added_routes = set()


@pytest.fixture(scope='function', autouse=True)
def skip_if_not_supported(is_route_flow_counter_supported):     # noqa F811
    """Skip the test if route flow counter is not supported on this platform

    Args:
        is_route_flow_counter_supported: fixture
    """
    pytest_require(is_route_flow_counter_supported,
                   'route flow counter is not supported')


@pytest.fixture(scope='function', autouse=True)
def clear_route_flow_counter_config(rand_selected_dut, skip_if_not_supported):
    """Clear route flow counter configuration

    Args:
        rand_selected_dut (object): DUT object
    """
    yield

    flow_counter_utils.set_route_flow_counter_status(rand_selected_dut, False)
    flow_counter_utils.remove_all_route_flow_counter_patterns(
        rand_selected_dut)
    for route in added_routes:
        rand_selected_dut.shell('config route del prefix {} nexthop {}'.format(
            route[0], route[1]), module_ignore_errors=True)
    added_routes.clear()


def add_route(duthost, prefix, nexthop):
    """Add static route

    Args:
        duthost (object): DUT object
        prefix (str): Route prefix
        nexthop (str): Route nexthop
    """
    duthost.shell(
        'config route add prefix {} nexthop {}'.format(prefix, nexthop))
    added_routes.add((prefix, nexthop))


def del_route(duthost, prefix, nexthop):
    """Remove static route

    Args:
        duthost (object): DUT object
        prefix (str): Route prefix
        nexthop (str): Route nexthop
    """
    duthost.shell('config route del prefix {} nexthop {}'.format(
        prefix, nexthop), module_ignore_errors=True)
    added_routes.remove((prefix, nexthop))


class TestRouteCounter:
    @pytest.mark.parametrize("route_flow_counter_params", test_update_route_pattern_para)
    def test_update_route_pattern(self, rand_selected_dut, ptfadapter, tbinfo, route_flow_counter_params):
        """Test steps:
            1. Add two routes a and b, configure route pattern match a
            2. Verify only route flow counter for a is created
            3. Send traffic to a and verify packet/byte counters increment
            4. Update route pattern to match b
            5. Verify only route flow counter for b is created
            6. Send traffic to b and verify packet/byte counters increment

        Args:
            rand_selected_dut (object): DUT object
            ptfadapter: PTF adapter for sending traffic
            tbinfo: Testbed info
            route_flow_counter_params (list): A list contains the test parameter.
            [ipv6, pattern_a, pattern_b, prefix_a, prefix_b]
        """
        def _check_route_flow_counter_state(dut, prefix, exist=True):
            stats = flow_counter_utils.parse_route_flow_counter_stats(dut)
            return exist == (prefix in stats)
        duthost = rand_selected_dut
        ipv6 = route_flow_counter_params['is_ipv6']
        route_pattern_a = route_flow_counter_params['route_pattern_a']
        route_pattern_b = route_flow_counter_params['route_pattern_b']
        prefix_a = route_flow_counter_params['prefix_a']
        prefix_b = route_flow_counter_params['prefix_b']
        with allure.step('Enable route flow counter and config route pattern to {}'.format(route_pattern_a)):
            flow_counter_utils.set_route_flow_counter_status(duthost, True)
            # Set polling interval to 1s so counters update quickly for traffic verification
            flow_counter_utils.set_route_flow_counter_interval(duthost, FLOW_COUNTER_INTERVAL)
            flow_counter_utils.set_route_flow_counter_pattern(
                duthost, route_pattern_a)

        with allure.step('Adding static route {} and {}'.format(prefix_a, prefix_b)):
            nexthop_addr = self._get_nexthop(duthost, ipv6=ipv6)
            add_route(rand_selected_dut, prefix_a, nexthop_addr)
            add_route(rand_selected_dut, prefix_b, nexthop_addr)

        with allure.step('Route pattern is {}, verify route flow counter is bound to {}'.format(
                route_pattern_a, prefix_a)):
            pytest_assert(wait_until(5, 1, 0, _check_route_flow_counter_state, duthost, prefix_a, True),
                          'Route flow counter for {} is not created'.format(prefix_a))
            pytest_assert(wait_until(5, 1, 0, _check_route_flow_counter_state, duthost, prefix_b, False),
                          'Route flow counter for {} should not be created'.format(prefix_b))

        with allure.step('Send traffic to {} and verify counters increment'.format(prefix_a)):
            verify_counter_incremented_by_traffic(duthost, ptfadapter, tbinfo, prefix_a, ipv6=ipv6)

        with allure.step('Change route flow pattern to {}, verify route flow counter is bound to {}'.format(
                route_pattern_b, prefix_b)):
            flow_counter_utils.set_route_flow_counter_pattern(
                duthost, route_pattern_b)
            pytest_assert(wait_until(5, 1, 0, _check_route_flow_counter_state, duthost, prefix_a, False),
                          'Route flow counter for {} is not removed'.format(prefix_a))
            pytest_assert(wait_until(5, 1, 0, _check_route_flow_counter_state, duthost, prefix_b, True),
                          'Route flow counter for {} is not created'.format(prefix_b))

        with allure.step('Send traffic to {} and verify counters increment'.format(prefix_b)):
            verify_counter_incremented_by_traffic(duthost, ptfadapter, tbinfo, prefix_b, ipv6=ipv6)

    def test_max_match_count(self, rand_selected_dut, ptfadapter, tbinfo):
        """Test steps:
            1. Add 3 routes, set max allowed match to 2, verify only 2 route flow counters are created
            2. Send traffic to matched routes and verify packet/byte counters increment
            3. Remove 1 route, verify there are still 2 route flow counters
               as it should automatically fill the room. Verify counters increment with traffic.
            4. Set max_allowed_match to 1, verify there is 1 route flow counter.
               Verify counter increments with traffic.
            5. Set max_allowed_match to 2 again, verify there are 2 route flow counters
               as it should automatically fill the room. Verify counters increment with traffic.

        Args:
            rand_selected_dut (object): DUT object
            ptfadapter: PTF adapter for sending traffic
            tbinfo: Testbed info
        """
        def _check_route_flow_counter_number(dut, expected_number):
            stats = flow_counter_utils.parse_route_flow_counter_stats(dut)
            return expected_number == len(stats)

        def _verify_active_counters_incremented_by_traffic():
            """Send traffic to all currently matched prefixes and verify counters increment."""
            stats = flow_counter_utils.parse_route_flow_counter_stats(duthost)
            for prefix in stats.keys():
                verify_counter_incremented_by_traffic(duthost, ptfadapter, tbinfo, prefix)

        duthost = rand_selected_dut
        route_pattern = '1.1.0.0/16'
        prefix_list = ['1.1.1.0/24', '1.1.2.0/24', '1.1.3.0/24']
        expect_route_flow_counter = len(prefix_list) - 1
        nexthop_addr = self._get_nexthop(duthost, False)

        with allure.step('Enable route flow counter and config route pattern to {} with max allowed {}'.format(
                route_pattern, expect_route_flow_counter)):
            flow_counter_utils.set_route_flow_counter_status(duthost, True)
            # Set polling interval to 1s so counters update quickly for traffic verification
            flow_counter_utils.set_route_flow_counter_interval(duthost, 1000)
            flow_counter_utils.set_route_flow_counter_pattern(
                duthost, route_pattern, max_match_count=expect_route_flow_counter)

        with allure.step('Adding {} static routes while max allowed match count is {}'.format(
                len(prefix_list), expect_route_flow_counter)):
            for prefix in prefix_list:
                add_route(rand_selected_dut, prefix, nexthop_addr)

        with allure.step('Verify there are {} route flow counters'.format(expect_route_flow_counter)):
            pytest_assert(
                wait_until(5, 1, 0, _check_route_flow_counter_number, duthost, expect_route_flow_counter),
                'Expected {} route flow counters, but the actual is different'.format(expect_route_flow_counter))

        with allure.step('Send traffic to matched routes and verify counters increment'):
            _verify_active_counters_incremented_by_traffic()

        with allure.step(
                'Removing a route, verify there are still {} route flow counters'.format(expect_route_flow_counter)):
            del_route(rand_selected_dut, prefix_list[0], nexthop_addr)
            pytest_assert(
                wait_until(5, 1, 0, _check_route_flow_counter_number, duthost, expect_route_flow_counter),
                'Expected {} route flow counters, but the actual is different'.format(expect_route_flow_counter))

        with allure.step('Verify counters still work after route removal'):
            _verify_active_counters_incremented_by_traffic()

        expect_route_flow_counter -= 1
        with allure.step('Set max_match_count to {}, verify there are {} route flow counters'.format(
                expect_route_flow_counter, expect_route_flow_counter)):
            flow_counter_utils.set_route_flow_counter_pattern(
                duthost, route_pattern, max_match_count=expect_route_flow_counter)
            pytest_assert(
                wait_until(5, 1, 0, _check_route_flow_counter_number, duthost, expect_route_flow_counter),
                'Expected {} route flow counters, but the actual is different'.format(expect_route_flow_counter))

        with allure.step('Verify counters work after reducing max_match_count'):
            _verify_active_counters_incremented_by_traffic()

        expect_route_flow_counter += 1
        with allure.step('Set max_match_count to {}, verify there are {} route flow counters'.format(
                expect_route_flow_counter, expect_route_flow_counter)):
            flow_counter_utils.set_route_flow_counter_pattern(
                duthost, route_pattern, max_match_count=expect_route_flow_counter)
            pytest_assert(
                wait_until(5, 1, 0, _check_route_flow_counter_number, duthost, expect_route_flow_counter),
                'Expected {} route flow counters, but the actual is different'.format(expect_route_flow_counter))

        with allure.step('Verify counters work after increasing max_match_count'):
            _verify_active_counters_incremented_by_traffic()

    def _get_nexthop(self, duthost, ipv6):
        """Get next hop from BGP neighbors

        Args:
            duthost (object): DUT object
            ipv6 (bool): True if getting IPv6 nexthop

        Returns:
            str: Nexthop IP
        """
        if ipv6:
            cmd = 'show ipv6 bgp summary'
        else:
            cmd = 'show ip bgp summary'
        parse_result = duthost.show_and_parse(cmd)
        if 'neighbor' in parse_result[0]:
            return parse_result[0]['neighbor']
        else:
            return parse_result[0]['neighbhor']
