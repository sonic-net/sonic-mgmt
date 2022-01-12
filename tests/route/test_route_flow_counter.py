import logging
import pytest
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.flow_counter import flow_counter_utils

logger = logging.getLogger(__name__)


@pytest.fixture(scope='function', autouse=True)
def skip_if_not_supported(rand_selected_dut):
    """Skip the test if route flow counter is not supported on this platform

    Args:
        rand_selected_dut (object): DUT object
    """
    pytest_require(flow_counter_utils.is_route_flow_counter_supported(rand_selected_dut))


class TestRouteCounter:
    @pytest.mark.parametrize("route_flow_counter_params", [(False, '1.1.0.0/16', '1.1.1.0/24'),
                                                           (True, '1234::/64', '1234::/64')])
    def test_add_remove_route(self, rand_selected_dut, route_flow_counter_params):
        """Test steps:
           1. Add route and verify the route flow counter is created.
           2. Remove route and verify the route flow counter is removed.

        Args:
            rand_selected_dut (object): DUT object
            route_flow_counter_params (list): A list contains the test parameter. [ipv6, route_pattern, prefix]
        """
        duthost = rand_selected_dut
        ipv6 = route_flow_counter_params[0]
        route_pattern = route_flow_counter_params[1]
        prefix = route_flow_counter_params[2]
        flow_counter_utils.set_route_flow_counter_status(duthost, True)
        flow_counter_utils.set_route_flow_counter_pattern(duthost, route_pattern)
        nexthop_addr = self._get_nexthop(duthost, ipv6=ipv6)

        logger.info('Adding static route {} {}, check route flow counter is created'.format(prefix, nexthop_addr))
        duthost.shell("sonic-db-cli CONFIG_DB hmset 'STATIC_ROUTE|{}' nexthop {}".format(prefix, nexthop_addr))
        stats = flow_counter_utils.parse_route_flow_counter_stats(duthost)
        pytest_assert(prefix in stats, 'Route flow counter is not created')

        logger.info('Removing static route {} {}, check route flow counter is removed'.format(prefix, nexthop_addr))
        duthost.shell("sonic-db-cli CONFIG_DB del 'STATIC_ROUTE|{}'".format(prefix), module_ignore_errors=True)
        stats = flow_counter_utils.parse_route_flow_counter_stats(duthost)
        pytest_assert(prefix not in stats, 'Route flow counter is not removed')

        flow_counter_utils.set_route_flow_counter_status(duthost, False)
        flow_counter_utils.remove_route_flow_counter_pattern(duthost, route_pattern)

    @pytest.mark.parametrize("route_flow_counter_params", [(False, '1.1.0.0/16', '1.2.0.0/16', '1.1.1.0/24', '1.2.1.0/24'),
                                                           (True, '1234:0:0:1::/64', '1234:0:0:2::/64', '1234:0:0:1::/64', '1234:0:0:2::/64')])
    def test_update_route_pattern(self, rand_selected_dut, route_flow_counter_params):
        """Test steps:
            1. Add two routes a and b, configure route pattern match a
            2. Verify only route flow counter for a is created
            3. Update route pattern to match b
            4. Verify only route flow counter for b is created

        Args:
            rand_selected_dut (object): DUT object
            route_flow_counter_params (list): A list contains the test parameter. [ipv6, pattern_a, pattern_b, prefix_a, prefix_b]
        """
        duthost = rand_selected_dut
        ipv6 = route_flow_counter_params[0]
        route_pattern_a =  route_flow_counter_params[1]
        route_pattern_b =  route_flow_counter_params[2]
        prefix_a =  route_flow_counter_params[3]
        prefix_b =  route_flow_counter_params[4]
        flow_counter_utils.set_route_flow_counter_status(duthost, True)
        flow_counter_utils.set_route_flow_counter_pattern(duthost, route_pattern_a)
        nexthop_addr = self._get_nexthop(duthost, ipv6=ipv6)

        logger.info('Adding static route {} and {}'.format(prefix_a, prefix_b))
        duthost.shell("sonic-db-cli CONFIG_DB hmset 'STATIC_ROUTE|{}' nexthop {}".format(prefix_a, nexthop_addr))
        duthost.shell("sonic-db-cli CONFIG_DB hmset 'STATIC_ROUTE|{}' nexthop {}".format(prefix_b, nexthop_addr))

        stats = flow_counter_utils.parse_route_flow_counter_stats(duthost)
        pytest_assert(prefix_a in stats, 'Route flow counter for {} is not created'.format(prefix_a))
        pytest_assert(prefix_b not in stats, 'Route flow counter for {} should not be created'.format(prefix_b))


        flow_counter_utils.set_route_flow_counter_pattern(duthost, route_pattern_b)
        stats = flow_counter_utils.parse_route_flow_counter_stats(duthost)
        pytest_assert(prefix_a not in stats, 'Route flow counter for {} is not removed'.format(prefix_a))
        pytest_assert(prefix_b in stats, 'Route flow counter for {} is not created'.format(prefix_b))

        duthost.shell("sonic-db-cli CONFIG_DB del 'STATIC_ROUTE|{}'".format(prefix_a), module_ignore_errors=True)
        duthost.shell("sonic-db-cli CONFIG_DB del 'STATIC_ROUTE|{}'".format(prefix_b), module_ignore_errors=True)

        flow_counter_utils.set_route_flow_counter_status(duthost, False)
        flow_counter_utils.remove_route_flow_counter_pattern(duthost, route_pattern_b)

    def test_max_match_count(self, rand_selected_dut):
        """Test steps:
            1. Add 3 routes, set max allowed match to 2, verify only 2 route flow counters are created
            2. Remove 1 routes, verify that there are still 2 route flow counters as it should automatically fill the room
            3. Set max_allowed_match to 1, verify that there is 1 route flow counter
            4. Set max_allowed match to 2 again, verify that there are two route flow counter as it should automatically fill the room

        Args:
            rand_selected_dut ([type]): [description]
        """
        duthost = rand_selected_dut
        route_pattern = '1.1.0.0/16'
        prefix_list = ['1.1.1.0/24', '1.1.2.0/24', '1.1.3.0/24']
        nexthop_addr = self._get_nexthop(duthost, False)
        flow_counter_utils.set_route_flow_counter_status(duthost, True)
        expect_route_flow_counter = len(prefix_list) - 1
        flow_counter_utils.set_route_flow_counter_pattern(duthost, route_pattern, max_match_count=expect_route_flow_counter)
        logger.info('Adding {} static routes while max allowed match count is {}'.format(len(prefix_list), expect_route_flow_counter))
        for prefix in prefix_list:
            duthost.shell("sonic-db-cli CONFIG_DB hmset 'STATIC_ROUTE|{}' nexthop {}".format(prefix, nexthop_addr))

        logger.info('Verify there are {} route flow counters'.format(expect_route_flow_counter))
        stats = flow_counter_utils.parse_route_flow_counter_stats(duthost)

        pytest_assert(len(stats) == expect_route_flow_counter, 'Expecetd {} route flow counters, but got {} counters'.format(expect_route_flow_counter, len(stats)))

        logger.info('Removing a route, verify there are still {} route flow counters'.format(expect_route_flow_counter))
        duthost.shell("sonic-db-cli CONFIG_DB del 'STATIC_ROUTE|{}'".format(prefix_list[0]), module_ignore_errors=True)
        stats = flow_counter_utils.parse_route_flow_counter_stats(duthost)
        pytest_assert(len(stats) == expect_route_flow_counter, 'Max allowed match counter is {}, but got {} counters'.format(expect_route_flow_counter, len(stats)))

        expect_route_flow_counter -= 1
        logger.info('Set max_match_count to {}, verify there is {} route flow counters'.format(expect_route_flow_counter, expect_route_flow_counter))
        flow_counter_utils.set_route_flow_counter_pattern(duthost, route_pattern, max_match_count=expect_route_flow_counter)
        stats = flow_counter_utils.parse_route_flow_counter_stats(duthost)
        pytest_assert(len(stats) == expect_route_flow_counter, 'Max allowed match counter is {}, but got {} counters'.format(expect_route_flow_counter, len(stats)))

        expect_route_flow_counter += 1
        logger.info('Set max_match_count to {}, verify there is {} route flow counters'.format(expect_route_flow_counter, expect_route_flow_counter))
        flow_counter_utils.set_route_flow_counter_pattern(duthost, route_pattern, max_match_count=expect_route_flow_counter)
        stats = flow_counter_utils.parse_route_flow_counter_stats(duthost)
        pytest_assert(len(stats) == expect_route_flow_counter, 'Max allowed match counter is {}, but got {} counters'.format(expect_route_flow_counter, len(stats)))

        for prefix in prefix_list:
            duthost.shell("sonic-db-cli CONFIG_DB del 'STATIC_ROUTE|{}'".format(prefix), module_ignore_errors=True)
        flow_counter_utils.set_route_flow_counter_status(duthost, False)
        flow_counter_utils.remove_route_flow_counter_pattern(duthost, route_pattern)

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
        return parse_result[0]['neighbhor']
