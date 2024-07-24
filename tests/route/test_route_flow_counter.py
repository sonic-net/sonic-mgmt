import logging
import pytest
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.flow_counter import flow_counter_utils
from tests.flow_counter.flow_counter_utils import is_route_flow_counter_supported   # noqa F401
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)
allure.logger = logger

pytestmark = [
    pytest.mark.topology("any"),
    pytest.mark.device_type('physical')
]

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
def clear_route_flow_counter(rand_selected_dut, skip_if_not_supported):
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
    def test_update_route_pattern(self, rand_selected_dut, route_flow_counter_params):
        """Test steps:
            1. Add two routes a and b, configure route pattern match a
            2. Verify only route flow counter for a is created
            3. Update route pattern to match b
            4. Verify only route flow counter for b is created

        Args:
            rand_selected_dut (object): DUT object
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

        with allure.step('Change route flow pattern to {}, verify route flow counter is bound to {}'.format(
                route_pattern_b, prefix_b)):
            flow_counter_utils.set_route_flow_counter_pattern(
                duthost, route_pattern_b)
            pytest_assert(wait_until(5, 1, 0, _check_route_flow_counter_state, duthost, prefix_a, False),
                          'Route flow counter for {} is not removed'.format(prefix_a))
            pytest_assert(wait_until(5, 1, 0, _check_route_flow_counter_state, duthost, prefix_b, True),
                          'Route flow counter for {} is not created'.format(prefix_b))

    def test_max_match_count(self, rand_selected_dut):
        """Test steps:
            1. Add 3 routes, set max allowed match to 2, verify only 2 route flow counters are created
            2. Remove 1 routes, verify that
               there are still 2 route flow counters as it should automatically fill the room
            3. Set max_allowed_match to 1, verify that there is 1 route flow counter
            4. Set max_allowed match to 2 again, verify that
               there are two route flow counter as it should automatically fill the room

        Args:
            rand_selected_dut (object): DUT object
        """
        def _check_route_flow_counter_number(dut, expected_number):
            stats = flow_counter_utils.parse_route_flow_counter_stats(dut)
            return expected_number == len(stats)
        duthost = rand_selected_dut
        route_pattern = '1.1.0.0/16'
        prefix_list = ['1.1.1.0/24', '1.1.2.0/24', '1.1.3.0/24']
        expect_route_flow_counter = len(prefix_list) - 1
        nexthop_addr = self._get_nexthop(duthost, False)

        with allure.step('Enable route flow counter and config route pattern to {} with max allowed {}'.format(
                route_pattern, expect_route_flow_counter)):
            flow_counter_utils.set_route_flow_counter_status(duthost, True)
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

        with allure.step(
                'Removing a route, verify there are still {} route flow counters'.format(expect_route_flow_counter)):
            del_route(rand_selected_dut, prefix_list[0], nexthop_addr)
            pytest_assert(
                wait_until(5, 1, 0, _check_route_flow_counter_number, duthost, expect_route_flow_counter),
                'Expected {} route flow counters, but the actual is different'.format(expect_route_flow_counter))

        expect_route_flow_counter -= 1
        with allure.step('Set max_match_count to {}, verify there are {} route flow counters'.format(
                expect_route_flow_counter, expect_route_flow_counter)):
            flow_counter_utils.set_route_flow_counter_pattern(
                duthost, route_pattern, max_match_count=expect_route_flow_counter)
            pytest_assert(
                wait_until(5, 1, 0, _check_route_flow_counter_number, duthost, expect_route_flow_counter),
                'Expected {} route flow counters, but the actual is different'.format(expect_route_flow_counter))

        expect_route_flow_counter += 1
        with allure.step('Set max_match_count to {}, verify there are {} route flow counters'.format(
                expect_route_flow_counter, expect_route_flow_counter)):
            flow_counter_utils.set_route_flow_counter_pattern(
                duthost, route_pattern, max_match_count=expect_route_flow_counter)
            pytest_assert(
                wait_until(5, 1, 0, _check_route_flow_counter_number, duthost, expect_route_flow_counter),
                'Expected {} route flow counters, but the actual is different'.format(expect_route_flow_counter))

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
