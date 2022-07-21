import allure
import logging
import pytest
import random
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until, check_skip_release

logger = logging.getLogger(__name__)

skip_versions = ['201811', '201911', '202012', '202106', '202111']
CAPABILITY_WAIT_TIME_IN_SEC = 180
CAPABILITY_CHECK_INTERVAL_IN_SEC = 5


class RouteFlowCounterTestContext:
    """Allow caller to use "with" key words to run router flow counter test.
    """
    def __init__(self, support, dut, route_pattern_list, expected_stats, interval=1000):
        """Init RouteFlowCounterTestContext

        Args:
            dut (object): DUT object
            route_pattern_list (list): a list of route pattern, e.g. ['1.1.1.0/24', 'Vrf1|1.1.1.0/24', 'Vnet1|2.2.2.0/24']
            expected_stats (dict): Expected result value. e.g. {'1.1.1.0/24': {'packets': '5', 'bytes': '4500'}}
            interval (int, optional): Route flow counter query interval. Defaults to 1000.
        """
        self.dut = dut
        self.route_pattern_list = route_pattern_list
        self.expected_stats = expected_stats
        self.interval = interval
        self.is_route_flow_counter_supported = support

    def __enter__(self):
        """Enable route flow counter and configure route pattern
        """
        if not self.is_route_flow_counter_supported:
            return
        with allure.step('Enable route flow counter and config route flow pattern: {}'.format(','.join(self.route_pattern_list))):
            set_route_flow_counter_interval(self.dut, self.interval)
            set_route_flow_counter_status(self.dut, True)
            for route_pattern in self.route_pattern_list:
                set_route_flow_counter_pattern(self.dut, route_pattern)

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Do following tasks:
            1. Verify route flow counter stats agaist expected value
            2. Disable route flow coutern and remove route pattern

        Args:
            exc_type (object): not used
            exc_val (object): not used
            exc_tb (object): not used
        """
        if not self.is_route_flow_counter_supported:
            return

        try:
            result, message = self.check_stats()
            pytest_assert(result, message)
        finally:
            set_route_flow_counter_status(self.dut, False)
            for route_pattern in self.route_pattern_list:
                remove_route_flow_counter_pattern(self.dut, route_pattern)


    def check_stats(self):
        """Verify route flow counter statistic

        Returns:
            tuple: (status, error message)
        """
        logger.info('Checking route flow counter stats')
        with allure.step('Checking route flow counter stats'):
            actual_stats = parse_route_flow_counter_stats(self.dut)
            result, message = verify_route_flow_counter_stats(self.expected_stats, actual_stats)
            if not result:
                return result, message

        if len(self.expected_stats) > 0:
            logger.info('Checking route flow counter stats after clearing by route')
            with allure.step('Checking route flow counter stats after clearing by route'):
                to_clear = random.sample(list(self.expected_stats.keys()), 1)[0]
                clear_route_flow_counter_by_route(self.dut, to_clear)
                for key in self.expected_stats[to_clear]:
                    self.expected_stats[to_clear][key] = '0'
                actual_stats = parse_route_flow_counter_stats(self.dut)
                result, message = verify_route_flow_counter_stats(self.expected_stats, actual_stats)
                if not result:
                    return result, message

        with allure.step('Checking route flow counter stats after clearing by pattern or clearing all'):
            if len(self.expected_stats) == 1 and len(self.route_pattern_list) == 1:
                logger.info('Checking route flow counter stats after clearing by pattern')
                clear_route_flow_counter_by_pattern(self.dut, self.route_pattern_list[0])
            else:
                logger.info('Checking route flow counter stats after clearing all routes')
                clear_route_flow_counter(self.dut)
            for prefix, value in self.expected_stats.items():
                for key in value:
                    self.expected_stats[prefix][key] = '0'

            actual_stats = parse_route_flow_counter_stats(self.dut)
            return verify_route_flow_counter_stats(self.expected_stats, actual_stats)


@pytest.fixture(scope = "module")
def is_route_flow_counter_supported(duthosts, enum_rand_one_per_hwsku_hostname):
    """Check if route flow counter is supported on this platform

    Args:
        dut (object): DUT object

    Returns:
        bool: True if supported
    """
    rand_selected_dut = duthosts[enum_rand_one_per_hwsku_hostname]
    if rand_selected_dut.facts['asic_type'] == 'vs':
        # vs platform always set SAI capability to enabled, however, it does not really support all SAI atrributes.
        # Currently, vs platform does not support route flow counter.
        return False
    skip, _ = check_skip_release(rand_selected_dut, skip_versions)
    if skip:
        logger.info('Route flow counter is not supported on these versions: {}'.format(skip_versions))
        return False

    route_flow_counter_capability = [] # Use a list to store the capability
    if not wait_until(CAPABILITY_WAIT_TIME_IN_SEC, CAPABILITY_CHECK_INTERVAL_IN_SEC, 0, get_route_flow_counter_capability, rand_selected_dut, route_flow_counter_capability):
        pytest_assert(False, 'Failed to get route flow counter capability')
    if not route_flow_counter_capability[0]:
        logger.info('Route flow counter is not supported on this platform')
    return route_flow_counter_capability[0]


def get_route_flow_counter_capability(dut, route_flow_counter_capability):
    """Get route flow counter capability from STATE DB

    Args:
        dut (object): DUT object

    Returns:
        bool: True if capability is successfully retrieved from STATE DB
    """
    support = dut.shell('sudo sonic-db-cli STATE_DB HGET "FLOW_COUNTER_CAPABILITY_TABLE|route" support')['stdout'].strip()
    if support == 'true':
        route_flow_counter_capability.append(True)
    elif support == 'false':
        route_flow_counter_capability.append(False)
    elif support:
        # Impossible branch, just incase
        pytest_assert(False, 'support field of FLOW_COUNTER_CAPABILITY_TABLE|route has invalid value {}'.format(support))
    return len(route_flow_counter_capability) > 0


def set_route_flow_counter_status(dut, status):
    """Set route flow counter status

    Args:
        dut (object): DUT object
        status (bool): Enable if True else disable
    """
    dut.command('counterpoll flowcnt-route {}'.format('enable' if status else 'disable'))


def set_route_flow_counter_interval(dut, interval):
    """Set route flow counter interval

    Args:
        dut (object): DUT object
        interval (int): Query interval value in ms
    """
    dut.command('counterpoll flowcnt-route interval {}'.format(interval))


def set_route_flow_counter_pattern(dut, route_pattern, max_match_count=30):
    """Set route pattern for route flow counter

    Args:
        dut (object): DUT object
        route_pattern (str): Route pattern. e.g. "1.1.1.0/24", "2000::/64", "Vrf1|2.2.2.0/24"
        max_match_count (int, optional): Max allowed match count. Defaults to 30.
    """
    items = route_pattern.split('|')
    if len(items) == 2:
        dut.command('sudo config flowcnt-route pattern add {} --vrf {} --max {} -y'.format(items[1], items[0], max_match_count))
    elif len(items) == 1:
        dut.command('sudo config flowcnt-route pattern add {} --max {} -y'.format(items[0], max_match_count))
    else:
        logger.error('Invalid route pattern {}'.format(route_pattern))


def remove_route_flow_counter_pattern(dut, route_pattern):
    """Remove route pattern for route flow counter

    Args:
        dut (object): DUT object
        route_pattern (str): Route pattern. e.g. "1.1.1.0/24", "2000::/64", "Vrf1|2.2.2.0/24"
    """
    items = route_pattern.split('|')
    if len(items) == 2:
        dut.command('sudo config flowcnt-route pattern remove {} --vrf {}'.format(items[1], items[0]))
    elif len(items) == 1:
        dut.command('sudo config flowcnt-route pattern remove {}'.format(items[0]))
    else:
        logger.error('Invalid route pattern {}'.format(route_pattern))

def remove_all_route_flow_counter_patterns(dut):
    """Remove all route patterns

    Args:
        dut (object): DUT object
    """
    data = dut.show_and_parse('show flowcnt-route config')
    for item in data:
        prefix = item['route pattern']
        vrf = item['vrf']
        if vrf != 'default':
            dut.command('sudo config flowcnt-route pattern remove {} --vrf {}'.format(prefix, vrf))
        else:
            dut.command('sudo config flowcnt-route pattern remove {}'.format(prefix))


def clear_route_flow_counter(dut):
    """Clear all route flow counter statistics

    Args:
        dut (object): DUT object
    """
    dut.command('sonic-clear flowcnt-route')


def clear_route_flow_counter_by_pattern(dut, route_pattern):
    """Clear route flow counter statistics by pattern

    Args:
        dut (object): DUT object
        route_pattern (str): Route pattern. e.g. "1.1.1.0/24", "2000::/64", "Vrf1|2.2.2.0/24"
    """
    items = route_pattern.split('|')
    if len(items) == 2:
        dut.command('sonic-clear flowcnt-route pattern {} --vrf {}'.format(items[1], items[0]))
    elif len(items) == 1:
        dut.command('sonic-clear flowcnt-route pattern {}'.format(items[0]))
    else:
        logger.error('Invalid route pattern {}'.format(route_pattern))


def clear_route_flow_counter_by_route(dut, prefix):
    """Clear route flow counter statistics by route

    Args:
        dut (object): DUT object
        prefix (str): Prefix pattern. e.g. "1.1.1.0/24", "2000::/64", "Vrf1|2.2.2.0/24"
    """
    items = prefix.split('|')
    if len(items) == 2:
        dut.command('sonic-clear flowcnt-route route {} --vrf {}'.format(items[1], items[0]))
    elif len(items) == 1:
        dut.command('sonic-clear flowcnt-route route {}'.format(items[0]))
    else:
        logger.error('Invalid prefix pattern {}'.format(prefix))


def parse_route_flow_counter_stats(dut):
    """Parse command output of "show flowcnt-route stats"

    Args:
        dut (object): DUT object

    Returns:
        dict: Parsed result. e.g. {'1.1.1.0/24': {'packets': '5', 'bytes': '4500'}}
    """
    stats_list = dut.show_and_parse('show flowcnt-route stats')
    parse_result = {}
    for stats in stats_list:
        if stats['vrf'] == 'default':
            key = stats['matched routes']
        else:
            key = '|'.join([stats['vrf'], stats['matched routes']])
        parse_result[key] = {
            'packets': stats['packets'],
            'bytes': stats['bytes']
        }
    return parse_result


def verify_route_flow_counter_stats(expect_stats, actual_stats):
    """Verify actual statistic with expected statistic

    Args:
        expect_stats (dict): Expected stats. e.g. {'1.1.1.0/24': {'packets': '5', 'bytes': '4500'}}
        actual_stats (dict): Actual stats. e.g. {'1.1.1.0/24': {'packets': '5', 'bytes': '4500'}}

    Returns:
        bool: Match if True.
    """
    logger.info('Expected stats: {}'.format(expect_stats))
    logger.info('Actual stats: {}'.format(actual_stats))
    for key, value in expect_stats.items():
        if key not in actual_stats:
            return False, 'Failed to find {} in result'.format(key)

        for stats_type, expect_value in value.items():
            if int(expect_value) != int(actual_stats[key][stats_type].replace(',', '')):
                return False, 'Expected {} value of {} is {}, but got {}'.format(stats_type, key, expect_value, actual_stats[key][stats_type])

    return True, None
