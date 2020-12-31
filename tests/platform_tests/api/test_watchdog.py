import os
import re
import time
import logging
import yaml
import pytest
from tests.common.helpers.platform_api import watchdog
from tests.common.helpers.assertions import pytest_assert
from platform_api_test_base import PlatformApiTestBase

from collections import OrderedDict

def ordered_load(stream, Loader=yaml.Loader, object_pairs_hook=OrderedDict):
    class OrderedLoader(Loader):
        pass
    def construct_mapping(loader, node):
        loader.flatten_mapping(node)
        return object_pairs_hook(loader.construct_pairs(node))
    OrderedLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
        construct_mapping)
    return yaml.load(stream, OrderedLoader)

pytestmark = [
    pytest.mark.disable_loganalyzer,  # disable automatic loganalyzer
    pytest.mark.topology('any')
]

logger = logging.getLogger(__name__)

TEST_CONFIG_FILE = os.path.join(os.path.split(__file__)[0], "watchdog.yml")
TEST_WAIT_TIME_SECONDS = 2
TIMEOUT_DEVIATION = 2


class TestWatchdogApi(PlatformApiTestBase):
    ''' Hardware watchdog platform API test cases '''

    @pytest.fixture(scope='function', autouse=True)
    def watchdog_not_running(self, platform_api_conn):
        ''' Fixture that automatically runs on each test case and
        verifies that watchdog is not running before the test begins
        and disables it after the test ends'''

        assert not watchdog.is_armed(platform_api_conn)

        try:
            yield
        finally:
            watchdog.disarm(platform_api_conn)

    @pytest.fixture(scope='module')
    def conf(self, request, duthost):
        ''' Reads the watchdog test configuration file @TEST_CONFIG_FILE and
        results in a dictionary which holds parameters for test '''

        test_config = None
        with open(TEST_CONFIG_FILE) as stream:
            test_config = ordered_load(stream)

        config = test_config['default']

        platform = duthost.facts['platform']
        hwsku = duthost.facts['hwsku']

        # override test config with platform/hwsku specific configs
        for platform_regexp in test_config:
            if re.match(platform_regexp, platform):
                config.update(test_config[platform_regexp].get('default', {}))
                for hwsku_regexp in test_config[platform_regexp]:
                    if re.match(hwsku_regexp, hwsku):
                        config.update(test_config[platform_regexp][hwsku_regexp])

        pytest_assert('valid_timeout' in config, "valid_timeout is not defined in config")
        # make sure watchdog won't reboot the system when test sleeps for @TEST_WAIT_TIME_SECONDS
        pytest_assert(config['valid_timeout'] > TEST_WAIT_TIME_SECONDS * 2, "valid_timeout {} seconds is too short".format(config['valid_timeout']))

        logger.info('Test configuration for platform: {} hwksu: {}: {}'.format(platform, hwsku, config))
        return config

    @pytest.mark.dependency()
    def test_arm_disarm_states(self, duthost, localhost, platform_api_conn, conf):
        ''' arm watchdog with a valid timeout value, verify it is in armed state,
        disarm watchdog and verify it is in disarmed state
        '''
        watchdog_timeout = conf['valid_timeout']
        actual_timeout = watchdog.arm(platform_api_conn, watchdog_timeout)

        if self.expect(actual_timeout is not None, "Watchdog.arm is not supported"):
            if self.expect(isinstance(actual_timeout, int), "actual_timeout appears incorrect"):
                if self.expect(actual_timeout != -1, "Failed to arm the watchdog"):
                    self.expect(actual_timeout >= watchdog_timeout, "Actual watchdog timeout {} seconds appears wrong, should be equal or greater than {} seconds".format(actual_timeout, watchdog_timeout))

        watchdog_status = watchdog.is_armed(platform_api_conn)
        if self.expect(watchdog_status is not None, "Failed to retrieve watchdog status"):
            self.expect(watchdog_status is True, "Watchdog is not armed.")

        remaining_time = watchdog.get_remaining_time(platform_api_conn)

        if self.expect(remaining_time is not None, "Failed to get the remaining time of watchdog"):
            if self.expect(isinstance(remaining_time, int), "remaining_time appears incorrect"):
                self.expect(remaining_time <= actual_timeout, "Watchdog remaining_time {} seconds appears wrong compared to watchdog timeout {} seocnds".format(remaining_time, actual_timeout))

        watchdog_status = watchdog.disarm(platform_api_conn)
        if self.expect(watchdog_status is not None, "Watchdog.disarm is not supported"):
            self.expect(watchdog_status is True, "Failed to disarm the watchdog")

        watchdog_status = watchdog.is_armed(platform_api_conn)
        if self.expect(watchdog_status is not None, "Failed to check the watchdog status"):
            self.expect(watchdog_status is False, "Watchdog is not disarmed")

        remaining_time = watchdog.get_remaining_time(platform_api_conn)
        if self.expect(remaining_time is not None, "Failed to get the remaining time of watchdog"):
            self.expect(remaining_time is -1, "Watchdog remaining_time {} seconds is wrong for disarmed state".format(remaining_time))

        res = localhost.wait_for(host=duthost.mgmt_ip, port=22, state="stopped", delay=5, timeout=watchdog_timeout + TIMEOUT_DEVIATION, module_ignore_errors=True)

        self.expect('Timeout' in res.get('msg', ''), "unexpected disconnection from dut")
        self.assert_expectations()

    @pytest.mark.dependency(depends=["test_arm_disarm_states"])
    def test_remaining_time(self, duthost, platform_api_conn, conf):
        ''' arm watchdog with a valid timeout and verify that remaining time API works correctly '''

        watchdog_timeout = conf['valid_timeout']

        # in the begginging of the test watchdog is not armed, so
        # get_remaining_time has to return -1
        remaining_time = watchdog.get_remaining_time(platform_api_conn)
        if self.expect(remaining_time is not None and remaining_time is -1, "watchdog should be disabled in the initial state"):
            actual_timeout = watchdog.arm(platform_api_conn, watchdog_timeout)
            remaining_time = watchdog.get_remaining_time(platform_api_conn)

            if self.expect(actual_timeout >= watchdog_timeout, "watchdog arm with {} seconds failed".format(watchdog_timeout)):
                if self.expect(remaining_time > 0, "Remaining_time {} seconds is not valid".format(remaining_time)):
                    self.expect(remaining_time <= actual_timeout, "Remaining_time {} seconds should be less than watchdog armed timeout {} seconds".format(remaining_time, actual_timeout))

        remaining_time = watchdog.get_remaining_time(platform_api_conn)
        time.sleep(TEST_WAIT_TIME_SECONDS)
        remaining_time_new = watchdog.get_remaining_time(platform_api_conn)
        self.expect(remaining_time_new < remaining_time, "Remaining_time {} seconds should be decreased from previous remaining_time {} seconds".format(remaining_time_new, remaining_time))
        self.assert_expectations()

    @pytest.mark.dependency(depends=["test_arm_disarm_states"])
    def test_periodic_arm(self, duthost, platform_api_conn, conf):
        ''' arm watchdog several times as watchdog deamon would and verify API behaves correctly '''

        watchdog_timeout = conf['valid_timeout']
        actual_timeout = watchdog.arm(platform_api_conn, watchdog_timeout)
        time.sleep(TEST_WAIT_TIME_SECONDS)
        remaining_time = watchdog.get_remaining_time(platform_api_conn)
        actual_timeout_new = watchdog.arm(platform_api_conn, watchdog_timeout)
        remaining_time_new = watchdog.get_remaining_time(platform_api_conn)

        self.expect(actual_timeout == actual_timeout_new, "{}: new watchdog timeout {} seconds setting should be same as the previous actual watchdog timeout {} seconds".format(self.test_periodic_arm.__name__, actual_timeout_new, actual_timeout))
        self.expect(remaining_time_new > remaining_time, "{}: new remaining timeout {} seconds should be greater than the previous remaining timeout {} seconds by {} seconds".format(self.test_periodic_arm.__name__, remaining_time_new, remaining_time, TEST_WAIT_TIME_SECONDS))
        self.assert_expectations()

    @pytest.mark.dependency(depends=["test_arm_disarm_states"])
    def test_arm_different_timeout_greater(self, duthost, platform_api_conn, conf):
        ''' arm the watchdog with greater timeout value and verify new timeout was accepted;
        If platform accepts only single valid timeout value, @greater_timeout should be None.
        '''

        watchdog_timeout = conf['valid_timeout']
        watchdog_timeout_greater = conf['greater_timeout']
        if watchdog_timeout_greater is None:
            pytest.skip('"greater_timeout" parameter is required for this test case')
        actual_timeout = watchdog.arm(platform_api_conn, watchdog_timeout)
        remaining_time = watchdog.get_remaining_time(platform_api_conn)
        actual_timeout_greater = watchdog.arm(platform_api_conn, watchdog_timeout_greater)
        self.expect(actual_timeout < actual_timeout_greater, "{}: 1st timeout {} seconds should be less than 2nd timeout {} seconds".format(self.test_arm_different_timeout_greater.__name__, actual_timeout, actual_timeout_greater))
        remaining_time_greater = watchdog.get_remaining_time(platform_api_conn)
        self.expect(remaining_time_greater > remaining_time, "{}: 2nd remaining_timeout {} seconds should be greater than 1st remaining timeout {} seconds".format(self.test_arm_different_timeout_greater.__name__, remaining_time_greater, remaining_time))
        self.assert_expectations()

    @pytest.mark.dependency(depends=["test_arm_disarm_states"])
    def test_arm_different_timeout_smaller(self, duthost, platform_api_conn, conf):
        ''' arm the watchdog with smaller timeout value and verify new timeout was accepted;
        If platform accepts only single valid timeout value, @greater_timeout should be None.
        '''

        watchdog_timeout = conf['greater_timeout']
        if watchdog_timeout is None:
            pytest.skip('"greater_timeout" parameter is required for this test case')
        watchdog_timeout_smaller = conf['valid_timeout']
        actual_timeout = watchdog.arm(platform_api_conn, watchdog_timeout)
        remaining_time = watchdog.get_remaining_time(platform_api_conn)
        actual_timeout_smaller = watchdog.arm(platform_api_conn, watchdog_timeout_smaller)

        self.expect(actual_timeout > actual_timeout_smaller, "{}: 1st timeout {} seconds should be greater than 2nd timeout {} seconds".format(self.test_arm_different_timeout_smaller.__name__, actual_timeout, actual_timeout_smaller))
        remaining_time_smaller = watchdog.get_remaining_time(platform_api_conn)
        self.expect(remaining_time_smaller < remaining_time, "{}: 2nd remaining_timeout {} seconds should be less than 1st remaining timeout {} seconds".format(self.test_arm_different_timeout_smaller.__name__, remaining_time_smaller, remaining_time))
        self.assert_expectations()

    @pytest.mark.dependency(depends=["test_arm_disarm_states"])
    def test_arm_too_big_timeout(self, duthost, platform_api_conn, conf):
        ''' try to arm the watchdog with timeout that is too big for hardware watchdog;
        If no such limitation exist, @too_big_timeout should be None for such platform.
        '''

        watchdog_timeout = conf['too_big_timeout']
        if watchdog_timeout is None:
            pytest.skip('"too_big_timeout" parameter is required for this test case')
        actual_timeout = watchdog.arm(platform_api_conn, watchdog_timeout)
        self.expect(actual_timeout == -1, "{}: Watchdog should be disarmed, but returned timeout of {} seconds".format(self.test_arm_too_big_timeout.__name__, watchdog_timeout))
        self.assert_expectations()

    @pytest.mark.dependency(depends=["test_arm_disarm_states"])
    def test_arm_negative_timeout(self, duthost, platform_api_conn):
        ''' try to arm the watchdog with negative value '''

        watchdog_timeout = -1
        actual_timeout = watchdog.arm(platform_api_conn, watchdog_timeout)
        self.expect(actual_timeout == -1, "{}: Watchdog should be disarmed, but returned timeout of {} seconds".format(self.test_arm_negative_timeout.__name__, watchdog_timeout))
        self.assert_expectations()

