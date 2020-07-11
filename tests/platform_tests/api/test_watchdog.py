import os
import time
import logging
import yaml
import pytest
from common.helpers.platform_api import watchdog
from common.helpers.assertions import pytest_assert
from platform_api_test_base import PlatformApiTestBase

pytestmark = [
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
            test_config = yaml.safe_load(stream)

        config = test_config['default']

        platform = duthost.facts['platform']
        hwsku = duthost.facts['hwsku']

        if platform in test_config and 'default' in test_config[platform]:
            config.update(test_config[platform]['default'])
        if platform in test_config and hwsku in test_config[platform]:
            config.update(test_config[platform][hwsku])

        self.expect('valid_timeout' in config, "valid_timeout is not defined in config")
        # make sure watchdog won't reboot the system when test sleeps for @TEST_WAIT_TIME_SECONDS
        self.expect(config['valid_timeout'] > TEST_WAIT_TIME_SECONDS * 2, "valid_timeout {} is too short".format(config['valid_timeout']))
        self.assert_expectations()
        return config

    def test_arm_disarm_states(self, duthost, localhost, platform_api_conn, conf):
        ''' arm watchdog with a valid timeout value, verify it is in armed state,
        disarm watchdog and verify it is in disarmed state
        '''
        watchdog_timeout = conf['valid_timeout']
        actual_timeout = watchdog.arm(platform_api_conn, watchdog_timeout)

        if self.expect(actual_timeout is not None, "Failed to arm the watchdog"):
            self.expect(actual_timeout >= watchdog_timeout, "Actual watchdog setting with {} apears wrong from the original setting {}".format(actual_timeout, watchdog_timeout))

        watchdog_status = watchdog.is_armed(platform_api_conn)
        if self.expect(watchdog_status is not None, "Failed to check the watchdog status"):
            self.expect(watchdog_status is True, "Watchdog armed is expected but not armed.")

        remaining_time = watchdog.get_remaining_time(platform_api_conn)
        if self.expect(remaining_time is not None, "Failed to get the remaining time of watchdog"):
            self.expect(remaining_time <= watchdog_timeout, "watchdog remaining_time is not expected value {}".format(remaining_time))

        watchdog_status = watchdog.disarm(platform_api_conn)
        if self.expect(watchdog_status is not None, "Failed to disarm the watchdog"):
            self.expect(watchdog_status is True, "Watchdog disarm returns False")

        watchdog_status = watchdog.is_armed(platform_api_conn)
        if self.expect(watchdog_status is not None, "Failed to check the watchdog status"):
            self.expect(watchdog_status is False, "Watchdog disarmed is expected but armed")

        remaining_time = watchdog.get_remaining_time(platform_api_conn)
        if self.expect(remaining_time is not None, "Failed to get the remaining time of watchdog"):
            self.expect(remaining_time is -1, "watchdog remaining_time is not expected value {}".format(remaining_time))

        res = localhost.wait_for(host=duthost.hostname, port=22, state="stopped", delay=5, timeout=watchdog_timeout + TIMEOUT_DEVIATION, module_ignore_errors=True)

        self.expect('exception' in res, "unexpected disconnection from dut")
        self.assert_expectations()

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
                if self.expect(remaining_time > 0, "watchdog remaining_time {} is not valid".format(remaining_time)):
                    self.expect(remaining_time <= actual_timeout, "remaining_time {} should be less than watchdog armed timeout {}".format(remaining_timeout, actual_timeout))

        remaining_time = watchdog.get_remaining_time(platform_api_conn)
        time.sleep(TEST_WAIT_TIME_SECONDS)
        remaining_time_new = watchdog.get_remaining_time(platform_api_conn)
        self.expect(remaining_time_new < remaining_time, "remaining_time {} should be decreased from previous remaining_time {}".format(remaining_time_new, remaining_time))
        self.assert_expectations()

    def test_periodic_arm(self, duthost, platform_api_conn, conf):
        ''' arm watchdog several times as watchdog deamon would and verify API behaves correctly '''

        watchdog_timeout = conf['valid_timeout']
        actual_timeout = watchdog.arm(platform_api_conn, watchdog_timeout)
        time.sleep(TEST_WAIT_TIME_SECONDS)
        remaining_time = watchdog.get_remaining_time(platform_api_conn)
        actual_timeout_new = watchdog.arm(platform_api_conn, watchdog_timeout)
        remaining_time_new = watchdog.get_remaining_time(platform_api_conn)

        self.expect(actual_timeout == actual_timeout_new, "{}: new watchdog timeout {} setting should be same as the previous actual watchdog timeout {}".format(test_periodic_arm.__name__, actual_timeout_new, actual_timeout))
        self.expect(remaining_time_new > remaining_time, "{}: new remaining timeout {} should be bigger than the previous remaining timeout {} by {}".format(test_periodic_arm.__name__, remaining_time_new, remaining_time, TEST_WAIT_TIME_SECONDS))
        self.assert_expectations()

    def test_arm_different_timeout_greater(self, duthost, platform_api_conn, conf):
        ''' arm the watchdog with greater timeout value and verify new timeout was accepted;
        If platform accepts only single valid timeout value, @greater_timeout should be None.
        '''

        watchdog_timeout = conf['valid_timeout']
        watchdog_timeout_greater = conf['greater_timeout']
        if watchdog_timeout_greater is None:
            pytest.skip('"greater_timeout" parameter is required for this test case')
        actual_timeout_second = watchdog.arm(platform_api_conn, watchdog_timeout)
        remaining_time = watchdog.get_remaining_time(platform_api_conn)
        actual_timeout_second_second = watchdog.arm(platform_api_conn, watchdog_timeout_greater)
        self.expect(actual_timeout_second < actual_timeout_second_second, "{}: 1st timeout {} should be smaller than 2nd timeout {}".format(test_arm_different_timeout_greater.__name__, actual_timeout_second, actual_timeout_second_second))
        remaining_time_second = watchdog.get_remaining_time(platform_api_conn)
        self.expect(remaining_time_second > remaining_time, "{}: 2nd remaining_timeout {} should be bigger than 1st remaining timeout {}".format(test_arm_different_timeout_greater.__name__, remaining_time_second, remaining_time))
        self.assert_expectations()

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

        self.expect(actual_timeout > actual_timeout_smaller, "{}: 1st timeout {} should be bigger than 2nd timeout {}".format(test_arm_different_timeout_smaller.__name__, actual_timeout, actual_timeout_smaller))
        remaining_time_smaller = watchdog.get_remaining_time(platform_api_conn)
        self.expect(remaining_time_smaller < remaining_time, "{}: 2nd remaining_timeout {} should be smaller than 1st remaining timeout {}".format(test_arm_different_timeout_smaller.__name__, remaining_time_smaller, remaining_time))
        self.assert_expectations()

    def test_arm_too_big_timeout(self, duthost, platform_api_conn, conf):
        ''' try to arm the watchdog with timeout that is too big for hardware watchdog;
        If no such limitation exist, @too_big_timeout should be None for such platform.
        '''

        watchdog_timeout = conf['too_big_timeout']
        if watchdog_timeout is None:
            pytest.skip('"too_big_timeout" parameter is required for this test case')
        actual_timeout = watchdog.arm(platform_api_conn, watchdog_timeout)
        self.expect(actual_timeout == -1, "{}: watchdog time {} shouldn't be set".format(test_arm_too_big_timeout.__name__, watchdog_timeout))
        self.assert_expectations()

    def test_arm_negative_timeout(self, duthost, platform_api_conn):
        ''' try to arm the watchdog with negative value '''

        watchdog_timeout = -1
        actual_timeout = watchdog.arm(platform_api_conn, watchdog_timeout)
        self.expect(actual_timeout == -1, "{}: watchdog time {} shouldn't be set".format(test_arm_negative_timeout.__name__, watchdog_timeout))
        self.assert_expectations()
