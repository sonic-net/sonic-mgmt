import os
import time
import logging
import yaml
import pytest
from common.helpers.platform_api import watchdog

logger = logging.getLogger(__name__)

TEST_CONFIG_FILE = os.path.join(os.path.split(__file__)[0], "watchdog.yml")
TEST_WAIT_TIME_SECONDS = 2

class TestWatchdogAPI(object):
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

        assert 'valid_timeout' in config
        # make sure watchdog won't reboot the system when test sleeps for @TEST_WAIT_TIME_SECONDS
        assert config['valid_timeout'] > TEST_WAIT_TIME_SECONDS * 2

        return config


    def test_arm_disarm_states(self, testbed_devices, platform_api_conn, conf):
        ''' arm watchdog with a valid timeout value, verify it is in armed state,
        disarm watchdog and verify it is in disarmed state
        '''

        duthost = testbed_devices['dut']
        localhost = testbed_devices['localhost']

        watchdog_timeout = conf['valid_timeout']
        actual_timeout = watchdog.arm(platform_api_conn, watchdog_timeout)

        assert actual_timeout != -1
        assert actual_timeout >= watchdog_timeout
        assert watchdog.is_armed(platform_api_conn)

        assert watchdog.disarm(platform_api_conn)
        assert not watchdog.is_armed(platform_api_conn)

        res = localhost.wait_for(host=duthost.hostname,
                port=22, state="stopped", delay=5, timeout=watchdog_timeout,
                module_ignore_errors=True)

        assert 'exception' in res

    def test_remaining_time(self, duthost, platform_api_conn, conf):
        ''' arm watchdog with a valid timeout and verify that remaining time API works correctly '''

        watchdog_timeout = conf['valid_timeout']

        # in the begginging of the test watchdog is not armed, so
        # get_remaining_time has to return -1
        assert watchdog.get_remaining_time(platform_api_conn) == -1

        actual_timeout = watchdog.arm(platform_api_conn, watchdog_timeout)
        remaining_time = watchdog.get_remaining_time(platform_api_conn)

        assert remaining_time > 0
        assert remaining_time <= actual_timeout

        remaining_time = watchdog.get_remaining_time(platform_api_conn)
        time.sleep(TEST_WAIT_TIME_SECONDS)
        assert watchdog.get_remaining_time(platform_api_conn) < remaining_time

    def test_periodic_arm(self, duthost, platform_api_conn, conf):
        ''' arm watchdog several times as watchdog deamon would and verify API behaves correctly '''

        watchdog_timeout = conf['valid_timeout']
        actual_timeout = watchdog.arm(platform_api_conn, watchdog_timeout)
        time.sleep(TEST_WAIT_TIME_SECONDS)
        remaining_time = watchdog.get_remaining_time(platform_api_conn)
        actual_timeout_new = watchdog.arm(platform_api_conn, watchdog_timeout)

        assert actual_timeout == actual_timeout_new
        assert watchdog.get_remaining_time(platform_api_conn) > remaining_time

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

        assert actual_timeout_second < actual_timeout_second_second
        assert watchdog.get_remaining_time(platform_api_conn) > remaining_time

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

        assert actual_timeout > actual_timeout_smaller
        assert watchdog.get_remaining_time(platform_api_conn) < remaining_time

    def test_arm_too_big_timeout(self, duthost, platform_api_conn, conf):
        ''' try to arm the watchdog with timeout that is too big for hardware watchdog;
        If no such limitation exist, @too_big_timeout should be None for such platform.
        '''

        watchdog_timeout = conf['too_big_timeout']
        if watchdog_timeout is None:
            pytest.skip('"too_big_timeout" parameter is required for this test case')
        actual_timeout = watchdog.arm(platform_api_conn, watchdog_timeout)

        assert actual_timeout == -1

    def test_arm_negative_timeout(self, duthost, platform_api_conn):
        ''' try to arm the watchdog with negative value '''

        watchdog_timeout = -1
        actual_timeout = watchdog.arm(platform_api_conn, watchdog_timeout)

        assert actual_timeout == -1

    @pytest.mark.disable_loganalyzer
    def test_reboot(self, testbed_devices, platform_api_conn, conf):
        ''' arm the watchdog and verify it did its job after timeout expiration '''

        duthost = testbed_devices['dut']
        localhost = testbed_devices['localhost']

        watchdog_timeout = conf['valid_timeout']
        actual_timeout = watchdog.arm(platform_api_conn, watchdog_timeout)

        assert actual_timeout != -1

        res = localhost.wait_for(host=duthost.hostname, port=22, state="stopped", delay=2, timeout=actual_timeout,
                                 module_ignore_errors=True)
        assert 'exception' in res

        res = localhost.wait_for(host=duthost.hostname, port=22, state="started", delay=10, timeout=120,
                                 module_ignore_errors=True)
        assert 'exception' not in res

        # wait for system to startup
        time.sleep(120)
