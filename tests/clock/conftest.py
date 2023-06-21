import re
import time
import pytest
import logging

from tests.clock.ClockConsts import ClockConsts
from tests.clock.ClockUtils import ClockUtils


def pytest_addoption(parser):
    parser.addoption("--ntp_server", action="store", default=None, help="IP of NTP server to use")


@pytest.fixture(scope='session', autouse=True)
def ntp_server(request):
    """
    @summary: Return NTP server's ip if given, otherwise skip the test
    """
    ntp_server_ip = request.config.getoption("ntp_server")
    logging.info('NTP server ip from execution parameter: {}'.format(ntp_server_ip))
    if ntp_server_ip is None:
        logging.info('IP of NTP server was not given, will not run the test')
        pytest.skip("IP of NTP server was not given, will not run the test")
    return ntp_server_ip


@pytest.fixture(scope="function")
def init_timezone(duthosts):
    """
    @summary: fixture to init timezone before and after each test
    """

    logging.info('Set timezone to {} before test'.format(ClockConsts.TEST_TIMEZONE))
    ClockUtils.run_cmd(duthosts, ClockConsts.CMD_CONFIG_CLOCK_TIMEZONE, ClockConsts.TEST_TIMEZONE)

    yield

    logging.info('Set timezone to {} after test'.format(ClockConsts.TEST_TIMEZONE))
    ClockUtils.run_cmd(duthosts, ClockConsts.CMD_CONFIG_CLOCK_TIMEZONE, ClockConsts.TEST_TIMEZONE)


@pytest.fixture(scope="function")
def restore_time(duthosts, ntp_server):
    """
    @summary: fixture to restore time after test (using ntp)
    """

    yield

    logging.info('Reset time after test. Sync with NTP server: {}')

    logging.info('Sync with NTP server: {}'.format(ntp_server))
    ClockUtils.verify_substring(ClockConsts.OUTPUT_CMD_NTP_ADD_SUCCESS.format(ntp_server),
                                ClockUtils.run_cmd(duthosts, ClockConsts.CMD_CONFIG_NTP_ADD, ntp_server))

    logging.info('Check polling time')
    show_ntp_output = ClockUtils.run_cmd(duthosts, ClockConsts.CMD_SHOW_NTP)
    match = re.search(ClockConsts.REGEX_NTP_POLLING_TIME, show_ntp_output)
    if match:
        polling_time_seconds = int(match.group(1))
    else:
        logging.info('Could not match the regex.\nPattern: "{}"\nShow ntp output string: "{}"'.format(ClockConsts.REGEX_NTP_POLLING_TIME, show_ntp_output))
        polling_time_seconds = ClockConsts.RANDOM_NUM
    logging.info('Polling time (in seconds): {}'.format(polling_time_seconds + 1))

    logging.info('Wait for the sync')
    time.sleep(polling_time_seconds)

    logging.info('Delete NTP server: {}'.format(ntp_server))
    ClockUtils.verify_substring(ClockConsts.OUTPUT_CMD_NTP_DEL_SUCCESS.format(ntp_server),
                                ClockUtils.run_cmd(duthosts, ClockConsts.CMD_CONFIG_NTP_DEL, ntp_server))
