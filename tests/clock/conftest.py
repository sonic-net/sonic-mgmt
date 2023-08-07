import re
import time
import pytest
import logging

from tests.clock.test_clock import ClockConsts, ClockUtils


def pytest_addoption(parser):
    parser.addoption("--ntp_server", action="store", default=None, help="IP of NTP server to use")


@pytest.fixture(scope='session', autouse=True)
def ntp_server(request):
    """
    @summary: Return NTP server's ip if given, otherwise skip the test
    """
    ntp_server_ip = request.config.getoption("ntp_server")
    logging.info(f'NTP server ip from execution parameter: {ntp_server_ip}')
    if ntp_server_ip is None:
        pytest.fail("IP of NTP server was not given")
    return ntp_server_ip


@pytest.fixture(scope="function")
def init_timezone(duthosts):
    """
    @summary: fixture to init timezone before and after each test
    """

    logging.info(f'Set timezone to {ClockConsts.TEST_TIMEZONE} before test')
    ClockUtils.run_cmd(duthosts, ClockConsts.CMD_CONFIG_CLOCK_TIMEZONE, ClockConsts.TEST_TIMEZONE)

    yield

    logging.info(f'Set timezone to {ClockConsts.TEST_TIMEZONE} after test')
    ClockUtils.run_cmd(duthosts, ClockConsts.CMD_CONFIG_CLOCK_TIMEZONE, ClockConsts.TEST_TIMEZONE)


@pytest.fixture(scope="function")
def restore_time(duthosts, ntp_server):
    """
    @summary: fixture to restore time after test (using ntp)
    """

    yield

    logging.info(f'Reset time after test. Sync with NTP server: {ntp_server}')

    logging.info(f'Sync with NTP server: {ntp_server}')
    output = ClockUtils.run_cmd(duthosts, ClockConsts.CMD_CONFIG_NTP_ADD, ntp_server)
    assert ClockConsts.OUTPUT_CMD_NTP_ADD_SUCCESS.format(ntp_server) in output, \
        f'Error: The given string does not contain the expected substring.\n' \
        f'Expected substring: "{ClockConsts.OUTPUT_CMD_NTP_ADD_SUCCESS.format(ntp_server)}"\n' \
        f'Given (whole) string: "{output}"'

    logging.info('Check polling time')
    show_ntp_output = ClockUtils.run_cmd(duthosts, ClockConsts.CMD_SHOW_NTP)
    match = re.search(ClockConsts.REGEX_NTP_POLLING_TIME, show_ntp_output)
    if match:
        polling_time_seconds = int(match.group(1))
    else:
        logging.info('Could not match the regex.\nPattern: "{}"\nShow ntp output string: "{}"'
                     .format(ClockConsts.REGEX_NTP_POLLING_TIME, show_ntp_output))
        polling_time_seconds = ClockConsts.RANDOM_NUM
    logging.info(f'Polling time (in seconds): {polling_time_seconds + 1}')

    logging.info('Wait for the sync')
    time.sleep(polling_time_seconds)

    logging.info(f'Delete NTP server: {ntp_server}')
    output = ClockUtils.run_cmd(duthosts, ClockConsts.CMD_CONFIG_NTP_DEL, ntp_server)
    assert ClockConsts.OUTPUT_CMD_NTP_DEL_SUCCESS.format(ntp_server) in output, \
        f'Error: The given string does not contain the expected substring.\n' \
        f'Expected substring: "{ClockConsts.OUTPUT_CMD_NTP_DEL_SUCCESS.format(ntp_server)}"\n' \
        f'Given (whole) string: "{output}"'
