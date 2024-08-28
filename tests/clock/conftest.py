import re
import time
import pytest
import logging

from tests.clock.test_clock import ClockConsts, ClockUtils


def pytest_addoption(parser):
    parser.addoption("--ntp_server", action="store", default=None, required=False, help="IP of NTP server to use")


@pytest.fixture(scope='session', autouse=True)
def ntp_server(request):
    """
    @summary: Return NTP server's ip if given, otherwise skip the test
    """
    ntp_server_ip = request.config.getoption("ntp_server")
    logging.info(f'NTP server ip from execution parameter: {ntp_server_ip}')
    if ntp_server_ip is None:
        pytest.skip("IP of NTP server was not given")
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
    logging.info('Check NTP server reachability')
    try:
        ClockUtils.run_cmd(duthosts, f'{ClockConsts.CMD_NTPDATE} -q {ntp_server}', raise_err=True)
    except Exception as e:
        pytest.skip(f'Unreachable NTP server {ntp_server}: {str(e)}')

    logging.info('Check if there is ntp configured before test')
    show_ntp_output = ClockUtils.run_cmd(duthosts, ClockConsts.CMD_SHOW_NTP)
    if 'unsynchronised' in show_ntp_output:
        logging.info('There is no NTP server configured before test')
        orig_ntp_server = None
    else:
        synchronized_str = 'synchronised to NTP server'
        logging.info('There is NTP server configured before test')
        assert synchronized_str in show_ntp_output, f'There is NTP configured but output do not contain ' \
                                                    f'"{synchronized_str}"'
        orig_ntp_server = re.findall(r'\d+.\d+.\d+.\d+',
                                     re.findall(r'synchronised to NTP server \(\d+.\d+.\d+.\d+\)',
                                                show_ntp_output)[0])[0]
        logging.info(f'Original NTP: {orig_ntp_server}')

    if orig_ntp_server:
        logging.info('Disable original NTP before test')
        output = ClockUtils.run_cmd(duthosts, ClockConsts.CMD_CONFIG_NTP_DEL, orig_ntp_server)
        assert ClockConsts.OUTPUT_CMD_NTP_DEL_SUCCESS.format(orig_ntp_server) in output, \
            f'Error: The given string does not contain the expected substring.\n' \
            f'Expected substring: "{ClockConsts.OUTPUT_CMD_NTP_DEL_SUCCESS.format(orig_ntp_server)}"\n' \
            f'Given (whole) string: "{output}"'

    yield

    logging.info(f'Reset time after test. Sync with NTP server: {ntp_server}')

    logging.info('Stopping NTP service')
    ClockUtils.run_cmd(duthosts, ClockConsts.CMD_NTP_STOP)

    logging.info(f'Syncing datetime with NTP server {ntp_server}')
    ClockUtils.run_cmd(duthosts, ClockConsts.CMD_NTPDATE, f'-s {ntp_server}')

    logging.info('Starting NTP service')
    ClockUtils.run_cmd(duthosts, ClockConsts.CMD_NTP_START)

    if orig_ntp_server:
        logging.info('Restore original NTP server after test')
        output = ClockUtils.run_cmd(duthosts, ClockConsts.CMD_CONFIG_NTP_ADD, orig_ntp_server)
        assert ClockConsts.OUTPUT_CMD_NTP_ADD_SUCCESS.format(orig_ntp_server) in output, \
            f'Error: The given string does not contain the expected substring.\n' \
            f'Expected substring: "{ClockConsts.OUTPUT_CMD_NTP_ADD_SUCCESS.format(orig_ntp_server)}"\n' \
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
