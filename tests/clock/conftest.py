import pytest
import logging

from tests.clock.test_clock import ClockConsts, ClockUtils
from tests.common.helpers.ntp_helper import get_ntp_daemon_in_use, run_ntp, stop_ntp


def pytest_addoption(parser):
    parser.addoption("--ntp_server", action="store", default=None, required=False, help="IP of NTP server to use")


@pytest.fixture(scope="function")
def init_timezone(duthosts):
    """
    @summary: fixture to init timezone before and after each test
    """
    # Get the original timezone before changing it
    logging.info('Check current timezone before test')
    duthost = duthosts[0]
    timezone_output = duthost.shell("timedatectl | grep 'Time zone'")['stdout']
    original_timezone = timezone_output.split(':')[1].strip().split()[0]
    if not original_timezone:
        # in case of empty timezone, set it to UTC
        original_timezone = "UTC"
    logging.info(f'Original timezone: {original_timezone}')
    logging.info(f'Set timezone to {ClockConsts.TEST_TIMEZONE} before test')
    ClockUtils.run_cmd(duthosts, ClockConsts.CMD_CONFIG_CLOCK_TIMEZONE, ClockConsts.TEST_TIMEZONE)

    yield

    logging.info(f'Set timezone to {original_timezone} after test')
    ClockUtils.run_cmd(duthosts, ClockConsts.CMD_CONFIG_CLOCK_TIMEZONE, original_timezone)


@pytest.fixture(scope="function")
def restore_time(duthosts):
    """
    @summary:
        Fixture that restores the DUT system time after a test that deliberately
        changes the clock.

        Before the test the NTP daemon is stopped so it does not correct the clock
        mid-test. After the test the DUT is re-synchronised with its configured NTP
        server(s) via run_ntp(), which restarts the daemon and asserts that the DUT
        becomes synchronised again. Any failure to re-sync is surfaced as a real
        test error instead of being skipped or hidden.

        Supports ntpsec, chrony and classic ntp based images.
    """
    duthost = duthosts[0]
    ntp_daemon = get_ntp_daemon_in_use(duthost)
    logging.info(f'NTP daemon in use on DUT: {ntp_daemon.name}')

    logging.info('Stopping NTP daemon so it does not correct the clock during the test')
    stop_ntp(duthost, ntp_daemon)

    yield

    logging.info(f'Restore DUT time by re-syncing with NTP ({ntp_daemon.name})')
    run_ntp(duthost, ntp_daemon)
