import logging
import time

import pytest

from tests.platform_tests.test_platform_info import check_sensord_status, start_pmon_sensord_task

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer
]

SIG_KILL = "-9"
SIG_TERM = "-15"
SIG_HUP = "-1"


@pytest.fixture(scope="module")
def check_sensord_supported(duthosts, rand_one_dut_hostname):
    """
    @summary: Check that sensord is enabled / supported by the SKU
    """
    duthost = duthosts[rand_one_dut_hostname]

    cmd = "docker exec pmon ls /etc/sensors.d/sensors.conf"
    no_sensors_config = duthost.shell(cmd, module_ignore_errors=True)['failed']
    if no_sensors_config:
        pytest.skip(f"No sensors.conf for this SKU {duthost.facts['platform']}")


@pytest.fixture(scope="function")
def sensord_start_and_get_pid(duthosts, rand_one_dut_hostname, check_sensord_supported):
    """
    @summary: Ensure sensord is running, and provide the PID to the testcase
    """
    duthost = duthosts[rand_one_dut_hostname]

    daemon_status, pid = check_sensord_status(duthost)
    if daemon_status is False:
        start_pmon_sensord_task(duthost)

    yield pid

    start_pmon_sensord_task(duthost)


def assert_expected_daemon_status(duthost, expected_daemon_status):
    daemon_status, _ = check_sensord_status(duthost)
    assert daemon_status == expected_daemon_status


def test_pmon_sensord_sigterm(sensord_start_and_get_pid, duthosts, rand_one_dut_hostname):
    """
    @summary: Assert that sensord stops after sigterm
    """
    duthost = duthosts[rand_one_dut_hostname]

    sensord_pid = sensord_start_and_get_pid

    duthost.kill_pmon_daemon_pid_w_sig(sensord_pid, SIG_TERM)
    time.sleep(2)

    assert_expected_daemon_status(duthost, False)

    start_pmon_sensord_task(duthost)
    time.sleep(10)

    assert_expected_daemon_status(duthost, True)


def test_pmon_sensord_sigkill(sensord_start_and_get_pid, duthosts, rand_one_dut_hostname):
    """
    @summary: Assert that sensord stops after sigkill
    """
    duthost = duthosts[rand_one_dut_hostname]

    sensord_pid = sensord_start_and_get_pid

    duthost.kill_pmon_daemon_pid_w_sig(sensord_pid, SIG_KILL)
    time.sleep(2)

    assert_expected_daemon_status(duthost, False)

    start_pmon_sensord_task(duthost)
    time.sleep(10)

    assert_expected_daemon_status(duthost, True)


def test_pmon_sensord_sighup(sensord_start_and_get_pid, duthosts, rand_one_dut_hostname):
    """
    @summary: Assert that sensord remains running after receiving a sighup
    """
    duthost = duthosts[rand_one_dut_hostname]

    sensord_pid = sensord_start_and_get_pid

    duthost.kill_pmon_daemon_pid_w_sig(sensord_pid, SIG_HUP)
    time.sleep(2)

    # daemon should still be running
    assert_expected_daemon_status(duthost, True)
