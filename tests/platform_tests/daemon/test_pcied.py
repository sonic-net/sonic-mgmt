"""
Check daemon status inside PMON container. Each daemon status is checked under the conditions below in this script:
* Daemon Running Status 
* Daemon Stop status
* Daemon Restart status

This script is to cover the test case in the SONiC platform daemon and service test plan:
https://github.com/Azure/sonic-mgmt/blob/master/docs/testplan/PMON-Services-Daemons-test-plan.md
"""
import logging
import re
import time

from datetime import datetime

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.daemon_utils import check_pmon_daemon_enable_status
from tests.common.platform.processes_utils import wait_critical_processes, check_critical_processes
from tests.common.utilities import compose_dict_from_cli, skip_release, wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer
]

expected_running_status = "RUNNING"
expected_stopped_status = "STOPPED"
expected_exited_status = "EXITED"

daemon_name = "pcied"

SIG_STOP_SERVICE = None
SIG_TERM = "-15"
SIG_KILL = "-9"

pcie_devices_status_tbl_key = ""
status_field = "status"
expected_pcied_devices_status = "PASSED"

@pytest.fixture(scope="module", autouse=True)
def setup(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    daemon_en_status = check_pmon_daemon_enable_status(duthost, daemon_name)
    if daemon_en_status is False:
        pytest.skip("{} is not enabled in {}".format(daemon_name, duthost.facts['platform'], duthost.os_version))


@pytest.fixture(scope="module", autouse=True)
def teardown_module(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    yield

    daemon_status, daemon_pid = duthost.get_pmon_daemon_status(daemon_name)
    if daemon_status is not "RUNNING":
        duthost.start_pmon_daemon(daemon_name)
        time.sleep(10)
    logger.info("Tearing down: to make sure all the critical services, interfaces and transceivers are good")
    check_critical_processes(duthost, watch_secs=10)


@pytest.fixture
def check_daemon_status(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    daemon_status, daemon_pid = duthost.get_pmon_daemon_status(daemon_name)
    if daemon_status is not "RUNNING":
        duthost.start_pmon_daemon(daemon_name)
        time.sleep(10)

@pytest.fixture(scope="module", autouse=True)
def get_pcie_devices_tbl_key(duthosts,rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    command_output = duthost.shell("redis-cli -n 6 keys '*' | grep PCIE_DEVICES")
    
    global pcie_devices_status_tbl_key
    pcie_devices_status_tbl_key = command_output["stdout"]

def collect_data(duthost):
    keys = duthost.shell('redis-cli -n 6 keys "PCIE_DEVICE|*"')['stdout_lines']

    dev_data = {}
    for k in keys:
        data = duthost.shell('redis-cli -n 6 hgetall "{}"'.format(k))['stdout_lines']
        data = compose_dict_from_cli(data)
        dev_data[k] = data
    
    dev_summary_status = duthost.get_pmon_daemon_db_value(pcie_devices_status_tbl_key, status_field)
    return {'status': dev_summary_status, 'devices': dev_data}
    
def wait_data(duthost):
    class shared_scope:
        data_after_restart = {}
    def _collect_data():
        shared_scope.data_after_restart = collect_data(duthost)
        return bool(shared_scope.data_after_restart['devices'])
    pcied_pooling_interval = 60
    wait_until(pcied_pooling_interval, 6, _collect_data)
    return shared_scope.data_after_restart

@pytest.fixture(scope='module')
def data_before_restart(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    data = collect_data(duthost)
    return data


def test_pmon_pcied_running_status(duthosts, rand_one_dut_hostname, data_before_restart):
    """
    @summary: This test case is to check pcied status on dut
    """
    duthost = duthosts[rand_one_dut_hostname]
    daemon_status, daemon_pid = duthost.get_pmon_daemon_status(daemon_name)
    logger.info("{} daemon is {} with pid {}".format(daemon_name, daemon_status, daemon_pid))
    pytest_assert(daemon_status == expected_running_status,
                          "{} expected running status is {} but is {}".format(daemon_name, expected_running_status, daemon_status))
    pytest_assert(daemon_pid != -1,
                          "{} expected pid is a positive integer but is {}".format(daemon_name, daemon_pid))

    daemon_db_value = data_before_restart['status']
    pytest_assert(daemon_db_value == expected_pcied_devices_status,
                          "Expected {} {} is {} but is {}".format(get_pcie_devices_tbl_key, status_field, expected_pcied_devices_status, daemon_db_value))
    pytest_assert(data_before_restart['devices'], 'pcied data not found in DB')


def test_pmon_pcied_stop_and_start_status(check_daemon_status, duthosts, rand_one_dut_hostname, data_before_restart):
    """
    @summary: This test case is to check the pcied stopped and restarted status 
    """
    duthost = duthosts[rand_one_dut_hostname]
    pre_daemon_status, pre_daemon_pid = duthost.get_pmon_daemon_status(daemon_name)
    logger.info("{} daemon is {} with pid {}".format(daemon_name, pre_daemon_status, pre_daemon_pid))

    duthost.stop_pmon_daemon(daemon_name, SIG_STOP_SERVICE)
    time.sleep(2)

    daemon_status, daemon_pid = duthost.get_pmon_daemon_status(daemon_name)
    pytest_assert(daemon_status == expected_stopped_status,
                          "{} expected stopped status is {} but is {}".format(daemon_name, expected_stopped_status, daemon_status))
    pytest_assert(daemon_pid == -1,
                          "{} expected pid is -1 but is {}".format(daemon_name, daemon_pid))

    data = collect_data(duthost)
    pytest_assert(not data['status'], "DB data is not cleared on daemon stop")
    pytest_assert(not data['devices'], "DB data is not cleared on daemon stop")

    duthost.start_pmon_daemon(daemon_name)
    time.sleep(10)

    post_daemon_status, post_daemon_pid = duthost.get_pmon_daemon_status(daemon_name)
    pytest_assert(post_daemon_status == expected_running_status,
                          "{} expected restarted status is {} but is {}".format(daemon_name, expected_running_status, post_daemon_status))
    pytest_assert(post_daemon_pid != -1,
                          "{} expected pid is -1 but is {}".format(daemon_name, post_daemon_pid))
    pytest_assert(post_daemon_pid > pre_daemon_pid,
                          "Restarted {} pid should be bigger than {} but it is {}".format(daemon_name, pre_daemon_pid, post_daemon_pid))
    
    data_after_restart = wait_data(duthost)
    pytest_assert(data_after_restart == data_before_restart, 'DB data present before and after restart does not match')


def test_pmon_pcied_term_and_start_status(check_daemon_status, duthosts, rand_one_dut_hostname, data_before_restart):
    """
    @summary: This test case is to check the pcied terminated and restarted status
    """
    duthost = duthosts[rand_one_dut_hostname]

    skip_release(duthost, ["201811", "201911"])

    pre_daemon_status, pre_daemon_pid = duthost.get_pmon_daemon_status(daemon_name)
    logger.info("{} daemon is {} with pid {}".format(daemon_name, pre_daemon_status, pre_daemon_pid))

    duthost.stop_pmon_daemon(daemon_name, SIG_TERM, pre_daemon_pid)

    daemon_status, daemon_pid = duthost.get_pmon_daemon_status(daemon_name)
    pytest_assert(daemon_status != expected_running_status and pre_daemon_pid != daemon_pid,
                         "{} status for SIG_TERM should not be {} with pid:{}!".format(daemon_name, daemon_status, daemon_pid))

    time.sleep(10)

    post_daemon_status, post_daemon_pid = duthost.get_pmon_daemon_status(daemon_name)
    pytest_assert(post_daemon_status == expected_running_status,
                          "{} expected restarted status is {} but is {}".format(daemon_name, expected_running_status, post_daemon_status))
    pytest_assert(post_daemon_pid != -1,
                          "{} expected pid is -1 but is {}".format(daemon_name, post_daemon_pid))
    pytest_assert(post_daemon_pid > pre_daemon_pid,
                          "Restarted {} pid should be bigger than {} but it is {}".format(daemon_name, pre_daemon_pid, post_daemon_pid))
    data_after_restart = wait_data(duthost)
    pytest_assert(data_after_restart == data_before_restart, 'DB data present before and after restart does not match')


def test_pmon_pcied_kill_and_start_status(check_daemon_status, duthosts, rand_one_dut_hostname, data_before_restart):
    """
    @summary: This test case is to check the pcied killed unexpectedly (automatically restarted) status
    """
    duthost = duthosts[rand_one_dut_hostname]
    pre_daemon_status, pre_daemon_pid = duthost.get_pmon_daemon_status(daemon_name)
    logger.info("{} daemon is {} with pid {}".format(daemon_name, pre_daemon_status, pre_daemon_pid))

    duthost.stop_pmon_daemon(daemon_name, SIG_KILL, pre_daemon_pid)

    daemon_status, daemon_pid = duthost.get_pmon_daemon_status(daemon_name)
    pytest_assert(daemon_status != expected_running_status,
                          "{} unexpected killed status is not {}".format(daemon_name, daemon_status))

    time.sleep(10)

    post_daemon_status, post_daemon_pid = duthost.get_pmon_daemon_status(daemon_name)
    pytest_assert(post_daemon_status == expected_running_status,
                          "{} expected restarted status is {} but is {}".format(daemon_name, expected_running_status, post_daemon_status))
    pytest_assert(post_daemon_pid != -1,
                          "{} expected pid is -1 but is {}".format(daemon_name, post_daemon_pid))
    pytest_assert(post_daemon_pid > pre_daemon_pid,
                          "Restarted {} pid should be bigger than {} but it is {}".format(daemon_name, pre_daemon_pid, post_daemon_pid))
    data_after_restart = wait_data(duthost)
    pytest_assert(data_after_restart == data_before_restart, 'DB data present before and after restart does not match')
