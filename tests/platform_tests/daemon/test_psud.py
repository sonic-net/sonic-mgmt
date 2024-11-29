"""
Check daemon status inside PMON container. Each daemon status is checked under the conditions below in this script:
* Daemon Running Status
* Daemon Stop status
* Daemon Restart status

This script is to cover the test case in the SONiC platform daemon and service test plan:
https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testplan/PMON-Services-Daemons-test-plan.md
"""
import logging
import time
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.daemon_utils import check_pmon_daemon_enable_status
from tests.common.platform.processes_utils import check_critical_processes
from tests.common.utilities import compose_dict_from_cli, skip_release, wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('physical'),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer
]

expected_running_status = "RUNNING"
expected_stopped_status = "STOPPED"
expected_exited_status = "EXITED"

daemon_name = "psud"

SIG_STOP_SERVICE = None
SIG_TERM = "-15"
SIG_KILL = "-9"

STATE_DB = 6
psud_tbl_key = ""


@pytest.fixture(scope="module", autouse=True)
def setup(duthosts, enum_supervisor_dut_hostname):
    duthost = duthosts[enum_supervisor_dut_hostname]
    daemon_en_status = check_pmon_daemon_enable_status(duthost, daemon_name)
    if daemon_en_status is False:
        pytest.skip("{} is not enabled in {} {}".format(daemon_name, duthost.facts['platform'], duthost.os_version))


@pytest.fixture(scope="module", autouse=True)
def teardown_module(duthosts, enum_supervisor_dut_hostname):
    duthost = duthosts[enum_supervisor_dut_hostname]
    yield

    daemon_status, daemon_pid = duthost.get_pmon_daemon_status(daemon_name)
    if daemon_status != "RUNNING":
        duthost.start_pmon_daemon(daemon_name)
        time.sleep(10)
    logger.info(
        "Tearing down: to make sure all the critical services, interfaces and transceivers are good")
    check_critical_processes(duthost, watch_secs=10)


@pytest.fixture
def check_daemon_status(duthosts, enum_supervisor_dut_hostname):
    duthost = duthosts[enum_supervisor_dut_hostname]
    daemon_status, daemon_pid = duthost.get_pmon_daemon_status(daemon_name)
    if daemon_status != "RUNNING":
        duthost.start_pmon_daemon(daemon_name)
        time.sleep(10)


def check_if_daemon_restarted(duthost, daemon_name, pre_daemon_pid):
    daemon_status, daemon_pid = duthost.get_pmon_daemon_status(daemon_name)
    return (daemon_pid > pre_daemon_pid)


def check_expected_daemon_status(duthost, expected_daemon_status):
    daemon_status, post_daemon_pid = duthost.get_pmon_daemon_status(daemon_name)
    return daemon_status == expected_daemon_status


def check_pmon_daemon_id(duthost, daemon_name, expected_id):
    _, daemon_id = duthost.get_pmon_daemon_status(daemon_name)
    if daemon_id != expected_id:
        logger.info(f"{daemon_name} pmon id is {daemon_id} != {expected_id}")
    return daemon_id == expected_id


def collect_data(duthost):
    keys = duthost.shell(
        'sonic-db-cli STATE_DB KEYS "PSU_INFO|*"')['stdout_lines']

    dev_data = {}
    for k in keys:
        data = duthost.shell(
            'sonic-db-cli STATE_DB HGETALL "{}"'.format(k))['stdout']
        data = compose_dict_from_cli(data)
        dev_data[k] = data

    return {'keys': keys, 'data': dev_data}


def wait_data(duthost):
    class shared_scope:
        data_after_restart = {}

    def _collect_data():
        shared_scope.data_after_restart = collect_data(duthost)
        return bool(shared_scope.data_after_restart['data'])
    psud_pooling_interval = 60
    wait_until(psud_pooling_interval, 6, 0, _collect_data)
    return shared_scope.data_after_restart


@pytest.fixture(scope='module')
def data_before_restart(duthosts, enum_supervisor_dut_hostname):
    duthost = duthosts[enum_supervisor_dut_hostname]
    data = collect_data(duthost)
    return data


def verify_data(data_before, data_after):
    """
    Compare PSU_INFO taken from state_db before_restart and after_restart,
    avoid comparing fields that are not persistent
    Args:
        data_before: Dict with PSU_INFO before daemon restart
        data_after: Dict with PSU_INFO after daemon restart
    """
    ignore_fields = ["power", "temp", "current",
                     "voltage", "input_current", "input_voltage"]
    msg = 'Data_before_restart {} dont match data_after_restart {} for field {}'
    for psu_key in data_before['data']:
        for field in data_before['data'][psu_key]:
            if field not in ignore_fields:
                value_before = data_before['data'][psu_key][field]

                # This will slowly populate by supervisor. If we dont have this check we will have KeyError
                if psu_key not in data_after["data"] or field not in data_after["data"][psu_key]:
                    return False

                value_after = data_after['data'][psu_key][field]
                if value_before != value_after:
                    logger.info(msg.format(value_before, value_after, field))
                    return False
    return True


def get_and_verify_data(duthost, data_before_restart):
    data_after_restart = wait_data(duthost)
    return verify_data(data_before_restart, data_after_restart)


def test_pmon_psud_running_status(duthosts, enum_supervisor_dut_hostname, data_before_restart):
    """
    @summary: This test case is to check psud status on dut
    """
    duthost = duthosts[enum_supervisor_dut_hostname]
    daemon_status, daemon_pid = duthost.get_pmon_daemon_status(daemon_name)
    logger.info("{} daemon is {} with pid {}".format(daemon_name, daemon_status, daemon_pid))
    pytest_assert(daemon_status == expected_running_status,
                  "{} expected running status is {} but is {}"
                  .format(daemon_name, expected_running_status, daemon_status))
    pytest_assert(daemon_pid != -1,
                  "{} expected pid is a positive integer but is {}".format(daemon_name, daemon_pid))

    pytest_assert(data_before_restart['keys'],
                  "DB keys is not availale on daemon running")
    pytest_assert(data_before_restart['data'],
                  "DB data is not availale on daemon running")


def test_pmon_psud_stop_and_start_status(check_daemon_status, duthosts,
                                         enum_supervisor_dut_hostname, data_before_restart):
    """
    @summary: This test case is to check the psud stopped and restarted status
    """
    duthost = duthosts[enum_supervisor_dut_hostname]
    pre_daemon_status, pre_daemon_pid = duthost.get_pmon_daemon_status(daemon_name)
    logger.info("{} daemon is {} with pid {}".format(daemon_name, pre_daemon_status, pre_daemon_pid))

    duthost.stop_pmon_daemon(daemon_name, SIG_STOP_SERVICE)

    time.sleep(2)

    wait_until(120, 10, 0, check_pmon_daemon_id, duthost, daemon_name, -1)
    wait_until(50, 10, 0, check_expected_daemon_status, duthost, expected_stopped_status)

    daemon_status, daemon_pid = duthost.get_pmon_daemon_status(daemon_name)
    pytest_assert(daemon_status == expected_stopped_status,
                  "{} expected stopped status is {} but is {}"
                  .format(daemon_name, expected_stopped_status, daemon_status))
    pytest_assert(daemon_pid == -1,
                  "{} expected pid is -1 but is {}".format(daemon_name, daemon_pid))

    data = collect_data(duthost)

    pytest_assert(wait_until(60, 10, 0, lambda: not data['keys']),
                  "DB data keys is not cleared on daemon stop")

    pytest_assert(wait_until(60, 10, 0, lambda: not data['data']),
                  "DB data is not cleared on daemon stop")

    duthost.start_pmon_daemon(daemon_name)

    wait_until(120, 10, 0, check_if_daemon_restarted, duthost, daemon_name, pre_daemon_pid)
    wait_until(50, 10, 0, check_expected_daemon_status, duthost, expected_running_status)

    post_daemon_status, post_daemon_pid = duthost.get_pmon_daemon_status(daemon_name)
    pytest_assert(post_daemon_status == expected_running_status,
                  "{} expected restarted status is {} but is {}"
                  .format(daemon_name, expected_running_status, post_daemon_status))
    pytest_assert(post_daemon_pid != -1,
                  "{} expected pid is -1 but is {}".format(daemon_name, post_daemon_pid))
    pytest_assert(post_daemon_pid > pre_daemon_pid,
                  "Restarted {} pid should be bigger than {} but it is {}"
                  .format(daemon_name, pre_daemon_pid, post_daemon_pid))

    # Wait till DB PSU_INFO key values are restored

    # For T2 it takes around 1 minute for the information to be populated in supervisor
    is_modular_chassis = duthost.get_facts().get("modular_chassis")
    wait_time = 90 if is_modular_chassis else 40

    wait_until(wait_time, 5, 0, get_and_verify_data, duthost, data_before_restart)


def test_pmon_psud_term_and_start_status(check_daemon_status, duthosts,
                                         enum_supervisor_dut_hostname, data_before_restart):
    """
    @summary: This test case is to check the psud terminated and restarted status
    """
    duthost = duthosts[enum_supervisor_dut_hostname]

    skip_release(duthost, ["201811", "201911"])

    pre_daemon_status, pre_daemon_pid = duthost.get_pmon_daemon_status(daemon_name)
    logger.info("{} daemon is {} with pid {}".format(daemon_name, pre_daemon_status, pre_daemon_pid))

    duthost.stop_pmon_daemon(daemon_name, SIG_TERM, pre_daemon_pid)

    wait_until(120, 10, 0, check_if_daemon_restarted, duthost, daemon_name, pre_daemon_pid)
    wait_until(50, 10, 5, check_expected_daemon_status, duthost, expected_running_status)

    post_daemon_status, post_daemon_pid = duthost.get_pmon_daemon_status(daemon_name)
    pytest_assert(post_daemon_status == expected_running_status,
                  "{} expected restarted status is {} but is {}"
                  .format(daemon_name, expected_running_status, post_daemon_status))
    pytest_assert(post_daemon_pid != -1,
                  "{} expected pid is -1 but is {}".format(daemon_name, post_daemon_pid))
    pytest_assert(post_daemon_pid > pre_daemon_pid,
                  "Restarted {} pid should be bigger than {} but it is {}"
                  .format(daemon_name, pre_daemon_pid, post_daemon_pid))
    # Wait till DB PSU_INFO key values are restored
    wait_until(40, 5, 0, get_and_verify_data, duthost, data_before_restart)


def test_pmon_psud_kill_and_start_status(check_daemon_status, duthosts,
                                         enum_supervisor_dut_hostname, data_before_restart):
    """
    @summary: This test case is to check the psud killed unexpectedly (automatically restarted) status
    """
    duthost = duthosts[enum_supervisor_dut_hostname]

    skip_release(duthost, ["201811", "201911"])

    pre_daemon_status, pre_daemon_pid = duthost.get_pmon_daemon_status(daemon_name)
    logger.info("{} daemon is {} with pid {}".format(daemon_name, pre_daemon_status, pre_daemon_pid))

    duthost.stop_pmon_daemon(daemon_name, SIG_KILL, pre_daemon_pid)

    wait_until(120, 10, 0, check_if_daemon_restarted, duthost, daemon_name, pre_daemon_pid)
    wait_until(120, 10, 0, check_expected_daemon_status, duthost, expected_running_status)

    post_daemon_status, post_daemon_pid = duthost.get_pmon_daemon_status(daemon_name)
    pytest_assert(post_daemon_status == expected_running_status,
                  "{} expected restarted status is {} but is {}"
                  .format(daemon_name, expected_running_status, post_daemon_status))
    pytest_assert(post_daemon_pid != -1,
                  "{} expected pid is -1 but is {}".format(daemon_name, post_daemon_pid))
    pytest_assert(post_daemon_pid > pre_daemon_pid,
                  "Restarted {} pid should be bigger than {} but it is {}"
                  .format(daemon_name, pre_daemon_pid, post_daemon_pid))
    # Wait till DB PSU_INFO key values are restored
    wait_until(40, 5, 0, get_and_verify_data, duthost, data_before_restart)
