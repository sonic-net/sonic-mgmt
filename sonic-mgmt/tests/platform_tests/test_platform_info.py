"""
Check platform information

This script covers the test case 'Check platform information' in the SONiC platform test plan:
https://github.com/Azure/SONiC/blob/master/doc/pmon/sonic_platform_test_plan.md
"""
import json
import logging
import time
from retry.api import retry_call

import pytest

from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError
from tests.common.utilities import wait_until
from tests.common.platform.device_utils import get_dut_psu_line_pattern
from thermal_control_test_helper import *

pytestmark = [
    pytest.mark.topology('any')
]

CMD_PLATFORM_PSUSTATUS = "show platform psustatus"
CMD_PLATFORM_PSUSTATUS_JSON = "{} --json".format(CMD_PLATFORM_PSUSTATUS)
CMD_PLATFORM_FANSTATUS = "show platform fan"
CMD_PLATFORM_TEMPER = "show platform temperature"

THERMAL_CONTROL_TEST_WAIT_TIME = 65
THERMAL_CONTROL_TEST_CHECK_INTERVAL = 5

THERMAL_POLICY_VALID_FILE = 'valid_policy.json'
THERMAL_POLICY_INVALID_FORMAT_FILE = 'invalid_format_policy.json'
THERMAL_POLICY_INVALID_VALUE_FILE = 'invalid_value_policy.json'

LOG_EXPECT_POLICY_FILE_INVALID = '.*Caught exception while initializing thermal manager.*'
LOG_EXPECT_FAN_REMOVE_RE = '.*Fan removed warning:.*'
LOG_EXPECT_FAN_REMOVE_CLEAR_RE = '.*Fan removed warning cleared:.*'
LOG_EXPECT_FAN_FAULT_RE = '.*Fan fault warning:.*'
LOG_EXPECT_FAN_FAULT_CLEAR_RE = '.*Fan fault warning cleared:.*'
LOG_EXPECT_FAN_UNDER_SPEED_RE = '.*Fan low speed warning:.*'
LOG_EXPECT_FAN_UNDER_SPEED_CLEAR_RE = '.*Fan low speed warning cleared:.*'
LOG_EXPECT_FAN_OVER_SPEED_RE = '.*Fan high speed warning:*'
LOG_EXPECT_FAN_OVER_SPEED_CLEAR_RE = '.*Fan high speed warning cleared:.*'
LOG_EXPECT_INSUFFICIENT_FAN_NUM_RE = '.*Insufficient number of working fans warning:.*'
LOG_EXPECT_INSUFFICIENT_FAN_NUM_CLEAR_RE = '.*Insufficient number of working fans warning cleared:.*'

# These error messages are not triggered by platform test cases,
# Ref to https://github.com/Azure/sonic-buildimage/issues/8944
SKIP_ERROR_LOG_COMMON = ['.*ERR syncd#syncd:.*SAI_API_QUEUE:_brcm_sai_cosq_stat_get:.* queue egress Min limit get failed with error Invalid parameter.*',
                         '.*ERR syncd#syncd:.*collectQueueCounters: QUEUE_WATERMARK_STAT_COUNTER: failed to get stats of queue.*']

SKIP_ERROR_LOG_SHOW_PLATFORM_TEMP = ['.*ERR pmon#thermalctld.*int\(\) argument must be a string.* or a number.*',
                                     '.*ERR pmon#thermalctld.*invalid literal for int\(\) with base 10.*',
                                     '.*ERR pmon#thermalctld.*Failed to get minimum ambient temperature, use pessimistic instead.*',
                                     '.*ERR pmon#thermalctld.*Failed to read from file /run/hw-management/thermal.*',
                                     '.*ERR pmon#thermalctld.*Failed to read from file /var/run/hw-management/thermal.*',
                                     '.*ERR pmon#thermalctld.*Failed to run thermal policy.*']

SKIP_ERROR_LOG_PSU_ABSENCE = ['.*Error getting sensor data: dps460.*Kernel interface error.*',
                              '.*ERR pmon#psud:.*Fail to read model number: No key PN_VPD_FIELD in.*',
                              '.*ERR pmon#psud:.*Fail to read serial number: No key SN_VPD_FIELD in.*',
                              '.*ERR pmon#psud:.*Fail to read revision: No key REV_VPD_FIELD in.*',
                              '.*ERR pmon#psud: Failed to read from file /var/run/hw-management/power/psu\d_volt.*']

SKIP_ERROR_LOG_SHOW_PLATFORM_TEMP.extend(SKIP_ERROR_LOG_COMMON)
SKIP_ERROR_LOG_PSU_ABSENCE.extend(SKIP_ERROR_LOG_COMMON)

def check_sensord_status(ans_host):
    """
    @summary: Check sensord running status by analyzing the output of "ps -x" and return the PID if it's running
    @return: first return value will be a bool, True to indicate task is running.
             second return value is int PID, a none -1 value for a valid PID of sensord task
    """
    running_status = False
    sensord_pid = -1
    pmon_ps_output = ans_host.command("docker exec pmon ps -x")
    for line in pmon_ps_output["stdout_lines"]:
        key_value = line.split()
        if "/usr/sbin/sensord" in key_value:
            running_status = True
            sensord_pid = int(key_value[0])
            break

    return running_status, sensord_pid


def stop_pmon_sensord_task(ans_host):
    """
    @summary: Stop sensord task of pmon docker if it's running.
    """
    sensord_running_status, sensord_pid = check_sensord_status(ans_host)
    if sensord_running_status:
        ans_host.command("docker exec pmon kill -SIGTERM {}".format(sensord_pid))

    sensord_running_status, sensord_pid = check_sensord_status(ans_host)
    if sensord_running_status:
        pytest_assert(False, "Failed to stop sensord task before test.")
    else:
        logging.info("sensord stopped successfully")


@pytest.fixture(scope="module")
def psu_test_setup_teardown(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Sensord task will print out error msg when detect PSU offline,
              which can cause log analyzer fail the test. So stop sensord task
              before test and restart it after all test finished.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    logging.info("Starting psu test setup")
    stop_pmon_sensord_task(duthost)

    yield

    logging.info("Starting psu test teardown")
    sensord_running_status, sensord_pid = check_sensord_status(duthost)
    if not sensord_running_status:
        duthost.command("docker exec pmon supervisorctl restart lm-sensors")
        time.sleep(3)
        sensord_running_status, sensord_pid = check_sensord_status(duthost)
        if sensord_running_status:
            logging.info("sensord task restarted, pid = {}".format(sensord_pid))
        else:
            pytest_assert(False, "Failed to restart sensord task after test.")
    else:
        logging.info("sensord is running, pid = {}".format(sensord_pid))


@pytest.fixture(scope="function")
def ignore_particular_error_log(request, duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix='turn_on_off_psu_and_check_psustatus')
    loganalyzer.load_common_config()

    ignore_list = request.param
    loganalyzer.ignore_regex.extend(ignore_list)
    marker = loganalyzer.init()

    yield

    loganalyzer.analyze(marker)


def get_psu_num(dut):
    cmd_num_psu = "sudo psuutil numpsus"

    logging.info("Check whether the DUT has enough PSUs for this testing")
    psu_num_out = dut.command(cmd_num_psu)
    psu_num = 0
    try:
        psu_num = int(psu_num_out["stdout"])
    except Exception as e:
        pytest_assert(False, "Unable to get the number of PSUs using command '{}' with exception {}".format(cmd_num_psu, repr(e)))

    return psu_num

def get_healthy_psu_num(duthost):
    """
        @Summary: get number of healthy PSUs
        @param: DUT host instance
        @return: Number of healthy PSUs
    """
    PSUUTIL_CMD = "sudo psuutil status"
    healthy_psus = 0
    psuutil_status_output = duthost.command(PSUUTIL_CMD)

    psus_status = psuutil_status_output["stdout_lines"][2:]
    for iter in psus_status:
        fields = iter.split()
        if fields[2] == 'OK':
            healthy_psus += 1

    return healthy_psus


def check_vendor_specific_psustatus(dut, psu_status_line, psu_line_pattern):
    """
    @summary: Vendor specific psu status check
    """
    if dut.facts["asic_type"] in ["mellanox"]:
        from .mellanox.check_sysfs import check_psu_sysfs

        psu_match = psu_line_pattern.match(psu_status_line)
        psu_id = psu_match.group(1)
        psu_status = psu_match.group(2)

        check_psu_sysfs(dut, psu_id, psu_status)


def turn_all_outlets_on(pdu_ctrl):
    all_outlet_status = pdu_ctrl.get_outlet_status()
    pytest_require(all_outlet_status and len(all_outlet_status) >= 2, 'Skip the test, cannot to get at least 2 outlet status: {}'.format(all_outlet_status))
    for outlet in all_outlet_status:
        if not outlet["outlet_on"]:
            pdu_ctrl.turn_on_outlet(outlet)
            time.sleep(5)


def check_all_psu_on(dut, psu_test_results):
    """
        @summary: check all PSUs are in 'OK' status.
        @param dut: dut host instance.
        @param psu_test_results: dictionary of all PSU names, values are not important.
    """
    power_off_psu_list = []

    if "201811" in dut.os_version or "201911" in dut.os_version:
        cli_psu_status = dut.command(CMD_PLATFORM_PSUSTATUS)
        for line in cli_psu_status["stdout_lines"][2:]:
            fields = line.split()
            psu_test_results[fields[1]] = line
            if " ".join(fields[2:]) == "NOT OK":
                power_off_psu_list.append(fields[1])
    else:
        # Use JSON output
        cli_psu_status = dut.command(CMD_PLATFORM_PSUSTATUS_JSON)
        psu_info_list = json.loads(cli_psu_status["stdout"])
        for psu_info in psu_info_list:
            psu_test_results[psu_info['name']] = psu_info
            if psu_info["status"] == "NOT OK":
                power_off_psu_list.append(psu_info["index"])

    if power_off_psu_list:
        logging.warn('Powered off PSUs: {}'.format(power_off_psu_list))

    return len(power_off_psu_list) == 0


@pytest.mark.disable_loganalyzer
@pytest.mark.parametrize('ignore_particular_error_log', [SKIP_ERROR_LOG_PSU_ABSENCE], indirect=True)
def test_turn_on_off_psu_and_check_psustatus(duthosts, enum_rand_one_per_hwsku_hostname, pdu_controller, ignore_particular_error_log, tbinfo):
    """
    @summary: Turn off/on PSU and check PSU status using 'show platform psustatus'
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    psu_line_pattern = get_dut_psu_line_pattern(duthost)

    psu_num = get_healthy_psu_num(duthost)
    pytest_require(psu_num >= 2, "At least 2 PSUs required for rest of the testing in this case")

    logging.info("Create PSU controller for testing")
    pdu_ctrl = pdu_controller
    pytest_require(pdu_ctrl, "No PSU controller for %s, skip rest of the testing in this case" % duthost.hostname)

    logging.info("To avoid DUT being shutdown, need to turn on PSUs that are not powered")
    turn_all_outlets_on(pdu_ctrl)

    logging.info("Initialize test results")
    psu_test_results = {}
    pytest_require(check_all_psu_on(duthost, psu_test_results), "Some PSU are still down, skip rest of the testing in this case")

    pytest_assert(len(psu_test_results.keys()) == psu_num, \
        "In consistent PSU number output by '%s' and '%s'" % (CMD_PLATFORM_PSUSTATUS, "sudo psuutil numpsus"))

    logging.info("Start testing turn off/on PSUs")
    all_outlet_status = pdu_ctrl.get_outlet_status()
    pytest_require(all_outlet_status and len(all_outlet_status) >= 2, 'Skip the test, cannot get at least 2 outlet status: {}'.format(all_outlet_status))
    if tbinfo["topo"]["properties"]["configuration_properties"]["common"]["dut_type"] == "MgmtTsToR":
        all_outlet_status = all_outlet_status[0:-2]
        logging.info("DUT is MgmtTsToR, the last 2 outlets are reserved for Console Switch and are not visible from DUT.")
    for outlet in all_outlet_status:
        psu_under_test = None

        logging.info("Turn off outlet {}".format(outlet))
        pdu_ctrl.turn_off_outlet(outlet)
        time.sleep(5)

        cli_psu_status = duthost.command(CMD_PLATFORM_PSUSTATUS)
        for line in cli_psu_status["stdout_lines"][2:]:
            psu_match = psu_line_pattern.match(line)
            pytest_assert(psu_match, "Unexpected PSU status output")
            if psu_match.group(2) != "OK":
                psu_under_test = psu_match.group(1)
            check_vendor_specific_psustatus(duthost, line, psu_line_pattern)
        pytest_assert(psu_under_test is not None, "No PSU is turned off")

        logging.info("Turn on outlet {}".format(outlet))
        pdu_ctrl.turn_on_outlet(outlet)
        time.sleep(5)

        cli_psu_status = duthost.command(CMD_PLATFORM_PSUSTATUS)
        for line in cli_psu_status["stdout_lines"][2:]:
            psu_match = psu_line_pattern.match(line)
            pytest_assert(psu_match, "Unexpected PSU status output")
            if psu_match.group(1) == psu_under_test:
                pytest_assert(psu_match.group(2) == "OK", "Unexpected PSU status after turned it on")
            check_vendor_specific_psustatus(duthost, line, psu_line_pattern)

        psu_test_results[psu_under_test] = True

    for psu in psu_test_results:
        pytest_assert(psu_test_results[psu], "Test psu status of PSU %s failed" % psu)


@pytest.mark.disable_loganalyzer
def test_show_platform_fanstatus_mocked(duthosts, enum_rand_one_per_hwsku_hostname, mocker_factory, disable_thermal_policy):
    """
    @summary: Check output of 'show platform fan'.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    # Mock data and check
    mocker = mocker_factory(duthost, 'FanStatusMocker')
    pytest_require(mocker, "No FanStatusMocker for %s, skip rest of the testing in this case" % duthost.facts['asic_type'])

    logging.info('Mock FAN status data...')
    mocker.mock_data()
    logging.info('Wait and check actual data with mocked FAN status data...')
    retry_call(check_cli_output_with_mocker, fargs=[duthost, mocker, CMD_PLATFORM_FANSTATUS, THERMAL_CONTROL_TEST_WAIT_TIME, 2], tries=3, delay=30)




@pytest.mark.disable_loganalyzer
@pytest.mark.parametrize('ignore_particular_error_log', [SKIP_ERROR_LOG_SHOW_PLATFORM_TEMP], indirect=True)
def test_show_platform_temperature_mocked(duthosts, enum_rand_one_per_hwsku_hostname, mocker_factory, ignore_particular_error_log):
    """
    @summary: Check output of 'show platform temperature'
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    # Mock data and check
    mocker = mocker_factory(duthost, 'ThermalStatusMocker')
    pytest_require(mocker, "No ThermalStatusMocker for %s, skip rest of the testing in this case" % duthost.facts['asic_type'])

    logging.info('Mock Thermal status data...')
    mocker.mock_data()
    logging.info('Wait and check actual data with mocked Thermal status data...')
    retry_call(check_cli_output_with_mocker, fargs=[duthost, mocker, CMD_PLATFORM_TEMPER, THERMAL_CONTROL_TEST_WAIT_TIME], tries=3, delay=30)


@pytest.mark.disable_loganalyzer
def test_thermal_control_load_invalid_format_json(duthosts, enum_rand_one_per_hwsku_hostname, thermal_manager_enabled):
    """
    @summary: Load a thermal policy file with invalid format, check thermal
              control daemon is up and there is an error log printed
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    logging.info('Loading invalid format policy file...')
    check_thermal_control_load_invalid_file(duthost, THERMAL_POLICY_INVALID_FORMAT_FILE)


@pytest.mark.disable_loganalyzer
def test_thermal_control_load_invalid_value_json(duthosts, enum_rand_one_per_hwsku_hostname, thermal_manager_enabled):
    """
    @summary: Load a thermal policy file with invalid value, check thermal
              control daemon is up and there is an error log printed
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    logging.info('Loading invalid value policy file...')
    check_thermal_control_load_invalid_file(duthost, THERMAL_POLICY_INVALID_VALUE_FILE)


def check_thermal_control_load_invalid_file(duthost, file_name):
    """
    @summary: Load an invalid thermal policy file check thermal
              control daemon is up and there is an error log printed
    """
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix='thermal_control')
    loganalyzer.expect_regex = [LOG_EXPECT_POLICY_FILE_INVALID]
    with loganalyzer:
        with ThermalPolicyFileContext(duthost, file_name):
            restart_thermal_control_daemon(duthost)


@pytest.mark.disable_loganalyzer
def test_thermal_control_fan_status(duthosts, enum_rand_one_per_hwsku_hostname, mocker_factory):
    """
    @summary: Make FAN absence, over speed and under speed, check logs and LED color.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix='thermal_control')
    loganalyzer.load_common_config()

    with ThermalPolicyFileContext(duthost, THERMAL_POLICY_VALID_FILE):
        fan_mocker = mocker_factory(duthost, 'FanStatusMocker')
        pytest_require(fan_mocker, "No FanStatusMocker for %s, skip rest of the testing in this case" % duthost.facts['asic_type'])

        logging.info('Mock FAN status data...')
        fan_mocker.mock_data()  # make data random
        restart_thermal_control_daemon(duthost)
        wait_until(THERMAL_CONTROL_TEST_WAIT_TIME, THERMAL_CONTROL_TEST_CHECK_INTERVAL, 0, fan_mocker.check_all_fan_speed,
                   60)
        check_thermal_algorithm_status(duthost, mocker_factory, False)

        single_fan_mocker = mocker_factory(duthost, 'SingleFanMocker')
        time.sleep(THERMAL_CONTROL_TEST_WAIT_TIME)
        if "201811" in duthost.os_version or "201911" in duthost.os_version:
            THERMALCTLD_PATH = '/usr/bin/thermalctld'
        else:
            THERMALCTLD_PATH = '/usr/local/bin/thermalctld'

        _fan_log_supported = duthost.command('docker exec pmon grep -E "{}" {}'\
                .format(LOG_EXPECT_INSUFFICIENT_FAN_NUM_RE, THERMALCTLD_PATH), module_ignore_errors=True)

        if single_fan_mocker.is_fan_removable():
            loganalyzer.expect_regex = [LOG_EXPECT_FAN_REMOVE_RE, LOG_EXPECT_INSUFFICIENT_FAN_NUM_RE]
            if _fan_log_supported.is_failed:
                loganalyzer.expect_regex.remove(LOG_EXPECT_INSUFFICIENT_FAN_NUM_RE)
            with loganalyzer:
                logging.info('Mocking an absence FAN...')
                single_fan_mocker.mock_absence()
                check_cli_output_with_mocker(duthost, single_fan_mocker, CMD_PLATFORM_FANSTATUS, THERMAL_CONTROL_TEST_WAIT_TIME, 2)

            loganalyzer.expect_regex = [LOG_EXPECT_FAN_REMOVE_CLEAR_RE, LOG_EXPECT_INSUFFICIENT_FAN_NUM_CLEAR_RE]
            if _fan_log_supported.is_failed:
                loganalyzer.expect_regex.remove(LOG_EXPECT_INSUFFICIENT_FAN_NUM_CLEAR_RE)
            with loganalyzer:
                logging.info('Make the absence FAN back to presence...')
                single_fan_mocker.mock_presence()
                check_cli_output_with_mocker(duthost, single_fan_mocker, CMD_PLATFORM_FANSTATUS, THERMAL_CONTROL_TEST_WAIT_TIME, 2)

        if not _fan_log_supported.is_failed:
            loganalyzer.expect_regex = [LOG_EXPECT_FAN_FAULT_RE, LOG_EXPECT_INSUFFICIENT_FAN_NUM_RE]
            with loganalyzer:
                logging.info('Mocking a fault FAN...')
                single_fan_mocker.mock_status(False)
                check_cli_output_with_mocker(duthost, single_fan_mocker, CMD_PLATFORM_FANSTATUS, THERMAL_CONTROL_TEST_WAIT_TIME, 2)

            loganalyzer.expect_regex = [LOG_EXPECT_FAN_FAULT_CLEAR_RE, LOG_EXPECT_INSUFFICIENT_FAN_NUM_CLEAR_RE]
            with loganalyzer:
                logging.info('Mocking the fault FAN back to normal...')
                single_fan_mocker.mock_status(True)
                check_cli_output_with_mocker(duthost, single_fan_mocker, CMD_PLATFORM_FANSTATUS, THERMAL_CONTROL_TEST_WAIT_TIME, 2)

        loganalyzer.expect_regex = [LOG_EXPECT_FAN_OVER_SPEED_RE]
        with loganalyzer:
            logging.info('Mocking an over speed FAN...')
            single_fan_mocker.mock_over_speed()
            check_cli_output_with_mocker(duthost, single_fan_mocker, CMD_PLATFORM_FANSTATUS, THERMAL_CONTROL_TEST_WAIT_TIME, 2)

        loganalyzer.expect_regex = [LOG_EXPECT_FAN_OVER_SPEED_CLEAR_RE]
        with loganalyzer:
            logging.info('Make the over speed FAN back to normal...')
            single_fan_mocker.mock_normal_speed()
            check_cli_output_with_mocker(duthost, single_fan_mocker, CMD_PLATFORM_FANSTATUS, THERMAL_CONTROL_TEST_WAIT_TIME, 2)

        loganalyzer.expect_regex = [LOG_EXPECT_FAN_UNDER_SPEED_RE]
        with loganalyzer:
            logging.info('Mocking an under speed FAN...')
            single_fan_mocker.mock_under_speed()
            check_cli_output_with_mocker(duthost, single_fan_mocker, CMD_PLATFORM_FANSTATUS, THERMAL_CONTROL_TEST_WAIT_TIME, 2)

        loganalyzer.expect_regex = [LOG_EXPECT_FAN_UNDER_SPEED_CLEAR_RE]
        with loganalyzer:
            logging.info('Make the under speed FAN back to normal...')
            single_fan_mocker.mock_normal_speed()
            check_cli_output_with_mocker(duthost, single_fan_mocker, CMD_PLATFORM_FANSTATUS, THERMAL_CONTROL_TEST_WAIT_TIME, 2)
