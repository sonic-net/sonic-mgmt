"""
Check platform information

This script covers the test case 'Check platform information' in the SONiC platform test plan:
https://github.com/Azure/SONiC/blob/master/doc/pmon/sonic_platform_test_plan.md
"""
import json
import logging
import re
import time

import pytest

from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError
from tests.common.utilities import wait_until
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

SKIP_ERROR_LOG_SHOW_PLATFORM_TEMP = ['.*ERR pmon#thermalctld.*int\(\) argument must be a string.* or a number.*',
                                     '.*ERR pmon#thermalctld.*invalid literal for int\(\) with base 10.*']

SKIP_ERROR_LOG_PSU_ABSENCE = ['.*Error getting sensor data: dps460.*Kernel interface error.*']


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
def psu_test_setup_teardown(duthosts, rand_one_dut_hostname):
    """
    @summary: Sensord task will print out error msg when detect PSU offline,
              which can cause log analyzer fail the test. So stop sensord task
              before test and restart it after all test finished.
    """
    duthost = duthosts[rand_one_dut_hostname]
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
def ignore_particular_error_log(request, duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
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


def get_dut_psu_line_pattern(dut):
    if "201811" in dut.os_version or "201911" in dut.os_version:
        psu_line_pattern = re.compile(r"PSU\s+(\d)+\s+(OK|NOT OK|NOT PRESENT)")
    else:
        """
        Changed the pattern to match space (s+) and non-space (S+) only.
        w+ cannot match following examples properly:

        example 1:
            PSU 1  PWR-500AC-R  L8180S01HTAVP  N/A            N/A            N/A          OK        green
            PSU 2  PWR-500AC-R  L8180S01HFAVP  N/A            N/A            N/A          OK        green
        example 2:
            PSU 1  N/A      N/A               12.05           3.38        40.62  OK        green
            PSU 2  N/A      N/A               12.01           4.12        49.50  OK        green

        """
        psu_line_pattern = re.compile(r"PSU\s+(\d+)\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(OK|NOT OK|NOT PRESENT)\s+(green|amber|red|off)")
    return psu_line_pattern


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
def test_turn_on_off_psu_and_check_psustatus(duthosts, enum_rand_one_per_hwsku_hostname, pdu_controller, ignore_particular_error_log):
    """
    @summary: Turn off/on PSU and check PSU status using 'show platform psustatus'
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    psu_line_pattern = get_dut_psu_line_pattern(duthost)

    psu_num = get_psu_num(duthost)
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
def test_show_platform_fanstatus_mocked(duthosts, rand_one_dut_hostname, mocker_factory, disable_thermal_policy):
    """
    @summary: Check output of 'show platform fan'.
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Mock data and check
    mocker = mocker_factory(duthost, 'FanStatusMocker')
    pytest_require(mocker, "No FanStatusMocker for %s, skip rest of the testing in this case" % duthost.facts['asic_type'])

    logging.info('Mock FAN status data...')
    mocker.mock_data()
    logging.info('Wait and check actual data with mocked FAN status data...')
    result = check_cli_output_with_mocker(duthost, mocker, CMD_PLATFORM_FANSTATUS, THERMAL_CONTROL_TEST_WAIT_TIME, 2)

    pytest_assert(result, 'FAN mock data mismatch')


@pytest.mark.disable_loganalyzer
@pytest.mark.parametrize('ignore_particular_error_log', [SKIP_ERROR_LOG_SHOW_PLATFORM_TEMP], indirect=True)
def test_show_platform_temperature_mocked(duthosts, rand_one_dut_hostname, mocker_factory, ignore_particular_error_log):
    """
    @summary: Check output of 'show platform temperature'
    """
    duthost = duthosts[rand_one_dut_hostname]
    # Mock data and check
    mocker = mocker_factory(duthost, 'ThermalStatusMocker')
    pytest_require(mocker, "No ThermalStatusMocker for %s, skip rest of the testing in this case" % duthost.facts['asic_type'])

    logging.info('Mock Thermal status data...')
    mocker.mock_data()
    logging.info('Wait and check actual data with mocked Thermal status data...')
    result = check_cli_output_with_mocker(duthost, mocker, CMD_PLATFORM_TEMPER, THERMAL_CONTROL_TEST_WAIT_TIME)

    pytest_assert(result, 'Thermal mock data mismatch')


@pytest.mark.disable_loganalyzer
def test_thermal_control_load_invalid_format_json(duthosts, rand_one_dut_hostname):
    """
    @summary: Load a thermal policy file with invalid format, check thermal
              control daemon is up and there is an error log printed
    """
    duthost = duthosts[rand_one_dut_hostname]
    logging.info('Loading invalid format policy file...')
    check_thermal_control_load_invalid_file(duthost, THERMAL_POLICY_INVALID_FORMAT_FILE)


@pytest.mark.disable_loganalyzer
def test_thermal_control_load_invalid_value_json(duthosts, rand_one_dut_hostname):
    """
    @summary: Load a thermal policy file with invalid value, check thermal
              control daemon is up and there is an error log printed
    """
    duthost = duthosts[rand_one_dut_hostname]
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
@pytest.mark.parametrize('ignore_particular_error_log', [SKIP_ERROR_LOG_PSU_ABSENCE], indirect=True)
def test_thermal_control_psu_absence(duthosts, enum_rand_one_per_hwsku_hostname, pdu_controller, mocker_factory, ignore_particular_error_log):
    """
    @summary: Turn off/on PSUs, check thermal control is working as expect.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    psu_num = get_psu_num(duthost)
    
    pytest_require(psu_num >= 2, "At least 2 PSUs required for rest of the testing in this case")

    logging.info("Create PDU controller for testing")
    pdu_ctrl = pdu_controller

    pytest_require(pdu_ctrl, "No PDU controller for %s, skip rest of the testing in this case" % duthost.hostname)

    logging.info("To avoid DUT being shutdown, need to turn on PSUs that are not powered")
    turn_all_outlets_on(pdu_ctrl)

    logging.info("Initialize test results")
    psu_test_results = {}
    pytest_require(check_all_psu_on(duthost, psu_test_results), "Some PSU are still down, skip rest of the testing in this case")

    with ThermalPolicyFileContext(duthost, THERMAL_POLICY_VALID_FILE):
        fan_mocker = mocker_factory(duthost, 'FanStatusMocker')
        pytest_require(fan_mocker, "No FanStatusMocker for %s, skip rest of the testing in this case" % duthost.facts['asic_type'])

        restart_thermal_control_daemon(duthost)
        logging.info('Wait and check all FAN speed turn to 60%...')
        wait_result = wait_until(THERMAL_CONTROL_TEST_WAIT_TIME,
                                 THERMAL_CONTROL_TEST_CHECK_INTERVAL,
                                 fan_mocker.check_all_fan_speed,
                                 60)

        pytest_require(wait_result, "FAN speed is not 60%, there might be abnormal in FAN/PSU, skip rest of the testing in this case")

        check_thermal_algorithm_status(duthost, mocker_factory, False)

        logging.info('Shutdown first PDU outlet and check thermal control result...')
        all_outlet_status = pdu_ctrl.get_outlet_status()
        pytest_require(all_outlet_status and len(all_outlet_status) >= 2, 'Skip the test, cannot get at least 2 outlet status: {}'.format(all_outlet_status))
        outlet = all_outlet_status[0]
        turn_off_outlet_and_check_thermal_control(duthost, pdu_ctrl, outlet, fan_mocker)
        psu_test_results.clear()
        pytest_require(check_all_psu_on(duthost, psu_test_results), "Some PSU are still down, skip rest of the testing in this case")

        logging.info('Shutdown second PDU outlet and check thermal control result...')
        outlet = all_outlet_status[1]
        turn_off_outlet_and_check_thermal_control(duthost, pdu_ctrl, outlet, fan_mocker)
        psu_test_results.clear()
        pytest_require(check_all_psu_on(duthost, psu_test_results), "Some PSU are still down, skip rest of the testing in this case")

        logging.info('Wait and check all FAN speed turn to 65%...')
        pytest_assert(wait_until(THERMAL_CONTROL_TEST_WAIT_TIME,
                                 THERMAL_CONTROL_TEST_CHECK_INTERVAL,
                                 fan_mocker.check_all_fan_speed,
                                 65), 'FAN speed not change to 65% according to policy')


def turn_off_outlet_and_check_thermal_control(dut, pdu_ctrl, outlet, mocker):
    """
    @summary: Turn off PSUs, check all FAN speed are set to 100% according to thermal
              control policy file.
    """
    logging.info("Turn off outlet %s" % str(outlet["outlet_id"]))
    pdu_ctrl.turn_off_outlet(outlet)
    time.sleep(5)

    psu_under_test = None
    psu_line_pattern = get_dut_psu_line_pattern(duthost)
    cli_psu_status = dut.command(CMD_PLATFORM_PSUSTATUS)
    for line in cli_psu_status["stdout_lines"][2:]:
        psu_match = psu_line_pattern.match(line)
        pytest_assert(psu_match, "Unexpected PSU status output")
        if psu_match.group(2) != "OK":
            psu_under_test = psu_match.group(1)

    pytest_assert(psu_under_test is not None, "No PSU is turned off")
    logging.info('Wait and check all FAN speed turn to 100%...')
    pytest_assert(wait_until(THERMAL_CONTROL_TEST_WAIT_TIME,
                             THERMAL_CONTROL_TEST_CHECK_INTERVAL,
                             mocker.check_all_fan_speed,
                             100), 'FAN speed not turn to 100% after PSU off')

    pdu_ctrl.turn_on_outlet(outlet)
    time.sleep(5)


@pytest.mark.disable_loganalyzer
def test_thermal_control_fan_status(duthosts, rand_one_dut_hostname, mocker_factory):
    """
    @summary: Make FAN absence, over speed and under speed, check logs and LED color.
    """
    duthost = duthosts[rand_one_dut_hostname]
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix='thermal_control')
    loganalyzer.load_common_config()

    with ThermalPolicyFileContext(duthost, THERMAL_POLICY_VALID_FILE):
        fan_mocker = mocker_factory(duthost, 'FanStatusMocker')
        pytest_require(fan_mocker, "No FanStatusMocker for %s, skip rest of the testing in this case" % duthost.facts['asic_type'])

        logging.info('Mock FAN status data...')
        fan_mocker.mock_data()  # make data random
        restart_thermal_control_daemon(duthost)
        wait_until(THERMAL_CONTROL_TEST_WAIT_TIME, THERMAL_CONTROL_TEST_CHECK_INTERVAL, fan_mocker.check_all_fan_speed,
                   60)
        check_thermal_algorithm_status(duthost, mocker_factory, False)

        single_fan_mocker = mocker_factory(duthost, 'SingleFanMocker')
        time.sleep(THERMAL_CONTROL_TEST_WAIT_TIME)

        _fan_log_supported = duthost.command('docker exec pmon grep -E "{}" /usr/bin/thermalctld'\
                .format(LOG_EXPECT_INSUFFICIENT_FAN_NUM_RE), module_ignore_errors=True)

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
