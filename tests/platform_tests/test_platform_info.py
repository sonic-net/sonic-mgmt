"""
Check platform information

This script covers the test case 'Check platform information' in the SONiC platform test plan:
https://github.com/Azure/SONiC/blob/master/doc/pmon/sonic_platform_test_plan.md
"""
import logging
import re
import time

import pytest

from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError
from tests.common.utilities import wait_until
from thermal_control_test_helper import *

pytestmark = [
    pytest.mark.topology('any')
]

CMD_PLATFORM_PSUSTATUS = "show platform psustatus"
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
        assert False, "Failed to stop sensord task before test."
    else:
        logging.info("sensord stopped successfully")


@pytest.fixture(scope="module")
def psu_test_setup_teardown(duthost):
    """
    @summary: Sensord task will print out error msg when detect PSU offline,
              which can cause log analyzer fail the test. So stop sensord task
              before test and restart it after all test finished.
    """
    logging.info("Starting psu test setup")
    stop_pmon_sensord_task(duthost)

    yield

    logging.info("Starting psu test teardown")
    sensord_running_status, sensord_pid = check_sensord_status(duthost)
    if not sensord_running_status:
        ans_host.command("docker exec pmon supervisorctl restart lm-sensors")
        time.sleep(3)
        sensord_running_status, sensord_pid = check_sensord_status(duthost)
        if sensord_running_status:
            logging.info("sensord task restarted, pid = {}".format(sensord_pid))
        else:
            assert False, "Failed to restart sensord task after test."
    else:
        logging.info("sensord is running, pid = {}".format(sensord_pid))


def get_psu_num(dut):
    cmd_num_psu = "sudo psuutil numpsus"

    logging.info("Check whether the DUT has enough PSUs for this testing")
    psu_num_out = dut.command(cmd_num_psu)
    psu_num = 0
    try:
        psu_num = int(psu_num_out["stdout"])
    except:
        assert False, "Unable to get the number of PSUs using command '%s'" % cmd_num_psu

    return psu_num


def check_vendor_specific_psustatus(dut, psu_status_line):
    """
    @summary: Vendor specific psu status check
    """
    if dut.facts["asic_type"] in ["mellanox"]:
        from .mellanox.check_sysfs import check_psu_sysfs

        psu_line_pattern = re.compile(r"PSU\s+(\d)+\s+(OK|NOT OK|NOT PRESENT)")
        psu_match = psu_line_pattern.match(psu_status_line)
        psu_id = psu_match.group(1)
        psu_status = psu_match.group(2)

        check_psu_sysfs(dut, psu_id, psu_status)


def turn_all_psu_on(psu_ctrl):
    all_psu_status = psu_ctrl.get_psu_status()
    if all_psu_status:
        for psu in all_psu_status:
            if not psu["psu_on"]:
                psu_ctrl.turn_on_psu(psu["psu_id"])
                time.sleep(5)


def check_all_psu_on(dut, psu_test_results):
    cli_psu_status = dut.command(CMD_PLATFORM_PSUSTATUS)
    power_off_psu_list = []
    for line in cli_psu_status["stdout_lines"][2:]:
        fields = line.split()
        psu_test_results[fields[1]] = False
        if " ".join(fields[2:]) == "NOT OK":
            power_off_psu_list.append(fields[1])

    if power_off_psu_list:
        logging.warn('Power off PSU list: {}'.format(power_off_psu_list))

    return len(power_off_psu_list) == 0


@pytest.mark.disable_loganalyzer
def test_turn_on_off_psu_and_check_psustatus(duthost, psu_controller):
    """
    @summary: Turn off/on PSU and check PSU status using 'show platform psustatus'
    """
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix='turn_on_off_psu_and_check_psustatus')
    loganalyzer.load_common_config()

    loganalyzer.ignore_regex.append("Error getting sensor data: dps460.*Kernel interface error")
    marker = loganalyzer.init()

    psu_line_pattern = re.compile(r"PSU\s+\d+\s+(OK|NOT OK|NOT PRESENT)")

    psu_num = get_psu_num(duthost)
    if psu_num < 2:
        pytest.skip("At least 2 PSUs required for rest of the testing in this case")

    logging.info("Create PSU controller for testing")
    psu_ctrl = psu_controller
    if psu_ctrl is None:
        pytest.skip("No PSU controller for %s, skip rest of the testing in this case" % duthost.hostname)

    logging.info("To avoid DUT being shutdown, need to turn on PSUs that are not powered")
    turn_all_psu_on(psu_ctrl)

    logging.info("Initialize test results")
    psu_test_results = {}
    if not check_all_psu_on(duthost, psu_test_results):
        pytest.skip("Some PSU are still down, skip rest of the testing in this case")

    assert len(psu_test_results.keys()) == psu_num, \
        "In consistent PSU number output by '%s' and '%s'" % (CMD_PLATFORM_PSUSTATUS, cmd_num_psu)

    logging.info("Start testing turn off/on PSUs")
    all_psu_status = psu_ctrl.get_psu_status()
    for psu in all_psu_status:
        psu_under_test = None

        logging.info("Turn off PSU %s" % str(psu["psu_id"]))
        psu_ctrl.turn_off_psu(psu["psu_id"])
        time.sleep(5)

        cli_psu_status = duthost.command(CMD_PLATFORM_PSUSTATUS)
        for line in cli_psu_status["stdout_lines"][2:]:
            assert psu_line_pattern.match(line), "Unexpected PSU status output"
            fields = line.split()
            if fields[2] != "OK":
                psu_under_test = fields[1]
            check_vendor_specific_psustatus(duthost, line)
        assert psu_under_test is not None, "No PSU is turned off"

        logging.info("Turn on PSU %s" % str(psu["psu_id"]))
        psu_ctrl.turn_on_psu(psu["psu_id"])
        time.sleep(5)

        cli_psu_status = duthost.command(CMD_PLATFORM_PSUSTATUS)
        for line in cli_psu_status["stdout_lines"][2:]:
            assert psu_line_pattern.match(line), "Unexpected PSU status output"
            fields = line.split()
            if fields[1] == psu_under_test:
                assert fields[2] == "OK", "Unexpected PSU status after turned it on"
            check_vendor_specific_psustatus(duthost, line)

        psu_test_results[psu_under_test] = True

    for psu in psu_test_results:
        assert psu_test_results[psu], "Test psu status of PSU %s failed" % psu

    loganalyzer.analyze(marker)


def test_show_platform_fanstatus_mocked(duthost, mocker_factory):
    """
    @summary: Check output of 'show platform fan'.
    """
    # Mock data and check
    mocker = mocker_factory(duthost, 'FanStatusMocker')
    if mocker is None:
        pytest.skip("No FanStatusMocker for %s, skip rest of the testing in this case" % duthost.facts['asic_type'])

    logging.info('Mock FAN status data...')
    mocker.mock_data()
    logging.info('Wait and check actual data with mocked FAN status data...')
    result = check_cli_output_with_mocker(duthost, mocker, CMD_PLATFORM_FANSTATUS, THERMAL_CONTROL_TEST_WAIT_TIME, 2)

    assert result, 'FAN mock data mismatch'


def test_show_platform_temperature_mocked(duthost, mocker_factory):
    """
    @summary: Check output of 'show platform temperature'
    """
    # Mock data and check
    mocker = mocker_factory(duthost, 'ThermalStatusMocker')
    if mocker is None:
        pytest.skip("No ThermalStatusMocker for %s, skip rest of the testing in this case" % duthost.facts['asic_type'])

    logging.info('Mock Thermal status data...')
    mocker.mock_data()
    logging.info('Wait and check actual data with mocked Thermal status data...')
    result = check_cli_output_with_mocker(duthost, mocker, CMD_PLATFORM_TEMPER, THERMAL_CONTROL_TEST_WAIT_TIME)

    assert result, 'Thermal mock data mismatch'


@pytest.mark.disable_loganalyzer
def test_thermal_control_load_invalid_format_json(duthost):
    """
    @summary: Load a thermal policy file with invalid format, check thermal
              control daemon is up and there is an error log printed
    """
    logging.info('Loading invalid format policy file...')
    check_thermal_control_load_invalid_file(duthost, THERMAL_POLICY_INVALID_FORMAT_FILE)


@pytest.mark.disable_loganalyzer
def test_thermal_control_load_invalid_value_json(duthost):
    """
    @summary: Load a thermal policy file with invalid value, check thermal
              control daemon is up and there is an error log printed
    """
    logging.info('Loading invalid value policy file...')
    check_thermal_control_load_invalid_file(duthost, THERMAL_POLICY_INVALID_VALUE_FILE)


def check_thermal_control_load_invalid_file(duthost, file_name):
    """
    @summary: Load an invalid thermal policy file check thermal
              control daemon is up and there is an error log printed
    """
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix='thermal_control')
    with ThermalPolicyFileContext(duthost, file_name):
        loganalyzer.expect_regex = [LOG_EXPECT_POLICY_FILE_INVALID]
        with loganalyzer:
            restart_thermal_control_daemon(duthost)


def test_thermal_control_psu_absence(duthost, psu_controller, mocker_factory):
    """
    @summary: Turn off/on PSUs, check thermal control is working as expect.
    """
    psu_num = get_psu_num(duthost)
    if psu_num < 2:
        pytest.skip("At least 2 PSUs required for rest of the testing in this case")

    logging.info("Create PSU controller for testing")
    psu_ctrl = psu_controller
    if psu_ctrl is None:
        pytest.skip("No PSU controller for %s, skip rest of the testing in this case" % duthost.hostname)

    logging.info("To avoid DUT being shutdown, need to turn on PSUs that are not powered")
    turn_all_psu_on(psu_ctrl)

    logging.info("Initialize test results")
    psu_test_results = {}
    if not check_all_psu_on(duthost, psu_test_results):
        pytest.skip("Some PSU are still down, skip rest of the testing in this case")

    with ThermalPolicyFileContext(duthost, THERMAL_POLICY_VALID_FILE):
        fan_mocker = mocker_factory(duthost, 'FanStatusMocker')
        if fan_mocker is None:
            pytest.skip("No FanStatusMocker for %s, skip rest of the testing in this case" % duthost.facts['asic_type'])

        restart_thermal_control_daemon(duthost)
        logging.info('Wait and check all FAN speed turn to 60%...')
        wait_result = wait_until(THERMAL_CONTROL_TEST_WAIT_TIME,
                                 THERMAL_CONTROL_TEST_CHECK_INTERVAL,
                                 fan_mocker.check_all_fan_speed,
                                 60)
        if not wait_result:
             pytest.skip("FAN speed is not 60%, there might be abnormal in FAN/PSU, skip rest of the testing in this case")

        check_thermal_algorithm_status(duthost, mocker_factory, False)

        logging.info('Shutdown first PSU and check thermal control result...')
        all_psu_status = psu_ctrl.get_psu_status()
        psu = all_psu_status[0]
        turn_off_psu_and_check_thermal_control(duthost, psu_ctrl, psu, fan_mocker)
        psu_test_results.clear()
        if not check_all_psu_on(duthost, psu_test_results):
            pytest.skip("Some PSU are still down, skip rest of the testing in this case")

        logging.info('Shutdown second PSU and check thermal control result...')
        psu = all_psu_status[1]
        turn_off_psu_and_check_thermal_control(duthost, psu_ctrl, psu, fan_mocker)
        psu_test_results.clear()
        if not check_all_psu_on(duthost, psu_test_results):
            pytest.skip("Some PSU are still down, skip rest of the testing in this case")

        logging.info('Wait and check all FAN speed turn to 65%...')
        assert wait_until(THERMAL_CONTROL_TEST_WAIT_TIME,
                          THERMAL_CONTROL_TEST_CHECK_INTERVAL,
                          fan_mocker.check_all_fan_speed,
                          65), 'FAN speed not change to 65% according to policy'


def turn_off_psu_and_check_thermal_control(dut, psu_ctrl, psu, mocker):
    """
    @summary: Turn off PSUs, check all FAN speed are set to 100% according to thermal
              control policy file.
    """
    logging.info("Turn off PSU %s" % str(psu["psu_id"]))
    psu_ctrl.turn_off_psu(psu["psu_id"])
    time.sleep(5)

    psu_under_test = None
    psu_line_pattern = re.compile(r"PSU\s+\d+\s+(OK|NOT OK|NOT PRESENT)")
    cli_psu_status = dut.command(CMD_PLATFORM_PSUSTATUS)
    for line in cli_psu_status["stdout_lines"][2:]:
        assert psu_line_pattern.match(line), "Unexpected PSU status output"
        fields = line.split()
        if fields[2] != "OK":
            psu_under_test = fields[1]

    assert psu_under_test is not None, "No PSU is turned off"
    logging.info('Wait and check all FAN speed turn to 100%...')
    assert wait_until(THERMAL_CONTROL_TEST_WAIT_TIME,
                      THERMAL_CONTROL_TEST_CHECK_INTERVAL,
                      mocker.check_all_fan_speed,
                      100), 'FAN speed not turn to 100% after PSU off'

    psu_ctrl.turn_on_psu(psu["psu_id"])
    time.sleep(5)


@pytest.mark.disable_loganalyzer
def test_thermal_control_fan_status(duthost, mocker_factory):
    """
    @summary: Make FAN absence, over speed and under speed, check logs and LED color.
    """
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix='thermal_control')
    loganalyzer.load_common_config()

    with ThermalPolicyFileContext(duthost, THERMAL_POLICY_VALID_FILE):
        fan_mocker = mocker_factory(duthost, 'FanStatusMocker')
        if fan_mocker is None:
            pytest.skip("No FanStatusMocker for %s, skip rest of the testing in this case" % duthost.facts['asic_type'])

        logging.info('Mock FAN status data...')
        fan_mocker.mock_data()  # make data random
        restart_thermal_control_daemon(duthost)
        wait_until(THERMAL_CONTROL_TEST_WAIT_TIME, THERMAL_CONTROL_TEST_CHECK_INTERVAL, fan_mocker.check_all_fan_speed,
                   60)
        check_thermal_algorithm_status(duthost, mocker_factory, False)

        single_fan_mocker = mocker_factory(duthost, 'SingleFanMocker')
        time.sleep(THERMAL_CONTROL_TEST_WAIT_TIME)

        if single_fan_mocker.is_fan_removable():
            loganalyzer.expect_regex = [LOG_EXPECT_FAN_REMOVE_RE, LOG_EXPECT_INSUFFICIENT_FAN_NUM_RE]
            with loganalyzer:
                logging.info('Mocking an absence FAN...')
                single_fan_mocker.mock_absence()
                check_cli_output_with_mocker(duthost, single_fan_mocker, CMD_PLATFORM_FANSTATUS, THERMAL_CONTROL_TEST_WAIT_TIME, 2)

            loganalyzer.expect_regex = [LOG_EXPECT_FAN_REMOVE_CLEAR_RE, LOG_EXPECT_INSUFFICIENT_FAN_NUM_CLEAR_RE]
            with loganalyzer:
                logging.info('Make the absence FAN back to presence...')
                single_fan_mocker.mock_presence()
                check_cli_output_with_mocker(duthost, single_fan_mocker, CMD_PLATFORM_FANSTATUS, THERMAL_CONTROL_TEST_WAIT_TIME, 2)

        loganalyzer.expect_regex = [LOG_EXPECT_FAN_FAULT_RE, LOG_EXPECT_INSUFFICIENT_FAN_NUM_RE]
        with loganalyzer:
            logging.info('Mocking a fault FAN...')
            single_fan_mocker.mock_status(False)
            check_cli_output_with_mocker(dut, single_fan_mocker, CMD_PLATFORM_FANSTATUS, THERMAL_CONTROL_TEST_WAIT_TIME, 2)

        loganalyzer.expect_regex = [LOG_EXPECT_FAN_FAULT_CLEAR_RE, LOG_EXPECT_INSUFFICIENT_FAN_NUM_CLEAR_RE]
        with loganalyzer:
            logging.info('Mocking the fault FAN back to normal...')
            single_fan_mocker.mock_status(True)
            check_cli_output_with_mocker(dut, single_fan_mocker, CMD_PLATFORM_FANSTATUS, THERMAL_CONTROL_TEST_WAIT_TIME, 2)

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
