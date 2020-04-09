"""
Check platform information

This script covers the test case 'Check platform information' in the SONiC platform test plan:
https://github.com/Azure/SONiC/blob/master/doc/pmon/sonic_platform_test_plan.md
"""
import logging
import re
import time
import os
import sys

import pytest

from common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError
from common.utilities import wait_until
from thermal_control_test_helper import *

CMD_PLATFORM_SUMMARY = "show platform summary"
CMD_PLATFORM_PSUSTATUS = "show platform psustatus"
CMD_PLATFORM_SYSEEPROM = "show platform syseeprom"
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
def psu_test_setup_teardown(testbed_devices):
    """
    @summary: Sensord task will print out error msg when detect PSU offline,
              which can cause log analyzer fail the test. So stop sensord task
              before test and restart it after all test finished.
    """
    logging.info("Starting psu test setup")
    ans_host = testbed_devices["dut"]
    stop_pmon_sensord_task(ans_host)

    yield

    logging.info("Starting psu test teardown")
    sensord_running_status, sensord_pid = check_sensord_status(ans_host)
    if not sensord_running_status:
        ans_host.command("docker exec pmon supervisorctl restart lm-sensors")
        time.sleep(3)
        sensord_running_status, sensord_pid = check_sensord_status(ans_host)
        if sensord_running_status:
            logging.info("sensord task restarted, pid = {}".format(sensord_pid))
        else:
            assert False, "Failed to restart sensord task after test."
    else:
        logging.info("sensord is running, pid = {}".format(sensord_pid))


def test_show_platform_summary(testbed_devices):
    """
    @summary: Check output of 'show platform summary'
    """
    ans_host = testbed_devices["dut"]

    logging.info("Check output of '%s'" % CMD_PLATFORM_SUMMARY)
    platform_summary = ans_host.command(CMD_PLATFORM_SUMMARY)
    expected_fields = set(["Platform", "HwSKU", "ASIC"])
    actual_fields = set()
    for line in platform_summary["stdout_lines"]:
        key_value = line.split(":")
        assert len(key_value) == 2, "output format is not 'field_name: field_value'"
        assert len(key_value[1]) > 0, "No value for field %s" % key_value[0]
        actual_fields.add(line.split(":")[0])
    assert actual_fields == expected_fields, \
        "Unexpected output fields, actual=%s, expected=%s" % (str(actual_fields), str(expected_fields))


def check_vendor_specific_psustatus(dut, psu_status_line):
    """
    @summary: Vendor specific psu status check
    """
    if dut.facts["asic_type"] in ["mellanox"]:
        current_file_dir = os.path.dirname(os.path.realpath(__file__))
        sub_folder_dir = os.path.join(current_file_dir, "mellanox")
        if sub_folder_dir not in sys.path:
            sys.path.append(sub_folder_dir)
        from check_sysfs import check_psu_sysfs

        psu_line_pattern = re.compile(r"PSU\s+(\d)+\s+(OK|NOT OK|NOT PRESENT)")
        psu_match = psu_line_pattern.match(psu_status_line)
        psu_id = psu_match.group(1)
        psu_status = psu_match.group(2)

        check_psu_sysfs(dut, psu_id, psu_status)


def test_show_platform_psustatus(testbed_devices):
    """
    @summary: Check output of 'show platform psustatus'
    """
    ans_host = testbed_devices["dut"]

    logging.info("Check PSU status using '%s', hostname: %s" % (CMD_PLATFORM_PSUSTATUS, ans_host.hostname))
    psu_status = ans_host.command(CMD_PLATFORM_PSUSTATUS)
    psu_line_pattern = re.compile(r"PSU\s+\d+\s+(OK|NOT OK|NOT PRESENT)")
    for line in psu_status["stdout_lines"][2:]:
        assert psu_line_pattern.match(line), "Unexpected PSU status output"
        check_vendor_specific_psustatus(ans_host, line)


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


def test_turn_on_off_psu_and_check_psustatus(testbed_devices, psu_controller):
    """
    @summary: Turn off/on PSU and check PSU status using 'show platform psustatus'
    """
    ans_host = testbed_devices["dut"]

    psu_line_pattern = re.compile(r"PSU\s+\d+\s+(OK|NOT OK|NOT PRESENT)")

    psu_num = get_psu_num(ans_host)
    if psu_num < 2:
        pytest.skip("At least 2 PSUs required for rest of the testing in this case")

    logging.info("Create PSU controller for testing")
    psu_ctrl = psu_controller
    if psu_ctrl is None:
        pytest.skip("No PSU controller for %s, skip rest of the testing in this case" % ans_host.hostname)

    logging.info("To avoid DUT being shutdown, need to turn on PSUs that are not powered")
    turn_all_psu_on(psu_ctrl)

    logging.info("Initialize test results")
    psu_test_results = {}
    if not check_all_psu_on(ans_host, psu_test_results):
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

        cli_psu_status = ans_host.command(CMD_PLATFORM_PSUSTATUS)
        for line in cli_psu_status["stdout_lines"][2:]:
            assert psu_line_pattern.match(line), "Unexpected PSU status output"
            fields = line.split()
            if fields[2] != "OK":
                psu_under_test = fields[1]
            check_vendor_specific_psustatus(ans_host, line)
        assert psu_under_test is not None, "No PSU is turned off"

        logging.info("Turn on PSU %s" % str(psu["psu_id"]))
        psu_ctrl.turn_on_psu(psu["psu_id"])
        time.sleep(5)

        cli_psu_status = ans_host.command(CMD_PLATFORM_PSUSTATUS)
        for line in cli_psu_status["stdout_lines"][2:]:
            assert psu_line_pattern.match(line), "Unexpected PSU status output"
            fields = line.split()
            if fields[1] == psu_under_test:
                assert fields[2] == "OK", "Unexpected PSU status after turned it on"
            check_vendor_specific_psustatus(ans_host, line)

        psu_test_results[psu_under_test] = True

    for psu in psu_test_results:
        assert psu_test_results[psu], "Test psu status of PSU %s failed" % psu


def parse_platform_summary(raw_input_lines):
    """
    @summary: Helper function for parsing the output of 'show system platform'
    @return: Returned parsed information in a dictionary
    """
    res = {}
    for line in raw_input_lines:
        fields = line.split(":")
        if len(fields) != 2:
            continue
        res[fields[0].lower()] = fields[1].strip()
    return res


def test_show_platform_syseeprom(testbed_devices):
    """
    @summary: Check output of 'show platform syseeprom'
    """
    ans_host = testbed_devices["dut"]

    logging.info("Check output of '%s'" % CMD_PLATFORM_SYSEEPROM)
    show_output = ans_host.command(CMD_PLATFORM_SYSEEPROM)
    if ans_host.facts["asic_type"] in ["mellanox"]:
        expected_fields = [
            "Product Name",
            "Part Number",
            "Serial Number",
            "Base MAC Address",
            "Manufacture Date",
            "Device Version",
            "MAC Addresses",
            "Manufacturer",
            "Vendor Extension",
            "ONIE Version",
            "CRC-32"]
        utility_cmd = "sudo python -c \"import imp; \
            m = imp.load_source('eeprom', '/usr/share/sonic/device/%s/plugins/eeprom.py'); \
            t = m.board('board', '', '', ''); e = t.read_eeprom(); t.decode_eeprom(e)\"" % ans_host.facts["platform"]
        utility_cmd_output = ans_host.command(utility_cmd)

        for field in expected_fields:
            assert show_output["stdout"].find(field) >= 0, "Expected field %s is not found" % field
            assert utility_cmd_output["stdout"].find(field) >= 0, "Expected field %s is not found" % field

        for line in utility_cmd_output["stdout_lines"]:
            assert line in show_output["stdout"], \
                "Line %s is not found in output of '%s'" % (line, CMD_PLATFORM_SYSEEPROM)


def check_show_platform_fanstatus_output(lines):
    """
    @summary: Check basic output of 'show platform fan'. Expect output are:
              "Fan Not detected" or a table of fan status data with 8 columns.
    """
    assert len(lines) > 0, 'There must be at least one line output for show platform fans'
    if len(lines) == 1:
        assert lines[0].encode('utf-8').strip() == 'Fan Not detected'
    else:
        assert len(lines) > 2, 'There must be at least two lines output for show platform fans if any FAN is detected'
        second_line = lines[1]
        field_ranges = get_field_range(second_line)
        assert len(field_ranges) == 8, 'There must be 8 columns in output of show platform fans'


def test_show_platform_fanstatus(testbed_devices, mocker_factory):
    """
    @summary: Check output of 'show platform fan'.
    """
    # Do basic check first
    dut = testbed_devices["dut"]
    logging.info("Check output of '%s'" % CMD_PLATFORM_FANSTATUS)
    cli_fan_status = dut.command(CMD_PLATFORM_FANSTATUS)
    lines = cli_fan_status["stdout_lines"]
    check_show_platform_fanstatus_output(lines)

    # Mock data and check
    mocker = mocker_factory(dut, 'FanStatusMocker')
    if mocker is None:
        pytest.skip("No FanStatusMocker for %s, skip rest of the testing in this case" % dut.facts['asic_type'])

    logging.info('Mock FAN status data...')
    mocker.mock_data()
    logging.info('Wait and check actual data with mocked FAN status data...')
    result = check_cli_output_with_mocker(dut, mocker, CMD_PLATFORM_FANSTATUS, THERMAL_CONTROL_TEST_WAIT_TIME, 1)

    assert result, 'FAN mock data mismatch'


def check_show_platform_temperature_output(lines):
    """
    @summary: Check basic output of 'show platform temperature'. Expect output are:
              "Thermal Not detected" or a table of thermal status data with 8 columns.
    """
    assert len(lines) > 0, 'There must be at least one line output for show platform temperature'
    if len(lines) == 1:
        assert lines[0].encode('utf-8').strip() == 'Thermal Not detected'
    else:
        assert len(lines) > 2, 'There must be at least two lines output for show platform temperature if any thermal is detected'
        second_line = lines[1]
        field_ranges = get_field_range(second_line)
        assert len(field_ranges) == 8, 'There must be 8 columns in output of show platform temperature'


def test_show_platform_temperature(testbed_devices, mocker_factory):
    """
    @summary: Check output of 'show platform temperature'
    """
    # Do basic check first
    dut = testbed_devices["dut"]
    logging.info("Check output of '%s'" % CMD_PLATFORM_TEMPER)
    cli_thermal_status = dut.command(CMD_PLATFORM_TEMPER)

    # Mock data and check
    mocker = mocker_factory(dut, 'ThermalStatusMocker')
    if mocker is None:
        pytest.skip("No ThermalStatusMocker for %s, skip rest of the testing in this case" % dut.facts['asic_type'])

    logging.info('Mock Thermal status data...')
    mocker.mock_data()
    logging.info('Wait and check actual data with mocked Thermal status data...')
    result = check_cli_output_with_mocker(dut, mocker, CMD_PLATFORM_TEMPER, THERMAL_CONTROL_TEST_WAIT_TIME)

    assert result, 'Thermal mock data mismatch'


@pytest.mark.disable_loganalyzer
def test_thermal_control_load_invalid_format_json(testbed_devices):
    """
    @summary: Load a thermal policy file with invalid format, check thermal
              control daemon is up and there is an error log printed
    """
    logging.info('Loading invalid format policy file...')
    check_thermal_control_load_invalid_file(testbed_devices, THERMAL_POLICY_INVALID_FORMAT_FILE)


@pytest.mark.disable_loganalyzer
def test_thermal_control_load_invalid_value_json(testbed_devices):
    """
    @summary: Load a thermal policy file with invalid value, check thermal
              control daemon is up and there is an error log printed
    """
    logging.info('Loading invalid value policy file...')
    check_thermal_control_load_invalid_file(testbed_devices, THERMAL_POLICY_INVALID_VALUE_FILE)


def check_thermal_control_load_invalid_file(testbed_devices, file_name):
    """
    @summary: Load an invalid thermal policy file check thermal
              control daemon is up and there is an error log printed
    """
    dut = testbed_devices["dut"]
    loganalyzer = LogAnalyzer(ansible_host=dut, marker_prefix='thermal_control')
    with ThermalPolicyFileContext(dut, file_name):
        loganalyzer.expect_regex = [LOG_EXPECT_POLICY_FILE_INVALID]
        with loganalyzer:
            restart_thermal_control_daemon(dut)


def test_thermal_control_psu_absence(testbed_devices, psu_controller, mocker_factory):
    """
    @summary: Turn off/on PSUs, check thermal control is working as expect.
    """
    dut = testbed_devices["dut"]
    psu_num = get_psu_num(dut)
    if psu_num < 2:
        pytest.skip("At least 2 PSUs required for rest of the testing in this case")

    logging.info("Create PSU controller for testing")
    psu_ctrl = psu_controller
    if psu_ctrl is None:
        pytest.skip("No PSU controller for %s, skip rest of the testing in this case" % dut.hostname)

    logging.info("To avoid DUT being shutdown, need to turn on PSUs that are not powered")
    turn_all_psu_on(psu_ctrl)

    logging.info("Initialize test results")
    psu_test_results = {}
    if not check_all_psu_on(dut, psu_test_results):
        pytest.skip("Some PSU are still down, skip rest of the testing in this case")

    with ThermalPolicyFileContext(dut, THERMAL_POLICY_VALID_FILE):
        fan_mocker = mocker_factory(dut, 'FanStatusMocker')
        if fan_mocker is None:
            pytest.skip("No FanStatusMocker for %s, skip rest of the testing in this case" % dut.facts['asic_type'])

        restart_thermal_control_daemon(dut)
        logging.info('Wait and check all FAN speed turn to 60%...')
        wait_result = wait_until(THERMAL_CONTROL_TEST_WAIT_TIME,
                                 THERMAL_CONTROL_TEST_CHECK_INTERVAL,
                                 fan_mocker.check_all_fan_speed,
                                 60)
        if not wait_result:
             pytest.skip("FAN speed is not 60%, there might be abnormal in FAN/PSU, skip rest of the testing in this case")

        check_thermal_algorithm_status(dut, mocker_factory, False)

        logging.info('Shutdown first PSU and check thermal control result...')
        all_psu_status = psu_ctrl.get_psu_status()
        psu = all_psu_status[0]
        turn_off_psu_and_check_thermal_control(dut, psu_ctrl, psu, fan_mocker)
        psu_test_results.clear()
        if not check_all_psu_on(dut, psu_test_results):
            pytest.skip("Some PSU are still down, skip rest of the testing in this case")

        logging.info('Shutdown second PSU and check thermal control result...')
        psu = all_psu_status[1]
        turn_off_psu_and_check_thermal_control(dut, psu_ctrl, psu, fan_mocker)
        psu_test_results.clear()
        if not check_all_psu_on(dut, psu_test_results):
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
def test_thermal_control_fan_status(testbed_devices, mocker_factory):
    """
    @summary: Make FAN absence, over speed and under speed, check logs and LED color.
    """
    dut = testbed_devices["dut"]
    loganalyzer = LogAnalyzer(ansible_host=dut, marker_prefix='thermal_control')
    loganalyzer.load_common_config()

    with ThermalPolicyFileContext(dut, THERMAL_POLICY_VALID_FILE):
        fan_mocker = mocker_factory(dut, 'FanStatusMocker')
        if fan_mocker is None:
            pytest.skip("No FanStatusMocker for %s, skip rest of the testing in this case" % dut.facts['asic_type'])

        logging.info('Mock FAN status data...')
        fan_mocker.mock_data()  # make data random
        restart_thermal_control_daemon(dut)
        wait_until(THERMAL_CONTROL_TEST_WAIT_TIME, THERMAL_CONTROL_TEST_CHECK_INTERVAL, fan_mocker.check_all_fan_speed,
                   60)
        check_thermal_algorithm_status(dut, mocker_factory, False)

        single_fan_mocker = mocker_factory(dut, 'SingleFanMocker')
        time.sleep(THERMAL_CONTROL_TEST_WAIT_TIME)

        if single_fan_mocker.is_fan_removable():
            loganalyzer.expect_regex = [LOG_EXPECT_FAN_REMOVE_RE, LOG_EXPECT_INSUFFICIENT_FAN_NUM_RE]
            with loganalyzer:
                logging.info('Mocking an absence FAN...')
                single_fan_mocker.mock_absence()
                check_cli_output_with_mocker(dut, single_fan_mocker, CMD_PLATFORM_FANSTATUS, THERMAL_CONTROL_TEST_WAIT_TIME, 1)

            loganalyzer.expect_regex = [LOG_EXPECT_FAN_REMOVE_CLEAR_RE, LOG_EXPECT_INSUFFICIENT_FAN_NUM_CLEAR_RE]
            with loganalyzer:
                logging.info('Make the absence FAN back to presence...')
                single_fan_mocker.mock_presence()
                check_cli_output_with_mocker(dut, single_fan_mocker, CMD_PLATFORM_FANSTATUS, THERMAL_CONTROL_TEST_WAIT_TIME, 1)

        loganalyzer.expect_regex = [LOG_EXPECT_FAN_FAULT_RE, LOG_EXPECT_INSUFFICIENT_FAN_NUM_RE]
        with loganalyzer:
            logging.info('Mocking a fault FAN...')
            single_fan_mocker.mock_status(False)
            check_cli_output_with_mocker(dut, single_fan_mocker, CMD_PLATFORM_FANSTATUS, THERMAL_CONTROL_TEST_WAIT_TIME, 1)

        loganalyzer.expect_regex = [LOG_EXPECT_FAN_FAULT_CLEAR_RE, LOG_EXPECT_INSUFFICIENT_FAN_NUM_CLEAR_RE]
        with loganalyzer:
            logging.info('Mocking the fault FAN back to normal...')
            single_fan_mocker.mock_status(True)
            check_cli_output_with_mocker(dut, single_fan_mocker, CMD_PLATFORM_FANSTATUS, THERMAL_CONTROL_TEST_WAIT_TIME, 1)
        
        loganalyzer.expect_regex = [LOG_EXPECT_FAN_OVER_SPEED_RE]
        with loganalyzer:
            logging.info('Mocking an over speed FAN...')
            single_fan_mocker.mock_over_speed()
            check_cli_output_with_mocker(dut, single_fan_mocker, CMD_PLATFORM_FANSTATUS, THERMAL_CONTROL_TEST_WAIT_TIME, 1)

        loganalyzer.expect_regex = [LOG_EXPECT_FAN_OVER_SPEED_CLEAR_RE]
        with loganalyzer:
            logging.info('Make the over speed FAN back to normal...')
            single_fan_mocker.mock_normal_speed()
            check_cli_output_with_mocker(dut, single_fan_mocker, CMD_PLATFORM_FANSTATUS, THERMAL_CONTROL_TEST_WAIT_TIME, 1)

        loganalyzer.expect_regex = [LOG_EXPECT_FAN_UNDER_SPEED_RE]
        with loganalyzer:
            logging.info('Mocking an under speed FAN...')
            single_fan_mocker.mock_under_speed()
            check_cli_output_with_mocker(dut, single_fan_mocker, CMD_PLATFORM_FANSTATUS, THERMAL_CONTROL_TEST_WAIT_TIME, 1)

        loganalyzer.expect_regex = [LOG_EXPECT_FAN_UNDER_SPEED_CLEAR_RE]
        with loganalyzer:
            logging.info('Make the under speed FAN back to normal...')
            single_fan_mocker.mock_normal_speed()
            check_cli_output_with_mocker(dut, single_fan_mocker, CMD_PLATFORM_FANSTATUS, THERMAL_CONTROL_TEST_WAIT_TIME, 1)
