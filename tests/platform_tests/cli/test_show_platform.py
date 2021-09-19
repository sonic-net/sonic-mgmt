"""
Tests for the `show platform ...` commands in SONiC
"""

# TODO: All `show` commands should be tested by running as a read-only user.
#       This will help catch any permissions issues which may exist.

# TODO: Add tests for `show platform psustatus <PSU_NUM>`
# TODO: Add tests for `show platform firmware updates`
# TODO: Add tests for `show platform firmware version`

import json
import logging
import re

import pytest

import util
from pkg_resources import parse_version
from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.daemon_utils import check_pmon_daemon_status
from tests.common.platform.device_utils import get_dut_psu_line_pattern
from tests.common.utilities import get_inventory_files, get_host_visible_vars
from tests.common.utilities import skip_release_for_platform

pytestmark = [
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,  # disable automatic loganalyzer
    pytest.mark.topology('any')
]

CMD_SHOW_PLATFORM = "show platform"

THERMAL_CONTROL_TEST_WAIT_TIME = 65
THERMAL_CONTROL_TEST_CHECK_INTERVAL = 5

@pytest.fixture(scope='module')
def dut_vars(duthosts, enum_rand_one_per_hwsku_hostname, request):
    inv_files = get_inventory_files(request)
    dut_vars = get_host_visible_vars(inv_files, enum_rand_one_per_hwsku_hostname)
    yield dut_vars

def test_show_platform_summary(duthosts, enum_rand_one_per_hwsku_hostname, dut_vars):
    """
    @summary: Verify output of `show platform summary`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    cmd = " ".join([CMD_SHOW_PLATFORM, "summary"])

    logging.info("Verifying output of '{}' on '{}'...".format(cmd, duthost.hostname))
    summary_output_lines = duthost.command(cmd)["stdout_lines"]
    summary_dict = util.parse_colon_speparated_lines(summary_output_lines)
    expected_fields = set(["Platform", "HwSKU", "ASIC"])
    actual_fields = set(summary_dict.keys())
    new_field = set(["ASIC Count", "Serial Number", "Hardware Revision", "Model Number"])

    missing_fields = expected_fields - actual_fields
    pytest_assert(len(missing_fields) == 0, "Output missing fields: {} on '{}'".format(repr(missing_fields), duthost.hostname))

    unexpected_fields = actual_fields - expected_fields
    pytest_assert(((unexpected_fields.issubset(new_field)) or len(unexpected_fields) == 0),
                  "Unexpected fields in output: {}  on '{}'".format(repr(unexpected_fields), duthost.hostname))

    # Testing for missing values
    for key in expected_fields:
        pytest_assert(summary_dict[key], "Missing value for '{}' on '{}'".format(key, duthost.hostname))

    # Testings values against values defined in the inventory if present in the inventory.
    #    hwsku based on 'hwsku' or 'sonic_hwsku' inventory variable.
    #    platform based on 'sonic_hw_platform'  inventory variable.
    #    asic based on 'asic_type'  inventory variable.
    #    num_asic on 'num_asics' inventory variable
    expected_hwsku = dut_vars['hwsku'] if 'hwsku' in dut_vars else None
    if not expected_hwsku:
        # Lets try 'sonic_hwsku' as well
        expected_hwsku = dut_vars['sonic_hwsku'] if 'sonic_hwsku' in dut_vars else None
    expected_platform = dut_vars['sonic_hw_platform'] if 'sonic_hw_platform' in dut_vars else None
    expected_asic = dut_vars['asic_type'] if 'asic_type' in dut_vars else None
    expected_num_asic = str(dut_vars['num_asics']) if 'num_asics' in dut_vars else None

    expected_fields_values = {expected_platform, expected_hwsku, expected_asic}
    if len(unexpected_fields) != 0:
        expected_fields_values.add(expected_num_asic)

    actual_fields_values = set(summary_dict.values())
    diff_fields_values = expected_fields_values.difference(actual_fields_values)
    pytest_assert((len(diff_fields_values) == 0 or (len(diff_fields_values) == 1 and diff_fields_values.pop() is None)),
                  "Unexpected value of fields, actual={}, expected={} on host '{}'".format(actual_fields_values, expected_fields_values, duthost.hostname))


def test_show_platform_syseeprom(duthosts, enum_rand_one_per_hwsku_hostname, dut_vars):
    """
    @summary: Verify output of `show platform syseeprom`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    skip_release_for_platform(duthost, ["202012", "201911", "201811"], ["arista_7050"])
    cmd = " ".join([CMD_SHOW_PLATFORM, "syseeprom"])

    logging.info("Verifying output of '{}' on '{}' ...".format(cmd, duthost.hostname))
    syseeprom_cmd = duthost.command(cmd)
    syseeprom_output = syseeprom_cmd["stdout"]
    syseeprom_output_lines = syseeprom_cmd["stdout_lines"]

    """
    Gather expected data from a inventory file instead if 'syseeprom_info' is defined in the inventory
    # Sample inventory with syseeprom:
    
    str-msn2700-01:
        ansible_host: 10.251.0.188
        model: MSN2700-CS2FO
        serial: MT1234X56789
        base_mac: 24:8a:07:12:34:56
        syseeprom_info:
            "0x21": "MSN2700"
            "0x22": "MSN2700-CS2FO"
            "0x23": "MT1234X56789"
            "0x24": "24:8a:07:12:34:56"
            "0x25": "12/07/2016"
            "0x26": "0"
            "0x28": "x86_64-mlnx_x86-r0"
            "0x29": "2016.11-5.1.0008-9600"
            "0x2A": "128"
            "0x2B": "Mellanox"
            "0xFE": "0xFBA1E964"
    """
    if 'syseeprom_info' in dut_vars:
        expected_syseeprom_info_dict = dut_vars['syseeprom_info']

        parsed_syseeprom = {}
        # Can't use util.get_fields as the values go beyond the last set of '---' in the hearder line.
        regex_int = re.compile(r'([\S\s]+)(0x[A-F0-9]+)\s+([\d]+)\s+([\S\s]*)')
        for line in syseeprom_output_lines[6:]:
            t1 = regex_int.match(line)
            if t1:
                tlv_code_lower_case = t1.group(2).strip().lower()
                parsed_syseeprom[tlv_code_lower_case] = t1.group(4).strip()

        for field in expected_syseeprom_info_dict:
            pytest_assert(field.lower() in parsed_syseeprom, "Expected field '{}' not present in syseeprom on '{}'".format(field, duthost.hostname))
            pytest_assert(parsed_syseeprom[field.lower()] == expected_syseeprom_info_dict[field],
                          "System EEPROM info is incorrect - for '{}', rcvd '{}', expected '{}' on '{}'".
                          format(field, parsed_syseeprom[field.lower()], expected_syseeprom_info_dict[field], duthost.hostname))

    if duthost.facts["asic_type"] in ["mellanox"]:
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
            m = imp.load_source('eeprom', '/usr/share/sonic/device/{}/plugins/eeprom.py'); \
            t = m.board('board', '', '', ''); e = t.read_eeprom(); t.decode_eeprom(e)\"".format(duthost.facts["platform"])

        utility_cmd_output = duthost.command(utility_cmd)

        for field in expected_fields:
            pytest_assert(syseeprom_output.find(field) >= 0, "Expected field '{}' was not found on '{}'".format(field, duthost.hostname))
            pytest_assert(utility_cmd_output["stdout"].find(field) >= 0, "Expected field '{}' was not found on '{}'".format(field, duthost.hostname))

        for line in utility_cmd_output["stdout_lines"]:
            if not line.startswith('-'):  # do not validate line '-------------------- ---- --- -----'
                line_regexp = re.sub(r'\s+', '\s+', line)
                pytest_assert(re.search(line_regexp, syseeprom_output), "Line '{}' was not found in output on '{}'".format(line, duthost.hostname))


def test_show_platform_psustatus(duthosts, enum_supervisor_dut_hostname):
    """
    @summary: Verify output of `show platform psustatus`
    """
    duthost = duthosts[enum_supervisor_dut_hostname]
    logging.info("Check pmon daemon status on dut '{}'".format(duthost.hostname))
    assert check_pmon_daemon_status(duthost), "Not all pmon daemons running on '{}'".format(duthost.hostname)
    cmd = " ".join([CMD_SHOW_PLATFORM, "psustatus"])

    logging.info("Verifying output of '{}' on '{}' ...".format(cmd, duthost.hostname))
    psu_status_output_lines = duthost.command(cmd)["stdout_lines"]

    psu_line_pattern = get_dut_psu_line_pattern(duthost)

    # Check that all PSUs are showing valid status and also at least one PSU is OK
    num_psu_ok = 0

    for line in psu_status_output_lines[2:]:
        psu_match = psu_line_pattern.match(line)
        pytest_assert(psu_match, "Unexpected PSU status output: '{}' on '{}'".format(line, duthost.hostname))
        psu_status = psu_match.group(2)
        if psu_status == "OK":
            num_psu_ok += 1

    pytest_assert(num_psu_ok > 0, "No PSUs are displayed with OK status on '{}'".format(duthost.hostname))


def test_show_platform_psustatus_json(duthosts, rand_one_dut_hostname):
    """
    @summary: Verify output of `show platform psustatus --json`
    """
    duthost = duthosts[rand_one_dut_hostname]

    if "201811" in duthost.os_version or "201911" in duthost.os_version:
        pytest.skip("JSON output not available in this version")

    logging.info("Check pmon daemon status")
    pytest_assert(check_pmon_daemon_status(duthost), "Not all pmon daemons running.")

    cmd = " ".join([CMD_SHOW_PLATFORM, "psustatus", "--json"])

    logging.info("Verifying output of '{}' ...".format(cmd))
    psu_status_output = duthost.command(cmd)["stdout"]
    psu_info_list = json.loads(psu_status_output)

    # TODO: Compare against expected platform-specific output
    for psu_info in psu_info_list:
        expected_keys = ["index", "name", "presence", "status", "led_status", "model", "serial", "voltage", "current", "power"]
        pytest_assert(all(key in psu_info for key in expected_keys), "Expected key(s) missing from JSON output: '{}'".format(psu_status_output))
        pytest_assert(psu_info["status"] in ["OK", "NOT OK", "NOT PRESENT"], "Unexpected PSU status value: '{}'".format(psu_info["status"]))
        pytest_assert(psu_info["led_status"] in ["green", "amber", "red", "off"], "Unexpected PSU led_status value: '{}'".format(psu_info["led_status"]))


def verify_show_platform_fan_output(duthost, raw_output_lines):
    """
    @summary: Verify output of `show platform fan`. Expected output is
              "Fan Not detected" or a table of fan status data conaining expect number of columns.
    """
    # workaround to make this test compatible with 201911 and master
    if parse_version(duthost.kernel_version) > parse_version('4.9.0'):
        NUM_EXPECTED_COLS = 8
    else:
        NUM_EXPECTED_COLS = 6
    fans = {}
    pytest_assert(len(raw_output_lines) > 0, "There must be at least one line of output on '{}'".format(duthost.hostname))
    if len(raw_output_lines) == 1:
        pytest_assert(raw_output_lines[0].encode('utf-8').strip() == "Fan Not detected", "Unexpected fan status output on '{}'".format(duthost.hostname))
    else:
        pytest_assert(len(raw_output_lines) > 2, "There must be at least two lines of output if any fan is detected on '{}'".format(duthost.hostname))
        second_line = raw_output_lines[1]
        field_ranges = util.get_field_range(second_line)
        field_names = util.get_fields(raw_output_lines[0], field_ranges)
        pytest_assert(len(field_ranges) == NUM_EXPECTED_COLS, "Output should consist of {} columns on '{}'".format(NUM_EXPECTED_COLS, duthost.hostname))

        fan_num = 0
        for line in raw_output_lines[2:]:
            field_values = util.get_fields(line, field_ranges)
            fans['fan' + str(fan_num)] = {}
            for field_index, a_field in enumerate(field_names):
                fans['fan' + str(fan_num)][a_field] = field_values[field_index]
            fan_num += 1

    return fans

def test_show_platform_fan(duthosts, enum_supervisor_dut_hostname):
    """
    @summary: Verify output of `show platform fan`
    """
    duthost = duthosts[enum_supervisor_dut_hostname]
    cmd = " ".join([CMD_SHOW_PLATFORM, "fan"])

    logging.info("Verifying output of '{}' on '{}' ...".format(cmd, duthost.hostname))
    fan_status_output_lines = duthost.command(cmd)["stdout_lines"]
    fans = verify_show_platform_fan_output(duthost, fan_status_output_lines)

    # Check that all fans are showing valid status and also at-least one PSU is OK.
    num_fan_ok = 0
    for a_fan in fans.values():
        if a_fan['Status'] == "OK":
            num_fan_ok += 1
    pytest_assert(num_fan_ok > 0, " No Fans are displayed with OK status on '{}'".format(duthost.hostname))


def verify_show_platform_temperature_output(raw_output_lines, hostname):
    """
    @summary: Verify output of `show platform temperature`. Expected output is
              "Thermal Not detected" or a table of thermal status data with 8 columns.
    """
    NUM_EXPECTED_COLS = 8

    pytest_assert(len(raw_output_lines) > 0, "There must be at least one line of output on '{}'".format(hostname))
    if len(raw_output_lines) == 1:
        pytest_assert(raw_output_lines[0].encode('utf-8').strip() == "Thermal Not detected", "Unexpected thermal status output on '{}'".format(hostname))
    else:
        pytest_assert(len(raw_output_lines) > 2, "There must be at least two lines of output if any thermal is detected on '{}'".format(hostname))
        second_line = raw_output_lines[1]
        field_ranges = util.get_field_range(second_line)
        pytest_assert(len(field_ranges) == NUM_EXPECTED_COLS, "Output should consist of {} columns on '{}'".format(NUM_EXPECTED_COLS, hostname))


def test_show_platform_temperature(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `show platform temperature`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    cmd = " ".join([CMD_SHOW_PLATFORM, "temperature"])

    logging.info("Verifying output of '{}' on '{}'...".format(cmd, duthost.hostname))
    temperature_output_lines = duthost.command(cmd)["stdout_lines"]
    verify_show_platform_temperature_output(temperature_output_lines, duthost.hostname)

    # TODO: Test values against platform-specific expected data


def test_show_platform_ssdhealth(duthosts, enum_supervisor_dut_hostname):
    """
    @summary: Verify output of `show platform ssdhealth`
    """
    duthost = duthosts[enum_supervisor_dut_hostname]
    cmd = " ".join([CMD_SHOW_PLATFORM, "ssdhealth"])

    logging.info("Verifying output of '{}' on ''{}'...".format(cmd, duthost.hostname))
    ssdhealth_output_lines = duthost.command(cmd)["stdout_lines"]
    ssdhealth_dict = util.parse_colon_speparated_lines(ssdhealth_output_lines)
    expected_fields = set(["Device Model", "Health", "Temperature"])
    actual_fields = set(ssdhealth_dict.keys())

    missing_fields = expected_fields - actual_fields
    pytest_assert(len(missing_fields) == 0, "Output missing fields: {} on '{}'".format(repr(missing_fields), duthost.hostname))

    unexpected_fields = actual_fields - expected_fields
    pytest_assert(len(unexpected_fields) == 0, "Unexpected fields in output: {} on '{}'".format(repr(unexpected_fields), duthost.hostname))

    # TODO: Test values against platform-specific expected data instead of testing for missing values
    for key in expected_fields:
        pytest_assert(ssdhealth_dict[key], "Missing value for '{}' on '{}'".format(key, duthost.hostname))


def verify_show_platform_firmware_status_output(raw_output_lines, hostname):
    """
    @summary: Verify output of `show platform firmware status`. Expected output is
              a table of firmware data conaining 5 columns.
    """
    NUM_EXPECTED_COLS = 5

    pytest_assert(len(raw_output_lines) > 2, "There must be at least two lines of output on '{}'".format(hostname))
    second_line = raw_output_lines[1]
    field_ranges = util.get_field_range(second_line)
    pytest_assert(len(field_ranges) == NUM_EXPECTED_COLS, "Output should consist of {} columns on '{}'".format(NUM_EXPECTED_COLS, hostname))


def test_show_platform_firmware_status(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `show platform firmware status`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    skip_release_for_platform(duthost, ["202012", "201911", "201811"], ["arista"])


    cmd = " ".join([CMD_SHOW_PLATFORM, "firmware", "status"])

    logging.info("Verifying output of '{}' on '{}' ...".format(cmd, duthost.hostname))
    firmware_output_lines = duthost.command(cmd)["stdout_lines"]
    verify_show_platform_firmware_status_output(firmware_output_lines, duthost.hostname)

    # TODO: Test values against platform-specific expected data
