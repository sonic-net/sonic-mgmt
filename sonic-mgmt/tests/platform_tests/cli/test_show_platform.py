"""
Tests for the `show platform ...` commands in SONiC
"""

# TODO: All `show` commands should be tested by running as a read-only user.
#       This will help catch any permissions issues which may exist.

# TODO: Add tests for `show platform psustatus <PSU_NUM>`
# TODO: Add tests for `show platform firmware updates`
# TODO: Add tests for `show platform firmware version`

import logging
import re
import time

import pytest

import util
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,  # disable automatic loganalyzer
    pytest.mark.topology('any')
]

CMD_SHOW_PLATFORM = "show platform"

THERMAL_CONTROL_TEST_WAIT_TIME = 65
THERMAL_CONTROL_TEST_CHECK_INTERVAL = 5


def test_show_platform_summary(duthost):
    """
    @summary: Verify output of `show platform summary`
    """
    cmd = " ".join([CMD_SHOW_PLATFORM, "summary"])

    logging.info("Verifying output of '{}' ...".format(cmd))
    summary_output_lines = duthost.command(cmd)["stdout_lines"]
    summary_dict = util.parse_colon_speparated_lines(summary_output_lines)
    expected_fields = set(["Platform", "HwSKU", "ASIC"])
    actual_fields = set(summary_dict.keys())

    missing_fields = expected_fields - actual_fields
    pytest_assert(len(missing_fields) == 0, "Output missing fields: {}".format(repr(missing_fields)))

    unexpected_fields = actual_fields - expected_fields
    pytest_assert(len(unexpected_fields) == 0, "Unexpected fields in output: {}".format(repr(unexpected_fields)))

    # TODO: Test values against platform-specific expected data instead of testing for missing values
    for key in expected_fields:
        pytest_assert(summary_dict[key], "Missing value for '{}'".format(key))


def test_show_platform_syseeprom(duthost):
    """
    @summary: Verify output of `show platform syseeprom`
    """
    cmd = " ".join([CMD_SHOW_PLATFORM, "syseeprom"])

    logging.info("Verifying output of '{}' ...".format(cmd))
    syseeprom_output = duthost.command(cmd)["stdout"]
    # TODO: Gather expected data from a platform-specific data file instead of this method

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
            m = imp.load_source('eeprom', '/usr/share/sonic/device/%s/plugins/eeprom.py'); \
            t = m.board('board', '', '', ''); e = t.read_eeprom(); t.decode_eeprom(e)\"" % duthost.facts["platform"]

        utility_cmd_output = duthost.command(utility_cmd)

        for field in expected_fields:
            pytest_assert(syseeprom_output.find(field) >= 0, "Expected field '{}' was not found".format(field))
            pytest_assert(utility_cmd_output["stdout"].find(field) >= 0, "Expected field '{}' was not found".format(field))

        for line in utility_cmd_output["stdout_lines"]:
            pytest_assert(line in syseeprom_output, "Line '{}' was not found in output".format(line))


def test_show_platform_psustatus(duthost):
    """
    @summary: Verify output of `show platform psustatus`
    """
    cmd = " ".join([CMD_SHOW_PLATFORM, "psustatus"])

    logging.info("Verifying output of '{}' ...".format(cmd))
    psu_status_output_lines = duthost.command(cmd)["stdout_lines"]
    psu_line_pattern = re.compile(r"PSU\s+\d+\s+(OK|NOT OK|NOT PRESENT)")
    for line in psu_status_output_lines[2:]:
        pytest_assert(psu_line_pattern.match(line), "Unexpected PSU status output: '{}'".format(line))
        # TODO: Compare against expected platform-specific output


def verify_show_platform_fan_output(raw_output_lines):
    """
    @summary: Verify output of `show platform fan`. Expected output is
              "Fan Not detected" or a table of fan status data conaining 8 columns.
    """
    NUM_EXPECTED_COLS = 8

    pytest_assert(len(raw_output_lines) > 0, "There must be at least one line of output")
    if len(raw_output_lines) == 1:
        pytest_assert(raw_output_lines[0].encode('utf-8').strip() == "Fan Not detected", "Unexpected fan status output")
    else:
        pytest_assert(len(raw_output_lines) > 2, "There must be at least two lines of output if any fan is detected")
        second_line = raw_output_lines[1]
        field_ranges = util.get_field_range(second_line)
        pytest_assert(len(field_ranges) == NUM_EXPECTED_COLS, "Output should consist of {} columns".format(NUM_EXPECTED_COLS))


def test_show_platform_fan(duthost):
    """
    @summary: Verify output of `show platform fan`
    """
    cmd = " ".join([CMD_SHOW_PLATFORM, "fan"])

    logging.info("Verifying output of '{}' ...".format(cmd))
    fan_status_output_lines = duthost.command(cmd)["stdout_lines"]
    verify_show_platform_fan_output(fan_status_output_lines)

    # TODO: Test values against platform-specific expected data


def verify_show_platform_temperature_output(raw_output_lines):
    """
    @summary: Verify output of `show platform temperature`. Expected output is
              "Thermal Not detected" or a table of thermal status data with 8 columns.
    """
    NUM_EXPECTED_COLS = 8

    pytest_assert(len(raw_output_lines) > 0, "There must be at least one line of output")
    if len(raw_output_lines) == 1:
        pytest_assert(raw_output_lines[0].encode('utf-8').strip() == "Thermal Not detected", "Unexpected thermal status output")
    else:
        pytest_assert(len(raw_output_lines) > 2, "There must be at least two lines of output if any thermal is detected")
        second_line = raw_output_lines[1]
        field_ranges = util.get_field_range(second_line)
        pytest_assert(len(field_ranges) == NUM_EXPECTED_COLS, "Output should consist of {} columns".format(NUM_EXPECTED_COLS))


def test_show_platform_temperature(duthost):
    """
    @summary: Verify output of `show platform temperature`
    """
    cmd = " ".join([CMD_SHOW_PLATFORM, "temperature"])

    logging.info("Verifying output of '{}' ...".format(cmd))
    temperature_output_lines = duthost.command(cmd)["stdout_lines"]
    verify_show_platform_temperature_output(temperature_output_lines)

    # TODO: Test values against platform-specific expected data


def test_show_platform_ssdhealth(duthost):
    """
    @summary: Verify output of `show platform ssdhealth`
    """
    cmd = " ".join([CMD_SHOW_PLATFORM, "ssdhealth"])

    logging.info("Verifying output of '{}' ...".format(cmd))
    ssdhealth_output_lines = duthost.command(cmd)["stdout_lines"]
    ssdhealth_dict = util.parse_colon_speparated_lines(ssdhealth_output_lines)
    expected_fields = set(["Device Model", "Health", "Temperature"])
    actual_fields = set(ssdhealth_dict.keys())

    missing_fields = expected_fields - actual_fields
    pytest_assert(len(missing_fields) == 0, "Output missing fields: {}".format(repr(missing_fields)))

    unexpected_fields = actual_fields - expected_fields
    pytest_assert(len(unexpected_fields) == 0, "Unexpected fields in output: {}".format(repr(unexpected_fields)))

    # TODO: Test values against platform-specific expected data instead of testing for missing values
    for key in expected_fields:
        pytest_assert(ssdhealth_dict[key], "Missing value for '{}'".format(key))


def verify_show_platform_firmware_status_output(raw_output_lines):
    """
    @summary: Verify output of `show platform firmware status`. Expected output is
              a table of firmware data conaining 5 columns.
    """
    NUM_EXPECTED_COLS = 5

    pytest_assert(len(raw_output_lines) > 2, "There must be at least two lines of output")
    second_line = raw_output_lines[1]
    field_ranges = util.get_field_range(second_line)
    pytest_assert(len(field_ranges) == NUM_EXPECTED_COLS, "Output should consist of {} columns".format(NUM_EXPECTED_COLS))


def test_show_platform_firmware_status(duthost):
    """
    @summary: Verify output of `show platform firmware status`
    """
    cmd = " ".join([CMD_SHOW_PLATFORM, "firmware", "status"])

    logging.info("Verifying output of '{}' ...".format(cmd))
    firmware_output_lines = duthost.command(cmd)["stdout_lines"]
    verify_show_platform_firmware_status_output(firmware_output_lines)

    # TODO: Test values against platform-specific expected data
