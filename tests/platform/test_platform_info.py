"""
Check platform information

This script covers the test case 'Check platform information' in the SONiC platform test plan:
https://github.com/Azure/SONiC/blob/master/doc/pmon/sonic_platform_test_plan.md
"""
import logging
import re
import time

import pytest

from psu_controller import psu_controller


CMD_PLATFORM_SUMMARY = "show platform summary"
CMD_PLATFORM_PSUSTATUS = "show platform psustatus"
CMD_PLATFORM_SYSEEPROM = "show platform syseeprom"


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


def test_show_platform_psustatus(testbed_devices):
    """
    @summary: Check output of 'show platform psustatus'
    """
    ans_host = testbed_devices["dut"]

    logging.info("Check PSU status using '%s', hostname: %s" % (CMD_PLATFORM_PSUSTATUS, ans_host.hostname))
    psu_status = ans_host.command(CMD_PLATFORM_PSUSTATUS)
    psu_line_pattern = re.compile(r"PSU\s+\d+\s+(OK|NOT OK)")
    for line in psu_status["stdout_lines"][2:]:
        assert psu_line_pattern.match(line), "Unexpected PSU status output"


def test_turn_on_off_psu_and_check_psustatus(testbed_devices, psu_controller):
    """
    @summary: Turn off/on PSU and check PSU status using 'show platform psustatus'
    """
    ans_host = testbed_devices["dut"]

    psu_line_pattern = re.compile(r"PSU\s+\d+\s+(OK|NOT OK|NOT PRESENT)")
    cmd_num_psu = "sudo psuutil numpsus"

    logging.info("Check whether the DUT has enough PSUs for this testing")
    psu_num_out = ans_host.command(cmd_num_psu)
    psu_num = 0
    try:
        psu_num = int(psu_num_out["stdout"])
    except:
        assert False, "Unable to get the number of PSUs using command '%s'" % cmd_num_psu
    if psu_num < 2:
        pytest.skip("At least 2 PSUs required for rest of the testing in this case")

    logging.info("Create PSU controller for testing")
    psu_ctrl = psu_controller(ans_host.hostname, ans_host.facts["asic_type"])
    if psu_ctrl is None:
        pytest.skip("No PSU controller for %s, skip rest of the testing in this case" % ans_host.hostname)

    logging.info("To avoid DUT losing power, need to turn on PSUs that are not powered")
    all_psu_status = psu_ctrl.get_psu_status()
    if all_psu_status:
        for psu in all_psu_status:
            if not psu["psu_on"]:
                psu_ctrl.turn_on_psu(psu["psu_id"])
                time.sleep(5)

    logging.info("Initialize test results")
    cli_psu_status = ans_host.command(CMD_PLATFORM_PSUSTATUS)
    psu_test_results = {}
    for line in cli_psu_status["stdout_lines"][2:]:
        fields = line.split()
        psu_test_results[fields[1]] = False
        if " ".join(fields[2:]) == "NOT OK":
            pytest.skip("Some PSUs are still not powered, it is not safe to proceed, skip testing")
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
    assert show_output["rc"] == 0, "Run command '%s' failed" % CMD_PLATFORM_SYSEEPROM
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
