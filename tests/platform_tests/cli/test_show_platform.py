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
import six
from . import util
from pkg_resources import parse_version
from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.daemon_utils import check_pmon_daemon_status
from tests.common.platform.device_utils import get_dut_psu_line_pattern
from tests.common.utilities import get_inventory_files, get_host_visible_vars
from tests.common.utilities import skip_release_for_platform
from tests.common.utilities import wait_until


pytestmark = [
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,  # disable automatic loganalyzer
    pytest.mark.topology('any'),
    pytest.mark.device_type('physical')
]

CMD_SHOW_PLATFORM = "show platform"

THERMAL_CONTROL_TEST_WAIT_TIME = 65
THERMAL_CONTROL_TEST_CHECK_INTERVAL = 5
VPD_DATA_FILE = "/var/run/hw-management/eeprom/vpd_data"

BF_3_PLATFORM = 'arm64-nvda_bf-bf3comdpu'
AMD_ELBA_PLATFORM = 'arm64-elba-asic-flash128-r0'


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
    expected_fields = {"Platform", "HwSKU", "ASIC"}
    actual_fields = set(summary_dict.keys())
    if 'switch_type' in dut_vars:
        new_field = {"ASIC Count", "Serial Number", "Hardware Revision", "Model Number", "Switch Type"}
    else:
        new_field = {"ASIC Count", "Serial Number", "Hardware Revision", "Model Number"}
    missing_fields = expected_fields - actual_fields
    pytest_assert(len(missing_fields) == 0, "Output missing fields: {} on '{}'".format(repr(missing_fields),
                                                                                       duthost.hostname))

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

    # for expected_num_asic, get number of asics listed in asics_present list in dut_vars
    expected_num_asic = str(len(dut_vars['asics_present'])) if 'asics_present' in dut_vars else None
    # if expected_num_asic is still None use 'num_asics' from dut_vars
    if not expected_num_asic:
        expected_num_asic = str(dut_vars['num_asics']) if 'num_asics' in dut_vars else None

    expected_fields_values = {expected_platform, expected_hwsku, expected_asic}
    if len(unexpected_fields) != 0:
        expected_fields_values.add(expected_num_asic)

    if duthost.facts["asic_type"] in ["mellanox"]:
        # For Mellanox devices, we validate the hw-revision using the value at VPD_DATA_FILE
        vpd_data = duthost.command(f"cat {VPD_DATA_FILE}")["stdout_lines"]
        hw_rev_expected = util.parse_colon_speparated_lines(vpd_data)["REV"]
        expected_fields_values.add(hw_rev_expected)

    actual_fields_values = set(summary_dict.values())
    diff_fields_values = expected_fields_values.difference(actual_fields_values)
    pytest_assert((len(diff_fields_values) == 0 or (len(diff_fields_values) == 1 and diff_fields_values.pop() is None)),
                  "Unexpected value of fields, actual={}, expected={} on host '{}'".format(actual_fields_values,
                                                                                           expected_fields_values,
                                                                                           duthost.hostname))


def test_platform_serial_no(duthosts, enum_rand_one_per_hwsku_hostname, dut_vars):
    """
    @summary: Verify device's serial no with output of `sudo decode-syseeprom -s`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    cmd = "sudo decode-syseeprom -s"
    get_serial_no_cmd = duthost.command(cmd, module_ignore_errors=True)
    assert get_serial_no_cmd['rc'] == 0, "Run command '{}' failed".format(cmd)

    logging.info("Verifying output of '{}' on '{}' ...".format(get_serial_no_cmd, duthost.hostname))
    get_serial_no_output = get_serial_no_cmd["stdout"].replace('\x00', '')
    expected_serial_no = dut_vars.get('serial', "")

    pytest_assert(get_serial_no_output == expected_serial_no,
                  "Expected serial_no '{}' is not matching with {} in syseeprom on '{}'".
                  format(expected_serial_no, get_serial_no_output, duthost.hostname))


def test_show_platform_syseeprom(duthosts, enum_rand_one_per_hwsku_hostname, dut_vars):
    """
    @summary: Verify output of `show platform syseeprom`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    skip_release_for_platform(duthost, ["202012", "201911", "201811"], ["arista_7050", "arista_7260", "arista_7060"])
    cmd = " ".join([CMD_SHOW_PLATFORM, "syseeprom"])

    syseeprom_cmd = duthost.command(cmd, module_ignore_errors=True)
    assert syseeprom_cmd['rc'] == 0, "Run command '{}' failed".format(cmd)

    logging.info("Verifying output of '{}' on '{}' ...".format(cmd, duthost.hostname))
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
    if 'arista' in duthost.facts.get('platform', '').lower():
        """
        'show platform syseeprom' output is vendor specific and on Arista duts the
        output is what is contained in our prefdl. Validate that the output contains
        non empty data.
        """
        pytest_assert(len(syseeprom_output_lines) > 0, "Cmd returns no output")
        # Validate each output line has a "Key Value" format
        parsed_syseeprom = {}
        for line in syseeprom_output_lines:
            fields = line.split(': ', 1)
            pytest_assert(len(fields) == 2, "Expected format: 'Key: Value'")

            key = fields[0]
            value = fields[1]
            parsed_syseeprom[key] = value
        # Validate that we have a min set of expected fields
        exp_fields = ["SID", "SKU", "SerialNumber"]
        for exp_field in exp_fields:
            pytest_assert(parsed_syseeprom.get(exp_field, None) is not None,
                          "Expected field {} not present.".format(exp_field))
    elif 'syseeprom_info' in dut_vars:
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
            pytest_assert(field.lower() in parsed_syseeprom, "Expected field '{}' not present in syseeprom on '{}'".
                          format(field, duthost.hostname))
            pytest_assert(parsed_syseeprom[field.lower()] == expected_syseeprom_info_dict[field],
                          "System EEPROM info is incorrect - for '{}', rcvd '{}', expected '{}' on '{}'".
                          format(field, parsed_syseeprom[field.lower()], expected_syseeprom_info_dict[field],
                                 duthost.hostname))

    if duthost.facts["asic_type"] in ["mellanox"]:
        # Define the expected fields that should be present in the syseeprom output
        expected_fields = [
            "Product Name",
            "Platform Name",
            "Part Number",
            "Serial Number",
            "Base MAC Address",
            "Manufacture Date",
            "Device Version",
            "MAC Addresses",
            "Manufacturer",
            "Vendor Name",
            "Vendor Extension",
            "ONIE Version",
            "CRC-32"]

        # Dump Redis database 6 (EEPROM database) to get all EEPROM-related data
        cmd = "redis-dump -d 6 -y"
        # Example Redis data structure:
        # {
        #     "EEPROM_INFO|0x2d": {
        #         "expireat": 1742287244.9024103,
        #         "ttl": -0.001,
        #         "type": "hash",
        #         "value": {
        #             "Len": "10",
        #             "Name": "Vendor Name",
        #             "Value": "Nvidia"
        #         }
        #     }
        # }
        cmd_output = duthost.command(cmd)['stdout']
        try:
            db_data = json.loads(cmd_output)
        except json.JSONDecodeError as e:
            pytest.fail(f"Failed to parse Redis dump output: {str(e)}")

        # Fields to exclude from validation as they are internal metadata
        exclude_fields = ['EEPROM_INFO|Checksum', 'EEPROM_INFO|State', 'EEPROM_INFO|TlvHeader']

        # Get all keys containing EEPROM data from Redis
        eeprom_db_keys_all = [key for key in db_data.keys() if "EEPROM" in key]

        if not eeprom_db_keys_all:
            pytest.fail("No EEPROM keys found in Redis database")

        # Filter out excluded fields to get only relevant EEPROM data
        eeprom_db_keys_fields = [db_key for db_key in eeprom_db_keys_all if db_key not in exclude_fields]
        logging.info(f"Found {len(eeprom_db_keys_fields)} EEPROM fields to validate")

        # Track all validation errors to report them together
        validation_errors = []

        for db_key in eeprom_db_keys_fields:
            # Analyze the structure of the Redis data for this key
            # Example structure for a key:
            # {
            #     'expireat': 'float',
            #     'ttl': 'float',
            #     'type': 'str',
            #     'value': ['Len', 'Name', 'Value']
            # }
            db_key_structure = util.analyze_structure(db_data[db_key])
            value_structure = db_key_structure.get('value')
            db_value_data = db_data[db_key].get('value')

            # Skip if no value structure is found
            if not value_structure:
                logging.warning(f"No value structure found for EEPROM key: {db_key}")
                continue

            # Get all 'Name' fields from the value structure
            value_names = util.get_db_keys('Name', value_structure)

            # Validate that parameter names exist in both syseeprom output and expected fields
            for value_name in value_names:
                if db_value_data[value_name] and (db_value_data[value_name] not in syseeprom_output or
                                                  db_value_data[value_name] not in expected_fields):
                    validation_errors.append(
                        f"EEPROM parameter name '{db_value_data[value_name]}' from Redis key '{db_key}' "
                        f"not found in syseeprom CLI output or not in expected fields"  # noqa: E713
                    )

            # Get all 'Value' fields from the value structure
            param_values = util.get_db_keys('Value', value_structure)

            # Validate that parameter values exist in the syseeprom output
            for param_value in param_values:
                if db_value_data[param_value] and db_value_data[param_value] not in syseeprom_output:
                    validation_errors.append(
                        f"EEPROM value '{db_value_data[param_value]}' from Redis key '{db_key}' "
                        f"not found in syseeprom CLI output"  # noqa: E713
                    )

        # If any validation errors occurred, format and report them all at once
        if validation_errors:
            error_msg = "\n".join([
                "EEPROM validation failed with the following errors:",
                *[f"- {error}" for error in validation_errors]
            ])
            pytest.fail(error_msg)


def test_show_platform_psustatus(duthosts, enum_supervisor_dut_hostname):
    """
    @summary: Verify output of `show platform psustatus`
    """
    duthost = duthosts[enum_supervisor_dut_hostname]

    if duthost.facts["platform"] == AMD_ELBA_PLATFORM:
        pytest.skip(f"Skip the test, as it is not supported on AMD ELBA DPU : {AMD_ELBA_PLATFORM}.")

    logging.info("Check pmon daemon status on dut '{}'".format(duthost.hostname))
    pytest_assert(
        wait_until(60, 5, 0, check_pmon_daemon_status, duthost),
        "Not all pmon daemons running on '{}'".format(duthost.hostname)
    )
    cmd = " ".join([CMD_SHOW_PLATFORM, "psustatus"])

    logging.info("Verifying output of '{}' on '{}' ...".format(cmd, duthost.hostname))
    psu_status_output = duthost.command(cmd, module_ignore_errors=True)
    assert psu_status_output['rc'] == 0, "Run command '{}' failed".format(cmd)

    psu_status_output_lines = psu_status_output["stdout_lines"]

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


def test_show_platform_psustatus_json(duthosts, enum_supervisor_dut_hostname):
    """
    @summary: Verify output of `show platform psustatus --json`
    """
    duthost = duthosts[enum_supervisor_dut_hostname]

    if duthost.facts["platform"] == AMD_ELBA_PLATFORM:
        pytest.skip(f"Skip the test, as it is not supported on AMD ELBA DPU : {AMD_ELBA_PLATFORM}.")

    if "201811" in duthost.os_version or "201911" in duthost.os_version:
        pytest.skip("JSON output not available in this version")

    logging.info("Check pmon daemon status")
    pytest_assert(
        wait_until(60, 5, 0, check_pmon_daemon_status, duthost),
        "Not all pmon daemons running.")

    cmd = " ".join([CMD_SHOW_PLATFORM, "psustatus", "--json"])

    logging.info("Verifying output of '{}' ...".format(cmd))
    psu_status_output = duthost.command(cmd, module_ignore_errors=True)
    assert psu_status_output['rc'] == 0, "Run command '{}' failed".format(cmd)

    psu_status_output = psu_status_output["stdout"]

    psu_info_list = json.loads(psu_status_output)

    # TODO: Compare against expected platform-specific output
    if duthost.facts["platform"] == "x86_64-dellemc_z9332f_d1508-r0":
        led_status_list = ["N/A"]
    else:
        led_status_list = ["green", "amber", "red", "off", "N/A"]
    for psu_info in psu_info_list:
        expected_keys = ["index", "name", "presence", "status", "led_status", "model", "serial", "voltage", "current",
                         "power"]
        pytest_assert(all(key in psu_info for key in expected_keys), "Expected key(s) missing from JSON output: '{}'".
                      format(psu_status_output))
        pytest_assert(psu_info["status"] in ["OK", "NOT OK", "NOT PRESENT"], "Unexpected PSU status value: '{}'".
                      format(psu_info["status"]))
        pytest_assert(psu_info["led_status"] in led_status_list, "Unexpected PSU led_status value: '{}'".
                      format(psu_info["led_status"]))


def verify_show_platform_fan_output(duthost, raw_output_lines):
    """
    @summary: Verify output of `show platform fan`. Expected output is
              "Fan Not detected" or a table of fan status data conaining expect number of columns.
    """
    # workaround to make this test compatible with 201911 and master
    if parse_version(duthost.kernel_version) > parse_version('4.9.0'):
        num_expected_clos = 8
    else:
        num_expected_clos = 6
    fans = {}
    pytest_assert(len(raw_output_lines) > 0, "There must be at least one line of output on '{}'".
                  format(duthost.hostname))
    if len(raw_output_lines) == 1:
        if six.PY2:
            pytest_assert(raw_output_lines[0].encode('utf-8').strip() == "Fan Not detected",
                          "Unexpected fan status output on '{}'".format(duthost.hostname))
        else:
            pytest_assert(raw_output_lines[0].strip() == "Fan Not detected",
                          "Unexpected fan status output on '{}'".format(duthost.hostname))
    else:
        pytest_assert(len(raw_output_lines) > 2,
                      "There must be at least two lines of output if any fan is detected on '{}'".
                      format(duthost.hostname))
        second_line = raw_output_lines[1]
        field_ranges = util.get_field_range(second_line)
        field_names = util.get_fields(raw_output_lines[0], field_ranges)
        pytest_assert(len(field_ranges) == num_expected_clos, "Output should consist of {} columns on '{}'".
                      format(num_expected_clos, duthost.hostname))

        fan_num = 0
        for line in raw_output_lines[2:]:
            field_values = util.get_fields(line, field_ranges)
            fans['fan' + str(fan_num)] = {}
            for field_index, a_field in enumerate(field_names):
                fans['fan' + str(fan_num)][a_field] = field_values[field_index]
            fan_num += 1

    return fans


def check_fan_status(duthost, cmd):
    logging.info("Verifying output of '{}' on '{}' ...".format(cmd, duthost.hostname))
    fan_status_output_lines = duthost.command(cmd)["stdout_lines"]
    fans = verify_show_platform_fan_output(duthost, fan_status_output_lines)

    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    if not fans and config_facts['DEVICE_METADATA']['localhost'].get('switch_type', '') == 'dpu':
        return True
    if duthost.facts["asic_type"] == "vs":
        return True
    # Check that all fans are showing valid status and also at-least one PSU is OK.
    num_fan_ok = 0
    for a_fan in list(fans.values()):
        if a_fan['Status'] == "OK":
            num_fan_ok += 1
    return num_fan_ok > 0


def test_show_platform_fan(duthosts, enum_supervisor_dut_hostname):
    """
    @summary: Verify output of `show platform fan`
    """
    duthost = duthosts[enum_supervisor_dut_hostname]
    cmd = " ".join([CMD_SHOW_PLATFORM, "fan"])
    pytest_assert(wait_until(90, 5, 0, check_fan_status, duthost, cmd),
                  " No Fans are displayed with OK status on '{}'".format(duthost.hostname))


def verify_show_platform_temperature_output(raw_output_lines, hostname):
    """
    @summary: Verify output of `show platform temperature`. Expected output is
              "Thermal Not detected" or a table of thermal status data with 8 columns.
    """
    num_expected_clos = 8

    pytest_assert(len(raw_output_lines) > 0, "There must be at least one line of output on '{}'".format(hostname))
    if len(raw_output_lines) == 1:
        if six.PY2:
            pytest_assert(raw_output_lines[0].encode('utf-8').strip() == "Thermal Not detected",
                          "Unexpected thermal status output on '{}'".format(hostname))
        else:
            pytest_assert(raw_output_lines[0].strip() == "Thermal Not detected",
                          "Unexpected thermal status output on '{}'".format(hostname))
    else:
        pytest_assert(len(raw_output_lines) > 2,
                      "There must be at least two lines of output if any thermal is detected on '{}'".format(hostname))
        second_line = raw_output_lines[1]
        field_ranges = util.get_field_range(second_line)
        pytest_assert(len(field_ranges) == num_expected_clos, "Output should consist of {} columns on '{}'".
                      format(num_expected_clos, hostname))


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
    cmds_list = [CMD_SHOW_PLATFORM, "ssdhealth"]
    supported_disks = ["SATA", "NVME", "EMMC"]

    platform_ssd_device_path_dict = {BF_3_PLATFORM: "/dev/nvme0"}
    unsupported_ssd_values_per_platform = {AMD_ELBA_PLATFORM: ["Temperature"]}

    # Build specific path to SSD device based on platform/ssd path mapping dict
    platform = duthost.facts['platform']
    if platform_ssd_device_path_dict.get(platform):
        cmds_list.append(platform_ssd_device_path_dict[platform])

    cmd = " ".join(cmds_list)

    logging.info("Verifying output of '{}' on ''{}'...".format(cmd, duthost.hostname))

    ssdhealth_output_lines = duthost.command(cmd)["stdout_lines"]
    if not any(disk_type in ssdhealth_output_lines[0] for disk_type in supported_disks):
        pytest.skip("Disk Type {} is not supported".format(ssdhealth_output_lines[0].split(':')[-1]))
    ssdhealth_dict = util.parse_colon_speparated_lines(ssdhealth_output_lines)
    expected_fields = {"Disk Type", "Device Model", "Health", "Temperature"}
    actual_fields = set(ssdhealth_dict.keys())

    missing_fields = expected_fields - actual_fields
    pytest_assert(len(missing_fields) == 0, "Output missing fields: {} on '{}'".
                  format(repr(missing_fields), duthost.hostname))

    unexpected_fields = actual_fields - expected_fields
    pytest_assert(len(unexpected_fields) == 0, "Unexpected fields in output: {} on '{}'".
                  format(repr(unexpected_fields), duthost.hostname))

    for key in expected_fields:
        pytest_assert(ssdhealth_dict[key], "Missing value for '{}' on '{}'".format(key, duthost.hostname))

        line_data = ssdhealth_dict[key]
        # Some platforms may have "N/A" value which is expected
        is_line_empty = True if (not line_data or line_data == "N/A") else False
        is_not_supported = True if key in unsupported_ssd_values_per_platform.get(platform, []) else False

        if is_line_empty and is_not_supported:
            logging.info("Validation ignored for '{}' on platform: '{}'".format(key, platform))
            continue

        pytest_assert(not is_line_empty, "Invalid data '{}' for '{}'".format(line_data, key))

        if key == "Health":
            health_float_value = float(line_data.strip("%"))
            pytest_assert(0.0 <= health_float_value <= 100.0,
                          "SSD health value '{}' is outside the expected 0-100 range".format(health_float_value))

        if key == "Temperature":
            temp_float_value = float(line_data.strip("C"))
            pytest_assert(temp_float_value < 100.0,
                          "SSD temperature '{}' is too high, expected less than 100.0 C".format(line_data))


def verify_show_platform_firmware_status_output(raw_output_lines, hostname):
    """
    @summary: Verify output of `show platform firmware status`. Expected output is
              a table of firmware data conaining 5 columns.
    """
    num_expected_clos = 5
    # Skip if command not implemented for platform
    if len(raw_output_lines) <= 2:
        pytest.skip("show platform firmware status not implemented")
    pytest_assert(len(raw_output_lines) > 2, "There must be at least two lines of output on '{}'".format(hostname))
    second_line = raw_output_lines[1]
    field_ranges = util.get_field_range(second_line)
    pytest_assert(len(field_ranges) == num_expected_clos, "Output should consist of {} columns on '{}'".
                  format(num_expected_clos, hostname))


def test_show_platform_firmware_status(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `show platform firmware status`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    skip_release_for_platform(duthost, ["202012", "201911", "201811"], ["arista"])

    cmd = " ".join([CMD_SHOW_PLATFORM, "firmware", "status"])

    firmware_output = duthost.command(cmd, module_ignore_errors=True)
    assert firmware_output['rc'] == 0, "Run command '{}' failed".format(cmd)

    logging.info("Verifying output of '{}' on '{}' ...".format(cmd, duthost.hostname))
    firmware_output_lines = firmware_output["stdout_lines"]
    verify_show_platform_firmware_status_output(firmware_output_lines, duthost.hostname)

    # TODO: Test values against platform-specific expected data


def test_show_platform_pcieinfo(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify output of `show platform pcieinfo`
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    if duthost.facts["platform"] == AMD_ELBA_PLATFORM:
        pytest.skip(f"Skip the test, as it is not supported on AMD ELBA DPU : {AMD_ELBA_PLATFORM}.")

    cmd = "show platform pcieinfo -c"

    logging.info("Verifying output of '{}' on '{}' ...".format(cmd, duthost.hostname))
    pcieinfo_output_lines = duthost.command(cmd)["stdout_lines"]

    passed_check_regexp = r'\[Passed\]|PASSED'
    for line in pcieinfo_output_lines[1:]:
        error_message = "Failed to validate output of command '{}' line: '{}'".format(cmd, line)
        pytest_assert(re.search(passed_check_regexp, line), error_message)
