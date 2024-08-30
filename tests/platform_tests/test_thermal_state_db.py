
import json
import pytest
from tests.common.helpers.assertions import pytest_assert
from tests.platform_tests.cli.util import get_skip_mod_list

pytestmark = [
    pytest.mark.topology('t2')
]


def get_chassis_db_ip(duthost):
    out = duthost.command("cat /etc/sonic/chassisdb.conf")['stdout_lines']
    for line in out:
        if "chassis_db_address" in line.split("="):
            chassis_db_ip = line.split("=")[1]
            break
    return chassis_db_ip


def get_expected_num_thermals(duts, dutname=None):
    num_of_therms = 0
    cmd = "show platform temperature"
    if dutname:
        dut = duts[dutname]
        therm_out = dut.show_and_parse(cmd)
        num_of_therms = len(therm_out)
    else:
        for dut in duts:
            therm_out = dut.show_and_parse(cmd)
            num_of_therms += len(therm_out)

    return num_of_therms


def check_therm_data(thermal_dict):
    failed_check_msg = []
    for therm_sensor in list(thermal_dict.keys()):
        max_threshold = float(thermal_dict[therm_sensor]['value']['high_threshold'])
        low_threshold = float(thermal_dict[therm_sensor]['value']['low_threshold'])
        min_temp = float(thermal_dict[therm_sensor]['value']['maximum_temperature'])
        high_temp = float(thermal_dict[therm_sensor]['value']['minimum_temperature'])
        warning_status = thermal_dict[therm_sensor]['value']['warning_status']
        if high_temp > max_threshold:
            if warning_status == 'False':
                failed_check_msg.append(
                    "high temperature {} exceeded max threshold {} warning status expected true but is {} for {}"
                    .format(high_temp, max_threshold, warning_status, therm_sensor))
        elif min_temp < low_threshold:
            if warning_status == 'False':
                failed_check_msg.append(
                    "Minimum temperature {} lower than min threshold {} warning status expected true but is {} for {}"
                    .format(high_temp, max_threshold, warning_status, therm_sensor))
        else:
            if warning_status == 'True':
                failed_check_msg.append(
                    "warning status expected False but is {} for {}"
                    .format(warning_status, therm_sensor))

    return failed_check_msg


def test_thermal_state_db(duthosts, enum_rand_one_per_hwsku_hostname, tbinfo):
    """
     This test case will verify thermal local state db data on each hwsku type in chassis
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    if not duthost.facts['modular_chassis']:
        pytest.skip("Test skipped applicable to modular chassis only")
    num_thermals = get_expected_num_thermals(duthosts, enum_rand_one_per_hwsku_hostname)
    thermal_out = duthost.command("redis-dump -d 6 -y -k \"TEMP*\"")
    out_dict = json.loads(thermal_out['stdout'])
    pytest_assert(len(list(out_dict.keys())) == num_thermals,
                  "num of thermal sensors incorrect expected {} but got {}"
                  .format(num_thermals, len(list(out_dict.keys()))))
    result = check_therm_data(out_dict)
    pytest_assert(not result,
                  "Warning status incorrect for following thermal sensors:\n{}".format("\n".join(result)))


def test_thermal_global_state_db(duthosts, enum_supervisor_dut_hostname, tbinfo):
    """
     This test case will verify global state db data on supervisor
     Verify data for all sensors from line cards and fabric cards present in global state db
    """
    duthost = duthosts[enum_supervisor_dut_hostname]
    if not duthost.facts['modular_chassis']:
        pytest.skip("Test skipped applicable to modular chassis only")
    if not duthost.is_supervisor_node():
        pytest.skip("Test skipped applicable to supervisor only")
    chassis_db_ip = get_chassis_db_ip(duthost)
    expected_num_thermals = get_expected_num_thermals(duthosts)
    thermal_out = duthost.command("redis-dump -H {} -p 6380 -d 13 -y -k \"TEMP*\"".format(chassis_db_ip))
    out_dict = json.loads(thermal_out['stdout'])
    """
     For Logical Chassis we need to skip Thermal info from LCs that are physically there but logically
     not part of this logical chassis. This can be found from the skip_module "thermals" list.
     To handle logical chassis remove those known thermal info from the dictionary that was gathered from the
     global state DB before continuing
    """
    thermal_skip_list = get_skip_mod_list(duthost, ['thermals'])
    for thermal in thermal_skip_list:
        skip_thermal = duthost.command("redis-dump -H {} -p 6380 -d 13 -y -k \"{}|*\"".format(chassis_db_ip, thermal))
        skip_dict = json.loads(skip_thermal['stdout'])
        """
        delete all keys that we know should not be checked from the global dictionary
        """
        for skip_sensor_key in list(skip_dict.keys()):
            if skip_sensor_key in list(out_dict.keys()):
                del out_dict[skip_sensor_key]

    actual_num_thermal_sensors = len(list(out_dict.keys()))
    pytest_assert(actual_num_thermal_sensors == expected_num_thermals,
                  "got {} thermal sensors expected {}".format(actual_num_thermal_sensors, expected_num_thermals))
    result = check_therm_data(out_dict)
    pytest_assert(not result,
                  "Warning status incorrect in global db for following thermal sensors:\n{}".format(
                      "\n".join(result)))
