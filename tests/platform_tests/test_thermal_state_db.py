
import json
import pytest
from tests.common.helpers.assertions import pytest_assert

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
    for therm_sensor in thermal_dict.keys():
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
    if duthost.facts['modular_chassis'] == "False":
        pytest.skip("Test skipped applicable to modular chassis only")
    num_thermals = get_expected_num_thermals(duthosts, enum_rand_one_per_hwsku_hostname)
    thermal_out = duthost.command("redis-dump -d 6 -y -k \"*TEMP*\"")
    out_dict = json.loads(thermal_out['stdout'])
    pytest_assert(len(out_dict.keys()) == num_thermals, "number of thermal sensors incorrect expected  {} but got {}".format(num_thermals, len(out_dict.keys())))
    result = check_therm_data(out_dict)
    pytest_assert(not result,
                  "Warning status incorrect for following thermal sensors:\n{}".format("\n".join(result)))


def test_thermal_global_state_db(duthosts, enum_supervisor_dut_hostname, tbinfo):
    """
     This test case will verify global state db data on supervisor
     Verify data for all sensors from line cards and fabric cards present in global state db
    """
    duthost = duthosts[enum_supervisor_dut_hostname]
    if duthost.facts['modular_chassis'] == "False":
        pytest.skip("Test skipped applicable to modular chassis only")
    chassis_db_ip = get_chassis_db_ip(duthost)
    expected_num_thermals = get_expected_num_thermals(duthosts)
    thermal_out = duthost.command("redis-dump -H {} -p 6380 -d 13 -y -k \"*TEMP*\"".format(chassis_db_ip))
    out_dict = json.loads(thermal_out['stdout'])
    actual_num_thermal_sensors = len(out_dict.keys())
    pytest_assert(actual_num_thermal_sensors == expected_num_thermals,
                  "got {} thermal sensors expected {}".format(actual_num_thermal_sensors, expected_num_thermals))
    result = check_therm_data(out_dict)
    pytest_assert(not result,
                  "Warning status incorrect in global db for following thermal sensors:\n{}".format(
                      "\n".join(result)))
