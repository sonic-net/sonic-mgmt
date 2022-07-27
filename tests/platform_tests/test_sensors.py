import json
import logging
import pytest

from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('any')
]

def to_json(obj):
    return json.dumps(obj, indent=4)

def test_sensors(duthosts, rand_one_dut_hostname, creds):
    duthost = duthosts[rand_one_dut_hostname]
    # Get platform name
    platform = duthost.facts['platform']

    # Prepare check list
    sensors_checks = creds['sensors_checks']

    if platform not in sensors_checks.keys():
        pytest.skip("Skip test due to not support check sensors for current platform({})".format(platform))

    logging.info("Sensor checks:\n{}".format(to_json(sensors_checks[platform])))

    # Special treatment for Mellanox platforms which have two different A0 and A1 types
    if platform in ['x86_64-mlnx_msn4700-r0', 'x86_64-mlnx_msn4410-r0', 'x86_64-mlnx_msn4600c-r0']:
        # Check the hardware version and choose sensor conf data accordingly
        output = duthost.command('cat /run/hw-management/system/config1', module_ignore_errors=True)
        if output["rc"] == 0 and output["stdout"] == '1':
            platform = platform + '-a1'

    # Special treatment for Mellanox platforms which have two different hardware sensors on the same platform
    if platform in ['x86_64-mlnx_msn3700-r0', 'x86_64-mlnx_msn3700c-r0', 'x86_64-mlnx_msn4600c-r0',
                    'x86_64-mlnx_msn4600c-r0-a1']:
        # Check the hardware version and choose sensor conf data accordingly
        output = duthost.command('cat /run/hw-management/system/config3', module_ignore_errors=True)
        if output["rc"] == 0 and output["stdout"] == '1':
            platform = platform + '-respined'

    # Gather sensor facts
    sensors_facts = duthost.sensors_facts(checks=sensors_checks[platform])['ansible_facts']

    logging.info("Sensor facts:\n{}".format(to_json(sensors_facts)))

    # Analyze sensor alarms
    is_sensor_alarm = sensors_facts['sensors']['alarm']
    sensor_alarms = sensors_facts['sensors']['alarms']

    pytest_assert(not is_sensor_alarm, "Sensor alarms:\n{}".format(to_json(sensor_alarms)))

    # Analyze sensor warnings
    is_sensor_warning = sensors_facts['sensors']['warning']
    sensor_warnings = sensors_facts['sensors']['warnings']

    if is_sensor_warning:
        logging.warning("Sensor warnings:\n{}".format(to_json(sensor_warnings)))
