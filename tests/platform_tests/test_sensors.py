import json
import logging
import pytest

from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('any')
]

def to_json(obj):
    return json.dumps(obj, indent=4)

def test_sensors(duthost, creds):
    # Get platform name
    platform = duthost.facts['platform']

    # Prepare check list
    sensors_checks = creds['sensors_checks']

    if platform not in sensors_checks.keys():
        pytest.skip("Skip test due to not support check sensors for current platform({})".format(platform))

    logging.info("Sensor checks:\n{}".format(to_json(sensors_checks[platform])))

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
