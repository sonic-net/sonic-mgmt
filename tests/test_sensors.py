import pytest
import logging

from common.helpers.assertions import pytest_assert

def test_sensors(duthost, creds):
    # Get platform name
    platform = duthost.get_platform_info()['platform']

    # Prepare check list
    sensors_checks = creds['sensors_checks']

    # Gather sensors
    if platform not in sensors_checks.keys():
        pytest.skip("Skip test due to not support check sensors for current platform({})".format(platform))

    sensors_facts = duthost.sensors_facts(checks=sensors_checks[platform])['ansible_facts']

    pytest_assert(not sensors_facts['sensors']['alarm'], "sensors facts: {}".format(sensors_facts))
    if sensors_facts['sensors']['warning']:
        logging.debug("Show warnings: %s" % sensors_facts['sensors']['warning'])