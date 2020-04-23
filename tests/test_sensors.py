import pytest
import logging

def test_sensors(duthost, creds):
    # Get platform name
    platform = duthost.shell("show platform summary | grep Platform | awk '{print $2}'")['stdout']

    # Prepare check list
    sensors_checks = creds['sensors_checks']

    # Gather sensors
    if platform not in sensors_checks.keys():
        pytest.skip("Skip test due to not support check sensors for current platform({})".format(platform))

    sensors_facts = duthost.sensors_facts(checks=sensors_checks[platform])['ansible_facts']
    logging.debug("Output of sensors information: %s" % sensors_facts)

    assert not sensors_facts['sensors']['alarm']
    if sensors_facts['sensors']['warning']:
        logging.debug("Show warnings: %s" % sensors_facts['sensors']['warning'])