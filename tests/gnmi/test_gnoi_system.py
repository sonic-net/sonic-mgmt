import pytest
import logging
import json

from .helper import gnoi_request
from tests.common.helpers.assertions import pytest_assert
from tests.common.reboot import wait_for_startup
import re

pytestmark = [
    pytest.mark.topology('any')
]


"""
This module contains tests for the gNOI System API.
"""


def test_gnoi_system_time(duthosts, rand_one_dut_hostname, localhost):
    """
    Verify the gNOI System Time API returns the current system time in valid JSON format.
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Get current time
    ret, msg = gnoi_request(duthost, localhost, "Time", "")
    pytest_assert(ret == 0, "System.Time API reported failure (rc = {}) with message: {}".format(ret, msg))
    logging.info("System.Time API returned msg: {}".format(msg))
    # Message should contain a json substring like this {"time":1735921221909617549}
    # Extract JSON part from the message
    msg_json = extract_first_json_substring(msg)
    if not msg_json:
        pytest.fail("Failed to extract JSON from System.Time API response")
    logging.info("Extracted JSON: {}".format(msg_json))
    pytest_assert("time" in msg_json, "System.Time API did not return time")


def test_gnoi_system_reboot(duthosts, rand_one_dut_hostname, localhost):
    """
    Verify the gNOI System Reboot API triggers a reboot and the device comes back online.
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Trigger reboot
    ret, msg = gnoi_request(duthost, localhost, "Reboot", '{"method": 1}')
    pytest_assert(ret == 0, "System.Reboot API reported failure (rc = {}) with message: {}".format(ret, msg))
    logging.info("System.Reboot API returned msg: {}".format(msg))


def test_gnoi_system_reboot_fail_invalid_method(duthosts, rand_one_dut_hostname, localhost):
    """
    Verify the gNOI System Reboot API fails with invalid method.
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Trigger reboot with invalid method
    ret, msg = gnoi_request(duthost, localhost, "Reboot", '{"method": 99}')
    pytest_assert(ret != 0, "System.Reboot API did not report failure with invalid method")


def test_gnoi_system_reboot_when_reboot_active(duthosts, rand_one_dut_hostname, localhost):
    """
    Verify the gNOI System Reboot API fails if a reboot is already active.
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Trigger first reboot
    ret, msg = gnoi_request(duthost, localhost, "Reboot", '{"method": 1}')
    pytest_assert(ret == 0, "System.Reboot API reported failure (rc = {}) with message: {}".format(ret, msg))
    logging.info("System.Reboot API returned msg: {}".format(msg))

    # Trigger second reboot while the first one is still active
    ret, msg = gnoi_request(duthost, localhost, "Reboot", '{"method": 1}')
    pytest_assert(ret != 0, "System.Reboot API did not report failure when reboot is already active")


def test_gnoi_system_reboot_status_immediately(duthosts, rand_one_dut_hostname, localhost):
    """
    Verify the gNOI System RebootStatus API returns the correct status immediately after reboot.
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Trigger reboot
    ret, msg = gnoi_request(duthost, localhost, "Reboot", '{"method": 1, "message": "test"}')
    pytest_assert(ret == 0, "System.Reboot API reported failure (rc = {}) with message: {}".format(ret, msg))
    logging.info("System.Reboot API returned msg: {}".format(msg))

    # Get reboot status
    ret, msg = gnoi_request(duthost, localhost, "RebootStatus", "")
    pytest_assert(ret == 0, "System.RebootStatus API reported failure (rc = {}) with message: {}".format(ret, msg))
    logging.info("System.RebootStatus API returned msg: {}".format(msg))
    # Message should contain a json substring like this
    # {"active":true,"wait":0,"when":0,"reason":"test","count":1,"method":1,"status":1}
    # Extract JSON part from the message
    msg_json = extract_first_json_substring(msg)
    if not msg_json:
        pytest.fail("Failed to extract JSON from System.RebootStatus API response")
    logging.info("Extracted JSON: {}".format(msg_json))
    pytest_assert("active" in msg_json, "System.RebootStatus API did not return active")
    pytest_assert(msg_json["active"] is True, "System.RebootStatus API did not return active = true")


def gnoi_system_reboot_status_after_startup(duthosts, rand_one_dut_hostname, localhost):
    """
    Verify the gNOI System RebootStatus API returns the correct status after the device has started up.
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Trigger reboot
    ret, msg = gnoi_request(duthost, localhost, "Reboot", '{"method": 1, "message": "test"}')
    pytest_assert(ret == 0, "System.Reboot API reported failure (rc = {}) with message: {}".format(ret, msg))
    logging.info("System.Reboot API returned msg: {}".format(msg))

    # Wait for device to come back online
    wait_for_startup(duthost)

    # Get reboot status
    ret, msg = gnoi_request(duthost, localhost, "RebootStatus", "")
    pytest_assert(ret == 0, "System.RebootStatus API reported failure (rc = {}) with message: {}".format(ret, msg))
    logging.info("System.RebootStatus API returned msg: {}".format(msg))
    # Message should contain a json substring like this
    # {"active":false,"wait":0,"when":0,"reason":"test","count":1,"method":1,"status":1}
    # Extract JSON part from the message
    msg_json = extract_first_json_substring(msg)
    if not msg_json:
        pytest.fail("Failed to extract JSON from System.RebootStatus API response")
    logging.info("Extracted JSON: {}".format(msg_json))
    pytest_assert("active" in msg_json, "System.RebootStatus API did not return active")
    pytest_assert(msg_json["active"] is False, "System.RebootStatus API did not return active = false")


def extract_first_json_substring(s):
    """
    Extract the first JSON substring from a given string.

    :param s: The input string containing JSON substring.
    :return: The first JSON substring if found, otherwise None.
    """

    json_pattern = re.compile(r'\{.*?\}')
    match = json_pattern.search(s)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            logging.error("Failed to parse JSON: {}".format(match.group()))
            return None
    return None
