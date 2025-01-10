import pytest
import logging
import json

from .helper import gnoi_request
from tests.common.helpers.assertions import pytest_assert
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
