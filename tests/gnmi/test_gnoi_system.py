import pytest
import logging
import json

from .helper import gnoi_request
from tests.common.helpers.assertions import pytest_assert

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
    logging.info("System.Time API returned: {}".format(msg))
    pytest_assert(ret == 0, "System.Time API unexpectedly reported failure")
    try:
        # Message should looks like this: System Time\n{"time":1735921221909617549}
        # Extract JSON part from the message
        json_part = msg.split('\n', 1)[1]
        msg_json = json.loads(json_part)
        pytest_assert("time" in msg_json, "System.Time API did not return time")
    except (json.JSONDecodeError, IndexError):
        pytest.fail("System.Time API did not return valid JSON")
