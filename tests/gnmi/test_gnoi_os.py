import pytest
import logging

from .helper import gnoi_request, extract_gnoi_response
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('any')
]

"""
This module contains tests for the gNOI OS API.
"""


@pytest.mark.disable_loganalyzer
def test_gnoi_os_verify(duthosts, rand_one_dut_hostname, localhost):
    """
    Verify the gNOI OS Verify API returns the current OS version.
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Get current OS version
    ret, msg = gnoi_request(duthost, localhost, "OS", "Verify", "")
    pytest_assert(ret == 0, "OS.Verify API reported failure (rc = {}) with message: {}".format(ret, msg))
    logging.info("OS.Verify API returned msg: {}".format(msg))
    # Message should contain a json substring like this {"version":"SONiC-OS-20240510.24"}
    # Extract JSON part from the message
    msg_json = extract_gnoi_response(msg)
    if not msg_json:
        pytest.fail("Failed to extract JSON from OS.Verify API response")
    logging.info("Extracted JSON: {}".format(msg_json))
    pytest_assert("version" in msg_json, "OS.Verify API did not return os_version")

    os_version_ansible = duthost.image_facts()["ansible_facts"]["ansible_image_facts"]["current"]
    pytest_assert(msg_json["version"] == os_version_ansible, "OS.Verify API returned incorrect OS version")
