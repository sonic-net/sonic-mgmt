import pytest
import logging
import json

from .helper import gnoi_request, extract_gnoi_response
from tests.common.helpers.assertions import pytest_assert

pytestmark = [pytest.mark.topology("any")]

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


@pytest.mark.disable_loganalyzer
def test_gnoi_os_activate_invalid_image(duthosts, rand_one_dut_hostname, localhost):
    """
    Verify the gNOI OS Activate capable of detecting invalid OS version.
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Activate an invalid image
    request_json = '{"version":"invalid-image-name"}'
    ret, msg = gnoi_request(duthost, localhost, "OS", "Activate", request_json)
    pytest_assert(ret == 0, "OS.Activate API reported failure (rc = {}) with message: {}".format(ret, msg))
    logging.info("OS.Activate API returned msg: {}".format(msg))
    pytest_assert("ActivateError" in msg, "OS.Activate API did not return an error as expected")
    pytest_assert("Image does not exist" in msg, "OS.Activate API error message does not indicate missing image")


@pytest.mark.disable_loganalyzer
def test_gnoi_os_activate_valid_image(duthosts, rand_one_dut_hostname, localhost):
    """
    Verify the gNOI OS Activate API capable of activating the current OS version.
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Activate a valid image
    os_version_ansible = duthost.image_facts()["ansible_facts"]["ansible_image_facts"]["current"]

    request_json = json.dumps({"version": os_version_ansible})
    ret, msg = gnoi_request(duthost, localhost, "OS", "Activate", request_json)
    pytest_assert(ret == 0, "OS.Activate API reported failure (rc = {}) with message: {}".format(ret, msg))
    logging.info("OS.Activate API returned msg: {}".format(msg))
    # Assert that the response contains "ActivateOk"
    pytest_assert("ActivateOk" in msg, "OS.Activate API did not return 'ActivateOk' as expected")


@pytest.mark.disable_loganalyzer
def test_gnoi_os_install_valid_image(duthosts, rand_one_dut_hostname, localhost):
    """
    Verify that gNOI OS Install RPC is returning Unimplimented Error
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Get the Valid image SONiC OS Version
    os_version_ansible = duthost.image_facts()["ansible_facts"]["ansible_image_facts"]["current"]
    request_json = json.dumps({"transferRequest": {"version": os_version_ansible, "standby_supervisor": False}})

    # Creating a dummy OS file and copying it to the host
    dummy_creation = duthost.shell(
        "dd if=/dev/urandom of=dummy-SONiC-OS.tar.gz bs=1M count=5", module_ignore_errors=True
    )
    copy_file = duthost.shell("docker cp dummy-SONiC-OS.tar.gz gnmi:SONiC-OS.tar.gz", module_ignore_errors=True)

    input_file = ' --input_file="SONiC-OS.tar.gz"'
    ret, msg = gnoi_request(duthost, localhost, "OS", "Install", request_json, input_file)
    pytest_assert(ret == -1, f"OS.Install RPC failed: rc = {ret}, msg = {msg}")

    logging.info("OS.Install API returned msg: {}".format(msg))
    # Assert that the response contains "Unimplimented Error"
    pytest_assert("Unimplemented" in msg, "Expected method unimplemented error")


@pytest.mark.disable_loganalyzer
def test_gnoi_os_install_without_valid_image(duthosts, rand_one_dut_hostname, localhost):
    """
    Verify that gNOI OS Install RPC is returning Unimplimented Error
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Get the Valid image SONiC OS Version
    os_version_ansible = duthost.image_facts()["ansible_facts"]["ansible_image_facts"]["current"]
    request_json = json.dumps({"transferRequest": {"version": os_version_ansible, "standby_supervisor": False}})

    ret, msg = gnoi_request(duthost, localhost, "OS", "Install", request_json)
    pytest_assert(ret == -1, f"OS.Install RPC failed: rc = {ret}, msg = {msg}")

    logging.info("OS.Install API returned msg: {}".format(msg))
    # Assert that the response contains "--input_file is required error"
    pytest_assert("--input_file is required" in msg, "Expected input_file parameter required error")
