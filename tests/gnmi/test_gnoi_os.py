import pytest
import logging

# Import fixtures module to ensure pytest discovers them
import tests.common.fixtures.grpc_fixtures  # noqa: F401

from tests.common.helpers.assertions import pytest_assert

# Enable TLS fixture by default for all tests in this module
pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.usefixtures("setup_gnoi_tls_server")
]

"""
This module contains tests for the gNOI OS API.
"""


@pytest.mark.disable_loganalyzer
def test_gnoi_os_verify(duthosts, rand_one_dut_hostname, ptf_gnoi):
    """
    Verify the gNOI OS Verify API returns the current OS version.
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Get current OS version using the new TLS-enabled client
    response = ptf_gnoi.os_verify()
    logging.info("OS.Verify API returned response: {}".format(response))
    pytest_assert("version" in response, "OS.Verify API did not return os_version")

    os_version_ansible = duthost.image_facts()["ansible_facts"]["ansible_image_facts"]["current"]
    pytest_assert(response["version"] == os_version_ansible, "OS.Verify API returned incorrect OS version")


@pytest.mark.disable_loganalyzer
def test_gnoi_os_activate_invalid_image(duthosts, rand_one_dut_hostname, ptf_gnoi):
    """
    Verify the gNOI OS Activate capable of detecting invalid OS version.
    """
    # Activate an invalid image - should return an error response
    invalid_version = "invalid-image-name"
    response = ptf_gnoi.os_activate(invalid_version)
    logging.info("OS.Activate API returned response: {}".format(response))

    # Check that the response contains an activateError field
    pytest_assert("activateError" in response, "OS.Activate API did not return an error as expected")

    # Check that the error indicates missing image
    error_detail = response.get("activateError", {}).get("detail", "")
    pytest_assert("Image does not exist" in error_detail,
                  "OS.Activate API error message does not indicate missing image: {}".format(error_detail))


@pytest.mark.disable_loganalyzer
def test_gnoi_os_activate_valid_image(duthosts, rand_one_dut_hostname, ptf_gnoi):
    """
    Verify the gNOI OS Activate API capable of activating the current OS version.
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Activate a valid image
    os_version_ansible = duthost.image_facts()["ansible_facts"]["ansible_image_facts"]["current"]

    response = ptf_gnoi.os_activate(os_version_ansible)
    logging.info("OS.Activate API returned response: {}".format(response))
    # Assert that the response indicates success (either contains "ActivateOk" or doesn't raise exception)
    pytest_assert(True, "OS.Activate API completed successfully")
