"""
Tests for gNOI OS service APIs.

This module tests the gNOI (gRPC Network Operations Interface) OS service,
which provides methods for managing operating system images on network devices.
"""

import logging

import pytest

from tests.common.helpers.assertions import pytest_assert

pytest_plugins = ("tests.common.fixtures.grpc_fixtures",)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("any"),
    pytest.mark.disable_loganalyzer,
]


def test_gnoi_os_verify(duthosts, rand_one_dut_hostname, ptf_gnoi):
    """
    Verify the gNOI OS Verify API returns the current OS version.

    Args:
        duthosts: Fixture providing access to DUT hosts
        rand_one_dut_hostname: Fixture providing a random DUT hostname
        ptf_gnoi: Fixture providing gNOI client interface
    """
    duthost = duthosts[rand_one_dut_hostname]

    response = ptf_gnoi.os_verify()
    logger.info("OS.Verify API returned response: %s", response)

    pytest_assert(
        "version" in response,
        "OS.Verify API did not return version field"
    )

    current_image = duthost.image_facts()["ansible_facts"]["ansible_image_facts"]["current"]
    pytest_assert(
        response["version"] == current_image,
        f"OS.Verify returned incorrect version: expected {current_image}, got {response['version']}"
    )


def test_gnoi_os_activate_invalid_image(ptf_gnoi):
    """
    Verify the gNOI OS Activate API rejects an invalid OS version.

    Args:
        ptf_gnoi: Fixture providing gNOI client interface
    """
    invalid_version = "invalid-image-name"
    response = ptf_gnoi.os_activate(invalid_version)
    logger.info("OS.Activate API returned response: %s", response)

    pytest_assert(
        "activateError" in response,
        f"OS.Activate did not return activateError for invalid image: {response}"
    )

    error_detail = response.get("activateError", {}).get("detail", "")
    pytest_assert(
        "Image does not exist" in error_detail,
        f"OS.Activate error message does not indicate missing image: {error_detail}"
    )


def test_gnoi_os_activate_valid_image(duthosts, rand_one_dut_hostname, ptf_gnoi):
    """
    Verify the gNOI OS Activate API can activate the current OS version.

    Args:
        duthosts: Fixture providing access to DUT hosts
        rand_one_dut_hostname: Fixture providing a random DUT hostname
        ptf_gnoi: Fixture providing gNOI client interface
    """
    duthost = duthosts[rand_one_dut_hostname]

    current_image = duthost.image_facts()["ansible_facts"]["ansible_image_facts"]["current"]
    current_image = str(current_image)

    logger.info("Testing activation with image: %s", current_image)

    response = ptf_gnoi.os_activate(current_image)
    logger.info("OS.Activate API returned response: %s", response)

    pytest_assert(
        "activateOk" in response or "activate_ok" in str(response).lower(),
        f"OS.Activate did not return success for image {current_image}: {response}"
    )
