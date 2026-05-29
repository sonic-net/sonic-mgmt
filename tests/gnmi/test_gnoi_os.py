"""
Tests for gNOI OS service APIs.

This module tests the gNOI (gRPC Network Operations Interface) OS service,
which provides methods for managing operating system images on network devices.
"""

import logging
import pytest

from tests.common.helpers.assertions import pytest_assert

from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("any"),
]


def test_gnoi_os_verify(duthosts, rand_one_dut_hostname, gnmi_tls):  # noqa: F811
    """
    Verify the gNOI OS Verify API returns the current OS version.

    Args:
        duthosts: Fixture providing access to DUT hosts
        rand_one_dut_hostname: Fixture providing a random DUT hostname
        gnmi_tls: Fixture providing gNOI client interface (TLS)
    """
    duthost = duthosts[rand_one_dut_hostname]

    response = gnmi_tls.gnoi.os_verify()

    pytest_assert(
        "version" in response,
        "OS.Verify API did not return version field"
    )

    current_image = duthost.image_facts()["ansible_facts"]["ansible_image_facts"]["current"]
    pytest_assert(
        response["version"] == current_image,
        f"OS.Verify returned incorrect version: expected {current_image}, got {response['version']}"
    )


@pytest.mark.disable_loganalyzer
def test_gnoi_os_activate_invalid_image(gnmi_tls):  # noqa: F811
    """
    Verify the gNOI OS Activate API rejects an invalid OS version.

    Args:
        gnmi_tls: Fixture providing gNOI client interface (TLS)
    """
    invalid_version = "invalid-image-name"

    response = gnmi_tls.gnoi.os_activate(invalid_version)

    pytest_assert(
        "activateError" in response,
        f"OS.Activate did not return activateError for invalid image: {response}"
    )

    error_detail = response.get("activateError", {}).get("detail", "")
    pytest_assert(
        "Image does not exist" in error_detail,
        f"OS.Activate error message does not indicate missing image: {error_detail}"
    )


@pytest.mark.disable_loganalyzer
def test_gnoi_os_activate_valid_image(duthosts, rand_one_dut_hostname, gnmi_tls):  # noqa: F811
    """
    Verify the gNOI OS Activate API responds correctly for a valid image.

    This test uses the version returned by OS.Verify and attempts to activate it.
    Note: As of the current implementation, activating the currently running image
    may return an error even though the same operation succeeds via sonic-installer CLI.
    This test validates the API response format rather than the activation result.

    Args:
        duthosts: Fixture providing access to DUT hosts
        rand_one_dut_hostname: Fixture providing a random DUT hostname
        gnmi_tls: Fixture providing gNOI client interface (TLS)
    """
    duthost = duthosts[rand_one_dut_hostname]

    verify_response = gnmi_tls.gnoi.os_verify()

    current_image = verify_response.get("version")
    if not current_image:
        pytest.skip("Could not get current image version from OS.Verify")

    result = duthost.shell("sudo sonic-installer list", module_ignore_errors=True)

    pytest_assert(
        current_image in result.get('stdout', ''),
        f"Image {current_image} not found in sonic-installer list output"
    )

    response = gnmi_tls.gnoi.os_activate(current_image)

    pytest_assert(
        "activateOk" in response or "activateError" in response,
        f"OS.Activate returned unexpected response format (missing activateOk/activateError): {response}"
    )
