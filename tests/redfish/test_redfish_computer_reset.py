"""
Tests for Redfish ComputerSystem.Reset action endpoint.

Section 5: Computer System Reset (Test Cases #11–#15)

WARNING: Tests #12, #13, #14 trigger actual power state changes on the BMC DUT.
They restore the system to its original power state after each test.
"""
import logging
import time
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.redfish.redfish_utils import assert_field_in, assert_status_ok

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('bmc-dual-mgmt', 'bmc-shared-mgmt'),
]

RESET_PATH = "/redfish/v1/Systems/system/Actions/ComputerSystem.Reset"
SYSTEM_PATH = "/redfish/v1/Systems/system"

POWER_ON_TIMEOUT = 120    # seconds to wait for system to power on
POWER_OFF_TIMEOUT = 120   # seconds to wait for system to power off
POLL_INTERVAL = 5         # seconds between power state polls


def _get_power_state(redfish_client):
    """Return current PowerState string from /redfish/v1/Systems/system."""
    response = redfish_client.get(SYSTEM_PATH)
    if response.status_code != 200:
        return None
    return response.json().get("PowerState")


def _wait_for_power_state(redfish_client, target_state, timeout):
    """Poll until PowerState equals target_state or timeout expires. Returns True on success."""
    elapsed = 0
    while elapsed < timeout:
        state = _get_power_state(redfish_client)
        logger.info("PowerState: {} (waiting for {})".format(state, target_state))
        if state == target_state:
            return True
        time.sleep(POLL_INTERVAL)
        elapsed += POLL_INTERVAL
    return False


def _ensure_system_on(redfish_client):
    """Power on the system if it is not currently On."""
    state = _get_power_state(redfish_client)
    if state != "On":
        logger.info("System is {}, sending ResetType=On to restore".format(state))
        redfish_client.post(RESET_PATH, json={"ResetType": "On"})
        assert _wait_for_power_state(redfish_client, "On", POWER_ON_TIMEOUT), \
            "System did not reach PowerState=On within {}s".format(POWER_ON_TIMEOUT)


class TestRedfishComputerReset:

    def test_reset_on(self, redfish_client):
        """
        Test Case #11 — Reset with valid ResetType "On".

        POST ResetType=On and validate system reaches PowerState=On.
        If system is already On, the action is a no-op and 200/204 is still expected.
        """
        response = redfish_client.post(RESET_PATH, json={"ResetType": "On"})
        logger.info("POST {} ResetType=On -> {}".format(RESET_PATH, response.status_code))

        pytest_assert(
            response.status_code in (200, 204),
            "Expected HTTP 200 or 204, got: {}".format(response.status_code)
        )

        reached = _wait_for_power_state(redfish_client, "On", POWER_ON_TIMEOUT)
        pytest_assert(reached, "System did not reach PowerState=On within {}s".format(
            POWER_ON_TIMEOUT))

    def test_reset_graceful_shutdown(self, redfish_client):
        """
        Test Case #12 — Reset with valid ResetType "GracefulShutdown".

        Verifies system powers off gracefully, then restores it to On.
        """
        _ensure_system_on(redfish_client)

        response = redfish_client.post(RESET_PATH, json={"ResetType": "GracefulShutdown"})
        logger.info("POST {} ResetType=GracefulShutdown -> {}".format(RESET_PATH,
                                                                       response.status_code))

        pytest_assert(
            response.status_code in (200, 204),
            "Expected HTTP 200 or 204, got: {}".format(response.status_code)
        )

        reached = _wait_for_power_state(redfish_client, "Off", POWER_OFF_TIMEOUT)
        pytest_assert(reached, "System did not reach PowerState=Off within {}s".format(
            POWER_OFF_TIMEOUT))

        # Restore system to On
        _ensure_system_on(redfish_client)

    def test_reset_force_off(self, redfish_client):
        """
        Test Case #13 — Reset with valid ResetType "ForceOff".

        Verifies system powers off immediately, then restores it to On.
        """
        _ensure_system_on(redfish_client)

        response = redfish_client.post(RESET_PATH, json={"ResetType": "ForceOff"})
        logger.info("POST {} ResetType=ForceOff -> {}".format(RESET_PATH, response.status_code))

        pytest_assert(
            response.status_code in (200, 204),
            "Expected HTTP 200 or 204, got: {}".format(response.status_code)
        )

        reached = _wait_for_power_state(redfish_client, "Off", POWER_OFF_TIMEOUT)
        pytest_assert(reached, "System did not reach PowerState=Off within {}s".format(
            POWER_OFF_TIMEOUT))

        # Restore system to On
        _ensure_system_on(redfish_client)

    def test_reset_power_cycle(self, redfish_client):
        """
        Test Case #14 — Reset with valid ResetType "PowerCycle".

        Verifies system power-cycles and returns to PowerState=On.
        """
        _ensure_system_on(redfish_client)

        response = redfish_client.post(RESET_PATH, json={"ResetType": "PowerCycle"})
        logger.info("POST {} ResetType=PowerCycle -> {}".format(RESET_PATH, response.status_code))

        pytest_assert(
            response.status_code in (200, 204),
            "Expected HTTP 200 or 204, got: {}".format(response.status_code)
        )

        # System may briefly go to Off before returning to On
        reached = _wait_for_power_state(redfish_client, "On", POWER_ON_TIMEOUT)
        pytest_assert(reached, "System did not return to PowerState=On after PowerCycle within {}s".format(
            POWER_ON_TIMEOUT))

    def test_reset_invalid_type(self, redfish_client):
        """
        Test Case #15 — Reset with invalid ResetType is rejected.

        POST ResetType=InvalidType must return HTTP 400 with a Redfish error body.
        """
        response = redfish_client.post(RESET_PATH, json={"ResetType": "InvalidType"})
        logger.info("POST {} ResetType=InvalidType -> {}".format(RESET_PATH, response.status_code))

        pytest_assert(
            response.status_code == 400,
            "Expected HTTP 400 for invalid ResetType, got: {}".format(response.status_code)
        )

        try:
            error_body = response.json()
        except ValueError:
            pytest_assert(False, "Error response is not valid JSON: {}".format(response.text))

        pytest_assert(
            "error" in error_body,
            "Expected Redfish error object with 'error' key, got: {}".format(error_body)
        )
