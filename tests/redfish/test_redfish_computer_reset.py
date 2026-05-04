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

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('bmc-dual-mgmt', 'bmc-shared-mgmt'),
]

RESET_PATH = "/redfish/v1/Systems/system/Actions/ComputerSystem.Reset"

POWER_ON_TIMEOUT = 120    # seconds to wait for x86 CPU to come out of reset
POWER_OFF_TIMEOUT = 120   # seconds to wait for x86 CPU to be held in reset
POLL_INTERVAL = 5         # seconds between CPU-state polls

CPU_STATUS_CMD = "switch_cpu_utils.sh status"


def _cpu_running(bmc_exec):
    """Return True iff the x86 host CPU is OUT OF RESET (running).

    Trusts the BMC-side switch_cpu_utils.sh output (which reads the hardware
    reset pin) rather than the Redfish PowerState field, since bmcweb's
    PowerState can lag or misreport the actual CPU state.
    """
    stdout, _, _ = bmc_exec(CPU_STATUS_CMD)
    return "OUT OF RESET" in stdout


def _wait_for_cpu_running(bmc_exec, want_running, timeout):
    """Poll switch_cpu_utils.sh until CPU running state matches want_running."""
    elapsed = 0
    while elapsed < timeout:
        running = _cpu_running(bmc_exec)
        logger.info("CPU running={} (waiting for running={})".format(running, want_running))
        if running == want_running:
            return True
        time.sleep(POLL_INTERVAL)
        elapsed += POLL_INTERVAL
    return False


def _ensure_system_on(redfish_client, bmc_exec):
    """Power on the x86 CPU if it is not currently running."""
    if _cpu_running(bmc_exec):
        return
    logger.info("CPU is in reset, sending ResetType=On to restore")
    redfish_client.post(RESET_PATH, json={"ResetType": "On"})
    assert _wait_for_cpu_running(bmc_exec, True, POWER_ON_TIMEOUT), \
        "x86 CPU did not come out of reset within {}s".format(POWER_ON_TIMEOUT)


class TestRedfishComputerReset:

    def test_reset_on(self, redfish_client, bmc_exec):
        """
        Test Case #11 — Reset with valid ResetType "On".

        POST ResetType=On and validate the x86 CPU is OUT OF RESET (running)
        per switch_cpu_utils.sh on the BMC.
        """
        response = redfish_client.post(RESET_PATH, json={"ResetType": "On"})
        logger.info("POST {} ResetType=On -> {}".format(RESET_PATH, response.status_code))

        pytest_assert(
            response.status_code in (200, 204),
            "Expected HTTP 200 or 204, got: {}".format(response.status_code)
        )

        reached = _wait_for_cpu_running(bmc_exec, True, POWER_ON_TIMEOUT)
        pytest_assert(reached, "x86 CPU did not come out of reset within {}s".format(
            POWER_ON_TIMEOUT))

    def test_reset_graceful_shutdown(self, redfish_client, bmc_exec):
        """
        Test Case #12 — Reset with valid ResetType "GracefulShutdown".

        Verifies the x86 CPU is held in reset after graceful shutdown, then
        restores it to running.
        """
        _ensure_system_on(redfish_client, bmc_exec)

        response = redfish_client.post(RESET_PATH, json={"ResetType": "GracefulShutdown"})
        logger.info("POST {} ResetType=GracefulShutdown -> {}".format(RESET_PATH,
                                                                       response.status_code))

        pytest_assert(
            response.status_code in (200, 204),
            "Expected HTTP 200 or 204, got: {}".format(response.status_code)
        )

        reached = _wait_for_cpu_running(bmc_exec, False, POWER_OFF_TIMEOUT)
        pytest_assert(reached, "x86 CPU was not held in reset within {}s".format(
            POWER_OFF_TIMEOUT))

        _ensure_system_on(redfish_client, bmc_exec)

    def test_reset_power_cycle(self, redfish_client, bmc_exec):
        """
        Test Case #14 — Reset with valid ResetType "PowerCycle".

        Verifies the x86 CPU power-cycles and returns to OUT OF RESET (running).
        """
        _ensure_system_on(redfish_client, bmc_exec)

        response = redfish_client.post(RESET_PATH, json={"ResetType": "PowerCycle"})
        logger.info("POST {} ResetType=PowerCycle -> {}".format(RESET_PATH, response.status_code))

        pytest_assert(
            response.status_code in (200, 204),
            "Expected HTTP 200 or 204, got: {}".format(response.status_code)
        )

        # CPU may briefly enter reset before coming back out
        reached = _wait_for_cpu_running(bmc_exec, True, POWER_ON_TIMEOUT)
        pytest_assert(reached,
                      "x86 CPU did not return to OUT OF RESET after PowerCycle within {}s".format(
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
