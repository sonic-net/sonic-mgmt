"""
Tests for Redfish ComputerSystem.Reset action endpoint.

WARNING: GracefulShutdown and PowerCycle tests trigger actual power state changes
on the BMC DUT. They restore the system to its original power state after each test.
"""
import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.platform_api import chassis, module as module_api
from tests.common.platform.device_utils import (  # noqa: F401
    platform_api_conn,
    start_platform_api_service
)
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('bmc'),
]

RESET_PATH = "/redfish/v1/Systems/system/Actions/ComputerSystem.Reset"

POWER_ON_TIMEOUT = 120    # seconds to wait for x86 CPU to come out of reset
POWER_OFF_TIMEOUT = 120   # seconds to wait for x86 CPU to be held in reset
POLL_INTERVAL = 5         # seconds between CPU-state polls

POWER_CYCLE_OFF_TIMEOUT = 30
POWER_CYCLE_OFF_POLL = 1

SWITCH_HOST_MODULE_NAME = "SWITCH-HOST"
MODULE_STATUS_ONLINE = "Online"
MODULE_STATUS_OFFLINE = "Offline"


@pytest.fixture(scope="function")
def cpu_running(platform_api_conn):  # noqa: F811
    """Return a callable reporting whether the x86 host CPU is out of reset.

    Reads the hardware reset pin through the SWITCH-HOST module's
    get_oper_status(), which is independent of the Redfish path under test.
    """
    sw_idx = chassis.get_module_index(platform_api_conn, SWITCH_HOST_MODULE_NAME)
    # The RPC layer returns None when the platform raises NotImplementedError,
    # which is a different condition from the module genuinely being absent.
    if sw_idx is None:
        pytest.skip("Chassis does not implement get_module_index()")
    if sw_idx < 0:
        pytest.skip("Device does not expose a {} module".format(SWITCH_HOST_MODULE_NAME))

    def _cpu_running():
        status = module_api.get_oper_status(platform_api_conn, sw_idx)
        normalized = status.lower() if isinstance(status, str) else status
        if normalized == MODULE_STATUS_ONLINE.lower():
            return True
        if normalized == MODULE_STATUS_OFFLINE.lower():
            return False
        # Reading the reset register requires root, which the platform API server
        # has. Anything other than Online/Offline here is a genuine read failure,
        # not a privilege problem, so surface it instead of reporting "in reset".
        raise AssertionError(
            "SWITCH-HOST oper status is {!r}, expected {} or {}: the BMC failed to "
            "read the switch host CPU reset register".format(
                status, MODULE_STATUS_ONLINE, MODULE_STATUS_OFFLINE))

    return _cpu_running


def _cpu_running_or_unknown(cpu_running):
    """Non-raising variant for teardown: an unreadable state counts as not-running.

    pytest.fail.Exception derives from BaseException rather than Exception, so it
    is caught explicitly alongside it (same as wait_until does).
    """
    try:
        return cpu_running()
    except (Exception, pytest.fail.Exception) as e:
        logger.error("Could not read x86 CPU state: %s", e)
        return False


def _cpu_state_matches(cpu_running, want_running):
    """wait_until predicate: True iff the CPU running state matches want_running."""
    running = cpu_running()
    logger.info("CPU running=%s (waiting for running=%s)", running, want_running)
    return running == want_running


def _ensure_system_on(redfish_client, cpu_running):
    """Power on the x86 CPU if it is not currently running."""
    if cpu_running():
        return
    logger.info("CPU is in reset, sending ResetType=On to restore")
    redfish_client.post(RESET_PATH, json={"ResetType": "On"})
    pytest_assert(
        wait_until(POWER_ON_TIMEOUT, POLL_INTERVAL, 0,
                   _cpu_state_matches, cpu_running, True),
        "x86 CPU did not come out of reset within {}s".format(POWER_ON_TIMEOUT),
    )


def _ensure_system_in_reset(redfish_client, cpu_running):
    """Hold the x86 CPU in reset if it is currently running."""
    if not cpu_running():
        return
    logger.info("CPU is running, sending ResetType=GracefulShutdown to enter reset")
    redfish_client.post(RESET_PATH, json={"ResetType": "GracefulShutdown"})
    pytest_assert(
        wait_until(POWER_OFF_TIMEOUT, POLL_INTERVAL, 0,
                   _cpu_state_matches, cpu_running, False),
        "x86 CPU did not enter reset within {}s".format(POWER_OFF_TIMEOUT),
    )


class TestRedfishComputerReset:

    @pytest.fixture(autouse=True)
    def _restore_cpu_on(self, redfish_client, cpu_running):
        """Best-effort finalizer: never leave the x86 CPU held in reset.

        GracefulShutdown / PowerCycle power the CPU off and restore it before
        returning, but a mid-test failure (failed assertion, timeout) would
        otherwise leave the CPU in reset for every subsequent test. This runs
        after each test and powers the CPU back on if it is still in reset,
        logging instead of asserting so it never masks the test's own failure.
        """
        yield
        if _cpu_running_or_unknown(cpu_running):
            return
        logger.warning("CPU left in reset (or unreadable) after test; restoring with ResetType=On")
        redfish_client.post(RESET_PATH, json={"ResetType": "On"})
        if not wait_until(POWER_ON_TIMEOUT, POLL_INTERVAL, 0,
                          _cpu_state_matches, cpu_running, True):
            logger.error("Failed to restore x86 CPU to running state in teardown")

    def test_reset_on_when_already_on(self, redfish_client, cpu_running):
        """
        ResetType=On when the CPU is already running is a no-op.

        Brings the CPU to a running state first, then POST ResetType=On and
        verify the BMC accepts the request and the CPU stays running.
        """
        _ensure_system_on(redfish_client, cpu_running)

        response = redfish_client.post(RESET_PATH, json={"ResetType": "On"})
        logger.info("POST {} ResetType=On -> {}".format(RESET_PATH, response.status_code))

        pytest_assert(
            response.status_code in (200, 204),
            "Expected HTTP 200 or 204, got: {}".format(response.status_code)
        )

        pytest_assert(
            cpu_running(),
            "x86 CPU should remain running after ResetType=On from a running state"
        )

    def test_reset_on_when_in_reset(self, redfish_client, cpu_running):
        """
        ResetType=On brings the CPU out of reset.

        Holds the CPU in reset first, then POST ResetType=On and verify the
        CPU transitions to OUT OF RESET (running).
        """
        _ensure_system_in_reset(redfish_client, cpu_running)

        response = redfish_client.post(RESET_PATH, json={"ResetType": "On"})
        logger.info("POST {} ResetType=On -> {}".format(RESET_PATH, response.status_code))

        pytest_assert(
            response.status_code in (200, 204),
            "Expected HTTP 200 or 204, got: {}".format(response.status_code)
        )

        reached = wait_until(POWER_ON_TIMEOUT, POLL_INTERVAL, 0,
                             _cpu_state_matches, cpu_running, True)
        pytest_assert(reached, "x86 CPU did not come out of reset within {}s".format(
            POWER_ON_TIMEOUT))

    def test_reset_graceful_shutdown(self, redfish_client, cpu_running):
        """
        Reset with valid ResetType "GracefulShutdown".

        Verifies the x86 CPU is held in reset after graceful shutdown, then
        restores it to running.
        """
        _ensure_system_on(redfish_client, cpu_running)

        response = redfish_client.post(RESET_PATH, json={"ResetType": "GracefulShutdown"})
        logger.info("POST {} ResetType=GracefulShutdown -> {}".format(
            RESET_PATH, response.status_code))

        pytest_assert(
            response.status_code in (200, 204),
            "Expected HTTP 200 or 204, got: {}".format(response.status_code)
        )

        reached = wait_until(POWER_OFF_TIMEOUT, POLL_INTERVAL, 0,
                             _cpu_state_matches, cpu_running, False)
        pytest_assert(reached, "x86 CPU was not held in reset within {}s".format(
            POWER_OFF_TIMEOUT))

        _ensure_system_on(redfish_client, cpu_running)

    def test_reset_power_cycle(self, redfish_client, cpu_running):
        """
        Reset with valid ResetType "PowerCycle".

        Observes BOTH transitions — CPU enters reset, then exits reset — so
        the test cannot pass trivially if the BMC silently no-ops the API and
        leaves the CPU running the whole time.
        """
        _ensure_system_on(redfish_client, cpu_running)

        response = redfish_client.post(RESET_PATH, json={"ResetType": "PowerCycle"})
        logger.info("POST {} ResetType=PowerCycle -> {}".format(RESET_PATH, response.status_code))

        pytest_assert(
            response.status_code in (200, 204),
            "Expected HTTP 200 or 204, got: {}".format(response.status_code)
        )

        # First observe the off-transition. The off-window is brief (~1-2s),
        # so poll faster than POLL_INTERVAL to avoid missing it.
        entered_reset = wait_until(POWER_CYCLE_OFF_TIMEOUT, POWER_CYCLE_OFF_POLL, 0,
                                   _cpu_state_matches, cpu_running, False)
        pytest_assert(
            entered_reset,
            "x86 CPU did not enter reset after PowerCycle within {}s — "
            "BMC may have silently no-op'd the API".format(POWER_CYCLE_OFF_TIMEOUT),
        )

        # Then wait for it to come back out.
        reached = wait_until(POWER_ON_TIMEOUT, POLL_INTERVAL, 0,
                             _cpu_state_matches, cpu_running, True)
        pytest_assert(reached,
                      "x86 CPU did not return to OUT OF RESET after PowerCycle within {}s".format(
                          POWER_ON_TIMEOUT))

    def test_reset_invalid_type(self, redfish_client):
        """
        Reset with invalid ResetType is rejected.

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
            error_body = None
        pytest_assert(
            isinstance(error_body, dict),
            "Error response is not a valid JSON object: {}".format(response.text)
        )

        # Redfish error responses carry an "error" object with at least a
        # "code" and a "message" field (DSP0266 error payload shape).
        error = (error_body or {}).get("error")
        pytest_assert(
            isinstance(error, dict),
            "Expected a Redfish error object under 'error', got: {}".format(error_body)
        )
        pytest_assert(
            "code" in (error or {}) and "message" in (error or {}),
            "Redfish error object must contain 'code' and 'message', got: {}".format(error)
        )
