"""
Tests for Redfish ComputerSystem.Reset action endpoint.

WARNING: GracefulShutdown, ForceOff and PowerCycle tests trigger actual power state
changes on the BMC DUT. They restore the system to its original power state after each test.
"""
import logging
import time

import pytest

from ansible.errors import AnsibleConnectionFailure
from pytest_ansible.errors import AnsibleConnectionFailure as PytestAnsibleConnectionFailure

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.platform_api import chassis, module as module_api
from tests.common.helpers.sonic_db import STATE_DB, redis_hgetall, redis_keys
from tests.common.platform.device_utils import (  # noqa: F401
    platform_api_conn,
    start_platform_api_service
)
from tests.common.utilities import wait_until
from tests.redfish.redfish_utils import assert_no_content, assert_redfish_error

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('bmc'),
]

RESET_PATH = "/redfish/v1/Systems/system/Actions/ComputerSystem.Reset"

POWER_ON_TIMEOUT = 120    # seconds to wait for x86 CPU to come out of reset
POWER_OFF_TIMEOUT = 120   # seconds to wait for x86 CPU to be held in reset
POLL_INTERVAL = 5         # seconds between CPU-state polls

HOST_BOOT_TIMEOUT = 600      # seconds for the switch host to boot back to SSH after PowerCycle
HOST_RESOLVE_TIMEOUT = 300   # seconds to resolve the switch host before the test issues a reset
HOST_POLL_INTERVAL = 10      # seconds between boot-id polls

SWITCH_HOST_MODULE_NAME = "SWITCH-HOST"
MODULE_STATUS_ONLINE = "Online"
MODULE_STATUS_OFFLINE = "Offline"

# ForceOff is the one ResetType bmcweb routes through the Chassis rather than the
# Host transition; sonic-dbus-bridge writes it to STATE_DB as this command.
COMMAND_KEY_GLOB = "RACK_MANAGER_COMMAND|*"
CMD_POWER_OFF = "POWER_OFF"
COMMAND_ROW_TIMEOUT = 30
COMMAND_POLL = 1


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


@pytest.fixture(scope="function")
def switch_host(bmc_duthost):
    """Return a callable resolving the host-side switch once it answers over SSH.

    Building the host object gathers facts over SSH, so it cannot run while the
    host is still booting. A preceding test in this class may have just cycled
    the host, and the CPU leaving reset does not mean the host is up yet, so
    resolve it lazily from the test body and retry the connection rather than
    erroring during fixture setup. Only connection failures are retried; a
    device that is not a BMC, or a testbed file with no host-side switch, fails
    immediately.
    """
    def _switch_host():
        deadline = time.time() + HOST_RESOLVE_TIMEOUT
        while True:
            try:
                return bmc_duthost.get_bmc_host()
            except (AnsibleConnectionFailure, PytestAnsibleConnectionFailure) as e:
                if time.time() >= deadline:
                    pytest.fail(
                        "Switch host was still unreachable {}s into this test, before any reset "
                        "was issued, so it did not come back from an earlier power operation: "
                        "{}".format(HOST_RESOLVE_TIMEOUT, e))
                logger.info("Switch host not reachable yet, retrying in %ss", HOST_POLL_INTERVAL)
                time.sleep(HOST_POLL_INTERVAL)

    return _switch_host


def _host_boot_id(switch_host):
    """Return the switch host's boot id, or None while it is unreachable (e.g. mid-reboot)."""
    try:
        res = switch_host.command("cat /proc/sys/kernel/random/boot_id", module_ignore_errors=True)
    except (AnsibleConnectionFailure, PytestAnsibleConnectionFailure):
        return None
    if res.get("rc", 1) != 0:
        return None
    # An empty read is not an identity: returning "" would compare unequal to the
    # id captured before the reset and report a reboot that never happened.
    return res.get("stdout", "").strip() or None


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

        assert_no_content(response, RESET_PATH)

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

        assert_no_content(response, RESET_PATH)

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

        assert_no_content(response, RESET_PATH)

        reached = wait_until(POWER_OFF_TIMEOUT, POLL_INTERVAL, 0,
                             _cpu_state_matches, cpu_running, False)
        pytest_assert(reached, "x86 CPU was not held in reset within {}s".format(
            POWER_OFF_TIMEOUT))

        _ensure_system_on(redfish_client, cpu_running)

    def test_reset_force_off(self, redfish_client, bmc_duthost, cpu_running):
        """
        Reset with valid ResetType "ForceOff".

        ForceOff removes power without a graceful shutdown. It must be
        accepted, become exactly one RACK_MANAGER_COMMAND row with
        command=POWER_OFF (GracefulShutdown writes GRACEFUL_SHUT), and hold
        the x86 CPU in reset. Restores the CPU to running afterwards.
        """
        _ensure_system_on(redfish_client, cpu_running)
        keys_before = set(redis_keys(bmc_duthost, STATE_DB, COMMAND_KEY_GLOB))

        response = redfish_client.post(RESET_PATH, json={"ResetType": "ForceOff"})
        logger.info("POST {} ResetType=ForceOff -> {}".format(RESET_PATH, response.status_code))

        assert_no_content(response, RESET_PATH)

        def _new_command_keys():
            return set(redis_keys(bmc_duthost, STATE_DB, COMMAND_KEY_GLOB)) - keys_before

        pytest_assert(
            wait_until(COMMAND_ROW_TIMEOUT, COMMAND_POLL, 0, _new_command_keys),
            "No RACK_MANAGER_COMMAND row appeared within {}s of ForceOff".format(COMMAND_ROW_TIMEOUT)
        )
        new_keys = _new_command_keys()
        pytest_assert(len(new_keys) == 1, "One ForceOff must create one command row, got: {}".format(sorted(new_keys)))
        key = new_keys.pop()
        command = redis_hgetall(bmc_duthost, STATE_DB, key).get("command")
        pytest_assert(
            command == CMD_POWER_OFF,
            "{} command must be {} for ResetType=ForceOff, got: {!r}".format(key, CMD_POWER_OFF, command)
        )
        logger.info("ForceOff became {} command={}".format(key, command))

        reached = wait_until(POWER_OFF_TIMEOUT, POLL_INTERVAL, 0,
                             _cpu_state_matches, cpu_running, False)
        pytest_assert(reached, "x86 CPU was not held in reset within {}s of ForceOff".format(
            POWER_OFF_TIMEOUT))

        _ensure_system_on(redfish_client, cpu_running)

    def test_reset_power_cycle(self, redfish_client, cpu_running, switch_host):
        """
        Reset with valid ResetType "PowerCycle".

        Proves the cycle by the switch host's boot id changing, which happens
        only on an actual restart, so a BMC that no-ops the API still fails.
        """
        _ensure_system_on(redfish_client, cpu_running)

        host = switch_host()
        boot_id_before = _host_boot_id(host)
        pytest_assert(boot_id_before is not None,
                      "Could not read the switch host boot id before PowerCycle")

        response = redfish_client.post(RESET_PATH, json={"ResetType": "PowerCycle"})
        logger.info("POST {} ResetType=PowerCycle -> {}".format(RESET_PATH, response.status_code))

        assert_no_content(response, RESET_PATH)

        def _host_rebooted():
            boot_id = _host_boot_id(host)
            return boot_id is not None and boot_id != boot_id_before

        pytest_assert(
            wait_until(HOST_BOOT_TIMEOUT, HOST_POLL_INTERVAL, 0, _host_rebooted),
            "Switch host boot id did not change within {}s of PowerCycle: either the BMC "
            "silently no-op'd the API or the host did not boot back".format(HOST_BOOT_TIMEOUT),
        )

    def test_reset_invalid_type(self, redfish_client):
        """
        Reset with a ResetType outside the Redfish enum is rejected.

        POST ResetType=InvalidType must return HTTP 400 with a Redfish error
        carrying ActionParameterUnknown for the Reset action and the value sent.
        """
        response = redfish_client.post(RESET_PATH, json={"ResetType": "InvalidType"})
        logger.info("POST {} ResetType=InvalidType -> {} {!r}".format(
            RESET_PATH, response.status_code, response.text[:300]))

        assert_redfish_error(response, 400, "ActionParameterUnknown", message_args=["Reset", "InvalidType"])
