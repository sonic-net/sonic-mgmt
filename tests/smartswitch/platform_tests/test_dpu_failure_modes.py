"""
Tests for new DPU failure modes introduced by the DPU robustness enhancement.

Covers:
  - databasedpu crash on NPU: per-DPU Redis instance crash and recovery
  - PCIe failure: PCIe link loss detection and chassisd-driven recovery
  - Control-plane-only down: DPU control plane goes down while midplane stays up

Reference: sonic-net/sonic-buildimage#27450
HLD: sonic-net/SONiC#2310
"""

import ast
import logging
import re
import time
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.platform.processes_utils import wait_critical_processes
from tests.smartswitch.common.device_utils_dpu import (
    post_test_dpus_check,
    check_dpu_module_status,
    get_dpuhost_for_dpu,
    get_dpu_state_from_chassis_state_db,
    check_dpu_ready_state, check_dpu_not_ready_state,
    assert_dpu_db_state_ready,
    get_dpu_auto_recovery, set_dpu_auto_recovery,
    DPU_AUTO_RECOVERY_ENABLE, DPU_AUTO_RECOVERY_DISABLE,
    DPU_MAX_ONLINE_TIMEOUT, DPU_TIME_INT,
    DPU_READY_AFTER_RECOVERY_TIMEOUT,
)
# Fixtures — imported for pytest discovery, not called directly
from tests.smartswitch.common.device_utils_dpu import num_dpu_modules  # noqa: F401

pytestmark = [
    pytest.mark.topology('smartswitch')
]

# Timeouts in seconds
DATABASEDPU_RECOVERY_TIMEOUT = 300
PCIE_RECOVERY_TIMEOUT = 360
CONTROL_PLANE_DOWN_DETECT_TIMEOUT = 120
# Window to confirm the midplane stays up after a control-plane-only failure.
MIDPLANE_STABILITY_WAIT = 15


# ---------------------------------------------------------------------------
# databasedpu crash on NPU
# ---------------------------------------------------------------------------

class TestDatabaseDpuCrash:
    """
    Test: Kill the per-DPU Redis database instance (databasedpu<N>) on the NPU
    and verify chassisd detects the failure, marks the DPU as not-ready, and
    recovers once the database instance is restarted by systemd.

    Expected behavior per HLD:
      - chassisd detects loss of DPU state → ready_status = false
      - systemd restarts the Redis instance
      - chassisd re-polls DPU state → ready_status = true
    """

    def _get_databasedpu_service(self, dpu_name):
        """Get the systemd service name for the per-DPU database container."""
        return f"database{dpu_name.lower()}"

    def _is_databasedpu_running(self, duthost, service_name):
        """Check if the databasedpu service is active."""
        result = duthost.shell(
            f"systemctl is-active {service_name}",
            module_ignore_errors=True
        )
        return result.get("stdout", "").strip() == "active"

    @pytest.mark.disable_loganalyzer
    def test_dpu_recovery_after_databasedpu_crash(
        self, dpuhosts, prepare_testable_dpus, num_dpu_modules  # noqa: F811
    ):
        """
        Steps:
        1. Pre-test: for each DPU in dpuhosts, bring admin-up if needed.
        2. Kill the databasedpu container for each DPU.
        3. Verify chassisd detects failure: ready_status transitions to false.
        4. Wait for systemd to restart the database instance.
        5. Verify chassisd recovers: ready_status transitions back to true.
        """
        duthost, testable_dpus, testable_ips = prepare_testable_dpus

        for dpu_name in testable_dpus:
            service_name = self._get_databasedpu_service(dpu_name)

            logging.info("Verifying %s is running before kill", service_name)
            pytest_assert(
                self._is_databasedpu_running(duthost, service_name),
                f"{service_name} is not running before test"
            )

            logging.info("Killing %s to simulate databasedpu crash", service_name)
            duthost.shell(f"sudo systemctl kill -s KILL {service_name}")

            logging.info("Verifying chassisd detects %s failure (ready_status=false)", dpu_name)
            pytest_assert(
                wait_until(CONTROL_PLANE_DOWN_DETECT_TIMEOUT, DPU_TIME_INT, 0,
                           check_dpu_not_ready_state, duthost, dpu_name),
                f"{dpu_name}: ready_status did not transition to false after "
                f"databasedpu crash. State: "
                f"{get_dpu_state_from_chassis_state_db(duthost, dpu_name)}"
            )

            logging.info("Waiting for systemd to restart %s", service_name)
            pytest_assert(
                wait_until(DATABASEDPU_RECOVERY_TIMEOUT, DPU_TIME_INT, 0,
                           self._is_databasedpu_running, duthost, service_name),
                f"{service_name} did not restart within {DATABASEDPU_RECOVERY_TIMEOUT}s"
            )

        logging.info("Verifying all tested DPUs recover to ready state")
        for dpu_name in testable_dpus:
            assert_dpu_db_state_ready(duthost, dpu_name,
                                      timeout=DPU_READY_AFTER_RECOVERY_TIMEOUT)

        logging.info("Post-test: verifying DPU connectivity")
        post_test_dpus_check(duthost, dpuhosts,
                             testable_dpus, testable_ips,
                             num_dpu_modules, None)


# ---------------------------------------------------------------------------
# PCIe failure
# ---------------------------------------------------------------------------

class TestPcieFailure:
    """
    Test: Simulate PCIe link failure by detaching the DPU's PCIe device and
    verify chassisd detects the failure, power-cycles the DPU, performs PCIe
    rescan, and recovers.

    Expected behavior per HLD:
      - pcied detects PCIe link down → PCIE_DETACH_INFO|DPU<N> dpu_state=detached
      - chassisd detects midplane loss → ready_status=false
      - chassisd power-cycles DPU + PCIe rescan
      - DPU boots and reports ready_status=true
    """

    def _get_pcie_detach_info(self, duthost, dpu_name):
        """Read PCIE_DETACH_INFO from STATE_DB for a given DPU."""
        cmd = f"sonic-db-cli STATE_DB hgetall 'PCIE_DETACH_INFO|{dpu_name}'"
        result = duthost.shell(cmd, module_ignore_errors=True)
        stdout = result.get("stdout", "").strip()
        if not stdout or result.get("rc", 1) != 0:
            return {}

        if stdout.startswith("{"):
            try:
                parsed = ast.literal_eval(stdout)
                if isinstance(parsed, dict):
                    return {str(k).strip(): str(v).strip() for k, v in parsed.items()}
            except (ValueError, SyntaxError):
                # Not a dict literal; fall back to line-by-line parsing below.
                pass

        lines = stdout.splitlines()
        info = {}
        for i in range(0, len(lines) - 1, 2):
            info[lines[i].strip()] = lines[i + 1].strip()
        return info

    def _get_dpu_pcie_bus_info(self, duthost, dpu_name):
        """
        Get the PCIe bus address for a DPU from PCIE_DETACH_INFO or platform data.
        Returns bus_info string like '0000:03:00.0' or None.
        """
        info = self._get_pcie_detach_info(duthost, dpu_name)
        bus_info = info.get("bus_info")
        if bus_info:
            return bus_info

        # Fallback: try platform.json or lspci
        result = duthost.shell(
            f"sonic-db-cli STATE_DB hget 'PCIE_DETACH_INFO|{dpu_name}' 'bus_info'",
            module_ignore_errors=True
        )
        stdout = result.get("stdout", "").strip()
        return stdout if stdout else None

    def _check_pcie_detached(self, duthost, dpu_name):
        """Check if PCIe state is 'detached' in STATE_DB."""
        info = self._get_pcie_detach_info(duthost, dpu_name)
        return info.get("dpu_state", "").lower() == "detached"

    def _check_pcie_reattached(self, duthost, dpu_name):
        """Check if PCIe state is 'reattached' in STATE_DB."""
        info = self._get_pcie_detach_info(duthost, dpu_name)
        return info.get("dpu_state", "").lower() == "reattached"

    @pytest.mark.disable_loganalyzer
    def test_dpu_recovery_after_pcie_detach(
        self, dpuhosts, prepare_testable_dpus, num_dpu_modules  # noqa: F811
    ):
        """
        Steps:
        1. Pre-test: verify all DPUs are ready.
        2. For one DPU, remove its PCIe device via sysfs to simulate PCIe failure.
        3. Verify pcied detects: PCIE_DETACH_INFO dpu_state = detached.
        4. Verify chassisd detects: ready_status = false.
        5. Wait for chassisd to power-cycle the DPU and perform PCIe rescan.
        6. Verify recovery: ready_status = true, PCIE_DETACH_INFO = reattached.
        """
        duthost, testable_dpus, testable_ips = prepare_testable_dpus

        # Test on the first DPU
        target_dpu = testable_dpus[0]

        bus_info = self._get_dpu_pcie_bus_info(duthost, target_dpu)
        if not bus_info:
            pytest.skip(f"Cannot determine PCIe bus_info for {target_dpu}. "
                        "PCIE_DETACH_INFO not populated. Platform may not support this test.")

        logging.info("Simulating PCIe failure for %s by removing device at %s",
                     target_dpu, bus_info)
        remove_cmd = f"echo 1 | sudo tee /sys/bus/pci/devices/{bus_info}/remove"
        duthost.shell(remove_cmd)

        logging.info("Verifying pcied detects PCIe detach for %s", target_dpu)
        pytest_assert(
            wait_until(PCIE_RECOVERY_TIMEOUT, DPU_TIME_INT, 0,
                       self._check_pcie_detached, duthost, target_dpu),
            f"{target_dpu}: PCIE_DETACH_INFO did not show 'detached' after PCIe removal. "
            f"Info: {self._get_pcie_detach_info(duthost, target_dpu)}"
        )

        logging.info("Verifying chassisd detects %s failure (ready_status=false)", target_dpu)
        pytest_assert(
            wait_until(CONTROL_PLANE_DOWN_DETECT_TIMEOUT, DPU_TIME_INT, 0,
                       check_dpu_not_ready_state, duthost, target_dpu),
            f"{target_dpu}: ready_status did not transition to false after PCIe detach. "
            f"State: {get_dpu_state_from_chassis_state_db(duthost, target_dpu)}"
        )

        logging.info("Waiting for chassisd to recover %s (power-cycle + PCIe rescan)",
                     target_dpu)
        assert_dpu_db_state_ready(duthost, target_dpu,
                                  timeout=DPU_READY_AFTER_RECOVERY_TIMEOUT)

        logging.info("Verifying PCIe is reattached for %s", target_dpu)
        pytest_assert(
            wait_until(DPU_MAX_ONLINE_TIMEOUT, DPU_TIME_INT, 0,
                       self._check_pcie_reattached, duthost, target_dpu),
            f"{target_dpu}: PCIE_DETACH_INFO did not return to 'reattached'. "
            f"Info: {self._get_pcie_detach_info(duthost, target_dpu)}"
        )

        logging.info("Post-test: verifying DPU connectivity and state")
        post_test_dpus_check(duthost, dpuhosts,
                             testable_dpus, testable_ips,
                             num_dpu_modules, None)


# ---------------------------------------------------------------------------
# Control-plane-only down
# ---------------------------------------------------------------------------

class TestControlPlaneOnlyDown:
    """
    Test: Simulate DPU control plane going down while midplane stays up.
    This happens when a critical container on the DPU fails, causing
    SYSTEM_READY to go false (dpu_control_plane_state=down) while the
    DPU is still reachable via midplane.

    Expected behavior per HLD:
      - chassisd polls dpu_control_plane_state and observes 'down'
      - chassisd sets ready_status=false, issues power-cycle
      - DPU recovers: ready_status=true
    """

    def _stop_critical_container_on_dpu(self, dpuhost, container="swss"):
        """
        Stop a critical container on the DPU to trigger SYSTEM_READY=false
        without killing the DPU OS (midplane stays up).
        """
        logging.info("%s: stopping critical container '%s'", dpuhost.hostname, container)
        dpuhost.shell(f"sudo systemctl stop {container}", module_ignore_errors=True)

    def _check_control_plane_down(self, duthost, dpu_name):
        """Check if dpu_control_plane_state is 'down' in CHASSIS_STATE_DB."""
        state = get_dpu_state_from_chassis_state_db(duthost, dpu_name)
        return state.get("dpu_control_plane_state", "").lower() == "down"

    def _check_midplane_still_up(self, duthost, dpu_name):
        """Check if dpu_midplane_link_state is still 'up' in CHASSIS_STATE_DB."""
        state = get_dpu_state_from_chassis_state_db(duthost, dpu_name)
        return state.get("dpu_midplane_link_state", "").lower() == "up"

    @pytest.mark.disable_loganalyzer
    def test_dpu_recovery_after_control_plane_down(
        self, dpuhosts, prepare_testable_dpus, num_dpu_modules  # noqa: F811
    ):
        """
        Steps:
        1. Pre-test: verify all DPUs are ready.
        2. Stop a critical container (swss) on one DPU to make
           SYSTEM_READY go false.
        3. Verify midplane stays up (DPU OS is still running).
        4. Verify chassisd detects control-plane-down: ready_status = false,
           dpu_control_plane_state = down.
        5. Wait for chassisd to power-cycle and recover the DPU.
        6. Verify recovery: ready_status = true, all planes up.
        """
        duthost, testable_dpus, testable_ips = prepare_testable_dpus

        # Test on the first DPU
        target_dpu = testable_dpus[0]
        dpu_id = int(re.search(r'\d+', target_dpu).group())

        dpuhost = get_dpuhost_for_dpu(dpuhosts, dpu_id)

        logging.info("Stopping critical container on %s to trigger control-plane-down",
                     target_dpu)
        self._stop_critical_container_on_dpu(dpuhost, container="swss")

        logging.info("Verifying midplane stays up for %s (DPU OS still running)", target_dpu)
        # Let chassisd react, then confirm the midplane (PCIe link) stayed up.
        time.sleep(MIDPLANE_STABILITY_WAIT)
        pytest_assert(
            self._check_midplane_still_up(duthost, target_dpu),
            f"{target_dpu}: midplane went down unexpectedly after stopping swss. "
            f"State: {get_dpu_state_from_chassis_state_db(duthost, target_dpu)}"
        )

        logging.info("Verifying chassisd detects control-plane-down for %s", target_dpu)
        pytest_assert(
            wait_until(CONTROL_PLANE_DOWN_DETECT_TIMEOUT, DPU_TIME_INT, 0,
                       self._check_control_plane_down, duthost, target_dpu),
            f"{target_dpu}: dpu_control_plane_state did not transition to 'down' "
            f"after stopping swss container. "
            f"State: {get_dpu_state_from_chassis_state_db(duthost, target_dpu)}"
        )

        logging.info("Verifying chassisd marks %s as not-ready", target_dpu)
        pytest_assert(
            wait_until(CONTROL_PLANE_DOWN_DETECT_TIMEOUT, DPU_TIME_INT, 0,
                       check_dpu_not_ready_state, duthost, target_dpu),
            f"{target_dpu}: ready_status did not transition to false after "
            f"control-plane-down. "
            f"State: {get_dpu_state_from_chassis_state_db(duthost, target_dpu)}"
        )

        logging.info("Waiting for chassisd to power-cycle and recover %s", target_dpu)
        assert_dpu_db_state_ready(duthost, target_dpu,
                                  timeout=DPU_READY_AFTER_RECOVERY_TIMEOUT)

        logging.info("Post-test: verifying full DPU state and connectivity")
        post_test_dpus_check(duthost, dpuhosts,
                             testable_dpus, testable_ips,
                             num_dpu_modules,
                             re.compile(r"reboot|Non-Hardware", re.IGNORECASE))


# ---------------------------------------------------------------------------
# Auto-Recovery Flag (disabled)
# ---------------------------------------------------------------------------

class TestAutoRecoveryDisabled:
    """
    Test: With DEVICE_METADATA|localhost dpu_auto_recovery=disable, verify
    chassisd does NOT automatically power-cycle a failed DPU
    (ManualIntervention state).

    Expected behavior per HLD:
      - chassisd detects DPU failure (control-plane-down)
      - chassisd sets ready_status=false
      - chassisd does NOT issue power-cycle (auto-recovery disabled)
      - DPU remains in ManualIntervention until operator intervention
      - After re-enabling, chassisd recovers the DPU
    """

    # Time to wait to confirm no recovery happens (negative test)
    NO_RECOVERY_WAIT = 90

    @pytest.mark.disable_loganalyzer
    def test_no_recovery_when_auto_recovery_disabled(
        self, dpuhosts, prepare_testable_dpus, num_dpu_modules  # noqa: F811
    ):
        """
        Steps:
        1. Pre-test: verify all DPUs are ready.
        2. Disable dpu_auto_recovery.
        3. Stop critical container (swss) on one DPU to trigger failure.
        4. Verify chassisd detects failure (ready_status=false).
        5. Wait and confirm chassisd does NOT power-cycle the DPU
           (DPU stays in not-ready state, no reboot).
        6. Re-enable dpu_auto_recovery.
        7. Verify chassisd now recovers the DPU (ready_status=true).
        """
        duthost, testable_dpus, testable_ips = prepare_testable_dpus

        target_dpu = testable_dpus[0]
        dpu_id = int(re.search(r'\d+', target_dpu).group())
        dpuhost = get_dpuhost_for_dpu(dpuhosts, dpu_id)

        # Save original state for cleanup
        original_state = get_dpu_auto_recovery(duthost)

        try:
            logging.info("Disabling dpu_auto_recovery")
            set_dpu_auto_recovery(duthost, DPU_AUTO_RECOVERY_DISABLE)

            logging.info("Stopping swss on %s to trigger control-plane-down", target_dpu)
            dpuhost.shell("sudo systemctl stop swss", module_ignore_errors=True)

            logging.info("Verifying chassisd detects failure for %s", target_dpu)
            pytest_assert(
                wait_until(CONTROL_PLANE_DOWN_DETECT_TIMEOUT, DPU_TIME_INT, 0,
                           check_dpu_not_ready_state, duthost, target_dpu),
                f"{target_dpu}: ready_status did not transition to false. "
                f"State: {get_dpu_state_from_chassis_state_db(duthost, target_dpu)}"
            )

            logging.info("Waiting %ds to confirm chassisd does NOT auto-recover %s",
                         self.NO_RECOVERY_WAIT, target_dpu)
            time.sleep(self.NO_RECOVERY_WAIT)

            # DPU should still be not-ready (no power-cycle issued)
            state = get_dpu_state_from_chassis_state_db(duthost, target_dpu)
            pytest_assert(
                state.get("ready_status", "").lower() == "false",
                f"{target_dpu}: DPU unexpectedly recovered while auto-recovery "
                f"was disabled. State: {state}"
            )
            logging.info("%s confirmed: still not-ready (no auto-recovery)", target_dpu)

            logging.info("Re-enabling dpu_auto_recovery")
            set_dpu_auto_recovery(duthost, DPU_AUTO_RECOVERY_ENABLE)

            logging.info("Waiting for chassisd to auto-recover %s", target_dpu)
            assert_dpu_db_state_ready(duthost, target_dpu,
                                      timeout=DPU_READY_AFTER_RECOVERY_TIMEOUT)

        finally:
            # Restore original auto-recovery state
            if original_state and original_state != DPU_AUTO_RECOVERY_DISABLE:
                set_dpu_auto_recovery(duthost, original_state)

        logging.info("Post-test: verifying DPU connectivity")
        post_test_dpus_check(duthost, dpuhosts,
                             testable_dpus, testable_ips,
                             num_dpu_modules,
                             re.compile(r"reboot|Non-Hardware", re.IGNORECASE))


# ---------------------------------------------------------------------------
# Unrecoverable State (reset_limit exceeded)
# ---------------------------------------------------------------------------

class TestUnrecoverableState:
    """
    Test: Verify that after reset_limit consecutive unplanned failures,
    chassisd marks the DPU as recovery_status=unrecoverable and stops
    retrying power-cycles.

    Expected behavior per HLD:
      - Each failure increments reset_count
      - When reset_count >= reset_limit, recovery_status = unrecoverable
      - chassisd stops further automatic power-cycle attempts
    """

    def _get_reset_count(self, duthost, dpu_name):
        """Get current reset_count from CHASSIS_STATE_DB."""
        state = get_dpu_state_from_chassis_state_db(duthost, dpu_name)
        count_str = state.get("reset_count", "0")
        try:
            return int(count_str)
        except ValueError:
            return 0

    def _get_recovery_status(self, duthost, dpu_name):
        """Get current recovery_status from CHASSIS_STATE_DB."""
        state = get_dpu_state_from_chassis_state_db(duthost, dpu_name)
        return state.get("recovery_status", "").lower()

    def _get_reset_limit(self, duthost):
        """
        Get the DPU reset limit from platform.json, defaulting to chassisd's
        DEFAULT_DPU_RESET_LIMIT (2). The key must match the one chassisd reads
        (dpu_reset_limit); otherwise the test's notion of the limit would
        diverge from chassisd's.
        """
        cmd = ("python3 -c \"import json; "
               "d=json.load(open('/usr/share/sonic/platform/platform.json')); "
               "print(d.get('dpu_reset_limit', 2))\"")
        result = duthost.shell(cmd, module_ignore_errors=True)
        try:
            return int(result.get("stdout", "2").strip())
        except ValueError:
            return 2

    def _check_unrecoverable(self, duthost, dpu_name):
        """Check if DPU is marked unrecoverable."""
        return self._get_recovery_status(duthost, dpu_name) == "unrecoverable"

    @pytest.mark.disable_loganalyzer
    def test_dpu_marked_unrecoverable_after_reset_limit(
        self, dpuhosts, prepare_testable_dpus, num_dpu_modules  # noqa: F811
    ):
        """
        Steps:
        1. Pre-test: verify all DPUs are ready.
        2. Read the reset_limit from platform.json (default 2).
        3. Repeatedly trigger DPU failures (stop swss) and let chassisd
           power-cycle until reset_count reaches reset_limit. chassisd checks
           reset_count >= reset_limit *before* incrementing/power-cycling, so
           reaching 'unrecoverable' requires reset_limit + 1 failures.
        4. Verify recovery_status transitions to 'unrecoverable'.
        5. Verify chassisd stops retrying (DPU stays not-ready).
        6. Cleanup: restart chassisd/pmon to reset the state.
        """
        duthost, testable_dpus, testable_ips = prepare_testable_dpus

        target_dpu = testable_dpus[0]
        dpu_id = int(re.search(r'\d+', target_dpu).group())

        reset_limit = self._get_reset_limit(duthost)
        logging.info("Reset limit for platform: %d", reset_limit)

        initial_reset_count = self._get_reset_count(duthost, target_dpu)
        logging.info("%s initial reset_count: %d", target_dpu, initial_reset_count)

        # chassisd checks the limit before incrementing, so one failure beyond
        # reset_limit is needed to mark the DPU unrecoverable.
        max_failures = reset_limit + 1
        for attempt in range(max_failures):
            current_count = self._get_reset_count(duthost, target_dpu)
            logging.info("Failure attempt %d/%d (current reset_count=%d)",
                         attempt + 1, max_failures, current_count)

            if self._check_unrecoverable(duthost, target_dpu):
                logging.info("%s already marked unrecoverable at attempt %d",
                             target_dpu, attempt + 1)
                break

            # Wait for DPU to be ready before triggering next failure
            if attempt > 0:
                logging.info("Waiting for %s to recover before next failure trigger",
                             target_dpu)
                pytest_assert(
                    wait_until(DPU_READY_AFTER_RECOVERY_TIMEOUT, DPU_TIME_INT, 0,
                               check_dpu_ready_state, duthost, target_dpu),
                    f"{target_dpu}: did not recover before attempt {attempt + 1}. "
                    f"State: {get_dpu_state_from_chassis_state_db(duthost, target_dpu)}"
                )

            # Trigger failure: stop swss on DPU
            dpuhost = get_dpuhost_for_dpu(dpuhosts, dpu_id)
            if dpuhost is None:
                pytest.skip(f"DPU{dpu_id} not in dpuhosts, no SSH access")

            dpuhost.shell("sudo systemctl stop swss", module_ignore_errors=True)

            # Wait for chassisd to detect and mark not-ready
            pytest_assert(
                wait_until(CONTROL_PLANE_DOWN_DETECT_TIMEOUT, DPU_TIME_INT, 0,
                           check_dpu_not_ready_state, duthost, target_dpu),
                f"{target_dpu}: ready_status did not become false on attempt {attempt + 1}"
            )

        # Verify DPU is now unrecoverable
        logging.info("Verifying %s is marked unrecoverable", target_dpu)
        pytest_assert(
            wait_until(DPU_READY_AFTER_RECOVERY_TIMEOUT, DPU_TIME_INT, 0,
                       self._check_unrecoverable, duthost, target_dpu),
            f"{target_dpu}: recovery_status did not become 'unrecoverable' "
            f"after {max_failures} failures. "
            f"State: {get_dpu_state_from_chassis_state_db(duthost, target_dpu)}"
        )

        final_count = self._get_reset_count(duthost, target_dpu)
        logging.info("%s final reset_count=%d, recovery_status=unrecoverable",
                     target_dpu, final_count)
        pytest_assert(
            final_count >= reset_limit,
            f"{target_dpu}: reset_count ({final_count}) < reset_limit ({reset_limit})"
        )

        # Cleanup (pmon restart + wait for recovery) is handled by the
        # prepare_testable_dpus fixture teardown, so it runs even on failure.


# ---------------------------------------------------------------------------
# State Machine Transitions
# ---------------------------------------------------------------------------

class TestStateMachineTransitions:
    """
    Test: Verify the DPU state machine transitions tracked in CHASSIS_STATE_DB
    during planned operations (shutdown → offline → startup → booting → ready).

    Verifies:
      - Ready → Offline: shutdown sets ready_status=false, oper_status=Offline
      - Offline → Booting: startup triggers boot, control_plane=down
      - Booting → Ready: all planes up, ready_status=true
    """

    def _check_dpu_offline_state(self, duthost, dpu_name):
        """Check DPU is in offline state: ready_status=false, module offline."""
        state = get_dpu_state_from_chassis_state_db(duthost, dpu_name)
        ready = state.get("ready_status", "").lower() == "false"
        module_off = check_dpu_module_status(duthost, "off", dpu_name)
        return ready and module_off

    def _check_dpu_booting_state(self, duthost, dpu_name):
        """
        Check DPU is in booting state: module online but control plane not yet up.
        """
        state = get_dpu_state_from_chassis_state_db(duthost, dpu_name)
        ready = state.get("ready_status", "").lower() == "false"
        cp_down = state.get("dpu_control_plane_state", "").lower() == "down"
        module_on = check_dpu_module_status(duthost, "on", dpu_name)
        return ready and cp_down and module_on

    @pytest.mark.disable_loganalyzer
    def test_shutdown_startup_state_transitions(
        self, dpuhosts, prepare_testable_dpus, num_dpu_modules  # noqa: F811
    ):
        """
        Steps:
        1. Pre-test: verify DPU is in Ready state.
        2. Shutdown DPU → verify transition to Offline state.
        3. Startup DPU → observe Booting state (transient).
        4. Verify DPU reaches Ready state with all fields correct.
        5. Confirm last_down_time and last_ready_time are updated.
        """
        duthost, testable_dpus, testable_ips = prepare_testable_dpus

        target_dpu = testable_dpus[0]

        # Record state before shutdown
        state_before = get_dpu_state_from_chassis_state_db(duthost, target_dpu)
        logging.info("%s state before shutdown: %s", target_dpu, state_before)
        pytest_assert(
            state_before.get("ready_status", "").lower() == "true",
            f"{target_dpu}: not in Ready state before test"
        )

        # --- Transition: Ready → Offline ---
        logging.info("Shutting down %s", target_dpu)
        duthost.shell(f"sudo config chassis modules shutdown {target_dpu}")

        logging.info("Verifying %s transitions to Offline state", target_dpu)
        pytest_assert(
            wait_until(DPU_MAX_ONLINE_TIMEOUT, DPU_TIME_INT, 0,
                       self._check_dpu_offline_state, duthost, target_dpu),
            f"{target_dpu}: did not reach Offline state after shutdown. "
            f"State: {get_dpu_state_from_chassis_state_db(duthost, target_dpu)}"
        )

        state_offline = get_dpu_state_from_chassis_state_db(duthost, target_dpu)
        logging.info("%s state after shutdown: %s", target_dpu, state_offline)

        # Verify last_down_time is set
        pytest_assert(
            state_offline.get("last_down_time", ""),
            f"{target_dpu}: last_down_time not set after shutdown"
        )

        # --- Transition: Offline → Booting → Ready ---
        logging.info("Starting up %s", target_dpu)
        duthost.shell(f"sudo config chassis modules startup {target_dpu}")

        # Try to observe transient Booting state (best-effort, may be too fast)
        booting_observed = wait_until(60, 5, 0,
                                      self._check_dpu_booting_state, duthost, target_dpu)
        if booting_observed:
            logging.info("%s: Booting state observed (control_plane=down, module=on)", target_dpu)
        else:
            logging.info("%s: Booting state was transient (already moved past it)", target_dpu)

        # Wait for full Ready state
        logging.info("Waiting for %s to reach Ready state", target_dpu)
        assert_dpu_db_state_ready(duthost, target_dpu,
                                  timeout=DPU_READY_AFTER_RECOVERY_TIMEOUT)

        state_ready = get_dpu_state_from_chassis_state_db(duthost, target_dpu)
        logging.info("%s state after startup: %s", target_dpu, state_ready)

        # Verify last_ready_time is set and updated
        pytest_assert(
            state_ready.get("last_ready_time", ""),
            f"{target_dpu}: last_ready_time not set after recovery"
        )

        # Verify recovery_status is still recoverable (planned operation)
        pytest_assert(
            state_ready.get("recovery_status", "").lower() == "recoverable",
            f"{target_dpu}: recovery_status is not 'recoverable' after planned restart"
        )

        logging.info("Post-test: verifying full connectivity")
        post_test_dpus_check(duthost, dpuhosts,
                             testable_dpus, testable_ips,
                             num_dpu_modules,
                             re.compile(r"reboot|Non-Hardware", re.IGNORECASE))


# ---------------------------------------------------------------------------
# Race Condition: Module shutdown during auto-recovery
# ---------------------------------------------------------------------------

class TestShutdownDuringAutoRecovery:
    """
    Test: Issue 'config chassis module shutdown' while chassisd is in the
    middle of auto-recovering a DPU. Verify chassisd aborts the recovery
    loop and proceeds with graceful shutdown.

    Expected behavior per HLD:
      - chassisd detects admin-down request during auto-recovery
      - chassisd aborts auto-recovery loop
      - DPU transitions to Offline (not stuck in recovery)
    """

    @pytest.mark.disable_loganalyzer
    def test_shutdown_aborts_auto_recovery(
        self, dpuhosts, prepare_testable_dpus, num_dpu_modules  # noqa: F811
    ):
        """
        Steps:
        1. Pre-test: verify all DPUs are ready.
        2. Trigger DPU failure (stop swss) to initiate auto-recovery.
        3. As soon as chassisd detects failure (ready_status=false),
           issue 'config chassis modules shutdown' on the same DPU.
        4. Verify DPU transitions to Offline (not stuck in power-cycle loop).
        5. Startup the DPU and verify it recovers to Ready.
        """
        duthost, testable_dpus, testable_ips = prepare_testable_dpus

        target_dpu = testable_dpus[0]
        dpu_id = int(re.search(r'\d+', target_dpu).group())

        dpuhost = get_dpuhost_for_dpu(dpuhosts, dpu_id)

        logging.info("Stopping swss on %s to trigger auto-recovery", target_dpu)
        dpuhost.shell("sudo systemctl stop swss", module_ignore_errors=True)

        logging.info("Waiting for chassisd to detect failure on %s", target_dpu)
        pytest_assert(
            wait_until(CONTROL_PLANE_DOWN_DETECT_TIMEOUT, DPU_TIME_INT, 0,
                       check_dpu_not_ready_state, duthost, target_dpu),
            f"{target_dpu}: ready_status did not become false"
        )

        logging.info("Issuing module shutdown on %s during recovery", target_dpu)
        duthost.shell(f"sudo config chassis modules shutdown {target_dpu}")

        logging.info("Verifying %s transitions to Offline", target_dpu)
        pytest_assert(
            wait_until(DPU_MAX_ONLINE_TIMEOUT, DPU_TIME_INT, 0,
                       check_dpu_module_status, duthost, "off", target_dpu),
            f"{target_dpu}: did not reach Offline after shutdown during recovery"
        )

        # Verify DPU is cleanly offline with ready_status=false
        state = get_dpu_state_from_chassis_state_db(duthost, target_dpu)
        logging.info("%s state after shutdown during recovery: %s", target_dpu, state)
        pytest_assert(
            state.get("ready_status", "").lower() == "false",
            f"{target_dpu}: ready_status not false after shutdown"
        )

        # Recover: startup the DPU
        logging.info("Starting up %s after shutdown-during-recovery test", target_dpu)
        duthost.shell(f"sudo config chassis modules startup {target_dpu}")

        assert_dpu_db_state_ready(duthost, target_dpu,
                                  timeout=DPU_READY_AFTER_RECOVERY_TIMEOUT)

        logging.info("Post-test: verifying full DPU state and connectivity")
        post_test_dpus_check(duthost, dpuhosts,
                             testable_dpus, testable_ips,
                             num_dpu_modules,
                             re.compile(r"reboot|Non-Hardware", re.IGNORECASE))


# ---------------------------------------------------------------------------
# DPU failure during/after config reload
# ---------------------------------------------------------------------------

class TestDpuFailureAfterConfigReload:
    """
    Test: Verify the DPU recovery state machine works correctly when a DPU
    fails immediately after a config reload on the NPU.

    This ensures chassisd's monitoring recovers properly after config reload
    re-initializes services and that the new DB fields track the failure.
    """

    @pytest.mark.disable_loganalyzer
    def test_dpu_recovery_after_config_reload_and_failure(
        self, dpuhosts, prepare_testable_dpus, num_dpu_modules  # noqa: F811
    ):
        """
        Steps:
        1. Pre-test: verify all DPUs are ready.
        2. Perform 'config reload' on the NPU.
        3. Wait for critical services to come back.
        4. Immediately trigger DPU failure (stop swss on one DPU).
        5. Verify chassisd detects the failure (ready_status=false).
        6. Wait for chassisd to power-cycle and recover the DPU.
        7. Verify DB state is correct (ready_status=true, reset_count incremented).
        """
        duthost, testable_dpus, testable_ips = prepare_testable_dpus

        target_dpu = testable_dpus[0]
        dpu_id = int(re.search(r'\d+', target_dpu).group())

        # Record reset_count before the test
        state_before = get_dpu_state_from_chassis_state_db(duthost, target_dpu)
        reset_count_before = int(state_before.get("reset_count", "0"))
        logging.info("%s reset_count before test: %d", target_dpu, reset_count_before)

        logging.info("Performing config reload on NPU")
        duthost.shell("sudo config reload -y &>/dev/null", executable="/bin/bash")

        logging.info("Waiting for critical services to restart after config reload")
        wait_critical_processes(duthost)

        # config reload reverts CONFIG_DB to disk; re-enable runtime auto-recovery.
        set_dpu_auto_recovery(duthost, DPU_AUTO_RECOVERY_ENABLE)

        # Wait for DPU to be ready after config reload before triggering failure
        logging.info("Waiting for %s to be ready after config reload", target_dpu)
        assert_dpu_db_state_ready(duthost, target_dpu,
                                  timeout=DPU_READY_AFTER_RECOVERY_TIMEOUT)

        dpuhost = get_dpuhost_for_dpu(dpuhosts, dpu_id)

        logging.info("Triggering DPU failure on %s after config reload", target_dpu)
        dpuhost.shell("sudo systemctl stop swss", module_ignore_errors=True)

        logging.info("Verifying chassisd detects failure for %s", target_dpu)
        pytest_assert(
            wait_until(CONTROL_PLANE_DOWN_DETECT_TIMEOUT, DPU_TIME_INT, 0,
                       check_dpu_not_ready_state, duthost, target_dpu),
            f"{target_dpu}: ready_status did not become false after failure "
            f"post config-reload. "
            f"State: {get_dpu_state_from_chassis_state_db(duthost, target_dpu)}"
        )

        logging.info("Waiting for chassisd to recover %s", target_dpu)
        assert_dpu_db_state_ready(duthost, target_dpu,
                                  timeout=DPU_READY_AFTER_RECOVERY_TIMEOUT)

        # Verify reset_count was incremented
        state_after = get_dpu_state_from_chassis_state_db(duthost, target_dpu)
        reset_count_after = int(state_after.get("reset_count", "0"))
        logging.info("%s reset_count after test: %d", target_dpu, reset_count_after)
        pytest_assert(
            reset_count_after > reset_count_before,
            f"{target_dpu}: reset_count not incremented after failure "
            f"(before={reset_count_before}, after={reset_count_after})"
        )

        logging.info("Post-test: verifying full DPU state and connectivity")
        post_test_dpus_check(duthost, dpuhosts,
                             testable_dpus, testable_ips,
                             num_dpu_modules,
                             re.compile(r"reboot|Non-Hardware", re.IGNORECASE))
