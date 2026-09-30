"""
Pytest fixtures for SmartSwitch platform tests.
"""
import logging
import pytest
from pytest_ansible.errors import AnsibleConnectionFailure
from tests.common.helpers.assertions import pytest_assert as pt_assert
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.reboot import wait_for_startup
from tests.common.utilities import wait_until
from tests.smartswitch.common.device_utils_dpu import (  # noqa: F401
    assert_dpu_db_state_ready,
    check_dpu_module_status,
    check_dpu_ready_state,
    dpus_startup_and_check,
    get_dpu_auto_recovery,
    get_dpu_id_from_hostname,
    get_dpuhost_for_dpu,
    is_dark_mode_enabled,
    is_dpu_db_state_supported,
    num_dpu_modules,
    set_dpu_auto_recovery,
    unset_dpu_auto_recovery,
    DPU_AUTO_RECOVERY_ENABLE,
    DPU_DB_STATE_PROBE_TIMEOUT,
    DPU_MAX_ONLINE_TIMEOUT,
    DPU_READY_AFTER_RECOVERY_TIMEOUT,
    DPU_TIME_INT,
    SWITCH_MAX_DELAY,
    SWITCH_MAX_TIMEOUT,
)
from tests.common.platform.device_utils import platform_api_conn, start_platform_api_service  # noqa: F401


def _reset_dpu_recovery_state(duthost, dpuhosts, testable_dpus):
    """Reset chassisd DPU recovery state (start swss, restart pmon to clear
    reset_count/unrecoverable, wait for ready) so the suite is order-independent.
    """
    try:
        for dpu_name in testable_dpus:
            dpu_id = int(dpu_name.replace("DPU", ""))
            dpuhost = get_dpuhost_for_dpu(dpuhosts, dpu_id)
            if dpuhost is not None:
                dpuhost.shell("sudo systemctl start swss", module_ignore_errors=True)

        duthost.shell("sudo systemctl restart pmon")

        for dpu_name in testable_dpus:
            if not wait_until(DPU_READY_AFTER_RECOVERY_TIMEOUT, DPU_TIME_INT, 0,
                              check_dpu_ready_state, duthost, dpu_name):
                logging.warning(
                    "%s did not become ready after recovery-state reset in teardown",
                    dpu_name)
    except Exception as e:
        logging.warning("Resetting DPU recovery state in teardown failed "
                        "(non-fatal): %s", e)


def _get_dpu_admin_status(duthost, dpu_name):
    """Return the CONFIG_DB CHASSIS_MODULE admin_status for a DPU (lower-cased),
    or "" if the entry/field is absent (an unconfigured DPU)."""
    return duthost.shell(
        f"sonic-db-cli CONFIG_DB hget 'CHASSIS_MODULE|{dpu_name}' admin_status",
        module_ignore_errors=True).get("stdout", "").strip().lower()


@pytest.fixture()
def prepare_testable_dpus(duthosts, dpuhosts, enum_rand_one_per_hwsku_hostname,
                          platform_api_conn, num_dpu_modules):  # noqa: F811
    """
    Ensure all DPUs present in dpuhosts are admin-up, online, and DB-ready.
    Skip in dark mode (all DPUs admin down); otherwise bring up any individually
    admin-down DPU and fail early if a DPU does not come online.

    Yields:
        (duthost, testable_dpus, testable_ips) where testable_dpus is the list
        of DPU names available in dpuhosts and testable_ips their midplane IPs.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    if is_dark_mode_enabled(duthost, platform_api_conn, num_dpu_modules):
        pytest.skip("SmartSwitch is in dark mode (all DPUs admin down); "
                    "skipping DPU failure-mode tests.")

    # Build testable DPUs from the DPU hosts we have SSH access to, deriving each
    # real module id from its hostname so a subset maps to correct ids (not indexes).
    testable_dpus = []
    for dpuhost in dpuhosts:
        dpu_id = get_dpu_id_from_hostname(getattr(dpuhost, "hostname", ""))
        if dpu_id is not None:
            testable_dpus.append(f"DPU{dpu_id}")
    # Fall back to positional enumeration for non-standard DPU hostnames.
    if not testable_dpus:
        testable_dpus = [f"DPU{dpu_id}" for dpu_id in range(len(dpuhosts))]
    testable_dpus = sorted(set(testable_dpus), key=lambda name: int(name[len("DPU"):]))
    pt_assert(testable_dpus, "No DPUs available in dpuhosts")

    # Skip (before mutating any state) on images lacking the CHASSIS_STATE_DB
    # DPU_STATE schema, so the failure-mode suite doesn't hard-fail on old images.
    for dpu_name in testable_dpus:
        if not wait_until(DPU_DB_STATE_PROBE_TIMEOUT, DPU_TIME_INT, 0,
                          is_dpu_db_state_supported, duthost, dpu_name):
            pytest.skip(
                f"{dpu_name}: CHASSIS_STATE_DB DPU_STATE schema not present; "
                "image does not support the DPU robustness enhancement. "
                "Skipping DPU failure-mode tests."
            )

    # Enable auto-recovery so chassisd recovers failed DPUs; save original for teardown.
    original_auto_recovery = get_dpu_auto_recovery(duthost)
    set_dpu_auto_recovery(duthost, DPU_AUTO_RECOVERY_ENABLE)

    # Track the DPUs this fixture starts and their original admin state so the
    # teardown can restore it. Defined before the try so the finally always sees
    # them, even if setup raises midway.
    dpus_brought_up = []
    original_admin_status = {}

    try:
        # Bring up any offline DPUs, remembering each one's original admin state.
        for dpu_name in testable_dpus:
            if check_dpu_module_status(duthost, "off", dpu_name):
                original_admin_status[dpu_name] = _get_dpu_admin_status(duthost, dpu_name)
                logging.info("%s is admin down, bringing it admin up", dpu_name)
                duthost.shell(f"sudo config chassis modules startup {dpu_name}")
                dpus_brought_up.append(dpu_name)

        for dpu_name in dpus_brought_up:
            logging.info("Waiting for %s to come online after admin up", dpu_name)
            pt_assert(
                wait_until(DPU_MAX_ONLINE_TIMEOUT, DPU_TIME_INT, 0,
                           check_dpu_module_status, duthost, "on", dpu_name),
                f"{dpu_name} did not come online after admin up"
            )

        # Fail early if any DPU is not online
        dpus_not_online = [dpu for dpu in testable_dpus
                           if not check_dpu_module_status(duthost, "on", dpu)]
        pt_assert(
            not dpus_not_online,
            f"DPUs failed to come online: {dpus_not_online}"
        )

        # Wait for all testable DPUs to be ready in DB
        for dpu_name in testable_dpus:
            assert_dpu_db_state_ready(duthost, dpu_name,
                                      timeout=DPU_READY_AFTER_RECOVERY_TIMEOUT)

        # Gather midplane IPs, index-aligned with testable_dpus.
        midplane_output = duthost.show_and_parse("show chassis modules midplane-status")
        midplane_ip_by_dpu = {
            entry.get("name", "").lower(): entry.get("ip-address", "")
            for entry in midplane_output
        }
        testable_ips = []
        missing_ip_dpus = []
        for dpu_name in testable_dpus:
            ip = midplane_ip_by_dpu.get(dpu_name.lower(), "")
            if not ip:
                missing_ip_dpus.append(dpu_name)
            testable_ips.append(ip)
        pt_assert(not missing_ip_dpus,
                  f"Could not resolve midplane IPs for DPUs: {missing_ip_dpus}")

        yield duthost, testable_dpus, testable_ips
    finally:
        # Restore admin state: shut down any DPU this fixture started that was not
        # originally admin-up, so subsequent tests do not inherit DPUs it enabled.
        # Runs on both success and failure; best-effort per DPU.
        dpus_to_restore_down = [
            dpu for dpu in dpus_brought_up
            if original_admin_status.get(dpu, "") != "up"
        ]
        for dpu_name in dpus_to_restore_down:
            try:
                logging.info("Restoring %s to admin-down (started by fixture)", dpu_name)
                duthost.shell(f"sudo config chassis modules shutdown {dpu_name}")
            except Exception as e:
                logging.warning(
                    "Failed to restore %s to admin-down in teardown (non-fatal): %s",
                    dpu_name, e)

        # Reset chassisd DPU recovery state for DPUs that remain administratively up,
        # so tests are order-independent; runs even if setup or the test body raised.
        dpus_remaining_up = [dpu for dpu in testable_dpus
                             if dpu not in dpus_to_restore_down]
        _reset_dpu_recovery_state(duthost, dpuhosts, dpus_remaining_up)

        # Restore auto-recovery exactly: re-apply the original value, or delete the
        # field if it was unset before the fixture enabled it. Tolerate failures so a
        # restore error in teardown cannot surface as an error masking the real result.
        try:
            if original_auto_recovery:
                set_dpu_auto_recovery(duthost, original_auto_recovery)
            else:
                unset_dpu_auto_recovery(duthost)
        except Exception as e:
            logging.warning(
                "Failed to restore DPU auto-recovery to '%s' in teardown (non-fatal): %s",
                original_auto_recovery or "<unset>", e)


@pytest.fixture(autouse=True)
def ensure_all_dpus_ready(duthosts,
                          enum_rand_one_per_hwsku_hostname,
                          localhost,
                          num_dpu_modules):  # noqa: F811
    """
    Teardown safety net: after each test case, restore only DPUs that were
    administratively up before the test but are offline afterwards.

    DPUs that were not explicitly admin-up at setup (e.g. dark mode, an
    individually shut DPU, or an unconfigured DPU with no admin_status) are
    never powered on, so a skipped or DPU-untouched test cannot defeat
    dark-mode protection or start DPUs whose images are not installed.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dpu_names = ["DPU{}".format(i) for i in range(num_dpu_modules)]

    def _admin_up_dpus():
        """DPUs explicitly admin-up in CONFIG_DB. A missing/empty admin_status
        (an unconfigured DPU) is treated as NOT up, so teardown never powers on
        a DPU that was never configured up."""
        return [dpu for dpu in dpu_names
                if _get_dpu_admin_status(duthost, dpu) == "up"]

    # Capture the original admin state before the test mutates anything.
    original_admin_up = _admin_up_dpus()

    yield

    def _get_offline_dpus():
        """Offline DPUs limited to those that were admin-up at setup, so we
        never power on a DPU that was intentionally left admin-down."""
        output = duthost.shell("show chassis module status")["stdout"]
        return [
            dpu for dpu in original_admin_up
            if any(dpu in line and "offline" in line.lower()
                   for line in output.splitlines())
        ]

    def _do_dpu_recovery():
        offline = _get_offline_dpus()
        if offline:
            logging.info("DPUs found offline after test: %s. Bringing them back UP...", offline)
            dpus_startup_and_check(duthost, offline, num_dpu_modules)
            logging.info("All DPUs are back online after recovery.")
        else:
            logging.info("No admin-up DPUs require recovery after test.")

    try:
        _do_dpu_recovery()
    except AnsibleConnectionFailure:
        logging.warning(
            "DUT %s unreachable in teardown (still rebooting?); waiting for it to come back up",
            duthost.hostname
        )
        try:
            wait_for_startup(duthost, localhost, SWITCH_MAX_DELAY, SWITCH_MAX_TIMEOUT)
            wait_critical_processes(duthost)
            logging.info("DUT %s is back up; retrying DPU recovery", duthost.hostname)
            _do_dpu_recovery()
        except Exception as e:
            logging.warning("DPU recovery after DUT reboot wait failed (non-fatal): %s", e)
    except Exception as e:
        logging.warning("DPU recovery in teardown failed (non-fatal): %s", e)
