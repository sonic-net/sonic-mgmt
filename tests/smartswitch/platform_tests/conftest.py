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
    get_dpuhost_for_dpu,
    num_dpu_modules,
    set_dpu_auto_recovery,
    DPU_AUTO_RECOVERY_ENABLE,
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


@pytest.fixture()
def prepare_testable_dpus(duthosts, dpuhosts, enum_rand_one_per_hwsku_hostname,
                          num_dpu_modules):  # noqa: F811
    """
    Ensure all DPUs present in dpuhosts are admin-up, online, and DB-ready.
    If any DPU is admin down, bring it up. Fail early if any DPU does not
    come online.

    Yields:
        (duthost, testable_dpus, testable_ips) where testable_dpus is the list
        of DPU names available in dpuhosts and testable_ips their midplane IPs.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    # Build list of all DPUs in dpuhosts
    testable_dpus = []
    for dpu_id in range(num_dpu_modules):
        if get_dpuhost_for_dpu(dpuhosts, dpu_id) is not None:
            testable_dpus.append(f"DPU{dpu_id}")
    pt_assert(testable_dpus, "No DPUs available in dpuhosts")

    # Enable DPU auto-recovery so chassisd recovers failed DPUs back to ready.
    set_dpu_auto_recovery(duthost, DPU_AUTO_RECOVERY_ENABLE)

    # Bring up any admin-down DPUs
    dpus_brought_up = []
    for dpu_name in testable_dpus:
        if check_dpu_module_status(duthost, "off", dpu_name):
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

    # Teardown: reset chassisd DPU recovery state so tests are order-independent;
    # runs even if the test body raised. Best-effort (see helper).
    _reset_dpu_recovery_state(duthost, dpuhosts, testable_dpus)


@pytest.fixture(autouse=True)
def ensure_all_dpus_ready(duthosts,
                          enum_rand_one_per_hwsku_hostname,
                          localhost,
                          num_dpu_modules):  # noqa: F811
    """
    Teardown fixture: after each test case, ensure all DPUs are back online.
    If any DPU is found offline at the end of a test, it will be started up
    before the next test begins.
    """
    yield

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dpu_names = ["DPU{}".format(i) for i in range(num_dpu_modules)]

    def _get_offline_dpus():
        """Single shell call to find all offline DPUs."""
        output = duthost.shell("show chassis module status")["stdout"]
        return [
            dpu for dpu in dpu_names
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
            logging.info("All DPUs are online after test. No recovery needed.")

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
