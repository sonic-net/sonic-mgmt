"""
Pytest fixtures for SmartSwitch platform tests.
"""
import logging
import pytest
from pytest_ansible.errors import AnsibleConnectionFailure
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.reboot import wait_for_startup
from tests.smartswitch.common.device_utils_dpu import (  # noqa: F401
    dpus_startup_and_check, SWITCH_MAX_DELAY, SWITCH_MAX_TIMEOUT, num_dpu_modules
)
from tests.common.platform.device_utils import platform_api_conn, start_platform_api_service  # noqa: F401


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
