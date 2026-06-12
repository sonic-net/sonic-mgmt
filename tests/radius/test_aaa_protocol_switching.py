"""
Combined / Cross-Protocol AAA Test — TC_AAA_COMBO_001
Verifies switching from one AAA protocol to another works correctly.
"""
import logging
import pytest

from tests.radius.utils import ssh_connect_remote_retry, close_ssh
from tests.radius.combined_utils import set_aaa_authentication, restore_local_aaa

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology("any", "t1-multi-asic"),
    pytest.mark.device_type("vs"),
    pytest.mark.skip_check_dut_health,
]


def test_tc_aaa_combo_001_switch_from_local_to_radius(combined_aaa_setup, radius_creds):
    """
    TC_AAA_COMBO_001: Switch AAA from local to radius — RADIUS user login succeeds.

    Steps:
        1. Set AAA authentication to local (baseline).
        2. Verify local admin login works.
        3. Switch AAA authentication to 'radius local'.
        4. Verify RADIUS user login now succeeds.
        5. Verify local admin still works (fallback).

    Expected: After switching to radius, RADIUS user can log in.
              Local admin still works due to 'local' fallback.
    """
    duthost = combined_aaa_setup["duthost"]

    # Step 1 — Set to local only
    set_aaa_authentication(duthost, "local")

    # Step 2 — Local admin baseline
    local_client = ssh_connect_remote_retry(
        duthost.mgmt_ip,
        radius_creds["local_user"],
        radius_creds["local_user_passwd"],
    )
    close_ssh(local_client)
    assert local_client is not None, "Local admin login failed at baseline"
    logger.info("Baseline: local admin login OK")

    # Step 3 — Switch to RADIUS
    set_aaa_authentication(duthost, "radius local")
    logger.info("Switched AAA to: radius local")

    # Step 4 — RADIUS user should now work
    radius_client = ssh_connect_remote_retry(
        duthost.mgmt_ip,
        radius_creds["radius_rw_user"],
        radius_creds["radius_rw_user_passwd"],
    )
    close_ssh(radius_client)
    assert radius_client is not None, \
        "RADIUS user login FAILED after switching AAA to 'radius local'"
    logger.info("Step 4: RADIUS user login after switch: OK")

    # Step 5 — Local admin still works
    local_client2 = ssh_connect_remote_retry(
        duthost.mgmt_ip,
        radius_creds["local_user"],
        radius_creds["local_user_passwd"],
    )
    close_ssh(local_client2)
    assert local_client2 is not None, \
        "Local admin login FAILED after switching to 'radius local'"
    logger.info("Step 5: local admin fallback after switch: OK")

    logger.info("TC_AAA_COMBO_001 PASS: switch from local → radius local works correctly")
