"""
RADIUS Security / Edge Case Test — TC_RADIUS_022
Verifies RADIUS configuration persists after config save + reload.
"""
import logging
import time
import pytest

from tests.radius.utils import (
    ssh_connect_remote_retry,
    close_ssh,
)
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology("any", "t1-multi-asic"),
    pytest.mark.device_type("vs"),
    pytest.mark.skip_check_dut_health,
]

RELOAD_WAIT_SEC = 180


def test_tc_radius_022_config_persists_after_save_reload(radius_server_setup, radius_creds):
    """
    TC_RADIUS_022: RADIUS auth works after 'config save' + 'config reload'.

    Steps:
        1. Verify RADIUS login works (baseline).
        2. Run: sudo config save -y
        3. Run: sudo config reload -y
        4. Wait for DUT to recover (~180s).
        5. Verify RADIUS login still works (post-reload).

    Expected: RADIUS configuration persists in ConfigDB. Login succeeds after reload.
    """
    duthost = radius_server_setup["duthost"]
    username = radius_creds["radius_rw_user"]
    password = radius_creds["radius_rw_user_passwd"]

    # Step 1 — Baseline: verify RADIUS login works before reload
    client = ssh_connect_remote_retry(duthost.mgmt_ip, username, password)
    assert client is not None, "Baseline RADIUS login FAILED before reload"
    close_ssh(client)
    logger.info("Baseline RADIUS login: OK")

    # Step 2 & 3 — Save and reload config
    duthost.shell("config save -y")
    logger.info("Config saved. Starting reload...")
    duthost.shell("config reload -y", module_ignore_errors=True)

    # Step 4 — Wait for DUT to come back
    logger.info("Waiting %ds for DUT to recover after reload...", RELOAD_WAIT_SEC)
    time.sleep(RELOAD_WAIT_SEC)

    def dut_is_reachable():
        result = duthost.shell("echo alive", module_ignore_errors=True)
        return result["rc"] == 0

    assert wait_until(60, 10, 0, dut_is_reachable), \
        "DUT did not recover within 60s after reload"

    # Step 5 — Post-reload: verify RADIUS still works
    client = ssh_connect_remote_retry(duthost.mgmt_ip, username, password, retries=5, delay=10)
    try:
        assert client is not None, \
            "RADIUS login FAILED after config reload — config was not persisted"
        logger.info("TC_RADIUS_022 PASS: RADIUS login works after config reload")
    finally:
        close_ssh(client)
