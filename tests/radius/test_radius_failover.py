"""
RADIUS Failover Test — TC_RADIUS_015
Verifies local fallback when the RADIUS server is unreachable.

Other failover scenarios (radius-only mode, multi-server priority, timing
windows, freeradius restarts) are deliberately excluded: they reconfigure
AAA mid-test and are prone to leaving the DUT in a state where admin SSH
is blocked.
"""
import logging
import time
import pytest

from tests.radius.utils import (
    ssh_connect_remote_retry,
    close_ssh,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology("t0", "t1", "any"),
    pytest.mark.skip_check_dut_health,
]


def test_tc_radius_015_local_fallback_when_server_unreachable(
        radius_server_setup, radius_creds, radius_server_unreachable):
    """
    TC_RADIUS_015: When RADIUS server is unreachable, local user can still login.
    Expected: Local admin login succeeds after timeout (~timeout*retransmit seconds).
    """
    duthost = radius_server_setup["duthost"]

    start = time.time()
    client = ssh_connect_remote_retry(
        host=duthost.mgmt_ip,
        username=radius_creds["local_user"],
        password=radius_creds["local_user_passwd"],
        timeout=60,
        retries=1,
    )
    elapsed = time.time() - start

    try:
        assert client is not None, \
            "Local admin login FAILED when RADIUS unreachable (fallback broken)"
        logger.info("TC_RADIUS_015 PASS: local fallback worked in %.1fs", elapsed)
    finally:
        close_ssh(client)
