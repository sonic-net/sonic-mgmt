"""
RADIUS JIT User Provisioning Test — TC_RADIUS_021
Verifies that SONiC auto-creates a local account on first RADIUS login (Just-In-Time).
"""
import logging
import pytest

from tests.radius.utils import (
    ssh_connect_remote_retry,
    ssh_run_command,
    close_ssh,
    user_exists_on_dut,
    delete_jit_user,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology("any", "t1-multi-asic"),
    pytest.mark.device_type("vs"),
    pytest.mark.skip_check_dut_health,
]


def test_tc_radius_021_jit_user_created_on_first_login(radius_server_setup, radius_creds):
    """
    TC_RADIUS_021: JIT — local account is created on DUT on first successful RADIUS login.

    Steps:
        1. Ensure the user does NOT exist locally on DUT before login.
        2. SSH into DUT as the RADIUS RW user.
        3. Verify the account is created in /etc/passwd.
        4. Verify group membership matches priv-lvl=15 (sudo + netadmin).

    Expected: Account created, groups include sudo and netadmin.
    Teardown: Delete JIT user with userdel -r.
    """
    duthost = radius_server_setup["duthost"]
    username = radius_creds["radius_rw_user"]

    # Pre-condition: remove any existing JIT account
    delete_jit_user(duthost, username)
    assert not user_exists_on_dut(duthost, username), \
        "Pre-condition FAILED: user '{}' still exists before test".format(username)

    # Login as RADIUS user (triggers JIT creation via hostcfgd)
    client = ssh_connect_remote_retry(
        host=duthost.mgmt_ip,
        username=username,
        password=radius_creds["radius_rw_user_passwd"],
    )

    try:
        assert client is not None, \
            "SSH login FAILED for RADIUS user '{}' — JIT test cannot proceed".format(username)

        # Verify account exists in /etc/passwd
        assert user_exists_on_dut(duthost, username), \
            "JIT account was NOT created in /etc/passwd for '{}'".format(username)

        # Verify group membership
        rc, out, _ = ssh_run_command(client, "id")
        assert rc == 0, "id command failed"
        assert "sudo" in out, \
            "JIT user should be in sudo group (priv-lvl=15), got: {}".format(out)
        assert "netadmin" in out, \
            "JIT user should be in netadmin group (priv-lvl=15), got: {}".format(out)

        logger.info("TC_RADIUS_021 PASS: JIT user created. id=%s", out)

    finally:
        close_ssh(client)
        delete_jit_user(duthost, username)
