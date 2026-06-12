"""
RADIUS Authorization Tests — TC_RADIUS_008 to TC_RADIUS_010
Verifies that RADIUS priv-lvl VSA maps correctly to SONiC Linux groups.
"""
import logging
import pytest

from tests.radius.utils import ssh_run_command, get_user_groups

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology("any", "t1-multi-asic"),
    pytest.mark.device_type("vs"),
    pytest.mark.skip_check_dut_health,
]


def test_tc_radius_008_rw_user_has_sudo(rw_user_ssh, radius_creds):
    """
    TC_RADIUS_008: RW user (priv-lvl=15) has sudo and netadmin group membership.
    Expected: id shows sudo and netadmin groups.
    """
    assert rw_user_ssh is not None, \
        "SSH login failed for RW user '{}'".format(radius_creds["radius_rw_user"])

    rc, out, _ = ssh_run_command(rw_user_ssh, "id")
    assert rc == 0, "id command failed"
    assert "sudo" in out, \
        "RW user should be in sudo group. id output: {}".format(out)
    assert "netadmin" in out, \
        "RW user should be in netadmin group. id output: {}".format(out)
    logger.info("TC_RADIUS_008 PASS: RW user groups: %s", out)


def test_tc_radius_009_ro_user_no_sudo(ro_user_ssh, radius_creds):
    """
    TC_RADIUS_009: RO user (priv-lvl=1) does NOT have sudo group.
    Expected: sudo command fails with permission denied.
    """
    assert ro_user_ssh is not None, \
        "SSH login failed for RO user '{}'".format(radius_creds["radius_ro_user"])

    rc, out, _ = ssh_run_command(ro_user_ssh, "id")
    assert rc == 0, "id command failed"
    assert "sudo" not in out, \
        "RO user should NOT be in sudo group. id output: {}".format(out)

    # Also verify sudo actually fails
    rc2, _, err = ssh_run_command(ro_user_ssh, "sudo id")
    assert rc2 != 0, \
        "sudo should have FAILED for RO user, but succeeded"
    logger.info("TC_RADIUS_009 PASS: RO user correctly has no sudo. groups: %s", out)


def test_tc_radius_010_concurrent_rw_ro_sessions(radius_server_setup, radius_creds):
    """
    TC_RADIUS_010: Concurrent RW and RO user sessions can exist simultaneously.
    Expected: Both sessions active at same time with correct group membership.
    """
    from tests.radius.utils import ssh_connect_remote_retry, close_ssh

    duthost = radius_server_setup["duthost"]

    rw_client = ssh_connect_remote_retry(
        duthost.mgmt_ip, radius_creds["radius_rw_user"], radius_creds["radius_rw_user_passwd"])
    ro_client = ssh_connect_remote_retry(
        duthost.mgmt_ip, radius_creds["radius_ro_user"], radius_creds["radius_ro_user_passwd"])

    try:
        assert rw_client is not None, "RW user SSH login failed"
        assert ro_client is not None, "RO user SSH login failed"

        _, rw_id, _ = ssh_run_command(rw_client, "id")
        _, ro_id, _ = ssh_run_command(ro_client, "id")

        assert "sudo" in rw_id, \
            "RW user missing sudo group in concurrent session: {}".format(rw_id)
        assert "sudo" not in ro_id, \
            "RO user should not have sudo in concurrent session: {}".format(ro_id)

        logger.info("TC_RADIUS_010 PASS: concurrent sessions working. RW=%s RO=%s", rw_id, ro_id)
    finally:
        close_ssh(rw_client)
        close_ssh(ro_client)
