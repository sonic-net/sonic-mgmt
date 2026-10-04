"""
RADIUS Authorization Tests — TC_RADIUS_008, TC_RADIUS_009
Verifies that RADIUS priv-lvl VSA maps correctly to SONiC Linux groups.
"""
import logging
import pytest

from tests.radius.utils import ssh_run_command

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology("t0", "t1", "any"),
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
