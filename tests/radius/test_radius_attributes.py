"""
RADIUS Attribute / VSA Tests — TC_RADIUS_023 to TC_RADIUS_026
Verifies RADIUS packet attributes and Vendor-Specific Attribute (VSA) handling.
"""
import logging
import pytest

from tests.radius.utils import (
    radtest_verify,
    ssh_connect_remote_retry,
    ssh_run_command,
    close_ssh,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology("any", "t1-multi-asic"),
    pytest.mark.device_type("vs"),
    pytest.mark.skip_check_dut_health,
]


def test_tc_radius_023_access_request_contains_username(ptfhost, radius_creds):
    """
    TC_RADIUS_023: Access-Request packet contains the correct User-Name attribute.
    Expected: radtest verbose output shows User-Name matching the test user.
    """
    cmd = "radtest -x {} {} 127.0.0.1 0 {}".format(
        radius_creds["radius_rw_user"],
        radius_creds["radius_rw_user_passwd"],
        radius_creds["passkey"],
    )
    result = ptfhost.shell(cmd, module_ignore_errors=True)
    output = result["stdout"] + result.get("stderr", "")

    assert radius_creds["radius_rw_user"] in output, \
        "User-Name '{}' not found in radtest output:\n{}".format(
            radius_creds["radius_rw_user"], output)
    assert "Access-Accept" in output, \
        "Expected Access-Accept in output:\n{}".format(output)
    logger.info("TC_RADIUS_023 PASS: User-Name present in Access-Request")


def test_tc_radius_024_cisco_avpair_priv15_maps_to_sudo(radius_server_setup, radius_creds):
    """
    TC_RADIUS_024: Cisco-AVPair shell:priv-lvl=15 maps to sudo+netadmin groups on DUT.
    Expected: RW user login → groups include sudo and netadmin.
    """
    duthost = radius_server_setup["duthost"]

    client = ssh_connect_remote_retry(
        duthost.mgmt_ip,
        radius_creds["radius_rw_user"],
        radius_creds["radius_rw_user_passwd"],
    )
    try:
        assert client is not None, "Login failed for RW user"
        _, out, _ = ssh_run_command(client, "id")
        assert "sudo" in out, \
            "priv-lvl=15 should map to sudo group, got: {}".format(out)
        assert "netadmin" in out, \
            "priv-lvl=15 should map to netadmin group, got: {}".format(out)
        logger.info("TC_RADIUS_024 PASS: priv-lvl=15 → sudo+netadmin. id=%s", out)
    finally:
        close_ssh(client)


def test_tc_radius_025_cisco_avpair_priv1_maps_to_readonly(radius_server_setup, radius_creds):
    """
    TC_RADIUS_025: Cisco-AVPair shell:priv-lvl=1 maps to read-only (no sudo) on DUT.
    Expected: RO user login → id shows no sudo group.
    """
    duthost = radius_server_setup["duthost"]

    client = ssh_connect_remote_retry(
        duthost.mgmt_ip,
        radius_creds["radius_ro_user"],
        radius_creds["radius_ro_user_passwd"],
    )
    try:
        assert client is not None, "Login failed for RO user"
        _, out, _ = ssh_run_command(client, "id")
        assert "sudo" not in out, \
            "priv-lvl=1 should NOT map to sudo group, got: {}".format(out)
        logger.info("TC_RADIUS_025 PASS: priv-lvl=1 → no sudo. id=%s", out)
    finally:
        close_ssh(client)


def test_tc_radius_026_radtest_protocol_level_verify(ptfhost, radius_creds):
    """
    TC_RADIUS_026: Protocol-level verification via radtest — both users return Access-Accept.
    Expected: radtest returns Access-Accept for RW and RO users.
    """
    rw_ok = radtest_verify(
        ptfhost,
        username=radius_creds["radius_rw_user"],
        password=radius_creds["radius_rw_user_passwd"],
        secret=radius_creds["passkey"],
    )
    ro_ok = radtest_verify(
        ptfhost,
        username=radius_creds["radius_ro_user"],
        password=radius_creds["radius_ro_user_passwd"],
        secret=radius_creds["passkey"],
    )

    assert rw_ok, "radtest: Access-Accept NOT received for RW user"
    assert ro_ok, "radtest: Access-Accept NOT received for RO user"
    logger.info("TC_RADIUS_026 PASS: both users return Access-Accept via radtest")
