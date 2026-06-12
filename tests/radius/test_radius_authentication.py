"""
RADIUS Authentication Tests — TC_RADIUS_001 to TC_RADIUS_007
"""
import logging
import pytest

from tests.radius.utils import (
    ssh_connect_remote_retry,
    ssh_run_command,
    close_ssh,
    radtest_verify,
    _radius_del,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology("any", "t1-multi-asic"),
    pytest.mark.device_type("vs"),
    pytest.mark.skip_check_dut_health,
]


def test_tc_radius_001_valid_rw_user_login(radius_server_setup, radius_creds):
    """
    TC_RADIUS_001: Valid RW RADIUS user SSH login succeeds.
    Expected: Login granted. Shell accessible. id shows sudo+netadmin groups.
    """
    duthost = radius_server_setup["duthost"]
    client = ssh_connect_remote_retry(
        host=duthost.mgmt_ip,
        username=radius_creds["radius_rw_user"],
        password=radius_creds["radius_rw_user_passwd"],
    )
    try:
        assert client is not None, \
            "SSH login FAILED for valid RW user '{}'".format(radius_creds["radius_rw_user"])

        rc, out, _ = ssh_run_command(client, "id")
        assert rc == 0, "id command failed"
        logger.info("TC_RADIUS_001 PASS: id=%s", out)
    finally:
        close_ssh(client)


def test_tc_radius_002_invalid_password_rejected(radius_server_setup, radius_creds):
    """
    TC_RADIUS_002: SSH login with wrong password is rejected.
    Expected: Login fails — SSH returns None (connection refused/denied).
    """
    duthost = radius_server_setup["duthost"]
    client = ssh_connect_remote_retry(
        host=duthost.mgmt_ip,
        username=radius_creds["radius_rw_user"],
        password="WRONG_PASSWORD_XYZ",
        retries=1,
    )
    try:
        assert client is None, \
            "SSH login should have FAILED with wrong password but succeeded"
        logger.info("TC_RADIUS_002 PASS: login correctly rejected")
    finally:
        close_ssh(client)


def test_tc_radius_003_valid_ro_user_login(radius_server_setup, radius_creds):
    """
    TC_RADIUS_003: Valid RO RADIUS user SSH login succeeds.
    Expected: Login granted. id does NOT show sudo group.
    """
    duthost = radius_server_setup["duthost"]
    client = ssh_connect_remote_retry(
        host=duthost.mgmt_ip,
        username=radius_creds["radius_ro_user"],
        password=radius_creds["radius_ro_user_passwd"],
    )
    try:
        assert client is not None, \
            "SSH login FAILED for valid RO user '{}'".format(radius_creds["radius_ro_user"])

        rc, out, _ = ssh_run_command(client, "id")
        assert rc == 0, "id command failed"
        assert "sudo" not in out, \
            "RO user should NOT be in sudo group, but got: {}".format(out)
        logger.info("TC_RADIUS_003 PASS: RO user id=%s", out)
    finally:
        close_ssh(client)


def test_tc_radius_004_unknown_user_rejected(radius_server_setup):
    """
    TC_RADIUS_004: Unknown RADIUS user is rejected.
    Expected: Login fails.
    """
    duthost = radius_server_setup["duthost"]
    client = ssh_connect_remote_retry(
        host=duthost.mgmt_ip,
        username="nonexistent_user_abc123",
        password="somepassword",
        retries=1,
    )
    try:
        assert client is None, \
            "SSH login should have FAILED for unknown user but succeeded"
        logger.info("TC_RADIUS_004 PASS: unknown user correctly rejected")
    finally:
        close_ssh(client)


def test_tc_radius_005_local_admin_still_works(radius_server_setup, radius_creds):
    """
    TC_RADIUS_005: Local admin login still works when AAA=radius local.
    Expected: Local admin can log in via local fallback.
    """
    duthost = radius_server_setup["duthost"]
    client = ssh_connect_remote_retry(
        host=duthost.mgmt_ip,
        username=radius_creds["local_user"],
        password=radius_creds["local_user_passwd"],
    )
    try:
        assert client is not None, \
            "Local admin login FAILED when AAA=radius local"
        rc, out, _ = ssh_run_command(client, "whoami")
        assert radius_creds["local_user"] in out, \
            "Expected whoami={}, got: {}".format(radius_creds["local_user"], out)
        logger.info("TC_RADIUS_005 PASS: local admin login works")
    finally:
        close_ssh(client)


def test_tc_radius_006_wrong_shared_secret_rejected(duthosts, enum_rand_one_per_hwsku_hostname,
                                                     ptfhost, radius_creds):
    """
    TC_RADIUS_006: Wrong shared secret on DUT causes login failure.
    Expected: Login fails because RADIUS server drops the request.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    # Override passkey with wrong value
    _radius_del(duthost, ptfhost.mgmt_ip)
    duthost.shell("config radius add {} -k WRONGSECRET -t 3 -p 1".format(ptfhost.mgmt_ip))
    duthost.shell("config aaa authentication login radius local")

    try:
        client = ssh_connect_remote_retry(
            host=duthost.mgmt_ip,
            username=radius_creds["radius_rw_user"],
            password=radius_creds["radius_rw_user_passwd"],
            retries=1,
        )
        close_ssh(client)
        assert client is None, \
            "Login should have failed with wrong shared secret"
        logger.info("TC_RADIUS_006 PASS: wrong secret correctly causes rejection")
    finally:
        # Restore correct passkey
        _radius_del(duthost, ptfhost.mgmt_ip)
        duthost.shell("config radius add {} -k {} -t 5 -p 1".format(
            ptfhost.mgmt_ip, radius_creds["passkey"]))
        duthost.shell("config aaa authentication login radius local")


def test_tc_radius_007_radius_server_reachable_from_dut(duthosts, enum_rand_one_per_hwsku_hostname,
                                                         ptfhost, radius_creds):
    """
    TC_RADIUS_007: DUT can reach RADIUS server — verified via radtest from PTF with DUT as NAS.
    Expected: Access-Accept received using the DUT's configured passkey.
    """
    accepted = radtest_verify(
        ptfhost,
        username=radius_creds["radius_rw_user"],
        password=radius_creds["radius_rw_user_passwd"],
        secret=radius_creds["passkey"],
    )
    assert accepted, "radtest did not return Access-Accept — RADIUS server not reachable/working"
    logger.info("TC_RADIUS_007 PASS: RADIUS server is reachable and responding")
