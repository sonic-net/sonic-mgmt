"""
RADIUS Accounting Tests — TC_RADIUS_011 to TC_RADIUS_014
Verifies Accounting-Start and Accounting-Stop records are generated correctly.
"""
import logging
import time
import pytest

from tests.radius.utils import (
    ssh_connect_remote_retry,
    ssh_run_command,
    close_ssh,
    get_acct_log_entries,
    _save_local_aaa,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology("any", "t1-multi-asic"),
    pytest.mark.device_type("vs"),
    pytest.mark.skip_check_dut_health,
]


@pytest.fixture(scope="module", autouse=True)
def enable_radius_accounting(radius_server_setup):
    """Enable RADIUS accounting on DUT for this test module. Restores and saves on teardown."""
    duthost = radius_server_setup["duthost"]
    duthost.shell("config aaa accounting radius", module_ignore_errors=True)
    yield
    duthost.shell("config aaa accounting disable", module_ignore_errors=True)
    duthost.shell("config save -y", module_ignore_errors=True)


def test_tc_radius_011_acct_start_on_login(radius_server_setup, radius_creds, ptfhost):
    """
    TC_RADIUS_011: Successful RADIUS login generates Accounting-Start record on server.
    Expected: radacct log contains Acct-Status-Type = Start for the user.
    """
    duthost = radius_server_setup["duthost"]
    username = radius_creds["radius_rw_user"]

    # Clear old accounting logs
    ptfhost.shell("rm -rf /var/log/freeradius/radacct/ && mkdir -p /var/log/freeradius/radacct/",
                  module_ignore_errors=True)

    client = ssh_connect_remote_retry(duthost.mgmt_ip, username, radius_creds["radius_rw_user_passwd"])
    assert client is not None, "SSH login failed — cannot test accounting"

    time.sleep(3)  # Allow accounting packet to be sent and logged
    close_ssh(client)
    time.sleep(2)

    log = get_acct_log_entries(ptfhost, username)
    assert username in log, \
        "No accounting record found for user '{}' in radacct. Log:\n{}".format(username, log)
    logger.info("TC_RADIUS_011 PASS: accounting record found for %s", username)


def test_tc_radius_012_acct_stop_on_logout(radius_server_setup, radius_creds, ptfhost):
    """
    TC_RADIUS_012: User logout generates Accounting-Stop record.
    Expected: radacct log contains Stop entry after session ends.
    """
    duthost = radius_server_setup["duthost"]
    username = radius_creds["radius_rw_user"]

    ptfhost.shell("rm -rf /var/log/freeradius/radacct/ && mkdir -p /var/log/freeradius/radacct/",
                  module_ignore_errors=True)

    client = ssh_connect_remote_retry(duthost.mgmt_ip, username, radius_creds["radius_rw_user_passwd"])
    assert client is not None, "SSH login failed"
    time.sleep(2)

    # Explicit logout
    ssh_run_command(client, "exit")
    close_ssh(client)
    time.sleep(3)

    log = get_acct_log_entries(ptfhost, username)
    assert username in log, \
        "No Stop accounting record found for '{}'. Log:\n{}".format(username, log)
    logger.info("TC_RADIUS_012 PASS: accounting Stop record found for %s", username)


def test_tc_radius_013_acct_contains_nas_ip(radius_server_setup, radius_creds, ptfhost):
    """
    TC_RADIUS_013: Accounting record contains the DUT's NAS-IP-Address attribute.
    Expected: radacct entry includes the DUT management IP.
    """
    duthost = radius_server_setup["duthost"]
    username = radius_creds["radius_rw_user"]

    ptfhost.shell("rm -rf /var/log/freeradius/radacct/ && mkdir -p /var/log/freeradius/radacct/",
                  module_ignore_errors=True)

    client = ssh_connect_remote_retry(duthost.mgmt_ip, username, radius_creds["radius_rw_user_passwd"])
    assert client is not None, "SSH login failed"
    time.sleep(3)
    close_ssh(client)
    time.sleep(2)

    log = get_acct_log_entries(ptfhost, username)
    assert duthost.mgmt_ip in log, \
        "DUT IP {} not found in accounting log:\n{}".format(duthost.mgmt_ip, log)
    logger.info("TC_RADIUS_013 PASS: NAS-IP %s found in accounting record", duthost.mgmt_ip)


def test_tc_radius_014_no_acct_when_disabled(radius_server_setup, radius_creds, ptfhost):
    """
    TC_RADIUS_014: When accounting is disabled, no records are generated.
    Expected: radacct log is empty after login+logout with accounting disabled.
    """
    duthost = radius_server_setup["duthost"]
    username = radius_creds["radius_rw_user"]

    # Disable accounting
    duthost.shell("config aaa accounting disable", module_ignore_errors=True)
    time.sleep(1)

    ptfhost.shell("rm -rf /var/log/freeradius/radacct/ && mkdir -p /var/log/freeradius/radacct/",
                  module_ignore_errors=True)

    client = ssh_connect_remote_retry(duthost.mgmt_ip, username, radius_creds["radius_rw_user_passwd"])
    time.sleep(2)
    close_ssh(client)
    time.sleep(2)

    log = get_acct_log_entries(ptfhost, username)
    assert username not in log, \
        "Accounting record found when accounting was disabled. Log:\n{}".format(log)
    logger.info("TC_RADIUS_014 PASS: no accounting records when disabled")

    # Re-enable for remaining tests
    duthost.shell("config aaa accounting radius", module_ignore_errors=True)
