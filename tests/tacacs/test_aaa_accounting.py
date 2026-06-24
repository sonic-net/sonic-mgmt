"""
test_aaa_accounting.py -- TC_006, TC_007, TC_017, TC_018: AAA Accounting tests.

Uses the same helpers (wait_for_log, check_tacacs_server_log_exist,
change_and_wait_aaa_config_update) proven in tests/tacacs/test_accounting.py.

Test cases covered
------------------
TC_006  Accounting records login events: login writes a 'start' record to tac_plus.acct
TC_007  Accounting records command execution: each command appears in tac_plus.acct
TC_017  Wildcard command encoding: server receives literal *, ? not expanded filenames
TC_018  Dual accounting (tacacs+ local): command appears in both tac_plus.acct AND DUT syslog
"""

import logging
import time
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import skip_release, paramiko_ssh
from tests.common.helpers.tacacs.tacacs_helper import (
    check_tacacs,                               # noqa: F401
    start_tacacs_server,
    stop_tacacs_server,
    per_command_accounting_skip_versions,
)
from tests.common.fixtures.tacacs import tacacs_creds  # noqa: F401
from tests.tacacs.utils import (
    check_server_received,
    change_and_wait_aaa_config_update,
    get_auditd_config_reload_timestamp,
    ssh_connect_remote_retry,
    ssh_run_command,
    cleanup_tacacs_log,
    TIMEOUT_LIMIT,
)
from tests.common.devices.ptf import PTFHost

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any', 't1-multi-asic'),
    pytest.mark.device_type('vs'),
]

# ---------------------------------------------------------------------------
# Module-level skip: per-command accounting not available on older images
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def check_image_version(duthost):
    """Skip entire module on SONiC images that lack per-command accounting."""
    skip_release(duthost, per_command_accounting_skip_versions)


# ---------------------------------------------------------------------------
# Helpers (mirrors tests/tacacs/test_accounting.py helpers)
# ---------------------------------------------------------------------------

def _host_run(host, command):
    """Run a command on either PTFHost or SonicHost."""
    if isinstance(host, PTFHost):
        return host.command(command)
    return host.shell("sudo {0}".format(command))


def _flush_log(host, log_file):
    """Force the OS to flush buffered log data to disk."""
    if "syslog" in log_file:
        _host_run(host, "kill -HUP $(cat /var/run/rsyslogd.pid)")
    _host_run(host, "sync {0}".format(log_file))


def _wait_for_log(host, log_file, sed_pattern, timeout=80, interval=1):
    """
    Poll log_file with sed_pattern until a match is found or timeout expires.
    Returns list of matching lines (empty if timeout).
    """
    waited = 0
    while waited <= timeout:
        _flush_log(host, log_file)
        res = _host_run(host, "sed -nE '{0}' {1}".format(sed_pattern, log_file))
        lines = res["stdout_lines"]
        if lines:
            logger.debug("Found log lines: %s", lines)
            return lines
        time.sleep(interval)
        waited += interval
    return []


def _check_tacacs_server_acct_log(ptfhost, username, command, timeout=60):
    """Assert that tac_plus.acct contains a record for username running command."""
    pattern = "/\t{0}\t.*\tcmd=.*{1}/P".format(username, command)
    lines = _wait_for_log(ptfhost, "/var/log/tac_plus.acct", pattern, timeout=timeout)
    pytest_assert(
        len(lines) > 0,
        "Expected accounting record for user='{}' cmd='{}' in tac_plus.acct but found none".format(
            username, command)
    )


def _check_syslog_acct_log(duthost, username, command, timeout=120):
    """Assert that DUT syslog contains an audisp-tacplus accounting entry for command."""
    pattern = (
        "/ansible.legacy.command Invoked/D;"
        "/INFO audisp-tacplus.+Accounting: user: {0},.*, command: .*{1},/P"
    ).format(username, command)
    lines = _wait_for_log(duthost, "/var/log/syslog", pattern, timeout=timeout)
    # Remove any lines that are themselves sed commands introduced by Ansible
    lines = [l for l in lines if 'sudo sed' not in l]
    pytest_assert(
        len(lines) > 0,
        "Expected syslog accounting entry for user='{}' cmd='{}' but found none".format(
            username, command)
    )


# ---------------------------------------------------------------------------
# Per-test fixture: authenticated RW user Paramiko client
# ---------------------------------------------------------------------------

@pytest.fixture
def rw_user_client(
        duthosts,
        enum_rand_one_per_hwsku_hostname,
        tacacs_creds,   # noqa: F811
        check_tacacs):  # noqa: F811  -- explicit dep: TACACS+ must be live before SSH
    """
    Paramiko client logged in as TACACS+ RW user. Auto-closed after test.

    check_tacacs is listed as an explicit dependency so pytest always sets up
    the TACACS+ server configuration on the DUT *before* this fixture tries to
    open the SSH connection.  Without it, pytest may resolve rw_user_client
    before check_tacacs because rw_user_client has no other ordering constraint,
    causing the SSH login to fail (TACACS+ not configured yet) → ERROR.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dutip = duthost.mgmt_ip
    client = ssh_connect_remote_retry(
        dutip,
        tacacs_creds['tacacs_rw_user'],
        tacacs_creds['tacacs_rw_user_passwd'],
        duthost,
    )
    yield client
    client.close()


# ---------------------------------------------------------------------------
# TC_006 -- Accounting records login events
# ---------------------------------------------------------------------------

def test_accounting_records_login_events(
        localhost,
        ptfhost,
        duthosts,
        enum_rand_one_per_hwsku_hostname,
        tacacs_creds,           # noqa: F811
        check_tacacs):          # noqa: F811
    """
    TC_006 -- When TACACS+ accounting is enabled, every SSH login must produce
    a 'start' record in /var/log/tac_plus.acct on the TACACS+ server.
    After the session ends, a 'stop' record with elapsed_time must also appear.

    Record format written by tac_plus:
        <timestamp>  <user>  <DUT_IP>  <tty>  start  service=shell
        <timestamp>  <user>  <DUT_IP>  <tty>  stop   elapsed_time=N  service=shell
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dutip = duthost.mgmt_ip
    username = tacacs_creds['tacacs_rw_user']

    # Enable accounting so login events are sent to the server
    change_and_wait_aaa_config_update(duthost, "sudo config aaa accounting tacacs+")

    # Clear the accounting log so previous entries do not interfere
    ptfhost.command("truncate -s 0 /var/log/tac_plus.acct")

    try:
        # Trigger a login session via ssh_remote_run (opens and closes SSH)
        from tests.common.helpers.tacacs.tacacs_helper import ssh_remote_run
        res = ssh_remote_run(
            localhost, dutip,
            username,
            tacacs_creds['tacacs_rw_user_passwd'],
            "show version"
        )
        pytest_assert(res['rc'] == 0, "Login for accounting test failed: {}".format(res))

        # Give tac_plus a moment to flush the accounting record
        time.sleep(3)

        # Assert 'start' record exists for this user
        start_pattern = "/\\t{0}\\t.*\\tstart/P".format(username)
        start_lines = _wait_for_log(
            ptfhost, "/var/log/tac_plus.acct", start_pattern, timeout=60
        )
        pytest_assert(
            len(start_lines) > 0,
            "Expected 'start' accounting record for user '{}' in tac_plus.acct "
            "but found none".format(username)
        )
        logger.info("TC_006 passed: login 'start' record found: %s", start_lines)

        # Assert 'stop' record exists (session closed after ssh_remote_run returns)
        stop_pattern = "/\\t{0}\\t.*\\tstop/P".format(username)
        stop_lines = _wait_for_log(
            ptfhost, "/var/log/tac_plus.acct", stop_pattern, timeout=60
        )
        pytest_assert(
            len(stop_lines) > 0,
            "Expected 'stop' accounting record for user '{}' in tac_plus.acct "
            "but found none".format(username)
        )
        logger.info("TC_006 passed: logout 'stop' record found: %s", stop_lines)

    finally:
        # Disable accounting so it does not affect subsequent tests
        duthost.shell("sudo config aaa accounting disable", module_ignore_errors=True)
        ptfhost.command("truncate -s 0 /var/log/tac_plus.acct")


# ---------------------------------------------------------------------------
# TC_007 -- Accounting records command execution
# ---------------------------------------------------------------------------

def test_accounting_records_command_execution(
        ptfhost,
        duthosts,
        enum_rand_one_per_hwsku_hostname,
        tacacs_creds,           # noqa: F811
        check_tacacs,           # noqa: F811
        rw_user_client):
    """
    TC_007 -- With per-command accounting enabled (requires SONiC >= 202112),
    every command run in an authenticated session must generate an accounting
    record in /var/log/tac_plus.acct.

    The record must contain:
        cmd=<command>   for the specific command that was run
        user=<username> for the authenticated user
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    username = tacacs_creds['tacacs_rw_user']
    test_command = "grep"   # short, safe, and easy to grep for in the log

    # Enable per-command accounting
    change_and_wait_aaa_config_update(duthost, "sudo config aaa accounting tacacs+")

    # Clear accounting log before running the command
    ptfhost.command("truncate -s 0 /var/log/tac_plus.acct")

    try:
        # Run the test command via the authenticated RW session
        ssh_run_command(rw_user_client, test_command)

        # Give tac_plus a moment to flush
        time.sleep(3)

        # Assert the command accounting record exists
        cmd_pattern = "/\\t{0}\\t.*\\tcmd=.*{1}/P".format(username, test_command)
        cmd_lines = _wait_for_log(
            ptfhost, "/var/log/tac_plus.acct", cmd_pattern, timeout=60
        )
        pytest_assert(
            len(cmd_lines) > 0,
            "Expected command accounting record for user='{}' cmd='{}' in "
            "tac_plus.acct but found none".format(username, test_command)
        )
        logger.info("TC_007 passed: command accounting record found: %s", cmd_lines)

    finally:
        duthost.shell("sudo config aaa accounting disable", module_ignore_errors=True)
        ptfhost.command("truncate -s 0 /var/log/tac_plus.acct")


# ---------------------------------------------------------------------------
# TC_017 -- Wildcard command encoding
# ---------------------------------------------------------------------------

def test_wildcard_encoding_sent_to_server(
        ptfhost,
        duthosts,
        enum_rand_one_per_hwsku_hostname,
        tacacs_creds,           # noqa: F811
        check_tacacs,           # noqa: F811
        rw_user_client,
        skip_in_container_test):
    """
    TC_017 -- When a user runs 'ls *' or 'ls testfile.?', the DUT must send
    the literal wildcard characters to the TACACS+ authorization server,
    NOT the shell-expanded filenames.

    check_server_received inspects tac_plus.log for the raw bytes sent by the DUT.

    Mirrors tests/tacacs/test_authorization.py::test_tacacs_authorization_wildcard.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    # Enable TACACS+ per-command authorization so every command is sent to server
    change_and_wait_aaa_config_update(duthost, "sudo config aaa authorization tacacs+")

    try:
        # Create some test files so shell would normally expand wildcards
        ssh_run_command(rw_user_client, "touch testfile.1", expect_exit_code=0, verify=True)
        ssh_run_command(rw_user_client, "touch testfile.2", expect_exit_code=0, verify=True)

        # Clear the TACACS+ log so we only see new entries
        ptfhost.command("truncate -s 0 /var/log/tac_plus.log")

        # Run ls *  -- server should receive cmd-arg=* not the expanded file list
        ssh_run_command(rw_user_client, "ls *", expect_exit_code=0, verify=True)
        check_server_received(ptfhost, "cmd=/usr/bin/ls")
        check_server_received(ptfhost, "cmd-arg=*")

        # Clear log between checks
        ptfhost.command("truncate -s 0 /var/log/tac_plus.log")

        # Run ls testfile.?  -- server should receive cmd-arg=testfile.?
        ssh_run_command(rw_user_client, "ls testfile.?", expect_exit_code=0, verify=True)
        check_server_received(ptfhost, "cmd=/usr/bin/ls")
        check_server_received(ptfhost, "cmd-arg=testfile.?")

    finally:
        # Restore authorization to local
        duthost.shell("sudo config aaa authorization local")
        # Clean up test files (best effort)
        ssh_run_command(rw_user_client, "rm -f testfile.1 testfile.2", verify=False)
        # Restore accounting setting touched by check_tacacs fixture
        ptfhost.command("truncate -s 0 /var/log/tac_plus.log")


# ---------------------------------------------------------------------------
# TC_018 -- Dual accounting: tac_plus.acct AND DUT syslog
# ---------------------------------------------------------------------------

def test_dual_accounting_tacacs_and_local(
        ptfhost,
        duthosts,
        enum_rand_one_per_hwsku_hostname,
        tacacs_creds,           # noqa: F811
        check_tacacs,           # noqa: F811
        rw_user_client):
    """
    TC_018 -- With 'config aaa accounting tacacs+ local', every command must
    be recorded in BOTH:
        1. /var/log/tac_plus.acct  on the PTF (TACACS+ server side)
        2. /var/log/syslog         on the DUT  (audisp-tacplus local side)

    Mirrors tests/tacacs/test_accounting.py::test_accounting_tacacs_and_local.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    username = tacacs_creds['tacacs_rw_user']
    test_command = "grep"

    # Enable dual accounting (tacacs+ then local).
    # Use single-quotes inside the shell string to avoid nested-quote issues
    # when duthost.shell() passes the command through Python subprocess.
    change_and_wait_aaa_config_update(
        duthost,
        "sudo config aaa accounting 'tacacs+ local'"
    )

    # Clear all log files before the test command
    cleanup_tacacs_log(ptfhost, rw_user_client)

    # Run the test command as the RW TACACS+ user
    ssh_run_command(rw_user_client, test_command)

    # --- Assert 1: PTF tac_plus.acct has the record ---
    _check_tacacs_server_acct_log(ptfhost, username, test_command)

    # --- Assert 2: DUT syslog has the audisp-tacplus accounting entry ---
    _check_syslog_acct_log(duthost, username, test_command)

    logger.info(
        "TC_018 passed: '%s' appeared in both tac_plus.acct and DUT syslog",
        test_command
    )
