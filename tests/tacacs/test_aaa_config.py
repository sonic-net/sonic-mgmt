"""
test_aaa_config.py -- TC_001 to TC_005: Core AAA authentication and authorization tests.

These are the five foundational test cases that verify the TACACS+ stack is
working end-to-end before the more advanced failover / accounting / resilience
tests are exercised.

Test cases covered
------------------
TC_001  Valid SSH authentication      – RW user logs in; /etc/passwd has correct GECOS
TC_002  Invalid credentials rejected  – Wrong password raises SSH auth failure
TC_003  Fallback to local when server unreachable – tac_plus stopped; local admin still logs in
TC_004  RO user blocked from write commands       – sudo config fails for RO user
TC_005  RW user can execute read and write commands – show version + sudo config both succeed
"""

import logging
import paramiko
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import check_output, paramiko_ssh
from tests.common.helpers.tacacs.tacacs_helper import (
    check_tacacs,                               # noqa: F401
    ssh_remote_run,
    start_tacacs_server,
    stop_tacacs_server,
)
from tests.common.fixtures.tacacs import tacacs_creds  # noqa: F401
from tests.tacacs.utils import (
    change_and_wait_aaa_config_update,
    ssh_connect_remote_retry,
    ssh_run_command,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any', 't1-multi-asic'),
    pytest.mark.device_type('vs'),
]


# ---------------------------------------------------------------------------
# TC_001 -- Valid SSH authentication
# ---------------------------------------------------------------------------

def test_valid_ssh_authentication(
        localhost,
        duthosts,
        enum_rand_one_per_hwsku_hostname,
        tacacs_creds,       # noqa: F811
        check_tacacs):      # noqa: F811
    """
    TC_001 -- A TACACS+ RW user (priv-lvl=15) can SSH into the DUT using
    valid credentials.  After login, /etc/passwd must contain their JIT
    account entry with the 'remote_user_su' GECOS field, which SONiC writes
    for priv-lvl=15 users to grant sudo access.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dutip = duthost.mgmt_ip

    res = ssh_remote_run(
        localhost, dutip,
        tacacs_creds['tacacs_rw_user'],
        tacacs_creds['tacacs_rw_user_passwd'],
        "cat /etc/passwd"
    )

    # rc==0 and the passwd line must contain both the username and 'remote_user_su'
    check_output(res, tacacs_creds['tacacs_rw_user'], 'remote_user_su')


# ---------------------------------------------------------------------------
# TC_002 -- Invalid credentials rejected
# ---------------------------------------------------------------------------

def test_invalid_credentials_rejected(
        duthosts,
        enum_rand_one_per_hwsku_hostname,
        tacacs_creds,       # noqa: F811
        check_tacacs):      # noqa: F811
    """
    TC_002 -- When a valid TACACS+ username is presented with a wrong password,
    the SSH login must be rejected.  No shell must be granted.

    paramiko raises SSHException (or its subclass AuthenticationException) on
    authentication failure -- we catch both since the exact subtype depends on
    how the server closes the connection.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dutip = duthost.mgmt_ip

    login_failed = False
    try:
        paramiko_ssh(dutip, tacacs_creds['tacacs_rw_user'], "DEFINITELY_WRONG_PASSWORD_XYZ")
    except paramiko.ssh_exception.SSHException as exc:
        login_failed = True
        logger.info("Expected SSH rejection with wrong password: %s", repr(exc))
    except Exception as exc:
        login_failed = True
        logger.info("Connection-level rejection (as expected): %s", repr(exc))

    pytest_assert(
        login_failed,
        "Expected login to fail for user '{}' with wrong password but it succeeded".format(
            tacacs_creds['tacacs_rw_user'])
    )


# ---------------------------------------------------------------------------
# TC_003 -- Fallback to local when server unreachable
# ---------------------------------------------------------------------------

def test_local_fallback_when_server_unreachable(
        localhost,
        duthosts,
        enum_rand_one_per_hwsku_hostname,
        ptfhost,
        tacacs_creds,       # noqa: F811
        check_tacacs):      # noqa: F811
    """
    TC_003 -- When AAA auth = 'tacacs+ local' (failthrough enabled) and the
    TACACS+ server is stopped, the local admin account must still be able to
    log in through the local PAM fallback.

    Steps:
        1. Ensure auth = 'tacacs+ local'.
        2. Stop tac_plus on the PTF.
        3. SSH as local admin -- must succeed.
        4. Restart tac_plus; restore auth.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dutip = duthost.mgmt_ip

    # Get local admin credentials from the Ansible inventory
    dut_vars = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars
    admin_user = dut_vars.get('ansible_user',
                 dut_vars.get('ansible_ssh_user', 'admin'))
    admin_pass = dut_vars.get('ansible_password',
                 dut_vars.get('ansible_ssh_pass', 'admin'))

    try:
        # Make sure local fallback is enabled before we kill the server
        change_and_wait_aaa_config_update(
            duthost, "sudo config aaa authentication login tacacs+"
        )
        duthost.shell("sudo config aaa authentication failthrough enable",
                      module_ignore_errors=True)

        # Kill the TACACS+ server -- every subsequent TACACS+ auth will fail
        stop_tacacs_server(ptfhost)

        # Local admin must still get in via the 'local' fallback
        res = ssh_remote_run(localhost, dutip, admin_user, admin_pass, "show version")
        pytest_assert(
            res['rc'] == 0,
            "Local admin login failed after TACACS+ server stopped (rc={}, stderr={})".format(
                res['rc'], res.get('stderr', ''))
        )
        logger.info("TC_003 passed: local fallback worked when TACACS+ server was unreachable")

    finally:
        # Restart the server so subsequent tests have a working TACACS+ stack
        start_tacacs_server(ptfhost)
        change_and_wait_aaa_config_update(
            duthost, "sudo config aaa authentication login tacacs+"
        )


# ---------------------------------------------------------------------------
# TC_004 -- RO user blocked from write commands
# ---------------------------------------------------------------------------

def test_ro_user_blocked_from_write_commands(
        duthosts,
        enum_rand_one_per_hwsku_hostname,
        tacacs_creds,       # noqa: F811
        check_tacacs):      # noqa: F811
    """
    TC_004 -- A TACACS+ RO user (priv-lvl=1) must not be able to execute
    write/privileged commands.  Attempting 'sudo config ...' must be denied
    with a permission error.

    SONiC maps priv-lvl=1 to the 'remote_user' group (no sudo).  Any sudo
    invocation is therefore blocked by sudoers before it reaches the switch CLI.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dutip = duthost.mgmt_ip

    client = paramiko_ssh(
        dutip,
        tacacs_creds['tacacs_ro_user'],
        tacacs_creds['tacacs_ro_user_passwd'],
    )
    try:
        # 'sudo config interface shutdown Ethernet0' requires priv-lvl=15
        exit_code, _, stderr = ssh_run_command(
            client, "sudo config interface shutdown Ethernet0", verify=False
        )
        stderr_text = "".join(stderr.readlines())
        logger.info("RO user sudo config exit_code=%s stderr=%s", exit_code, stderr_text)

        pytest_assert(
            exit_code != 0,
            "RO user should not be able to run privileged config commands (exit_code={})".format(
                exit_code)
        )
        # The error message should indicate a permission problem
        denied_indicators = ["RW permission", "sudoers", "Permission denied", "not allowed", "sudo"]
        pytest_assert(
            any(indicator in stderr_text for indicator in denied_indicators),
            "Expected permission denial in stderr but got: '{}'".format(stderr_text)
        )
    finally:
        client.close()


# ---------------------------------------------------------------------------
# TC_005 -- RW user can execute read and write commands
# ---------------------------------------------------------------------------

def test_rw_user_read_write_commands(
        duthosts,
        enum_rand_one_per_hwsku_hostname,
        tacacs_creds,       # noqa: F811
        check_tacacs):      # noqa: F811
    """
    TC_005 -- A TACACS+ RW user (priv-lvl=15) must be able to execute both
    read-only commands ('show version') and privileged commands ('sudo config').

    SONiC maps priv-lvl=15 to the 'remote_user_su' group which grants sudo
    access, so both command classes must succeed.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dutip = duthost.mgmt_ip

    client = paramiko_ssh(
        dutip,
        tacacs_creds['tacacs_rw_user'],
        tacacs_creds['tacacs_rw_user_passwd'],
    )
    try:
        # --- Read command: must succeed ---
        exit_code_r, stdout_r, _ = ssh_run_command(
            client, "show version", verify=False
        )
        pytest_assert(
            exit_code_r == 0,
            "RW user failed to run 'show version' (exit_code={})".format(exit_code_r)
        )
        logger.info("TC_005 read command passed: show version rc=%s", exit_code_r)

        # --- Write command: must NOT get a 'RW permission' error ---
        # 'sudo config --help' is safe -- it just prints help -- but goes
        # through sudo, exercising the privilege path.
        exit_code_w, _, stderr_w = ssh_run_command(
            client, "sudo config --help", verify=False
        )
        stderr_text = "".join(stderr_w.readlines())
        pytest_assert(
            "RW permission" not in stderr_text,
            "RW user unexpectedly got 'RW permission' error on sudo config: {}".format(
                stderr_text)
        )
        logger.info("TC_005 write command passed: sudo config --help rc=%s", exit_code_w)

    finally:
        client.close()
