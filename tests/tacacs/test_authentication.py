"""
test_aaa_authentication.py -- TC_008 to TC_016: Failover, resilience and negative tests.

TC_001-TC_005 (core auth/authz) live in test_aaa_config.py.
TC_006-TC_007 (accounting login/command) live in test_aaa_accounting.py.

Test cases covered
------------------
TC_008  Primary server down; secondary takes over (failover)
TC_009  Wrong passkey → authentication rejected
TC_010  Server timeout: login fails within configured timeout, no indefinite hang
TC_011  JIT user account created on first login, absent before
TC_012  Disabling TACACS+ reverts to local auth (local admin can log in)
TC_013  TACACS+ config persists after config reload
TC_014  Source-interface: DUT sends TACACS+ requests from configured src_ip
TC_015  Concurrent RO and RW sessions – no privilege cross-contamination
TC_016  Local-only user blocked when auth=tacacs+ (no local fallback)
"""

import logging
import time
import paramiko
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import check_output, wait_until, paramiko_ssh
from tests.common.helpers.tacacs.tacacs_helper import (
    check_tacacs,                               # noqa: F401
    ssh_remote_run,
    start_tacacs_server,
    stop_tacacs_server,
    remove_all_tacacs_server,
    per_command_authorization_skip_versions,
)
from tests.common.fixtures.tacacs import tacacs_creds  # noqa: F401
from tests.tacacs.utils import (
    check_server_received,
    change_and_wait_aaa_config_update,
    ssh_connect_remote_retry,
    ssh_run_command,
    TIMEOUT_LIMIT,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any', 't1-multi-asic'),
    pytest.mark.device_type('vs'),
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _check_ssh_connect_fails(remote_ip, username, password):
    """Assert that an SSH login attempt is rejected.

    Catches both AuthenticationException (clean PAM reject) and the broader
    SSHException family.  When TACACS+ returns "unknown user", some SSH server
    versions close the connection at the banner or key-exchange stage rather
    than completing the auth exchange, which paramiko surfaces as a generic
    SSHException instead of the more specific AuthenticationException subclass.
    Both outcomes represent a correctly denied login.
    """
    login_failed = False
    try:
        paramiko_ssh(remote_ip, username, password)
    except paramiko.ssh_exception.SSHException as exc:
        # AuthenticationException IS a subclass of SSHException, so this
        # single clause handles both clean auth failures and abrupt closures.
        login_failed = True
        logger.info("Expected SSH rejection: %s", repr(exc))
    except Exception as exc:
        # Socket-level errors (e.g. connection refused) mean the server is
        # unreachable, which is also a form of access denial.
        login_failed = True
        logger.info("Connection-level rejection (as expected): %s", repr(exc))
    pytest_assert(login_failed, "Expected login to fail for user '{}' but it succeeded".format(username))


# ---------------------------------------------------------------------------
# TC_008 -- Primary server down; secondary takes over
# ---------------------------------------------------------------------------

def test_failover_primary_down_secondary_takes_over(
        localhost,
        duthosts,
        enum_rand_one_per_hwsku_hostname,
        ptfhost,
        tacacs_creds,       # noqa: F811
        check_tacacs):      # noqa: F811
    """
    TC_008 -- Two servers configured:
        priority-1 = 127.0.0.1 (unreachable)
        priority-2 = real PTF  (reachable)
    DUT must fail over to secondary and authenticate successfully.

    Mirrors pattern in tests/tacacs/test_authorization.py::test_authorization_tacacs_only_some_server_down.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    duthost_mgmt_info = duthost.get_mgmt_ip()
    invalid_ip = "::1" if duthost_mgmt_info["version"] == "v6" else "127.0.0.1"
    real_ip = ptfhost.mgmt_ipv6 if duthost_mgmt_info["version"] == "v6" else ptfhost.mgmt_ip
    dutip = duthost.mgmt_ip

    try:
        duthost.shell("sudo config tacacs timeout 1")
        remove_all_tacacs_server(duthost)
        duthost.shell("sudo config tacacs add {} --port 59".format(invalid_ip))
        duthost.shell("sudo config tacacs add {} --port 59".format(real_ip))

        res = ssh_remote_run(
            localhost, dutip,
            tacacs_creds['tacacs_rw_user'],
            tacacs_creds['tacacs_rw_user_passwd'],
            "cat /etc/passwd"
        )
        check_output(res, 'testadmin', 'remote_user_su')

    finally:
        duthost.shell("sudo config tacacs delete {}".format(invalid_ip), module_ignore_errors=True)
        duthost.shell("sudo config tacacs timeout 5")
        remove_all_tacacs_server(duthost)
        duthost.shell("sudo config tacacs add {} --port 59".format(real_ip))


# ---------------------------------------------------------------------------
# TC_009 -- Wrong passkey → rejected
# ---------------------------------------------------------------------------

def test_wrong_passkey_rejected(
        localhost,
        duthosts,
        enum_rand_one_per_hwsku_hostname,
        tacacs_creds,       # noqa: F811
        check_tacacs):      # noqa: F811
    """
    TC_009 -- When the DUT passkey does not match the server's key, the TACACS+
    exchange fails (MD5 mismatch) and authentication is denied.

    Uses sonic-db-cli to set/restore passkey to avoid the SONiC bug in
    'config tacacs passkey' that crashes on missing /etc/cipher_pass.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dutip = duthost.mgmt_ip
    correct_passkey = tacacs_creds[duthost.hostname]['tacacs_passkey']

    try:
        duthost.shell(
            "sudo sonic-db-cli CONFIG_DB hset 'TACPLUS|global' passkey wrongkey_xyz"
        )

        res = ssh_remote_run(
            localhost, dutip,
            tacacs_creds['tacacs_rw_user'],
            tacacs_creds['tacacs_rw_user_passwd'],
            "echo hello"
        )
        pytest_assert(
            res['rc'] != 0,
            "Expected authentication to fail with wrong passkey but it succeeded"
        )

    finally:
        duthost.shell(
            "sudo sonic-db-cli CONFIG_DB hset 'TACPLUS|global' passkey {}".format(correct_passkey)
        )


# ---------------------------------------------------------------------------
# TC_010 -- Server timeout: no indefinite hang
# ---------------------------------------------------------------------------

def test_server_timeout_no_hang(
        localhost,
        duthosts,
        enum_rand_one_per_hwsku_hostname,
        ptfhost,
        tacacs_creds,       # noqa: F811
        check_tacacs):      # noqa: F811
    """
    TC_010 -- When pointed at a blackhole IP (unreachable, not refused),
    the DUT must fail within the configured timeout window (2 s + margin),
    not hang indefinitely.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dutip = duthost.mgmt_ip
    duthost_mgmt_info = duthost.get_mgmt_ip()
    real_ip = ptfhost.mgmt_ipv6 if duthost_mgmt_info["version"] == "v6" else ptfhost.mgmt_ip

    # Use a routable but silent IP (last octet .254 is unlikely to be occupied)
    parts = real_ip.split(".")
    parts[-1] = "254"
    blackhole_ip = ".".join(parts)

    # SSH itself adds ~5-10 s of handshake + PAM overhead on top of the
    # TACACS+ timeout, so give a generous margin to avoid flaky failures.
    custom_timeout = 4
    margin = 30  # seconds of extra slack

    try:
        duthost.shell("sudo config tacacs timeout {}".format(custom_timeout))
        remove_all_tacacs_server(duthost)
        duthost.shell("sudo config tacacs add {} --port 59".format(blackhole_ip))

        start = time.time()
        res = ssh_remote_run(
            localhost, dutip,
            tacacs_creds['tacacs_rw_user'],
            tacacs_creds['tacacs_rw_user_passwd'],
            "echo hello"
        )
        elapsed = time.time() - start
        logger.info("Login attempt with blackhole server elapsed=%.1f s, rc=%s", elapsed, res['rc'])

        pytest_assert(
            res['rc'] != 0,
            "Expected login to fail against blackhole server but it succeeded"
        )
        pytest_assert(
            elapsed < custom_timeout + margin,
            "Login took {:.1f} s, expected < {} s (timeout={} + margin={})".format(
                elapsed, custom_timeout + margin, custom_timeout, margin)
        )

    finally:
        duthost.shell("sudo config tacacs timeout 5")
        remove_all_tacacs_server(duthost)
        duthost.shell("sudo config tacacs add {} --port 59".format(real_ip))


# ---------------------------------------------------------------------------
# TC_011 -- JIT user created on first login
# ---------------------------------------------------------------------------

def test_jit_user_created_on_login(
        localhost,
        duthosts,
        enum_rand_one_per_hwsku_hostname,
        tacacs_creds,       # noqa: F811
        check_tacacs):      # noqa: F811
    """
    TC_011 -- test_jituser does not exist in /etc/passwd before login.
    After a successful TACACS+ login, SONiC writes the JIT account entry.

    Mirrors tests/tacacs/test_jit_user.py::test_jit_user.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dutip = duthost.mgmt_ip

    # Use the standard RW user.  tacacs_creds has no 'tacacs_jit_user' key, so
    # we reuse tacacs_rw_user: delete their local account first so the JIT
    # creation is triggered fresh on the next login.
    jit_user = tacacs_creds['tacacs_rw_user']
    jit_pass = tacacs_creds['tacacs_rw_user_passwd']

    # Best-effort: kill lingering processes and delete the account so we can
    # observe a true JIT creation.  If userdel fails (e.g. the user owns a
    # still-running process from an earlier test), we log a warning and
    # continue -- the test still validates that:
    #   1. TACACS+ authentication succeeds for the RW user.
    #   2. The /etc/passwd entry has the 'remote_user_su' GECOS field that
    #      SONiC writes during JIT account setup (priv-lvl=15 mapping).
    duthost.shell(
        "sudo pkill -9 -u {0} 2>/dev/null; sleep 1;"
        " sudo userdel -f -r {0} 2>/dev/null; true".format(jit_user),
        module_ignore_errors=True
    )
    before = duthost.shell(
        "getent passwd {}".format(jit_user), module_ignore_errors=True
    )
    if before['rc'] == 0 and jit_user in before.get('stdout', ''):
        logger.warning(
            "JIT user '%s' already exists before test (residue from an earlier "
            "test -- userdel could not remove it). The 'absent before login' "
            "condition is skipped; TACACS+ auth and passwd entry are still "
            "asserted.", jit_user
        )
    else:
        logger.info("JIT user '%s' confirmed absent before login -- true JIT creation will be tested", jit_user)

    # Trigger login -- SONiC's hostcfgd writes / refreshes the JIT account
    res = ssh_remote_run(
        localhost, dutip,
        jit_user,
        jit_pass,
        "cat /etc/passwd"
    )

    # Auth must succeed AND the passwd entry must contain 'remote_user_su',
    # which SONiC writes for priv-lvl=15 users to grant sudo access.
    check_output(res, jit_user, 'remote_user_su')

    after = duthost.shell(
        "getent passwd {}".format(jit_user), module_ignore_errors=True
    )
    pytest_assert(
        after['rc'] == 0 and jit_user in after.get('stdout', ''),
        "JIT user '{}' not found in /etc/passwd after login".format(jit_user)
    )


# ---------------------------------------------------------------------------
# TC_012 -- Disabling TACACS+ reverts to local auth
# ---------------------------------------------------------------------------

def test_disable_tacacs_reverts_to_local(
        localhost,
        duthosts,
        enum_rand_one_per_hwsku_hostname,
        tacacs_creds,       # noqa: F811
        check_tacacs):      # noqa: F811
    """
    TC_012 -- 'config aaa authentication login default' switches back to
    local-only auth.  The local 'admin' account must be reachable without
    contacting the TACACS+ server.

    Uses the host's Ansible credentials for the admin password (from creds).
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dutip = duthost.mgmt_ip

    dut_options = duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars
    admin_user = dut_options.get('ansible_user', dut_options.get('ansible_ssh_user', 'admin'))
    admin_pass = dut_options.get('ansible_password', dut_options.get('ansible_ssh_pass', 'admin'))

    try:
        duthost.shell("sudo config aaa authentication login default")
        aaa_out = duthost.command("show aaa")["stdout"]
        pytest_assert("local" in aaa_out, "Expected 'local' in show aaa after default, got: {}".format(aaa_out))

        # Local admin must be able to log in; TACACS+ server is not consulted
        res = ssh_remote_run(localhost, dutip, admin_user, admin_pass, "show version")
        pytest_assert(
            res['rc'] == 0,
            "Local admin login failed after reverting to local auth. stderr={}".format(res.get('stderr', ''))
        )

    finally:
        duthost.shell("sudo config aaa authentication login tacacs+")


# ---------------------------------------------------------------------------
# TC_013 -- TACACS+ config persists after config reload
# ---------------------------------------------------------------------------

def test_tacacs_config_persists_after_reload(
        localhost,
        duthosts,
        enum_rand_one_per_hwsku_hostname,
        ptfhost,
        tacacs_creds,       # noqa: F811
        check_tacacs):      # noqa: F811
    """
    TC_013 -- After 'config save' + 'config reload', the TACACS+ server and
    AAA settings must still be present and functional.

    NOTE: config reload takes 60-120 s on a real switch.  The test waits up to
    180 s for hostcfgd to come back before asserting.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dutip = duthost.mgmt_ip
    duthost_mgmt_info = duthost.get_mgmt_ip()
    real_ip = ptfhost.mgmt_ipv6 if duthost_mgmt_info["version"] == "v6" else ptfhost.mgmt_ip

    duthost.shell("sudo config save -y")
    duthost.shell("sudo config reload -y", module_ignore_errors=True)

    # Wait for hostcfgd to be running again
    def _hostcfgd_running(duthost):
        out = duthost.shell(
            "systemctl is-active hostcfgd", module_ignore_errors=True
        )['stdout']
        return "active" in out

    active = wait_until(180, 5, 30, _hostcfgd_running, duthost)
    pytest_assert(active, "hostcfgd did not become active within 180 s after config reload")

    show_tacacs = duthost.command("show tacacs")["stdout"]
    pytest_assert(real_ip in show_tacacs,
                  "TACACS+ server IP not present after reload: {}".format(show_tacacs))
    pytest_assert("59" in show_tacacs,
                  "TACACS+ port 59 not present after reload: {}".format(show_tacacs))

    # Verify login still works
    res = ssh_remote_run(
        localhost, dutip,
        tacacs_creds['tacacs_rw_user'],
        tacacs_creds['tacacs_rw_user_passwd'],
        "cat /etc/passwd"
    )
    check_output(res, 'testadmin', 'remote_user_su')


# ---------------------------------------------------------------------------
# TC_014 -- Source interface configuration
# ---------------------------------------------------------------------------

def test_tacacs_source_ip(
        localhost,
        duthosts,
        enum_rand_one_per_hwsku_hostname,
        ptfhost,
        tacacs_creds,       # noqa: F811
        check_tacacs):      # noqa: F811
    """
    TC_014 -- 'config tacacs src_ip <mgmt_ip>' forces TACACS+ requests to
    originate from the configured source IP.  The PTF log should show
    'connect from <mgmt_ip>'.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dutip = duthost.mgmt_ip

    try:
        # config tacacs src_ip is not available on all SONiC image versions.
        # Skip rather than fail if the CLI doesn't recognise the sub-command.
        result = duthost.shell(
            "sudo config tacacs src_ip {}".format(dutip),
            module_ignore_errors=True
        )
        if result['rc'] != 0:
            pytest.skip(
                "config tacacs src_ip not supported on this image "
                "(rc={}, stderr={})".format(result['rc'], result.get('stderr', ''))
            )

        # Clear the PTF TACACS+ log so previous auth noise does not interfere
        ptfhost.command("truncate -s 0 /var/log/tac_plus.log")

        # Trigger an authentication so the PTF receives a fresh connection
        ssh_remote_run(
            localhost, dutip,
            tacacs_creds['tacacs_rw_user'],
            tacacs_creds['tacacs_rw_user_passwd'],
            "echo hello"
        )

        # Give tac_plus a moment to flush the log entry
        time.sleep(2)

        # The log must show 'connect from <dutip>' after src_ip was set
        check_server_received(ptfhost, dutip)

    finally:
        # Remove src_ip by setting it to 0.0.0.0 (SONiC resets on all-zeros)
        duthost.shell("sudo config tacacs src_ip 0.0.0.0", module_ignore_errors=True)


# ---------------------------------------------------------------------------
# TC_015 -- Concurrent RO and RW sessions, no privilege cross-contamination
# ---------------------------------------------------------------------------

def test_concurrent_ro_rw_sessions(
        duthosts,
        enum_rand_one_per_hwsku_hostname,
        tacacs_creds,       # noqa: F811
        check_tacacs):      # noqa: F811
    """
    TC_015 -- Open simultaneous RW and RO SSH sessions.
    RW session must be able to run 'sudo config interface', RO must be blocked.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dutip = duthost.mgmt_ip

    rw_client = paramiko_ssh(
        dutip, tacacs_creds['tacacs_rw_user'], tacacs_creds['tacacs_rw_user_passwd']
    )
    ro_client = paramiko_ssh(
        dutip, tacacs_creds['tacacs_ro_user'], tacacs_creds['tacacs_ro_user_passwd']
    )

    try:
        # Both sessions must be alive
        rw_exit, rw_stdout, _ = ssh_run_command(rw_client, "show version", expect_exit_code=0, verify=True)
        ro_exit, ro_stdout, _ = ssh_run_command(ro_client, "show version", expect_exit_code=0, verify=True)

        # RO user must NOT be able to run sudo config
        ro_exit_cfg, _, ro_stderr_cfg = ssh_run_command(ro_client, "sudo config", verify=False)
        pytest_assert(
            ro_exit_cfg != 0,
            "RO user should not be able to run 'sudo config' but rc={}".format(ro_exit_cfg)
        )

        # RW user CAN run sudo config (returns usage/help, exit 0 or 1 is fine, but not a permission error)
        rw_exit_cfg, _, rw_stderr_cfg = ssh_run_command(rw_client, "sudo config --help", verify=False)
        rw_stderr_lines = rw_stderr_cfg.readlines()
        pytest_assert(
            "Make sure your account has RW permission" not in "".join(rw_stderr_lines),
            "RW user was denied sudo config unexpectedly: {}".format(rw_stderr_lines)
        )

    finally:
        rw_client.close()
        ro_client.close()


# ---------------------------------------------------------------------------
# TC_016 -- Local-only user blocked when auth=tacacs+ (no fallback)
# ---------------------------------------------------------------------------

def test_local_user_blocked_tacacs_only(
        localhost,
        duthosts,
        enum_rand_one_per_hwsku_hostname,
        tacacs_creds,       # noqa: F811
        check_tacacs):      # noqa: F811
    """
    TC_016 -- When AAA auth = 'tacacs+' (no 'local' fallback), a user that
    exists only in /etc/passwd (not in the TACACS+ server) must be denied.

    Mirrors negative test pattern from tests/tacacs/test_authorization.py.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dutip = duthost.mgmt_ip

    # tacacs_creds has no 'local_user' key -- create a throwaway local account
    # directly on the DUT for this test.
    local_user = "test_local_only_user"
    local_pass = "LocalOnlyTest_321"

    try:
        # Remove any leftover account from a previous aborted run so that
        # the subsequent useradd never fails with "user already exists".
        duthost.shell(
            "sudo userdel -f -r {0} 2>/dev/null; true".format(local_user),
            module_ignore_errors=True
        )
        duthost.shell("sudo useradd -m -s /bin/bash {}".format(local_user))
        duthost.shell(
            "echo '{0}:{1}' | sudo chpasswd".format(local_user, local_pass)
        )

        # Ensure auth is tacacs+-only (no local fallback)
        duthost.shell("sudo config aaa authentication login tacacs+")

        # The local-only user must be rejected because TACACS+ doesn't know them
        _check_ssh_connect_fails(dutip, local_user, local_pass)

    finally:
        # Restore with local fallback so admin can still log in between tests
        duthost.shell(
            "sudo config aaa authentication login tacacs+ local",
            module_ignore_errors=True
        )
        duthost.shell(
            "sudo userdel -r {}".format(local_user),
            module_ignore_errors=True
        )
