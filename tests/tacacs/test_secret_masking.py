"""
test_secret_masking.py — Verify that audisp-tacplus masks secrets in accounting records.

Tests that syslog NEVER contains plaintext secrets when the following commands are run
by a TACACS+ user (auid > 1000, triggering the audit EXECVE rule):

  - config tacacs passkey <SECRET>
  - config radius passkey <SECRET>
  - config snmp community add <SECRET> <RO|RW>
  - config snmp community del <SECRET>
  - config snmp community replace <OLD_SECRET> <NEW_SECRET>

Each test:
  1. Runs the command as a TACACS+ user via SSH.
  2. Checks syslog for audisp-tacplus accounting records.
  3. Asserts the plaintext secret does NOT appear in any accounting line.
  4. Asserts that a masked form (containing '*') IS present, confirming the record
     was written (not silently dropped).

Modelled on test_accounting.py's check_local_log_exist and wait_for_log pattern,
which are known to work reliably in CI.

Test topology: vs (virtual switch), any
Requires: TACACS+ server on ptfhost, tacacs_creds fixture, check_tacacs fixture.
"""

import logging
import re
import time
import pytest

from tests.common.helpers.tacacs.tacacs_helper import (  # noqa: F401
    per_command_accounting_skip_versions,
    check_tacacs,
)
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import skip_release
from .utils import (
    change_and_wait_aaa_config_update,
    ssh_connect_remote_retry,
    ssh_run_command,
    cleanup_tacacs_log,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology("any", "t1-multi-asic"),
    pytest.mark.device_type("vs"),
]

# Sentinel secrets used in tests — must not appear in syslog.
_TACACS_SECRET = "Cade_TacacsSecret_99"
_RADIUS_SECRET = "Cade_RadiusSecret_99"
_SNMP_SECRET_ADD = "Cade_SnmpAdd_99"
_SNMP_SECRET_DEL = "Cade_SnmpDel_99"
_SNMP_SECRET_REPLACE_OLD = "Cade_SnmpOld_99"
_SNMP_SECRET_REPLACE_NEW = "Cade_SnmpNew_99"

# Timeout parameters — match test_accounting.py's wait_for_log defaults.
_SYSLOG_WAIT_TIMEOUT = 120
_SYSLOG_CHECK_INTERVAL = 1
_RETRY_COUNT = 3


# ---------------------------------------------------------------------------
# Helpers — exact same pattern as test_accounting.py's check_local_log_exist
# ---------------------------------------------------------------------------

def _flush_syslog(duthost):
    """Force rsyslogd to flush buffered writes (same as test_accounting.py's flush_log)."""
    duthost.shell("sudo kill -HUP $(cat /var/run/rsyslogd.pid) 2>/dev/null || true")
    duthost.shell("sudo sync /var/log/syslog 2>/dev/null || true")


def _wait_for_log(duthost, pattern, timeout=_SYSLOG_WAIT_TIMEOUT):
    """
    Poll /var/log/syslog using sed until pattern matches or timeout.
    Mirrors test_accounting.py's wait_for_log exactly.
    Returns matching lines (list of str) or empty list on timeout.
    """
    wait_time = 0
    while wait_time <= timeout:
        _flush_syslog(duthost)
        sed_command = "sed -nE '{0}' /var/log/syslog".format(pattern)
        res = duthost.shell("sudo {0}".format(sed_command), module_ignore_errors=True)
        lines = [line for line in res.get("stdout_lines", []) if "sudo sed" not in line]
        if lines:
            return lines
        time.sleep(_SYSLOG_CHECK_INTERVAL)
        wait_time += _SYSLOG_CHECK_INTERVAL
    return []


def _assert_secret_masked(duthost, ptfhost, tacacs_creds, rw_user_client,
                          ssh_command, command_fragment, secret, description,
                          retry=_RETRY_COUNT):
    """
    Run ssh_command as the TACACS user and verify the audisp-tacplus accounting record:
      1. Exists in syslog.
      2. Does NOT contain plaintext secret.
      3. Contains a masked ('*') form.

    Mirrors check_local_log_exist from test_accounting.py:
    - Re-enables local accounting and truncates syslog on each retry.
    - Uses the same sed pattern format with /ansible.legacy.command Invoked/D filter.
    """
    username = tacacs_creds["tacacs_rw_user"]
    # Mirror check_local_log_exist's pattern: filter Ansible noise, match accounting record.
    # command_fragment must appear somewhere in the command field (no trailing comma required,
    # since some commands have extra args after the secret, e.g. 'add SECRET RO').
    log_pattern = (
        "/ansible.legacy.command Invoked/D;"
        "/INFO audisp-tacplus.+Accounting: user: {0},.*, command: .*{1}/P"
        .format(username, command_fragment)
    )

    logs = []
    while retry > 0:
        retry -= 1
        # Re-enable local accounting (same as check_local_log_exist's loop body).
        change_and_wait_aaa_config_update(duthost, "sudo config aaa accounting local")
        cleanup_tacacs_log(ptfhost, rw_user_client)

        # Run the command under test as the TACACS user.
        ssh_run_command(rw_user_client, ssh_command)

        logs = _wait_for_log(duthost, log_pattern)

        if not logs:
            recent = duthost.shell("sudo tail -n 100 /var/log/syslog",
                                   module_ignore_errors=True).get("stdout", "")
            audisp_lines = [line for line in recent.splitlines() if "audisp" in line or "Accounting" in line]
            logger.warning(
                "%s: no accounting record found (retry remaining=%d). "
                "pattern=%r. recent audisp lines: %s",
                description, retry, log_pattern, audisp_lines
            )
        else:
            logger.info("%s: found %d accounting record(s): %s", description, len(logs), logs)
            break

    pytest_assert(logs, "{}: no audisp-tacplus accounting record found for '{}' after {} attempts".format(
        description, command_fragment, _RETRY_COUNT))

    leaked = [r for r in logs if secret in r]
    pytest_assert(
        len(leaked) == 0,
        "{}: plaintext secret '{}' found in {} accounting record(s): {}".format(
            description, secret, len(leaked), leaked
        ),
    )

    masked = [r for r in logs if "*" in r]
    pytest_assert(
        len(masked) > 0,
        "{}: no masked ('*') form found — masking may be silently dropping the secret: {}".format(
            description, logs
        ),
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def check_image_version(duthost):
    skip_release(duthost, per_command_accounting_skip_versions)


@pytest.fixture(scope="module", autouse=True)
def require_passwd_cmds(duthost):
    """Skip all tests if audisp-tacplus PASSWD_CMDS masking is not configured on this DUT.

    Reads /etc/sudoers and verifies that at least one PASSWD_CMDS entry referencing
    'config tacacs passkey' is present. If not found, skip rather than fail.
    """
    result = duthost.shell(
        "sudo grep -c 'config tacacs passkey' /etc/sudoers",
        module_ignore_errors=True
    )
    count = 0
    try:
        count = int(result.get("stdout", "0").strip())
    except ValueError:
        pass
    if count == 0:
        pytest.skip(
            "audisp-tacplus PASSWD_CMDS masking not configured in /etc/sudoers — "
            "'config tacacs passkey' not found. Skipping secret masking tests."
        )


@pytest.fixture
def rw_user_client(duthosts, enum_rand_one_per_hwsku_hostname, tacacs_creds):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dutip = duthost.mgmt_ip
    client = ssh_connect_remote_retry(
        dutip,
        tacacs_creds["tacacs_rw_user"],
        tacacs_creds["tacacs_rw_user_passwd"],
        duthost,
    )
    yield client
    client.close()


@pytest.fixture(autouse=True)
def disable_accounting_after_test(duthosts, enum_rand_one_per_hwsku_hostname):
    """Restore default (disabled) accounting after each test."""
    yield
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    duthost.shell("sudo config aaa accounting default", module_ignore_errors=True)


# ---------------------------------------------------------------------------
# Tests — TACACS passkey
# ---------------------------------------------------------------------------

def test_tacacs_passkey_secret_masked(
    duthosts,
    enum_rand_one_per_hwsku_hostname,
    tacacs_creds,
    ptfhost,
    check_tacacs,  # noqa: F811
    rw_user_client,
):
    """'config tacacs passkey SECRET' must not leak SECRET in syslog accounting."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    _assert_secret_masked(
        duthost, ptfhost, tacacs_creds, rw_user_client,
        ssh_command="sudo config tacacs passkey {0}".format(_TACACS_SECRET),
        command_fragment="config tacacs passkey",
        secret=_TACACS_SECRET,
        description="tacacs passkey",
    )

    # Restore original passkey so subsequent tests are not broken.
    original_passkey = tacacs_creds.get(duthost.hostname, {}).get("tacacs_passkey", "")
    if original_passkey:
        duthost.shell("sudo config tacacs passkey {0}".format(original_passkey),
                      module_ignore_errors=True)


# ---------------------------------------------------------------------------
# Tests — RADIUS passkey
# ---------------------------------------------------------------------------

def test_radius_passkey_secret_masked(
    duthosts,
    enum_rand_one_per_hwsku_hostname,
    tacacs_creds,
    ptfhost,
    check_tacacs,  # noqa: F811
    rw_user_client,
):
    """'config radius passkey SECRET' must not leak SECRET in syslog accounting."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    _assert_secret_masked(
        duthost, ptfhost, tacacs_creds, rw_user_client,
        ssh_command="sudo config radius passkey {0}".format(_RADIUS_SECRET),
        command_fragment="config radius passkey",
        secret=_RADIUS_SECRET,
        description="radius passkey",
    )

    duthost.shell("sudo config radius default passkey", module_ignore_errors=True)


# ---------------------------------------------------------------------------
# Tests — SNMP community add
# ---------------------------------------------------------------------------

def test_snmp_community_add_secret_masked(
    duthosts,
    enum_rand_one_per_hwsku_hostname,
    tacacs_creds,
    ptfhost,
    check_tacacs,  # noqa: F811
    rw_user_client,
):
    """'config snmp community add SECRET RO' must not leak SECRET in syslog accounting."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    _assert_secret_masked(
        duthost, ptfhost, tacacs_creds, rw_user_client,
        ssh_command="sudo config snmp community add {0} RO".format(_SNMP_SECRET_ADD),
        command_fragment="config snmp community add",
        secret=_SNMP_SECRET_ADD,
        description="snmp community add",
    )

    duthost.shell("sudo config snmp community del {0}".format(_SNMP_SECRET_ADD),
                  module_ignore_errors=True)


# ---------------------------------------------------------------------------
# Tests — SNMP community del
# ---------------------------------------------------------------------------

def test_snmp_community_del_secret_masked(
    duthosts,
    enum_rand_one_per_hwsku_hostname,
    tacacs_creds,
    ptfhost,
    check_tacacs,  # noqa: F811
    rw_user_client,
):
    """'config snmp community del SECRET' must not leak SECRET in syslog accounting."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    duthost.shell("sudo config snmp community add {0} RO".format(_SNMP_SECRET_DEL),
                  module_ignore_errors=True)

    _assert_secret_masked(
        duthost, ptfhost, tacacs_creds, rw_user_client,
        ssh_command="sudo config snmp community del {0}".format(_SNMP_SECRET_DEL),
        command_fragment="config snmp community del",
        secret=_SNMP_SECRET_DEL,
        description="snmp community del",
    )


# ---------------------------------------------------------------------------
# Tests — SNMP community replace (two-secret case)
# ---------------------------------------------------------------------------

@pytest.mark.xfail(
    reason="Multi-wildcard PASSWD_CMDS masking ('replace * *') requires sonic-buildimage#29088 "
           "(merged 2026-08-27). Marked xfail until confirmed in VS image; will xpass once present.",
    strict=False,
)
def test_snmp_community_replace_both_secrets_masked(
    duthosts,
    enum_rand_one_per_hwsku_hostname,
    tacacs_creds,
    ptfhost,
    check_tacacs,  # noqa: F811
    rw_user_client,
):
    """
    'config snmp community replace OLD NEW' must not leak EITHER secret in syslog accounting.
    Exercises the multi-wildcard PASSWD_CMDS pattern 'replace * *'.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    username = tacacs_creds["tacacs_rw_user"]

    duthost.shell("sudo config snmp community add {0} RO".format(_SNMP_SECRET_REPLACE_OLD),
                  module_ignore_errors=True)

    log_pattern = (
        "/ansible.legacy.command Invoked/D;"
        "/INFO audisp-tacplus.+Accounting: user: {0},.*, command: .*config snmp community replace/P"
        .format(username)
    )

    logs = []
    retry = _RETRY_COUNT
    while retry > 0:
        retry -= 1
        change_and_wait_aaa_config_update(duthost, "sudo config aaa accounting local")
        cleanup_tacacs_log(ptfhost, rw_user_client)

        ssh_run_command(
            rw_user_client,
            "sudo config snmp community replace {0} {1}".format(
                _SNMP_SECRET_REPLACE_OLD, _SNMP_SECRET_REPLACE_NEW
            ),
        )

        logs = _wait_for_log(duthost, log_pattern)
        if logs:
            break

    pytest_assert(logs, "snmp community replace: no accounting record found after {} attempts".format(_RETRY_COUNT))

    logger.info("snmp community replace: found %d accounting record(s): %s", len(logs), logs)

    leaked_old = [r for r in logs if _SNMP_SECRET_REPLACE_OLD in r]
    leaked_new = [r for r in logs if _SNMP_SECRET_REPLACE_NEW in r]
    pytest_assert(len(leaked_old) == 0,
                  "snmp community replace: plaintext OLD secret leaked: {}".format(leaked_old))
    pytest_assert(len(leaked_new) == 0,
                  "snmp community replace: plaintext NEW secret leaked: {}".format(leaked_new))

    masked = [r for r in logs if re.search(r"\*{3,}", r)]
    pytest_assert(len(masked) > 0,
                  "snmp community replace: no masked ('***+') form found: {}".format(logs))

    duthost.shell("sudo config snmp community del {0}".format(_SNMP_SECRET_REPLACE_NEW),
                  module_ignore_errors=True)
