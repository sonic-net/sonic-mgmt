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

Test topology: vs (virtual switch), any
Requires: TACACS+ server on ptfhost, tacacs_creds fixture, check_tacacs fixture.
"""

import logging
import re
import time
import pytest

from tests.common.helpers.tacacs.tacacs_helper import (
    per_command_accounting_skip_versions,
    check_tacacs,  # noqa: F401
)
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import skip_release
from .utils import (
    change_and_wait_aaa_config_update,
    get_auditd_config_reload_timestamp,
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

# Wait up to 60 seconds for syslog to contain the accounting record.
_SYSLOG_WAIT_TIMEOUT = 60
_SYSLOG_CHECK_INTERVAL = 2


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _flush_syslog(duthost):
    """Force rsyslogd to flush buffered writes."""
    duthost.shell("kill -HUP $(cat /var/run/rsyslogd.pid) 2>/dev/null || true")
    duthost.shell("sync /var/log/syslog 2>/dev/null || true")


def _get_recent_syslog(duthost, lines=500):
    """Return the last N lines of syslog as a single string."""
    result = duthost.shell("tail -n {0} /var/log/syslog".format(lines))
    return "\n".join(result["stdout_lines"])


def _wait_for_accounting_record(duthost, username, command_fragment, timeout=_SYSLOG_WAIT_TIMEOUT):
    """
    Poll syslog until an audisp-tacplus accounting record for `username`
    containing `command_fragment` appears, or timeout expires.

    Returns the matching lines (list of str), or empty list on timeout.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        _flush_syslog(duthost)
        log = _get_recent_syslog(duthost)
        matches = [
            line for line in log.splitlines()
            if "audisp-tacplus" in line
            and "Accounting" in line
            and username in line
            and command_fragment in line
        ]
        if matches:
            return matches
        time.sleep(_SYSLOG_CHECK_INTERVAL)
    return []


def _assert_secret_masked(duthost, username, command_fragment, secret, description):
    """
    Assert:
      - An accounting record for `username` / `command_fragment` exists in syslog.
      - None of those records contain the plaintext `secret`.

    `description` is used in assertion messages.
    """
    records = _wait_for_accounting_record(duthost, username, command_fragment)

    pytest_assert(
        len(records) > 0,
        "{}: no audisp-tacplus accounting record found for command fragment '{}' "
        "in syslog within {}s".format(description, command_fragment, _SYSLOG_WAIT_TIMEOUT),
    )

    logger.info("%s: found %d accounting record(s): %s", description, len(records), records)

    leaked = [r for r in records if secret in r]
    pytest_assert(
        len(leaked) == 0,
        "{}: plaintext secret '{}' found in {} accounting record(s): {}".format(
            description, secret, len(leaked), leaked
        ),
    )

    masked = [r for r in records if "*" in r]
    pytest_assert(
        len(masked) > 0,
        "{}: no masked ('*') form found in accounting records — "
        "masking may be silently dropping the secret rather than replacing it: {}".format(
            description, records
        ),
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def check_image_version(duthost):
    skip_release(duthost, per_command_accounting_skip_versions)


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
def enable_local_accounting(duthosts, enum_rand_one_per_hwsku_hostname, ptfhost, rw_user_client):
    """Enable local accounting so syslog receives audisp-tacplus records."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    change_and_wait_aaa_config_update(duthost, "sudo config aaa accounting local")
    cleanup_tacacs_log(ptfhost, rw_user_client)
    yield
    # Restore default (no accounting)
    duthost.shell("sudo config aaa accounting default", module_ignore_errors=True)


# ---------------------------------------------------------------------------
# Tests — TACACS passkey
# ---------------------------------------------------------------------------

def test_tacacs_passkey_secret_masked(
    duthosts,
    enum_rand_one_per_hwsku_hostname,
    tacacs_creds,
    check_tacacs,  # noqa: F811
    rw_user_client,
):
    """
    'config tacacs passkey SECRET' must not leak SECRET in syslog accounting.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    username = tacacs_creds["tacacs_rw_user"]

    # Run the command; ignore exit code (passkey may or may not be accepted by server)
    ssh_run_command(rw_user_client, "sudo config tacacs passkey {0}".format(_TACACS_SECRET))

    _assert_secret_masked(
        duthost, username, "config tacacs passkey", _TACACS_SECRET,
        "tacacs passkey"
    )

    # Cleanup — restore original passkey
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
    check_tacacs,  # noqa: F811
    rw_user_client,
):
    """
    'config radius passkey SECRET' must not leak SECRET in syslog accounting.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    username = tacacs_creds["tacacs_rw_user"]

    ssh_run_command(rw_user_client, "sudo config radius passkey {0}".format(_RADIUS_SECRET))

    _assert_secret_masked(
        duthost, username, "config radius passkey", _RADIUS_SECRET,
        "radius passkey"
    )

    # Cleanup
    duthost.shell("sudo config radius default passkey", module_ignore_errors=True)


# ---------------------------------------------------------------------------
# Tests — SNMP community add
# ---------------------------------------------------------------------------

def test_snmp_community_add_secret_masked(
    duthosts,
    enum_rand_one_per_hwsku_hostname,
    tacacs_creds,
    check_tacacs,  # noqa: F811
    rw_user_client,
):
    """
    'config snmp community add SECRET RO' must not leak SECRET in syslog accounting.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    username = tacacs_creds["tacacs_rw_user"]

    ssh_run_command(
        rw_user_client,
        "sudo config snmp community add {0} RO".format(_SNMP_SECRET_ADD),
    )

    _assert_secret_masked(
        duthost, username, "config snmp community add", _SNMP_SECRET_ADD,
        "snmp community add"
    )

    # Cleanup
    duthost.shell(
        "sudo config snmp community del {0}".format(_SNMP_SECRET_ADD),
        module_ignore_errors=True,
    )


# ---------------------------------------------------------------------------
# Tests — SNMP community del
# ---------------------------------------------------------------------------

def test_snmp_community_del_secret_masked(
    duthosts,
    enum_rand_one_per_hwsku_hostname,
    tacacs_creds,
    check_tacacs,  # noqa: F811
    rw_user_client,
):
    """
    'config snmp community del SECRET' must not leak SECRET in syslog accounting.

    Note: 'del' takes the community string as identifier (not truly a secret in the
    same sense), but it appears in PASSWD_CMDS and is masked by audisp-tacplus.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    username = tacacs_creds["tacacs_rw_user"]

    # Pre-create so del succeeds
    duthost.shell(
        "sudo config snmp community add {0} RO".format(_SNMP_SECRET_DEL),
        module_ignore_errors=True,
    )

    ssh_run_command(
        rw_user_client,
        "sudo config snmp community del {0}".format(_SNMP_SECRET_DEL),
    )

    _assert_secret_masked(
        duthost, username, "config snmp community del", _SNMP_SECRET_DEL,
        "snmp community del"
    )


# ---------------------------------------------------------------------------
# Tests — SNMP community replace (two-secret case)
# ---------------------------------------------------------------------------

def test_snmp_community_replace_both_secrets_masked(
    duthosts,
    enum_rand_one_per_hwsku_hostname,
    tacacs_creds,
    check_tacacs,  # noqa: F811
    rw_user_client,
):
    """
    'config snmp community replace OLD NEW' must not leak EITHER secret in
    syslog accounting.

    This exercises the multi-wildcard PASSWD_CMDS pattern 'replace * *' and
    the audisp-tacplus fix that iterates over all capture groups.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    username = tacacs_creds["tacacs_rw_user"]

    # Pre-create old community
    duthost.shell(
        "sudo config snmp community add {0} RO".format(_SNMP_SECRET_REPLACE_OLD),
        module_ignore_errors=True,
    )

    ssh_run_command(
        rw_user_client,
        "sudo config snmp community replace {0} {1}".format(
            _SNMP_SECRET_REPLACE_OLD, _SNMP_SECRET_REPLACE_NEW
        ),
    )

    # Both OLD and NEW must be absent from accounting records
    records = _wait_for_accounting_record(duthost, username, "config snmp community replace")

    pytest_assert(
        len(records) > 0,
        "snmp community replace: no audisp-tacplus accounting record found in syslog "
        "within {}s".format(_SYSLOG_WAIT_TIMEOUT),
    )

    logger.info("snmp community replace: found %d accounting record(s): %s", len(records), records)

    leaked_old = [r for r in records if _SNMP_SECRET_REPLACE_OLD in r]
    leaked_new = [r for r in records if _SNMP_SECRET_REPLACE_NEW in r]

    pytest_assert(
        len(leaked_old) == 0,
        "snmp community replace: plaintext OLD secret '{}' leaked in record(s): {}".format(
            _SNMP_SECRET_REPLACE_OLD, leaked_old
        ),
    )
    pytest_assert(
        len(leaked_new) == 0,
        "snmp community replace: plaintext NEW secret '{}' leaked in record(s): {}".format(
            _SNMP_SECRET_REPLACE_NEW, leaked_new
        ),
    )

    # Confirm masking is present (not just silently dropped)
    masked = [r for r in records if re.search(r"\*{3,}", r)]
    pytest_assert(
        len(masked) > 0,
        "snmp community replace: no masked ('***+') form found — "
        "secret may be silently dropped rather than masked: {}".format(records),
    )

    # Cleanup
    duthost.shell(
        "sudo config snmp community del {0}".format(_SNMP_SECRET_REPLACE_NEW),
        module_ignore_errors=True,
    )
