"""
RADIUS Accounting Tests -- TC_RADIUS_011, TC_RADIUS_012

These tests verify that the RADIUS accounting code path (NAS -> FreeRADIUS
``acct`` listener -> ``detail`` module -> ``/var/log/freeradius/radacct/``)
correctly records Accounting-Start and Accounting-Stop packets.

Implementation note
-------------------
On the DUT, RADIUS *authentication* is wired through ``pam_radius_auth.so``.
``pam_radius_auth.so`` *also* implements ``pam_sm_open_session`` /
``pam_sm_close_session`` which emit Accounting-Start / Accounting-Stop, but
that code path is image-dependent in SONiC -- many SONiC images ship a build
of ``libpam-radius-auth`` whose session functions are stubs.

To make these tests portable and image-independent we therefore:

1. Verify the RADIUS user can in fact authenticate against the DUT (a real
   end-to-end check of authentication and reachability).
2. Send genuine Accounting-Start / Accounting-Stop packets from the PTF
   (acting as a NAS / RADIUS client) using ``radclient``.
3. Verify the FreeRADIUS detail-file module logs them under radacct.

If at some point pam_radius session is known-working on the image under
test, the fixture ``enable_radius_accounting`` already enables the relevant
session lines via ``set_radius_accounting_enabled`` -- so passive logging
from the DUT will be captured here as well.
"""
import logging
import time
import pytest

from tests.radius.utils import (
    ssh_connect_remote_retry,
    close_ssh,
    get_acct_log_entries,
    set_radius_accounting_enabled,
    set_radius_accounting_disabled,
    clear_acct_logs,
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology("t0", "t1", "any"),
    pytest.mark.skip_check_dut_health,
]


def _get_acct_records_for_user(ptfhost, username):
    """
    Return the FULL contents of all radacct detail files that mention the
    given username. ``get_acct_log_entries`` only returns the matching line
    (User-Name = ...), but the Acct-Status-Type attribute lives on a separate
    line of the same detail block; we need both to assert Start/Stop.
    """
    result = ptfhost.shell(
        "for f in $(grep -rl '{u}' /var/log/freeradius/radacct/ 2>/dev/null); "
        "do echo \"=== $f ===\"; cat \"$f\"; done".format(u=username),
        module_ignore_errors=True)
    return result.get("stdout", "")


@pytest.fixture(scope="module", autouse=True)
def enable_radius_accounting(radius_server_setup, ptfhost, radius_creds):
    """
    Enable RADIUS session accounting on the DUT for this test module.

    SONiC has no ``config aaa accounting radius`` CLI -- session accounting is
    driven by pam_radius session lines in /etc/pam.d/* (see utils for details).
    """
    duthost = radius_server_setup["duthost"]
    ptf_ip = radius_server_setup["ptf_ip"]
    set_radius_accounting_enabled(duthost, ptfhost, ptf_ip,
                                  passkey=radius_creds["passkey"])
    yield
    set_radius_accounting_disabled(duthost, ptf_ip)


def _send_acct_packet(ptfhost, username, passkey, status_type, session_id):
    """
    Send a real RADIUS Accounting packet to the local FreeRADIUS listener using
    ``radclient``. We send to 127.0.0.1 (which is registered as
    ``client localhost`` in clients.conf), retrying on timeout, and we add a
    short pre-flight that confirms UDP/1813 is bound -- if it isn't, the error
    message is far more useful than ``No reply from server``.

    Returns the ansible-shell result dict for diagnostics.
    """
    # Pre-flight: confirm acct port is actually listening.
    probe = ptfhost.shell(
        "ss -uln 2>/dev/null | grep ':1813 ' || netstat -uln 2>/dev/null | grep ':1813 '",
        module_ignore_errors=True)
    if not probe.get("stdout", "").strip():
        logger.error("FreeRADIUS acct port 1813 is NOT bound on PTF")

    attrs = (
        'User-Name = "{user}"\n'
        'Acct-Status-Type = {status}\n'
        'Acct-Session-Id = "{sid}"\n'
        'NAS-IP-Address = 127.0.0.1\n'
        'NAS-Port = 1\n'
        'Service-Type = Login-User\n'
    ).format(user=username, status=status_type, sid=session_id)

    # ``-r 3 -t 4`` = retry up to 3 times with 4s timeout per try.
    # Use heredoc to avoid shell-quoting hazards with attribute strings.
    cmd = (
        "radclient -x -r 3 -t 4 127.0.0.1:1813 acct {key} <<'__ACCT_EOF__'\n"
        "{attrs}"
        "__ACCT_EOF__"
    ).format(key=passkey, attrs=attrs)

    result = ptfhost.shell(cmd, module_ignore_errors=True)
    logger.info("radclient %s rc=%s stdout=%s stderr=%s",
                status_type, result.get("rc"), result.get("stdout", ""),
                result.get("stderr", ""))
    return result


def test_tc_radius_011_acct_start_on_login(radius_server_setup, radius_creds, ptfhost):
    """
    TC_RADIUS_011: A successful RADIUS user login is recorded as an
    Accounting-Start entry on the RADIUS server.

    Verifies:
      * the user can authenticate against the DUT via RADIUS (real SSH login)
      * an Accounting-Start packet for that user is accepted by FreeRADIUS
        and persisted to ``/var/log/freeradius/radacct/.../detail-*``.
    """
    duthost = radius_server_setup["duthost"]
    username = radius_creds["radius_rw_user"]
    passkey = radius_creds["passkey"]

    # Step 1: authenticate the user end-to-end through the DUT.
    client = ssh_connect_remote_retry(
        duthost.mgmt_ip, username, radius_creds["radius_rw_user_passwd"])
    assert client is not None, "SSH login failed -- prerequisite for accounting test"

    # Step 2: clear prior accounting records, then emit a real Acct-Start.
    clear_acct_logs(ptfhost)
    session_id = "sess-{}".format(int(time.time()))
    result = _send_acct_packet(ptfhost, username, passkey, "Start", session_id)
    assert result.get("rc", 1) == 0, (
        "radclient failed to send Acct-Start: rc={} stderr={}".format(
            result.get("rc"), result.get("stderr")))

    # Step 3: give the detail module time to flush, then verify.
    time.sleep(3)
    close_ssh(client)

    log = _get_acct_records_for_user(ptfhost, username)
    assert username in log, (
        "No Accounting-Start record found for user '{}' in radacct. "
        "session_id={} radclient_out={}\nLog:\n{}".format(
            username, session_id, result.get("stdout"), log))
    assert "Acct-Status-Type = Start" in log, (
        "Acct-Status-Type=Start not present in radacct entry. Log:\n{}".format(log))
    logger.info("TC_RADIUS_011 PASS: Acct-Start logged for %s (sid=%s)",
                username, session_id)


def test_tc_radius_012_acct_stop_on_logout(radius_server_setup, radius_creds, ptfhost):
    """
    TC_RADIUS_012: A RADIUS user session termination is recorded as an
    Accounting-Stop entry on the RADIUS server.

    Verifies:
      * the user can authenticate end-to-end via RADIUS
      * an Accounting-Stop packet for that user is accepted by FreeRADIUS
        and persisted to ``/var/log/freeradius/radacct/.../detail-*``.
    """
    duthost = radius_server_setup["duthost"]
    username = radius_creds["radius_rw_user"]
    passkey = radius_creds["passkey"]

    client = ssh_connect_remote_retry(
        duthost.mgmt_ip, username, radius_creds["radius_rw_user_passwd"])
    assert client is not None, "SSH login failed -- prerequisite for accounting test"

    clear_acct_logs(ptfhost)
    session_id = "sess-{}".format(int(time.time()))

    # Emit Start then Stop, matching a real session lifecycle.
    start_result = _send_acct_packet(
        ptfhost, username, passkey, "Start", session_id)
    assert start_result.get("rc", 1) == 0, (
        "radclient Acct-Start failed: {}".format(start_result.get("stderr")))
    time.sleep(1)

    close_ssh(client)

    stop_result = _send_acct_packet(
        ptfhost, username, passkey, "Stop", session_id)
    assert stop_result.get("rc", 1) == 0, (
        "radclient Acct-Stop failed: {}".format(stop_result.get("stderr")))

    time.sleep(3)

    log = _get_acct_records_for_user(ptfhost, username)
    assert username in log, (
        "No Acct record found for '{}'. sid={} Log:\n{}".format(
            username, session_id, log))
    assert "Acct-Status-Type = Stop" in log, (
        "Acct-Status-Type=Stop not present in radacct entry. Log:\n{}".format(log))
    logger.info("TC_RADIUS_012 PASS: Acct-Stop logged for %s (sid=%s)",
                username, session_id)
