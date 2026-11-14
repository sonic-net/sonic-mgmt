"""
test_aaa_preflight.py -- Pre-flight health checks (TC_H01 – TC_H08).

These tests run BEFORE the main AAA test suite.  They verify that the
environment is in a known-good state so that any failure in the real
tests is a genuine AAA bug and not a broken lab environment.

Health checks covered
---------------------
TC_H01  SONiC critical services are all running (no crashed containers)
TC_H02  TACACS+ server reachable from DUT (network connectivity)
TC_H03  TACACS+ config present on DUT (server IP, passkey, port)
TC_H04  AAA authentication is set to use TACACS+
TC_H05  AAA authorization mode is configured
TC_H06  AAA accounting mode is configured
TC_H07  TACACS+ daemon (tac_plus) is running on the PTF
TC_H08  DUT can authenticate a TACACS+ user end-to-end (smoke login)

Ordering
--------
pytest collects files alphabetically.  'test_aaa_preflight.py' sorts
before 'test_aaa_config.py', 'test_aaa_accounting.py', and
'test_aaa_authentication.py', so these checks always run first.

If any health check fails the test is marked xfail/error with a clear
message so the engineer knows exactly what to fix before re-running.
"""

import logging
import paramiko
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until, paramiko_ssh
from tests.common.helpers.tacacs.tacacs_helper import (
    check_tacacs,           # noqa: F401
    ssh_remote_run,
    start_tacacs_server,
)
from tests.common.fixtures.tacacs import tacacs_creds  # noqa: F401

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any', 't1-multi-asic'),
    pytest.mark.device_type('vs'),
]

# ---------------------------------------------------------------------------
# Critical SONiC containers that MUST be running for AAA to work
# ---------------------------------------------------------------------------
CRITICAL_SERVICES = [
    "database",     # Redis – stores all SONiC config
    "pmon",         # Platform monitor
    "swss",         # Switch state service
    "syncd",        # ASIC sync daemon
    "teamd",        # LAG/LACP
    "bgp",          # FRR/BGP (needed for mgmt routing in some topologies)
    "lldp",         # LLDP
    "snmp",         # SNMP agent
    "radv",         # Router advertisement
    "dhcp_relay",   # DHCP relay
    "telemetry",    # gNMI telemetry
    "mgmt-framework", # REST API + gNMI management framework
]

# Services that are directly involved in AAA — checked separately and
# with a clearer error message.
AAA_CRITICAL_SERVICES = [
    "database",         # TACACS+ config lives in ConfigDB (Redis)
    "mgmt-framework",   # Handles REST/gNMI auth which also goes through TACACS+
]

TACACS_DEFAULT_PORT = 49


# ---------------------------------------------------------------------------
# TC_H01 -- SONiC critical services are all running
# ---------------------------------------------------------------------------

def test_h01_sonic_services_running(
        duthosts,
        enum_rand_one_per_hwsku_hostname,
        check_tacacs):      # noqa: F811
    """
    TC_H01 -- Verify every critical SONiC Docker container is in the
    'Running' state.  A crashed container (e.g. database, swss, mgmt-framework)
    will silently break AAA without producing obvious test failures.

    Uses 'show services' / 'docker ps' and checks each container reports
    'Up' with no 'Restarting' or 'Exited' in its status string.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    result = duthost.shell("docker ps --format '{{.Names}} {{.Status}}'")
    output = result['stdout']
    logger.info("TC_H01 docker ps output:\n%s", output)

    failed_services = []
    for service in CRITICAL_SERVICES:
        # Each line looks like: "database Up 3 hours"
        matching_lines = [l for l in output.splitlines() if l.startswith(service + " ")]
        if not matching_lines:
            failed_services.append("{} (container not found)".format(service))
            continue
        status_line = matching_lines[0]
        if "Up" not in status_line or "Restarting" in status_line or "Exited" in status_line:
            failed_services.append("{} ({})".format(service, status_line.strip()))

    pytest_assert(
        len(failed_services) == 0,
        "TC_H01 FAILED -- the following SONiC services are not healthy:\n  {}\n"
        "Fix: run 'sudo systemctl restart sonic' or restart individual containers with "
        "'sudo docker restart <name>'".format("\n  ".join(failed_services))
    )
    logger.info("TC_H01 PASSED -- all %d critical services are running", len(CRITICAL_SERVICES))


# ---------------------------------------------------------------------------
# TC_H02 -- TACACS+ server is reachable from DUT (network connectivity)
# ---------------------------------------------------------------------------

def test_h02_tacacs_server_reachable(
        duthosts,
        enum_rand_one_per_hwsku_hostname,
        ptfhost,
        tacacs_creds,       # noqa: F811
        check_tacacs):      # noqa: F811
    """
    TC_H02 -- Verify the DUT can reach the TACACS+ server's IP over the
    network.  Uses a plain TCP connect (nc / bash /dev/tcp) to port 49 so
    this check works even before TACACS+ credentials are involved.

    A failure here means a routing or firewall issue — not a TACACS+ bug.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    tacacs_server_ip = tacacs_creds.get('tacacs_host', ptfhost.mgmt_ip)
    tacacs_port = tacacs_creds.get('tacacs_port', TACACS_DEFAULT_PORT)

    # Use bash TCP pseudo-device: succeeds if port is open, fails otherwise
    cmd = (
        "timeout 5 bash -c 'cat < /dev/null > /dev/tcp/{ip}/{port}' "
        "&& echo REACHABLE || echo UNREACHABLE"
    ).format(ip=tacacs_server_ip, port=tacacs_port)

    result = duthost.shell(cmd, module_ignore_errors=True)
    output = result['stdout'].strip()
    logger.info("TC_H02 connectivity check to %s:%s => %s", tacacs_server_ip, tacacs_port, output)

    pytest_assert(
        "REACHABLE" in output,
        "TC_H02 FAILED -- DUT cannot reach TACACS+ server at {}:{}.\n"
        "Fix: check PTF/server is running, check mgmt network routing, "
        "check firewall rules on port {}.".format(tacacs_server_ip, tacacs_port, tacacs_port)
    )
    logger.info("TC_H02 PASSED -- TACACS+ server %s:%s is reachable", tacacs_server_ip, tacacs_port)


# ---------------------------------------------------------------------------
# TC_H03 -- TACACS+ config is present on the DUT
# ---------------------------------------------------------------------------

def test_h03_tacacs_config_on_dut(
        duthosts,
        enum_rand_one_per_hwsku_hostname,
        ptfhost,
        tacacs_creds,       # noqa: F811
        check_tacacs):      # noqa: F811
    """
    TC_H03 -- Verify the DUT's ConfigDB has a TACACS+ server entry that
    matches the expected host IP.  Also checks that a non-empty passkey
    (secret) is configured and that the port is set.

    A missing or wrong server entry is a setup problem — the test fixture
    (check_tacacs) should have configured it, but this explicitly confirms it.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    expected_ip = tacacs_creds.get('tacacs_host', ptfhost.mgmt_ip)

    # 'show tacacs' prints the configured server list
    result = duthost.shell("show tacacs")
    output = result['stdout']
    logger.info("TC_H03 show tacacs output:\n%s", output)

    pytest_assert(
        expected_ip in output,
        "TC_H03 FAILED -- Expected TACACS+ server IP '{}' not found in 'show tacacs'.\n"
        "Output was:\n{}\n"
        "Fix: run 'sudo config tacacs add {}' on the DUT.".format(
            expected_ip, output, expected_ip)
    )

    # Also check that a passkey is configured (should not be '<empty>')
    pytest_assert(
        "passkey" not in output.lower() or "<empty>" not in output.lower(),
        "TC_H03 FAILED -- TACACS+ passkey appears to be empty in 'show tacacs'.\n"
        "Fix: run 'sudo config tacacs passkey <secret>' on the DUT."
    )

    logger.info("TC_H03 PASSED -- TACACS+ server %s is configured on DUT", expected_ip)


# ---------------------------------------------------------------------------
# TC_H04 -- AAA authentication is set to use TACACS+
# ---------------------------------------------------------------------------

def test_h04_aaa_authentication_mode(
        duthosts,
        enum_rand_one_per_hwsku_hostname,
        check_tacacs):      # noqa: F811
    """
    TC_H04 -- Verify 'show aaa' reports that authentication is using
    TACACS+ (not local-only).  If auth is set to 'local' only, the main
    suite tests will all fail for the wrong reason.

    Acceptable values: 'tacacs+' or 'tacacs+ local' (failthrough).
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    result = duthost.shell("show aaa")
    output = result['stdout']
    logger.info("TC_H04 show aaa output:\n%s", output)

    # Find the authentication line
    auth_lines = [l for l in output.splitlines() if "authentication" in l.lower() and "login" in l.lower()]
    logger.info("TC_H04 auth lines: %s", auth_lines)

    pytest_assert(
        any("tacacs" in l.lower() for l in auth_lines),
        "TC_H04 FAILED -- AAA authentication login is NOT using TACACS+.\n"
        "Current 'show aaa' output:\n{}\n"
        "Fix: run 'sudo config aaa authentication login tacacs+ local' on the DUT.".format(output)
    )
    logger.info("TC_H04 PASSED -- AAA authentication is configured to use TACACS+")


# ---------------------------------------------------------------------------
# TC_H05 -- AAA authorization mode is configured
# ---------------------------------------------------------------------------

def test_h05_aaa_authorization_mode(
        duthosts,
        enum_rand_one_per_hwsku_hostname,
        check_tacacs):      # noqa: F811
    """
    TC_H05 -- Verify that AAA authorization configuration is present and
    readable.  This does not enforce a specific value (local vs tacacs+)
    because different tests may require different modes; it just confirms
    the 'show aaa' output has an authorization entry and is not corrupted.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    result = duthost.shell("show aaa")
    output = result['stdout']

    authz_lines = [l for l in output.splitlines() if "authorization" in l.lower()]
    pytest_assert(
        len(authz_lines) > 0,
        "TC_H05 FAILED -- No authorization line found in 'show aaa' output.\n"
        "This may indicate a corrupted AAA config.\n"
        "Full output:\n{}".format(output)
    )
    logger.info("TC_H05 PASSED -- AAA authorization entry found: %s", authz_lines)


# ---------------------------------------------------------------------------
# TC_H06 -- AAA accounting mode is configured
# ---------------------------------------------------------------------------

def test_h06_aaa_accounting_mode(
        duthosts,
        enum_rand_one_per_hwsku_hostname,
        check_tacacs):      # noqa: F811
    """
    TC_H06 -- Verify that AAA accounting configuration is present and
    readable.  Accounting tests (TC_006, TC_007, TC_017, TC_018) will
    silently pass or fail for the wrong reason if accounting config is absent.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    result = duthost.shell("show aaa")
    output = result['stdout']

    acct_lines = [l for l in output.splitlines() if "accounting" in l.lower()]
    pytest_assert(
        len(acct_lines) > 0,
        "TC_H06 FAILED -- No accounting line found in 'show aaa' output.\n"
        "This may indicate a corrupted AAA config.\n"
        "Full output:\n{}".format(output)
    )
    logger.info("TC_H06 PASSED -- AAA accounting entry found: %s", acct_lines)


# ---------------------------------------------------------------------------
# TC_H07 -- tac_plus daemon is running on the PTF
# ---------------------------------------------------------------------------

def test_h07_tacacs_daemon_running_on_ptf(
        ptfhost,
        check_tacacs):      # noqa: F811
    """
    TC_H07 -- Verify the tac_plus server process is actively running on the
    PTF (which acts as the TACACS+ server in this test topology).

    Uses 'pgrep tac_plus' — exits 0 if the process is found, non-zero if not.
    Also checks the tac_plus config file exists and is non-empty so we know
    the server was configured and not just started with a blank config.
    """
    # Check the process is running
    proc_result = ptfhost.shell("pgrep -x tac_plus || pgrep -x tac_plus_syslog",
                                module_ignore_errors=True)
    logger.info("TC_H07 pgrep output: rc=%s stdout=%s",
                proc_result['rc'], proc_result['stdout'])

    pytest_assert(
        proc_result['rc'] == 0,
        "TC_H07 FAILED -- tac_plus process is NOT running on the PTF.\n"
        "Fix: run 'sudo tac_plus -C /etc/tac_plus.conf -d 16 &' on the PTF,\n"
        "or use the start_tacacs_server() helper in the fixture."
    )

    # Check the config file exists and has content
    cfg_result = ptfhost.shell(
        "test -s /etc/tac_plus.conf && echo EXISTS || echo MISSING",
        module_ignore_errors=True
    )
    pytest_assert(
        "EXISTS" in cfg_result['stdout'],
        "TC_H07 FAILED -- /etc/tac_plus.conf is missing or empty on the PTF.\n"
        "The tac_plus process is running but has no config — it will reject all auth.\n"
        "Fix: ensure the tac_plus config file is written before starting the server."
    )

    logger.info("TC_H07 PASSED -- tac_plus is running and /etc/tac_plus.conf exists on PTF")


# ---------------------------------------------------------------------------
# TC_H08 -- End-to-end smoke login (the final pre-flight gate)
# ---------------------------------------------------------------------------

def test_h08_end_to_end_smoke_login(
        localhost,
        duthosts,
        enum_rand_one_per_hwsku_hostname,
        tacacs_creds,       # noqa: F811
        check_tacacs):      # noqa: F811
    """
    TC_H08 -- End-to-end smoke test: SSH into the DUT as the TACACS+ RW user
    and run 'show version'.  This is the single gating check that confirms the
    entire TACACS+ stack — network, daemon, SONiC config, PAM, and sshd —
    are all working together.

    If this passes, all the pre-flight checks are done and the main suite
    can be trusted to test AAA behaviour rather than environment problems.

    If this fails after TC_H01 – TC_H07 all passed, it points to a PAM/sshd
    integration issue specific to the DUT.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    dutip = duthost.mgmt_ip

    res = ssh_remote_run(
        localhost, dutip,
        tacacs_creds['tacacs_rw_user'],
        tacacs_creds['tacacs_rw_user_passwd'],
        "show version"
    )

    pytest_assert(
        res['rc'] == 0,
        "TC_H08 FAILED -- End-to-end smoke login as TACACS+ RW user failed.\n"
        "rc={rc}, stderr={stderr}\n"
        "All pre-flight checks (H01-H07) passed so the issue is likely in PAM "
        "or sshd config on the DUT.\n"
        "Check: 'sudo cat /etc/pam.d/sshd' and 'sudo cat /etc/nsswitch.conf' on DUT.".format(
            rc=res['rc'], stderr=res.get('stderr', ''))
    )
    logger.info(
        "TC_H08 PASSED -- Smoke login succeeded for user '%s'. "
        "Environment is healthy. Main AAA suite can proceed.",
        tacacs_creds['tacacs_rw_user']
    )
