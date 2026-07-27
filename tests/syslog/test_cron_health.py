"""
Tests for cron daemon health and cron file security on SONiC devices.

Covers test gap issue #19527:
  "Test to validate if cron job run is a success" — Production incident where
  cron jobs silently failed due to insecure file permissions, causing a flood
  of tickets. This test validates:
    1. The cron service is running.
    2. Cron configuration files have secure permissions and ownership.
    3. No cron-related security errors appear in system logs.
    4. Standard SONiC scheduled jobs (logrotate via cron or systemd timer)
       are properly installed and active.

Topology: any (runs on all platforms)
"""

import logging
import pytest

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("any"),
    pytest.mark.disable_loganalyzer,
]

# Cron directories to audit for file permissions and ownership
CRON_DIRS = [
    "/etc/cron.d",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
]

# Known cron error patterns that indicate misconfiguration.
# These are emitted by the cron daemon itself when it rejects a crontab entry.
CRON_ERROR_PATTERNS = [
    "INSECURE MODE",
    "WRONG FILE OWNER",
    "bad username",
    "ORPHAN",
]


# ---------------------------------------------------------------------------
# Test 1: cron service is active
# ---------------------------------------------------------------------------
def test_cron_service_running(duthosts, rand_one_dut_hostname):
    """Verify the cron daemon is running on the DUT.

    The cron service is essential for periodic maintenance tasks such as
    log rotation and core-dump cleanup.  If it is not running, scheduled
    jobs silently stop executing.
    """
    duthost = duthosts[rand_one_dut_hostname]

    result = duthost.shell("systemctl is-active cron", module_ignore_errors=True)
    status = result["stdout"].strip()
    logger.info("cron service status: %s", status)
    assert status == "active", \
        "cron service is not active (status: '{}')".format(status)


# ---------------------------------------------------------------------------
# Test 2: cron file permissions and ownership are secure
# ---------------------------------------------------------------------------
def test_cron_file_permissions_secure(duthosts, rand_one_dut_hostname):
    """Verify cron configuration files are not group/other-writable and are
    owned by root.

    The cron daemon refuses to load crontab files that are writable by
    group or other (mode & 022 != 0) and logs an 'INSECURE MODE' warning.
    Files not owned by root:root are also rejected ('WRONG FILE OWNER').
    """
    duthost = duthosts[rand_one_dut_hostname]
    insecure_files = []

    # --- Check /etc/crontab ---
    result = duthost.shell(
        "stat -c '%a %U %G %n' /etc/crontab",
        module_ignore_errors=True,
    )
    if result["rc"] == 0:
        parts = result["stdout"].strip().split()
        mode_str, owner, group = parts[0], parts[1], parts[2]
        mode = int(mode_str, 8)
        if mode & 0o022:
            insecure_files.append("/etc/crontab (mode: {})".format(mode_str))
        if owner != "root" or group != "root":
            insecure_files.append(
                "/etc/crontab (owner: {}:{}, expected root:root)".format(owner, group)
            )

    # --- Check files in cron directories ---
    for cron_dir in CRON_DIRS:
        # Find files that are group-or-other writable
        cmd = (
            "find {dir} -maxdepth 1 -type f "
            "\\( -perm /022 -o ! -user root -o ! -group root \\) "
            "-exec stat -c '%a %U %G %n' {{}} + 2>/dev/null"
        ).format(dir=cron_dir)

        result = duthost.shell(cmd, module_ignore_errors=True)
        if result["rc"] == 0 and result["stdout"].strip():
            for line in result["stdout"].strip().splitlines():
                parts = line.split(None, 3)
                if len(parts) < 4:
                    continue
                mode_str, owner, group, filepath = parts
                reasons = []
                if int(mode_str, 8) & 0o022:
                    reasons.append("mode={}".format(mode_str))
                if owner != "root":
                    reasons.append("owner={}".format(owner))
                if group != "root":
                    reasons.append("group={}".format(group))
                if reasons:
                    insecure_files.append(
                        "{} ({})".format(filepath, ", ".join(reasons))
                    )

    if insecure_files:
        logger.error("Insecure cron files:\n%s", "\n".join(insecure_files))

    assert len(insecure_files) == 0, \
        "Insecure cron files found (group/other writable or bad ownership):\n{}".format(
            "\n".join(insecure_files)
        )


# ---------------------------------------------------------------------------
# Test 3: no cron security errors in current-boot logs
# ---------------------------------------------------------------------------
def test_cron_no_security_errors_in_log(duthosts, rand_one_dut_hostname):
    """Check system logs from the current boot for cron security errors.

    These errors indicate that the cron daemon rejected one or more crontab
    files due to bad permissions or ownership — exactly the production
    failure described in issue #19527.
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Try journalctl first (scoped to current boot); fall back to syslog
    grep_pattern = "|".join(CRON_ERROR_PATTERNS)

    result = duthost.shell(
        "journalctl -b -u cron.service --no-pager 2>/dev/null "
        "| grep -iE '({pat})' | head -30".format(pat=grep_pattern),
        module_ignore_errors=True,
    )

    if result["rc"] != 0 or not result["stdout"].strip():
        # journalctl unavailable or no matches — try syslog (last 24h)
        result = duthost.shell(
            "awk -v cutoff=\"$(date -d '24 hours ago' '+%b %e %H:%M')\" "
            "'$0 >= cutoff' /var/log/syslog 2>/dev/null "
            "| grep -i cron "
            "| grep -iE '({pat})' | head -30".format(pat=grep_pattern),
            module_ignore_errors=True,
        )

    errors = result["stdout"].strip() if result["rc"] == 0 else ""

    if errors:
        logger.error("Cron security errors found:\n%s", errors)
        error_lines = errors.splitlines()
        pytest.fail(
            "Found {} cron security error(s) in system log:\n{}".format(
                len(error_lines), errors
            )
        )


# ---------------------------------------------------------------------------
# Test 4: standard SONiC scheduled jobs are installed and active
# ---------------------------------------------------------------------------
def test_logrotate_scheduled_job_active(duthosts, rand_one_dut_hostname):
    """Verify logrotate is scheduled — either via cron or systemd timer.

    Modern SONiC images may use a systemd timer (logrotate.timer) instead
    of a cron.d entry.  Both are valid; at least one must be present.
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Check for cron-based logrotate
    cron_logrotate = duthost.shell(
        "test -f /etc/cron.d/logrotate -o -f /etc/cron.hourly/logrotate "
        "&& echo found || echo missing",
        module_ignore_errors=True,
    )["stdout"].strip()

    # Check for timer-based logrotate
    timer_logrotate = duthost.shell(
        "systemctl is-active logrotate.timer 2>/dev/null || echo inactive",
        module_ignore_errors=True,
    )["stdout"].strip()

    cron_ok = cron_logrotate == "found"
    timer_ok = timer_logrotate == "active"

    logger.info(
        "logrotate scheduling: cron=%s, timer=%s",
        "present" if cron_ok else "absent",
        "active" if timer_ok else "inactive",
    )

    assert cron_ok or timer_ok, (
        "logrotate is not scheduled by cron or systemd timer. "
        "cron file: {}, logrotate.timer: {}".format(
            cron_logrotate, timer_logrotate
        )
    )


# ---------------------------------------------------------------------------
# Test 5: cron directories exist with correct permissions
# ---------------------------------------------------------------------------
def test_cron_directories_secure(duthosts, rand_one_dut_hostname):
    """Verify that /etc/cron.d and related directories exist and have
    restrictive permissions (not world-writable)."""
    duthost = duthosts[rand_one_dut_hostname]
    issues = []

    for cron_dir in ["/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily"]:
        result = duthost.shell(
            "stat -c '%a %U %G' {} 2>/dev/null".format(cron_dir),
            module_ignore_errors=True,
        )
        if result["rc"] != 0:
            # Directory may not exist — that's acceptable for optional dirs
            logger.info("%s does not exist, skipping", cron_dir)
            continue

        parts = result["stdout"].strip().split()
        mode_str, owner = parts[0], parts[1]
        mode = int(mode_str, 8)

        if mode & 0o002:
            issues.append("{} is world-writable (mode: {})".format(cron_dir, mode_str))
        if owner != "root":
            issues.append("{} owner is '{}', expected 'root'".format(cron_dir, owner))

    if issues:
        logger.error("Cron directory issues:\n%s", "\n".join(issues))

    assert len(issues) == 0, \
        "Cron directory security issues found:\n{}".format("\n".join(issues))
