"""Shared helpers for BMC platform tests (syslog, event.log, Switch-Host)."""

import argparse
import ast
import logging
import shlex
import time

from contextlib import contextmanager

import pytest


from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.sonic_db import CONFIG_DB, STATE_DB, redis_hget, redis_hgetall, redis_hset
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

# BMC event log on-disk path
BMC_EVENT_LOG = '/host/bmc/event.log'

# Reboot causes accepted as "BMC-initiated" by Switch-Host
# Hard power off (ACTION_POWER_OFF: rack-mgr POWER_OFF, CRITICAL-leak power_off)
CAUSE_POWER_DOWN_FROM_BMC = 'power down request from bmc'
# Graceful shutdown (ACTION_GRACEFUL_SHUTDOWN: CLI config shutdown, rack-mgr GRACEFUL_SHUT)
CAUSE_GRACEFUL_SHUTDOWN_FROM_BMC = 'graceful shutdown from bmc'
CAUSE_POWER_LOSS = 'power loss'
BMC_INITIATED_REBOOT_CAUSES = (
    CAUSE_POWER_DOWN_FROM_BMC,
    CAUSE_GRACEFUL_SHUTDOWN_FROM_BMC,
    CAUSE_POWER_LOSS,
)

MAX_BMC_CLOCK_SKEW_SECONDS = 60


def assert_bmc_clock_in_sync(duthost, max_skew_seconds=MAX_BMC_CLOCK_SKEW_SECONDS):
    """Fail if the BMC and sonic-mgmt container clocks are too far apart."""
    container_now = int(time.time())
    bmc_now = int(duthost.shell("date -u +%s")["stdout"].strip())
    skew = container_now - bmc_now

    pytest_assert(
        abs(skew) <= max_skew_seconds,
        "BMC clock is {}s {} sonic-mgmt container ({} vs {}). "
        "Synchronize the clocks before running BMC tests.".format(
            abs(skew),
            "behind" if skew > 0 else "ahead of",
            time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(container_now)),
            time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(bmc_now)),
        ),
    )


# --- pmon daemon helpers ---------------------------------------------------

@contextmanager
def pause_pmon_daemon(duthost, daemon_name):
    """Stop a pmon daemon for the `with` block; restart on exit."""
    logger.info("Pausing pmon daemon '%s' for duration of injection", daemon_name)
    duthost.stop_pmon_daemon_service(daemon_name)
    try:
        yield
    finally:
        logger.info("Restarting pmon daemon '%s'", daemon_name)
        duthost.start_pmon_daemon(daemon_name)


def get_switch_host_or_skip_test(duthost):
    """Return the paired Switch-Host SonicHost, or pytest.skip if unreachable."""
    host = None
    target = "<unknown>"
    try:
        host = duthost.get_bmc_host()
        target = f"{host.hostname} ({getattr(host, 'mgmt_ip', 'no-ip')})"
        logger.info("Probing paired Switch-Host %s from BMC '%s'", target, duthost.hostname)
        host.command("echo ping")
    except Exception as e:
        pytest.skip(f"paired Switch-Host {target} not reachable from BMC {duthost.hostname}: {e}")
    return host


# --- Log helpers -----------------------------------------------------------

LOG_TARGET_EVENT_LOG = 'event_log'
LOG_TARGET_SYSLOG = 'syslog'


class BmcLogAnalyzer:
    """
    Unified log analyzer for BMC tests supporting both /host/bmc/event.log and syslog.

    The standard LogAnalyzer.analyze() always calls extract_log on /var/log/syslog*
    to locate the start marker. On BMC platforms the syslog is on tmpfs and is
    wiped on every reboot/power-loss, so the marker is lost and extract_log throws.

    This class provides the same init()/analyze() interface as LogAnalyzer but
    lets the caller choose the log target per analyze() call:

      log_target='event_log' (default):
        - init()    : writes start marker into /host/bmc/event.log (persistent).
        - analyze() : scans event.log from the start marker forward.
        - Use for post-reboot checks — syslog is wiped, event.log survives.

      log_target='syslog':
        - init()    : delegates to LogAnalyzer.init() (writes marker to syslog).
        - analyze() : delegates to LogAnalyzer.analyze() (scans /var/log/syslog*).
        - Use for live trigger-and-verify checks where no reboot occurs.

    Usage:
        la = make_bmc_loganalyzer(duthost, "my_test")

        # post-reboot (default):
        marker = la.init()
        reboot(...)
        result = la.analyze(marker)               # uses event_log

        # live trigger (no reboot):
        marker = la.init(log_target='syslog')
        trigger_something()
        result = la.analyze(marker, log_target='syslog')

    Tests using this MUST be decorated with @pytest.mark.disable_loganalyzer.
    """

    def __init__(self, duthost, marker_prefix):
        self.duthost = duthost
        self.marker_prefix = marker_prefix.replace(' ', '_')
        self.match_regex = []
        self.ignore_regex = []
        self._la = None  # lazy LogAnalyzer for syslog path

    def _get_syslog_analyzer(self):
        """Lazily create and return the underlying LogAnalyzer for syslog scans."""
        if self._la is None:
            from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer
            self._la = LogAnalyzer(ansible_host=self.duthost,
                                   marker_prefix=self.marker_prefix)
        self._la.match_regex = list(self.match_regex)
        self._la.ignore_regex = list(self.ignore_regex)
        return self._la

    def init(self, log_target=LOG_TARGET_EVENT_LOG):
        """Write a start marker and return the marker string.

        For event_log: appends marker line to /host/bmc/event.log (persistent).
        For syslog: delegates to LogAnalyzer.init() (writes to syslog via loganalyzer.py).
        """
        import time
        if log_target == LOG_TARGET_SYSLOG:
            return self._get_syslog_analyzer().init()

        marker = "{}.{}".format(self.marker_prefix,
                                time.strftime("%Y-%m-%d-%H:%M:%S", time.gmtime()))
        start_line = "start-LogAnalyzer-{}".format(marker)
        self.duthost.shell("sync {}".format(shlex.quote(BMC_EVENT_LOG)))
        self.duthost.shell(
            "echo '{}' >> {}".format(start_line, BMC_EVENT_LOG),
            module_ignore_errors=True,
        )
        self.duthost.shell("sync {}".format(shlex.quote(BMC_EVENT_LOG)))
        logger.debug("BmcLogAnalyzer: wrote marker '%s' to %s", start_line, BMC_EVENT_LOG)
        return marker

    def analyze(self, marker, fail=False, log_target=LOG_TARGET_EVENT_LOG):
        """Scan logs from the start marker forward.

        log_target='event_log' (default): scans /host/bmc/event.log only.
        log_target='syslog': delegates to LogAnalyzer.analyze() (/var/log/syslog*).

        Returns the same dict shape as LogAnalyzer.analyze():
          {"total": {"match": <n>}, "match_messages": {"<path>": [lines]}}
        """
        import re as _re

        if log_target == LOG_TARGET_SYSLOG:
            return self._get_syslog_analyzer().analyze(marker, fail=fail)

        start_line = "start-LogAnalyzer-{}".format(marker)
        self.duthost.shell("sync {}".format(shlex.quote(BMC_EVENT_LOG)))
        result = self.duthost.shell(
            "sed -n {} {}".format(
                shlex.quote(r"/{}/,$p".format(start_line)),
                shlex.quote(BMC_EVENT_LOG)
            ),
            module_ignore_errors=True
        )
        content = (result.get('stdout', '') or '').strip()

        match_lines = []
        if content and self.match_regex:
            combined = _re.compile('|'.join(self.match_regex))
            match_lines = [ln for ln in content.splitlines() if combined.search(ln)]

        logger.debug("BmcLogAnalyzer.analyze(event_log): %d match lines for marker '%s'",
                     len(match_lines), marker)
        return {
            "total": {"match": len(match_lines),
                      "expected_match": 0,
                      "expected_missing_match": 0},
            "match_messages": {BMC_EVENT_LOG: match_lines},
            "match_files": {BMC_EVENT_LOG: {"match": len(match_lines), "expected_match": 0}},
            "expect_messages": {},
            "unused_expected_regexp": [],
        }


def make_bmc_loganalyzer(duthost, marker_prefix):
    """
    Return a BmcLogAnalyzer for BMC tests.

    Supports both event.log (default, persistent — use for post-reboot checks)
    and syslog (live — use for trigger-and-verify checks with no reboot).

    Tests using this MUST be decorated with @pytest.mark.disable_loganalyzer to
    avoid interference with the session-scoped LogAnalyzer fixture.
    """
    return BmcLogAnalyzer(duthost, marker_prefix)


def bmc_log_zgrep(duthost, pattern, tail=20, files='/var/log/syslog*'):
    """
    Historical / pre-existing-state scan that walks all rotated syslog files
    (including .gz). For trigger-and-verify checks, use make_bmc_loganalyzer +
    LogAnalyzer.analyze() instead so the scan is bounded by markers.

    Returns the matching lines (tail-N) as a string; empty if no match.

    Ansible logs every shell/command module invocation to syslog, echoing the
    full command line (including this search pattern) in a line tagged with
    ``ansible-ansible.legacy.command`` / ``ansible-ansible.legacy.shell``.
    Those lines are filtered out before ``tail`` so the scan cannot self-match
    its own command-invocation syslog entry.
    """
    r = duthost.shell(
        f"zgrep -hI -E '{pattern}' {files} 2>/dev/null "
        f"| grep -vE 'ansible-ansible\\.legacy\\.(command|shell)' "
        f"| tail -{tail}",
        module_ignore_errors=True,
    )
    return (r.get('stdout', '') or '').strip()


# --- Leak-sensor injection helpers ----------------------------------------

LIQUID_COOLING_INFO_TABLE = 'LIQUID_COOLING_INFO'


def get_sensor_data(duthost, sensor_name):
    """
    Return LIQUID_COOLING_INFO|<sensor_name> from STATE_DB as a field dict.

    Reads via ``sonic-db-cli STATE_DB HGETALL`` and parses the result into a
    Python dictionary (e.g. leaking, leak_severity, leak_sensor_status).
    Returns an empty dict when the key is absent.
    """
    return redis_hgetall(duthost, STATE_DB, f'{LIQUID_COOLING_INFO_TABLE}|{sensor_name}')


def inject_leak_sensor(duthost, sensor_name, leak_severity, leaking='Yes', leak_sensor_status='Good',
                       sensor_type=None, location=None):
    """HSET LIQUID_COOLING_INFO|<sensor_name> with thermalctld's wire schema."""
    fields = {
        'name': sensor_name,
        'leaking': leaking,
        # leak_status is a back-compat alias of leaking consumed by system-health
        # and legacy `leakageshow` CLI; thermalctld writes both.
        'leak_status': leaking,
        'leak_sensor_status': leak_sensor_status,
        'leak_severity': leak_severity,
    }
    if sensor_type is not None:
        fields['type'] = sensor_type
    if location is not None:
        fields['location'] = location
    redis_hset(duthost, STATE_DB, f'{LIQUID_COOLING_INFO_TABLE}|{sensor_name}', **fields)


def get_system_leak_status(duthost):
    """Return SYSTEM_LEAK_STATUS|system device_leak_status (stripped, '' if absent)."""
    return redis_hget(duthost, STATE_DB, 'SYSTEM_LEAK_STATUS|system', 'device_leak_status')


def set_system_leak_status(duthost, status):
    """HSET SYSTEM_LEAK_STATUS|system device_leak_status."""
    redis_hset(duthost, STATE_DB, 'SYSTEM_LEAK_STATUS|system', device_leak_status=status)


def get_platform_major_leak_num_min_sensors(duthost, default=0):
    """Return the platform-defined MIN-N from LiquidCoolingBase.get_major_leak_num_min_sensors().

    This is the system-wide default used by thermalctld when there is no user override.
    A value of 0 means the count-based MAJOR rule is off (the MAX-T escalation rule is
    independent of MIN-N). Only an explicitly unsupported API returns `default`;
    command errors, malformed results and unexpected implementation failures fail.
    """
    # Only explicit missing method / NotImplementedError is unsupported. Import,
    # transport, implementation errors and malformed results remain failures.
    script = """from sonic_platform.chassis import Chassis
lc = Chassis().get_liquid_cooling()
method = getattr(lc, 'get_major_leak_num_min_sensors', None)
if method is None:
    print('UNSUPPORTED')
else:
    try:
        value = method()
    except NotImplementedError:
        print('UNSUPPORTED')
    else:
        if type(value) is not int or not 0 <= value <= 4294967295 or value == 1:
            raise ValueError('Invalid MIN-N: {!r}'.format(value))
        print(value)
"""
    out = duthost.shell("python3 -c {}".format(shlex.quote(script)), module_ignore_errors=True)
    pytest_assert(out.get('rc') == 0, "Platform MIN-N query failed: {}".format(out))
    raw = (out.get('stdout') or '').strip()
    if raw == 'UNSUPPORTED':
        return default
    pytest_assert(raw.isdigit() and int(raw) <= 4294967295 and int(raw) != 1,
                  "Invalid platform MIN-N response: {!r}".format(raw))
    return int(raw)


def read_bmc_hash(duthost, db, key):
    """Read native sonic-db-cli HGETALL dictionary output without losing values.

    RedisReply::formatDictReply emits a quoted dictionary, including {} on a
    missing hash. Blank output and raw line pairs are not this protocol: reject
    them rather than interpreting transport/format failures as safe defaults.
    """
    out = duthost.shell("sonic-db-cli {} HGETALL {}".format(db, shlex.quote(key)),
                        module_ignore_errors=True)
    pytest_assert(out.get('rc') == 0, "Cannot read {} {}: {}".format(db, key, out))
    raw = out.get('stdout')
    pytest_assert(isinstance(raw, str), "Missing hash output for {}".format(key))
    try:
        expression = ast.parse(raw.strip(), mode='eval').body
    except (ValueError, SyntaxError) as error:
        pytest.fail("Invalid native hash output for {}: {}".format(key, error))
    pytest_assert(isinstance(expression, ast.Dict), "Expected native hash dictionary for {}".format(key))
    fields = {}
    for field, value in zip(expression.keys, expression.values):
        pytest_assert(isinstance(field, ast.Constant) and isinstance(field.value, str) and
                      isinstance(value, ast.Constant) and isinstance(value.value, str),
                      "Invalid hash fields for {}".format(key))
        pytest_assert(field.value not in fields, "Duplicate hash field for {}".format(key))
        fields[field.value] = value.value
    return fields


def get_effective_leak_policy(duthost):
    """Mirror bmcctld's first-existing-row rule, not a per-field fallback.

    Table.get('') addresses the bare table name. Failed or malformed reads stop
    admission. A policy snapshot is not a lock: callers still need exclusive,
    hardware-owner-authorized test access; never disable enforcement to obtain it.
    """
    policy = {
        'system_leak_policy': 'enabled',
        'system_critical_leak_action': 'power_off',
        'system_major_leak_action': 'syslog_only',
        'system_minor_leak_action': 'syslog_only',
        'rack_mgr_leak_policy': 'enabled',
        'rack_mgr_critical_alert_action': 'syslog_only',
        'rack_mgr_major_alert_action': 'syslog_only',
        'rack_mgr_minor_alert_action': 'syslog_only',
    }
    for key in ('LEAK_CONTROL_POLICY|policy', 'LEAK_CONTROL_POLICY|LEAK_CONTROL_POLICY',
                'LEAK_CONTROL_POLICY'):
        row = read_bmc_hash(duthost, CONFIG_DB, key)
        if row:
            policy.update({k: v for k, v in row.items() if k in policy})
            break
    return policy


def _read_pmon_daemon_source(duthost, daemon):
    """Read installed source only: CLI and daemon packages upgrade independently."""
    pytest_assert(daemon in ('bmcctld', 'thermalctld'), "Unexpected daemon {}".format(daemon))
    out = duthost.shell("docker exec pmon cat /usr/local/bin/{}".format(daemon), module_ignore_errors=True)
    pytest_assert(out.get('rc') == 0 and out.get('stdout'),
                  "Cannot establish installed {} contract: {}".format(daemon, out))
    source = out['stdout']
    try:
        ast.parse(source)
    except SyntaxError as error:
        pytest.fail("Invalid installed {} source: {}".format(daemon, error))
    return source


def is_liquid_cooling_updater_enabled(duthost):
    """Resolve the running thermalctld startup gate, not physical sensor presence.

    This getter query requires owner-approved platform API access/initialization. Unlike the
    API-test module skip helpers, errors/non-booleans are never unsupported.
    No API server fixture, daemon construction or cooling-object query is used.
    """
    source = _read_pmon_daemon_source(duthost, 'thermalctld')
    # Recognize the supported startup contract, not a package version or target
    # hash. Unknown implementations require review before using this query.
    contract = (
        "parser.add_argument('--enable_liquid_cooling', action='store_true', default=False)",
        'if not enable_liquid_cooling:',
        'enable_liquid_cooling = bool(self.chassis.is_liquid_cooled())',
        'self.liquid_cooling_updater = LiquidCoolingUpdater(self.chassis, liquid_cooling_update_interval) '
        'if enable_liquid_cooling else None',
    )
    pytest_assert(all(fragment in source for fragment in contract),
                  "Unrecognized thermalctld enablement contract; refusing to guess")
    status, pid = duthost.get_pmon_daemon_status('thermalctld')
    pytest_assert(status == 'RUNNING' and type(pid) is int and pid > 0,
                  "Cannot resolve running thermalctld startup")
    command = "docker exec pmon cat /proc/{}/cmdline".format(pid)
    out = duthost.shell(command, module_ignore_errors=True)
    pytest_assert(out.get('rc') == 0 and isinstance(out.get('stdout'), str),
                  "Cannot read thermalctld startup: {}".format(out))
    argv = out['stdout'].rstrip('\x00').split('\x00')
    pytest_assert(len(argv) >= 2 and argv[1] == '/usr/local/bin/thermalctld' and
                  argv[0].rsplit('/', 1)[-1].startswith('python3'),
                  "Unexpected thermalctld startup argv: {!r}".format(argv))
    parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    parser.add_argument('--enable_liquid_cooling', action='store_true')
    parser.add_argument('--thermal-monitor-initial-interval', type=int)
    parser.add_argument('--thermal-monitor-update-interval', type=int)
    parser.add_argument('--thermal-monitor-update-elapsed-threshold', type=int)
    parser.add_argument('--liquid_cooling_update_interval', type=float)
    try:
        args = parser.parse_args(argv[2:])
    except SystemExit:
        pytest.fail("Unrecognized thermalctld startup arguments; refusing to guess")
    if args.enable_liquid_cooling:
        pytest_assert(duthost.get_pmon_daemon_status('thermalctld') == (status, pid),
                      "thermalctld changed during applicability query; retry before testing")
        return True  # Explicit startup override takes precedence over platform False/errors.

    # Same Platform -> Chassis capability as thermalctld, in the same container.
    # Platform construction is not a pure source read: the owner must review the
    # installed constructor dependencies before approving this getter query.
    # Do not call get_liquid_cooling(): declared sensors do not enable the updater.
    script = """from sonic_platform.platform import Platform
value = Platform().get_chassis().is_liquid_cooled()
if type(value) is not bool:
    raise ValueError('is_liquid_cooled must return bool')
print(value)
"""
    out = duthost.shell("docker exec pmon python3 -B -c {}".format(shlex.quote(script)),
                        module_ignore_errors=True)
    pytest_assert(out.get('rc') == 0 and isinstance(out.get('stdout'), str) and
                  out['stdout'].strip() in ('True', 'False'),
                  "Cannot establish platform liquid-cooling capability: {}".format(out))
    pytest_assert(duthost.get_pmon_daemon_status('thermalctld') == (status, pid),
                  "thermalctld changed during applicability query; retry before testing")
    return out['stdout'].strip() == 'True'


def require_liquid_cooling_publisher(duthost):
    """Case-local admission: disabled is SKIP; enabled but missing data is FAIL."""
    if not is_liquid_cooling_updater_enabled(duthost):
        pytest.skip("Liquid-cooling updater is not enabled by thermalctld startup/platform capability; "
                    "publisher-dependent scenario is inapplicable (not a no-leak assertion)")
    baseline = read_bmc_hash(duthost, STATE_DB, 'SYSTEM_LEAK_STATUS|system').get('device_leak_status')
    pytest_assert(baseline in ('None', 'MINOR', 'MAJOR', 'CRITICAL'),
                  "Enabled liquid-cooling publisher has missing/unknown system leak baseline; refusing injection")
    return baseline


def is_major_leak_supported(duthost, daemon='bmcctld'):
    """Recognize known new/legacy daemon contracts; unknown is not unsupported."""
    source = _read_pmon_daemon_source(duthost, daemon)
    if daemon == 'thermalctld':
        if 'def _resolve_major_leak_min(' in source and 'SystemLeakStatus.MAJOR' in source:
            return True
        if 'escalated_to_critical = True' in source and 'sensor_leak_severity = LeakSeverity.CRITICAL' in source:
            return False
    else:
        if 'elif leak_status == SystemLeakStatus.MAJOR:' in source and '"MAJOR_SYSTEM_LEAK"' in source:
            return True
        if 'SYSTEM_LEAK_CRITICAL = "CRITICAL"' in source and 'SYSTEM_LEAK_MINOR = "MINOR"' in source:
            return False
    pytest.fail("Unrecognized installed {} leak contract; refusing to guess".format(daemon))


def get_power_on_block_reason(duthost):
    """Select the installed bmcctld result contract before issuing any command."""
    source = _read_pmon_daemon_source(duthost, 'bmcctld')
    if 'POWER_ON_BLOCK_REASON = "POWER_DOWN_POLICY_CONFIGURED_EVENT_ACTIVE"' in source:
        return 'POWER_DOWN_POLICY_CONFIGURED_EVENT_ACTIVE'
    if 'self._set_cmd_status(key, CMD_STATUS_FAILED, "CRITICAL_LEAK_PRESENT")' in source:
        return 'CRITICAL_LEAK_PRESENT'
    pytest.fail("Unrecognized bmcctld power-on refusal contract; refusing to guess")


def action_is_syslog_only(duthost, action_field):
    """Admit only enabled, known syslog-only policy; disabled is not test coverage."""
    policy = get_effective_leak_policy(duthost)
    pytest_assert(action_field in policy and action_field.endswith('_action'),
                  "Unknown action field {}".format(action_field))
    enabled_field = 'system_leak_policy' if action_field.startswith('system_') else 'rack_mgr_leak_policy'
    return policy[enabled_field] == 'enabled' and policy[action_field] == 'syslog_only'


def get_major_leak_min_sensors(duthost, default=None):
    """Return the effective MIN-N: the number of concurrent Minor leaks at or above
    which thermalctld classifies the system as MAJOR_SYSTEM_LEAK.

    Resolution order (mirrors thermalctld):
      1. User override LEAK_CONTROL_POLICY|policy system_major_leak_num_min_sensors in CONFIG_DB (>= 2)
      2. Platform API LiquidCoolingBase.get_major_leak_num_min_sensors()
      3. `default` (None) if neither is available; a missing value is not a configured threshold

    A value of 0 means the count-based MAJOR rule is off; the MAX-T escalation rule is
    independent of MIN-N.
    """
    # LEAK_CONTROL_POLICY is a single-row table; the CLI writes key "policy".
    val = read_bmc_hash(duthost, CONFIG_DB, 'LEAK_CONTROL_POLICY|policy').get(
        'system_major_leak_num_min_sensors')
    try:
        override = int(val)
    except (TypeError, ValueError):
        override = None
    # thermalctld ignores an override below 2 and falls back to the platform value.
    if override is not None and override >= 2:
        return override
    platform_val = get_platform_major_leak_num_min_sensors(duthost, default=None)
    return platform_val if platform_val is not None else default


# --- Switch-Host power-cycle verification ---------------------------------

def get_host_uptime(host):
    """Return `uptime -s` (boot timestamp) of the paired Switch-Host; '' on failure."""
    return host.shell("uptime -s", module_ignore_errors=True).get('stdout', '').strip()


def get_host_boot_id(host):
    """Return the kernel boot ID; and '' on failure."""
    return host.shell(
        "cat /proc/sys/kernel/random/boot_id",
        module_ignore_errors=True
    ).get('stdout', '').strip()


def wait_host_off(duthost, host, timeout=180, interval=10, delay=30):
    """Wait until the paired Switch-Host is powered off, as observed by the BMC.

    Powered-off is confirmed by two independent BMC-side signals
      1. Authoritative: the BMC reports the SWITCH-HOST module oper-status as
         'offline'. bmcctld writes this from the module's real power state
         (module.get_oper_status()), so it reflects actual power, not just liveness.
      2. Confirmation: the BMC can no longer ping the Switch-Host on its mgmt IP.
    """
    switch_host_ip = getattr(host, 'mgmt_ip', None)

    def _bmc_reports_offline():
        rows = duthost.show_and_parse("show chassis module status")
        for row in rows or []:
            if (row.get('name') or '').strip().startswith('SWITCH-HOST'):
                return (row.get('oper-status') or '').strip().lower() == 'offline'
        return False

    def _ping_unreachable():
        if not switch_host_ip:
            return True
        res = duthost.shell(f"ping -c 3 -W 1 {switch_host_ip}", module_ignore_errors=True)
        return res.get('rc') != 0

    return wait_until(timeout, interval, delay,
                      lambda: _bmc_reports_offline() and _ping_unreachable())


def wait_host_on(host, timeout=420, interval=10, delay=30):
    """Wait until the Switch-Host's critical services are fully started."""
    return wait_until(timeout, interval, delay, lambda: host.critical_services_fully_started())


SWITCH_HOST_STARTUP_ACK = "Starting up chassis module SWITCH-HOST"


def recover_switch_host_after_power_off(duthost, host, context=""):
    """Best-effort recovery of a Switch-Host that a BMC power action left powered OFF.

    A leak/BMC-triggered power_off can leave the module powered off while CONFIG_DB
    admin_status stays 'up', which makes a bare `config chassis modules startup` a no-op.
    If the host is still off, force a clean admin down->up transition (shutdown then
    startup) to clear the stale oper_status and actually re-power it, asserting the
    startup command was accepted. Finally confirm the host powers back on.
    """
    suffix = f" {context}" if context else ""
    if wait_host_off(duthost, host, delay=5):
        # shutdown first to clear the stale oper_status / force a real down->up transition
        duthost.shell("config chassis modules shutdown SWITCH-HOST", module_ignore_errors=True)
        startup_out = duthost.shell(
            "config chassis modules startup SWITCH-HOST", module_ignore_errors=True
        ).get('stdout', '').strip()
        # Match loosely: the CLI may prepend/append warnings or trailing lines to the ack.
        pytest_assert(SWITCH_HOST_STARTUP_ACK in startup_out,
                      f"Failed to command startup Switch-Host in recovery{suffix}, got {startup_out!r}")
    pytest_assert(wait_host_on(host), f"Switch-Host did not power on{suffix}")


def verify_bmc_initiated_reboot(host, pre_uptime,
                                valid_causes=BMC_INITIATED_REBOOT_CAUSES):
    """Assert paired Switch-Host rebooted (uptime advanced) with a BMC-initiated cause.

    `valid_causes` may be a single expected cause string or an iterable of accepted
    causes; the reported reboot-cause must contain one of them.
    """
    if isinstance(valid_causes, str):
        valid_causes = (valid_causes,)
    post_uptime = get_host_uptime(host)
    pytest_assert(post_uptime and post_uptime != pre_uptime,
                  f"Switch-Host uptime did not advance: pre={pre_uptime!r} post={post_uptime!r}")
    cause = host.shell('show reboot-cause', module_ignore_errors=True).get('stdout', '').strip().lower()
    pytest_assert(any(c in cause for c in valid_causes),
                  f"Switch-Host reboot-cause {cause!r} not in {valid_causes}")
