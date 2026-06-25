"""Shared helpers for BMC platform tests (syslog, event.log, Switch-Host)."""

import logging
from contextlib import contextmanager

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.sonic_db import STATE_DB, redis_hget, redis_hset
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

# BMC event log on-disk path
BMC_EVENT_LOG = '/host/bmc/event.log'

# Reboot causes accepted as "BMC-initiated" by Switch-Host
BMC_INITIATED_REBOOT_CAUSES = (
    'power down request from bmc',
    'graceful shutdown from bmc',
    'power loss',
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
        self.duthost.shell(
            "echo '{}' >> {}".format(start_line, BMC_EVENT_LOG),
            module_ignore_errors=True,
        )
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
        result = self.duthost.shell(
            "awk '/{}/ {{found=1; next}} found' {} 2>/dev/null".format(
                start_line.replace("'", r"'\''"), BMC_EVENT_LOG),
            module_ignore_errors=True,
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
    """
    r = duthost.shell(
        f"zgrep -hI -E '{pattern}' {files} 2>/dev/null | tail -{tail}",
        module_ignore_errors=True,
    )
    if r.get('rc') == 0:
        return (r.get('stdout', '') or '').strip()
    return ''


# --- Leak-sensor injection helpers ----------------------------------------

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
    redis_hset(duthost, STATE_DB, f'LIQUID_COOLING_INFO|{sensor_name}', **fields)


def get_system_leak_status(duthost):
    """Return SYSTEM_LEAK_STATUS|system device_leak_status (stripped, '' if absent)."""
    return redis_hget(duthost, STATE_DB, 'SYSTEM_LEAK_STATUS|system', 'device_leak_status')


def set_system_leak_status(duthost, status):
    """HSET SYSTEM_LEAK_STATUS|system device_leak_status."""
    redis_hset(duthost, STATE_DB, 'SYSTEM_LEAK_STATUS|system', device_leak_status=status)


# --- Switch-Host power-cycle verification ---------------------------------

def get_host_uptime(host):
    """Return `uptime -s` (boot timestamp) of the paired Switch-Host; '' on failure."""
    return host.shell("uptime -s", module_ignore_errors=True).get('stdout', '').strip()


def wait_host_off(host, timeout=180, interval=10, delay=30):
    """Wait until the Switch-Host SSH is unreachable (powered off)."""
    return wait_until(
        timeout, interval, delay,
        lambda: host.shell("true", module_ignore_errors=True).get('rc') != 0
    )


def wait_host_on(host, timeout=420, interval=10, delay=30):
    """Wait until the Switch-Host's critical services are fully started."""
    return wait_until(timeout, interval, delay, lambda: host.critical_services_fully_started())


def verify_bmc_initiated_reboot(host, pre_uptime,
                                valid_causes=BMC_INITIATED_REBOOT_CAUSES):
    """Assert paired Switch-Host rebooted (uptime advanced) with a BMC-initiated cause."""
    post_uptime = get_host_uptime(host)
    pytest_assert(post_uptime and post_uptime != pre_uptime,
                  f"Switch-Host uptime did not advance: pre={pre_uptime!r} post={post_uptime!r}")
    cause = host.shell('show reboot-cause', module_ignore_errors=True).get('stdout', '').strip().lower()
    pytest_assert(any(c in cause for c in valid_causes),
                  f"Switch-Host reboot-cause {cause!r} not in {valid_causes}")
