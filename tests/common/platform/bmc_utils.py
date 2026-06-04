"""Shared helpers for BMC platform tests (STATE_DB, syslog, event.log, Switch-Host)."""

import logging
from contextlib import contextmanager

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

APPL_DB = 'APPL_DB'
CONFIG_DB = 'CONFIG_DB'
STATE_DB = 'STATE_DB'

# BMC event log on-disk path
BMC_EVENT_LOG = '/host/bmc/event.log'

# Reboot causes accepted as "BMC-initiated" by Switch-Host
BMC_INITIATED_REBOOT_CAUSES = (
    'power down request from bmc',
    'graceful shutdown from bmc',
    'power loss',
)


# --- Redis helpers ---------------------------------------------------------
from tests.common.helpers.sonic_db import (  # noqa: F401,E402
    redis_hget,
    redis_hgetall,
    redis_hset,
    redis_del,
    redis_keys,
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
    try:
        host = duthost.get_bmc_host()
        host.command("echo ping", module_ignore_errors=True)
    except Exception as e:
        pytest.skip(f"paired Switch-Host not reachable from BMC {duthost.hostname}: {e}")
    return host


# --- Log helpers -----------------------------------------------------------

def make_bmc_loganalyzer(duthost, marker_prefix, include_event_log=True):
    """
    Return a LogAnalyzer configured for BMC tests.

    With include_event_log=True, /host/bmc/event.log is added to additional_files
    so init() writes a sentinel marker line into it and analyze() extracts the
    same windowed slice from both syslog (rotation-safe, incl. .gz) and event.log.

    Tests using this MUST be decorated with @pytest.mark.disable_loganalyzer to
    avoid interference with the session-scoped LogAnalyzer fixture.
    """
    from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer
    additional = {BMC_EVENT_LOG: ''} if include_event_log else {}
    return LogAnalyzer(ansible_host=duthost, marker_prefix=marker_prefix,
                       additional_files=additional)


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

def inject_leak_sensor(duthost, sensor_name, severity, leaking='Yes', leak_sensor_status='Good',
                       sensor_type=None, location=None):
    """HSET LIQUID_COOLING_INFO|<sensor_name> with thermalctld's wire schema."""
    fields = {
        'name': sensor_name,
        'leaking': leaking,
        'leak_sensor_status': leak_sensor_status,
        'severity': severity,
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
    cause_out = host.show_and_parse('show reboot-cause')
    cause = (cause_out[0].get('cause') or '').lower() if cause_out else ''
    pytest_assert(any(c in cause for c in valid_causes),
                  f"Switch-Host reboot-cause {cause!r} not in {valid_causes}")
