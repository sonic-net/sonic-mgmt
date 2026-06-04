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

def pmon_journal_contains(duthost, pattern, since='1 minute ago', tail=5):
    """True iff `pattern` appears in host /var/log/syslog (case-insensitive)."""
    r = duthost.shell(
        f"grep -ihI '{pattern}' /var/log/syslog /var/log/syslog.1 2>/dev/null | tail -{tail}",
        module_ignore_errors=True
    )
    return r.get('rc') == 0 and bool((r.get('stdout', '') or '').strip())


def bmc_event_log_exists(duthost):
    """True iff /host/bmc/event.log exists on the BMC."""
    r = duthost.shell(
        f"test -f {BMC_EVENT_LOG} && echo yes || echo no",
        module_ignore_errors=True
    )
    return (r.get('stdout', '') or '').strip() == 'yes'


def bmc_event_log_contains(duthost, pattern, tail=30):
    """True iff `/host/bmc/event.log` (tail -N lines) contains pattern (case-insensitive)."""
    r = duthost.shell(
        f"tail -{tail} {BMC_EVENT_LOG} 2>/dev/null | grep -i '{pattern}'",
        module_ignore_errors=True
    )
    return r.get('rc') == 0 and bool((r.get('stdout', '') or '').strip())


def bmc_event_log_line_count(duthost):
    """Return current line count of /host/bmc/event.log, or 0 if absent / unreadable."""
    r = duthost.shell(
        f"test -f {BMC_EVENT_LOG} && wc -l < {BMC_EVENT_LOG} || echo 0",
        module_ignore_errors=True
    )
    try:
        return int((r.get('stdout', '') or '0').strip())
    except ValueError:
        return 0


def bmc_event_log_tail_from(duthost, start_line):
    """Return lines from /host/bmc/event.log starting at start_line+1 (0 → whole file)."""
    r = duthost.shell(
        f"tail -n +{start_line + 1} {BMC_EVENT_LOG} 2>/dev/null",
        module_ignore_errors=True
    )
    return r.get('stdout', '') or ''


def bmc_event_or_syslog_contains(duthost, pattern, since='1 minute ago', tail=5):
    """True iff `pattern` appears in host syslog or /host/bmc/event.log."""
    r = duthost.shell(
        f"grep -hI '{pattern}' /var/log/syslog /var/log/syslog.1 2>/dev/null | tail -{tail}",
        module_ignore_errors=True
    )
    if r.get('rc') == 0 and (r.get('stdout', '') or '').strip():
        return True
    return (pmon_journal_contains(duthost, pattern, since=since, tail=tail)
            or bmc_event_log_contains(duthost, pattern))


def host_syslog_contains(duthost, pattern, tail=5):
    """True iff `pattern` appears in /var/log/syslog (and rotated /var/log/syslog.1)."""
    r = duthost.shell(
        f"grep -hI '{pattern}' /var/log/syslog /var/log/syslog.1 2>/dev/null | tail -{tail}",
        module_ignore_errors=True
    )
    return r.get('rc') == 0 and bool((r.get('stdout', '') or '').strip())


def bmc_event_log_only_contains(duthost, pattern, tail=30):
    """True iff `pattern` is in /host/bmc/event.log AND NOT in /var/log/syslog."""
    return (bmc_event_log_contains(duthost, pattern, tail=tail)
            and not host_syslog_contains(duthost, pattern))


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
