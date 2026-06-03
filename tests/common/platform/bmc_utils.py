"""
Shared helpers for BMC platform tests.

Centralises the sonic-db-cli / journalctl / /host/bmc/event.log / Switch-Host
power-cycle verification patterns repeated across:

  - tests/platform_tests/daemon/test_bmcctld.py
  - tests/platform_tests/daemon/test_thermalctld.py
  - tests/platform_tests/cli/test_show_bmc.py
"""

import logging
from contextlib import contextmanager

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

# SONiC logical DB names (sonic-db-cli accepts these directly).
# Kept as the bmc_utils public constants so callers stay DB-index-agnostic.
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
    """Stop a pmon daemon for the duration of the `with` block; restart on exit.

    Useful when a test injects a value into STATE_DB that the daemon would
    otherwise overwrite (e.g. injecting `SYSTEM_LEAK_STATUS.device_leak_status`
    while thermalctld is running would have thermalctld immediately reset the
    field on its next refresh).
    """
    logger.info("Pausing pmon daemon '%s' for duration of injection", daemon_name)
    duthost.stop_pmon_daemon_service(daemon_name)
    try:
        yield
    finally:
        logger.info("Restarting pmon daemon '%s'", daemon_name)
        duthost.start_pmon_daemon(daemon_name)


# --- Log helpers -----------------------------------------------------------

def pmon_journal_contains(duthost, pattern, since='1 minute ago', tail=5):
    """True iff `journalctl -u pmon --since <since>` contains pattern (case-insensitive)."""
    r = duthost.shell(
        f"journalctl -u pmon --since '{since}' 2>/dev/null"
        f" | grep -i '{pattern}' | tail -{tail}",
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
    """True iff `pattern` appears in pmon journal OR /host/bmc/event.log."""
    return (pmon_journal_contains(duthost, pattern, since=since, tail=tail)
            or bmc_event_log_contains(duthost, pattern))


# --- Leak-sensor injection helpers ----------------------------------------

def inject_leak_sensor(duthost, key, severity, leaking='Yes', leak_sensor_status='Good',
                       sensor_type=None, location=None):
    """HSET a LIQUID_COOLING_INFO row using the daemon's wire schema.

    `key` should already include the table prefix, e.g.
    'LIQUID_COOLING_INFO:test_sensor_xyz'.

    Schema fields (per thermalctld): name, type, location, severity,
    leaking, leak_sensor_status. `sensor_type` (written to the `type`
    field) and `location` are optional and only written when provided.
    """
    fields = {
        'name': key.split(':')[-1],
        'leaking': leaking,
        'leak_sensor_status': leak_sensor_status,
        'severity': severity,
    }
    if sensor_type is not None:
        fields['type'] = sensor_type
    if location is not None:
        fields['location'] = location
    redis_hset(duthost, STATE_DB, key, **fields)


def get_system_leak_status(duthost):
    """Return SYSTEM_LEAK_STATUS:system device_leak_status (stripped, '' if absent)."""
    return redis_hget(duthost, STATE_DB, 'SYSTEM_LEAK_STATUS:system', 'device_leak_status')


def set_system_leak_status(duthost, status):
    """HSET SYSTEM_LEAK_STATUS:system device_leak_status."""
    redis_hset(duthost, STATE_DB, 'SYSTEM_LEAK_STATUS:system', device_leak_status=status)


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
    """Assert the Switch-Host actually rebooted with a BMC-initiated cause.

    - `uptime -s` must advance from `pre_uptime`
    - `show reboot-cause` must report a cause in `valid_causes`
    """
    post_uptime = get_host_uptime(host)
    pytest_assert(post_uptime and post_uptime != pre_uptime,
                  f"Switch-Host uptime did not advance: pre={pre_uptime!r} post={post_uptime!r}")
    cause_out = host.show_and_parse('show reboot-cause')
    cause = (cause_out[0].get('cause') or '').lower() if cause_out else ''
    pytest_assert(any(c in cause for c in valid_causes),
                  f"Switch-Host reboot-cause {cause!r} not in {valid_causes}")
