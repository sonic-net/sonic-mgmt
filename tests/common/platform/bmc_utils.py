"""
Shared helpers for BMC platform tests.

Centralises the sonic-db-cli / journalctl / /host/bmc/event.log / Switch-Host
power-cycle verification patterns repeated across:

  - tests/platform_tests/daemon/test_bmcctld.py
  - tests/platform_tests/daemon/test_thermalctld.py
  - tests/platform_tests/cli/test_show_bmc.py
"""

import logging

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

def redis_hget(duthost, db, key, field):
    """Return HGET value (stripped str) or '' if absent."""
    r = duthost.shell(
        f"sonic-db-cli {db} HGET '{key}' {field}",
        module_ignore_errors=True
    )
    return (r.get('stdout', '') or '').strip()


def redis_hgetall(duthost, db, key):
    """Return HGETALL as dict; empty dict on miss."""
    r = duthost.shell(
        f"sonic-db-cli {db} HGETALL '{key}'",
        module_ignore_errors=True
    )
    out = (r.get('stdout', '') or '').strip()
    if not out:
        return {}
    # sonic-db-cli HGETALL returns Python-dict repr; fall back to line pairs
    # for back-compat with raw redis-cli style output.
    if out.startswith('{') and out.endswith('}'):
        try:
            import ast
            parsed = ast.literal_eval(out)
            if isinstance(parsed, dict):
                return {str(k): str(v) for k, v in parsed.items()}
        except (ValueError, SyntaxError):
            pass
    lines = out.split('\n')
    return {lines[i]: lines[i + 1] for i in range(0, len(lines), 2) if i + 1 < len(lines)}


def redis_hset(duthost, db, key, **fields):
    """HSET one or more field=value pairs."""
    if not fields:
        return
    parts = ' '.join(f"{k} {v}" for k, v in fields.items())
    duthost.shell(
        f"sonic-db-cli {db} HSET '{key}' {parts}",
        module_ignore_errors=True
    )


def redis_del(duthost, db, *keys):
    """DEL one or more keys."""
    for k in keys:
        duthost.shell(f"sonic-db-cli {db} DEL '{k}'", module_ignore_errors=True)


def redis_keys(duthost, db, pattern):
    """KEYS pattern → list of key names."""
    r = duthost.shell(
        f"sonic-db-cli {db} KEYS '{pattern}'",
        module_ignore_errors=True
    )
    out = (r.get('stdout', '') or '').strip()
    return out.split('\n') if out else []


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
                       extra_fields=None):
    """HSET a LIQUID_COOLING_INFO row using the daemon's wire schema.

    `key` should already include the table prefix, e.g.
    'LIQUID_COOLING_INFO:test_sensor_xyz'.
    """
    fields = {
        'name': key.split(':')[-1],
        'leaking': leaking,
        'leak_sensor_status': leak_sensor_status,
        'severity': severity,
    }
    if extra_fields:
        fields.update(extra_fields)
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
