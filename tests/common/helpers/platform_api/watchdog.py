""" This module provides interface to interact with DUT watchdog remotely """

import json
import logging

logger = logging.getLogger(__name__)


def watchdog_api(conn, name, args=None):
    if args is None:
        args = []
    conn.request('POST', '/platform/chassis/watchdog/{}'.format(name), json.dumps({'args': args}))
    resp = conn.getresponse()
    res = json.loads(resp.read())['res']
    logger.info('Executing watchdog API: "{}", arguments: "{}", result: "{}"'.format(name, args, res))
    return res


def arm(conn, seconds):
    return watchdog_api(conn, 'arm', [seconds])


def is_armed(conn):
    return watchdog_api(conn, 'is_armed')


def disarm(conn):
    return watchdog_api(conn, 'disarm')


def get_remaining_time(conn):
    return watchdog_api(conn, 'get_remaining_time')


# BMC-specific watchdog helpers (based on PR sonic-buildimage#26002)

def get_watchdog_armed_status(duthost):
    """Get watchdog armed status from watchdogutil"""
    result = duthost.shell("watchdogutil status", module_ignore_errors=True)
    if result['rc'] != 0:
        return None
    output = result['stdout'].strip().lower()
    return "armed" in output


def get_watchdog_remaining_time(duthost):
    """Extract remaining time from watchdog status (in seconds)"""
    import re
    result = duthost.shell("watchdogutil status", module_ignore_errors=True)
    if result['rc'] != 0:
        return None
    match = re.search(r"Time remaining:\s*(\d+)\s*seconds", result['stdout'])
    if match:
        return int(match.group(1))
    return None


def check_watchdog_service_status(duthost, service_name="watchdog-petting"):
    """Check if watchdog systemd service is active"""
    result = duthost.shell(f"systemctl is-active {service_name}", module_ignore_errors=True)
    if result['rc'] == 0:
        return result['stdout'].strip()
    return None


def check_watchdog_logs_in_bmc_dir(duthost):
    """Verify watchdog logs are in /host/bmc/ directory (persistent storage)"""
    result = duthost.shell("ls -la /host/bmc/ | grep -i watch", module_ignore_errors=True)
    return result['rc'] == 0 and result['stdout'].strip() != ""


def check_bmc_directory_exists(duthost):
    """Check if BMC directory exists for log storage"""
    result = duthost.shell("test -d /host/bmc && echo 'exists' || echo 'missing'",
                           module_ignore_errors=True)
    return "exists" in result['stdout']
