import os
import math
from utilities.common import ipcheck


def is_scmd(delay_factor):
    if delay_factor > 2:
        return True
    return False


def get_delay_factor(current):
    try: factor = float(os.getenv("SPYTEST_NETMIKO_DELAY_FACTOR", "1"))
    except Exception: factor = 1.0
    return current * factor


def max_time_to_delay_factor(max_time):
    return int(math.ceil((max_time * 1.0) / 100))


def max_time_from_delay_factor(delay_factor):
    return int(delay_factor * 100)


def check_console_ip(ip, logf):
    rv = bool(os.getenv("SPYTEST_DEVICE_SKIP_REACHABLE_CHECK", "0") != "0")
    return rv or (ip is None) or ipcheck(ip, 10, logf, "CONSOLE ", 5)
