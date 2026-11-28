import ipaddress
import logging
import re
import time

import pytest

from tests.common.plugins.proc_mem_cpu_monitor.top_parser import parse_free_m_used, parse_top_cpu_summary
from tests.common.utilities import wait_until

pytestmark = [
    pytest.mark.topology("any")
]

logger = logging.getLogger(__name__)

INTERFACE = "Ethernet0"
INTERFACE_IP = "192.168.100.1/30"
NEXT_HOP = "192.168.100.2"
ROUTE_BASE = "192.168.128.0/17"   # split into /24 test prefixes; allows up to 128 routes
ROUTE_COUNT = 100
ROUTE_TIMEOUT = 60
CPU_LIMIT_PERCENT = 90
MEM_LIMIT_PERCENT = 90


def generate_prefixes(count):
    """Return `count` /24 prefixes taken from ROUTE_BASE: 192.168.128.0/24, 192.168.129.0/24, ..."""
    subnets = ipaddress.ip_network(ROUTE_BASE).subnets(new_prefix=24)
    return [str(next(subnets)) for _ in range(count)]


def count_routes(duthost, prefixes):
    """Return how many of the given prefixes are installed as S>* in 'show ip route'."""
    output = duthost.shell("show ip route")["stdout"]
    # Lines look like "S>*192.168.128.0/24 [1/0] via ..."; some FRR outputs put a space after "S>*".
    installed = set(re.findall(r"^S>\*\s*(\S+)", output, re.MULTILINE))
    return len(installed & set(prefixes))


def config_routes(duthost, prefixes, op, ignore_errors=False):
    """Add or delete static routes with the config CLI, all in one shell call."""
    cmds = [f"sudo config route {op} prefix {prefix} nexthop {NEXT_HOP}" for prefix in prefixes]
    duthost.shell(" ; ".join(cmds) if ignore_errors else " && ".join(cmds), module_ignore_errors=ignore_errors)


def get_cpu_mem_usage(duthost):
    """Return (cpu_used_percent, mem_used_percent) on the DUT."""
    # top's first sample is the average since boot, so take the %Cpu line of the second sample.
    output = duthost.shell("top -bn2 -d 1 | grep '^%Cpu' | tail -1; free -m")["stdout"]
    return parse_top_cpu_summary(output)["busy_pct"], parse_free_m_used(output)["used_pct"]


def wait_for_route_count(duthost, prefixes, expected):
    """Wait until exactly `expected` of the prefixes are installed; fail the test on timeout."""
    done = wait_until(ROUTE_TIMEOUT, 1, 0, lambda: count_routes(duthost, prefixes) == expected)
    assert done, (f"Expected {expected} routes, found {count_routes(duthost, prefixes)} "
                  f"after {ROUTE_TIMEOUT} seconds")


@pytest.fixture
def setup_static_route(duthost):
    """Add an IP on INTERFACE so NEXT_HOP is reachable; remove leftover routes and the IP on teardown."""
    prefixes = generate_prefixes(ROUTE_COUNT)
    duthost.shell(f"sudo config interface ip add {INTERFACE} {INTERFACE_IP}")
    yield prefixes
    # pytest runs this teardown even when the test fails. Check CONFIG_DB (not 'show ip route'):
    # a route can be configured without being installed, and it still has to be removed.
    config_keys = duthost.shell("sonic-db-cli CONFIG_DB keys 'STATIC_ROUTE|*'")["stdout"]
    leftovers = [prefix for prefix in prefixes if f"|{prefix}" in config_keys]
    if leftovers:
        config_routes(duthost, leftovers, "del", ignore_errors=True)
    duthost.shell(f"sudo config interface ip remove {INTERFACE} {INTERFACE_IP}", module_ignore_errors=True)


def test_static_route_timing(duthost, setup_static_route):
    """
    Add static routes, measure how long until they appear in 'show ip route',
    check CPU and memory, then delete them and measure how long until they are gone.
    """
    prefixes = setup_static_route

    cpu_before, mem_before = get_cpu_mem_usage(duthost)
    logger.info(f"Before adding routes: CPU {cpu_before:.1f}%, memory {mem_before:.1f}%")

    start = time.time()
    config_routes(duthost, prefixes, "add")
    wait_for_route_count(duthost, prefixes, len(prefixes))
    logger.info(f"{len(prefixes)} static routes appeared in {time.time() - start:.2f} seconds")

    cpu_after, mem_after = get_cpu_mem_usage(duthost)
    logger.info(f"After adding routes: CPU {cpu_after:.1f}%, memory {mem_after:.1f}%")
    assert cpu_after < CPU_LIMIT_PERCENT, f"CPU usage {cpu_after:.1f}% is above {CPU_LIMIT_PERCENT}%"
    assert mem_after < MEM_LIMIT_PERCENT, f"Memory usage {mem_after:.1f}% is above {MEM_LIMIT_PERCENT}%"

    start = time.time()
    config_routes(duthost, prefixes, "del")
    wait_for_route_count(duthost, prefixes, 0)
    logger.info(f"{len(prefixes)} static routes were removed in {time.time() - start:.2f} seconds")
