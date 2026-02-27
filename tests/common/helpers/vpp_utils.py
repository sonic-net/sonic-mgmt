"""
Utilities for VPP (Vector Packet Processing) ASIC type.

Provides helpers to poll VPP FIB summary and wait until route
programming has converged (output stabilises between consecutive polls).
"""

import logging
import time

logger = logging.getLogger(__name__)

VPP_FIB_CMD_V4 = "docker exec syncd vppctl show ip fib summary"
VPP_FIB_CMD_V6 = "docker exec syncd vppctl show ip6 fib summary"


def get_vpp_fib_summary(duthost, ipv6=False):
    """
    Run ``vppctl show ip[6] fib summary`` on the DUT and return stdout.

    Args:
        duthost: DUT host object.
        ipv6 (bool): If True, query IPv6 FIB; otherwise IPv4.

    Returns:
        str: Raw command output (stdout).
    """
    cmd = VPP_FIB_CMD_V6 if ipv6 else VPP_FIB_CMD_V4
    res = duthost.shell(cmd)
    return res["stdout"].strip()


def wait_for_vpp_route_programming(
    duthost,
    ipv6=False,
    timeout=120,
    interval=1,
):
    """
    Poll VPP FIB summary until the output stabilises (no change between
    two consecutive polls), indicating that route programming is complete.

    Args:
        duthost: DUT host object.
        ipv6 (bool): If True, poll IPv6 FIB; otherwise IPv4.
        timeout (int): Maximum seconds to wait before giving up.
        interval (int): Seconds between consecutive polls.

    Returns:
        bool: True if output stabilised within *timeout*, False otherwise.
    """
    family = "IPv6" if ipv6 else "IPv4"
    logger.info(
        "Waiting for VPP %s route programming to stabilise "
        "(timeout=%ds, interval=%ds)",
        family, timeout, interval,
    )

    prev_output = None
    deadline = time.time() + timeout

    while time.time() < deadline:
        current_output = get_vpp_fib_summary(duthost, ipv6=ipv6)

        if prev_output is not None and current_output == prev_output:
            logger.info(
                "VPP %s FIB summary stabilised after %.1fs",
                family, timeout - (deadline - time.time()),
            )
            return True

        prev_output = current_output
        time.sleep(interval)

    logger.warning(
        "VPP %s FIB summary did not stabilise within %ds", family, timeout
    )
    return False
