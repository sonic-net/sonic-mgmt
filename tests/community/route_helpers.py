"""Helpers for generating and applying bulk static routes on a DUT."""

import logging

logger = logging.getLogger(__name__)

NUM_ROUTES = 40000
ROUTE_PREFIX = "40.0"


def generate_ip_route_commands(action, num_routes, nexthop):
    """
    Build a list of 'ip route' commands for the given action.

    Args:
        action: "add" or "del"
        num_routes: how many /32 routes to generate (starting at 40.0.0.0)
        nexthop: gateway IP address

    Returns:
        list of command strings, e.g.
        ["ip route add 40.0.0.0/32 via 10.0.0.1", ...]
    """
    commands = []
    for i in range(num_routes):
        commands.append("ip route {} 40.0.{}.{}/32 via {}".format(
            action, i // 256, i % 256, nexthop))
    return commands


def apply_routes(duthost, action, num_routes, nexthop):
    """
    Generate route commands and execute them on the DUT in one shot
    using 'ip -batch'.

    Returns the batch text that was applied (useful for logging/debug).
    """
    commands = generate_ip_route_commands(action, num_routes, nexthop)
    batch_text = "\n".join(
        cmd.replace("ip ", "", 1) for cmd in commands
    ) + "\n"
    batch_file = "/tmp/routes_{}.txt".format(action)

    duthost.copy(content=batch_text, dest=batch_file)
    duthost.shell("ip -batch {}".format(batch_file), module_ignore_errors=True)
    return batch_text
