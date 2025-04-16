import logging

# Initialize logger
logger = logging.getLogger(__name__)


def configure_loopback(duthost, loopback_id, ip_addr):
    """Configure a loopback interface with the given IP.

    Args:
        duthost: DUT host object
        loopback_id: Loopback interface ID
        ip_addr: IP address (IPv4 or IPv6) to configure
    """
    try:
        loopback_name = f"Loopback{loopback_id}"
        is_ipv6 = ':' in ip_addr
        prefix_len = '128' if is_ipv6 else '32'

        # Configure loopback interface - try to add it and handle the case if it already exists
        result = duthost.shell(f"config loopback add {loopback_name}", module_ignore_errors=True)
        if result['rc'] != 0 and "already exists" not in result.get('stderr', ''):
            logger.error(f"Failed to add loopback: {result.get('stderr', '')}")
            return False
        elif result['rc'] != 0 and "already exists" in result.get('stderr', ''):
            logger.info(f"Loopback {loopback_name} already exists, continuing with configuration")

        # Configure IP address
        duthost.add_ip_addr_to_port(loopback_name, f"{ip_addr}/{prefix_len}")

        return True

    except Exception as e:
        logger.error(f"Error configuring loopback: {str(e)}")
        return False


def unconfigure_loopback(duthost, loopback_id):
    """Unconfigure a loopback interface and its route.

    Args:
        duthost: DUT host object
        loopback_id: Loopback interface ID
        ip_addr: IP address (IPv4 or IPv6) configured on the loopback
    """
    try:
        loopback_name = f"Loopback{loopback_id}"

        # Remove loopback interface
        result = duthost.shell(f"config loopback del {loopback_name}", module_ignore_errors=True)
        if result['rc'] != 0 and "does not exist" not in result.get('stderr', ''):
            logger.error(f"Failed to remove loopback: {result['stderr']}")
            return False

        return True

    except Exception as e:
        logger.error(f"Error unconfiguring loopback: {str(e)}")
        return False


def configure_static_route(duthost, prefix, next_hop_ip):
    """Configure static route.

    Args:
        duthost: DUT host object
        prefix: Network prefix in CIDR notation (e.g. '192.168.1.0/24' or '2001:db8::/64')
        next_hop_ip: Next hop IP for reaching the prefix
    """
    try:
        is_ipv6 = ':' in prefix
        ip_route_cmd = 'ip -6 route' if is_ipv6 else 'ip route'

        route_cmd = f"{ip_route_cmd} add {prefix} via {next_hop_ip}"
        result = duthost.shell(route_cmd, module_ignore_errors=True)
        if result['rc'] != 0 and "File exists" not in result.get('stderr', ''):
            logger.error(f"Failed to configure route. Error: {result['stderr']}")
            return False

        return True

    except Exception as e:
        logger.error(f"Error configuring route: {str(e)}")
        return False


def unconfigure_static_route(duthost, prefix):
    """Unconfigure static route.

    Args:
        duthost: DUT host object
        prefix: Network prefix in CIDR notation (e.g. '192.168.1.0/24' or '2001:db8::/64')
    """
    try:
        is_ipv6 = ':' in prefix
        ip_route_cmd = 'ip -6 route' if is_ipv6 else 'ip route'

        route_cmd = f"{ip_route_cmd} del {prefix}"
        result = duthost.shell(route_cmd, module_ignore_errors=True)
        if result['rc'] != 0 and "No such process" not in result.get('stderr', ''):
            logger.error(f"Failed to unconfigure route. Error: {result['stderr']}")
            return False
        return True

    except Exception as e:
        logger.error(f"Error unconfiguring route: {str(e)}")
        return False
