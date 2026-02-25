import logging
from tests.common.devices.eos import EosHost

# Initialize logger
logger = logging.getLogger(__name__)


def configure_loopback(host, loopback_id, ip_addr):
    """Configure a loopback interface with the given IP.

    Args:
        host: DUT host object (SONiC or EOS)
        loopback_id: Loopback interface ID
        ip_addr: IP address (IPv4 or IPv6) to configure
    """
    if isinstance(host, EosHost):
        # For cEOS, use Arista EOS configuration commands
        try:
            loopback_name = f"Loopback{loopback_id}"
            is_ipv6 = ':' in ip_addr
            prefix_len = '128' if is_ipv6 else '32'

            if is_ipv6:
                ip_cmd = f"ipv6 address {ip_addr}/{prefix_len}"
            else:
                ip_cmd = f"ip address {ip_addr}/{prefix_len}"

            interface_commands = [
                ip_cmd,
                "no shutdown"
            ]

            result = host.eos_config(
                lines=interface_commands,
                parents=[f"interface {loopback_name}"]
            )
            if result.get('failed', False):  # type: ignore
                logger.error(f"Failed to configure EOS loopback: {result}")
                return False

            logger.info(f"Successfully configured loopback {loopback_name} with IP {ip_addr} on EOS host")
            return True

        except Exception as e:
            logger.error(f"Error configuring EOS loopback: {str(e)}")
            return False
    else:
        try:
            loopback_name = f"Loopback{loopback_id}"
            is_ipv6 = ':' in ip_addr
            prefix_len = '128' if is_ipv6 else '32'

            # Configure loopback interface - try to add it and handle the case if it already exists
            result = host.shell(f"config loopback add {loopback_name}", module_ignore_errors=True)
            if result['rc'] != 0 and "already exists" not in result.get('stderr', ''):
                logger.error(f"Failed to add loopback: {result.get('stderr', '')}")
                return False
            elif result['rc'] != 0 and "already exists" in result.get('stderr', ''):
                logger.info(f"Loopback {loopback_name} already exists, continuing with configuration")

            # Configure IP address
            host.add_ip_addr_to_port(loopback_name, f"{ip_addr}/{prefix_len}")

            return True

        except Exception as e:
            logger.error(f"Error configuring loopback: {str(e)}")
            return False


def unconfigure_loopback(host, loopback_id):
    """Unconfigure a loopback interface and its route.

    Args:
        host: DUT host object (SONiC or EOS)
        loopback_id: Loopback interface ID
    """
    if isinstance(host, EosHost):
        # For cEOS, use Arista EOS configuration commands
        try:
            loopback_name = f"Loopback{loopback_id}"
            commands = [f"no interface {loopback_name}"]

            result = host.eos_config(lines=commands)
            if result.get('failed', False):  # type: ignore
                logger.error(f"Failed to unconfigure EOS loopback: {result}")
                return False

            logger.info(f"Successfully unconfigured loopback {loopback_id} on EOS host")
            return True

        except Exception as e:
            logger.error(f"Error unconfiguring EOS loopback: {str(e)}")
            return False
    else:
        try:
            loopback_name = f"Loopback{loopback_id}"

            # Remove loopback interface
            result = host.shell(f"config loopback del {loopback_name}", module_ignore_errors=True)
            if result['rc'] != 0 and "does not exist" not in result.get('stderr', ''):
                logger.error(f"Failed to remove loopback: {result['stderr']}")
                return False

            return True

        except Exception as e:
            logger.error(f"Error unconfiguring loopback: {str(e)}")
            return False


def configure_static_route(host, prefix, next_hop_ip):
    """Configure static route.

    Args:
        host: DUT host object (SONiC or EOS)
        prefix: Network prefix in CIDR notation (e.g. '192.168.1.0/24' or '2001:db8::/64')
        next_hop_ip: Next hop IP for reaching the prefix
    """
    if isinstance(host, EosHost):
        # For cEOS, use Arista EOS configuration commands
        try:
            is_ipv6 = ':' in prefix

            # EOS configuration commands (note: EOS uses different syntax than Linux)
            # EOS format: "ip route <prefix> <next_hop>" (no "via" keyword)
            if is_ipv6:
                route_cmd = f"ipv6 route {prefix} {next_hop_ip}"
            else:
                route_cmd = f"ip route {prefix} {next_hop_ip}"

            result = host.eos_config(lines=[route_cmd])
            if result.get('failed', False):  # type: ignore
                logger.error(f"Failed to configure EOS static route: {result}")
                return False

            logger.info(f"Successfully configured static route {prefix} via {next_hop_ip} on EOS host")
            return True

        except Exception as e:
            logger.error(f"Error configuring EOS static route: {str(e)}")
            return False
    else:
        try:
            is_ipv6 = ':' in prefix
            ip_route_cmd = 'ip -6 route' if is_ipv6 else 'ip route'

            route_cmd = f"{ip_route_cmd} add {prefix} via {next_hop_ip}"
            result = host.shell(route_cmd, module_ignore_errors=True)
            if result['rc'] != 0 and "File exists" not in result.get('stderr', ''):
                logger.error(f"Failed to configure route. Error: {result['stderr']}")
                return False

            return True

        except Exception as e:
            logger.error(f"Error configuring route: {str(e)}")
            return False


def unconfigure_static_route(host, prefix):
    """Unconfigure static route.

    Args:
        host: DUT host object (SONiC or EOS)
        prefix: Network prefix in CIDR notation (e.g. '192.168.1.0/24' or '2001:db8::/64')
    """
    if isinstance(host, EosHost):
        # For cEOS, use Arista EOS configuration commands
        try:
            is_ipv6 = ':' in prefix

            if is_ipv6:
                route_cmd = f"no ipv6 route {prefix}"
            else:
                route_cmd = f"no ip route {prefix}"

            result = host.eos_config(lines=[route_cmd])
            if result.get('failed', False):  # type: ignore
                logger.error(f"Failed to unconfigure EOS static route: {result}")
                return False

            logger.info(f"Successfully unconfigured static route {prefix} on EOS host")
            return True

        except Exception as e:
            logger.error(f"Error unconfiguring EOS static route: {str(e)}")
            return False
    else:
        try:
            is_ipv6 = ':' in prefix
            ip_route_cmd = 'ip -6 route' if is_ipv6 else 'ip route'

            route_cmd = f"{ip_route_cmd} del {prefix}"
            result = host.shell(route_cmd, module_ignore_errors=True)
            if result['rc'] != 0 and "No such process" not in result.get('stderr', ''):
                logger.error(f"Failed to unconfigure route. Error: {result['stderr']}")
                return False
            return True

        except Exception as e:
            logger.error(f"Error unconfiguring route: {str(e)}")
            return False
