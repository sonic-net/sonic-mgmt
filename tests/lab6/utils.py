import ipaddress
import logging
import pdb

num_dest = 10
gw_ip = ipaddress.IPv4Address('1.1.1.1')
mask = 32
first_ip = ipaddress.IPv4Address('1.1.1.2')
logger = logging.getLogger()


def list_of_routes(num_dest, net_mask, first_ip):
    routes = []
    for i in range(num_dest):
        ip_address = first_ip + i
        routes.append("{}/{}".format(ip_address, net_mask))
    return routes


def add_routes(duthost, num_of_routes, routes):
    for i in range(num_of_routes):
        curr_route = routes[i]
        add_command = 'sudo config route add prefix {} nexthop dev Ethernet0'.format(curr_route)
        duthost.shell(add_command)
        logger.info("{} configured".format(curr_route))


def del_routes(duthost, routes):
    for route in routes:
        if route.strip():
            del_command = 'sudo config route del prefix {} nexthop dev Ethernet0'.format(route)
            duthost.shell(del_command)
            logger.info("{} deleted".format(route))


def config_routes(duthost, num_of_routes):
    routes = list_of_routes(num_of_routes, mask, first_ip)
    add_routes(duthost, num_dest, routes)
    show_command = 'show ip route'
    duthost.shell(show_command)
    del_routes(duthost, routes)
    duthost.shell(show_command)


