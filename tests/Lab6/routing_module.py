import utils
import logging

logger = logging.getLogger()


@utils.timing_decorator
def setup_routes(duthost, num_routes):
    routes = generate_routes(num_routes)
    configure_routes(routes, duthost)
    switch_routes = get_routes(duthost)
    assert switch_routes == routes
    logger.info("\n \n \n Routes After Adding Are: {} \n \n \n".format(switch_routes))


@utils.timing_decorator
def generate_routes(num_routes):
    routes = []
    start_ip = utils.START_IP
    subnet_mask = utils.SUBNET_MASK

    for i in range(num_routes):
        current_ip = start_ip + i
        current_subnet = '{}/{}'.format(current_ip, subnet_mask)
        routes.append(current_subnet)
    return routes


@utils.timing_decorator
def configure_routes(routes, duthost):
    for i in range(len(routes)):
        subnet_address = routes[i]
        add_command = "sudo config route add prefix {} nexthop dev Ethernet0".format(subnet_address)
        duthost.shell(add_command)

        if i >= (len(routes) // 2):
            # Check memory in the middle of adding
            memory_command = "free -h"
            res_dict = duthost.shell(memory_command)
            lines_str = "\n".join(res_dict["stdout_lines"])
            utils.MEM_LIST.append("Memory HALF THROUGH Adding : \n" + lines_str)


@utils.timing_decorator
def remove_routes(duthost):
    clean_routes(duthost)
    switch_routes = get_routes(duthost)
    assert switch_routes == []
    logger.info("\n \n \n Routes After Removing Are: {} \n \n \n".format(switch_routes))


def get_routes(duthost):
    # The command takes the output of the command "show ip route" and turns
    # it into a list of ip/subnet_mask for the static routes:
    # 1. First 6 lines are trash
    # 2. Static routes start with ^S
    # 3. The first field $1 is the IP
    # 4. first 4 characters in each line are trash
    command = 'show ip route | tail -n +6 | grep \'^S\' | awk \'{print $1}\' | cut -c 4-'

    res_dict = duthost.shell(command)
    return res_dict["stdout_lines"]


@utils.timing_decorator
def clean_routes(duthost):
    # Get the list of routes and delete each one
    routes = get_routes(duthost)
    for i, route in enumerate(routes):
        if route.strip():
            delete_command = "sudo config route del prefix {} nexthop dev Ethernet0".format(route)
            duthost.shell(delete_command)
        if i >= (len(routes) // 2):
            # Check memory in the middle of adding
            memory_command = "free -h"
            res_dict = duthost.shell(memory_command)
            lines_str = "\n".join(res_dict["stdout_lines"])
            utils.MEM_LIST.append("Memory HALF THROUGH Deleting : \n" + lines_str)

    logger.info("{} routes were Deleted Successfully.".format(len(routes)))
