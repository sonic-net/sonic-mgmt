from netaddr import IPNetwork
import json

ZERO_ADDR = r'0.0.0.0/0'

def generate_ips(num, prefix, exclude_ips):
    """ Generate random ips within prefix """
    prefix = IPNetwork(prefix)
    exclude_ips.append(prefix.broadcast)
    exclude_ips.append(prefix.network)
    available_ips = list(prefix)

    if len(available_ips) - len(exclude_ips)< num:
        raise Exception("Not enough available IPs")

    generated_ips = []
    for available_ip in available_ips:
        if available_ip not in exclude_ips:
            generated_ips.append(str(available_ip) + '/' + str(prefix.prefixlen))
        if len(generated_ips) == num:
            break

    return generated_ips


def route_through_default_routes(host, ip_addr):
    """
    @summary: Check if a given ip targets to default route
    @param host: The duthost
    @param ip_addr: The ip address to check
    @return: True if the given up goes to default route, False otherwise
    """
    output = host.shell("show ip route {} json".format(ip_addr))['stdout']
    routes_info = json.loads(output)
    ret = True
    
    for prefix in routes_info.keys():
        if prefix != ZERO_ADDR:
            ret = False
            break
    return ret


def generate_ip_through_default_route(host):
    """
    @summary: Generate a random IP address routed through default routes
    @param host: The duthost
    @return: A str, on None if non ip is found in given range
    """
    for leading in range(11, 255):
        ip_addr = generate_ips(1, "{}.0.0.1/24".format(leading), [])[0]
        if route_through_default_routes(host, ip_addr):
            return ip_addr
    return None
