import logging
import requests

logger = logging.getLogger(__name__)


#
# Helper func for print a set of lines
#
def print_lines(outlines):
    for line in outlines:
        logger.debug(line)


#
# Util functions for announce / withdraw routes from ptf docker.
#
def announce_route(ptfip, neighbor, route, nexthop, port):
    change_route("announce", ptfip, neighbor, route, nexthop, port)


def withdraw_route(ptfip, neighbor, route, nexthop, port):
    change_route("withdraw", ptfip, neighbor, route, nexthop, port)


def change_route(operation, ptfip, neighbor, route, nexthop, port):
    url = "http://%s:%d" % (ptfip, port)
    data = {"command": "neighbor %s %s route %s next-hop %s" % (neighbor, operation, route, nexthop)}
    r = requests.post(url, data=data)
    assert r.status_code == 200


#
# Skip some BGP neighbor check
#
def skip_bgp_neighbor_check(neighbor):
    skip_addresses = ['2064:100::1d', '2064:200::1e', '2064:300::1f']
    for addr in skip_addresses:
        if neighbor == addr:
            return True
    
    return False


#
# Helper func to check if a list of BGP neighbors are up
#
def check_bgp_neighbors_func(nbrhost, neighbors, vrf=""):
    cmd = "vtysh -c 'show bgp summary'"
    if vrf != "":
        cmd = "vtysh -c 'show bgp vrf {} summary'".format(vrf)
    res = nbrhost.command(cmd)["stdout_lines"]
    found = 0
    for neighbor in neighbors:
        if skip_bgp_neighbor_check(neighbor):
            logger.debug("Skip {} check".format(neighbor))
            found = found + 1
            continue
            
        for line in res:
            if neighbor in line:
                arr = line.split()
                pfxrcd = arr[9]
                try: 
                    int(pfxrcd)
                    found = found + 1
                    logger.debug("{} ==> BGP neighbor is up and gets pfxrcd {}".format(line, pfxrcd))
                except ValueError:
                    logger.debug("{} ==> BGP neighbor state {}, not up".format(line, pfxrcd))
    return len(neighbors) == found


#
# Checke BGP neighbors
#
def check_bgp_neighbors(nbrhost, neighbors, vrf=""):
    pytest_assert(check_bgp_neighbors_func(nbrhost, neighbors, vrf))


#
# Helper function to count number of Ethernet interfaces
#
def find_node_interfaces(nbrhost):
    cmd = "show version"
    res = nbrhost.command(cmd)["stdout_lines"]
    hwsku = ""
    for line in res:
        if "HwSKU:" in line:
            logger.debug("{}".format(line))
            sarr = line.split()
            hwsku = sarr[1]
            break

    cmd = "show interface status"
    res = nbrhost.command(cmd)["stdout_lines"]
    found = 0
    for line in res:
        logger.debug("{}".format(line))
        if "Ethernet" in line:
            found = found + 1

    return found, hwsku