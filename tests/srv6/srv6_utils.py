import logging
import requests
import ptf.packet as scapy
import ptf.testutils as testutils

from tests.common.helpers.assertions import pytest_assert

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

#
# Send receive packets
#
def runSendReceive(pkt, src_port, exp_pkt, dst_ports, pkt_expected, ptfadapter):
    """
    @summary Send packet and verify it is received/not received on the expected ports
    @param pkt: The packet that will be injected into src_port
    @param src_ports: The port into which the pkt will be injected
    @param exp_pkt: The packet that will be received on one of the dst_ports
    @param dst_ports: The ports on which the exp_pkt may be received
    @param pkt_expected: Indicated whether it is expected to receive the exp_pkt on one of the dst_ports
    @param ptfadapter: The ptfadapter fixture
    """
    # Send the packet and poll on destination ports
    testutils.send(ptfadapter, src_port, pkt, 1)
    logger.debug("Sent packet: " + pkt.summary())
    (index, rcv_pkt) = testutils.verify_packet_any_port(ptfadapter, exp_pkt, dst_ports)
    received = False
    if rcv_pkt:
        received = True
    pytest_assert(received == True)
    logger.debug('index=%s, received=%s' % (str(index), str(received)))
    if received:
        logger.debug("Received packet: " + scapy.Ether(rcv_pkt).summary())
    if pkt_expected:
        logger.debug('Expected packet on dst_ports')
        passed = True if received else False
        logger.debug('Received: ' + str(received))
    else:
        logger.debug('No packet expected on dst_ports')
        passed = False if received else True
        logger.debug('Received: ' + str(received))
    logger.debug('Passed: ' + str(passed))
    return passed