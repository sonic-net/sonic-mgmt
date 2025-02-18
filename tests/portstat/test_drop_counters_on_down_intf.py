import logging
import pytest
import time

from tests.common.helpers.assertions import pytest_assert
from tests.common.portstat_utilities import parse_portstat

logger = logging.getLogger('__name__')

pytestmark = [
    pytest.mark.topology('any')
]


def test_tx_drop_counters_on_oper_down_intf(duthosts, enum_rand_one_per_hwsku_frontend_hostname, nbrhosts):
    """
    Test that TX_DROP counters are not incremented when the interface is oper down.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    interfaces = duthost.shell("show lldp table")['stdout_lines'][3:]
    # find an oper up and admin up interface
    if len(interfaces) == 0:
        pytest.skip('No interfaces connected to switch neighbors found')
    intf = interfaces[0].split()[0]
    neighbor = interfaces[0].split()[1]
    neighbor_intf = interfaces[0].split()[2]

    assert neighbor, "Cannot find the hostname of neighbor connected to {}".format(intf)
    assert neighbor_intf, "Cannot find the interface name of neighbor connected to {}".format(intf)

    # get the neighbor's IP
    bgp_neighbors = duthost.shell("show ip bgp summary")['stdout_lines']
    for line in bgp_neighbors:
        if neighbor in line:
            neighbor_ip = line.split()[0]
            break
    assert neighbor_ip, "Cannot find the IP address of neighbor"

    logger.info('DUT Interface: {}, Neighbor: {}, Neighbor Interface: {}, Neighbor IP: {}'
                .format(intf, neighbor, neighbor_intf, neighbor_ip))

    # shutdown the interface of neighbor
    nbrhosts[neighbor]['host'].shutdown(neighbor_intf)
    time.sleep(2)

    # collect portstat before sleeping
    before_portstat = parse_portstat(duthost.command('portstat -i {}'.format(intf))['stdout_lines'])

    # Ping the neighbor from DUT
    duthost.command('ping {} -c 10'.format(neighbor_ip), module_ignore_errors=True)

    # collect portstat after sleeping
    after_portstat = parse_portstat(duthost.command('portstat -i {}'.format(intf))['stdout_lines'])

    # Assert that TX_DROP counters are not incremented
    pytest_assert(before_portstat[intf]['tx_drp'] == after_portstat[intf]['tx_drp'],
                  'TX_DROP counters should not be incremented when the interface is administratively down')

    # recover the neighbor interface
    nbrhosts[neighbor]['host'].no_shutdown(neighbor_intf)
