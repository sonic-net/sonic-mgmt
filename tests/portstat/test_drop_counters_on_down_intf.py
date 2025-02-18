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
    interfaces_status = duthost.shell("show interface status")['stdout_lines'].split("\n")[2:]
    # find an oper up and admin up interface
    intf = ''
    for line in interfaces_status:
        if line.count('up') >= 2:
            intf = line.split()[0]
            break
    if len(intf) == 0:
        pytest.skip('No oper up and admin up interface found')

    # get the corresponding neighbor and neighbor's interface
    neighbor_info = duthost.shell("show lldp neighbors {}".format(intf))['stdout_lines'].split("\n")[3:]
    for line in neighbor_info:
        if "SysName" in line:
            neighbor = line.split()[1]
        elif "PortID" in line:
            neighbor_intf = line.split()[2]

    # get the neighbor's IP
    bgp_neighbors = duthost.shell("show ip bgp summary")['stdout_lines'].split('\n')
    for line in bgp_neighbors:
        if neighbor in line:
            neighbor_ip = line.split()[0]
            break

    logger.info('DUT Interface: {}, Neighbor: {}, Neighbor Interface: {}, Neighbor IP: {}'
                .format(intf, neighbor, neighbor_intf, neighbor_ip))

    # shutdown the interface of neighbor
    nbrhosts[neighbor].shutdown(neighbor_intf)
    time.sleep(2)

    # collect portstat before sleeping
    before_portstat = parse_portstat(duthost.command('portstat -i {}'.format(intf))['stdout_lines'])

    # Ping the neighbor from DUT
    duthost.command('ping {} -c 10'.format(neighbor_ip), ignore_errors=True)

    # collect portstat after sleeping
    after_portstat = parse_portstat(duthost.command('portstat -i {}'.format(intf))['stdout_lines'])

    # Assert that TX_DROP counters are not incremented
    pytest_assert(before_portstat[intf]['tx_drop'] == after_portstat[intf]['tx_drop'],
                  'TX_DROP counters should not be incremented when the interface is administratively down')

    # recover the neighbor interface
    nbrhosts[neighbor].no_shutdown(neighbor_intf)
