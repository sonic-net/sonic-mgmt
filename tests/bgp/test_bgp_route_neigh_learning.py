import pytest
import logging
from tests.common.helpers.assertions import pytest_assert as py_assert
pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.device_type('vs')
]

Logger = logging.getLogger(__name__)

V4_PREFIX = "77.88.99.1"
V4_MASK = "32"


@pytest.fixture(name="setUp", scope="module")
def fixture_setUp(nbrhosts):
    '''
    This fixture setup filters the T1 neigbor names from the nbrhosts. and T the end cleans up the routes
    from the T1 neighbors.
    '''
    data = {}
    data['nbr'] = nbrhosts
    data['T1'] = []
    nbrnames = list(nbrhosts.keys())
    count = 2
    for name in nbrnames:
        if 'T1' in name:
            data['T1'].append(name)
            count -= 1
        if count == 0:
            break
    yield data

    Logger.info("Performing cleanup")
    for name in data['T1']:
        # remove the route in the neighbor T1 eos device
        cmds = ["configure",
                "router bgp 64600",
                "address-family ipv4",
                "no network {}/{}".format(V4_PREFIX, V4_MASK),
                "no interface loopback 1",
                "exit"
                ]
        Logger.info("Route, IP and Loopback 1 remvoed from %s", name)
        data['nbr'][name]['host'].run_command_list(cmds)


def run_bgp_neighbor_route_learning(duthosts, enum_frontend_dut_hostname, data):
    """ Route added on All neighbor should be learned by the DUT"""
    Logger.info("Adding routes on neighbors")

    for name in data['T1']:
        # add a route in the neighbor T1 eos device
        cmds = ["configure",
                "interface loopback 1",
                "ip address {}/{}".format(V4_PREFIX, V4_MASK),
                "exit",
                "router bgp 64600",
                "address-family ipv4",
                "network {}/{}".format(V4_PREFIX, V4_MASK),
                "exit"
                ]
        data['nbr'][name]['host'].run_command_list(cmds)
        Logger.info("Route %s added to :%s", V4_PREFIX, name)

    duthost = duthosts[enum_frontend_dut_hostname]
    #  redis-cli -n 0  hget "ROUTE_TABLE:99.99.99.99" 'nexthop'
    Logger.info("checking  DUT for route %s", V4_PREFIX)
    cmd = "redis-cli -n 0  hget \"ROUTE_TABLE:{}\" 'nexthop'".format(V4_PREFIX)
    result = duthost.shell(cmd)
    result = result['stdout']
    Logger.info("Route table nexthops are %s", result)
    py_assert(result != "", "The route has not propogated to the DUT")
    py_assert(len(result.split(",")) == len(data['T1']), "Some Neighbor did not propogate route to the DUT")


def test_bgp_neighbor_route_learnning(duthosts, enum_frontend_dut_hostname, setUp):
    run_bgp_neighbor_route_learning(duthosts, enum_frontend_dut_hostname, setUp)
