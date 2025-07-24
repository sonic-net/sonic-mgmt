import json
import pytest
import logging
from tests.common.helpers.assertions import pytest_assert as py_assert
from tests.common.devices.eos import EosHost
from tests.common.devices.sonic import SonicHost
from tests.common.utilities import wait_until
pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.device_type('vs')
]

Logger = logging.getLogger(__name__)

V4_PREFIX = "77.88.99.1"
V4_MASK = "32"


@pytest.fixture(name="setUp", scope="module")
def fixture_setUp(nbrhosts, duthosts, enum_frontend_dut_hostname):
    '''
    This fixture setup filters the T1 neighbor names from the nbrhosts. and T the end cleans up the routes
    from the T1 neighbors.
    '''
    duthost = duthosts[enum_frontend_dut_hostname]

    cmd = "vtysh -c 'show ip bgp summary json'"
    bgp_summary_json = json.loads(duthost.shell(cmd)['stdout'])
    bgp_info = {}

    py_assert('ipv4Unicast' in bgp_summary_json)
    py_assert('peers' in bgp_summary_json['ipv4Unicast'])
    for neighbor in bgp_summary_json['ipv4Unicast']['peers']:
        neighbor_info = bgp_summary_json['ipv4Unicast']['peers'][neighbor]
        bgp_info[neighbor_info['desc']] = neighbor_info['remoteAs']

    data = {}
    data['nbr'] = nbrhosts
    data['bgp'] = bgp_info
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
        nbrhost = data['nbr'][name]['host']
        bgp_as_num = data['bgp'][name]
        # remove the route in the neighbor T1 eos device
        if isinstance(nbrhost, EosHost):
            cmds = ["configure",
                    "router bgp {}".format(bgp_as_num),
                    "address-family ipv4",
                    "no network {}/{}".format(V4_PREFIX, V4_MASK),
                    "no interface loopback 1",
                    "exit"
                    ]
            Logger.info("Route, IP and Loopback 1 removed from %s", name)
            nbrhost.run_command_list(cmds)
        elif isinstance(nbrhost, SonicHost):
            cmd = "sudo vtysh -c 'configure terminal' " \
                  f"-c 'router bgp {bgp_as_num}' " \
                  "-c 'address-family ipv4 unicast' " \
                  f"-c 'no network {V4_PREFIX}/{V4_MASK}' " \
                  "-c 'exit-address-family'"
            result = nbrhost.shell(cmd)
            py_assert(result['rc'] == 0, "BGP network not removed")
            cmd = f"sudo config interface ip remove Loopback1 {V4_PREFIX}/{V4_MASK}"
            result = nbrhost.shell(cmd)
            py_assert(result['rc'] == 0, "loopback interface not removed")
        else:
            raise ValueError("Unsupported neighbor type")


def _check_route_propagation(duthost, data):
    cmd = "redis-cli -n 0 hget \"ROUTE_TABLE:{}\" 'nexthop'".format(V4_PREFIX)
    result = duthost.shell(cmd)
    if result['stdout'] == "":
        return None
    Logger.info("Route table nexthops are %s", result)
    nexthops = result['stdout'].split(",")
    if len(nexthops) != len(data['T1']):
        return False
    return True


def run_bgp_neighbor_route_learning(duthosts, enum_frontend_dut_hostname, data):
    """ Route added on All neighbor should be learned by the DUT"""
    Logger.info("Adding routes on neighbors")

    for name in data['T1']:
        bgp_as_num = data['bgp'][name]
        nbrhost = data['nbr'][name]['host']
        cmds = []
        # add a route in the neighbor T1 eos device
        if isinstance(nbrhost, EosHost):
            cmds = ["configure",
                    "interface loopback 1",
                    "ip address {}/{}".format(V4_PREFIX, V4_MASK),
                    "exit",
                    "router bgp {}".format(bgp_as_num),
                    "address-family ipv4",
                    "network {}/{}".format(V4_PREFIX, V4_MASK),
                    "exit"
                    ]
            nbrhost.run_command_list(cmds)
        elif isinstance(nbrhost, SonicHost):
            # Create and configure loopback interface
            cmd = f"sudo config interface ip add Loopback1 {V4_PREFIX}/{V4_MASK}"
            result = nbrhost.shell(cmd)
            py_assert(result['rc'] == 0, "Failed to configure loopback interface")
            # Configure BGP network
            cmd = "sudo vtysh -c 'configure terminal' " \
                  f"-c 'router bgp {bgp_as_num}' " \
                  "-c 'address-family ipv4 unicast' " \
                  f"-c 'network {V4_PREFIX}/{V4_MASK}' " \
                  "-c 'exit-address-family'"
            result = nbrhost.shell(cmd)
            py_assert(result['rc'] == 0, "Failed to configure BGP network")
        else:
            raise ValueError("Unsupported neighbor type")

    duthost = duthosts[enum_frontend_dut_hostname]
    Logger.info("checking  DUT for route %s", V4_PREFIX)
    is_route_propagated = wait_until(10, 2, 0, lambda: _check_route_propagation(duthost, data))
    py_assert(is_route_propagated, "Route did not propagate to the DUT")


def test_bgp_neighbor_route_learnning(duthosts, enum_frontend_dut_hostname, setUp):
    run_bgp_neighbor_route_learning(duthosts, enum_frontend_dut_hostname, setUp)
