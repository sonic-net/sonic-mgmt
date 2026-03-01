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

AFI_CONFIG = {
    "v4": {
        "afi": "ipv4Unicast",
        "prefix": "77.88.99.1",
        "mask": "32",
        "loopback_cmd_eos": "ip address {}/{}",
        "afi_cmd_eos": "address-family ipv4",
        "afi_cmd_sonic": "address-family ipv4 unicast",
    },
    "v6": {
        "afi": "ipv6Unicast",
        "prefix": "2001:db8:100::1",
        "mask": "128",
        "loopback_cmd_eos": "ipv6 address {}/{}",
        "afi_cmd_eos": "address-family ipv6",
        "afi_cmd_sonic": "address-family ipv6 unicast",
    },
}


def add_route_to_nbr(data, name, prefix, mask, afi_cmd_eos, loopback_cmd_eos):
    loopback = 1
    vrf = "default"
    if data["nbr"][name].get("is_multi_vrf_peer", False):
        vrf = name
        loopback += data["nbr"][name]["multi_vrf_data"]["intf_offset"]

    bgp_as_num = data['bgp'][name]
    # add a route in the neighbor T1 eos device
    cmds = ["configure",
            "interface loopback {}".format(loopback),
            "vrf {}".format(vrf),
            loopback_cmd_eos.format(prefix, mask),
            "exit",
            "router bgp {}".format(bgp_as_num),
            "vrf {}".format(vrf),
            afi_cmd_eos,
            "network {}/{}".format(prefix, mask),
            "exit",
            ]
    data['nbr'][name]['host'].run_command_list(cmds)
    Logger.info("Route %s added to vrf %s on %s", prefix, vrf, name)


def rm_route_from_nbr(data, name, prefix, mask, afi_cmd_eos):
    loopback = 1
    vrf = "default"
    if data["nbr"][name].get("is_multi_vrf_peer", False):
        vrf = name
        loopback += data["nbr"][name]["multi_vrf_data"]["intf_offset"]

    bgp_as_num = data['bgp'][name]
    # remove the route in the neighbor T1 eos device
    cmds = ["configure",
            "router bgp {}".format(bgp_as_num),
            "vrf {}".format(vrf),
            afi_cmd_eos,
            f"no network {prefix}/{mask}",
            "no interface loopback {}".format(loopback),
            "exit",
            ]
    data['nbr'][name]['host'].run_command_list(cmds)
    Logger.info("Route, IP and Loopback %d removed from %s on %s", loopback, vrf, name)


@pytest.fixture(name="setUp", scope="module")
def fixture_setUp(nbrhosts, duthosts, enum_frontend_dut_hostname, ip_version):
    '''
    This fixture setup filters the T1 neigbor names from the nbrhosts. and T the end cleans up the routes
    from the T1 neighbors.
    '''
    duthost = duthosts[enum_frontend_dut_hostname]
    afi_cfg = AFI_CONFIG[ip_version]

    cmd = "vtysh -c 'show bgp summary json'"
    bgp_summary_json = json.loads(duthost.shell(cmd)['stdout'])
    bgp_info = {}
    py_assert(afi_cfg["afi"] in bgp_summary_json)
    py_assert("peers" in bgp_summary_json[afi_cfg["afi"]])
    for neighbor in bgp_summary_json[afi_cfg["afi"]]['peers']:
        neighbor_info = bgp_summary_json[afi_cfg["afi"]]['peers'][neighbor]
        bgp_info[neighbor_info['desc']] = neighbor_info['remoteAs']

    data = {}
    data['nbr'] = nbrhosts
    data['bgp'] = bgp_info
    data['T1'] = []
    data['afi_cfg'] = afi_cfg
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
    prefix, mask = afi_cfg["prefix"], afi_cfg["mask"]
    for name in data['T1']:
        nbrhost = data['nbr'][name]['host']
        bgp_as_num = data['bgp'][name]
        # remove the route in the neighbor T1 eos device
        if isinstance(nbrhost, EosHost):
            rm_route_from_nbr(data, name, prefix, mask, afi_cfg["afi_cmd_eos"])
        elif isinstance(nbrhost, SonicHost):
            cmd = "sudo vtysh -c 'configure terminal' " \
                  f"-c 'router bgp {bgp_as_num}' " \
                  f"-c \"{afi_cfg['afi_cmd_sonic']}\" " \
                  f"-c 'no network {prefix}/{mask}' " \
                  "-c 'exit-address-family'"
            result = nbrhost.shell(cmd)
            py_assert(result['rc'] == 0, "BGP network not removed")
            cmd = f"sudo config interface ip remove Loopback1 {prefix}/{mask}"
            result = nbrhost.shell(cmd)
            py_assert(result['rc'] == 0, "loopback interface not removed")
        else:
            raise ValueError("Unsupported neighbor type")


def _check_route_propagation(duthost, data):
    cmd = "redis-cli -n 0 hget \"ROUTE_TABLE:{}\" 'nexthop'".format(data["afi_cfg"]["prefix"])
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
    afi_cfg = data["afi_cfg"]
    prefix, mask = afi_cfg["prefix"], afi_cfg["mask"]
    for name in data['T1']:
        bgp_as_num = data['bgp'][name]
        nbrhost = data['nbr'][name]['host']
        # add a route in the neighbor T1 eos device
        if isinstance(nbrhost, EosHost):
            add_route_to_nbr(data, name, prefix, mask, afi_cfg["afi_cmd_eos"], afi_cfg["loopback_cmd_eos"])
        elif isinstance(nbrhost, SonicHost):
            # Create and configure loopback interface
            cmd = f"sudo config interface ip add Loopback1 {prefix}/{mask}"
            result = nbrhost.shell(cmd)
            py_assert(result['rc'] == 0, "Failed to configure loopback interface")
            # Configure BGP network
            cmd = "sudo vtysh -c 'configure terminal' " \
                  f"-c 'router bgp {bgp_as_num}' " \
                  f"-c \"{afi_cfg['afi_cmd_sonic']}\" " \
                  f"-c 'network {prefix}/{mask}' " \
                  "-c 'exit-address-family'"
            result = nbrhost.shell(cmd)
            py_assert(result['rc'] == 0, "Failed to configure BGP network")
        else:
            raise ValueError("Unsupported neighbor type")

    duthost = duthosts[enum_frontend_dut_hostname]
    Logger.info("checking  DUT for route %s", prefix)
    is_route_propagated = wait_until(10, 2, 0, lambda: _check_route_propagation(duthost, data))
    py_assert(is_route_propagated, "Route did not propagate to the DUT")


def test_bgp_neighbor_route_learnning(duthosts, enum_frontend_dut_hostname, setUp):
    run_bgp_neighbor_route_learning(duthosts, enum_frontend_dut_hostname, setUp)
