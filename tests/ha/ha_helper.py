import pytest
import json
import logging

from ipaddress import ip_interface


logger = logging.getLogger(__name__)


def add_port_to_namespace(ptfhost, name_of_namespace, port_name, port_ip):
    """
    Add port to namespace of the PTF

    Args:
        ptfhost: PTF host object
        name_of_namespace: Name of namespace
        port_name: Port of the PTF
        port_ip: IP address of the port
    """
    cmds = []
    if not check_namespace(ptfhost, name_of_namespace):
        cmds.append('ip netns add {}'.format(name_of_namespace))
        cmds.append('ip -n {} link set lo up'.format(name_of_namespace))

    cmds.append('ip link set {} netns {}'.format(port_name, name_of_namespace))
    cmds.append('ip -n {} addr add {} dev {}'.format(name_of_namespace, port_ip, port_name))
    cmds.append('ip -n {} link set {} up'.format(name_of_namespace, port_name))

    ptfhost.shell_cmds(cmds=cmds)


def remove_namespace(ptfhost, name_of_namespace, port_name, port_ip):
    """
    Remove namespace from the PTF

    Args:
        ptfhost: PTF host object
        name_of_namespace: Name of namespace
        port_name: member name of namespace
        port_ip: IP address of the port
    """
    if check_namespace(ptfhost, name_of_namespace):
        cmds = []

        cmds.append('ip netns exec {} ip link set {} netns 1'.format(name_of_namespace, port_name))
        cmds.append('ip address add {} dev {}'.format(port_ip, port_name))
        cmds.append('ip link set {} up'.format(port_name))
        cmds.append('ip -n {} link set lo down'.format(name_of_namespace))
        cmds.append('ip netns del {}'.format(name_of_namespace))

        ptfhost.shell_cmds(cmds=cmds)


def add_static_route_to_ptf(ptfhost, network_ip, next_hop_ip, name_of_namespace=None):
    """
    Add static route on the PTF

    Args:
        ptfhost: PTF host object
        network_ip: Network IP address
        next_hop_ip: Next hop IP address
        name_of_namespace: Name of namespace
    """
    next_hop_ip = next_hop_ip.split('/')[0]
    if name_of_namespace:
        ptfhost.shell('ip netns exec {} ip route add {} nexthop via {}'
                      .format(name_of_namespace, network_ip, next_hop_ip))
    else:
        ptfhost.shell('ip route add {} nexthop via {}'
                      .format(network_ip, next_hop_ip))


def add_static_route_to_dut(duthost, network_ip, next_hop_ip):
    """
    Add static route on the DUT
    Args:
        duthost: DUT host object
        network_ip: Network IP address
        next_hop_ip: Next hop IP address
    """
    next_hop_ip = next_hop_ip.split('/')[0]
    duthost.shell('config route add prefix {} nexthop {}'.format(network_ip, next_hop_ip))


def check_namespace(ptfhost, name_of_namespace):
    """
    Check that namespace is available on the PTF

    Args:
        ptfhost: PTF host object
        name_of_namespace: Name of namespace

    Returns:
        Bool value which confirm availability of namespace on the PTF
    """
    out = ptfhost.shell('ip netns list')["stdout"]
    return name_of_namespace in out


@pytest.fixture(scope="module")
def dpu_index():
    return 1


def get_interface_ip(duthost, interface):
    cmd = f"ip addr show {interface} | grep -w inet | awk '{{print $2}}'"
    output = duthost.shell(cmd)["stdout"].strip()
    return ip_interface(output)


@pytest.fixture(scope="module")
def dpu_ip(duthost, dpu_index):
    dpu_port = get_dpu_dataplane_port(duthost, dpu_index)
    npu_interface_ip = get_interface_ip(duthost, dpu_port)
    return npu_interface_ip.ip + 1


def get_dpu_dataplane_port(duthost, dpu_index):
    platform = duthost.facts["platform"]
    platform_json = json.loads(duthost.shell(f"cat /usr/share/sonic/device/{platform}/platform.json")["stdout"])
    try:
        interface = list(platform_json["DPUS"][f"dpu{dpu_index}"]["interface"].keys())[0]
    except KeyError:
        if_dpu_index = 224 + dpu_index*8
        interface = f"Ethernet{if_dpu_index}"

    logger.info(f"DPU dataplane interface: {interface}")
    return interface
