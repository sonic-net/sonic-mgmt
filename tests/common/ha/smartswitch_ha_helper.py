import pytest
from common.plugins.ptfadapter import PtfTestAdapter


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


class PtfTcpTestAdapter(PtfTestAdapter):
    def __init__(self, base_adapter: PtfTestAdapter):
        self.__dict__.update(base_adapter.__dict__)

    def start_tcp_server(self, namespace=None):
        cmd = "python3 /root/tcp_server.py &"
        if namespace:
            cmd = f"ip netns exec {namespace} {cmd}"
        self.ptfhost.shell(cmd)

    def start_tcp_client(self, namespace=None):
        cmd = "python3 /root/tcp_client.py "
        if namespace:
            cmd = f"ip netns exec {namespace} {cmd}"
        self.ptfhost.shell(cmd)
