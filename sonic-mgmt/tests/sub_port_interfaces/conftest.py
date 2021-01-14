import os
import ipaddress
import jinja2

import pytest

from tests.common import config_reload
from sub_ports_helpers import DUT_TMP_DIR
from sub_ports_helpers import TEMPLATE_DIR
from sub_ports_helpers import SUB_PORTS_TEMPLATE


@pytest.fixture
def define_sub_ports_configuration(request, duthost, ptfhost):
    """
    Define configuration of sub-ports for TC run

    Args:
        request: pytest request object
        duthost: DUT host object
        ptfhost: PTF host object

    Yields:
        Dictonary of sub-port parameters for configuration DUT and PTF host
        For example:
        {
        'Ethernet4.10': {
            'ip': '172.16.0.1/30',
            'neighbor_port': 'eth1.10',
            'neighbor_ip': '172.16.0.2/30'
            },
        'Ethernet4.20': {
            'ip': '172.16.0.5/30',
            'neighbor_port': 'eth1.20',
            'neighbor_ip': '172.16.0.6/30'
            }
        }
    """
    vlan_ranges_dut = range(10, 30, 10)
    vlan_ranges_ptf = range(10, 30, 10)

    if 'invalid' in request.node.name:
        vlan_ranges_ptf = range(11, 31, 10)

    interface_ranges = range(1, 2)
    ip_subnet = u'172.16.0.0/16'
    prefix = 30
    subnet = ipaddress.ip_network(ip_subnet)

    cfg_facts = duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']
    config_vlan_members = cfg_facts['VLAN_MEMBER']['Vlan1000']
    config_port_indices = {v: k for k, v in cfg_facts['port_index_map'].items() if k in config_vlan_members and v in interface_ranges}
    ptf_ports_available_in_topo = ptfhost.host.options['variable_manager'].extra_vars.get("ifaces_map")
    ptf_ports = [v for k, v in ptf_ports_available_in_topo.items() if k in interface_ranges]

    subnets = [i for i, _ in zip(subnet.subnets(new_prefix=22), config_port_indices)]

    sub_ports_config = {}
    for port, ptf_port, subnet in zip(config_port_indices.values(), ptf_ports, subnets):
        for vlan_id_dut, vlan_id_ptf, net in zip(vlan_ranges_dut, vlan_ranges_ptf, subnet.subnets(new_prefix=30)):
            hosts_list = [i for i in net.hosts()]
            sub_ports_config['{}.{}'.format(port, vlan_id_dut)] = {
                'ip': '{}/{}'.format(hosts_list[0], prefix),
                'neighbor_port': '{}.{}'.format(ptf_port, vlan_id_ptf),
                'neighbor_ip': '{}/{}'.format(hosts_list[1], prefix)
            }

    yield {
        'sub_ports': sub_ports_config,
    }


@pytest.fixture
def apply_config_on_the_dut(define_sub_ports_configuration, duthost):
    """
    Apply Sub-ports configuration on the DUT and remove after tests

    Args:
        setup_env: Dictonary of parameters for configuration DUT
        duthost: DUT host object

    Yields:
        Dictonary of parameters for configuration DUT and PTF host
    """
    sub_ports_vars = {
        'sub_ports': define_sub_ports_configuration['sub_ports'],
    }

    sub_ports_config_path = os.path.join(DUT_TMP_DIR, SUB_PORTS_TEMPLATE)
    config_template = jinja2.Template(open(os.path.join(TEMPLATE_DIR, SUB_PORTS_TEMPLATE)).read())

    duthost.command("mkdir -p {}".format(DUT_TMP_DIR))
    duthost.copy(content=config_template.render(sub_ports_vars), dest=sub_ports_config_path)
    duthost.command('sonic-cfggen -j {} --write-to-db'.format(sub_ports_config_path))

    yield sub_ports_vars
    reload_dut_config(duthost)


@pytest.fixture
def apply_config_on_the_ptf(define_sub_ports_configuration, ptfhost):
    """
    Apply Sub-ports configuration on the PTF and remove after tests

    Args:
        setup_env: Dictonary of parameters for configuration DUT
        ptfhost: PTF host object

    """
    sub_ports = define_sub_ports_configuration['sub_ports']

    for sub_port_info in sub_ports.values():
        port, vlan = sub_port_info['neighbor_port'].split(".")
        ptfhost.shell("ip link add link {} name {} type vlan id {}".format(port, sub_port_info['neighbor_port'], vlan))
        ptfhost.shell("ip address add {} dev {}".format(sub_port_info['neighbor_ip'], sub_port_info['neighbor_port']))
        ptfhost.shell("ip link set {} up".format(sub_port_info['neighbor_port']))

    yield
    reload_ptf_config(ptfhost, sub_ports)


def reload_dut_config(duthost):
    """
    DUT's configuration reload on teardown

    Args:
        duthost: DUT host object

    """
    config_reload(duthost)


def reload_ptf_config(ptfhost, sub_ports):
    """
    PTF's configuration reload on teardown

    Args:
        ptfhost: PTF host object
    """
    for sub_port_info in sub_ports.values():
        ptfhost.shell("ip address del {} dev {}".format(sub_port_info['neighbor_ip'], sub_port_info['neighbor_port']))
        ptfhost.shell("ip link del {}".format(sub_port_info['neighbor_port']))
