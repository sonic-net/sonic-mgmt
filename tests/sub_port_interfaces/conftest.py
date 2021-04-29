import os
import ipaddress
import time
import random
import jinja2

import pytest

from tests.common import config_reload
from tests.common.helpers.assertions import pytest_assert as py_assert
from tests.common.utilities import wait_until
from sub_ports_helpers import DUT_TMP_DIR
from sub_ports_helpers import TEMPLATE_DIR
from sub_ports_helpers import SUB_PORTS_TEMPLATE
from sub_ports_helpers import check_sub_port
from sub_ports_helpers import remove_member_from_vlan
from sub_ports_helpers import get_port
from sub_ports_helpers import remove_sub_port
from sub_ports_helpers import remove_lag_port
from sub_ports_helpers import add_port_to_namespace
from sub_ports_helpers import add_static_route
from sub_ports_helpers import remove_namespace
from sub_ports_helpers import remove_static_route
from sub_ports_helpers import get_ptf_port_list


def pytest_addoption(parser):
    """
    Adds options to pytest that are used by the sub-ports tests.
    """
    parser.addoption(
        "--max_numbers_of_sub_ports",
        action="store",
        type=int,
        default=4,
        help="Max numbers of sub-ports for test_max_numbers_of_sub_ports test case",
    )


@pytest.fixture(params=['port', 'port_in_lag'])
def define_sub_ports_configuration(request, duthost, ptfhost, ptfadapter):
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
    sub_ports_config = {}
    max_numbers_of_sub_ports = request.config.getoption("--max_numbers_of_sub_ports")
    vlan_ranges_dut = range(10, 50, 10)
    vlan_ranges_ptf = range(10, 50, 10)

    if 'invalid' in request.node.name:
        vlan_ranges_ptf = range(11, 31, 10)

    if 'max_numbers' in request.node.name:
        vlan_ranges_dut = range(1, max_numbers_of_sub_ports + 1)
        vlan_ranges_ptf = range(1, max_numbers_of_sub_ports + 1)

        # Linux has the limitation of 15 characters on an interface name,
        # but name of LAG port should have prefix 'PortChannel' and suffix
        # '<0-9999>' on SONiC. So max length of LAG port suffix have be 3 characters
        # For example: 'PortChannel1.99'
        if 'port_in_lag' in request.param:
            max_numbers_of_sub_ports = max_numbers_of_sub_ports if max_numbers_of_sub_ports <= 99 else 99
            vlan_ranges_dut = range(1, max_numbers_of_sub_ports + 1)
            vlan_ranges_ptf = range(1, max_numbers_of_sub_ports + 1)

    interface_ranges = range(1, 3)
    ip_subnet = u'172.16.0.0/16'
    prefix = 30
    subnet = ipaddress.ip_network(ip_subnet)

    config_port_indices, ptf_ports = get_port(duthost, ptfhost, interface_ranges, request.param)

    subnets = [i for i, _ in zip(subnet.subnets(new_prefix=22), config_port_indices)]

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
        'dut_ports': config_port_indices,
        'ptf_ports': ptf_ports
    }


@pytest.fixture
def apply_config_on_the_dut(define_sub_ports_configuration, duthost, reload_dut_config):
    """
    Apply Sub-ports configuration on the DUT and remove after tests

    Args:
        define_sub_ports_configuration: Dictonary of parameters for configuration DUT
        duthost: DUT host object
        reload_dut_config: fixture for teardown of DUT

    Yields:
        Dictonary of parameters for configuration DUT and PTF host
    """
    sub_ports_vars = {
        'sub_ports': define_sub_ports_configuration['sub_ports']
    }

    parent_port_list = [sub_port.split('.')[0] for sub_port in define_sub_ports_configuration['sub_ports'].keys()]

    for port in set(parent_port_list):
        remove_member_from_vlan(duthost, '1000', port)

    sub_ports_config_path = os.path.join(DUT_TMP_DIR, SUB_PORTS_TEMPLATE)
    config_template = jinja2.Template(open(os.path.join(TEMPLATE_DIR, SUB_PORTS_TEMPLATE)).read())

    duthost.command("mkdir -p {}".format(DUT_TMP_DIR))
    duthost.copy(content=config_template.render(sub_ports_vars), dest=sub_ports_config_path)
    duthost.command('sonic-cfggen -j {} --write-to-db'.format(sub_ports_config_path))

    py_assert(wait_until(3, 1, check_sub_port, duthost, sub_ports_vars['sub_ports'].keys()),
              "Some sub-ports were not created")

    yield sub_ports_vars


@pytest.fixture
def apply_config_on_the_ptf(define_sub_ports_configuration, ptfhost, reload_ptf_config):
    """
    Apply Sub-ports configuration on the PTF and remove after tests

    Args:
        define_sub_ports_configuration: Dictonary of parameters for configuration DUT
        ptfhost: PTF host object
        reload_ptf_config: fixture for teardown of PTF
    """
    sub_ports = define_sub_ports_configuration['sub_ports']

    for sub_port_info in sub_ports.values():
        port, vlan = sub_port_info['neighbor_port'].split(".")
        ptfhost.shell("ip link add link {} name {} type vlan id {}".format(port, sub_port_info['neighbor_port'], vlan))
        ptfhost.shell("ip address add {} dev {}".format(sub_port_info['neighbor_ip'], sub_port_info['neighbor_port']))
        ptfhost.shell("ip link set {} up".format(sub_port_info['neighbor_port']))


@pytest.fixture(params=['same', 'different'])
def apply_route_config(request, define_sub_ports_configuration, apply_config_on_the_dut, apply_config_on_the_ptf, ptfhost):
    """
    Apply route configuration on the PTF and remove after tests

    Args:
        define_sub_ports_configuration: Dictonary of parameters for configuration DUT
        apply_config_on_the_dut: fixture for applying sub-ports configuration on the DUT
        apply_config_on_the_ptf: fixture for applying sub-ports configuration on the PTF
        ptfhost: PTF host object

    Yields:
        Dictonary of parameters for configuration DUT and PTF host
    """
    new_sub_ports = {}
    sub_ports = define_sub_ports_configuration['sub_ports']
    dut_ports = define_sub_ports_configuration['dut_ports']
    sub_ports_keys = sub_ports.copy()

    for port in dut_ports.values():
        if 'same' in request.param:
            sub_ports_on_port = random.sample([sub_port for sub_port in sub_ports_keys if port + '.' in sub_port], 2)
        else:
            sub_ports_on_port = [
                random.choice([sub_port for sub_port in sub_ports_keys if port + '.' in sub_port]),
                random.choice([sub_port for sub_port in sub_ports_keys if port + '.' not in sub_port])
            ]
            for sub_port in sub_ports_on_port:
                sub_ports_keys.pop(sub_port)

        src_port = sub_ports_on_port.pop(0)
        new_sub_ports[src_port] = []
        src_port_network = ipaddress.ip_network(unicode(sub_ports[src_port]['ip']), strict=False)

        for next_hop_sub_port in sub_ports_on_port:
            name_of_namespace = 'vnet_for_{}'.format(next_hop_sub_port)
            dst_port_network = ipaddress.ip_network(unicode(sub_ports[next_hop_sub_port]['neighbor_ip']), strict=False)

            add_port_to_namespace(ptfhost,
                                  name_of_namespace,
                                  sub_ports[next_hop_sub_port]['neighbor_port'],
                                  sub_ports[next_hop_sub_port]['neighbor_ip'])

            add_static_route(ptfhost, src_port_network, sub_ports[next_hop_sub_port]['ip'], name_of_namespace)
            add_static_route(ptfhost, dst_port_network, sub_ports[src_port]['ip'])

            new_sub_ports[src_port].append((next_hop_sub_port, name_of_namespace))

    yield {
        'new_sub_ports': new_sub_ports,
        'sub_ports': sub_ports
    }

    for src_port, next_hop_sub_ports in new_sub_ports.items():
        src_port_network = ipaddress.ip_network(unicode(sub_ports[src_port]['ip']), strict=False)

        for next_hop_sub_port in next_hop_sub_ports:
            sub_port, name_of_namespace = next_hop_sub_port
            dst_port_network = ipaddress.ip_network(unicode(sub_ports[sub_port]['ip']), strict=False)
            remove_static_route(ptfhost, src_port_network, sub_ports[sub_port]['ip'], name_of_namespace)
            remove_static_route(ptfhost, dst_port_network, sub_ports[src_port]['ip'])
            remove_namespace(ptfhost, name_of_namespace)


@pytest.fixture
def reload_dut_config(request, duthost, define_sub_ports_configuration):
    """
    DUT's configuration reload on teardown

    Args:
        request: pytest request object
        duthost: DUT host object
        define_sub_ports_configuration: Dictonary of parameters for configuration DUT
    """
    yield
    sub_ports = define_sub_ports_configuration['sub_ports']
    dut_ports = define_sub_ports_configuration['dut_ports']
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']

    for sub_port, sub_port_info in sub_ports.items():
        remove_sub_port(duthost, sub_port, sub_port_info['ip'])

    py_assert(check_sub_port(duthost, sub_ports.keys(), True), "Some sub-port were not deleted")

    if 'port_in_lag' in request.node.name:
        for lag_port in dut_ports.values():
            remove_lag_port(duthost, cfg_facts, lag_port)

    duthost.shell('sudo config load -y /etc/sonic/config_db.json')


@pytest.fixture
def reload_ptf_config(request, ptfhost, define_sub_ports_configuration):
    """
    PTF's configuration reload on teardown

    Args:
        request: pytest request object
        ptfhost: PTF host object
        define_sub_ports_configuration: Dictonary of parameters for configuration DUT
    """
    yield

    sub_ports = define_sub_ports_configuration['sub_ports']
    ptf_port_list = get_ptf_port_list(ptfhost)

    for sub_port_info in sub_ports.values():
        if sub_port_info['neighbor_port'] in ptf_port_list:
            ptfhost.shell("ip address del {} dev {}".format(sub_port_info['neighbor_ip'], sub_port_info['neighbor_port']))
            ptfhost.shell("ip link del {}".format(sub_port_info['neighbor_port']))

    if 'port_in_lag' in request.node.name:
        ptf_ports = define_sub_ports_configuration['ptf_ports']
        for bond_port, port_name in ptf_ports.items():
            if bond_port in ptf_port_list:
                ptfhost.shell("ip link set {} nomaster".format(bond_port))
                ptfhost.shell("ip link set {} nomaster".format(port_name))
                ptfhost.shell("ip link set {} up".format(port_name))
                ptfhost.shell("ip link del {}".format(bond_port))

    ptfhost.shell("supervisorctl restart ptf_nn_agent")
    time.sleep(5)


@pytest.fixture(scope="module", autouse=True)
def teardown_test_class(duthost):
    """
    Reload DUT configuration after running of test suite

    Args:
        duthost: DUT host object
    """
    yield
    config_reload(duthost)
