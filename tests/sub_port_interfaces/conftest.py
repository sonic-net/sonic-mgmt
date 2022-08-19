import os
import ipaddress
import time
import random
import jinja2
import pytest

from tests.common import config_reload
from tests.common.helpers.assertions import pytest_assert as py_assert
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.utilities import wait_until
from tests.common.ptf_agent_updater import PtfAgentUpdater
from tests.common import constants
from sub_ports_helpers import DUT_TMP_DIR
from sub_ports_helpers import TEMPLATE_DIR
from sub_ports_helpers import SUB_PORTS_TEMPLATE
from sub_ports_helpers import TUNNEL_TEMPLATE
from sub_ports_helpers import PTF_NN_AGENT_TEMPLATE
from sub_ports_helpers import check_sub_port
from sub_ports_helpers import remove_member_from_vlan
from sub_ports_helpers import get_port
from sub_ports_helpers import remove_sub_port
from sub_ports_helpers import remove_lag_port
from sub_ports_helpers import add_port_to_namespace
from sub_ports_helpers import add_static_route_to_ptf
from sub_ports_helpers import remove_namespace
from sub_ports_helpers import remove_static_route_from_ptf
from sub_ports_helpers import get_ptf_port_list
from sub_ports_helpers import remove_ip_from_port
from sub_ports_helpers import add_ip_to_dut_port
from sub_ports_helpers import add_ip_to_ptf_port
from sub_ports_helpers import remove_ip_from_ptf_port
from sub_ports_helpers import create_sub_port_on_ptf
from sub_ports_helpers import setup_vlan
from sub_ports_helpers import remove_vlan
from sub_ports_helpers import add_member_to_vlan
from sub_ports_helpers import remove_sub_port_from_ptf
from sub_ports_helpers import remove_bond_port
from sub_ports_helpers import add_static_route_to_dut
from sub_ports_helpers import remove_static_route_from_dut
from sub_ports_helpers import update_dut_arp_table


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
def port_type(request):
    """Port type to test, could be either port or port-channel."""
    return request.param


@pytest.fixture
def define_sub_ports_configuration(request, duthost, ptfhost, ptfadapter, port_type, tbinfo):
    """
    Define configuration of sub-ports for TC run

    Args:
        request: pytest request object
        duthost: DUT host object
        ptfhost: PTF host object
        port_type: Port type to test

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
    vlan_ranges_dut = range(20, 60, 10)
    vlan_ranges_ptf = range(20, 60, 10)

    if 'invalid' in request.node.name:
        vlan_ranges_ptf = range(21, 41, 10)

    if 'max_numbers' in request.node.name:
        vlan_ranges_dut = range(11, max_numbers_of_sub_ports + 11)
        vlan_ranges_ptf = range(11, max_numbers_of_sub_ports + 11)

        # Linux has the limitation of 15 characters on an interface name,
        # but name of LAG port should have prefix 'PortChannel' and suffix
        # '<0-9999>' on SONiC. So max length of LAG port suffix have be 3 characters
        # For example: 'PortChannel1.99'
        if 'port_in_lag' in port_type:
            vlan_range_end = min(100, max_numbers_of_sub_ports + 11)
            vlan_ranges_dut = range(11, vlan_range_end)
            vlan_ranges_ptf = range(11, vlan_range_end)

    interface_num = 2
    ip_subnet = u'172.16.0.0/16'
    prefix = 30
    network = ipaddress.ip_network(ip_subnet)

    # for normal t0, get_port tries to retrieve test ports from vlan members
    # let's enforce same behavior for t0-backend
    if "t0-backend" in tbinfo["topo"]["name"]:
        config_port_indices, ptf_ports = get_port(duthost, ptfhost, interface_num, port_type, exclude_sub_interface_ports=True)
    else:
        config_port_indices, ptf_ports = get_port(duthost, ptfhost, interface_num, port_type)

    subnets = [i for i, _ in zip(network.subnets(new_prefix=22), config_port_indices)]

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
        'ptf_ports': ptf_ports,
        'subnet': network,
        'interface_ranges': config_port_indices.keys(),
        'port_type': port_type
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

    py_assert(wait_until(3, 1, 0, check_sub_port, duthost, sub_ports_vars['sub_ports'].keys()),
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
        create_sub_port_on_ptf(ptfhost, sub_port_info['neighbor_port'], sub_port_info['neighbor_ip'])


@pytest.fixture(params=['same', 'different'])
def apply_route_config(request, ptfhost, define_sub_ports_configuration, apply_config_on_the_dut, apply_config_on_the_ptf):
    """
    Apply route configuration on the PTF and remove after tests

    Args:
        request: pytest request object
        ptfhost: PTF host object
        define_sub_ports_configuration: Dictonary of parameters for configuration DUT
        apply_config_on_the_dut: fixture for applying sub-ports configuration on the DUT
        apply_config_on_the_ptf: fixture for applying sub-ports configuration on the PTF

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

            if 'tunneling' not in request.node.name:
                add_static_route_to_ptf(ptfhost, src_port_network, sub_ports[next_hop_sub_port]['ip'], name_of_namespace)
                add_static_route_to_ptf(ptfhost, dst_port_network, sub_ports[src_port]['ip'])

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

            if 'tunneling' not in request.node.name:
                remove_static_route_from_ptf(ptfhost, src_port_network, sub_ports[sub_port]['ip'], name_of_namespace)
                remove_static_route_from_ptf(ptfhost, dst_port_network, sub_ports[src_port]['ip'])

            remove_namespace(ptfhost, name_of_namespace)


@pytest.fixture(params=['svi', 'l3'])
def apply_route_config_for_port(request, duthost, ptfhost, define_sub_ports_configuration, apply_config_on_the_dut, apply_config_on_the_ptf):
    """
    Apply route configuration on the PTF and remove after tests

    Args:
        request: pytest request object
        duthost: DUT host object
        ptfhost: PTF host object
        define_sub_ports_configuration: Dictonary of parameters for configuration DUT
        apply_config_on_the_dut: fixture for applying sub-ports configuration on the DUT
        apply_config_on_the_ptf: fixture for applying sub-ports configuration on the PTF

    Yields:
        Dictonary of parameters for configuration DUT and PTF host
    """
    port_map = {}
    vlan_id = 999

    sub_ports = define_sub_ports_configuration['sub_ports']
    dut_ports = define_sub_ports_configuration['dut_ports']
    port_type = define_sub_ports_configuration['port_type']
    subnet = define_sub_ports_configuration['subnet']

    # Get additional port for configuration of SVI port or L3 RIF
    if 'svi' in request.param:
        interface_num = 1
    else:
        interface_num = 2
    dut_ports, ptf_ports = get_port(duthost, ptfhost, interface_num, port_type, dut_ports.values(), exclude_sub_interface_ports=True)

    # Get additional IP addresses for configuration of RIF on the DUT and PTF
    subnet = ipaddress.ip_network(str(subnet.broadcast_address + 1) + u'/24')
    subnets = [i for i, _ in zip(subnet.subnets(new_prefix=30), dut_ports)]

    sub_ports_keys = sub_ports.copy()

    for dut_port, ptf_port, subnet in zip(dut_ports.values(), ptf_ports, subnets):
        dut_port_ip, ptf_port_ip = ('{}/{}'.format(host, 30) for host in subnet.hosts())
        remove_ip_from_port(duthost, dut_port)

        if 'svi' in request.param:
            # Configure  SVI port on the DUT
            ptf_port = '{}.{}'.format(ptf_port, vlan_id)
            remove_member_from_vlan(duthost, vlan_id, dut_port)
            setup_vlan(duthost, vlan_id)
            add_member_to_vlan(duthost, vlan_id, dut_port)
            add_ip_to_dut_port(duthost, 'Vlan{}'.format(vlan_id), dut_port_ip)
            # Configure additional sub-port for connection between SVI port of the DUT and PTF
            create_sub_port_on_ptf(ptfhost, ptf_port, ptf_port_ip)
        else:
            # should remove port from Vlan1000 first to configure L3 RIF
            remove_member_from_vlan(duthost, '1000', dut_port)
            # Configure L3 RIF on the DUT
            add_ip_to_dut_port(duthost, dut_port, dut_port_ip)
            # Configure L3 RIF on the PTF
            add_ip_to_ptf_port(ptfhost, ptf_port, ptf_port_ip)

        # Get two random sub-ports which are not part of the selected DUT interface
        sub_ports_on_port = random.sample([sub_port for sub_port in sub_ports_keys if dut_port + '.' not in sub_port], 2)

        for sub_port in sub_ports_on_port:
            sub_ports_keys.pop(sub_port)

        port_map[ptf_port] = {'dut_port': dut_port,
                              'ip': ptf_port_ip,
                              'neighbor_ip': dut_port_ip,
                              'dst_ports': []
                             }

        # Configure static route between selected sub-ports and selected interfaces on the PTF
        for next_hop_sub_port in sub_ports_on_port:
            name_of_namespace = 'vnet_for_{}'.format(next_hop_sub_port)
            dst_port_network = ipaddress.ip_network(unicode(sub_ports[next_hop_sub_port]['neighbor_ip']), strict=False)

            # Add selected sub-port to namespace on the PTF
            add_port_to_namespace(ptfhost,
                                  name_of_namespace,
                                  sub_ports[next_hop_sub_port]['neighbor_port'],
                                  sub_ports[next_hop_sub_port]['neighbor_ip'])

            # Add static route from sub-port to selected interface on the PTF
            add_static_route_to_ptf(ptfhost, subnet, sub_ports[next_hop_sub_port]['ip'], name_of_namespace)
            # Add static route from selected interface to sub-port on the PTF
            add_static_route_to_ptf(ptfhost, dst_port_network, dut_port_ip)

            port_map[ptf_port]['dst_ports'].append((next_hop_sub_port, name_of_namespace))

    yield {
        'port_map': port_map,
        'sub_ports': sub_ports
    }

    # Teardown
    for src_port, next_hop_sub_ports in port_map.items():
        src_port_network = ipaddress.ip_network(unicode(next_hop_sub_ports['ip']), strict=False)

        # Remove static route between selected sub-ports and selected interfaces from the PTF
        for sub_port, name_of_namespace in next_hop_sub_ports['dst_ports']:
            dst_port_network = ipaddress.ip_network(unicode(sub_ports[sub_port]['ip']), strict=False)
            remove_static_route_from_ptf(ptfhost, src_port_network, sub_ports[sub_port]['ip'], name_of_namespace)
            remove_static_route_from_ptf(ptfhost, dst_port_network, next_hop_sub_ports['neighbor_ip'])
            remove_namespace(ptfhost, name_of_namespace)

        if 'svi' in request.param:
            # Remove SVI port from the DUT
            remove_member_from_vlan(duthost, vlan_id, next_hop_sub_ports['dut_port'])
            remove_ip_from_port(duthost, 'Vlan{}'.format(vlan_id), ip=next_hop_sub_ports['neighbor_ip'])
            # Remove additional sub-port from the PTF
            remove_sub_port_from_ptf(ptfhost, src_port, next_hop_sub_ports['ip'])

            if 'port_in_lag' in port_type:
                bond_port = src_port.split('.')[0]
                cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
                remove_lag_port(duthost, cfg_facts, next_hop_sub_ports['dut_port'])
                remove_bond_port(ptfhost, bond_port, ptf_ports[bond_port])
        else:
            # Remove L3 RIF from the DUT
            remove_ip_from_port(duthost, next_hop_sub_ports['dut_port'], ip=next_hop_sub_ports['neighbor_ip'])
            # Remove L3 RIF from the PTF
            remove_ip_from_ptf_port(ptfhost, src_port, next_hop_sub_ports['ip'])

            if 'port_in_lag' in port_type:
                bond_port = src_port
                cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
                remove_lag_port(duthost, cfg_facts, next_hop_sub_ports['dut_port'])
                remove_bond_port(ptfhost, bond_port, ptf_ports[bond_port])

    if 'svi' in request.param:
        remove_vlan(duthost, vlan_id)


@pytest.fixture()
def apply_tunnel_table_to_dut(duthost, apply_route_config):
    """
    Apply tunnel configuration on the DUT and remove after tests

    Args:
        duthost: DUT host object
        apply_route_config: Fixture for applying route configuration on the PTF
    """
    tunnel_addr_list = []

    new_sub_ports = apply_route_config['new_sub_ports']
    sub_ports = apply_route_config['sub_ports']

    for src_port in new_sub_ports:
        tunnel_ip = sub_ports[src_port]['ip'].split('/')[0]
        tunnel_addr_list.append(tunnel_ip)

    tunnel_vars = {
        'tunnel_addr_list': tunnel_addr_list
    }

    tunnel_config_path = os.path.join(DUT_TMP_DIR, TUNNEL_TEMPLATE)
    config_template = jinja2.Template(open(os.path.join(TEMPLATE_DIR, TUNNEL_TEMPLATE)).read())

    duthost.command("mkdir -p {}".format(DUT_TMP_DIR))
    duthost.copy(content=config_template.render(tunnel_vars), dest=tunnel_config_path)
    duthost.command('sonic-cfggen -j {} --write-to-db'.format(tunnel_config_path))

    yield

    # Teardown
    for index in range(1, len(tunnel_addr_list)+1):
        duthost.command('docker exec -i database redis-cli -n 4 -c DEL "TUNNEL|MuxTunnel{}"'.format(index))


@pytest.fixture()
def apply_balancing_config(duthost, ptfhost, ptfadapter, define_sub_ports_configuration, apply_config_on_the_dut, apply_config_on_the_ptf, tbinfo):
    """
    Apply balancing configuration on the DUT and remove after tests
    Args:
        duthost: DUT host object
        ptfhost: PTF host object
        ptfadapter: PTF adapter
        define_sub_ports_configuration: Dictonary of parameters for configuration DUT
        apply_config_on_the_dut: fixture for applying sub-ports configuration on the DUT
        apply_config_on_the_ptf: fixture for applying sub-ports configuration on the PTF
    Yields:
        Dictonary of parameters for configuration DUT and PTF host
    """
    new_sub_ports = []
    sub_ports = define_sub_ports_configuration['sub_ports']
    dut_ports = define_sub_ports_configuration['dut_ports']
    ptf_ports = define_sub_ports_configuration['ptf_ports']

    ptf_agent_updater = PtfAgentUpdater(ptfhost=ptfhost,
                                        ptfadapter=ptfadapter,
                                        ptf_nn_agent_template=os.path.join(TEMPLATE_DIR, PTF_NN_AGENT_TEMPLATE))

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    if "backend" in tbinfo["topo"]["name"]:
        src_ports = set()
        for vlan_sub_interface in mg_facts['minigraph_vlan_sub_interfaces']:
            sub_intf_name = vlan_sub_interface['attachto']
            port = sub_intf_name.split(constants.VLAN_SUB_INTERFACE_SEPARATOR)[0]
            vlan_id = vlan_sub_interface['vlan']
            src_ports.add("eth" + str(mg_facts['minigraph_ptf_indices'][port]) + constants.VLAN_SUB_INTERFACE_SEPARATOR + str(vlan_id))
        src_ports = tuple(src_ports)
    else:
        mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
        all_up_ports = set()
        for port in mg_facts['minigraph_ports'].keys():
            all_up_ports.add("eth" + str(mg_facts['minigraph_ptf_indices'][port]))
        src_ports = tuple(all_up_ports.difference(ptf_ports))

    network = u'1.1.1.0/24'
    network = ipaddress.ip_network(network)

    for port, subnet in zip(dut_ports.values(), network.subnets(new_prefix=30)):
        sub_ports_on_port = [sub_port for sub_port in sub_ports if port + '.' in sub_port]

        sub_port_neighbors = [sub_ports[sub_port]['neighbor_port'] for sub_port in sub_ports_on_port]
        ptf_agent_updater.configure_ptf_nn_agent(sub_port_neighbors)

        new_sub_ports.append((sub_ports_on_port, subnet))

        for next_hop_sub_port in sub_ports_on_port:
            update_dut_arp_table(duthost, sub_ports[next_hop_sub_port]['neighbor_ip'].split('/')[0])
            add_static_route_to_dut(duthost, str(subnet), sub_ports[next_hop_sub_port]['neighbor_ip'])

    yield {
        'new_sub_ports': new_sub_ports,
        'sub_ports': sub_ports,
        'src_ports': src_ports
    }

    for sub_ports_on_port, subnet in new_sub_ports:
        sub_port_neighbors = [sub_ports[sub_port]['neighbor_port'] for sub_port in sub_ports_on_port]
        ptf_agent_updater.cleanup_ptf_nn_agent(sub_port_neighbors)

        for next_hop_sub_port in sub_ports_on_port:
            remove_static_route_from_dut(duthost, str(subnet), sub_ports[next_hop_sub_port]['neighbor_ip'])


@pytest.fixture
def reload_dut_config(request, duthost, define_sub_ports_configuration, loganalyzer):
    """
    DUT's configuration reload on teardown

    Args:
        request: pytest request object
        duthost: DUT host object
        define_sub_ports_configuration: Dictonary of parameters for configuration DUT
    """
    yield
    if loganalyzer and loganalyzer[duthost.hostname]:
        loganalyzer[duthost.hostname].add_start_ignore_mark()

    sub_ports = define_sub_ports_configuration['sub_ports']
    dut_ports = define_sub_ports_configuration['dut_ports']
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    existing_sub_ports = cfg_facts.get("VLAN_SUB_INTERFACE", {})
    for sub_port in sub_ports:
        if sub_port in existing_sub_ports:
            remove_sub_port(duthost, sub_port, sub_ports[sub_port]['ip'])

    py_assert(check_sub_port(duthost, sub_ports.keys(), True), "Some sub-port were not deleted")

    if 'port_in_lag' in request.node.name:
        for lag_port in dut_ports.values():
            remove_lag_port(duthost, cfg_facts, lag_port)

    duthost.shell('sudo config load -y /etc/sonic/config_db.json')
    wait_critical_processes(duthost)
    if loganalyzer and loganalyzer[duthost.hostname]:
        loganalyzer[duthost.hostname].add_end_ignore_mark()

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
            remove_sub_port_from_ptf(ptfhost, sub_port_info['neighbor_port'], sub_port_info['neighbor_ip'])

    if 'port_in_lag' in request.node.name:
        ptf_ports = define_sub_ports_configuration['ptf_ports']
        for bond_port, port_name in ptf_ports.items():
            if bond_port in ptf_port_list:
                remove_bond_port(ptfhost, bond_port, port_name)

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

@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exception(duthost, loganalyzer):
    if loganalyzer and loganalyzer[duthost.hostname]:
        ignore_regex_list = [
            ".*ERR teamd[0-9]*#tlm_teamd.*process_add_queue: Can't connect to teamd after.*attempts. LAG 'PortChannel.*'",
            ".*ERR swss[0-9]*#orchagent.*update: Failed to get port by bridge port ID.*"
        ]
        loganalyzer[duthost.hostname].ignore_regex.extend(ignore_regex_list)
