import os
import copy

import pytest

from nat_helpers import SUPPORTED_TOPO
from nat_helpers import SETUP_CONF
from nat_helpers import DUT_TMP_DIR
from nat_helpers import NAT_ADMIN_MODE
from nat_helpers import TEMPLATE_DIR
from nat_helpers import GLOBAL_NAT_TIMEOUT
from nat_helpers import GLOBAL_TCP_NAPT_TIMEOUT
from nat_helpers import GLOBAL_UDP_NAPT_TIMEOUT
from nat_helpers import NAT_GLOBAL_TEMPLATE
from nat_helpers import conf_ptf_interfaces
from nat_helpers import teardown_test_env
from nat_helpers import exec_command
from nat_helpers import dut_interface_control
from common.config_reload import config_reload


@pytest.fixture(params=['TCP', 'UDP', 'ICMP'])
def protocol_type(request):
    """
    used to parametrized test cases on protocol type
    :param request: pytest request object
    :return: protocol type
    """
    return request.param


@pytest.fixture(params=['TCP', 'UDP'])
def protocol_type_no_icmp(request):
    """
    used to parametrized test cases on protocol type
    :param request: pytest request object
    :return: protocol type
    """
    return request.param


@pytest.fixture(autouse=True)
def teardown(duthost):
    """
    Teardown procedure for all test function
    :param duthost: DUT host object
    """
    yield
    # Teardown after test finished
    shutdown_cmds = ["config nat remove {}".format(cmd) for cmd in ["static all", "bindings", "pools", "interfaces"]]
    exec_command(duthost, shutdown_cmds)
    # Clear all enries
    duthost.command("sonic-clear nat translations")


@pytest.fixture(params=["loopback", "port_in_lag"], scope='module')
def setup_test_env(request, ptfhost, duthost, testbed):
    """
    setup testbed's environment for CT run
    :param request: pytest request object
    :param ptfhost: PTF host object
    :param duthost: DUT host object
    :param testbed: Testbed object
    :return: interface type and testbed setup info
    """
    # Check if topology is supported
    if testbed['topo']['name'] not in SUPPORTED_TOPO:
        pytest.skip('Unsupported topology')
    interface_type = request.param
    interfaces_nat_zone = {}
    portchannels_port_indices = []
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']
    router_mac = duthost.setup()['ansible_facts']['ansible_Ethernet0']['macaddress']
    config_port_indices = cfg_facts['port_index_map']
    config_portchannels = cfg_facts.get('PORTCHANNEL', {})
    config_ports = cfg_facts['PORT']
    ptf_ports_available_in_topo = ptfhost.host.options['variable_manager'].extra_vars.get("ifaces_map")
    # Get outer port indices
    for port_id in config_portchannels.keys():
        port = config_portchannels[port_id]['members'][0]
        portchannels_port_indices.append(config_port_indices[port])
    ports = [p for p in config_ports
             if config_port_indices[p] in ptf_ports_available_in_topo and config_ports[p].get('admin_status', 'down') == 'up']
    vlan_port_indices = [config_port_indices[p] for p in ports]
    dut_rifs_in_topo_t0 = [el[8:] for el in duthost.setup()['ansible_facts'].keys()
                           if 'PortCh' in el or 'Loop' in el or 'Vlan' in el]
    dut_rifs_in_topo_t0 = sorted(dut_rifs_in_topo_t0, reverse=True)
    inner_zone_interfaces = dut_rifs_in_topo_t0[0]
    outer_zone_interfaces = dut_rifs_in_topo_t0[1:]
    for rif in dut_rifs_in_topo_t0:
        interfaces_nat_zone[rif] = {'interface_name': rif,
                                    "global_interface_name": '{}_INTERFACE'.format(
                                        (rif.encode()).translate(None, '0123456789').upper())
                                    }
        if rif in inner_zone_interfaces:
            interfaces_nat_zone[rif]['zone_id'] = 0
        elif rif in outer_zone_interfaces:
            interfaces_nat_zone[rif]['zone_id'] = 1
    indices_to_ports_config = dict((v, k) for k, v in config_port_indices.iteritems())
    if interface_type == "port_in_lag":
        outer_zone_interfaces = [outer_zone_interfaces[-2], outer_zone_interfaces[-3]]
        public_ip = SETUP_CONF["port_in_lag"]["vrf"]["red"]["gw"]
        second_public_ip = SETUP_CONF["port_in_lag"]["vrf"]["green"]["gw"]
    else:
        public_ip = duthost.setup()['ansible_facts']['ansible_Loopback0']['ipv4']['address']
        second_public_ip = duthost.setup()['ansible_facts']['ansible_Loopback0']['ipv4']['address']

    setup_information = {"router_mac": router_mac,
                         "interfaces_nat_zone": interfaces_nat_zone,
                         "dut_rifs_in_topo_t0": dut_rifs_in_topo_t0,
                         "indices_to_ports_config": indices_to_ports_config,
                         "ptf_ports_available_in_topo": ptf_ports_available_in_topo,
                         "config_portchannels": config_portchannels,
                         "pch_ips": {"PortChannel0001": duthost.setup()['ansible_facts']['ansible_PortChannel0001']['ipv4']['address'],
                                     "PortChannel0002": duthost.setup()['ansible_facts']['ansible_PortChannel0002']['ipv4']['address']},
                         "outer_vrf": ["red", "green"],
                         "inner_vrf": ["blue", "yellow"],
                         interface_type: {"vrf_conf": SETUP_CONF[interface_type]["vrf"],
                                          "inner_zone_interfaces": [inner_zone_interfaces, ],
                                          "outer_zone_interfaces": outer_zone_interfaces,
                                          "inner_port_id": [int(vlan_port_indices[0]), ],
                                          "outer_port_id": portchannels_port_indices,
                                          "src_ip": SETUP_CONF[interface_type]["vrf"]["blue"]["ip"],
                                          "second_src_ip": SETUP_CONF[interface_type]["vrf"]["yellow"]["ip"],
                                          "dst_ip": SETUP_CONF[interface_type]["vrf"]["red"]["ip"],
                                          "second_dst_ip": SETUP_CONF[interface_type]["vrf"]["green"]["ip"],
                                          "public_ip": public_ip,
                                          "second_public_ip": second_public_ip,
                                          "gw": duthost.setup()['ansible_facts']['ansible_Vlan1000']['ipv4']['address'],
                                          "acl_subnet": SETUP_CONF[interface_type]["acl_subnet"]
                                          }
                         }
    try:
        # Setup interfaces on PTF container
        conf_ptf_interfaces(ptfhost, duthost, setup_information, interface_type)
    except Exception as err:
        teardown_test_env(duthost, ptfhost, setup_information, interface_type)
        raise err
    yield interface_type, setup_information
    # Remove ptf interfaces
    conf_ptf_interfaces(ptfhost, duthost, setup_information, interface_type, teardown=True)


@pytest.fixture(scope='module', autouse=True)
def apply_global_nat_config(duthost):
    """
    generate global NAT configuration files and deploy them on DUT;
    after test run cleanup artifacts on DUT
    :param duthost: DUT host object
    """
    # Create temporary directory for NAT templates
    duthost.command("mkdir -p {}".format(DUT_TMP_DIR))
    # Initialize variables for NAT global table
    nat_table_vars = {
        'nat_admin_mode': NAT_ADMIN_MODE,
        'global_nat_timeout': GLOBAL_NAT_TIMEOUT,
        'tcp_timeout': GLOBAL_TCP_NAPT_TIMEOUT,
        'udp_timeout': GLOBAL_UDP_NAPT_TIMEOUT,
    }
    duthost.host.options['variable_manager'].extra_vars.update(nat_table_vars)
    nat_global_config = 'nat_table_global_{}.json'.format(NAT_ADMIN_MODE)
    nat_config_path = os.path.join(DUT_TMP_DIR, nat_global_config)
    duthost.template(src=os.path.join(TEMPLATE_DIR, NAT_GLOBAL_TEMPLATE), dest=nat_config_path)
    # Apply config file
    duthost.command('sonic-cfggen -j {} --write-to-db'.format(nat_config_path))
    yield
    # Remove temporary folders
    duthost.command('rm -rf {}'.format(DUT_TMP_DIR))
    # reload config on teardown
    config_reload(duthost, config_source='minigraph')


@pytest.fixture()
def enable_nat_config(request, duthost):
    """
    enable NAT configuration on teardown
    :param request: pytest request object
    :param duthost: DUT host object
    """
    yield
    if request.node.rep_call.failed:
        duthost.command("config nat feature enable")


@pytest.fixture()
def enable_nat_docker(request, duthost):
    """
    enable NAT Docker on teardown
    :param request: pytest request object
    :param duthost: DUT host object
    """
    yield
    if request.node.rep_call.failed:
        exec_command(duthost, ["sudo docker start nat"])


@pytest.fixture()
def enable_outer_interfaces(request, duthost, setup_test_env):
    """
    Enable outer interfaces(Flap interfaces test)
    :param request: pytest request object
    :param duthost: DUT host object
    :param ptfhost: PTF host object
    :param testbed: Testbed object
    :param setup_test_env: Setup information
    """
    yield
    if request.node.rep_call.failed:
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        # Enable outer interfaces
        ifnames = setup_data[interface_type]["outer_zone_interfaces"]
        for ifname in ifnames:
            members = setup_data["config_portchannels"][ifname]['members']
            for member in members:
                dut_interface_control(duthost, "enable", member)


@pytest.mark.trylast
def pytest_collection_modifyitems(session, config, items):
    """Remove redundant test cases
    """
    for item in items[:]:
        # for T0 only portchannel supported
        # Loopback interface type is not valid scenario for interfaces flap
        if 'test_nat_interfaces_flap_dynamic' in item.name and 'loopback' in item.name:
            items.remove(item)
