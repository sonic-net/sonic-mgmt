import random
import pytest

from nat_helpers import *


@pytest.fixture(params=['static_nat', 'static_napt'])
def static_nat_type(request):
    """
    used to parametrized test cases on static nat/napt
    :param request: pytest request object
    :return: static_nat_type
    """

    return request.param


@pytest.fixture(params=['cold', 'fast', 'warm'])
def reboot_type(request):
    """
    used to parametrized test cases on reboot
    :param request: pytest request object
    :return: reboot type
    """

    return request.param


@pytest.fixture(params=['TCP', 'UDP', 'ICMP'])
def protocol_type(request):
    """
    used to parametrized test cases on protocol type
    :param request: pytest request object
    :return: protocol type
    """

    return request.param


@pytest.fixture(params=[0, 1])
def zone_type(request):
    """
    used to parametrized test cases on NAT zone type
    :param request: pytest request object
    :return: zone type
    """

    return request.param


# TODO: Add all interfaces types
@pytest.fixture(params=["loopback", "port_in_lag"])
def interface_type(request):
    """
    used to parametrized test cases on interface_type
    :param request: pytest request object
    :return: interface type
    """

    return request.param


@pytest.fixture(autouse=True)
def apply_global_nat_config(duthost, ptfhost, setup_info, interface_type):
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
    # Teardown after test finished
    shutdown_cmds = ["config nat remove {}".format(cmd) for cmd in ["static all", "bindings", "pools", "interfaces"]]
    exec_command(duthost, shutdown_cmds)
    # Clear all enries
    duthost.command("sonic-clear nat translations")
    # Remove temporary folders
    duthost.command('rm -rf {}'.format(DUT_TMP_DIR))
    # Remove pth interfaces in case of any error appears during execution
    try:
        conf_ptf_interfaces(ptfhost, duthost, setup_info, interface_type, teardown=True)
    except Exception as e:
        print(e)


@pytest.fixture(scope="module")
def setup_info(ptfhost, duthost, testbed):
    """
    setup fixture gathers all test required information from DUT facts and testbed
    :param ptfhost: PTF host object
    :param duthost: DUT host object
    :param testbed: Testbed object
    :return: dictionary with all test required information
    """

    interfaces_nat_zone = {}
    portchannels_port_indices = []
    vlan_port_indices = []
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']
    router_mac = duthost.setup()['ansible_facts']['ansible_Ethernet0']['macaddress']
    config_port_indices = cfg_facts['port_index_map']
    config_portchannels = cfg_facts.get('PORTCHANNEL', {})
    config_ports = cfg_facts['PORT']
    ptf_ports_available_in_topo = ptfhost.host.options['variable_manager'].extra_vars.get("ifaces_map")
    # Get outer port indices
    for po in config_portchannels.keys():
        port = config_portchannels[po]['members'][0]
        portchannels_port_indices.append(config_port_indices[port])
    ports = [port for port in config_ports if config_port_indices[port] in ptf_ports_available_in_topo
             and config_ports[port].get('admin_status', 'down') == 'up']
    for po in ports:
        vlan_port_indices.append(config_port_indices[po])
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
    setup_information = {
        "router_mac": router_mac,
        "interfaces_nat_zone": interfaces_nat_zone,
        "dut_rifs_in_topo_t0": dut_rifs_in_topo_t0,
        "indices_to_ports_config": indices_to_ports_config,
        "ptf_ports_available_in_topo": ptf_ports_available_in_topo,
        "pch_ips": {"PortChannel0001": duthost.setup()['ansible_facts']['ansible_PortChannel0001']['ipv4']['address'],
                    "PortChannel0002": duthost.setup()['ansible_facts']['ansible_PortChannel0002']['ipv4']['address']},
        "outer_vrf": ["red", "green"],
        "inner_vrf": ["blue", "yellow"],
        # TODO: add pairs of necessary interfaces for setup_test_env
        "loopback": {
            "vrf_conf": SETUP_CONF["loopback"]["vrf"],
            "inner_zone_interfaces": [inner_zone_interfaces, ],
            "outer_zone_interfaces": outer_zone_interfaces,
            "inner_port_id": [int(vlan_port_indices[0]), ],
            "outer_port_id": portchannels_port_indices,
            "src_ip": SETUP_CONF["loopback"]["vrf"]["blue"]["ip"],
            "second_src_ip": SETUP_CONF["loopback"]["vrf"]["yellow"]["ip"],
            "dst_ip": SETUP_CONF["loopback"]["vrf"]["red"]["ip"],
            "second_dst_ip": SETUP_CONF["loopback"]["vrf"]["green"]["ip"],
            "public_ip": duthost.setup()['ansible_facts']['ansible_Loopback0']['ipv4']['address'],
            "second_public_ip": duthost.setup()['ansible_facts']['ansible_Loopback0']['ipv4']['address'],
            "gw": duthost.setup()['ansible_facts']['ansible_Vlan1000']['ipv4']['address']
        },
        "port_in_lag": {
            "vrf_conf": SETUP_CONF["port_in_lag"]["vrf"],
            "inner_zone_interfaces": [inner_zone_interfaces, ],
            "outer_zone_interfaces": [outer_zone_interfaces[-2], outer_zone_interfaces[-3]],
            "inner_port_id": [int(vlan_port_indices[0]), ],
            "outer_port_id": [portchannels_port_indices[0], ],
            "src_ip": SETUP_CONF["port_in_lag"]["vrf"]["blue"]["ip"],
            "second_src_ip": SETUP_CONF["port_in_lag"]["vrf"]["yellow"]["ip"],
            "dst_ip": SETUP_CONF["port_in_lag"]["vrf"]["red"]["ip"],
            "second_dst_ip": SETUP_CONF["port_in_lag"]["vrf"]["green"]["ip"],
            "public_ip": SETUP_CONF["port_in_lag"]["vrf"]["red"]["gw"],
            "second_public_ip": SETUP_CONF["port_in_lag"]["vrf"]["green"]["gw"],
            "gw": duthost.setup()['ansible_facts']['ansible_Vlan1000']['ipv4']['address']
        }
    }
    yield setup_information


class TestNat(object):
    """ TestNat class for testing nat """

    def test_nat_static_basic(self, ptfhost, testbed, duthost, ptfadapter, setup_info, interface_type, protocol_type,
                              setup_info_modify_zones=None, negative=False):
        setup_test_env(ptfhost, duthost, testbed, setup_info, interface_type)
        for direction in DIRECTION_PARAMS:
            if direction == 'leaf-tor':
                continue
            # Set public and private IPs for NAT configuration
            public_ip = get_public_ip(setup_info, interface_type)
            private_ip = get_src_ip(setup_info, direction, interface_type)
            # Set NAT configuration for test
            apply_static_nat_config(duthost, public_ip, private_ip, direction, nat_entry='static_nat')
            nat_zones_config(duthost, setup_info, interface_type)
            # Traffic send and check
            for path in DIRECTION_PARAMS:
                src_l4_port, dst_l4_port, exp_src_port, exp_dst_port = \
                    get_static_l4_ports(protocol_type, direction=path, nat_type='static_nat')
                check_rule_by_traffic(duthost, ptfhost, ptfadapter, testbed, setup_info, path, interface_type, protocol_type,
                                      source_l4_port=src_l4_port, dest_l4_port=dst_l4_port,
                                      exp_source_port=exp_src_port, exp_dst_port=exp_dst_port, negative=negative,
                                      handshake=not negative)
        if setup_info_modify_zones:
            nat_zones_config(duthost, setup_info_modify_zones, interface_type)
            # Traffic send and check
            for direction in DIRECTION_PARAMS:
                src_l4_port, dst_l4_port, exp_src_port, exp_dst_port = \
                    get_static_l4_ports(protocol_type, direction, nat_type='static_nat')
                check_rule_by_traffic(duthost, ptfhost, ptfadapter, testbed, setup_info, direction, interface_type, protocol_type,
                                      source_l4_port=src_l4_port, dest_l4_port=dst_l4_port,
                                      exp_source_port=exp_src_port, exp_dst_port=exp_dst_port, negative=True)
    
    def test_nat_static_napt(self, ptfhost, testbed, duthost, ptfadapter, setup_info, interface_type, protocol_type,
                             setup_info_modify_zones=None, negative=False):
        # setup PTF's interfaces
        setup_test_env(ptfhost, duthost, testbed, setup_info, interface_type)
        for direction in DIRECTION_PARAMS:
            if direction == 'host-tor' and protocol_type != "ICMP":
                continue
            elif direction == 'leaf-tor' and protocol_type == "ICMP":
                continue
            # set TCP/UDP SRC and DST ports
            src_l4_port, dst_l4_port, exp_src_port, exp_dst_port = get_static_l4_ports(protocol_type, direction,
                                                                                       nat_type='static_napt')
            # Set public and private IPs for NAT configuration
            public_ip = get_public_ip(setup_info, interface_type)
            private_ip = get_src_ip(setup_info, direction, interface_type, nat_type="static_napt")
            # Set NAT configuration for test
            apply_static_nat_config(duthost, public_ip, private_ip, direction, nat_entry='static_napt',
                                    protocol_type=protocol_type, global_port=dst_l4_port, local_port=src_l4_port)
            nat_zones_config(duthost, setup_info, interface_type)
            # Traffic send and check
            for path in DIRECTION_PARAMS:
                src_l4_port, dst_l4_port, exp_src_port, exp_dst_port = get_static_l4_ports(protocol_type,
                                                                                           direction=path,
                                                                                           nat_type='static_napt')
                check_rule_by_traffic(duthost, ptfhost, ptfadapter, testbed, setup_info, path, interface_type, 
                                      protocol_type, source_l4_port=src_l4_port, dest_l4_port=dst_l4_port,
                                      exp_source_port=exp_src_port, exp_dst_port=exp_dst_port, 
                                      nat_type='static_napt', negative=negative, handshake=not negative)
        if setup_info_modify_zones:
            nat_zones_config(duthost, setup_info_modify_zones, interface_type)
            # Traffic send and check
            for path in DIRECTION_PARAMS:
                src_l4_port, dst_l4_port, exp_src_port, exp_dst_port = get_static_l4_ports(protocol_type, direction,
                                                                                           nat_type='static_napt')
                check_rule_by_traffic(duthost, ptfhost, ptfadapter, testbed, setup_info, path, interface_type, protocol_type,
                                      source_l4_port=src_l4_port, dest_l4_port=dst_l4_port,
                                      exp_source_port=exp_src_port,
                                      exp_dst_port=exp_dst_port, nat_type='static_napt', negative=True)

    def test_nat_dynamic_basic(self, ptfhost, testbed, duthost, ptfadapter, setup_info, interface_type,
                               protocol_type, setup_info_modify_zones=None, remove_bindings=False, negative=False):
        # setup PTF's interfaces
        setup_test_env(ptfhost, duthost, testbed, setup_info, interface_type)
        # Configure default rules for Dynamic NAT
        configure_dynamic_nat_rule(duthost, setup_info, interface_type, default=True,
                                   remove_bindings=remove_bindings)
        # Traffic send and check
        for direction in DIRECTION_PARAMS:
            if protocol_type == 'ICMP' and direction == 'leaf-tor':
                continue
            check_rule_by_traffic(duthost, ptfhost, ptfadapter, testbed, setup_info, direction, interface_type, protocol_type,
                                  icmp_id=POOL_RANGE_START_PORT, negative=negative, handshake=True, nat_type='dynamic',
                                  default=True)
        if setup_info_modify_zones:
            for direction in DIRECTION_PARAMS:
                nat_zones_config(duthost, setup_info_modify_zones, interface_type)
                check_rule_by_traffic(duthost, ptfhost, ptfadapter, testbed, setup_info, direction, interface_type,
                                      protocol_type, icmp_id=POOL_RANGE_START_PORT, negative=negative, handshake=True,
                                      nat_type='dynamic', default=True)
    
    def test_nat_dynamic_entry_persist(self, ptfhost, testbed, duthost, ptfadapter, setup_info, interface_type,
                                       protocol_type):
        # setup PTF's interfaces123456

        setup_test_env(ptfhost, duthost, testbed, setup_info, interface_type)
        # Configure Dynamic NAT rules
        configure_dynamic_nat_rule(duthost, setup_info, interface_type, default=True)
        # Check if NAT entry stays persist due TCP/UDP timeout
        handshake = True
        for attempt in range(0, 4):
            if attempt == 1:
                handshake = False
            for direction in DIRECTION_PARAMS:
                if protocol_type == 'ICMP' and direction == 'leaf-tor':
                    continue
                check_rule_by_traffic(duthost, ptfhost, ptfadapter, testbed, setup_info, direction, interface_type,
                                      protocol_type, icmp_id=POOL_RANGE_START_PORT, handshake=handshake,
                                      nat_type='dynamic', default=True)
            # Wait some time and send packet again
            wait = random.randint(1, GLOBAL_UDP_NAPT_TIMEOUT / 2)
            wait_timeout(protocol_type, wait_time=wait, default=False)
 
    def test_nat_dynamic_disable_nat(self, ptfhost, testbed, duthost, ptfadapter, setup_info, interface_type,
                                     protocol_type):
        # setup PTF's interfaces
        setup_test_env(ptfhost, duthost, testbed, setup_info, interface_type)
        # Configure Dynamic NAT rules
        configure_dynamic_nat_rule(duthost, setup_info, interface_type, default=True)
        # Disable NAT feature
        duthost.command("config nat feature disable")
        # Send traffic and check that NAT does not happen
        for direction in DIRECTION_PARAMS:
            if protocol_type == 'ICMP' and direction == 'leaf-tor':
                continue
            check_rule_by_traffic(duthost, ptfhost, ptfadapter, testbed, setup_info, direction, interface_type,
                                  protocol_type, exp_source_port=POOL_RANGE_START_PORT, icmp_id=POOL_RANGE_START_PORT,
                                  handshake=True, nat_type='dynamic', default=True, negative=True)
        teardown_test_env(duthost, ptfhost, setup_info, interface_type)
        # Enable NAT feature and send traffic to check that NAT happens
        duthost.command("config nat feature enable")
        wait_timeout(protocol_type, wait_time=60, default=False)
        self.test_nat_dynamic_basic(ptfhost, testbed, duthost, ptfadapter, setup_info, interface_type, protocol_type)
    
    def test_nat_dynamic_acl_rule_actions(self, ptfhost, testbed, duthost, ptfadapter, setup_info, interface_type,
                                          protocol_type):
        # setup PTF's interfaces
        setup_test_env(ptfhost, duthost, testbed, setup_info, interface_type)
        # Configure Dynamic NAT rule and set action to "do_not_nat"
        acl_subnet = ".".join(SETUP_CONF[interface_type]['src_ip'].split(".")[0:-1]) + ".0/24"
        acl_rules = [{"priority": "10", "src_ip": acl_subnet, "action": "do_not_nat"}]
        configure_dynamic_nat_rule(duthost, setup_info, interface_type, acl_rules=acl_rules, default=True)
        for direction in DIRECTION_PARAMS:
            if protocol_type == 'ICMP' and direction == 'leaf-tor':
                continue
            check_rule_by_traffic(duthost, ptfhost, ptfadapter, testbed, setup_info, direction, interface_type,
                                  protocol_type, exp_source_port=POOL_RANGE_START_PORT, icmp_id=POOL_RANGE_START_PORT,
                                  handshake=True, nat_type='dynamic', default=True, negative=True, action='do_not_nat')
        # Change rules ACL rule from "do_not_nat" to "forward" and check that NAT traffic was NAT
        acl_rules = [{"priority": "10", "src_ip": acl_subnet, "action": "forward"}]
        configure_dynamic_nat_rule(duthost, setup_info, interface_type, acl_rules=acl_rules, default=True)

        # Wait for acl rules to update
        wait_timeout(protocol_type, wait_time=45, default=False)
        # Verify the behaviour when the ACL binding action changed from "do_not_nat" to "forward"
        for direction in DIRECTION_PARAMS:
            if protocol_type == 'ICMP' and direction == 'leaf-tor':
                continue
            check_rule_by_traffic(duthost, ptfhost, ptfadapter, testbed, setup_info, direction, interface_type, protocol_type,
                                  icmp_id=POOL_RANGE_START_PORT, handshake=True, nat_type='dynamic', default=True)
        # Change rules ACL rule from "forward" to "do_not_nat" and check that NAT traffic was not NAT
        acl_rules = [{"priority": "10", "src_ip": acl_subnet, "action": "do_not_nat"}]
        configure_dynamic_nat_rule(duthost, setup_info, interface_type, acl_rules=acl_rules, default=True)
        wait_timeout(protocol_type, wait_time=30, default=False)
        for direction in DIRECTION_PARAMS:
            if direction == 'leaf-tor':
                continue
            check_rule_by_traffic(duthost, ptfhost, ptfadapter, testbed, setup_info, direction, interface_type,
                                  protocol_type, exp_source_port=POOL_RANGE_START_PORT, icmp_id=POOL_RANGE_START_PORT,
                                  nat_type='dynamic', default=True, negative=True, action='do_not_nat')
    
    def test_nat_dynamic_zones(self, ptfhost, testbed, duthost, ptfadapter, setup_info, interface_type,
                               protocol_type, zone_type):
        # Prepare configuration for NAT zones modify test
        setup_info_modify_zones = {k: v for (k, v) in setup_info.items()}
        for key in setup_info_modify_zones['interfaces_nat_zone']:
            setup_info_modify_zones['interfaces_nat_zone'][key]['zone_id'] = 0
        # Prepare configuration for NAT zones negative test
        setup_info_negative_zones = {k: v for (k, v) in setup_info.items()}
        for key in setup_info_negative_zones['interfaces_nat_zone']:
            setup_info_negative_zones['interfaces_nat_zone'][key]['zone_id'] = zone_type
        # Check dynamic NAT when all NAT interfaces zones are 0
        self.test_nat_dynamic_basic(ptfhost, testbed, duthost, ptfadapter, setup_info_negative_zones,
                                    interface_type, protocol_type, negative=True)
        conf_ptf_interfaces(ptfhost, duthost, setup_info, interface_type, teardown=True)
        # Check dynamic NAT when all NAT interfaces zones changed to 1
        self.test_nat_dynamic_basic(ptfhost, testbed, duthost, ptfadapter, setup_info,
                                    interface_type, protocol_type, setup_info_modify_zones=setup_info_modify_zones,
                                    negative=True)
