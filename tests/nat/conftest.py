import re
import copy
import time

import pytest

from nat_helpers import SETUP_CONF
from nat_helpers import GLOBAL_NAT_TIMEOUT
from nat_helpers import GLOBAL_TCP_NAPT_TIMEOUT
from nat_helpers import GLOBAL_UDP_NAPT_TIMEOUT
from nat_helpers import FULL_CONE_TEST_SUBNET
from nat_helpers import conf_ptf_interfaces
from nat_helpers import teardown_test_env
from nat_helpers import exec_command
from nat_helpers import conf_dut_routes
from nat_helpers import dut_interface_control
from tests.common.config_reload import config_reload


@pytest.fixture(params=['TCP', 'UDP'])
def protocol_type(request):
    """
    used to parametrized test cases on protocol type
    :param request: pytest request object
    :return: protocol type
    """
    return request.param


def pytest_addoption(parser):
    """
    Adds options to pytest that are used by the NAT tests.
    """
    parser.addoption(
        "--enable_nat_feature",
        action="store_true",
        default=False,
        help="Enable NAT feature on DUT",
    )


@pytest.fixture(scope='module')
def config_nat_feature_enabled(request, duthost):
    """
    Enable NAT feature if optional argument was provided
    :param request: pytest request object
    :param duthost: DUT host object
    """
    if request.config.getoption("--enable_nat_feature"):
        feature_status, _ = duthost.get_feature_status()
        if feature_status['nat'] == 'disabled':
            duthost.shell("sudo config feature state nat enabled")
            time.sleep(2)


@pytest.fixture(autouse=True)
def teardown(duthost):
    """
    Teardown procedure for all test function
    :param duthost: DUT host object
    """
    yield
    # Teardown after test finished
    shutdown_cmds = ["sudo config nat remove {}".format(cmd) for cmd in ["static all", "bindings", "pools", "interfaces"]]
    exec_command(duthost, shutdown_cmds)
    # Clear all enries
    duthost.command("sudo sonic-clear nat translations")


@pytest.fixture(params=["loopback", "port_in_lag"], scope='module')
def setup_test_env(request, ptfhost, duthost, tbinfo):
    """
    setup tbinfo's environment for CT run
    :param request: pytest request object
    :param ptfhost: PTF host object
    :param duthost: DUT host object
    :param tbinfo: Testbed object
    :return: interface type and tbinfo setup info
    """
    interface_type = request.param
    interfaces_nat_zone = {}
    portchannels_port_indices = []
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']
    router_mac = cfg_facts['DEVICE_METADATA']['localhost']['mac']
    config_port_indices = cfg_facts['port_index_map']
    config_portchannels = cfg_facts.get('PORTCHANNEL', {})
    ptf_ports_available_in_topo = ptfhost.host.options['variable_manager'].extra_vars.get("ifaces_map")
    # Get outer port indices
    for port_id in config_portchannels.keys():
        port = config_portchannels[port_id]['members'][0]
        portchannels_port_indices.append(config_port_indices[port])
    inner_port_id = SETUP_CONF[interface_type]["vrf"]["blue"]["port_id"]
    outer_port_id = tbinfo['topo']['properties']['topology']['VMs']['ARISTA01T1']['vlans']
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
    else:
        public_ip = duthost.setup()['ansible_facts']['ansible_Loopback0']['ipv4']['address']

    setup_information = {"router_mac": router_mac,
                         "interfaces_nat_zone": interfaces_nat_zone,
                         "dut_rifs_in_topo_t0": dut_rifs_in_topo_t0,
                         "indices_to_ports_config": indices_to_ports_config,
                         "ptf_ports_available_in_topo": ptf_ports_available_in_topo,
                         "config_portchannels": config_portchannels,
                         "pch_ips": {"PortChannel0001": duthost.setup()['ansible_facts']['ansible_PortChannel0001']['ipv4']['address']},
                         "outer_vrf": ["red"],
                         "inner_vrf": ["blue", "yellow"],
                         interface_type: {"vrf_conf": SETUP_CONF[interface_type]["vrf"],
                                          "inner_zone_interfaces": [inner_zone_interfaces, ],
                                          "outer_zone_interfaces": outer_zone_interfaces,
                                          "inner_port_id": [int(inner_port_id)],
                                          "outer_port_id": outer_port_id,
                                          "src_ip": SETUP_CONF[interface_type]["vrf"]["blue"]["ip"],
                                          "second_src_ip": SETUP_CONF[interface_type]["vrf"]["yellow"]["ip"],
                                          "dst_ip": SETUP_CONF[interface_type]["vrf"]["red"]["ip"],
                                          "public_ip": public_ip,
                                          "gw": duthost.setup()['ansible_facts']['ansible_Vlan1000']['ipv4']['address'],
                                          "acl_subnet": SETUP_CONF[interface_type]["acl_subnet"]
                                         }
                        }
    try:
        # Setup interfaces on PTF container
        conf_ptf_interfaces(tbinfo, ptfhost, duthost, setup_information, interface_type)
    except Exception as err:
        teardown_test_env(tbinfo, duthost, ptfhost, setup_information, interface_type)
        raise err
    yield interface_type, setup_information
    # Remove ptf interfaces
    conf_ptf_interfaces(tbinfo, ptfhost, duthost, setup_information, interface_type, teardown=True)


def nat_global_config(duthost):
    """
    sets DUT's global NAT configuration;
    """
    # Set nat feature enabled
    duthost.command("sudo config feature state nat enabled")
    # Set nat global values
    duthost.command("sudo config nat feature enable")
    duthost.command("sudo config nat set timeout {}".format(GLOBAL_NAT_TIMEOUT))
    duthost.command("sudo config nat set tcp-timeout {}".format(GLOBAL_TCP_NAPT_TIMEOUT))
    duthost.command("sudo config nat set udp-timeout {}".format(GLOBAL_UDP_NAPT_TIMEOUT))

    # Verify nat global values
    output = duthost.command("show nat config globalvalues")
    show_cmd_output = output['stdout'].strip()
    admin_state = re.search(r"Admin Mode.+: (.+)", show_cmd_output).group(1)
    timeout = re.search(r"Global Timeout.+: (\d+)", show_cmd_output).group(1)
    tcp_timeout = re.search(r"TCP Timeout.+: (\d+)", show_cmd_output).group(1)
    udp_timeout = re.search(r"UDP Timeout.+: (\d+)", show_cmd_output).group(1)

    assert admin_state == 'enabled', "NAT was not enabled"
    assert int(timeout) == GLOBAL_NAT_TIMEOUT, "Global NAT timeout was not set to {}".format(GLOBAL_NAT_TIMEOUT)
    assert int(tcp_timeout) == GLOBAL_TCP_NAPT_TIMEOUT, "Global TCP NAT timeout was not set to {}".format(GLOBAL_TCP_NAPT_TIMEOUT)
    assert int(udp_timeout) == GLOBAL_UDP_NAPT_TIMEOUT, "Global UDP NAT timeout was not set to {}".format(GLOBAL_UDP_NAPT_TIMEOUT)


@pytest.fixture(scope='module', autouse=True)
def apply_global_nat_config(duthost, config_nat_feature_enabled):
    """
    applies DUT's global NAT configuration;
    after test run cleanup DUT's NAT configration
    :param duthost: DUT host object
    """
    status, _ = duthost.get_feature_status()
    if 'nat' not in status or status['nat'] == 'disabled':
        pytest.skip('nat feature is not enabled with image version {}'.format(duthost.os_version))

    nat_global_config(duthost)
    yield
    # reload config on teardown
    config_reload(duthost, config_source='minigraph')


@pytest.fixture()
def reload_dut_config(request, duthost, setup_test_env):
    """
    DUT's configuration reload on teardown
    :param request: pytest request object
    :param duthost: DUT host object
    """
    yield
    interface_type, setup_info = setup_test_env
    setup_data = copy.deepcopy(setup_info)
    dut_iface = setup_data[interface_type]["vrf_conf"]["red"]["dut_iface"]
    gw_ip = setup_data[interface_type]["vrf_conf"]["red"]["gw"]
    mask = setup_data[interface_type]["vrf_conf"]["red"]["mask"]
    config_reload(duthost, config_source='minigraph')
    pch_ip = setup_info["pch_ips"][dut_iface]
    duthost.shell("sudo config interface ip remove {} {}/31".format(dut_iface, pch_ip))
    duthost.shell("sudo config interface ip add {} {}/{}".format(dut_iface, gw_ip, mask))
    nat_global_config(duthost)


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
def cleaup_dut_route(request, duthost, setup_test_env):
    """
    Cleanup DUT route(Full cone test)
    :param request: pytest request object
    :param duthost: DUT host object
    :param ptfhost: PTF host object
    :param tbinfo: Testbed object
    :param setup_test_env: Setup information
    """
    yield
    if not request.node.rep_call.skipped:
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        conf_dut_routes(duthost, setup_data, FULL_CONE_TEST_SUBNET, interface_type, teardown=True)


@pytest.fixture()
def enable_outer_interfaces(request, duthost, setup_test_env):
    """
    Enable outer interfaces(Flap interfaces test)
    :param request: pytest request object
    :param duthost: DUT host object
    :param ptfhost: PTF host object
    :param tbinfo: Testbed object
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


@pytest.fixture()
def enable_nat_feature(request, duthost):
    """
    Enable nat feature(NAT disable test)
    :param request: pytest request object
    :param duthost: DUT host object
    """
    yield
    if request.node.rep_call.failed:
        duthost.command("config nat feature enable")


@pytest.mark.trylast
def pytest_collection_modifyitems(items):
    """Remove redundant test cases
    """
    for item in items[:]:
        # Remove static reboot TCs and run for one interface type with one NAT static type
        if ('reboot_static_basic' in item.name and 'port_in_lag' in item.name) or \
           ('reboot_static_napt' in item.name and 'loopback' in item.name):
            items.remove(item)
        # port_in_lag interface type is not valid scenario for add/remove NAT rule
        elif 'test_nat_static_stress_add_remove_nat_rule' in item.name and 'port_in_lag' in item.name:
            items.remove(item)
        # for T0 only portchannel supported
        # Loopback interface type is not valid scenario for interfaces flap
        elif 'test_nat_interfaces_flap_dynamic' in item.name and 'loopback' in item.name:
            items.remove(item)
        elif ('test_nat_dynamic_outside_interface_delete' in item.name and 'loopback' in item.name) or \
             ('test_nat_dynamic_binding_remove' in item.name and 'loopback' in item.name) or \
             ('test_nat_static_iptables_add_remove' in item.name and 'loopback' in item.name) or \
             ('test_nat_static_global_double_add' in item.name and 'loopback' in item.name) or \
             ('test_nat_static_interface_add_remove_interface_ip' in item.name and 'loopback' in item.name) or \
             ('test_nat_static_interface_add_remove_interface' in item.name and 'loopback' in item.name) or \
             ('test_nat_dynamic_iptable_snat' in item.name and 'loopback' in item.name):
            items.remove(item)
