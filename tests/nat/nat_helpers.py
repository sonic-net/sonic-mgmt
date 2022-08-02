import re
import os
import time
import logging
import json
from collections import namedtuple
from netaddr import IPAddress

import ptf.mask as mask
import ptf.packet as packet
import ptf.testutils as testutils
from tests.common.errors import RunAnsibleModuleFail
from tests.common.helpers.assertions import pytest_assert
from jinja2 import Environment, FileSystemLoader
from tests.common.config_reload import config_reload

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
DUT_TMP_DIR = os.path.join('tmp', os.path.basename(BASE_DIR))
NAT_CONF_J2_TEMPLATE = "templates/create_nat_binding.j2"
FILES_DIR = os.path.join(BASE_DIR, 'files')
TEMPLATE_DIR = os.path.join(BASE_DIR, 'templates')
NAT_GLOBAL_TEMPLATE = 'global_nat_table_config.j2'
NAT_STATIC_TEMPLATE = 'static_nat_napt_table_config.j2'
ZONES_TEMPLATE = 'nat_zone_table_config.j2'
NAT_ADMIN_MODE = "enabled"
STATIC_NAT_TABLE_NAME = "STATIC_NAT"
STATIC_NAPT_TABLE_NAME = "STATIC_NAPT"
ACL_TEMPLATE = 'create_acl_rule.j2'
GLOBAL_NAT_TIMEOUT = 300
GLOBAL_UDP_NAPT_TIMEOUT = 120
GLOBAL_TCP_NAPT_TIMEOUT = 300
TCP_GLOBAL_PORT = 3700
UDP_GLOBAL_PORT = 3000
TCP_LOCAL_PORT = 80
UDP_LOCAL_PORT = 161
POOL_RANGE_START_PORT = 5000
POOL_RANGE_END_PORT = 6000
logger = logging.getLogger(__name__)
DYNAMIC_POOL_NAME = "test_pool"
ACL_TABLE_GLOBAL_NAME = "test_acl_table"
DYNAMIC_BINDING_NAME = "test_binding"
ACL_SUBNET = "192.168.0.0/24"
BR_MAC = ["22:22:22:22:22:21"]
PORT_CHANNEL_TEMP = 'PortChannel10{}'
VRF = {"red": {"ip": "11.1.0.2", "id": "1", "mask": "30", "gw": "11.1.0.1", "dut_iface": PORT_CHANNEL_TEMP.format(1), "port_id": {"t0": ["28"],
                                                                                                                        "t0-64": ["0", "1"],
                                                                                                                        "t0-64-32": ["0", "1"]
                                                                                                                       }
              },
       "blue": {"ip": "192.168.0.101", "id": "2", "mask": "24", "gw": "192.168.0.1", "port_id": "6"},
       "yellow": {"ip": "192.168.0.201", "id": "3", "mask": "24", "gw": "192.168.0.1", "port_id": "7"}
      }
SETUP_CONF = {"loopback": {"vrf": VRF, "acl_subnet": ACL_SUBNET},
              "port_in_lag": {"vrf": VRF, "acl_subnet": ACL_SUBNET}
             }
DIRECTION_PARAMS = ['host-tor', 'leaf-tor']
FULL_CONE_TEST_IP = "172.20.1.2"
FULL_CONE_TEST_SUBNET = "172.20.1.0/24"
REBOOT_MAP = {'cold': {"timeout": 300}, 'fast': {"timeout": 180}, 'warm': {"timeout": 180}}
PTF_NETWORK_DATA = namedtuple('PTF_NETWORK_DATA', ['outer_ports', 'inner_ports', 'eth_dst', 'eth_src', 'ip_src',
                                                   'ip_dst', 'public_ip', 'private_ip', 'exp_src_ip', 'exp_dst_ip'])
L4_PORTS_DATA = namedtuple('L4_PORTS_DATA', ['src_port', 'dst_port', 'exp_src_port', 'exp_dst_port'])


def check_peers_by_ping(duthost):
    for vrf in VRF:
        duthost.command("ping {0} -c 5".format(VRF[vrf]['ip']))


def configure_nat_over_cli(duthost, action, nat_type, global_ip, local_ip, proto=None,
                           global_port=None, local_port=None):
    """
    static NAT/NAPT CLI wrapper
    :param duthost: DUT host object
    :param action: string rule action
    :param nat_type: string static nat type
    :param global_ip: string global IP address value
    :param local_ip: string local IP address value
    :param proto: string protocol type
    :param global_port: string global l4 port
    :param local_port: string local l4 port
    :return : dict with rule parameters
    """
    action_type_map = {'add': '-nat_type dnat', 'remove': ''}
    if nat_type == 'static_nat':
        duthost.command("sudo config nat {} static basic {} {} {}".format(action, global_ip, local_ip, action_type_map[action]))
        return {
            global_ip: {'local_ip': local_ip, 'nat_type': 'dnat'}
            }
    elif nat_type == 'static_napt':
        duthost.command("sudo config nat {} static {} {} {} {} {} {}".format(action, proto.lower(),
                                                                             global_ip, global_port,
                                                                             local_ip, local_port,
                                                                             action_type_map[action]))
        return {
            "{}|{}|{}".format(global_ip, proto.upper(), global_port): {'local_ip': local_ip,
                                                                       'local_port': "{}".format(local_port),
                                                                       'nat_type': 'dnat'
                                                                      }
            }
    return "Unkown NAT type"


def nat_statistics(duthost, show=False, clear=False):
    """
    NAT CLI helper which gets or clears NAT statistics
    :param duthost: DUT host object
    :param show: bool
    :param clear: bool
    :return : formatted CLI output
    """
    if show:
        output_cli = exec_command(duthost, ["show nat statistics"])
        if output_cli["rc"]:
            raise Exception('Return code is {} not 0'.format(output_cli["rc"]))
        output = {}
        entries = output_cli["stdout"].split()[10:]
        if entries:
            num_entries = len(entries[::5])
            keys = output_cli["stdout"].split()[:5]
            for num in range(0, num_entries):
                entry_values = entries[(num * 5):(num * 5) + 5]
                key = entry_values[1] if entry_values[1] != "---" else entry_values[2]
                output[key] = {keys[i]: entry_values[i] for i in range(0, len(keys))}
        return output
    elif clear:
        output_cli = exec_command(duthost, ["sudo sonic-clear nat statistics"])
        if output_cli["rc"]:
            raise Exception('Return code is {} not 0'.format(output_cli["rc"]))
        return output_cli["stdout"].lstrip()
    return None


def dut_nat_iptables_status(duthost):
    """
    NAT CLI helper gets DUT's iptables entries
    :param duthost: DUT host object
    :return : dict with nat PREROUTING/POSTROUTING iptables entries
    """
    nat_table_status = {}
    output_cli = exec_command(duthost, ["sudo iptables -nL -t nat"])
    if output_cli["rc"]:
        raise Exception('Return code is {} not 0'.format(output_cli["rc"]))
    entries = output_cli["stdout"].split("\n")
    index_prerouting = [i for i in range(0, len(entries)) if "PREROUTING" in entries[i]][0] + 2
    index_input = [i for i in range(0, len(entries)) if "INPUT" in entries[i]][0]
    index_postrouting = [i for i in range(0, len(entries)) if 'POSTROUTING' in entries[i]][0] + 2
    if any(['DOCKER' in entry for entry in entries]):
        index_docker = [i for i in range(0, len(entries)) if 'DOCKER' in entries[i]][0]
        postrouting = [el for el in entries[index_postrouting:index_docker] if len(el) > 1]
    else:
        postrouting = [el for el in entries[index_postrouting:] if len(el) > 1]
    prerouting = [el for el in entries[index_prerouting:index_input] if len(el) > 0]
    nat_table_status["prerouting"] = [" ".join([s.strip() for s in el.split() if len(el) > 0])
                                      for el in prerouting]
    nat_table_status["postrouting"] = [" ".join([s.strip() for s in el.split() if len(el) > 0])
                                       for el in postrouting]
    return nat_table_status


def dut_interface_status(duthost, interface_name):
    """
    NAT CLI helper gets DUT's interface status
    :param duthost: DUT host object
    :param interface_name: string interface to configure
    :return : string formatted CLI output with interface current operstatus
    """
    return duthost.show_interface(command='status', interfaces=interface_name)['ansible_facts']['int_status'][interface_name]['oper_state']


def dut_interface_control(duthost, action, interface_name, ip_addr=""):
    """
    NAT CLI helper enable/disable DUT's interface
    :param duthost: DUT host object
    :param action: string action to configure interface
    :param interface_name: string interface to configure
    :return : formatted CLI output with interface current operstatus
    """
    interface_actions = {"disable": "shutdown {}".format(interface_name),
                         "enable": "startup {}".format(interface_name),
                         "ip remove": "{} {}".format(action, ip_addr),
                         "ip add": "{} {}".format(action, ip_addr)
                        }
    expected_operstatus = {"disable": "down", "enable": "up", "ip remove": "up", "ip add": "up"}
    output_cli = exec_command(duthost, ["sudo config interface {}".format(interface_actions[action])])
    if output_cli["rc"]:
        raise Exception('Return code is {} not 0'.format(output_cli["rc"]))
    attempts = 3
    current_operstatus = dut_interface_status(duthost, interface_name)
    while current_operstatus != expected_operstatus[action]:
        if attempts == 0:
            break
        time.sleep(15)
        current_operstatus = dut_interface_status(duthost, interface_name)
        attempts -= 1
    return current_operstatus


def nat_translations(duthost, show=False, clear=False):
    """
    NAT CLI helper which gets or clears NAT translations
    :param duthost: DUT host object
    :param show: bool
    :param clear: bool
    :return : formatted CLI output
    """
    if show:
        output_cli = exec_command(duthost, ["show nat translations"])
        if output_cli["rc"]:
            raise Exception('Return code is {} not 0'.format(output_cli["rc"]))
        output = {}
        entries = output_cli["stdout"].split('\n')[15:]
        splited_entries = []
        for el in entries:
            splited_entries.extend(el.split())
        if splited_entries:
            num_entries = len(splited_entries[::5])
            keys = [el.strip() for el in output_cli["stdout"].split("\n")[13].split("  ") if el]
            for num in range(0, num_entries):
                entry_values = splited_entries[(num * 5):(num * 5) + 5]
                key = entry_values[1] if entry_values[1] != "---" else entry_values[2]
                output[key] = {keys[i]: entry_values[i] for i in range(0, len(keys))}
        return output
    elif clear:
        output_cli = exec_command(duthost, ["sudo sonic-clear nat translations"])
        if output_cli["rc"]:
            raise Exception('Return code is {} not 0'.format(output_cli["rc"]))
        return output_cli["stdout"].lstrip()
    return None


def crud_operations_basic(duthost, crud_operation):
    """
    static NAT CLI helper
    :param duthost: DUT host object
    :param crud_operation: dict dict with action and rule parameters
    :return : dict with rule parameters
    """
    nat_type = "static_nat"
    for key in crud_operation.keys():
        output = configure_nat_over_cli(duthost, crud_operation[key]["action"], nat_type,
                                        crud_operation[key]["global_ip"], crud_operation[key]["local_ip"])
    return output


def crud_operations_napt(duthost, crud_operation):
    """
    static NAPT CLI helper
    :param duthost: DUT host object
    :param crud_operation: dict dict with action and rule parameters
    :return : dict with rule parameters
    """
    nat_type = 'static_napt'
    for key in crud_operation.keys():
        output = configure_nat_over_cli(duthost, crud_operation[key]["action"], nat_type,
                                        crud_operation[key]["global_ip"], crud_operation[key]["local_ip"],
                                        proto=crud_operation[key]["proto"],
                                        global_port=crud_operation[key]["global_port"],
                                        local_port=crud_operation[key]["local_port"])
    return output


def exec_command(host, command_list):
    """
    Executes shell commands on host
    :param host: host object
    :param command_list: list of commands to execute
    :return : response from host or exception __str__
    """
    if len(command_list) == 1:
        try:
            response = host.shell(command_list[0])
            return response
        except Exception as e:
            return e.__str__()
    else:
        for command in command_list:
            exec_command(host, [command])


def nat_zones_config(duthost, setup_info, interface_type):
    """
    generate and deploy NAT zones configuration files
    :param duthost: DUT host object
    :param setup_info: dict, setup info fixture
    :param interface_type: interface type
    """
    # Get inner and outer interfaces from setup info
    inner_zone_interfaces = setup_info[interface_type]["inner_zone_interfaces"]
    outer_zone_interfaces = setup_info[interface_type]["outer_zone_interfaces"]
    for rif in setup_info["dut_rifs_in_topo_t0"]:
        if rif in inner_zone_interfaces or rif in outer_zone_interfaces:
            nat_zone_vars = setup_info['interfaces_nat_zone'][rif]
            # Add zone configuration
            duthost.command("sudo config nat add interface {0} -nat_zone {1}".format(rif, nat_zone_vars['zone_id']))
            # Check that zone was applied
            show_zones = duthost.command("show nat config zones")['stdout']
            zone_id = re.search(r"{}\s+(\d)".format(rif), show_zones).group(1)
            pytest_assert(str(nat_zone_vars['zone_id']) == zone_id, "NAT zone was not set to {}".format(zone_id))


def get_cli_show_nat_config_output(duthost, command):
    """
    created ditionary with output of show nat command
    :param duthost: DUT host object
    :param command: str, command to execute
    :return: list of dict with output
    """
    return duthost.show_and_parse("show nat config {}".format(command))


def apply_static_nat_config(duthost, ptfadapter, ptfhost, setup_data,
                            network_data, direction, interface_type, nat_type, public_ip,
                            private_ip, protocol_type=None, nat_entry=None, handshake=False):
    """
    generate and deploy  static NAT/NAPT configuration files
    :param duthost: DUT host object
    :param ptfadapter: ptf adapter fixture
    :param ptfhost: PTF host object
    :param setup_info: dict, setup info fixture
    :param direction: string, traffic's flow direction
    :param interface_type: interface type
    :param nat_type: string, static NAT type
    :param public_ip: IP Address of Internet IP (host-tor) or IP Address of Public Interface (leaf-tor)
    :param private_ip: IP Address of Local IP (host-tor) or IP Address of Internet IP (leaf-tor)
    :param nat_entry: static_nat/static_napt
    :param protocol_type: TCP/UDP
    """

    # Define network data and L4 ports
    network_data = get_network_data(ptfadapter, setup_data, direction, interface_type, nat_type=nat_type)
    src_port, dst_port = get_l4_default_ports(protocol_type)
    global_port = dst_port
    local_port = src_port
    if nat_entry != 'static_napt':
        # Add static basic rule
        duthost.command("sudo config nat add static basic {0} {1} -nat_type=dnat".format(public_ip, private_ip))
    else:
        # Add static napt rule
        duthost.command("sudo config nat add static {0} {1} {2} {3} {4} -nat_type=dnat".
                        format(protocol_type.lower(), public_ip, global_port, private_ip, local_port))
    # Check that rule was applied
    static_nat = get_cli_show_nat_config_output(duthost, "static")
    pytest_assert('dnat' == static_nat[0]['nat type'], "Default NAT type was changed")
    pytest_assert(public_ip == static_nat[0]['global ip'], "Global IP does not match {}".format(public_ip))
    pytest_assert(private_ip == static_nat[0]['local ip'], "Local IP does not match {}".format(private_ip))
    if nat_entry == 'static_napt':
        pytest_assert(protocol_type == static_nat[0]['ip protocol'], "Protocol does not match {}".format(protocol_type))
        pytest_assert(str(global_port) == static_nat[0]['global port'], "Global Port does not match {}".format(global_port))
        pytest_assert(str(local_port) == static_nat[0]['local port'], "Local Port does not match {}".format(local_port))
    else:
        pytest_assert('all' == static_nat[0]['ip protocol'])
    nat_zones_config(duthost, setup_data, interface_type)
    # Perform TCP handshake
    if handshake:
        if direction == 'leaf-tor':
            # set_arp entries
            check_peers_by_ping(duthost)
        perform_handshake(ptfhost, setup_data,
                          protocol_type, direction,
                          network_data.ip_dst, dst_port,
                          network_data.ip_src, src_port,
                          network_data.public_ip)


def get_src_port(setup_info, direction, interface_type, second_port=False):
    """
    return source port ids based on test case direction and interface_type
    :param setup_info: setup info fixture
    :param direction: 'host-tor', 'leaf-tor'
    :param interface_type: type of interface
    :param second_port: boolean if second port id needs to be returned
    :return: source port ids
    """
    if direction == 'host-tor':
        if second_port:
            return [setup_info[interface_type]['inner_port_id'][0] + 1]
        return setup_info[interface_type]['inner_port_id']
    return setup_info[interface_type]['outer_port_id']


def get_dst_port(setup_info, direction, interface_type, second_port=False):
    """
    return destination port ids based on test case direction and interface_type
    :param setup_info: setup info fixture
    :param direction: 'host-tor', 'leaf-tor'
    :param interface_type: type of interface
    :param second_port: boolean if second port id needs to be returned
    :return: destination port ids
    """
    if direction == 'leaf-tor':
        if second_port:
            return [setup_info[interface_type]['inner_port_id'][0] + 1]
        return setup_info[interface_type]['inner_port_id']
    return setup_info[interface_type]['outer_port_id']


def get_src_ip(setup_info, direction, interface_type, nat_type=None, second_port=False):
    """
    return source IP based on test case direction and interface_type
    :param setup_info: setup info fixture
    :param direction: 'host-tor', 'leaf-tor'
    :param interface_type: type of interface
    :param second_port: boolean if second port's IP settings need to be returned
    :param nat_type: string nat type
    :return: source IP
    """
    if direction == 'host-tor' or nat_type == "static_napt":
        if second_port:
            return setup_info[interface_type]["second_src_ip"]
        return setup_info[interface_type]['src_ip']
    return setup_info[interface_type]['dst_ip']


def get_dst_ip(setup_info, direction, interface_type, nat_type=None):
    """
    return destination IP based on test case direction and interface_type
    :param setup_info: setup info fixture
    :param direction: 'host-tor', 'leaf-tor'
    :param interface_type: type of interface
    :param nat_type: string nat type
    :return: destination IP
    """
    if direction == 'host-tor' or nat_type == "static_napt":
        return setup_info[interface_type]['dst_ip']
    return setup_info[interface_type]['public_ip']


def get_public_ip(setup_info, interface_type):
    """
    return public IP based on test case interface_type
    :param setup_info: setup info fixture
    :param interface_type: type of interface
    :return: public IP
    """
    return setup_info[interface_type]['public_ip']


def setup_ptf_interfaces(testbed, ptfhost, duthost, setup_info, interface_type, vrf_id, vrf_name, port_id,
                         ip_address, mask, gw_ip, key):
    """
    setup ptf interfaces for tests
    :param testbed: Testbed object
    :param ptfhost: PTF host object
    :param duthost: DUT host object
    :param setup_info: setup info fixture
    :param interface_type: string interface type
    :param vrf_id: id of vrf
    :param vrf_name: vrf name
    :param port_id: port id of interface
    :param ip_address: ip address of interface
    :param mask: vrf mask
    :param gw_ip: ip address of gateway
    :param key: dictionary key if vrf configuration
    """

    ptfhost.shell("grep -Fxq '{} {}' /etc/iproute2/rt_tables "
                  "|| echo '{} {}' >> /etc/iproute2/rt_tables".format(vrf_id, vrf_name, vrf_id, vrf_name))
    ptfhost.shell("ip link add {} type vrf table {}".format(vrf_name, vrf_id))
    ptfhost.shell("ip link set dev {} up".format(vrf_name))
    if vrf_name == "red":
        bond_interface = "bond1"
        ptfhost.shell("ip link add {} type bond".format(bond_interface))
        ptfhost.shell("ip link set {} type bond miimon 100 mode balance-xor".format(bond_interface))
        for iface_id in port_id[testbed['topo']['name']]:
            ptfhost.shell("ip link set eth{} down".format(iface_id))
            ptfhost.shell("ip link set eth{} master {}".format(iface_id, bond_interface))
        ptfhost.shell("ip link set dev {} up".format(bond_interface))
        ptfhost.shell("ifconfig {} hw ether {}".format(bond_interface, BR_MAC[0]))
        ptfhost.shell("ifconfig {} mtu 9216 up".format(bond_interface))
        ptfhost.shell("ip link set {} master {}".format(bond_interface, vrf_name))
        ptfhost.shell("ip addr add {}/{} dev {}".format(ip_address, mask, bond_interface))
    else:
        ptfhost.shell("ip link set eth{} master {}".format(port_id, vrf_name))
        ptfhost.shell("ip addr add {}/{} dev eth{}".format(ip_address, mask, port_id))
    ptfhost.shell("ip rule add iif {} table {}".format(vrf_name, vrf_id))
    ptfhost.shell("ip rule add oif {} table {}".format(vrf_name, vrf_id))
    ptfhost.shell("ip route add 0.0.0.0/0 via {} table {}".format(gw_ip, vrf_id))
    if "dut_iface" in setup_info[interface_type]["vrf_conf"][key].keys():
        dut_iface = setup_info[interface_type]["vrf_conf"][key]["dut_iface"]
        pch_ip = setup_info["pch_ips"][dut_iface]
        pch_mask = setup_info["pch_masks"][dut_iface]
        mask_prefix = IPAddress(pch_mask).netmask_bits()

        duthost.shell("sudo config interface ip remove {} {}/{}".format(dut_iface, pch_ip, mask_prefix))
        duthost.shell("sudo config interface ip add {} {}/{}".format(dut_iface, gw_ip, mask))


def teardown_ptf_interfaces(testbed, ptfhost, gw_ip, vrf_id, ip_address, mask, port_id, vrf_name):
    """
    teardown ptf interfaces after tests
    :param testbed: Testbed object
    :param ptfhost: PTF host object
    :param gw_ip: ip address of gateway
    :param vrf_id: id of vrf
    :param ip_address: ip address of interface
    :param mask: vrf mask
    :param port_id: port id of interface
    :param vrf_name: vrf name
    """
    ptfhost.shell("ip route del 0.0.0.0/0 via {} table {}".format(gw_ip, vrf_id))
    if vrf_name == "red":
        bond_interface = "bond1"
        ptfhost.shell("ip addr del {}/{} dev {}".format(ip_address, mask, bond_interface))
        ptfhost.shell("ip rule del iif {} table {}".format(vrf_name, vrf_id))
        ptfhost.shell("ip rule del oif {} table {}".format(vrf_name, vrf_id))
        ptfhost.shell("ip link set {} nomaster".format(bond_interface))
        for iface_id in port_id[testbed['topo']['name']]:
            ptfhost.shell("ip link set eth{} nomaster".format(iface_id))
            ptfhost.shell("ip link set eth{} up".format(iface_id))
        ptfhost.shell("ip link del {}".format(bond_interface))
        ptfhost.shell("ip link del {} type vrf table {}".format(vrf_name, vrf_id))
    else:
        ptfhost.shell("ip addr del {}/{} dev eth{}".format(ip_address, mask, port_id))
        ptfhost.shell("ip rule del iif {} table {}".format(vrf_name, vrf_id))
        ptfhost.shell("ip rule del oif {} table {}".format(vrf_name, vrf_id))
        ptfhost.shell("ip link set eth{} nomaster".format(port_id))
        ptfhost.shell("ip link del {} type vrf table {}".format(vrf_name, vrf_id))


def conf_ptf_interfaces(testbed, ptfhost, duthost, setup_info, interface_type, teardown=False):
    """
    setup testbed's environment for CT run
    :param testbed: Testbed object
    :param ptfhost: PTF host object
    :param duthost: DUT host object
    :param setup_info: setup info fixture
    :param interface_type: string interface type
    :param teardown: Boolean parameter to remove or not PTF's interfaces config
    """
    if not teardown:
        ptfhost.script("./scripts/change_mac.sh")
    for key in setup_info[interface_type]["vrf_conf"]:
        vrf_id = setup_info[interface_type]["vrf_conf"][key]["id"]
        vrf_name = key
        ip_address = setup_info[interface_type]["vrf_conf"][key]["ip"]
        gw_ip = setup_info[interface_type]["vrf_conf"][key]["gw"]
        port_id = setup_info[interface_type]["vrf_conf"][key]["port_id"]
        mask = setup_info[interface_type]["vrf_conf"][key]["mask"]
        if teardown:
            teardown_ptf_interfaces(testbed, ptfhost, gw_ip, vrf_id, ip_address, mask, port_id, vrf_name)
        else:
            setup_ptf_interfaces(testbed, ptfhost, duthost, setup_info, interface_type, vrf_id, vrf_name, port_id, ip_address,
                                 mask, gw_ip, key)
    if not teardown:
        ptfhost.shell('supervisorctl restart ptf_nn_agent')


def expected_mask_nated_packet(pkt, protocol_type, ip_dst, ip_src,
                               src_port=None, dst_port=None, icmp_id=None):
    """
    Generate expected packet
    :param pkt: packet to be sent
    :param protocol_type: protocol type TCP, UDP or ICMP
    :param ip_src: expected source IP
    :param ip_dst: expected destination IP
    :param src_port: source L4 expected port
    :param dst_port: destination L4 expected port
    :param icmp_id: id for specify ICMP dynamic connection
    :return: expected packet
    """
    # Set up all fields
    exp_pkt = pkt.copy()
    exp_pkt['IP'].ttl -= 1
    exp_pkt['IP'].dst = ip_dst
    exp_pkt['IP'].src = ip_src
    if protocol_type in ["TCP", "UDP"]:
        exp_pkt[protocol_type].sport = src_port
        exp_pkt[protocol_type].dport = dst_port
    if protocol_type == "ICMP":
        exp_pkt[protocol_type].id = icmp_id
    exp_pkt = mask.Mask(exp_pkt)
    exp_pkt.set_do_not_care_scapy(packet.Ether, 'dst')
    exp_pkt.set_do_not_care_scapy(packet.Ether, 'src')
    exp_pkt.set_do_not_care_scapy(packet.IP, 'chksum')
    exp_pkt.set_do_not_care_scapy(packet.IP, 'id')
    return exp_pkt


def create_packet(eth_dst, eth_src, ip_dst, ip_src, protocol_type, sport=None, dport=None):
    """
    generate packet to send
    :param eth_dst: destination Ethernet address
    :param eth_src: source Ethernet address
    :param ip_dst: destination IP address
    :param ip_src: source IP address
    :param protocol_type: TCP/UDP/ICMP
    :param sport: source port for UDP/TCP packet
    :param dport: destination port for UDP/TCP traffic
    :return: packet based on protocol type
    """
    if protocol_type == "TCP":
        return testutils.simple_tcp_packet(eth_dst=eth_dst, eth_src=eth_src, ip_dst=ip_dst, ip_src=ip_src,
                                           tcp_sport=sport, tcp_dport=dport, ip_ttl=64)
    elif protocol_type == "UDP":
        return testutils.simple_udp_packet(eth_dst=eth_dst, eth_src=eth_src, ip_dst=ip_dst, ip_src=ip_src,
                                           udp_sport=sport, udp_dport=dport, ip_ttl=64)
    return testutils.simple_icmp_packet(eth_dst=eth_dst, eth_src=eth_src, ip_dst=ip_dst, ip_src=ip_src, icmp_type=8,
                                        icmp_code=0, ip_ttl=64)


def teardown_test_env(testbed, duthost, ptfhost, setup_info, interface_type, reboot=False, before_test=False):
    """
    teardown function cleans DUT's config and PTF's interfaces
    :param duthost: duthost fixture
    :param ptfhost: ptfhost fixture
    :param setup_info: setup_info fixture
    :param interface_type: string interface type
    :param reboot: if True perform DUT reboot
    :param  before_test: boolean to not clear/clear PTF configuration
    """
    # reset dut to initial T0 configuration
    if reboot:
        duthost.command('reboot')
    else:
        config_reload(duthost)
    # wait for dut become stable
    time.sleep(180)
    # remove ptf interfaces configuration
    if not before_test:
        conf_ptf_interfaces(testbed, ptfhost, duthost, setup_info, interface_type, teardown=True)


def get_network_data(ptfadapter, setup_info, direction, interface_type, nat_type=None, second_port=False):
    """
    Gets network data: MACs, IPs, inner/outer ports ids

        Args:
            ptfadapter: ptf adapter fixture
            setup_info: setup_info fixture
            direction: string with current flow direction
            interface_type: string interface type
            nat_type: string with static napt/nat/dynamic types
            second_port: boolean if second port id needs to be returned
    """
    # Get outer and inner ports
    outer_ports = get_dst_port(setup_info, direction, interface_type,
                               second_port=second_port)
    inner_ports = get_src_port(setup_info, direction, interface_type,
                               second_port=second_port)
    mac_map = {"host-tor": ptfadapter.dataplane.get_mac(0, inner_ports[0]), "leaf-tor": BR_MAC[0]}
    # Get source and destination IPs for packets to send
    ip_src = get_src_ip(setup_info, direction, interface_type,
                        nat_type=nat_type, second_port=second_port)
    ip_dst = get_dst_ip(setup_info, direction, interface_type,
                        nat_type=nat_type)
    # Define expected source and destination IP based on direction
    if nat_type == "static_napt" and direction == "leaf-tor":
        exp_dst_ip = ip_src
        ip_src = ip_dst
        ip_dst = setup_info[interface_type]["public_ip"]
        exp_src_ip = ip_src
    elif direction == 'host-tor':
        exp_dst_ip = setup_info[interface_type]["dst_ip"]
        exp_src_ip = setup_info[interface_type]["public_ip"]
    else:
        exp_dst_ip = setup_info[interface_type]["src_ip"]
        exp_src_ip = setup_info[interface_type]["dst_ip"]
        if second_port:
            exp_dst_ip = setup_info[interface_type]["second_src_ip"]
    # Get MAC addresses for packets to send
    eth_dst = setup_info['router_mac']
    eth_src = mac_map[direction]
    # Get public and private IPs for NAT configuration
    public_ip = get_public_ip(setup_info, interface_type)
    private_ip = get_src_ip(setup_info, direction, interface_type, nat_type, second_port)
    return PTF_NETWORK_DATA(outer_ports, inner_ports, eth_dst, eth_src, ip_src, ip_dst, public_ip, private_ip, exp_src_ip, exp_dst_ip)


def perform_handshake(ptfhost, setup_info, protocol_type, direction,
                      ip_dst, dest_l4_port, ip_src, source_l4_port, public_ip, second_port=False):
    """
    Performs TCP handshake to initiate NAT translation

        Args:
            ptfhost: ptf host fixture
            setup_info: setup_info fixture
            protocol_type: sting with TCP/UDP values
            direction: string with current flow direction
            ip_dst: IP destination
            dest_l4_port: destination L4 port
            ip_src: IP source
            source_l4_port: source L4 port
            public_ip: Public IP
            second_port: boolean if second port id needs to be returned
            n_perf: int specifing number of connection for performance test
    """
    src_vrf = setup_info["inner_vrf"][0]
    dst_vrf = setup_info["outer_vrf"][0]
    if second_port:
        src_vrf = setup_info["inner_vrf"][1]
        dst_vrf = setup_info["outer_vrf"][1]

    if direction == "host-tor":
        echo_cmd = "python /tmp/nat_ptf_echo.py {} {} {} {} {} {} {} None &".format(protocol_type.lower(),
                                                                                    ip_dst, dest_l4_port,
                                                                                    ip_src, source_l4_port,
                                                                                    dst_vrf, src_vrf)
    else:
        echo_cmd = "python /tmp/nat_ptf_echo.py {} {} {} {} {} {} {} {} &".format(protocol_type.lower(),
                                                                                  ip_src, source_l4_port,
                                                                                  ip_dst, dest_l4_port,
                                                                                  dst_vrf, src_vrf,
                                                                                  public_ip)
    ptfhost.copy(src="./scripts/nat_ptf_echo.py", dest="/tmp")
    ptfhost.command(echo_cmd)


def generate_and_verify_traffic(duthost, ptfadapter, setup_info, interface_type, direction, protocol_type, nat_type, second_port=False,
                                src_port=None, dst_port=None, exp_src_port=None, exp_dst_port=None):
    """
    Generates TCP/UDP traffic and checks that traffic is translated due to NAT types/rules

        Args:
            duthost: duthost fixture
            ptfadapter: ptf adapter fixture
            setup_info: setup_info fixture
            interface_type: string interface type
            direction: string with current flow direction
            protocol_type: sting with TCP/UDP values
            nat_type: string with static napt/nat/dynamic types
            second_port: boolean if second port id needs to be returned
            src_port: L4 source port in packet to send
            dst_port: L4 destination port in packet to send
            exp_src_port: L4 source port in expected packet
            exp_dst_port: L4 destination port in expected packet
    """
    # Define network data and L4 ports
    network_data = get_network_data(ptfadapter, setup_info, direction, interface_type, nat_type=nat_type, second_port=second_port)
    if nat_type != 'dynamic':
        l4_ports = get_static_l4_ports(protocol_type, direction, nat_type)
    else:
        l4_ports = get_dynamic_l4_ports(duthost, protocol_type, direction, network_data.public_ip)
    if src_port is None:
        src_port = l4_ports.src_port
    if dst_port is None:
        dst_port = l4_ports.dst_port
    if exp_src_port is None:
        exp_src_port = l4_ports.exp_src_port
    if exp_dst_port is None:
        exp_dst_port = l4_ports.exp_dst_port
    # Create packet to send
    pkt = create_packet(network_data.eth_dst, network_data.eth_src,
                        network_data.ip_dst, network_data.ip_src,
                        protocol_type, sport=src_port, dport=dst_port)
    # Define expected packet
    exp_pkt = expected_mask_nated_packet(pkt, protocol_type, network_data.exp_dst_ip, network_data.exp_src_ip,
                                         src_port=exp_src_port, dst_port=exp_dst_port)
    # clear buffer
    ptfadapter.dataplane.flush()
    # Send packet
    for port in network_data.inner_ports:
        testutils.send(ptfadapter, port, pkt, count=5)
    # Verify that expected packets arrive on outer ports
    testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=network_data.outer_ports)


def generate_and_verify_not_translated_traffic(ptfadapter, setup_info, interface_type, direction, protocol_type, nat_type, second_port=False,
                                               ip_src=None, ip_dst=None, exp_ip_src=None, exp_ip_dst=None):
    """
    Generates TCP/UDP traffic and checks that traffic is not translated due to NAT types/rules

        Args:
            ptfadapter: ptf adapter fixture
            setup_info: setup_info fixture
            interface_type: string interface type
            direction: string with current flow direction
            protocol_type: sting with TCP/UDP values
            nat_type: string with static napt/nat/dynamic types
            second_port: boolean if second port id needs to be returned
            ip_src: IP source in packet to send
            ip_dst: IP destination in packet to send
            exp_ip_src: IP source in expected packet
            exp_ip_dst: IP destination in expected packet
    """
    # Define network data and L4 ports
    network_data = get_network_data(ptfadapter, setup_info, direction, interface_type, nat_type=nat_type, second_port=second_port)
    src_port, dst_port = get_l4_default_ports(protocol_type)
    if ip_src is None:
        ip_src = network_data.ip_src
    if ip_dst is None:
        ip_dst = network_data.ip_dst
    if exp_ip_src is None:
        exp_ip_src = network_data.ip_src
    if exp_ip_dst is None:
        exp_ip_dst = network_data.ip_dst
    # Create packet to send
    pkt = create_packet(network_data.eth_dst, network_data.eth_src, ip_dst, ip_src,
                        protocol_type, sport=src_port, dport=dst_port)
    # Define expected packet
    exp_pkt = expected_mask_nated_packet(pkt, protocol_type, exp_ip_dst, exp_ip_src,
                                         src_port=src_port, dst_port=dst_port)
    # clear buffer
    ptfadapter.dataplane.flush()
    # Send packet
    for port in network_data.inner_ports:
        testutils.send(ptfadapter, port, pkt, count=5)
    # Verify that expected packets arrive on outer ports
    testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=network_data.outer_ports)


def generate_and_verify_traffic_dropped(ptfadapter, setup_info, interface_type, direction, protocol_type, nat_type,
                                        src_port, dst_port, exp_src_port, exp_dst_port, second_port=False):
    """
    Generates TCP/UDP traffic and checks that traffic is dropped

        Args:
            ptfadapter: ptf adapter fixture
            setup_info: setup_info fixture
            interface_type: string interface type
            direction: string with current flow direction
            protocol_type: sting with TCP/UDP values
            nat_type: string with static napt/nat/dynamic types
            src_port: L4 source port in packet to send
            dst_port: L4 destination port in packet to send
            exp_src_port: L4 source port in expected packet
            exp_dst_port: L4 destination port in expected packet
            second_port: boolean if second port id needs to be returned
    """
    # Define network data and L4 ports
    network_data = get_network_data(ptfadapter, setup_info, direction, interface_type, nat_type=nat_type, second_port=second_port)
    # Create packet to send
    pkt = create_packet(network_data.eth_dst, network_data.eth_src,
                        network_data.ip_dst, network_data.ip_src,
                        protocol_type, sport=src_port, dport=dst_port)
    # Define expected packet
    exp_pkt = expected_mask_nated_packet(pkt, protocol_type, network_data.exp_dst_ip, network_data.exp_src_ip,
                                         src_port=exp_src_port, dst_port=exp_dst_port)
    # clear buffer
    ptfadapter.dataplane.flush()
    # Send packet
    for port in network_data.inner_ports:
        testutils.send(ptfadapter, port, pkt, count=5)
    # Verify that expected packets arrive on outer ports
    testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=network_data.outer_ports)


def generate_and_verify_icmp_traffic(ptfadapter, setup_info, interface_type, direction, nat_type, second_port=False, icmp_id=None):
    """
    Generates ICMP traffic and checks that traffic is translated due to NAT types/rules.

        Args:
            ptfadapter: ptf adapter fixture
            setup_info: setup_info fixture
            interface_type: string interface type
            direction: string with current flow direction
            nat_type: string with static napt/nat/dynamic types
            second_port: boolean if second port id needs to be returned
            icmp_id: id for specify ICMP dynamic connection
    """
    protocol_type = 'ICMP'
    # Define network data
    network_data = get_network_data(ptfadapter, setup_info, direction, interface_type, nat_type=nat_type, second_port=second_port)
    # Create packet to send
    pkt = create_packet(network_data.eth_dst, network_data.eth_src, network_data.ip_dst, network_data.ip_src, protocol_type)
    # Define expected packet(ICMP request)
    exp_pkt_request = expected_mask_nated_packet(pkt, protocol_type, network_data.exp_dst_ip, network_data.exp_src_ip, icmp_id=icmp_id)
    # Reverse source and destination IPs for reply
    exp_dst_ip = get_src_ip(setup_info, direction, interface_type,
                            nat_type=nat_type, second_port=second_port)
    exp_src_ip = get_dst_ip(setup_info, direction, interface_type,
                            nat_type=nat_type)
    # Define expected packet(ICMP reply)
    exp_pkt_reply = expected_mask_nated_packet(pkt, protocol_type, exp_dst_ip, exp_src_ip, icmp_id=0)
    exp_pkt_reply.exp_pkt[protocol_type].type = 0
    # clear buffer
    ptfadapter.dataplane.flush()
    # Send packet
    for port in network_data.inner_ports:
        testutils.send(ptfadapter, port, pkt, count=5)
    # Verify ICMP request packets arrive on outer ports
    testutils.verify_packet_any_port(ptfadapter, exp_pkt_request, ports=network_data.outer_ports)
    # Verify ICMP peply packets arrive on inner ports
    testutils.verify_packet_any_port(ptfadapter, exp_pkt_reply, ports=network_data.inner_ports)


def generate_and_verify_not_translated_icmp_traffic(ptfadapter, setup_info, interface_type, direction, nat_type, second_port=False,
                                                    ip_src=None, ip_dst=None, check_reply=True):
    """
    Generates ICMP traffic and checks that traffic is not translated due to NAT types/rules.

        Args:
            ptfadapter: ptf adapter fixture
            setup_info: setup_info fixture
            interface_type: string interface type
            direction: string with current flow direction
            nat_type: string with static napt/nat/dynamic types
            second_port: boolean if second port id needs to be returned
            ip_src:  IP source in packet to send
            ip_dst: IP destination in packet to send
            check_reply: boolean if requires to verify ICMP reply
    """
    protocol_type = 'ICMP'
    # Define network data
    network_data = get_network_data(ptfadapter, setup_info, direction, interface_type, nat_type=nat_type, second_port=second_port)
    if ip_src is None:
        ip_src = network_data.ip_src
    if ip_dst is None:
        ip_dst = network_data.ip_dst
    # Create packet to send
    pkt = create_packet(network_data.eth_dst, network_data.eth_src, ip_dst, ip_src, protocol_type)
    # Define expected packet(ICMP request)
    exp_pkt_request = expected_mask_nated_packet(pkt, protocol_type, ip_dst, ip_src)
    # Define expected packet(ICMP reply)
    exp_pkt_reply = expected_mask_nated_packet(pkt, protocol_type, ip_src, ip_dst)
    exp_pkt_reply.exp_pkt[protocol_type].type = 0
    # clear buffer
    ptfadapter.dataplane.flush()
    # Send packet
    for port in network_data.inner_ports:
        testutils.send(ptfadapter, port, pkt, count=5)
    # Verify ICMP request packets arrive on outer ports
    testutils.verify_packet_any_port(ptfadapter, exp_pkt_request, ports=network_data.outer_ports)
    if check_reply:
        # Verify ICMP peply packets arrive on inner ports
        testutils.verify_packet_any_port(ptfadapter, exp_pkt_reply, ports=network_data.inner_ports)


def get_l4_default_ports(protocol_type):
    """
    Get default L4 ports
    :param protocol_type: type of protocol TCP/UDP
    :return source_l4_port, dest_l4_port
    """
    source_l4_port = TCP_LOCAL_PORT
    dest_l4_port = TCP_GLOBAL_PORT
    if protocol_type == "UDP":
        source_l4_port = UDP_LOCAL_PORT
        dest_l4_port = UDP_GLOBAL_PORT
    return source_l4_port, dest_l4_port


def get_dynamic_l4_ports(duthost, proto, direction, public_ip):
    """
    Get l4 ports for dynamic NAT test cases
    :param proto: sting with TCP/UDP values
    :param direction: string with current flow direction
    :return named tuple with values src_port, dst_port, exp_src_port, exp_dst_por
    """
    time.sleep(5)
    # Get expected source port
    output = exec_command(duthost, ["show nat translation"])['stdout']
    # Find expected source port
    pattern = r"{}.+{}:(\d+)".format(proto.lower(), public_ip)
    ports = re.findall(pattern, output)
    if not ports:
        raise Exception("Dynamic NAT translation was not created")
    dynamic_global_port = int(sorted(ports)[-1])
    src_port, dst_port = get_l4_default_ports(proto)
    if direction == "leaf-tor":
        exp_src_port = dynamic_global_port
        exp_dst_port = src_port
        src_port = dynamic_global_port
        dst_port = dynamic_global_port
    else:
        exp_src_port = dynamic_global_port
        exp_dst_port = dynamic_global_port
        dst_port = dynamic_global_port
    return L4_PORTS_DATA(src_port, dst_port, exp_src_port, exp_dst_port)


def configure_dynamic_nat_rule(duthost, ptfadapter, ptfhost, setup_info, interface_type, protocol_type, pool_name=DYNAMIC_POOL_NAME,
                               public_ip=None, acl_table=ACL_TABLE_GLOBAL_NAME, ports_assigned=None, acl_rules=None,
                               binding_name=DYNAMIC_BINDING_NAME, port_range=None,
                               default=False, remove_bindings=False, handshake=False):
    """
    method configure Dynamic NAT rules
    :param duthost: duthost fixture
    :param setup_info: setup_info fixture
    :param interface_type: interface_type Loopback, Portchannel etc
    :param pool_name: name of the pool to apply
    :param public_ip: IP of Public L3 interface
    :param acl_table: acl table name to create
    :param ports_assigned: assigned ports to ACL table
    :param acl_rules: ALC rules to apply
    :param binding_name: NAT binding name
    :param port_range: range of L4 port to apply
    :param remove_bindings: if True remove applied bindings from NAT rules
    :param default: use default ports
    :param handshake: if True perform handshake
    """
    if default:
        # Set private IP for dynamic NAT configuration
        public_ip = get_public_ip(setup_info, interface_type) if not public_ip else public_ip
        acl_subnet = setup_info[interface_type]["acl_subnet"]
        acl_rules = [{"priority": "10", "src_ip": acl_subnet, "action": "forward"}] if not acl_rules else acl_rules
        port_range = "{0}-{1}".format(POOL_RANGE_START_PORT, POOL_RANGE_END_PORT) if not port_range else port_range
        ports_assigned = setup_info['indices_to_ports_config'][setup_info[interface_type]['inner_port_id'][0]] if not \
            ports_assigned else ports_assigned
    # Set NAT configuration for test
    duthost.command("sudo config nat add pool {0} {1} {2}".format(pool_name, public_ip, port_range))
    # Check that pool configuration was applied
    show_nat_pool = get_cli_show_nat_config_output(duthost, "pool")
    pytest_assert(pool_name == show_nat_pool[0]['pool name'], "Pool name was not set to {}".format(pool_name))
    pytest_assert(public_ip == show_nat_pool[0]['global ip range'], "Global IP Range was not set to {}".format(public_ip))
    pytest_assert(port_range == show_nat_pool[0]['global port range'], "Global Port Range was not set to {}".format(port_range))
    # Add bindings
    duthost.command("sudo config nat add binding {0} {1} {2}".format(binding_name, pool_name, acl_table))
    # Check that binding configuration was applied
    show_nat_binding = get_cli_show_nat_config_output(duthost, "bindings")
    pytest_assert(binding_name == show_nat_binding[0]['binding name'], "Binding Name was not set to {}".format(binding_name))
    pytest_assert(pool_name == show_nat_binding[0]['pool name'], "Pool Name was not set to {}".format(pool_name))
    pytest_assert(acl_table == show_nat_binding[0]['access-list'], "Access-List was not set to {}".format(acl_table))
    # Apply acl table and rule
    duthost.command("mkdir -p {}".format(DUT_TMP_DIR))
    # Initialize variables for NAT global table
    acl_rule_vars = {
        'acl_table_name': acl_table,
        'stage': "INGRESS",
        'ports_assigned': ports_assigned,
        'acl_rules': acl_rules
    }
    duthost.host.options['variable_manager'].extra_vars.update(acl_rule_vars)
    acl_config = 'acl_table.json'
    acl_config_path = os.path.join(DUT_TMP_DIR, acl_config)
    duthost.template(src=os.path.join(TEMPLATE_DIR, ACL_TEMPLATE), dest=acl_config_path)
    # Apply config file
    duthost.command('sonic-cfggen -j {} --write-to-db'.format(acl_config_path))
    # Remove temporary folders
    duthost.command('rm -rf {}'.format(DUT_TMP_DIR))
    if remove_bindings:
        duthost.command("config nat remove bindings")
    # Apply NAT zones
    nat_zones_config(duthost, setup_info, interface_type)
    # set_arp entries
    check_peers_by_ping(duthost)
    if handshake:
        # Perform handshake
        direction = 'host-tor'
        # Define network data and L4 ports
        network_data = get_network_data(ptfadapter, setup_info, direction, interface_type, nat_type='dynamic')
        src_port, dst_port = get_l4_default_ports(protocol_type)
        # Perform TCP handshake (host-tor -> leaf-tor)
        perform_handshake(ptfhost, setup_info,
                          protocol_type, direction,
                          network_data.ip_dst, dst_port,
                          network_data.ip_src, src_port,
                          network_data.public_ip)


def wait_timeout(protocol_type, wait_time=None, default=True):
    """
    method for wait until NAT entry expired or some time to check that they ware not expired
    :param protocol_type: type of protocol
    :param wait_time: time to wait
    :param default: wait default NAT timeout
    """
    if default:
        if protocol_type == "UDP":
            # Wait until UDP entry expires
            time.sleep(GLOBAL_UDP_NAPT_TIMEOUT + 80)
        elif protocol_type == "TCP":
            time.sleep(GLOBAL_TCP_NAPT_TIMEOUT + 80)
        else:
            time.sleep(60)
    else:
        time.sleep(wait_time)


def get_static_l4_ports(proto, direction, nat_type):
    """
    Get l4 ports for static NAT/NAPT test cases
    :param proto: sting with TCP/UDP values
    :param direction: string with current flow direction
    :param nat_type: string with static napt/nat types
    :return named tuple with values src_port, dst_port, exp_src_port, exp_dst_por
    """
    src_port, dst_port = get_l4_default_ports(proto)
    if nat_type == 'static_napt' and direction == "host-tor":
        exp_src_port = dst_port
        exp_dst_port = dst_port
    elif nat_type == "static_napt" and direction == "leaf-tor":
        exp_src_port, exp_dst_port = dst_port, src_port
        src_port = dst_port
    elif direction == "leaf-tor":
        exp_src_port, exp_dst_port = dst_port, src_port
        src_port, dst_port = dst_port, src_port
    elif direction == "host-tor":
        exp_src_port = src_port
        exp_dst_port = dst_port
    return L4_PORTS_DATA(src_port, dst_port, exp_src_port, exp_dst_port)


def conf_dut_routes(duthost, setup_info, subnet, interface_type, teardown=False):
    """
    method for add/delete routes on DUT
    :param duthost: DUT host object
    :param setup_info: dict with interfaces parameters to configure
    :param subnet: subnet to configure
    :param interface_type: string interface type
    :param teardown: Boolean parameter to remove or not DUT routes
    """
    gw = setup_info[interface_type]["vrf_conf"]["red"]["ip"][:-1] + "{}". \
        format(int(setup_info[interface_type]["vrf_conf"]["red"]["ip"][-1:]) + 1)
    if teardown:
        try:
            duthost.command("ip route del {} via {}".format(subnet, gw))
        except RunAnsibleModuleFail:
            logger.debug("Route '%s via %s' was not deleted/existed", subnet, gw)
    else:
        duthost.command("ip route add {} via {}".format(subnet, gw))


def get_redis_val(duthost, db, key):
        """
        Returns dictionary of value for redis key.
        :param duthost: DUT host object
        :param db: database to be selected
        :param key: key to be selected
        """
        try:
            output = exec_command(duthost, ["redis-dump -d {} --pretty -k *{}*".format(db, key)])
            if output["rc"]:
                raise Exception('Return code is {} not 0'.format(output_cli["rc"]))
            redis_dict = json.loads(output['stdout'])
            for table in redis_dict:
                if 'expireat' in redis_dict[table]:
                    redis_dict[table].pop('expireat')
                if 'ttl' in redis_dict[table]:
                    redis_dict[table].pop('ttl')
            return redis_dict
        except Exception as e:
            return e.__str__()


def get_db_rules(duthost, ptfadapter, setup_test_env, protocol_type, db_type, private_ip=None, public_ip=None, private_port=None,
                 public_port=None, start_port=POOL_RANGE_START_PORT, end_port=POOL_RANGE_END_PORT, access_list=ACL_TABLE_GLOBAL_NAME, nat_pool=DYNAMIC_POOL_NAME,
                 post_flag=False):
        """
        Returns dictionary of database rules.
        :param duthost: DUT host object
        :param ptfadapter: ptf adapter fixture
        :param setup_test_env: fixture used to gather setup_info fixture and interface_type (Loopback, Portchannel etc)
        :param protocol_type: type of protocol TCP/UDP
        :param db_type: databyte type used to select which redis dump should be checked
        :param private_ip: IP variable used to confirm proper configuration
        :param public_ip: IP variable used to confirm proper configuration
        :param private_port: port variable used to confirm proper configuration
        :param public_port: port variable used to confirm proper configuration
        :param start_port: port variable used to confirm proper configuration
        :param end_port: port variable used to confirm proper configuration
        :param access_list: ACL variable used to confirm proper configuration
        :param nat_pool: pool variable used to confirm proper configuration
        :param post_flag: boolean flag used to determine which redis dump template should be used (pre or post configuration)
        """
        interface_type, setup_info = setup_test_env
        setup_data = copy.deepcopy(setup_info)
        nat_type = 'static_napt'
        direction = 'host-tor'
        network_data = get_network_data(ptfadapter, setup_data, direction, interface_type, nat_type=nat_type)
        secondary_protocol = {"TCP": "UDP", "UDP": "TCP"}[protocol_type]
        global_port = {"TCP": TCP_GLOBAL_PORT, "UDP": UDP_GLOBAL_PORT}[protocol_type]
        local_port = {"TCP": TCP_LOCAL_PORT, "UDP": UDP_LOCAL_PORT}[protocol_type]
        db_rules = {}
        # APP_DB timeout
        if db_type == 'APP_DB timeout':
            offset = {True: 200, False: 0}[post_flag]
            db_rules = {"nat_timeout" : "{}".format(GLOBAL_NAT_TIMEOUT + offset),
                        "admin_mode" : "enabled",
                        "nat_udp_timeout" : "{}".format(GLOBAL_UDP_NAPT_TIMEOUT + offset),
                        "nat_tcp_timeout" : "{}".format(GLOBAL_TCP_NAPT_TIMEOUT + offset * 25)
                       }
        # Pool CONFIG_DB
        elif db_type == 'Pool CONFIG_DB':
            db_rules = {"nat_ip": "{}".format(public_ip),
                        "nat_port": "{}-{}".format(start_port, end_port)
                       }
        # Pool APP_DB
        elif db_type == 'Pool APP_DB':
            db_rules = {"port_range": "{}-{}".format(start_port, end_port)}
        # Binding CONFIG_DB
        elif db_type == 'Binding CONFIG_DB':
            db_rules = {"access_list": access_list,
                        "nat_pool": nat_pool,
                        "nat_type": "snat",
                        "twice_nat_id": "NULL"
                       }
        # NAPT APP_DB
        elif db_type == 'NAPT APP_DB':
            db_rules = {
                "NAPT_TABLE:{}:{}:{}".format(protocol_type, network_data.public_ip, global_port): {
                    "type": "hash",
                    "value": {
                        "entry_type": "static",
                        "nat_type": "dnat",
                        "translated_ip": "{}".format(network_data.private_ip),
                        "translated_l4_port": "{}".format(local_port)
                    }
                },
                "NAPT_TABLE:{}:{}:{}".format(protocol_type, network_data.private_ip, local_port): {
                    "type": "hash",
                    "value": {
                        "entry_type": "static",
                        "nat_type": "snat",
                        "translated_ip": "{}".format(network_data.public_ip),
                        "translated_l4_port": "{}".format(global_port)
                    }
                }
            }
        # NAPT CONFIG_DB
        elif db_type == 'NAPT CONFIG_DB':
            db_rules = {
                "STATIC_NAPT|{}|{}|{}".format(network_data.public_ip, protocol_type, global_port): {
                    "type": "hash",
                    "value": {
                        "local_ip": "{}".format(network_data.private_ip),
                        "local_port": "{}".format(local_port),
                        "nat_type": "dnat"
                    }
                }
            }
        # NAPT APP_DB POST
        elif db_type == 'NAPT APP_DB POST':
            db_rules = {
                "NAPT_TABLE:{}:{}:{}".format(protocol_type, public_ip, public_port): {
                    "type": "hash",
                    "value": {
                        "entry_type": "static",
                        "nat_type": "dnat",
                        "translated_ip": "{}".format(private_ip),
                        "translated_l4_port": "{}".format(private_port)
                    }
                },
                "NAPT_TABLE:{}:{}:{}".format(protocol_type, private_ip, private_port): {
                    "type": "hash",
                    "value": {
                        "entry_type": "static",
                        "nat_type": "snat",
                        "translated_ip": "{}".format(public_ip),
                        "translated_l4_port": "{}".format(public_port)
                    }
                },
                "NAPT_TABLE:{}:{}:{}".format(protocol_type, network_data.public_ip, global_port): {
                    "type": "hash",
                    "value": {
                        "entry_type": "static",
                        "nat_type": "dnat",
                        "translated_ip": "{}".format(network_data.private_ip),
                        "translated_l4_port": "{}".format(local_port)
                    }
                },
                "NAPT_TABLE:{}:{}:{}".format(protocol_type, network_data.private_ip, local_port): {
                    "type": "hash",
                    "value": {
                        "entry_type": "static",
                        "nat_type": "snat",
                        "translated_ip": "{}".format(network_data.public_ip),
                        "translated_l4_port": "{}".format(global_port)
                    }
                },
                "NAPT_TABLE:{}:{}:{}".format(secondary_protocol, public_ip, public_port): {
                    "type": "hash",
                    "value": {
                        "entry_type": "static",
                        "nat_type": "dnat",
                        "translated_ip": "{}".format(private_ip),
                        "translated_l4_port": "{}".format(private_port)
                    }
                },
                "NAPT_TABLE:{}:{}:{}".format(secondary_protocol, private_ip, private_port): {
                    "type": "hash",
                    "value": {
                        "entry_type": "static",
                        "nat_type": "snat",
                        "translated_ip": "{}".format(public_ip),
                        "translated_l4_port": "{}".format(public_port)
                    }
                }
            }
        # NAPT CONFIG_DB POST
        elif db_type == 'NAPT CONFIG_DB POST':
            db_rules = {
                "STATIC_NAPT|{}|{}|{}".format(public_ip, protocol_type, public_port): {
                    "type": "hash",
                    "value": {
                        "local_ip": "{}".format(private_ip),
                        "local_port": "{}".format(private_port),
                        "nat_type": "dnat"
                    }
                },
                "STATIC_NAPT|{}|{}|{}".format(public_ip, secondary_protocol, public_port): {
                    "type": "hash",
                    "value": {
                        "local_ip": "{}".format(private_ip),
                        "local_port": "{}".format(private_port),
                        "nat_type": "dnat"
                    }
                },
                "STATIC_NAPT|{}|{}|{}".format(network_data.public_ip, protocol_type, global_port): {
                    "type": "hash",
                    "value": {
                        "local_ip": "{}".format(network_data.private_ip),
                        "local_port": "{}".format(local_port),
                        "nat_type": "dnat"
                    }
                }
            }
        # ASIC_DB SRC status
        elif db_type == 'ASIC_DB SRC':
            db_rules = {
                "SAI_NAT_ENTRY_ATTR_SRC_IP": "{}".format(network_data.public_ip),
                "SAI_NAT_ENTRY_ATTR_L4_SRC_PORT": "{}".format(global_port)
            }
        # ASIC_DB DST status
        elif db_type == 'ASIC_DB DST':
            db_rules = {
                "SAI_NAT_ENTRY_ATTR_DST_IP": "{}".format(network_data.private_ip),
                "SAI_NAT_ENTRY_ATTR_L4_DST_PORT": "{}".format(local_port)
            }
        else:
            raise Exception('Improper db_type selected')
        return db_rules


def write_json(duthost, json_dict, feature):
        """
        Write NAT config json to dut
        :param DUT host name
        :param json dictionary with variables used by templates
        :param feature used to select which template should be used
        """
        TEMP_FILE = "{}.json".format(feature)
        curr_dir = os.path.dirname(os.path.abspath(__file__))
        j2_template = Environment(loader=FileSystemLoader(curr_dir), trim_blocks=True)
        if feature == "dynamic_binding":
            j2_temp = j2_template.get_template(NAT_CONF_J2_TEMPLATE).render(nat=json_dict)
        else:
            raise AttributeError("Unexpected feature {}".format(feature))
        exec_command(duthost, ["mkdir -p {}".format(DUT_TMP_DIR)])
        exec_command(duthost, ["echo '{j2_temp}' > {dir}/{file}".
                     format(j2_temp=j2_temp, dir=DUT_TMP_DIR, file=TEMP_FILE)])
        exec_command(duthost, ["sudo config load {} -y".format(DUT_TMP_DIR+"/"+TEMP_FILE)])
        exec_command(duthost, ["rm -rf {}".format(DUT_TMP_DIR)])
