import logging
import os
import time
import pytest
import ptf.testutils as testutils
import ptf.mask as mask
import ptf.packet as packet
import re

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
DUT_TMP_DIR = os.path.join('tmp', os.path.basename(BASE_DIR))
FILES_DIR = os.path.join(BASE_DIR, 'files')
TEMPLATE_DIR = os.path.join(BASE_DIR, 'templates')
NAT_GLOBAL_TEMPLATE = 'global_nat_table_config.j2'
NAT_STATIC_TEMPLATE = 'static_nat_napt_table_config.j2'
ZONES_TEMPLATE = 'nat_zone_table_config.j2'
DYNAMIC_TEMPLATE = 'dynamic_nat_napt_table_config.j2'
GLOBAL_NAT_TIMEOUT = 300
GLOBAL_UDP_NAPT_TIMEOUT = 120
GLOBAL_TCP_NAPT_TIMEOUT = 300
TCP_GLOBAL_PORT = 80
UDP_GLOBAL_PORT = 161
TCP_LOCAL_PORT = 3700
UDP_LOCAL_PORT = 3000
POOL_RANGE_START_PORT = 5000
POOL_RANGE_END_PORT = 6000
logger = logging.getLogger(__name__)
NAT_ADMIN_MODE = "enabled"
STATIC_NAT_TABLE_NAME = "STATIC_NAT"
STATIC_NAPT_TABLE_NAME = "STATIC_NAPT"
DYNAMIC_POOL_NAME = "test_pool"
ACL_TABLE_GLOBAL_NAME = "test_acl_table"
DYNAMIC_BINDING_NAME = "test_binding"
SUPPORTED_TOPO = ['t0', 't0-16', 't0-52', 't0-56', 't0-64', 't0-64-32', 't0-116']
DIRECTION_MAP = {'leaf-tor': 'dnat'}
SETUP_CONF = {"loopback": {"vrf": {"red": {"ip": "11.1.0.2", "id": "1", "mask": "30", "gw": "11.1.0.1",
                                           "port_id": "28", "dut_iface": "PortChannel0001"},
                                   "blue": {"ip": "192.168.0.101", "id": "2", "mask": "24", "gw": "192.168.0.1",
                                            "port_id": "2"},
                                   "green": {"ip": "12.1.0.2", "id": "3", "mask": "30", "gw": "12.1.0.1",
                                             "port_id": "29", "dut_iface": "PortChannel0002"},
                                   "yellow": {"ip": "192.168.0.201", "id": "4", "mask": "24", "gw": "192.168.0.1",
                                              "port_id": "3"}
                                   },
                           "acl_subnet": "192.168.0.0/24"
                           },
              "port_in_lag": {"vrf": {"red": {"ip": "11.1.0.2", "id": "1", "mask": "30", "gw": "11.1.0.1",
                                              "port_id": "28", "dut_iface": "PortChannel0001"},
                                      "blue": {"ip": "192.168.0.101", "id": "2", "mask": "24", "gw": "192.168.0.1",
                                               "port_id": "2"},
                                      "green": {"ip": "12.1.0.2", "id": "3", "mask": "30", "gw": "12.1.0.1",
                                                "port_id": "29", "dut_iface": "PortChannel0002"},
                                      "yellow": {"ip": "192.168.0.201", "id": "4", "mask": "24", "gw": "192.168.0.1",
                                                 "port_id": "3"}
                                      },
                              "acl_subnet": "192.168.0.0/24"
                              }
              }
DIRECTION_PARAMS = ['host-tor', 'leaf-tor']


def configure_nat_over_cli(duthost, flow_direction, action, nat_type, global_ip, local_ip, proto=None,
                           global_port=None, local_port=None):
    """
    static NAT/NAPT CLI wrapper
    :param duthost: DUT host object
    :param flow_direction: string traffic direction
    :param action: string rule action
    :param nat_type: string static nat type
    :param global_ip: string global IP address value
    :param local_ip: string local IP address value
    :param proto: string protocol type
    :param global_port: string global l4 port
    :param local_port: string local l4 port
    :return : dict with rule parameters
    """

    if nat_type == 'static_nat':
        entry = {
            global_ip: {'local_ip': local_ip}
        }
        duthost.command("sudo config nat {} static basic {} {}".format(action, global_ip, local_ip))
        return entry
    elif nat_type == 'static_napt':
        static_napt_type = DIRECTION_MAP[flow_direction]
        action_type_map = {'add': '-nat_type {}'.format(static_napt_type), 'remove': ''}
        entry = {
            "{}|{}|{}".format(global_ip, proto.upper(), global_port): {'local_ip': local_ip,
                                                                       'local_port': "{}".format(local_port),
                                                                       'nat_type': static_napt_type
                                                                       }
        }
        duthost.command("sudo config nat {} static {} {} {} {} {} {}".format(action, proto.lower(),
                                                                             global_ip, global_port,
                                                                             local_ip, local_port,
                                                                             action_type_map[action]))
        return entry


def nat_statistics(duthost, show=False, clear=False):
    """
    NAT CLI helper which gets or clears NAT statistics
    :param duthost: DUT host object
    :param show: bool 
    :param clear: bool
    :return : formatted CLI output
    """
    
    if show:
        output_cli = exec_command(duthost,["show nat statistics"])
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
                output[key] = {keys[i]:entry_values[i] for i in range(0, len(keys))}
        return output
    elif clear:
        output_cli = exec_command(duthost,["sudo sonic-clear nat statistics"])
        if output_cli["rc"]:
            raise Exception('Return code is {} not 0'.format(output_cli["rc"]))
        return  output_cli["stdout"].lstrip()
    return None
        

def dut_nat_iptables_status(duthost):
    """
    NAT CLI helper enable/disable DUT's interface
    :param duthost: DUT host object
    :return : dict with nat PREROUTING/POSTROUTING iptables entries
    """
    
    nat_table_status = {}
    output_cli = exec_command(duthost,["sudo iptables -nL -t nat"])
    if output_cli["rc"]:
        raise Exception('Return code is {} not 0'.format(output_cli["rc"]))
    entries = output_cli["stdout"].split("\n")
    index_prerouting = [i for i in range(0, len(entries)) if "PREROUTING" in entries[i]][0] + 2
    index_input = [i for i in range(0, len(entries)) if "INPUT" in entries[i]][0]
    index_postrouting = [i for i in range(0, len(entries)) if 'POSTROUTING' in entries[i]][0] + 2
    postrouting = [el for el in entries[index_postrouting:] if len(el) > 1]
    prerouting = [el for el in entries[index_prerouting:index_input] if len(el) > 0]
    nat_table_status["prerouting"] = [" ".join([s.strip() for s in el.split() if len(el) > 0])
                                        for el in prerouting]
    nat_table_status["postrouting"] = [" ".join([s.strip() for s in el.split() if len(el) > 0])
                                        for el in postrouting]
    return nat_table_status
        

def dut_interface_status(duthost, interface_name):
    """
    NAT CLI helper enable/disable DUT's interface
    :param duthost: DUT host object
    :param interface_name: string interface to configure 
    :return : string formatted CLI output with interface current operstatus
    """
    
    interfaces_status = {}
    output_cli = exec_command(duthost,["show interfaces status | grep {}".format(interface_name)])
    if output_cli["rc"]:
        raise Exception('Return code is {} not 0'.format(output_cli["rc"]))
    entries = output_cli["stdout"].split()
    num_entries = len(entries[::10])
    for num in range(0, num_entries):
        entry_values = entries[(num * 10):(num * 10) + 10]
        interfaces_status[entry_values[0]] = entry_values
    return interfaces_status[interface_name][6]
    
        
def dut_interface_control(duthost, action, interface_name):
    """
    NAT CLI helper enable/disable DUT's interface
    :param duthost: DUT host object
    :param action: string action to configure interface
    :param interface_name: string interface to configure 
    :return : formatted CLI output with interface current operstatus
    """
    
    interface_actions = {"disable": "shutdown", "enable": "startup"}
    expected_operstatus = {"disable": "down", "enable": "up"}
    output_cli = exec_command(duthost, ["sudo config interface {} {}".format(interface_actions[action],
                                                                                interface_name)])
    if output_cli["rc"]:
        raise Exception('Return code is {} not 0'.format(output_cli["rc"]))
    attempts = 3
    current_operstatus = dut_interface_status(duthost, interface_name)
    while current_operstatus != expected_operstatus[action]:
        if attempts == 0:
            break
        time.sleep(5)
        current_operstatus = dut_interface_status(duthost, interface_name)
        attempts -=1
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
        output_cli = exec_command(duthost,["show nat translations"])
        if output_cli["rc"]:
            raise Exception('Return code is {} not 0'.format(output_cli["rc"]))
        output = {}
        entries = output_cli["stdout"].split('\n')[15:]
        splited_entries = []
        for el in entries:
            splited_entries.extend(el.split())
        if splited_entries:
            num_entries = len(splited_entries[::5])
            keys = [el.strip() for el in output_cli["stdout"].split("\n")[13].split("  ") if len(el) > 0]
            for num in range(0, num_entries):
                entry_values = splited_entries[(num * 5):(num * 5) + 5]
                key = entry_values[1] if entry_values[1] != "---" else entry_values[2]
                output[key] = {keys[i]:entry_values[i] for i in range(0, len(keys))}
        return output
    elif clear:
        output_cli = exec_command(duthost,["sudo sonic-clear nat translations"])
        if output_cli["rc"]:
            raise Exception('Return code is {} not 0'.format(output_cli["rc"]))
        return  output_cli["stdout"].lstrip()
    return None
            
    
def crud_operations_basic(duthost, flow_direction, crud_operation):
    """
    static NAT CLI helper
    :param duthost: DUT host object
    :param flow_direction: string traffic direction
    :param crud_operation: dict dict with action and rule parameters
    :return : dict with rule parameters
    """

    nat_type = "static_nat"
    for key in crud_operation.keys():
        output = configure_nat_over_cli(duthost, flow_direction,
                                        crud_operation[key]["action"], nat_type,
                                        crud_operation[key]["global_ip"], crud_operation[key]["local_ip"])
    return output


def crud_operations_napt(duthost, flow_direction, crud_operation):
    """
    static NAPT CLI helper
    :param duthost: DUT host object
    :param flow_direction: string traffic direction
    :param crud_operation: dict dict with action and rule parameters
    :return : dict with rule parameters
    """

    nat_type = 'static_napt'
    for key in crud_operation.keys():
        output = configure_nat_over_cli(duthost, flow_direction,
                                        crud_operation[key]["action"], nat_type,
                                        crud_operation[key]["global_ip"], crud_operation[key]["local_ip"],
                                        proto=crud_operation[key]["proto"],
                                        global_port=crud_operation[key]["global_port"],
                                        local_port=crud_operation[key]["local_port"])
    return output


def exec_command(host, command_list):
    """
    method for shell execution of commands on host
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
    set NAT zones configuration files for deploy them on DUT;
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
            duthost.host.options['variable_manager'].extra_vars.update(nat_zone_vars)
            nat_zones_conf_file = 'nat_table_zones.json'
            zones_nat_config_path = os.path.join(DUT_TMP_DIR, nat_zones_conf_file)
            duthost.template(src=os.path.join(TEMPLATE_DIR, ZONES_TEMPLATE), dest=zones_nat_config_path)
            # Apply config file
            duthost.command('sonic-cfggen -j {} --write-to-db'.format(zones_nat_config_path))


def apply_static_nat_config(duthost, public_ip, private_ip, flow_direction, protocol_type=None, nat_entry=None,
                            global_port=None, local_port=None):
    """
    generate static NAT/NAPT configuration files and deploy them on DUT;
    :param duthost: DUT host object
    :param public_ip: IP Address of Internet IP (host-tor) or IP Address of Public Interface (leaf-tor)
    :param private_ip: IP Address of Local IP (host-tor) or IP Address of Internet IP (leaf-tor)
    :param nat_entry: static_nat/static_napt
    :param protocol_type: TCP/UDP
    :param flow_direction: host-tor or leaf-tor
    :param global_port: global l4 port
    :param local_port: local l4 port
    """

    # Initialize variables for Static NAT/NAPT table
    static_nat_table_vars = {
        'table_name': STATIC_NAPT_TABLE_NAME if nat_entry != 'static_nat' else STATIC_NAT_TABLE_NAME,
        'protocol': protocol_type if nat_entry != 'static_nat' else protocol_type,
        'global_port': global_port,
        'global_ip': public_ip,
        'nat_local_ip': private_ip,
        'napt_local_port': local_port,
        'static_nat_type': 'dnat'
    }
    duthost.host.options['variable_manager'].extra_vars.update(static_nat_table_vars)
    static_nat_global_config = '{}_config.json'.format(STATIC_NAPT_TABLE_NAME.lower() if nat_entry != 'static_nat'
                                                       else STATIC_NAT_TABLE_NAME.lower())
    static_nat_config_path = os.path.join(DUT_TMP_DIR, static_nat_global_config)
    duthost.template(src=os.path.join(TEMPLATE_DIR, NAT_STATIC_TEMPLATE), dest=static_nat_config_path)
    # Apply config file
    duthost.command('sonic-cfggen -j {} --write-to-db'.format(static_nat_config_path))


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
    if second_port and interface_type != 'loopback':
        return [setup_info[interface_type]['outer_port_id'][0] + 1]
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

    if direction == 'host-tor':
        if second_port and interface_type != 'loopback':
            return [setup_info[interface_type]['outer_port_id'][0] + 1]
        return setup_info[interface_type]['outer_port_id']
    if second_port: 
        return [setup_info[interface_type]['inner_port_id'][0] + 1]
    return setup_info[interface_type]['inner_port_id']
    
    
def get_src_ip(setup_info, direction, interface_type, nat_type=None, second_port=False):
    """
    return source IP  based on test case direction and interface_type
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
    if second_port:
        return setup_info[interface_type]["second_dst_ip"]
    return setup_info[interface_type]['dst_ip']


def get_dst_ip(setup_info, direction, interface_type, nat_type=None, second_port=False):
    """
    return destination IP  based on test case direction and interface_type
    :param setup_info: setup info fixture
    :param direction: 'host-tor', 'leaf-tor'
    :param interface_type: type of interface
    :param second_port: boolean if second port's IP settings need to be returned
    :param nat_type: string nat type
    :return: destination IP
    """

    if direction == 'host-tor' or nat_type == "static_napt":
        if second_port:
            return setup_info[interface_type]["second_dst_ip"]
        return setup_info[interface_type]['dst_ip']
    if second_port:
        return setup_info[interface_type]['second_public_ip']
    return setup_info[interface_type]['public_ip']


def get_public_ip(setup_info, interface_type, second_port=False):
    """
    return public IP  based on test case interface_type
    :param setup_info: setup info fixture
    :param interface_type: type of interface
    :param second_port: boolean if second port's IP settings need to be returned
    :return: public IP
    """
    if second_port and interface_type == "port_in_lag":
        return setup_info[interface_type]['second_public_ip']
    return setup_info[interface_type]['public_ip']


def setup_test_env(ptfhost, duthost, testbed, setup_info, interface_type):
    """
    setup testbed's environment for CT run
    :param ptfhost: PTF host object
    :param duthost: DUT host object
    :param testbed: Testbed object
    :param setup_info: fixture gathers all test required information from DUT facts and testbed
    :param interface_type: interface type to configure
    """

    # Check if topology is supported
    if testbed['topo']['name'] not in SUPPORTED_TOPO:
        pytest.skip('Unsupported topology')
    try:
        # TODO: extend with other interface types
        # Setup interfaces on PTF container
        conf_ptf_interfaces(ptfhost, duthost, setup_info, interface_type)
    except Exception as e:
        teardown_test_env(duthost, ptfhost, setup_info, interface_type)
        raise e


def setup_ptf_interfaces(ptfhost, duthost, setup_info, interface_type, vrf_id, vrf_name, port_id,
                         ip_address, mask, gw_ip, key):
    """
    setup ptf interfaces for tests
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
    ptfhost.shell("ip link set eth{} master {}".format(port_id, vrf_name))
    ptfhost.shell("ip rule add iif {} table {}".format(vrf_name, vrf_id))
    ptfhost.shell("ip rule add oif {} table {}".format(vrf_name, vrf_id))
    ptfhost.shell("ip addr add {}/{} dev eth{}".format(ip_address, mask, port_id))
    ptfhost.shell("ip route add 0.0.0.0/0 via {} table {}".format(gw_ip, vrf_id))
    if "dut_iface" in setup_info[interface_type]["vrf_conf"][key].keys():
        dut_iface = setup_info[interface_type]["vrf_conf"][key]["dut_iface"]
        pch_ip = setup_info["pch_ips"][dut_iface]
        duthost.shell("sudo config interface ip remove {} {}/31".format(dut_iface, pch_ip))
        duthost.shell("sudo config interface ip add {} {}/{}".format(dut_iface, gw_ip, mask))


def teardown_ptf_interfaces(ptfhost, gw_ip, vrf_id, ip_address, mask, port_id, vrf_name):
    """
    teardown ptf interfaces after tests
    :param ptfhost: PTF host object
    :param vrf_id: id of vrf
    :param vrf_name: vrf name
    :param port_id: port id of interface
    :param ip_address: ip address of interface
    :param mask: vrf mask
    :param gw_ip: ip address of gateway
    """
    ptfhost.shell("ip route del 0.0.0.0/0 via {} table {}".format(gw_ip, vrf_id))
    ptfhost.shell("ip addr del {}/{} dev eth{}".format(ip_address, mask, port_id))
    ptfhost.shell("ip rule del iif {} table {}".format(vrf_name, vrf_id))
    ptfhost.shell("ip rule del oif {} table {}".format(vrf_name, vrf_id))
    ptfhost.shell("ip link set eth{} nomaster".format(port_id))
    ptfhost.shell("ip link del {} type vrf table {}".format(vrf_name, vrf_id))


def conf_ptf_interfaces(ptfhost, duthost, setup_info, interface_type, teardown=False, second_port=False):
    """
    setup testbed's environment for CT run
    :param ptfhost: PTF host object
    :param duthost: DUT host object
    :param setup_info: setup info fixture
    :param interface_type: string interface type
    :param teardown: Boolean parameter to remove or not PTF's interfaces config
    :param second_port: bolean for PTF's interface ip address configuration
    """
    for key in setup_info[interface_type]["vrf_conf"]:
        vrf_id = setup_info[interface_type]["vrf_conf"][key]["id"]
        vrf_name = key
        ip_address = setup_info[interface_type]["vrf_conf"][key]["ip"]
        gw_ip = setup_info[interface_type]["vrf_conf"][key]["gw"]
        port_id = setup_info[interface_type]["vrf_conf"][key]["port_id"]
        mask = setup_info[interface_type]["vrf_conf"][key]["mask"]
        if teardown:
            teardown_ptf_interfaces(ptfhost, gw_ip, vrf_id, ip_address, mask, port_id, vrf_name)
        else:
            ptfhost.script("./scripts/change_mac.sh")
            setup_ptf_interfaces(ptfhost, duthost, setup_info, interface_type,vrf_id,vrf_name, port_id, ip_address,
                                 mask, gw_ip, key)


def expected_mask_nated_packet(pkt, setup_info, interface_type, direction, protocol_type, exp_src_ip=None,
                               exp_dst_ip=None, src_port=None, dst_port=None, icmp_id=None, second_port=False):
    """
    method for check expected packet fields
    :param pkt: packet to be sent
    :param setup_info: fixture gathers all test required information from DUT facts and testbed
    :param interface_type: type of interface
    :param direction: direction of the packet
    :param protocol_type: protocol type TCP, UDP or ICMP
    :param src_port: source L4 expected port
    :param dst_port: destination L4 expected port
    :param exp_src_ip: expected source IP
    :param exp_dst_ip: expected destination IP
    :param icmp_id: id for specify ICMP dynamic connection
    :param second_port: boolean for second port settings
    :return: expected packet
    """

    # Setup source and destination IP based on direction
    if direction == 'host-tor':
        if second_port:
            ip_dst = setup_info[interface_type]["second_dst_ip"]
            ip_src = setup_info[interface_type]["second_public_ip"]
        else:
            ip_dst = setup_info[interface_type]["dst_ip"] if not exp_dst_ip else exp_dst_ip
            ip_src = setup_info[interface_type]["public_ip"] if not exp_src_ip else exp_src_ip
    else:
        if second_port:
            ip_dst = setup_info[interface_type]["second_src_ip"]
            ip_src = setup_info[interface_type]["second_dst_ip"]
        else:
            ip_dst = setup_info[interface_type]["src_ip"] if not exp_dst_ip else exp_dst_ip
            ip_src = setup_info[interface_type]["dst_ip"] if not exp_src_ip else exp_src_ip

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
    generate packet to sent from public interface port to private interface port and vice versa
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
    else:
        return testutils.simple_icmp_packet(eth_dst=eth_dst, eth_src=eth_src, ip_dst=ip_dst, ip_src=ip_src, icmp_type=8,
                                            icmp_code=0, ip_ttl=64)


def teardown_test_env(duthost, ptfhost, setup_info, interface_type, reboot=False, before_test=False):
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
        duthost.command('config reload -y')
    # wait for dut become stable
    time.sleep(180)
    # remove ptf interfaces configuration
    if not before_test:
        conf_ptf_interfaces(ptfhost, duthost, setup_info, interface_type, teardown=True)


def check_rule_by_traffic(duthost, ptfhost, ptfadapter, setup_info, direction, interface_type, protocol_type,
                          outer_ports=None, inner_ports=None, ip_src=None, ip_dst=None, exp_src_ip=None,
                          exp_dst_ip=None, source_l4_port=None, dest_l4_port=None, exp_source_port=None,
                          exp_dst_port=None, icmp_id=None, nat_type=None, action=None,  negative=False,
                          second_port=False, handshake=False, default=False):
    """
    method for check traffic from host to tor and vise versa
    :param duthost: duthost fixture
    :param ptfhost: ptfhost fixture
    :param ptfadapter: ptfadapter fixtture
    :param setup_info: setup info fixture
    :param direction: host-tor or leaf-tor
    :param interface_type: type of interface to check
    :param protocol_type: TCP/UDP/ICMP
    :param outer_ports: port where expected packet will be sniffed
    :param inner_ports: port where packet will be send
    :param ip_src: source IP of packet to send
    :param ip_dst: destination IP of packet to send
    :param exp_src_ip: source IP of expected packet
    :param exp_dst_ip: destination IP of expected packet
    :param source_l4_port: source port for UDP/TCP packet to send
    :param dest_l4_port: destination port for UDP/TCP traffic packet to send
    :param exp_source_port: source port for UDP/TCP of expected packet to receive
    :param exp_dst_port: destination port for UDP/TCP traffic of expected packet to receive
    :param icmp_id: id to specify dynamic ICMP connection
    :param negative: check with negative scenario
    :param second_port: boolean if second port's IP settings need to be returned
    :param handshake: boolean perform initial TCP/UDP packets sending
    :param nat_type: type of the NAT
    :param default: user default parameters for initializing L4 ports
    :param action: used only for dynamic NAT, could be 'forward' or 'do_not_nat'
    """

    # Get outer and inner ports
    outer_ports = get_dst_port(setup_info, direction, interface_type,
                               second_port=second_port) if not outer_ports else outer_ports
    inner_ports = get_src_port(setup_info, direction, interface_type,
                               second_port=second_port) if not inner_ports else inner_ports
    # Set MAC addresses for packets to send
    eth_dst = setup_info['router_mac']
    eth_src = ptfadapter.dataplane.get_mac(0, inner_ports[0])
    # Set source and destination IPs for packets to send
    ip_src = get_src_ip(setup_info, direction, interface_type, 
                        nat_type=nat_type, second_port=second_port) if not ip_src else ip_src
    ip_dst = get_dst_ip(setup_info, direction, interface_type, 
                        nat_type=nat_type, second_port=second_port) if not ip_dst else ip_dst
    public_ip = get_public_ip(setup_info, interface_type)
    try:
        if handshake and direction == "host-tor" and protocol_type != "ICMP":
            if nat_type == "dynamic" and default:
                source_l4_port, dest_l4_port = set_l4_default_ports(protocol_type)
            src_vrf = setup_info["inner_vrf"][0] if not second_port else setup_info["inner_vrf"][1]
            dst_vrf = setup_info["outer_vrf"][0] if not second_port else setup_info["outer_vrf"][1]
            ptfhost.copy(src="./scripts/nat_ptf_echo.py", dest="/tmp")
            ptfhost.command("python /tmp/nat_ptf_echo.py {} "
                            "{} {} {} {} {} {} None &".format(protocol_type.lower(), ip_dst, dest_l4_port,
                                                              ip_src,source_l4_port, dst_vrf, src_vrf))
        elif handshake and direction == "leaf-tor" and protocol_type != "ICMP" and nat_type == "static_napt":
            src_vrf = setup_info["outer_vrf"][0] if not second_port else setup_info["outer_vrf"][1]
            dst_vrf = setup_info["inner_vrf"][0] if not second_port else setup_info["inner_vrf"][1]
            ptfhost.copy(src="./scripts/nat_ptf_echo.py", dest="/tmp")
            ptfhost.command("python /tmp/nat_ptf_echo.py {} "
                            "{} {} {} {} {} {} {} &".format(protocol_type.lower(), ip_src, source_l4_port, 
                                                            ip_dst, dest_l4_port, dst_vrf, src_vrf,
                                                            public_ip))
        if nat_type == 'dynamic':
            if not exp_source_port and not negative and protocol_type != 'ICMP':
                output = exec_command(duthost, ["show nat translation"])['stdout']
                # Find expected source port
                pattern = "tcp.+{}:(\d+)" if protocol_type == "TCP" else "udp.+{}:(\d+)"
                exp_source_port = sorted(re.findall(pattern.format(get_public_ip(setup_info, interface_type)),
                                                    output))[-1]
            if protocol_type == 'ICMP':
                exp_source_port = POOL_RANGE_START_PORT
                if action == 'do_not_nat':
                    icmp_id = 0
            if not exp_source_port and negative:
                exp_source_port = POOL_RANGE_START_PORT
            if default:
                source_l4_port, dest_l4_port, exp_source_port, exp_dst_port = initialize_dynamic_nat_l4_ports(
                    protocol_type, direction, exp_src_port=int(exp_source_port), default=default)
            else:
                source_l4_port, dest_l4_port, exp_source_port, exp_dst_port = initialize_dynamic_nat_l4_ports(
                    protocol_type, direction, src_port=source_l4_port, dst_port=dest_l4_port,
                    exp_src_port=int(exp_source_port), exp_dst_port=dest_l4_port)
        if nat_type == "static_napt" and direction == "leaf-tor" and protocol_type != 'ICMP':
            source_l4_port = dest_l4_port
            exp_source_port, exp_dst_port = exp_dst_port, exp_source_port
            exp_dst_ip = ip_src
            ip_src = ip_dst
            ip_dst = public_ip
            exp_src_ip = ip_src
        # Create packet to send
        pkt = create_packet(eth_dst, eth_src, ip_dst, ip_src, protocol_type, sport=source_l4_port, dport=dest_l4_port)
        exp_pkt = expected_mask_nated_packet(pkt, setup_info, interface_type, direction, protocol_type,
                                             exp_src_ip=exp_src_ip, exp_dst_ip=exp_dst_ip, src_port=exp_source_port,
                                             dst_port=exp_dst_port, icmp_id=icmp_id)
        # clear buffer
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, inner_ports[0], pkt, count=5)
        if not negative:
            # Verify that packets arrive on outer ports
            testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=outer_ports)
            if protocol_type == "ICMP":
                exp_pkt = expected_mask_nated_packet(pkt, setup_info, interface_type, 'leaf-tor', protocol_type,
                                                     exp_src_ip=exp_src_ip, exp_dst_ip=exp_dst_ip,
                                                     src_port=exp_source_port,
                                                     dst_port=exp_dst_port, icmp_id=0)
                exp_pkt.exp_pkt[protocol_type].type = 0
                testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=inner_ports)
        else:
            testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=outer_ports)
    except Exception as e:
        # Perform teardown if error happens
        conf_ptf_interfaces(ptfhost, duthost, setup_info, interface_type, teardown=True, second_port=second_port)
        raise e


def set_l4_default_ports(protocol_type):
    """
    method set default L4 ports fot test
    :param protocol_type: type of protocol TCP/UDP
    :return source_l4_port, dest_l4_port
    """
    if protocol_type == "UDP":
        source_l4_port = UDP_LOCAL_PORT
        dest_l4_port = UDP_GLOBAL_PORT
    else:
        source_l4_port = TCP_LOCAL_PORT
        dest_l4_port = TCP_GLOBAL_PORT
    return source_l4_port, dest_l4_port


def initialize_dynamic_nat_l4_ports(protocol_type, direction, src_port=None, dst_port=None, exp_src_port=None,
                                    exp_dst_port=None,
                                    default=False):
    """
    method set l4 ports for dynamic NAT test cases
    :param protocol_type: TCP/UDP/ICMP
    :param src_port: source port for UDP/TCP packet to send
    :param dst_port: destination port for UDP/TCP traffic packet to send
    :param exp_src_port: expected  source port for UDP/TCP packet to check
    :param exp_dst_port: expected  destination port for UDP/TCP packet to check
    :param default: use default ports
    :param direction: switch ports
    :return src_port, dst_port, exp_src_port, exp_dst_port
    """
    # Use default values but reverse ports for DNAT
    if default and direction == 'leaf-tor':
        src_port, dst_port = set_l4_default_ports(protocol_type)
        new_dest_l4_port = exp_src_port
        exp_src_port, exp_dst_port = dst_port, src_port
        src_port, dst_port = dst_port, new_dest_l4_port
        return src_port, dst_port, exp_src_port, exp_dst_port
    # Use default values without reversing
    if default:
        src_port, dst_port = set_l4_default_ports(protocol_type)
        exp_dst_port = dst_port
        return src_port, dst_port, exp_src_port, exp_dst_port
    # User argument values from function, all parameters have to be set and reverse for DNAT
    if direction != 'host-tor':
        new_dest_l4_port = exp_src_port
        exp_src_port, exp_dst_port = dst_port, src_port
        src_port, dst_port = dst_port, new_dest_l4_port
        return src_port, dst_port, exp_src_port, exp_dst_port
    # Return argument values without any changes
    return src_port, dst_port, exp_src_port, exp_dst_port


def configure_dynamic_nat_rule(duthost, setup_info, interface_type, pool_name=DYNAMIC_POOL_NAME,
                               public_ip=None, acl_table=ACL_TABLE_GLOBAL_NAME, ports_assigned=None, acl_rules=None,
                               binding_name=DYNAMIC_BINDING_NAME, port_range=None,
                               default=False, remove_bindings=False):
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
    static_nat_table_vars = {
        'pool_name': pool_name,
        'global_ip': public_ip,
        'port_range': port_range,
        'acl_table_name': acl_table,
        'stage': "INGRESS",
        'ports_assigned': ports_assigned,
        'acl_rules': acl_rules,
        'binding_name': binding_name
    }
    duthost.host.options['variable_manager'].extra_vars.update(static_nat_table_vars)
    dynamic_nat_global_config = 'dynamic_nat_{}_config.json'.format(pool_name)
    dynamic_nat_config_path = os.path.join(DUT_TMP_DIR, dynamic_nat_global_config)
    duthost.template(src=os.path.join(TEMPLATE_DIR, DYNAMIC_TEMPLATE), dest=dynamic_nat_config_path)
    # Apply config file
    duthost.command('sonic-cfggen -j {} --write-to-db'.format(dynamic_nat_config_path))
    if remove_bindings:
        duthost.command("config nat remove bindings")
    # Apply NAT zones
    nat_zones_config(duthost, setup_info, interface_type)


def wait_timeout(protocol_type, wait_time=None, default=True):
    """
    method for wait until NAT entry expired or some time to check that they ware not expired
    :param protocol_type: type of protocol
    :param wait_time: time to wait
    :param default: wait default NAT timeout
    """
    if protocol_type == "UDP":
        # Wait until UDP entry expires
        time.sleep(GLOBAL_UDP_NAPT_TIMEOUT + 60) if default else time.sleep(wait_time)
    if protocol_type == "TCP":
        time.sleep(GLOBAL_TCP_NAPT_TIMEOUT + 60) if default else time.sleep(wait_time)
    else:
        time.sleep(60) if default else time.sleep(wait_time)


def get_static_l4_ports(proto, direction, nat_type):
    """
    method set l4 ports for static NAT/NAPT test cases
    :param proto: sting with TCP/UDP values
    :param direction: string with current flow direction
    :param nat_type: string with static napt/nat types
    :return strings values for src_port, dst_port, exp_src_port, exp_dst_por
    """

    src_port, dst_port = set_l4_default_ports(proto)
    exp_src_port = src_port
    exp_dst_port = dst_port
    if nat_type == 'static_nat':
        if direction == 'leaf-tor':
            exp_src_port, exp_dst_port = dst_port, src_port
            src_port, dst_port = dst_port, src_port
    if nat_type == 'static_napt':
        if direction == "leaf-tor":
            exp_src_port = dst_port
            exp_dst_port = src_port
            src_port, dst_port = dst_port, src_port
            return src_port, dst_port, exp_src_port, exp_dst_port
        if direction == "host-tor":
            exp_src_port = src_port
            exp_dst_port = src_port
            src_port, dst_port = dst_port, src_port
            return src_port, dst_port, exp_src_port, exp_dst_port
    return src_port, dst_port, exp_src_port, exp_dst_port

