#! /usr/bin/env python3

'''
    Script to automate the cases listed in VxLAN HLD document:
    https://github.com/Azure/SONiC/blob/8ca1ac93c8912fda7b09de9bfd51498e5038c292/doc/vxlan/Overlay%20ECMP%20with%20BFD.md#test-cases

    To test functionality:
    ./run_tests.sh -n ucs-m5-2 -d mth64-m5-2 -O -u -e -s -e --disable_loganalyzer -m individual -p /home/vxr/vxlan/logs/    -c 'vxlan/test_vxlan_ecmp.py'

    To test ECMP with 2 paths per destination:
    ./run_tests.sh -n ucs-m5-2 -d mth64-m5-2 -O -u -e -s -e --disable_loganalyzer -m individual -p /home/vxr/vxlan/logs/    -c 'vxlan/test_vxlan_ecmp.py' -e '--nhs_per_destination=2'

    To test ECMP+Scale:
    ./run_tests.sh -n ucs-m5-2 -d mth64-m5-2 -O -u -e -s -e --disable_loganalyzer -m individual -p /home/vxr/vxlan/logs/    -c 'vxlan/test_vxlan_ecmp.py' \
                    -e '--ecmp_nhs_per_destination=128' -e '--total_number_of_nexthops=128000'

    To keep the temporary config files created in the DUT:
    ./run_tests.sh -n ucs-m5-2 -d mth64-m5-2 -O -u -e -s -e --keep_temp_files -c 'vxlan/test_vxlan_ecmp.py'

    Other options:
        keep_temp_files             : Keep the temporary files created in the DUT. Default: False
        debug_enabled               : Enable debug mode, for debugging script. The temp files will not have timestamped names. Default: False
        dut_hostid                  : An integer in the range of 1 - 100 to be used as the host part of the IP address for DUT. Default: 1
        ecmp_nhs_per_destination    : Number of ECMP next-hops per destination.
        total_number_of_endpoints : Number of Endpoints (a pool of this number of ip addresses will used for next-hops).
        total_number_of_nexthops    : Maximum number of all nexthops for every destination combined(per encap_type).
        vxlan_port                                : Global vxlan port (UDP port) to be used for the DUT. Default: 4789
'''

import time
import re
import ipaddress
import json
import logging
from datetime import datetime
from sys import getsizeof

import pytest

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory  # lgtm[py/unused-import]
from tests.ptf_runner import ptf_runner

Logger = logging.getLogger(__name__)

# Some of the Constants used in this script.
Constants = {}

# Mapping the version to the python module.
IP_TYPE = {
    'v4' : ipaddress.IPv4Address,
    'v6' : ipaddress.IPv6Address
}

# This is the mask values to use for destination
# in the vnet routes.
HOST_MASK = {'v4' : 32, 'v6' : 128}

# This is the list of encapsulations that will be tested in this script.
# v6_in_v4 means: V6 payload is encapsulated inside v4 outer layer.
# This list is used in many locations in the script.
SUPPORTED_ENCAP_TYPES = ['v4_in_v4', 'v4_in_v6', 'v6_in_v4', 'v6_in_v6']

pytestmark = [
    # This script supports any T1 topology: t1, t1-64-lag, t1-lag.
    pytest.mark.topology("t1", "t1-64-lag", "t1-lag"),
    pytest.mark.sanity_check(post_check=True)
]

def create_vxlan_tunnel(duthost, minigraph_data, af, tunnel_name=None, src_ip=None):
    '''
        Function to create a vxlan tunnel. The arguments:
            duthost : the DUT ansible host object.
            minigraph_data: minigraph facts from the dut host.
            tunnel_name : A name for the Tunnel, default: tunnel_<AF>
            src_ip : Source ip address of the tunnel. It has to be a local ip address in the DUT. Default: Loopback ip address.
            af : Address family : v4 or v6.
    '''
    if tunnel_name is None:
        tunnel_name = "tunnel_{}".format(af)

    if src_ip is None:
        src_ip = get_dut_loopback_address(duthost, minigraph_data, af)

    config = '''{{
        "VXLAN_TUNNEL": {{
            "{}": {{
                "src_ip": "{}"
            }}
        }}
    }}'''.format(tunnel_name, src_ip)

    apply_config_in_dut(duthost, config, name="vxlan_tunnel_"+ af)
    return tunnel_name

def apply_config_in_dut(duthost, config, name="vxlan"):
    '''
        The given json(config) will be copied to the DUT and loaded up.
    '''
    if Constants['DEBUG']:
        filename = "/tmp/" + name + ".json"
    else:
        filename = "/tmp/" + name + "-" + str(time.time()) + ".json"
    duthost.copy(content=config, dest=filename)
    duthost.shell("sudo config load {} -y".format(filename))
    time.sleep(1)
    if not Constants['KEEP_TEMP_FILES']:
        duthost.shell("rm {}".format(filename))

def get_dut_loopback_address(duthost, minigraph_data, af):
    '''
        Returns the IP address of the Loopback interface in DUT, from minigraph.
        Arguments:
            duthost : DUT Ansible Host object.
            minigraph_data: Minigraph facts from the DUT.
            af : Address Family(v4 or v6).
    '''
    lo_ip = minigraph_data['minigraph_lo_interfaces']
    for intf in lo_ip:
        if isinstance(ipaddress.ip_address(intf['addr']), IP_TYPE[af]):
            return intf['addr']

    raise RuntimeError("Couldnot find the {} loopback address for the DUT:{} from minigraph.".format(af, duthost.hostname))

def select_required_interfaces(duthost, number_of_required_interfaces, minigraph_data, af):
    '''
     Pick the required number of interfaces to use for tests.
     These interfaces will be selected based on if they are currently running a established BGP.
     The interfaces will be picked from the T1 facing side.
    '''
    bgp_interfaces = get_all_interfaces_running_bgp(duthost, minigraph_data)
    interface_ip_table = minigraph_data['minigraph_interfaces']
    if interface_ip_table:
        available_interfaces = interface_ip_table
    elif minigraph_data['minigraph_portchannels']:
        available_interfaces = minigraph_data['minigraph_portchannel_interfaces']
    else:
        raise RuntimeError("Couldn't find a viable interface: No Ethernet, No PortChannels in the minigraph file.")

    # Randomly pick the interface from the above list
    list_of_bgp_ips = []
    for neigh_ip_address in bgp_interfaces.keys():
        if isinstance(ipaddress.ip_address(neigh_ip_address), IP_TYPE[af]):
            list_of_bgp_ips.append(neigh_ip_address)

    ret_interface_list = []
    available_number = len(list_of_bgp_ips)
    # Confirm there are enough interfaces (basicaly more than or equal to the number of vnets).
    if available_number <= number_of_required_interfaces+1:
        raise RuntimeError('''There are not enough interfaces needed to perform the test.
            We need atleast {} interfaces, but only {} are available.'''.format(number_of_required_interfaces+1, available_number))
    for index in range(number_of_required_interfaces):
        neigh_ip_address = list_of_bgp_ips[index]
        current_interface_name = bgp_interfaces[neigh_ip_address].keys()[0]
        ret_interface_list.append(current_interface_name)

    if ret_interface_list:
        return ret_interface_list
    else:
        raise RuntimeError("There is no Ethernet interface running BGP. Pls run this test on any T1 topology.")

def get_portchannels_to_neighbors(duthost, neighbor_type, minigraph_data):
    '''
        A function to get the list of portchannels connected to BGP neighbors of given type(T0 or T2).
        It returns a list of portchannels+minigraph_lag_facts_of_that portchannel.
        Arguments:
            duthost : DUT Ansible Host object
            localhost : Localhost Ansible Host object.
            neighbor_type: T0 or T2.
    '''
    lag_facts = duthost.lag_facts(host=duthost.sonichost.mgmt_ip)
    names = lag_facts['ansible_facts']['lag_facts']['names']
    lags = lag_facts['ansible_facts']['lag_facts']['lags']

    return_list = {}
    pattern = re.compile("{}$".format(neighbor_type))
    for pc_name in names:
        port_struct = lags[pc_name]['po_config']['ports']
        if lags[pc_name]['po_intf_stat'] == "Up":
            intf = port_struct.keys()[0]
            neighbor = minigraph_data['minigraph_neighbors'][intf]['name']
            match = pattern.search(neighbor)
            if match:
                # We found an interface that has a given neighbor_type. Let us use this.
                return_list[pc_name] = port_struct

    return return_list

def get_ethernet_to_neighbors(neighbor_type, minigraph_data):
    '''
        A function to get the list of Ethernet interfaces connected to BGP neighbors of given type(T0 or T2).
        It returns a list of ports.
        Arguments:
            duthost : DUT Ansible Host object
            neighbor_type: T0 or T2.
    '''

    pattern = re.compile("{}$".format(neighbor_type))
    ret_list = []

    for intf in minigraph_data['minigraph_neighbors']:
        if pattern.search(minigraph_data['minigraph_neighbors'][intf]['name']):
            ret_list.append(intf)

    return ret_list

def assign_intf_ip_address(selected_interfaces, af):
    intf_ip_map = {}
    for intf in selected_interfaces:
        ip = get_ip_address(af=af, hostid=Constants['DUT_HOSTID'], netid=201)
        intf_ip_map[intf] = ip
    return intf_ip_map

def get_all_interfaces_running_bgp(duthost, minigraph_data):
    bgp_neigh_list = duthost.bgp_facts()['ansible_facts']['bgp_neighbors']
    minigraph_ip_interfaces = minigraph_data['minigraph_interfaces'] + minigraph_data['minigraph_portchannel_interfaces']
    peer_addr_map = {}
    for x in    minigraph_ip_interfaces:
        peer_addr_map[x['peer_addr']] = {x['attachto'] : x['addr']}

    ret_list = {}
    for x, entry in peer_addr_map.iteritems():
        if bgp_neigh_list[x]['state'] == 'established':
            ret_list[x] = entry

    return ret_list

def configure_vnet_neighbors(duthost, intf_to_ip_map, minigraph_data, af):
    '''
        setup the vnet neighbor ip addresses.
    '''
    family = "IPv4"
    if af == "v6":
        family = "IPv6"

    return_dict = {}

    config_list = []
    for intf, addr in intf_to_ip_map.iteritems():
        # If the given address is "net.1", the return address is "net.101"
        # THE ASSUMPTION HERE IS THAT THE DUT ADDRESSES ARE ENDING IN ".1".
        ptf_ip = str(ipaddress.ip_address(unicode(addr))+100)

        if "Ethernet" in intf:
            return_dict[intf] = ptf_ip
        elif "PortChannel" in intf:
            for member in get_ethernet_ports([intf], minigraph_data):
                return_dict[member] = ptf_ip

        config_list.append('''"{}|{}": {{
            "family": "{}"
        }}'''.format(intf, ptf_ip, family))

    full_config = '''{
        "NEIGH" : {
    ''' + ",\n".join(config_list) + '''\n}\n}'''

    apply_config_in_dut(duthost, full_config, name="vnet_nbr_"+af)

    return return_dict

def create_vnets(duthost, tunnel_name, vnet_count=1, scope=None, vni_base=10000, vnet_name_prefix="Vnet"):
    return_dict = {}
    scope_entry = ""
    if scope:
        scope_entry = '''"scope": "{}",'''.format(scope)
    config_list = []
    for i in range(vnet_count):
        name = vnet_name_prefix + "-" + str(i)
        vni = vni_base+i
        return_dict[name] = vni
        config_list.append('''"{}": {{
               "vxlan_tunnel": "{}",
               {}"vni": "{}",
               "peer_list": ""
        }}'''.format(name, tunnel_name, scope_entry, vni))

        full_config = '{\n"VNET": {' + ",\n".join(config_list) + '\n}\n}'

    apply_config_in_dut(duthost, full_config, "vnets_"+tunnel_name)
    return return_dict

def setup_vnet_intf(duthost, selected_interfaces, vnet_list, minigraph_data):
    if len(selected_interfaces) != len(vnet_list):
        raise RuntimeError("Different number of interfaces and vnets, not supported yet")

    ret_list = {}
    intf_config_list = []
    po_config_list = []
    for count in range(len(selected_interfaces)):
        intf = selected_interfaces[count]
        config = ('''
                "{}" : {{
                    "vnet_name": "{}"
                }}
        '''.format(intf, vnet_list[count]))

        if "Ethernet" in intf:
            intf_config_list.append(config)
            ret_list[intf] = vnet_list[count]
        elif "PortChannel" in intf:
            po_config_list.append(config)
            for member in get_ethernet_ports([intf], minigraph_data):
                ret_list[member] = vnet_list[count]

    full_config_list = []
    if intf_config_list:
        full_config_list.append(
            '''"INTERFACE": {\n''' + ",\n".join(intf_config_list) + '''}''')
    if po_config_list:
        full_config_list.append(
            '''"PORTCHANNEL_INTERFACE": {\n''' + ",\n".join(po_config_list) + '''}''')

    full_config = '''{\n''' + ",\n".join(full_config_list) + '''}'''
    apply_config_in_dut(duthost, full_config, "vnet_intf")
    return ret_list

def configure_vxlan_switch(duthost, vxlan_port=4789, dutmac=None):
    if dutmac == None:
        #dutmac = duthost.facts['router_mac']
        dutmac = "aa:bb:cc:dd:ee:ff"

    switch_config = '''
[
        {{
                "SWITCH_TABLE:switch": {{
                        "vxlan_port": "{}",
                        "vxlan_router_mac": "{}"
                }},
                "OP": "SET"
        }}
]
'''.format(vxlan_port, dutmac)
    apply_config_in_swss(duthost, switch_config, "vnet_switch")

def apply_config_in_swss(duthost, config, name="swss_"):
    if Constants['DEBUG']:
        filename = name + ".json"
    else:
        filename = name + "-" + str(time.time()) + ".json"

    duthost.copy(content=config, dest="/tmp/{}".format(filename))
    duthost.shell('docker exec -i swss swssconfig /dev/stdin < /tmp/{}'.format(filename))
    if not Constants['KEEP_TEMP_FILES']:
        duthost.shell("rm /tmp/{}".format(filename))
    time.sleep(1)

def get_list_of_nexthops(number, af, prefix=100):
    nexthop_list = []
    for i in range(number):
        nexthop_list.append(get_ip_address(af=af, netid=prefix, hostid=10))
    return nexthop_list

def create_vnet_routes(duthost, vnet_list, dest_af, nh_af, nhs_per_destination=1, number_of_available_nexthops=100, number_of_ecmp_nhs=1000, dest_net_prefix=150, nexthop_prefix=100):
    '''
        This configures the VNET_TUNNEL_ROUTES structure. It precalculates the required number of
        destinations based on the given "number_of_ecmp_nhs" and the "nhs_per_destination".

        inputs:
            number_of_available_nexthops : Total number of unique NextHops available for use.
            nhs_per_destination                    : Number of ECMP nexthops to use per destination.
            number_of_ecmp_nhs                     : Maximum number of all NextHops put together(for all destinations).
    '''
    available_nexthops = get_list_of_nexthops(number=number_of_available_nexthops, af=nh_af, prefix=nexthop_prefix)

    number_of_destinations = int(number_of_ecmp_nhs / nhs_per_destination)
    no_of_dests_per_vnet = int(number_of_destinations / len(vnet_list))
    available_nexthop_count = 0
    dest_to_nh_map = {}
    for vnet in vnet_list:
        for i in range(no_of_dests_per_vnet):
            dest = get_ip_address(af=dest_af, netid=dest_net_prefix)
            my_nhs = []
            for j in range(nhs_per_destination):
                my_nhs.append(available_nexthops[available_nexthop_count % number_of_available_nexthops])
                available_nexthop_count = available_nexthop_count + 1
                if available_nexthop_count > number_of_ecmp_nhs:
                    break

            try:
                dest_to_nh_map[vnet]
            except KeyError:
                dest_to_nh_map[vnet] = {}
            dest_to_nh_map[vnet][dest] = my_nhs

    set_routes_in_dut(duthost, dest_to_nh_map, dest_af, "SET")
    return dest_to_nh_map

def get_outer_layer_version(encap_type):
    match = re.search("in_(v[46])", encap_type)
    if match:
        return match.group(1)
    else:
        raise RuntimeError("Invalid format for encap_type:{}".format(encap_type))

def get_payload_version(encap_type):
    match = re.search("(v[46])_in_v", encap_type)
    if match:
        return match.group(1)
    else:
        raise RuntimeError("Invalid format for encap_type:{}".format(encap_type))

def create_single_route(vnet, dest, mask, nhs, op):
    '''
        Create a single route entry for vnet, for the given dest, through the endpoints:nhs, op:SET/DEL
    '''
    return '''{{
        "VNET_ROUTE_TUNNEL_TABLE:{}:{}/{}": {{
            "endpoint": "{}"
        }},
        "OP": "{}"
    }}'''.format(vnet, dest, mask, ",".join(nhs), op)

Address_Count = 0
def get_ip_address(af, hostid=1, netid=100):
    global Address_Count
    third_octet = Address_Count % 255
    second_octet = (Address_Count / 255) % 255
    first_octet = netid + (Address_Count / 65025)
    Address_Count = Address_Count + 1
    if af == 'v4':
        return "{}.{}.{}.{}".format(first_octet, second_octet, third_octet, hostid)
    if af == 'v6':
        # :0: gets removed in the IPv6 addresses. Adding a to octets, to avoid it.
        return "fddd:a{}:a{}::a{}:{}".format(first_octet, second_octet, third_octet, hostid)

def set_routes_in_dut(duthost, dest_to_nh_map, dest_af, op):
    config_list = []
    for vnet in dest_to_nh_map.keys():
        for dest in dest_to_nh_map[vnet].keys():
            config_list.append(create_single_route(vnet, dest, HOST_MASK[dest_af], dest_to_nh_map[vnet][dest], op))

    full_config = '[' + "\n,".join(config_list) + '\n]'
    apply_config_in_swss(duthost, full_config, "set_routes")

def get_t2_ports(duthost, minigraph_data):
    '''
        In T1 topology, any port connected to the T2 BGP neighbors are needed.
        In T0, any port connected to the T1 BGP neighbors are needed.
    '''
    list_of_portchannels_to_T2 = get_portchannels_to_neighbors(duthost, "T2", minigraph_data)
    list_of_interfaces = []
    if list_of_portchannels_to_T2:
        for pc_name in list_of_portchannels_to_T2:
            list_of_interfaces.extend(list_of_portchannels_to_T2[pc_name])
    else:
        list_of_interfaces = get_ethernet_to_neighbors("T2", minigraph_data)

    ret_list = []
    for iface in list_of_interfaces:
        ret_list.append(minigraph_data["minigraph_ptf_indices"][iface])
    return ret_list

def bgp_established(duthost):
    bgp_facts = duthost.bgp_facts()['ansible_facts']
    for k, v in bgp_facts['bgp_neighbors'].items():
        if v['state'] != 'established':
            Logger.info("Neighbor %s not established yet: %s", k, v['state'])
            return False
    return True

def get_ethernet_ports(intf_list, minigraph_data):
    '''
        The given interface list can be either Ethernet or Portchannel.
        This function will return a flat list of Ethernet ports corresponding to
        the given intf_list itself, or members of Portchannels.
    '''
    ret_list = []
    for intf in intf_list:
        if "Ethernet" in intf:
            ret_list.append(intf)
        elif "PortChannel" in intf:
            ret_list.extend(minigraph_data['minigraph_portchannels'][intf]['members'])

    return ret_list

@pytest.fixture(scope="module")
def setUp(duthosts, ptfhost, request, rand_one_dut_hostname, minigraph_facts,
          tbinfo):

    global Constants
    # Should I keep the temporary files copied to DUT?
    Constants['KEEP_TEMP_FILES'] = request.config.option.keep_temp_files

    # Is debugging going on, or is it a production run? If it is a
    # production run, use time-stamped file names for temp files.
    Constants['DEBUG'] = request.config.option.debug_enabled

    # The host id in the ip addresses for DUT. It can be anything,
    # but helps to keep as a single number that is easy to identify
    # as DUT.
    Constants['DUT_HOSTID'] = request.config.option.dut_hostid

    Logger.info("Constants to be used in the script:%s", Constants)

    data = {}
    data['ptfhost'] = ptfhost
    data['tbinfo'] = tbinfo
    data['duthost'] = duthosts[rand_one_dut_hostname]
    data['minigraph_facts'] = data['duthost'].get_extended_minigraph_facts(tbinfo)
    data['dut_mac'] = data['duthost'].facts['router_mac']
    data['vxlan_port'] = request.config.option.vxlan_port
    configure_vxlan_switch(data['duthost'], vxlan_port=data['vxlan_port'], dutmac=data['dut_mac'])

    selected_interfaces = {}
    for encap_type in SUPPORTED_ENCAP_TYPES:
        outer_layer_version = get_outer_layer_version(encap_type)
        selected_interfaces[encap_type] = select_required_interfaces(
            data['duthost'],
            number_of_required_interfaces=1,
            minigraph_data=minigraph_facts,
            af=outer_layer_version)

    # To store the names of the tunnels, for every outer layer version.
    tunnel_names = {}
    # To track the vnets for every outer_layer_version.
    vnet_af_map = {}
    for encap_type in SUPPORTED_ENCAP_TYPES:
        outer_layer_version = get_outer_layer_version(encap_type)
        try:
            tunnel_names[outer_layer_version]
        except KeyError:
            tunnel_names[outer_layer_version] = create_vxlan_tunnel(data['duthost'], minigraph_data=minigraph_facts, af=outer_layer_version)

        payload_version = get_payload_version(encap_type)
        encap_type = "{}_in_{}".format(payload_version, outer_layer_version)
        encap_type_data = {}
        encap_type_data['selected_interfaces'] = selected_interfaces[encap_type]

        try:
            encap_type_data['vnet_vni_map'] = vnet_af_map[outer_layer_version]
        except KeyError:
            vnet_af_map[outer_layer_version] = create_vnets(data['duthost'],
                                                            tunnel_name=tunnel_names[outer_layer_version],
                                                            vnet_count=1, # default scope can take only one vnet.
                                                            vnet_name_prefix="Vnet_" + encap_type,
                                                            scope="default",
                                                            vni_base=10000)
            encap_type_data['vnet_vni_map'] = vnet_af_map[outer_layer_version]

        encap_type_data['vnet_intf_map'] = setup_vnet_intf(data['duthost'],
                                                           selected_interfaces=encap_type_data['selected_interfaces'],
                                                           vnet_list=encap_type_data['vnet_vni_map'].keys(),
                                                           minigraph_data=minigraph_facts)
        encap_type_data['intf_to_ip_map'] = assign_intf_ip_address(selected_interfaces=encap_type_data['selected_interfaces'], af=payload_version)
        encap_type_data['t2_ports'] = get_t2_ports(data['duthost'], minigraph_facts)
        encap_type_data['neighbor_config'] = configure_vnet_neighbors(data['duthost'], encap_type_data['intf_to_ip_map'], minigraph_data=minigraph_facts, af=payload_version)
        encap_type_data['dest_to_nh_map'] = create_vnet_routes(data['duthost'], encap_type_data['vnet_vni_map'].keys(),
                                                               nhs_per_destination=request.config.option.ecmp_nhs_per_destination,
                                                               number_of_available_nexthops=request.config.option.total_number_of_endpoints,
                                                               number_of_ecmp_nhs=request.config.option.total_number_of_nexthops,
                                                               dest_af=payload_version,
                                                               dest_net_prefix=150, # Hardcoded to avoid conflicts with topology networks.
                                                               nexthop_prefix=100, # Hardcoded to avoid conflicts with topology networks.
                                                               nh_af=outer_layer_version)

        data[encap_type] = encap_type_data

    # This data doesn't change per testcase, so we copy
    # it as a seperate file. The test-specific config
    # data will be copied on testase basis.
    data['ptfhost'].copy(content=json.dumps(
        {
            'minigraph_facts':    data['minigraph_facts'],
            'tbinfo' : data['tbinfo']
        },
        indent=4), dest="/tmp/vxlan_topo_info.json")

    yield data

    # Cleanup code.
    for encap_type in SUPPORTED_ENCAP_TYPES:
        outer_layer_version = get_outer_layer_version(encap_type)
        payload_version = get_payload_version(encap_type)

        encap_type = "{}_in_{}".format(payload_version, outer_layer_version)
        set_routes_in_dut(data['duthost'], data[encap_type]['dest_to_nh_map'], payload_version, "DEL")

        for intf in data[encap_type]['selected_interfaces']:
            redis_string = "INTERFACE"
            if "PortChannel" in intf > 0:
                redis_string = "PORTCHANNEL_INTERFACE"
            data['duthost'].shell("redis-cli -n 4 hdel \"{}|{}\" vnet_name".format(redis_string, intf))

        for vnet in data[encap_type]['vnet_vni_map'].keys():
            data['duthost'].shell("redis-cli -n 4 del \"VNET|{}\"".format(vnet))

    for tunnel in tunnel_names.values():
        data['duthost'].shell("redis-cli -n 4 del \"VXLAN_TUNNEL|{}\"".format(tunnel))

@pytest.mark.parametrize("encap_type", SUPPORTED_ENCAP_TYPES)
class Test_VxLAN:

    def dump_self_info_and_run_ptf(self, tcname, encap_type, expect_encap_success):
        '''
           Just a wrapper for dump_info_to_ptf to avoid entering 30 lines everytime.
        '''

        if Constants['DEBUG']:
            config_filename = "/tmp/vxlan_configs.json"
        else:
            config_filename = "/tmp/vxlan_configs." + tcname + "-" + encap_type + "-" + str(time.time()) + ".json"
        self.setup['ptfhost'].copy(content=json.dumps(
            {
                'vnet_vni_map' : self.setup[encap_type]['vnet_vni_map'],
                'vnet_intf_map' : self.setup[encap_type]['vnet_intf_map'],
                'dest_to_nh_map': self.setup[encap_type]['dest_to_nh_map'],
                'neighbors' : self.setup[encap_type]['neighbor_config'],
                'intf_to_ip_map': self.setup[encap_type]['intf_to_ip_map'],
            },
            indent=4), dest=config_filename)

        time.sleep(int(0.00005*getsizeof(self.setup[encap_type]['dest_to_nh_map'])) + 1)
        ptf_runner(self.setup['ptfhost'],
                   "ptftests",
                   "vxlan_traffic.VXLAN",
                   platform_dir="ptftests",
                   params={
                       "topo_file": "/tmp/vxlan_topo_info.json",
                       "config_file": config_filename,
                       "t0_ports":get_ethernet_ports(self.setup[encap_type]['selected_interfaces'], self.setup['minigraph_facts']),
                       "t2_ports":self.setup[encap_type]['t2_ports'],
                       "dut_mac":self.setup['dut_mac'],
                       "vxlan_port": self.setup['vxlan_port'],
                       "expect_encap_success":expect_encap_success
                       },
                   qlen=1000,
                   log_file="/tmp/vxlan-tests.{}.{}.{}.log".format(tcname, encap_type, datetime.now().strftime('%Y-%m-%d-%H:%M:%S')))

class Test_VxLAN_route_tests(Test_VxLAN):
    def test_vxlan_single_endpoint(self, setUp, encap_type):
        self.setup = setUp
        Logger.info("tc1:Create a tunnel route to a single endpoint a. Send packets to the route prefix dst.")
        self.dump_self_info_and_run_ptf("tc1", encap_type, True)
