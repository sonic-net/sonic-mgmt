#! /usr/bin/env python3

'''
    Script to automate the cases listed in VxLAN HLD document:
    https://github.com/Azure/SONiC/blob/8ca1ac93c8912fda7b09de9bfd51498e5038c292/doc/vxlan/Overlay%20ECMP%20with%20BFD.md#test-cases

    To test functionality:
    ./run_tests.sh -n ucs-m5-2 -d mth64-m5-2 -O -u -e -s -e --disable_loganalyzer -m individual -p /home/vxr/vxlan/logs/    -c 'vxlan/test_vxlan_ecmp.py'

    To test ECMP with 2 paths per destination:
    ./run_tests.sh -n ucs-m5-2 -d mth64-m5-2 -O -u -e -s -e --disable_loganalyzer -m individual -p /home/vxr/vxlan/logs/    -c 'vxlan/test_vxlan_ecmp.py' -e '--nhs_per_destination=2'

    To test ECMP+Scale(for all 4 types of encap):
    ./run_tests.sh -n ucs-m5-2 -d mth64-m5-2 -O -u -e -s -e --disable_loganalyzer -m individual -p /home/vxr/vxlan/logs/    -c  'vxlan/test_vxlan_ecmp.py::Test_VxLAN_route_tests::test_vxlan_single_endpoint' \
                    -e '--ecmp_nhs_per_destination=128' -e '--total_number_of_nexthops=32000' -e '--total_number_of_endpoints=1024'

    To keep the temporary config files created in the DUT:
    ./run_tests.sh -n ucs-m5-2 -d mth64-m5-2 -O -u -e -s -e --keep_temp_files -c 'vxlan/test_vxlan_ecmp.py'

    Other options:
        keep_temp_files             : Keep the temporary files created in the DUT. Default: False
        debug_enabled               : Enable debug mode, for debugging script. The temp files will not have timestamped names. Default: False
        dut_hostid                  : An integer in the range of 1 - 100 to be used as the host part of the IP address for DUT. Default: 1
        ecmp_nhs_per_destination    : Number of ECMP next-hops per destination.
        total_number_of_endpoints   : Number of Endpoints (a pool of this number of ip addresses will used for next-hops). Default:2
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
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.ptf_runner import ptf_runner

logger = logging.getLogger(__name__)

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

# Starting prefixes to be used for the destinations and End points.
DESTINATION_PREFIX = 150
NEXTHOP_PREFIX = 100

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
     The interfaces will be picked from the T0 facing side.
    '''
    bgp_interfaces = get_all_interfaces_running_bgp(duthost, minigraph_data, "T0")
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

def get_all_interfaces_running_bgp(duthost, minigraph_data, neighbor_type):
    bgp_neigh_list = duthost.bgp_facts()['ansible_facts']['bgp_neighbors']
    minigraph_ip_interfaces = minigraph_data['minigraph_interfaces'] + minigraph_data['minigraph_portchannel_interfaces']
    peer_addr_map = {}
    pattern = re.compile("{}$".format(neighbor_type))
    for x in    minigraph_ip_interfaces:
        peer_addr_map[x['peer_addr']] = {x['attachto'] : x['addr']}

    ret_list = {}
    for x, entry in peer_addr_map.iteritems():
        if bgp_neigh_list[x]['state'] == 'established' and pattern.search(bgp_neigh_list[x]['description']):
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
    time.sleep(int(0.0005*getsizeof(config)) + 1)
    if not Constants['KEEP_TEMP_FILES']:
        duthost.shell("rm /tmp/{}".format(filename))

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
    if number_of_available_nexthops < nhs_per_destination:
        raise RuntimeError("The number of available nexthops ip addresses is not enough to cover even one destination." \
                           "Pls rerun with total_number_of_endpoints({}) > ecmp_nhs_per_destination({})".format(number_of_available_nexthops, nhs_per_destination))

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
    apply_config_in_swss(duthost, full_config, op+"_routes")

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

def bgp_established(duthost, down_list=[]):
    bgp_facts = duthost.bgp_facts()['ansible_facts']
    for k, v in bgp_facts['bgp_neighbors'].items():
        if v['state'] == 'established':
            if k in down_list:
                # The neighbor is supposed to be down, and is actually up.
                logger.info("Neighbor %s is established, but should be down.", k)
                return False
            else:
                # The neighbor is supposed to be up, and is actually up.
                continue
        else:
            if k in down_list:
                # The neighbor is supposed to be down, and is actually down.
                continue
            else:
                # The neighbor is supposed to be up, but is actually down.
                logger.info("Neighbor %s is not yet established, has state: %s", k, v['state'])
                return False

    # Now wait for the routes to be updated.
    time.sleep(30)
    return True

def get_downed_bgp_neighbors(shut_intf_list, minigraph_data):
    '''
        Get the list of bgp neighbors that should be down,
        based on the interfaces that are shutdown.
    '''
    ret_list = []
    for intf in shut_intf_list:
        for m_intf in minigraph_data['minigraph_portchannel_interfaces']+minigraph_data['minigraph_interfaces']:
            if m_intf['attachto'] == intf:
                ret_list.append(m_intf['peer_addr'])
    return ret_list

def get_corresponding_ports(shut_intf_list, minigraph_data):
    '''
       This is for tests that shutdown some of the T2 ports.
       This function will check which ports are to be ignored for the encap packets coming
       back to the PTF. If the encap packet comes in any of these ports, it is a bug.
    '''
    eth_ifaces_list = []
    for intf in shut_intf_list:
        if "Ethernet" in intf:
            eth_ifaces_list.append(intf)
        elif "PortChannel" in intf:
            for port in get_ethernet_ports([intf], minigraph_data):
                eth_ifaces_list.append(port)
    return_list = [minigraph_data["minigraph_ptf_indices"][iface] for iface in eth_ifaces_list]
    return return_list

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


@pytest.fixture(scope="module", params=SUPPORTED_ENCAP_TYPES)
def encap_type(request):
    yield request.param


@pytest.fixture(scope="module")
def setUp(duthosts, ptfhost, request, rand_one_dut_hostname, minigraph_facts,
          tbinfo, encap_type):

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

    logger.info("Constants to be used in the script:%s", Constants)

    SUPPORTED_ENCAP_TYPES = [encap_type]

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
                                                               dest_net_prefix=DESTINATION_PREFIX,
                                                               nexthop_prefix=NEXTHOP_PREFIX,
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
            if "PortChannel" in intf:
                redis_string = "PORTCHANNEL_INTERFACE"
            data['duthost'].shell("redis-cli -n 4 hdel \"{}|{}\" vnet_name".format(redis_string, intf))

    # This script's setup code re-uses same vnets for v4inv4 and v6inv4.
    # There will be same vnet in multiple encap types.
    # So remove vnets *after* removing the routes first.
    for encap_type in SUPPORTED_ENCAP_TYPES:
         for vnet in data[encap_type]['vnet_vni_map'].keys():
             data['duthost'].shell("redis-cli -n 4 del \"VNET|{}\"".format(vnet))

    time.sleep(5)
    for tunnel in tunnel_names.values():
        data['duthost'].shell("redis-cli -n 4 del \"VXLAN_TUNNEL|{}\"".format(tunnel))


class Test_VxLAN:

    def dump_self_info_and_run_ptf(self, tcname, encap_type, expect_encap_success, packet_count=4):
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
                       "expect_encap_success":expect_encap_success,
                       "packet_count":packet_count
                       },
                   qlen=1000,
                   log_file="/tmp/vxlan-tests.{}.{}.{}.log".format(tcname, encap_type, datetime.now().strftime('%Y-%m-%d-%H:%M:%S')))

class Test_VxLAN_route_tests(Test_VxLAN):
    def test_vxlan_single_endpoint(self, setUp, encap_type):
        '''
            tc1:Create a tunnel route to a single endpoint a. Send packets to the route prefix dst.
        '''
        self.setup = setUp
        self.dump_self_info_and_run_ptf("tc1", encap_type, True)

    def test_vxlan_modify_route_different_endpoint(self, setUp, request, encap_type):
        '''
            tc2: change the route to different endpoint. packets are received only at endpoint b.")
        '''
        self.setup = setUp
        logger.info("Choose a vnet")
        vnet = self.setup[encap_type]['vnet_vni_map'].keys()[0]

        logger.info("Choose a destination, which is already present.")
        tc2_dest = self.setup[encap_type]['dest_to_nh_map'][vnet].keys()[0]

        logger.info("Create a new endpoint, or endpoint-list.")
        tc2_new_end_point_list = []
        for i in range(int(request.config.option.ecmp_nhs_per_destination)):
            tc2_new_end_point_list.append(get_ip_address(af=get_outer_layer_version(encap_type), netid=NEXTHOP_PREFIX))

        logger.info("Map the destination to the new endpoint(s).")
        self.setup[encap_type]['dest_to_nh_map'][vnet][tc2_dest] = tc2_new_end_point_list

        logger.info("Create the json and apply the config in the DUT swss.")
        # The config looks like:
        # [
        #   {
        #     "VNET_ROUTE_TUNNEL_TABLE:vnet:tc2_dest/32": {
        #       "endpoint": "{tc2_new_end_point_list}"
        #     },
        #     "OP": "{}"
        #   }
        # ]
        tc2_full_config = '[\n' + create_single_route(vnet, tc2_dest, HOST_MASK[get_payload_version(encap_type)], tc2_new_end_point_list, "SET") + '\n]'
        apply_config_in_swss(self.setup['duthost'], tc2_full_config, "vnet_route_tc2_"+encap_type)

        logger.info("Copy the new set of configs to the PTF and run the tests.")
        self.dump_self_info_and_run_ptf("tc2", encap_type, True)

    def test_vxlan_remove_all_route(self, setUp, encap_type):
        '''
            tc3: remove the tunnel route. send packets to the route prefix dst. packets should not be received at any ports with dst ip of b")
        '''
        self.setup = setUp
        try:
            logger.info("Remove the existing routes in the DUT.")
            set_routes_in_dut(self.setup['duthost'], self.setup[encap_type]['dest_to_nh_map'], get_payload_version(encap_type), "DEL")
            logger.info("Verify that the traffic is not coming back.")
            self.dump_self_info_and_run_ptf("tc3", encap_type, False)
        finally:
            logger.info("Restore the routes in the DUT.")
            set_routes_in_dut(self.setup['duthost'], self.setup[encap_type]['dest_to_nh_map'], get_payload_version(encap_type), "SET")

class Test_VxLAN_ecmp_create(Test_VxLAN):
    def test_vxlan_configure_route1_ecmp_group_a(self, setUp, encap_type):
        '''
            tc4:create tunnel route 1 with two endpoints a = {a1, a2...}. send packets to the route 1's prefix dst. packets are received at either a1 or a2.
        '''
        self.setup = setUp

        logger.info("Choose a vnet.")
        vnet = self.setup[encap_type]['vnet_vni_map'].keys()[0]

        logger.info("Create a new list of endpoint(s).")
        tc4_end_point_list = []
        for i in range(2):
            tc4_end_point_list.append(get_ip_address(af=get_outer_layer_version(encap_type), netid=NEXTHOP_PREFIX))

        logger.info("Create a new destination")
        tc4_new_dest = get_ip_address(af=get_payload_version(encap_type), netid=DESTINATION_PREFIX)

        logger.info("Map the new destination and the new endpoint(s).")
        self.setup[encap_type]['dest_to_nh_map'][vnet][tc4_new_dest] = tc4_end_point_list

        logger.info("Create a new config and Copy to the DUT.")
        tc4_config = '[\n' + create_single_route(vnet, tc4_new_dest, HOST_MASK[get_payload_version(encap_type)], tc4_end_point_list, "SET") + '\n]'
        apply_config_in_swss(self.setup['duthost'], tc4_config, "vnet_route_tc4_"+encap_type)

        logger.info("Verify that the new config takes effect and run traffic.")
        self.dump_self_info_and_run_ptf("tc4", encap_type, True)

    def test_vxlan_configure_route1_ecmp_group_b(self, setUp, encap_type):
        '''
            tc5: set tunnel route 2 to endpoint group a = {a1, a2}. send packets to route 2"s prefix dst. packets are received at either a1 or a2
        '''
        self.setup = setUp
        self.setup_route2_ecmp_group_b(encap_type)
        logger.info("Verify the configs work and traffic flows correctly.")
        self.dump_self_info_and_run_ptf("tc5", encap_type, True)

    def setup_route2_ecmp_group_b(self, encap_type):
        if self.setup[encap_type].get('tc5_dest', None):
            return
        logger.info("Choose a vnet for testing.")
        vnet = self.setup[encap_type]['vnet_vni_map'].keys()[0]

        logger.info("Select an existing endpoint.")
        tc5_end_point_list = self.setup[encap_type]['dest_to_nh_map'][vnet].values()[0]

        logger.info("Create a new destination to use.")
        tc5_new_dest = get_ip_address(af=get_payload_version(encap_type), netid=DESTINATION_PREFIX)

        logger.info("Map the new destination to the endpoint.")
        self.setup[encap_type]['dest_to_nh_map'][vnet][tc5_new_dest] = tc5_end_point_list

        logger.info("Create the new config and apply to the DUT.")
        tc5_config = '[\n' + create_single_route(vnet, tc5_new_dest, HOST_MASK[get_payload_version(encap_type)], tc5_end_point_list, "SET") + '\n]'
        apply_config_in_swss(self.setup['duthost'], tc5_config, "vnet_route_tc5_"+encap_type)
        self.setup[encap_type]['tc5_dest'] = tc5_new_dest

    def test_vxlan_configure_route2_ecmp_group_b(self, setUp, encap_type):
        '''
            tc6: set tunnel route 2 to endpoint group b = {b1, b2}. send packets to route 2"s prefix dst. packets are received at either b1 or b2.
        '''
        self.setup = setUp
        self.setup_route2_ecmp_group_b(encap_type)

        logger.info("Choose a vnet for testing.")
        vnet = self.setup[encap_type]['vnet_vni_map'].keys()[0]

        logger.info("Create a new list of endpoints.")
        tc6_end_point_list = []
        for i in range(2):
            tc6_end_point_list.append(get_ip_address(af=get_outer_layer_version(encap_type), netid=NEXTHOP_PREFIX))

        logger.info("Choose one of the existing destinations.")
        tc6_new_dest = self.setup[encap_type]['tc5_dest']

        logger.info("Map the destination to the new endpoints.")
        self.setup[encap_type]['dest_to_nh_map'][vnet][tc6_new_dest] = tc6_end_point_list

        logger.info("Create the config and apply on the DUT.")
        tc6_config = '[\n' + create_single_route(vnet, tc6_new_dest, HOST_MASK[get_payload_version(encap_type)], tc6_end_point_list, "SET") + '\n]'
        apply_config_in_swss(self.setup['duthost'], tc6_config, "vnet_route_tc6_"+encap_type)

        logger.info("Verify that the traffic works.")
        self.dump_self_info_and_run_ptf("tc6", encap_type, True)

class Test_VxLAN_NHG_Modify(Test_VxLAN):

    def setup_route2_single_endpoint(self, encap_type):
        if self.setup[encap_type].get('tc8_dest', None):
            return

        logger.info("Pick a vnet for testing.")
        vnet = self.setup[encap_type]['vnet_vni_map'].keys()[0]

        logger.info("Choose a route 2 destination and a new single endpoint for it.")
        tc8_new_dest = self.setup[encap_type]['dest_to_nh_map'][vnet].keys()[0]
        tc8_new_nh = get_ip_address(af=get_outer_layer_version(encap_type), netid=NEXTHOP_PREFIX)
        logger.info("Using destinations: dest:{} => nh:{}".format(tc8_new_dest, tc8_new_nh))

        logger.info("Map the destination and new endpoint.")
        tc8_config = '[\n' + create_single_route(vnet, tc8_new_dest, HOST_MASK[get_payload_version(encap_type)], [tc8_new_nh], "SET") + '\n]'
        self.setup[encap_type]['dest_to_nh_map'][vnet][tc8_new_dest] = [tc8_new_nh]

        logger.info("Apply the new config in the DUT and run traffic test.")
        apply_config_in_swss(self.setup['duthost'], tc8_config, "vnet_route_tc8_"+encap_type)
        self.setup[encap_type]['tc8_dest'] = tc8_new_dest

    def setup_route2_shared_endpoints(self, encap_type):
        if self.setup[encap_type].get('tc9_dest', None):
            return
        self.setup_route2_single_endpoint(encap_type)

        logger.info("Choose a vnet for testing.")
        vnet = self.setup[encap_type]['vnet_vni_map'].keys()[0]

        logger.info("Select 2 already existing destinations. They must have 2 different nexthops.")
        tc9_new_dest1 = self.setup[encap_type]['tc8_dest']
        nh1 = self.setup[encap_type]['dest_to_nh_map'][vnet][tc9_new_dest1][0]

        nh2 = None
        for dest in self.setup[encap_type]['dest_to_nh_map'][vnet].keys():
            nexthops = self.setup[encap_type]['dest_to_nh_map'][vnet][dest]
            for nh in nexthops:
                if nh == nh1:
                    continue
                else:
                    nh2 = nh
                    break
        if nh2:
            logger.info("Using destinations: dest:{}, nexthops:{}, {}".format(tc9_new_dest1, nh1, nh2))
        else:
            raise RuntimeError("Couldnot find different nexthop for this test. The current list: {}".format(self.setup[encap_type]['dest_to_nh_map']))

        logger.info("Use the selected nexthops(tunnel endpoints). They are guaranteed to be different.")
        tc9_new_nhs = [nh1, nh2]

        logger.info("Map the destination 1 to the combined list.")
        self.setup[encap_type]['dest_to_nh_map'][vnet][tc9_new_dest1] = tc9_new_nhs
        tc9_config = '[\n' + create_single_route(vnet, tc9_new_dest1, HOST_MASK[get_payload_version(encap_type)], tc9_new_nhs, "SET") + '\n]'

        logger.info("Apply the new config to the DUT and send traffic.")
        apply_config_in_swss(self.setup['duthost'], tc9_config, "vnet_route_tc9_"+encap_type)
        self.setup[encap_type]['tc9_dest'] = tc9_new_dest1

    def setup_route2_shared_different_endpoints(self, encap_type):
        if self.setup[encap_type].get('tc9_dest', None):
            return
        self.setup_route2_single_endpoint(encap_type)

        logger.info("Choose a vnet for testing.")
        vnet = self.setup[encap_type]['vnet_vni_map'].keys()[0]

        logger.info("Select 2 already existing destinations. They must have 2 different nexthops.")
        tc9_new_dest1 = self.setup[encap_type]['tc8_dest']
        old_nh = self.setup[encap_type]['dest_to_nh_map'][vnet][tc9_new_dest1][0]

        nh1 = None
        nh2 = None
        for dest in self.setup[encap_type]['dest_to_nh_map'][vnet].keys():
            nexthops = self.setup[encap_type]['dest_to_nh_map'][vnet][dest]
            for nh in nexthops:
                if nh == old_nh:
                    next
                else:
                    if not nh1:
                        nh1 = nh
                    elif not nh2:
                        if nh != nh1:
                            nh2 = nh
                            break
        if nh2:
            logger.info("Using destinations: dest:{}, nexthops:{}, {}".format(tc9_new_dest1, nh1, nh2))
        else:
            raise RuntimeError("Couldnot find different nexthop for this test. The current list: {}".format(self.setup[encap_type]['dest_to_nh_map']))

        logger.info("Use the selected nexthops(tunnel endpoints). They are guaranteed to be different.")
        tc9_new_nhs = [nh1, nh2]

        logger.info("Map the destination 1 to the combined list.")
        self.setup[encap_type]['dest_to_nh_map'][vnet][tc9_new_dest1] = tc9_new_nhs
        tc9_config = '[\n' + create_single_route(vnet, tc9_new_dest1, HOST_MASK[get_payload_version(encap_type)], tc9_new_nhs, "SET") + '\n]'

        logger.info("Apply the new config to the DUT and send traffic.")
        apply_config_in_swss(self.setup['duthost'], tc9_config, "vnet_route_tc9_"+encap_type)
        self.setup[encap_type]['tc9_dest'] = tc9_new_dest1


    def test_vxlan_remove_route2(self, setUp, encap_type):
        '''
            tc7:send packets to route 1's prefix dst. by removing route 2 from group a, no change expected to route 1.
        '''
        self.setup = setUp

        logger.info("Pick a vnet for testing.")
        vnet = self.setup[encap_type]['vnet_vni_map'].keys()[0]

        logger.info("Setup: Create two destinations with the same endpoint group.")
        tc7_end_point_list = []
        for i in range(2):
            tc7_end_point_list.append(get_ip_address(af=get_outer_layer_version(encap_type), netid=NEXTHOP_PREFIX))

        tc7_destinations = []
        for i in range(2):
            tc7_destinations.append(get_ip_address(af=get_payload_version(encap_type), netid=DESTINATION_PREFIX))

        logger.info("Map the new destinations to the same endpoint list.")
        for i in range(2):
            self.setup[encap_type]['dest_to_nh_map'][vnet][tc7_destinations[i]] = tc7_end_point_list

        logger.info("Apply the setup configs to the DUT.")
        for i in range(2):
            tc7_setup_config = '[\n' + create_single_route(vnet, tc7_destinations[i], HOST_MASK[get_payload_version(encap_type)], tc7_end_point_list, "SET") + '\n]'
            apply_config_in_swss(self.setup['duthost'], tc7_setup_config, "vnet_route_tc7_"+encap_type)

        logger.info("Verify the setup works.")
        self.dump_self_info_and_run_ptf("tc7", encap_type, True)
        logger.info("End of setup.")

        logger.info("Remove one of the routes.")
        logger.info("Pick one out of the two TC7 destinations.")
        tc7_removed_dest = tc7_destinations[0]
        tc7_removed_endpoint = self.setup[encap_type]['dest_to_nh_map'][vnet][tc7_removed_dest]
        del self.setup[encap_type]['dest_to_nh_map'][vnet][tc7_removed_dest]

        logger.info("Remove the chosen dest/endpoint from the DUT.")
        tc7_config = '[\n' + create_single_route(vnet, tc7_removed_dest, HOST_MASK[get_payload_version(encap_type)], tc7_removed_endpoint, "DEL") + '\n]'
        apply_config_in_swss(self.setup['duthost'], tc7_config, "vnet_route_tc7_"+encap_type)

        logger.info("Verify the rest of the traffic still works.")
        self.dump_self_info_and_run_ptf("tc7", encap_type, True)

    def test_vxlan_route2_single_nh(self, setUp, encap_type):
        '''
            tc8: set tunnel route 2 to single endpoint b1. send packets to route 2's prefix dst.
        '''
        self.setup = setUp
        self.setup_route2_single_endpoint(encap_type)
        self.dump_self_info_and_run_ptf("tc8", encap_type, True)

    def test_vxlan_route2_shared_nh(self, setUp, encap_type):
        '''
            tc9: set tunnel route 2 to shared endpoints a1 and b1. send packets to route 2's prefix dst.
        '''
        self.setup = setUp
        self.setup_route2_shared_endpoints(encap_type)
        self.dump_self_info_and_run_ptf("tc9", encap_type, True)

    def test_vxlan_route2_shared_different_nh(self, setUp, encap_type):
        '''
            tc9.2: set tunnel route 2 to 2 completely different shared(no-reuse) endpoints a1 and b1. send packets to route 2's prefix dst.
        '''
        self.setup = setUp
        self.setup_route2_shared_different_endpoints(encap_type)
        self.dump_self_info_and_run_ptf("tc9.2", encap_type, True)

    def test_vxlan_remove_ecmp_route2(self, setUp, encap_type):
        '''
            tc10: remove tunnel route 2. send packets to route 2's prefix dst.
        '''
        self.setup = setUp
        self.setup_route2_shared_endpoints(encap_type)
        logger.info("Backup the current route config.")
        full_map = dict(self.setup[encap_type]['dest_to_nh_map'])

        logger.info("This is to keep track if the selected route should be deleted in the end.")
        del_needed = False
        try:
            logger.info("Choose a vnet for testing.")
            vnet = self.setup[encap_type]['vnet_vni_map'].keys()[0]

            logger.info("Choose a destination and its nhs to delete.")
            tc10_dest = self.setup[encap_type]['tc9_dest']
            tc10_nhs = self.setup[encap_type]['dest_to_nh_map'][vnet][tc10_dest]
            logger.info("Using destination: dest:{}, nh:{}".format(tc10_dest, tc10_nhs))

            logger.info("Delete the dest and nh in the DUT.")
            tc10_config = '[\n' + create_single_route(vnet, tc10_dest, HOST_MASK[get_payload_version(encap_type)], tc10_nhs, "DEL") + '\n]'
            apply_config_in_swss(self.setup['duthost'], tc10_config, "vnet_route_tc10_"+encap_type)
            del_needed = True

            logger.info("We should pass only the deleted entry to the ptf call, and expect encap to fail.")
            logger.info("Clear out the mappings, and keep only the deleted dest and nhs.")
            self.setup[encap_type]['dest_to_nh_map'][vnet] = {}
            self.setup[encap_type]['dest_to_nh_map'][vnet][tc10_dest] = tc10_nhs

            logger.info("The deleted route should fail to receive traffic.")
            self.dump_self_info_and_run_ptf("tc10", encap_type, False)

            # all others should be working.
            # Housekeeping:
            logger.info("Restore the mapping of dest->nhs.")
            self.setup[encap_type]['dest_to_nh_map'] = dict(full_map)
            logger.info("Remove the deleted entry alone.")
            del self.setup[encap_type]['dest_to_nh_map'][vnet][tc10_dest]
            del_needed = False

            logger.info("Check the traffic is working in the other routes.")
            self.dump_self_info_and_run_ptf("tc10", encap_type, True)

        except:
            self.setup[encap_type]['dest_to_nh_map'] = dict(full_map)
            logger.info("Remove the deleted entry alone.")
            if del_needed:
                del self.setup[encap_type]['dest_to_nh_map'][vnet][tc10_dest]
            raise

class Test_VxLAN_ecmp_random_hash(Test_VxLAN):
    def test_vxlan_random_hash(self, setUp, encap_type):
        '''
            tc11: set tunnel route 3 to endpoint group c = {c1, c2, c3}. ensure c1, c2, and c3 matches to underlay default route. send 1000 pkt with random hash to route 3's prefix dst.
        '''
        self.setup = setUp

        logger.info("Chose a vnet for testing.")
        vnet = self.setup[encap_type]['vnet_vni_map'].keys()[0]

        logger.info("Create a new destination and 3 nhs for it.")
        tc11_new_dest = get_ip_address(af=get_payload_version(encap_type), netid=DESTINATION_PREFIX)
        tc11_new_nhs = []
        for i in range(3):
            tc11_new_nhs.append(get_ip_address(af=get_outer_layer_version(encap_type), netid=NEXTHOP_PREFIX))

        # the topology always provides the default routes for any ip address.
        # so it is already taken care of.

        logger.info("Map the new dest and nhs.")
        tc11_config = '[\n' + create_single_route(vnet, tc11_new_dest, HOST_MASK[get_payload_version(encap_type)], tc11_new_nhs, "SET") + '\n]'
        self.setup[encap_type]['dest_to_nh_map'][vnet][tc11_new_dest] = tc11_new_nhs

        logger.info("Apply the config in the DUT and verify traffic. The random hash and ECMP check is already taken care of in the VxLAN PTF script.")
        apply_config_in_swss(self.setup['duthost'], tc11_config, "vnet_route_tc11_"+encap_type)
        self.dump_self_info_and_run_ptf("tc11", encap_type, True, packet_count=1000)

class Test_VxLAN_underlay_ecmp(Test_VxLAN):
    @pytest.mark.parametrize("ecmp_path_count", [1, 2])
    def test_vxlan_modify_underlay_default(self, setUp, minigraph_facts, encap_type, ecmp_path_count):
        '''
            tc12: modify the underlay default route nexthop/s. send packets to route 3's prefix dst.
        '''
        self.setup = setUp
        # First step: pick one or two of the interfaces connected to t2, and bring them down.
        # verify that the encap is still working, and ptf receives the traffic.
        # Bring them back up.
        # After that, bring down all the other t2 interfaces, other than the ones used in the first step.
        # This will force a modification to the underlay default routes nexthops.

        all_t2_intfs = list(get_portchannels_to_neighbors(self.setup['duthost'], "T2", minigraph_facts))
        if not all_t2_intfs:
            all_t2_intfs = get_ethernet_to_neighbors("T2", minigraph_facts)
        logger.info("Dumping T2 link info: {}".format(all_t2_intfs))
        if not all_t2_intfs:
            raise RuntimeError("No interface found connected to t2 neighbors. pls check the testbed, aborting.")

        # Keep a copy of the internal housekeeping list of t2 ports.
        # This is the full list of DUT ports connected to T2 neighbors.
        # It is one of the arguments to the ptf code.
        all_t2_ports = list(self.setup[encap_type]['t2_ports'])

        # A distinction in this script between ports and interfaces:
        # Ports are physical (Ethernet) only.
        # Interfaces have IP address(Ethernet or PortChannel).

        try:
            selected_intfs = []
            # Choose some intfs based on the parameter ecmp_path_count.
            # when ecmp_path_count == 1, it is non-ecmp. The switching happens between ecmp and non-ecmp.
            # Otherwise, the switching happens within ecmp only.
            for i in range(ecmp_path_count):
                selected_intfs.append(all_t2_intfs[i])

            for intf in selected_intfs:
                self.setup['duthost'].shell("sudo config interface shutdown {}".format(intf))
            downed_ports = get_corresponding_ports(selected_intfs, minigraph_facts)
            self.setup[encap_type]['t2_ports'] = list(set(all_t2_ports) - set(downed_ports))
            downed_bgp_neighbors = get_downed_bgp_neighbors(selected_intfs, minigraph_facts)
            pytest_assert(wait_until(300, 30, 0, bgp_established, self.setup['duthost'], down_list=downed_bgp_neighbors), "BGP neighbors didn't come up after all interfaces have been brought up.")
            self.dump_self_info_and_run_ptf("tc12", encap_type, True, packet_count=1000)

            logger.info("Reverse the action: bring up the selected_intfs and shutdown others.")
            for intf in selected_intfs:
                self.setup['duthost'].shell("sudo config interface startup {}".format(intf))
            logger.info("Shutdown other interfaces.")
            remaining_interfaces = list(set(all_t2_intfs) - set(selected_intfs))
            for intf in remaining_interfaces:
                self.setup['duthost'].shell("sudo config interface shutdown {}".format(intf))
            downed_bgp_neighbors = get_downed_bgp_neighbors(remaining_interfaces, minigraph_facts)
            pytest_assert(wait_until(300, 30, 0, bgp_established, self.setup['duthost'], down_list=downed_bgp_neighbors), "BGP neighbors didn't come up after all interfaces have been brought up.")
            self.setup[encap_type]['t2_ports'] = get_corresponding_ports(selected_intfs, minigraph_facts)
            self.dump_self_info_and_run_ptf("tc12", encap_type, True, packet_count=1000)

            logger.info("Recovery. Bring all up, and verify traffic works.")
            for intf in all_t2_intfs:
                self.setup['duthost'].shell("sudo config interface startup {}".format(intf))
            logger.info("Wait for all bgp is up.")
            pytest_assert(wait_until(300, 30, 0, bgp_established, self.setup['duthost']), "BGP neighbors didn't come up after all interfaces have been brought up.")
            logger.info("Verify traffic flows after recovery.")
            self.setup[encap_type]['t2_ports'] = all_t2_ports
            self.dump_self_info_and_run_ptf("tc12", encap_type, True, packet_count=1000)

        except Exception:
            # If anything goes wrong in the try block, atleast bring the intf back up.
            self.setup[encap_type]['t2_ports'] = all_t2_ports
            for intf in all_t2_intfs:
                self.setup['duthost'].shell("sudo config interface startup {}".format(intf))
            pytest_assert(wait_until(300, 30, 0, bgp_established, self.setup['duthost']), "BGP neighbors didn't come up after all interfaces have been brought up.")
            raise

    def test_vxlan_remove_add_underlay_default(self, setUp, minigraph_facts, encap_type):
        '''
           tc13: remove the underlay default route.
           tc14: add the underlay default route.
        '''
        self.setup = setUp

        logger.info("Find all the underlay default routes' interfaces. This means all T2 interfaces.")
        all_t2_intfs = list(get_portchannels_to_neighbors(self.setup['duthost'], "T2", minigraph_facts))
        if not all_t2_intfs:
            all_t2_intfs = get_ethernet_to_neighbors("T2", minigraph_facts)
        logger.info("Dumping T2 link info: {}".format(all_t2_intfs))
        if not all_t2_intfs:
            raise RuntimeError("No interface found connected to t2 neighbors. pls check the testbed, aborting.")

        try:
            logger.info("Bring down the T2 interfaces.")
            for intf in all_t2_intfs:
                self.setup['duthost'].shell("sudo config interface shutdown {}".format(intf))
            downed_bgp_neighbors = get_downed_bgp_neighbors(all_t2_intfs, minigraph_facts)
            pytest_assert(wait_until(300, 30, 0, bgp_established, self.setup['duthost'], down_list=downed_bgp_neighbors),
                          "BGP neighbors have not reached the required state after T2 intf are shutdown.")

            logger.info("Verify that traffic is not flowing through.")
            self.dump_self_info_and_run_ptf("tc13", encap_type, False)

            '''
               tc14: Re-add the underlay default route.
            '''

            logger.info("Bring up the T2 interfaces.")
            for intf in all_t2_intfs:
                self.setup['duthost'].shell("sudo config interface startup {}".format(intf))

            logger.info("Wait for all bgp is up.")
            pytest_assert(wait_until(300, 30, 0, bgp_established, self.setup['duthost']), "BGP neighbors didn't come up after all interfaces have been brought up.")

            logger.info("Verify the traffic is flowing through, again.")
            self.dump_self_info_and_run_ptf("tc14", encap_type, True, packet_count=1000)

        except Exception:
            logger.info("If anything goes wrong in the try block, atleast bring the intf back up.")
            for intf in all_t2_intfs:
                self.setup['duthost'].shell("sudo config interface startup {}".format(intf))
            pytest_assert(wait_until(300, 30, 0, bgp_established, self.setup['duthost']), "BGP neighbors didn't come up after all interfaces have been brought up.")
            raise
