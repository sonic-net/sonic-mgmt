#! /usr/bin/env python3

'''
  Script to automate the cases listed in VxLAN HLD document:
  https://github.com/Azure/SONiC/blob/8ca1ac93c8912fda7b09de9bfd51498e5038c292/doc/vxlan/Overlay%20ECMP%20with%20BFD.md#test-cases

  To test functionality:
  ./run_tests.sh -n ucs-m5-2 -d mth64-m5-2 -O -u -e -s -e --disable_loganalyzer -m individual -p /home/vxr/vxlan/logs/  -c 'vxlan/test_vxlan.py'

  To test ECMP with 2 paths per destination:
  ./run_tests.sh -n ucs-m5-2 -d mth64-m5-2 -O -u -e -s -e --disable_loganalyzer -m individual -p /home/vxr/vxlan/logs/  -c 'vxlan/test_vxlan.py' -e '--nhs_per_destination=2'

  To test ECMP+Scale:
  ./run_tests.sh -n ucs-m5-2 -d mth64-m5-2 -O -u -e -s -e --disable_loganalyzer -m individual -p /home/vxr/vxlan/logs/  -c 'vxlan/test_vxlan.py' \
          -e '--ecmp_nhs_per_destination=128' -e '--total_number_of_nexthops=128000'
  
  Other options:
    ecmp_nhs_per_destination  : Number of ECMP next-hops per destination.
    total_number_of_endpoints : Number of Endpoints (a pool of this number of ip addresses will used for next-hops).
    total_number_of_nexthops  : Maximum number of all nexthops for every destination combined(per encap_type).
    vxlan_port                : Global vxlan port (UDP port) to be used for the DUT. Default: 4789
    num_vnet                  : Number of Vnets to test. Default: 1
'''

import time
import pytest
import re
import ipaddress
import json
import logging
from datetime import datetime
from tests.common.utilities import wait_until
from sys import getsizeof

from tests.common.config_reload import config_reload
from tests.common.fixtures.ptfhost_utils import remove_ip_addresses, change_mac_addresses, \
         copy_ptftests_directory, copy_arp_responder_py  # lgtm[py/unused-import]

from vnet_utils import safe_open_template

logger = logging.getLogger(__name__)

from tests.ptf_runner import ptf_runner

# Some of the constants used in this script.
constants = {}
# Should I keep the temporary files copied to DUT or PTF ?
constants['KEEP_TEMP_FILES'] = True
# Is debugging going on, or is it a production run? If it is a
# production run, use time-stamped file names for temp files.
constants['DEBUG'] = True
# The host id in the ip addresses for DUT. It can be anything, 
# but helps to keep as a single number that is easy to identify
# as DUT.
constants['DUT_HOSTID'] = 1

# Mapping the version to the python module.
IP_TYPE = {
  'v4' : ipaddress.IPv4Address,
  'v6' : ipaddress.IPv6Address
}
# This is the mask values to use for destination
# in the vnet routes.
HOST_MASK = { 'v4' : 32, 'v6' : 128 }

# This is the mask to use in the DUT ip address
NET_MASK  = { 'v4' : 24, 'v6' : 100 }

# This is the list of encapsulations that will be tested in this script.
# v6_in_v4 means: V6 payload is encapsulated inside v4 outer layer.
# This list is used in many locations in the script.
SUPPORTED_ENCAP_TYPES = ['v4_in_v4', 'v4_in_v6', 'v6_in_v4', 'v6_in_v6']

pytestmark = [
    # This script supports any T1 topology: t1, t1-64-lag, t1-lag.
    pytest.mark.topology("t1"),
    pytest.mark.sanity_check(post_check=False),
    pytest.mark.asic("cisco-8000")
]

def create_vxlan_tunnel(duthost, minigraph_data, tunnel_name=None, src_ip=None, af="v4"):
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
  if constants['DEBUG']:
    filename = "/tmp/" + name + ".json"
  else:
    filename = "/tmp/" + name + "-" + str(time.time()) + ".json"
  duthost.copy(content=config, dest=filename)
  duthost.shell("sudo config load {} -y".format(filename))
  time.sleep(1)
  if constants['KEEP_TEMP_FILES'] == False:
    duthost.shell("rm {}".format(filename))

def get_dut_loopback_address(duthost, minigraph_data, af="v4"):
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

  raise RuntimeError("Couldnot find the {} loopback address for the DUT({)) from minigraph.".format(af, duthost.hostname))

def select_required_interfaces(duthost, number_of_required_interfaces, minigraph_data, localhost, af="v4"):
  '''
   Pick the required number of interfaces to use for tests.
   These interfaces will be selected based on if they are currently running a established BGP.
   The interfaces will be randomly picked for the T2 facing side(which also will receive the decap'd traffic.)
  '''
  bgp_interfaces = get_all_interfaces_running_bgp(duthost, minigraph_data)
  interface_ip_table = minigraph_data['minigraph_interfaces']
  if len(interface_ip_table) != 0:
    available_interfaces = interface_ip_table
  elif len(minigraph_data['minigraph_portchannels']) != 0:
    available_interfaces =  minigraph_data['minigraph_portchannel_interfaces']
  else:
    raise RuntimeError("Couldn't find a viable interface: No Ethernet, No PortChannels in the minigraph file.")

  """
   First map the interface names to the local and remote IP addresses.
   We need this information to
    1. Remove the IP address from the interface and
    2. Shutdown the bgp neighbor.
  """
  map_intf_to_bgp_ips = {}
  for intf_struct in available_interfaces:
      try:
        map_intf_to_bgp_ips[intf_struct['attachto']]
      except KeyError:
        map_intf_to_bgp_ips[intf_struct['attachto']] = {}

      neigh_ip = intf_struct['peer_addr']
      if isinstance(ipaddress.ip_address(neigh_ip), IP_TYPE['v4']):
        map_intf_to_bgp_ips[intf_struct['attachto']]['v4'] = {'local' : intf_struct['subnet'], 'neigh': neigh_ip}
      elif isinstance(ipaddress.ip_address(neigh_ip), IP_TYPE['v6']):
        map_intf_to_bgp_ips[intf_struct['attachto']]['v6'] = {'local' : intf_struct['subnet'], 'neigh': neigh_ip}

  # Randomly pick the interface from the above list
  # Perform the required operations (remove ip address, shutdown bgp neighbor).
  list_of_bgp_ips = bgp_interfaces.keys()
  ret_interface_list = []
  available_number = len(list_of_bgp_ips)
  # Confirm there are enough interfaces (basicaly more than or equal to the number of  vnets).
  if available_number <= number_of_required_interfaces+1:
      raise RuntimeError('''There are not enough interfaces needed to perform the test.
        We need atleast {} interfaces, but only {} are available.'''.format(number_of_required_interfaces+1, available_number))
  while len(ret_interface_list) < number_of_required_interfaces:
    if len(list_of_bgp_ips) == 0:
      break
    index = random.randint(0, len(list_of_bgp_ips))
    try:
      neigh_ip_address = list_of_bgp_ips[index]
      current_interface_name = bgp_interfaces[neigh_ip_address].keys()[0]
      del list_of_bgp_ips[index]
      #if "Ethernet" in current_interface_name:
      current_interface_address = bgp_interfaces[neigh_ip_address].values()[0]
      if isinstance(ipaddress.ip_address(neigh_ip_address), IP_TYPE[af]):
        duthost.shell("sudo config bgp shutdown neighbor {}".format(neigh_ip_address))
        ret_interface_list.append(current_interface_name)

    except IndexError:
      next

  if len(ret_interface_list):
    return ret_interface_list
  else:
    raise RuntimeError("There is no Ethernet interface running BGP. Pls run this test on any T1 topology.")

def get_portchannels_to_neighbors(duthost, localhost, neighbor_type, community):
  '''
    A function to get the list of portchannels connected to BGP neighbors of given type(T0 or T2).
    It returns a list of portchannels+minigraph_lag_facts_of_that portchannel.
    Arguments:
      duthost : DUT Ansible Host object
      localhost : Localhost Ansible Host object.
      neighbor_type: T0 or T2.
      community: SNMP community string for lldp_facts() ansible library.
  '''
  lag_facts = duthost.lag_facts(host=duthost.sonichost.mgmt_ip)
  lldp_facts = localhost.lldp_facts(host=duthost.sonichost.mgmt_ip, version='v2c', community=community)
  names = lag_facts['ansible_facts']['lag_facts']['names']
  lags = lag_facts['ansible_facts']['lag_facts']['lags']

  return_list = {}
  pattern = re.compile("{}$".format(neighbor_type))
  for pc in names:
    port_struct = lags[pc]['po_config']['ports']
    if lags[pc]['po_intf_stat'] == "Up":
      intf = port_struct.keys()[0]
      neighbor = lldp_facts['ansible_facts']['ansible_lldp_facts'][intf]['neighbor_sys_name']
      m = pattern.search(neighbor)
      if m:
        # We found an interface that has a given neighbor_type. Let us use this.
        return_list[pc] = port_struct

  return return_list

def get_ethernet_to_neighbors(duthost, localhost, neighbor_type, community):
  '''
    A function to get the list of Ethernet interfaces connected to BGP neighbors of given type(T0 or T2).
    It returns a list of ports+lldp_facts of intf pairs.
    Arguments:
      duthost : DUT Ansible Host object
      localhost : Localhost Ansible Host object.
      neighbor_type: T0 or T2.
      community: SNMP community string for lldp table ansible lib.
  '''

  lldp_facts = localhost.lldp_facts(host=duthost.sonichost.mgmt_ip, version='v2c', community=community)['ansible_facts']['ansible_lldp_facts']
  pattern = re.compile("{}$".format(neighbor_type))
  ret_list = []

  for intf in lldp_facts:
    if pattern.search(lldp_facts[intf]['neighbor_sys_name']):
      ret_list.append(intf)

  return ret_list

def assign_intf_ip_address(duthost, selected_interfaces, af="v4"):
  intf_ip_map = {}
  for intf in selected_interfaces:
    ip = random_ip_address(af=af, hostid=constants['DUT_HOSTID'], net_id=201)
    config = '''{{
      "INTERFACE": {{
        "{interface}": {{}},
        "{interface}|{ip}/{mask}": {{}}
      }}
    }}'''.format(interface=intf, ip=ip, mask=NET_MASK[af])
    intf_ip_map[intf] = ip
    #apply_config_in_dut(duthost, config, "vnet_intf_ip_"+af)
  return intf_ip_map

def get_all_interfaces_running_bgp(duthost, minigraph_data, af="v4"):
    bgp_neigh_list = duthost.bgp_facts()['ansible_facts']['bgp_neighbors']
    minigraph_bgp_neigh_list = minigraph_data['minigraph_bgp']
    minigraph_ip_interfaces = minigraph_data['minigraph_interfaces'] + minigraph_data['minigraph_portchannel_interfaces']
    peer_addr_map = {}
    for x in  minigraph_ip_interfaces:
      peer_addr_map[x['peer_addr']] = {x['attachto'] : x['addr']}

    ret_list = {}
    for x,entry in peer_addr_map.iteritems():
      if bgp_neigh_list[x]['state'] == 'established':
        ret_list[x] = entry

    return ret_list

def configure_vnet_neighbors(duthost, ptfhost, tbinfo, intf_to_ip_map, minigraph_data, af="v4"):
  '''
    setup the vnet neighbor ip addresses.
    TODO: do we need to setup PTF intf addresses ? - probably not.
  '''
  ptf_ip_addresses = []
  family = "IPv4"
  if af == "v6":
    family = "IPv6"

  return_dict = {}

  config_list = []
  for intf,addr in intf_to_ip_map.iteritems():
    # TODO: Calculate a good address from the given address
    # If the given address is "net.1", the return address is "net.101"
    # THE ASSUMPTION HERE IS THAT THE DUT ADDRESSES ARE ENDING IN ".1".
    ptf_ip = str(ipaddress.ip_address(unicode(addr))+100)

    if "Ethernet" in intf:
      return_dict[intf] = ptf_ip
    elif "PortChannel" in intf:
      for member in get_ethernet_ports(duthost, [intf], minigraph_data):
        return_dict[member] = ptf_ip

    config_list.append('''"{}|{}": {{
      "family": "{}"
    }}'''.format(intf,ptf_ip,family))

  full_config = '''{
    "NEIGH" : {
  ''' + ",\n".join(config_list) + '''\n}\n}'''

  apply_config_in_dut(duthost, full_config, name="vnet_nbr_"+af)
  # Needed for decap only.
  #add_arp_or_ndp(duthost, af, ptf_ip, mac, intf)

  return return_dict

def add_arp_or_ndp(duthost, af, ptf_ip, mac, device):
  if af == "v4":
    af_opt = "-4"
    proto  = "arp"
  elif af == "v6":
    af_opt = "-6"
    proto  = "ndp"
  else:
    raise RuntimeError("Unrecognized address family:{}".format(af))

  duthost.shell("sonic-clear {}; ip {} neighbor add {} lladdr {} dev {}".format(proto, af_opt, ptf_ip, mac, device))

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
        for member in get_ethernet_ports(duthost, [intf], minigraph_data):
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

def configure_vxlan_switch(duthost, vxlan_port = 4789, dutmac = None):
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
  if constants['DEBUG']:
    filename = name + ".json"
  else:
    filename = name + "-" + str(time.time()) + ".json"

  duthost.copy(content=config, dest="/tmp/{}".format(filename))
  duthost.shell("docker cp /tmp/{} swss:/".format(filename))
  duthost.shell("docker exec swss sh -c \"swssconfig /{}\"".format(filename))
  time.sleep(1)

def generate_random_mac():
  # See https://stackoverflow.com/questions/8484877/mac-address-generator-in-python
  return "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255),
                             random.randint(0, 255),
                             random.randint(0, 255))

def get_list_of_nexthops(number, af, prefix=None):
  if prefix is None:
      prefix = random.randint(0, 220)
  nexthop_list = []
  for i in range(number):
    if af == "v4":
      nexthop_list.append("{}.{}.{}.{}".format(prefix, random.randint(0,255), random.randint(0, 255), random.randint(0, 255)))
    if af == "v6":
      nexthop_list.append("fddd::{}:{}:{}:{}".format(prefix, random.randint(0,255), random.randint(0, 255), random.randint(0, 255)))
  return nexthop_list

def create_vnet_routes(duthost, vnet_list, nhs_per_destination=1, number_of_available_nexthops=100, number_of_ecmp_nhs=1000, dest_af="v4", nh_af="v4", op="SET"):
  '''
    This configures the VNET_TUNNEL_ROUTES structure. It precalculates the required number of
    destinations based on the given "number_of_ecmp_nhs" and the "nhs_per_destination".

    inputs:
      number_of_available_nexthops : Total number of unique NextHops available for use.
      nhs_per_destination          : Number of ECMP nexthops to use per destination.
      number_of_ecmp_nhs           : Maximum number of all NextHops put together(for all destinations).
  '''
  available_nexthops = get_list_of_nexthops(number_of_available_nexthops, af=nh_af)

  number_of_destinations = int(number_of_ecmp_nhs / nhs_per_destination)
  no_of_dests_per_vnet = int(number_of_destinations / len(vnet_list))
  available_nexthop_count = 0
  config_list = []
  dest_to_nh_map = {}
  for vnet in vnet_list:
    for i in range(no_of_dests_per_vnet):
      dest = random_ip_address(af=dest_af)
      my_nhs = []
      for j in range(nhs_per_destination):
        my_nhs.append(available_nexthops[available_nexthop_count % number_of_available_nexthops])
        available_nexthop_count = available_nexthop_count + 1
        if available_nexthop_count > number_of_ecmp_nhs:
          break
      config_list.append(create_single_route(vnet, dest, HOST_MASK[dest_af], my_nhs, op))

      try:
        dest_to_nh_map[vnet]
      except KeyError:
        dest_to_nh_map[vnet] = {}
      dest_to_nh_map[vnet][dest] = my_nhs

  set_routes_in_dut(duthost, dest_to_nh_map, dest_af, op)
  return dest_to_nh_map

def get_outer_layer_version(encap_type):
    m = re.search("in_(v[46])", encap_type)
    if m:
        return m.group(1)
    else:
        raise RuntimeError("Invalid format for encap_type:{}".format(encap_type))

def get_payload_version(encap_type):
    m = re.search("(v[46])_in_v", encap_type)
    if m:
        return m.group(1)
    else:
        raise RuntimeError("Invalid format for encap_type:{}".format(encap_type))

def create_single_route(vnet, dest, mask, nhs, op):
  '''
    Create a single route entry for vnet, for the given dest, through the endpoints:nhs, op:SET/DEL
  '''
  return ('''{{
    "VNET_ROUTE_TUNNEL_TABLE:{}:{}/{}": {{
      "endpoint": "{}"
    }},
    "OP": "{}"
  }}'''.format(vnet, dest, mask, ",".join(nhs), op))

def random_ip_address(af='v4', hostid=None, net_id=None):
  if net_id is None:
    net_id = random.randint(1,220)
  if hostid is None:
    hostid = random.randint(1,150)
  if af == 'v4':
    return("{}.{}.{}.{}".format(net_id, random.randint(0,255), random.randint(0,255), hostid))
  if af == 'v6':
    return("fddd:{}:{}::{}:{}".format('%x' % random.randint(0,65535), '%x' % random.randint(0,65535), '%x' % random.randint(0,65535), '%x' % random.randint(0,65535)))

def set_routes_in_dut(duthost, dest_to_nh_map, dest_af, op):
  config_list = []
  for vnet in dest_to_nh_map.keys():
    for dest in dest_to_nh_map[vnet].keys():
      config_list.append(create_single_route(vnet, dest, HOST_MASK[dest_af], dest_to_nh_map[vnet][dest], op))

  full_config = '[' + "\n,".join(config_list) + '\n]'
  apply_config_in_swss(duthost, full_config, "set_routes")

def get_t2_ports(duthost, localhost, minigraph_data, community):
  '''
    In T1 topology, any port connected to the T2 BGP neighbors are needed.
    In T0, any port connected to the T1 BGP neighbors are needed.
  '''
  list_of_portchannels_to_T2 = get_portchannels_to_neighbors(duthost, localhost, "T2", community)
  list_of_interfaces = []
  for pc in list_of_portchannels_to_T2:
    list_of_interfaces.extend(list_of_portchannels_to_T2[pc])

  ret_list = [int(x[8:]) for x in list_of_interfaces]

  list_of_ethernet_to_T2 = get_ethernet_to_neighbors(duthost, localhost, "T2", community)
  ret_list.extend([int(x[8:]) for x in list_of_ethernet_to_T2])
  return ret_list

def bgp_established(duthost):
  bgp_facts = duthost.bgp_facts()['ansible_facts']
  for k, v in bgp_facts['bgp_neighbors'].items():
    if v['state'] != 'established':
      logger.info("Neighbor %s not established yet: %s", k, v['state'])
      return False
  return True

## Need this for decap.
#def prepare_arp_responder(ptfhost):
#  logger.info("Preparing PTF host")
#
#  arp_responder_conf = safe_open_template("templates/arp_responder.conf.j2") \
#                         .render(arp_responder_args="--conf /tmp/vxlan_arpresponder.conf")
#
#  ptfhost.copy(content=arp_responder_conf, dest="/etc/supervisor/conf.d/arp_responder.conf")
#  ptfhost.shell("supervisorctl reread")
#  ptfhost.shell("supervisorctl update")


def get_ethernet_ports(duthost, intf_list, minigraph_data):
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
          tbinfo, localhost, creds):
    data = {}
    data['ptfhost'] = ptfhost
    data['tbinfo'] = tbinfo
    data['duthost'] = duthosts[rand_one_dut_hostname]
    data['minigraph_facts'] = data['duthost'].get_extended_minigraph_facts(tbinfo) 
    data['dut_mac'] = data['duthost'].facts['router_mac']
    data['vxlan_port'] = request.config.option.vxlan_port
    configure_vxlan_switch(data['duthost'], vxlan_port = data['vxlan_port'], dutmac = data['dut_mac'])
    num_vnet = request.config.option.num_vnet
    # Need only for decap.
    #prepare_arp_responder(ptfhost)

    selected_interfaces = {}
    for encap_type in SUPPORTED_ENCAP_TYPES:
      outer_layer_version = get_outer_layer_version(encap_type)
      selected_interfaces[encap_type] = select_required_interfaces(
                data['duthost'],
                number_of_required_interfaces = request.config.option.num_vnet,
                minigraph_data=minigraph_facts,
                localhost = localhost,
                af= outer_layer_version)

    # The script only supports default scope for now.
    # So only one vnet per protocol will be supported.
    scope = "default"
    increment = num_vnet
    if scope == "default":
      increment = 0
      num_vnet  = 1
    count = 0
    # To store the names of the tunnels, for every outer layer version.
    tunnel_names = {}
    vnet_names = {}
    # To track the vnets for every outer_layer_version.
    vnet_af_map = {}
    for encap_type in SUPPORTED_ENCAP_TYPES:
      outer_layer_version = get_outer_layer_version(encap_type)
      try:
        tunnel_names[outer_layer_version]
      except KeyError:
        tunnel_names[outer_layer_version] = create_vxlan_tunnel(data['duthost'], minigraph_data = minigraph_facts, af=outer_layer_version)
      
      payload_version = get_payload_version(encap_type)
      count = count + increment
      encap_type = "{}_in_{}".format(payload_version, outer_layer_version)
      encap_type_data = {}
      encap_type_data['selected_interfaces'] = selected_interfaces[encap_type]

      try:
        encap_type_data['vnet_vni_map'] = vnet_af_map[outer_layer_version]
      except KeyError:
        if scope == "default":
            vnet_af_map[outer_layer_version] = create_vnets(data['duthost'],
                tunnel_name=tunnel_names[outer_layer_version],
                vnet_count=num_vnet,
                vnet_name_prefix = "Vnet_" + encap_type,
                scope=scope,
                vni_base=10000)
                #vni_base=(10000+count*num_vnet))
        encap_type_data['vnet_vni_map'] = vnet_af_map[outer_layer_version]
      encap_type_data['vnet_intf_map'] = setup_vnet_intf(data['duthost'],
                selected_interfaces = encap_type_data['selected_interfaces'],
                vnet_list = encap_type_data['vnet_vni_map'].keys(),
                minigraph_data = minigraph_facts)
      encap_type_data['intf_to_ip_map'] = assign_intf_ip_address(data['duthost'], selected_interfaces = encap_type_data['selected_interfaces'], af=payload_version)
      encap_type_data['t2_ports'] = get_t2_ports(data['duthost'], localhost,  minigraph_facts, creds['snmp_rocommunity'])
      encap_type_data['neighbor_config'] = configure_vnet_neighbors(data['duthost'], ptfhost, tbinfo, encap_type_data['intf_to_ip_map'], minigraph_data = minigraph_facts, af=payload_version)
      encap_type_data['dest_to_nh_map'] = create_vnet_routes(data['duthost'], encap_type_data['vnet_vni_map'].keys(),
          nhs_per_destination = request.config.option.ecmp_nhs_per_destination,
          number_of_available_nexthops = request.config.option.total_number_of_endpoints,
          number_of_ecmp_nhs = request.config.option.total_number_of_nexthops,
          dest_af = payload_version,
          nh_af = outer_layer_version)

      data[encap_type] = encap_type_data

    # This data doesn't change per testcase, so we copy
    # it as a seperate file. The test-specific config
    # data will be copied on testase basis.
    data['ptfhost'].copy(content=json.dumps(
      {
        'minigraph_facts':  data['minigraph_facts'],
        'tbinfo' : data['tbinfo']
      },
      indent=4), dest="/tmp/vxlan_topo_info.json")

    yield data

    # Cleanup code.
    data['duthost'].shell("sudo config bgp startup all")
    for encap_type in SUPPORTED_ENCAP_TYPES:
      outer_layer_version = get_outer_layer_version(encap_type)
      payload_version = get_payload_version(encap_type)
      
      encap_type = "{}_in_{}".format(payload_version, outer_layer_version)
      set_routes_in_dut(data['duthost'], data[encap_type]['dest_to_nh_map'], payload_version, "DEL") 

      for intf in data[encap_type]['vnet_intf_map'].keys():
        #data['duthost'].shell("redis-cli -n 4 del \"INTERFACE|{}|{}\"".format(intf, data[encap_type]['intf_to_ip_map']))
        #data['duthost'].shell("redis-cli -n 4 del \"INTERFACE|{}\"".format(intf))

        for entry in minigraph_facts['minigraph_interfaces'] + minigraph_facts['minigraph_portchannel_interfaces']:
          if intf == entry['attachto']:
            data['duthost'].shell("sudo config interface ip add {} {}".format(intf, entry['subnet']))

      for vnet in data[encap_type]['vnet_vni_map'].keys():
        data['duthost'].shell("redis-cli -n 4 del \"VNET|{}\"".format(vnet))

    for tunnel in tunnel_names.values():
      data['duthost'].shell("redis-cli -n 4 del \"VXLAN_TUNNEL|{}\"".format(tunnel))

@pytest.mark.parametrize("encap_type", SUPPORTED_ENCAP_TYPES)
class Test_VxLAN:

  @pytest.fixture
  def reapply_all_routes(self):
    for encap_type in SUPPORTED_ENCAP_TYPES:
      set_routes_in_dut(self.setup['duthost'], self.setup[encap_type]['dest_to_nh_map'], get_payload_version(encap_type), "SET")

  def dump_self_info_and_run_ptf(self, tcname, encap_type, expect_encap_success, expect_decap_success):
    '''
        just a wrapper for dump_info_to_ptf to avoid entering 6 lines everytime.
    '''

    if constants['DEBUG']:
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
    try:
      ptf_runner(self.setup['ptfhost'],
           "ptftests",
           "vxlan_traffic.VXLAN",
           platform_dir="ptftests",
           params={
               "topo_file": "/tmp/vxlan_topo_info.json",
               "config_file": config_filename,
               "t0_ports":get_ethernet_ports(self.setup['duthost'], self.setup[encap_type]['selected_interfaces'], self.setup['minigraph_facts']),
               "t2_ports":self.setup[encap_type]['t2_ports'],
               "dut_mac":self.setup['dut_mac'],
               "vxlan_port": self.setup['vxlan_port'],
               "decap_required":False,   # Decap is not required for the current usecase, disabled for now.
               "expect_encap_success":expect_encap_success,
               "expect_decap_success":expect_decap_success
               },
           qlen=1000,
           log_file="/tmp/vxlan-tests.{}.{}.log".format(tcname, encap_type, datetime.now().strftime('%Y-%m-%d-%H:%M:%S')))
    except:
      #import pdb; pdb.set_trace()
      raise

class Test_VxLAN_route_tests(Test_VxLAN):
  def test_vxlan_single_endpoint(self, setUp, encap_type):
    self.setup = setUp
    logger.info("tc1:Create a tunnel route to a single endpoint a. Send packets to the route prefix dst.")
    self.dump_self_info_and_run_ptf("tc1", encap_type, True, True)
