import ipaddress
from sys import getsizeof
import json, re, time

class Ecmp_Utils:
    Address_Count = 0
    
    # Some of the self.Constants used in this script.
    Constants = {}

    # Mapping the version to the python module.
    IP_TYPE = {
        'v4' : ipaddress.IPv4Address,
        'v6' : ipaddress.IPv6Address
    }

    # Starting prefixes to be used for the destinations and End points.
    DESTINATION_PREFIX = 150
    NEXTHOP_PREFIX = 100

    # Scale values for CRM test cases
    NHS_PER_DESTINATION = 8
    NUMBER_OF_AVAILABLE_NEXTHOPS = 4000
    NUMBER_OF_ECMP_NHS = 128000

    BFD_RESPONDER_SCRIPT_SRC_PATH = '../ansible/roles/test/files/helpers/bfd_responder.py'
    BFD_RESPONDER_SCRIPT_DEST_PATH = '/opt/bfd_responder.py'
    # This is the list of encapsulations that will be tested in this script.
    # v6_in_v4 means: V6 payload is encapsulated inside v4 outer layer.
    # This list is used in many locations in the script.
    SUPPORTED_ENCAP_TYPES = ['v4_in_v4', 'v4_in_v6', 'v6_in_v4', 'v6_in_v6']

    # This is the mask values to use for destination
    # in the vnet routes.
    HOST_MASK = {'v4' : 32, 'v6' : 128}
        
    def create_vxlan_tunnel(self, duthost, minigraph_data, af, tunnel_name=None, src_ip=None):
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
            src_ip = self.get_dut_loopback_address(duthost, minigraph_data, af)

        config = '''{{
            "VXLAN_TUNNEL": {{
                "{}": {{
                    "src_ip": "{}"
                }}
            }}
        }}'''.format(tunnel_name, src_ip)

        self.apply_config_in_dut(duthost, config, name="vxlan_tunnel_"+ af)
        return tunnel_name

    def init_ptf_bfd(self, ptfhost):
        ptfhost.shell("bfdd-beacon")


    def stop_ptf_bfd(self , ptfhost):
        ptfhost.shell("bfdd-control stop")

    def create_bfd_sessions_multihop(self , ptfhost, duthost, loopback_addr, ptf_intf, nexthop_ip, neighbor_addrs):
        # Create a tempfile for BFD sessions
        bfd_file_dir = duthost.shell('mktemp')['stdout']
        ptf_file_dir = ptfhost.shell('mktemp')['stdout']
        bfd_config = []
        ptf_config = []
        for neighbor_addr in neighbor_addrs:
            bfd_config.append({
                "BFD_SESSION_TABLE:default:default:{}".format(neighbor_addr): {
                    "local_addr": loopback_addr,
                    "multihop" : "true"
                },
                "OP": "SET"
            })
            ptf_config.append(
                {
                    "neighbor_addr": loopback_addr,
                    "local_addr" : neighbor_addr,
                    "multihop" : "true",
                    "ptf_intf" : "eth{}".format(ptf_intf)
                }
            )

        # Copy json file to DUT
        duthost.copy(content=json.dumps(bfd_config, indent=4), dest=bfd_file_dir, verbose=False)

        # Apply BFD sessions with swssconfig
        result = duthost.shell('docker exec -i swss swssconfig /dev/stdin < {}'.format(bfd_file_dir),
                            module_ignore_errors=True)
        if result['rc'] != 0:
            pytest.fail('Failed to apply BFD session configuration file: {}'.format(result['stderr']))

    def update_bfd_session_state(self, ptfhost, neighbor_addr, local_addr, state):
        ptfhost.shell("bfdd-control session local {} remote {} state {}".format(neighbor_addr, local_addr, state))

    def update_bfd_state(self, ptfhost, neighbor_addr, local_addr, state):
        ptfhost.shell("bfdd-control session local {} remote {} {}".format(neighbor_addr, local_addr, state))
        
    def apply_config_in_dut(self, duthost, config, name="vxlan"):
        '''
            The given json(config) will be copied to the DUT and loaded up.
        '''
        if self.Constants['DEBUG']:
            filename = "/tmp/" + name + ".json"
        else:
            filename = "/tmp/" + name + "-" + str(time.time()) + ".json"
        duthost.copy(content=config, dest=filename)
        duthost.shell("sudo config load {} -y".format(filename))
        time.sleep(1)
        if not self.Constants['KEEP_TEMP_FILES']:
            duthost.shell("rm {}".format(filename))

    def get_dut_loopback_address(self, duthost, minigraph_data, af):
        '''
            Returns the IP address of the Loopback interface in DUT, from minigraph.
            Arguments:
                duthost : DUT Ansible Host object.
                minigraph_data: Minigraph facts from the DUT.
                af : Address Family(v4 or v6).
        '''
        lo_ip = minigraph_data['minigraph_lo_interfaces']
        for intf in lo_ip:
            if isinstance(ipaddress.ip_address(intf['addr']), self.IP_TYPE[af]):
                return intf['addr']

        raise RuntimeError("Couldnot find the {} loopback address for the DUT:{} from minigraph.".format(af, duthost.hostname))

    def select_required_interfaces(self, duthost, number_of_required_interfaces, minigraph_data, af):
        '''
        Pick the required number of interfaces to use for tests.
        These interfaces will be selected based on if they are currently running a established BGP.
        The interfaces will be picked from the T0 facing side.
        '''
        bgp_interfaces = self.get_all_interfaces_running_bgp(duthost, minigraph_data, "T0")
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
            if isinstance(ipaddress.ip_address(neigh_ip_address), self.IP_TYPE[af]):
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

    def get_portchannels_to_neighbors(self, duthost, neighbor_type, minigraph_data):
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

    def get_ethernet_to_neighbors(self, neighbor_type, minigraph_data):
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

    def assign_intf_ip_address(self, selected_interfaces, af):
        intf_ip_map = {}
        for intf in selected_interfaces:
            ip = self.get_ip_address(af=af, hostid=self.Constants['DUT_HOSTID'], netid=201)
            intf_ip_map[intf] = ip
        return intf_ip_map

    def get_all_interfaces_running_bgp(self, duthost, minigraph_data, neighbor_type):
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

    def configure_vnet_neighbors(self, duthost, intf_to_ip_map, minigraph_data, af):
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
                for member in self.get_ethernet_ports([intf], minigraph_data):
                    return_dict[member] = ptf_ip

            config_list.append('''"{}|{}": {{
                "family": "{}"
            }}'''.format(intf, ptf_ip, family))

        full_config = '''{
            "NEIGH" : {
        ''' + ",\n".join(config_list) + '''\n}\n}'''

        #self.apply_config_in_dut(duthost, full_config, name="vnet_nbr_"+af)

        return return_dict

    def create_vnets(self, duthost, tunnel_name, vnet_count=1, scope=None, vni_base=10000, vnet_name_prefix="Vnet"):
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

        self.apply_config_in_dut(duthost, full_config, "vnets_"+tunnel_name)
        return return_dict

    def setup_vnet_intf(self, duthost, selected_interfaces, vnet_list, minigraph_data):
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
                for member in self.get_ethernet_ports([intf], minigraph_data):
                    ret_list[member] = vnet_list[count]

        full_config_list = []
        if intf_config_list:
            full_config_list.append(
                '''"INTERFACE": {\n''' + ",\n".join(intf_config_list) + '''}''')
        if po_config_list:
            full_config_list.append(
                '''"PORTCHANNEL_INTERFACE": {\n''' + ",\n".join(po_config_list) + '''}''')

        full_config = '''{\n''' + ",\n".join(full_config_list) + '''}'''
        self.apply_config_in_dut(duthost, full_config, "vnet_intf")
        return ret_list

    def configure_vxlan_switch(self, duthost, vxlan_port=4789, dutmac=None):
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
        self.apply_config_in_swss(duthost, switch_config, "vnet_switch")

    def apply_config_in_swss(self, duthost, config, name="swss_"):
        if self.Constants['DEBUG']:
            filename = name + ".json"
        else:
            filename = name + "-" + str(time.time()) + ".json"

        duthost.copy(content=config, dest="/tmp/{}".format(filename))
        duthost.shell('docker exec -i swss swssconfig /dev/stdin < /tmp/{}'.format(filename))
        time.sleep(int(0.0005*getsizeof(config)) + 1)
        if not self.Constants['KEEP_TEMP_FILES']:
            duthost.shell("rm /tmp/{}".format(filename))

    def get_list_of_nexthops(self, number, af, prefix=100):
        nexthop_list = []
        for i in range(number):
            nexthop_list.append(self.get_ip_address(af=af, netid=prefix, hostid=10))
        return nexthop_list

    def create_vnet_routes(self, duthost, vnet_list, dest_af, nh_af, nhs_per_destination=1, number_of_available_nexthops=100, number_of_ecmp_nhs=1000, dest_net_prefix=150, nexthop_prefix=100, bfd = None):
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

        available_nexthops = self.get_list_of_nexthops(number=number_of_available_nexthops, af=nh_af, prefix=nexthop_prefix)

        number_of_destinations = int(number_of_ecmp_nhs / nhs_per_destination)
        no_of_dests_per_vnet = int(number_of_destinations / len(vnet_list))
        available_nexthop_count = 0
        dest_to_nh_map = {}
        for vnet in vnet_list:
            for i in range(no_of_dests_per_vnet):
                dest = self.get_ip_address(af=dest_af, netid=dest_net_prefix)
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

        self.set_routes_in_dut(duthost, dest_to_nh_map, dest_af, "SET", bfd = bfd)
        return dest_to_nh_map

    def get_outer_layer_version(self, encap_type):
        match = re.search("in_(v[46])", encap_type)
        if match:
            return match.group(1)
        else:
            raise RuntimeError("Invalid format for encap_type:{}".format(encap_type))

    def get_payload_version(self, encap_type):
        match = re.search("(v[46])_in_v", encap_type)
        if match:
            return match.group(1)
        else:
            raise RuntimeError("Invalid format for encap_type:{}".format(encap_type))

    def create_single_route(self, vnet, dest, mask, nhs, op, bfd = None):
        '''
            Create a single route entry for vnet, for the given dest, through the endpoints:nhs, op:SET/DEL
        '''
        if bfd:
            config = '''{{
            "VNET_ROUTE_TUNNEL_TABLE:{}:{}/{}": {{
                "endpoint": "{}",
                "endpoint_monitor": "{}"
            }},
            "OP": "{}"
        }}'''.format(vnet, dest, mask, ",".join(nhs), ",".join(nhs), op)

        else:
            config = '''{{
            "VNET_ROUTE_TUNNEL_TABLE:{}:{}/{}": {{
                "endpoint": "{}"
            }},
            "OP": "{}"
        }}'''.format(vnet, dest, mask, ",".join(nhs), op)

        return config

    
    def get_ip_address(self, af, hostid=1, netid=100):
        third_octet = self.Address_Count % 255
        second_octet = (self.Address_Count / 255) % 255
        first_octet = netid + (self.Address_Count / 65025)
        self.Address_Count = self.Address_Count + 1
        if af == 'v4':
            return "{}.{}.{}.{}".format(first_octet, second_octet, third_octet, hostid)
        if af == 'v6':
            # :0: gets removed in the IPv6 addresses. Adding a to octets, to avoid it.
            return "fddd:a{}:a{}::a{}:{}".format(first_octet, second_octet, third_octet, hostid)

    def set_routes_in_dut(self, duthost, dest_to_nh_map, dest_af, op, bfd = None):
        config_list = []
        for vnet in dest_to_nh_map.keys():
            for dest in dest_to_nh_map[vnet].keys():
                config_list.append(self.create_single_route(vnet, dest, self.HOST_MASK[dest_af], dest_to_nh_map[vnet][dest], op, bfd = bfd))

        full_config = '[' + "\n,".join(config_list) + '\n]'
        self.apply_config_in_swss(duthost, full_config, op+"_routes")

    def get_t2_ports(self, duthost, minigraph_data):
        '''
            In T1 topology, any port connected to the T2 BGP neighbors are needed.
            In T0, any port connected to the T1 BGP neighbors are needed.
        '''
        list_of_portchannels_to_T2 = self.get_portchannels_to_neighbors(duthost, "T2", minigraph_data)
        list_of_interfaces = []
        if list_of_portchannels_to_T2:
            for pc_name in list_of_portchannels_to_T2:
                list_of_interfaces.extend(list_of_portchannels_to_T2[pc_name])
        else:
            list_of_interfaces = self.get_ethernet_to_neighbors("T2", minigraph_data)

        ret_list = []
        for iface in list_of_interfaces:
            ret_list.append(minigraph_data["minigraph_ptf_indices"][iface])
        return ret_list

    def bgp_established(self, duthost, down_list=[]):
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

    def get_downed_bgp_neighbors(self, shut_intf_list, minigraph_data):
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

    def get_all_bgp_neighbors(self, minigraph_facts, type):
        all_neighbors = {}
        for element in minigraph_facts['minigraph_bgp']:
            if type in element['name']:
                if ipaddress.ip_address(element['addr']).version == 4:
                    all_neighbors[element['name']] = {"v4":element['addr']}
                elif ipaddress.ip_address(element['addr']).version == 6:
                    all_neighbors[element['name']].update({"v6":element['addr']})
        return all_neighbors

    def get_corresponding_ports(self, shut_intf_list, minigraph_data):
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
                for port in self.get_ethernet_ports([intf], minigraph_data):
                    eth_ifaces_list.append(port)
        return_list = [minigraph_data["minigraph_ptf_indices"][iface] for iface in eth_ifaces_list]
        return return_list

    def get_ethernet_ports(self, intf_list, minigraph_data):
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
    
    def gather_ptf_indices_t2_neighbor(self, minigraph_facts, all_t2_neighbors, t2_neighbor, encap_type):
         # All T2 Neighbors VM's name to Neighbor IP Mapping
        all_pcs = minigraph_facts['minigraph_portchannel_interfaces']
        #Neighbor IP to Portchannel interfaces mapping
        pc_to_ip_map = {}
        for each_pc in all_pcs:
            pc_to_ip_map[each_pc['peer_addr']] = each_pc['attachto']
        #Finding the portchannel under shutdown T2 Neighbor
        required_pc = pc_to_ip_map[all_t2_neighbors[t2_neighbor][self.get_outer_layer_version(encap_type)].lower()]
        #Finding ethernet interfaces under that specific portchannel
        required_ethernet_interfaces = minigraph_facts['minigraph_portchannels'][required_pc]['members']
        #Finding interfaces with PTF indices
        ret_list = []
        for iface in required_ethernet_interfaces:
            ret_list.append(minigraph_facts["minigraph_ptf_indices"][iface])
        return ret_list

    def ptf_config(self, duthost, ptfhost, tbinfo, delete_member_a1 = None, delete_member_a2 = None):
        responder_output = ptfhost.command('supervisorctl stop bfd_responder')
        responder_output = responder_output['stdout_lines'][0]
        if responder_output not in ['bfd_responder: stopped','bfd_responder: ERROR (not running)']:
            raise RuntimeError("Something is wrong with bfd_responder. Please check")
        time.sleep(2)
        mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
        for element in mg_facts['minigraph_lo_interfaces']:
            if element['prefixlen'] == 32:
                loopback_addr = element['addr']
            # elif element['prefixlen'] == 128:
            #     loopback_addr = element['addr']
        ptf_indices = mg_facts['minigraph_ptf_indices'].values()
        ptfhost.copy(src="../tests/vxlan/bfd_sniffer.py", dest="/tmp/bfd_sniffer.py")
        ptfhost.command("python /tmp/bfd_sniffer.py {} {}".format(delete_member_a1, delete_member_a2))
        ptfhost.copy(src=self.BFD_RESPONDER_SCRIPT_SRC_PATH, dest=self.BFD_RESPONDER_SCRIPT_DEST_PATH)
        extra_vars = {"bfd_responder_args" : "-c {}".format("/tmp/ptf_config.json")}
        ptfhost.host.options["variable_manager"].extra_vars.update(extra_vars)
        ptfhost.template(src='templates/bfd_responder.conf.j2', dest='/etc/supervisor/conf.d/bfd_responder.conf')
        ptfhost.command('supervisorctl reread')
        ptfhost.command('supervisorctl update')
        ptfhost.command('supervisorctl start bfd_responder')
        