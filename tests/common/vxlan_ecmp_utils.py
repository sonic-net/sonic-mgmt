'''
    Usage:
    from tests.common.vxlan_ecmp_utils import Ecmp_Utils
    my_own_ecmp_utils = Ecmp_Utils()
    my_own_ecmp_utils.create_vxlan_tunnel(...)
'''

from sys import getsizeof
import re
import time
import logging
from ipaddress import ip_address, IPv4Address, IPv6Address

Logger = logging.getLogger(__name__)


class Ecmp_Utils(object):
    '''
        Collection of functions that are used by the VxLAN scripts.
    '''
    Address_Count = 0

    # Some of the self.Constants used in this script.
    Constants = {}

    # Mapping the version to the python module.
    IP_TYPE = {
        'v4': IPv4Address,
        'v6': IPv6Address
    }

    # Starting prefixes to be used for the destinations and End points.
    DESTINATION_PREFIX = 150
    NEXTHOP_PREFIX = 100

    # Scale values for CRM test cases
    NHS_PER_DESTINATION = 8
    NUMBER_OF_AVAILABLE_NEXTHOPS = 4000
    NUMBER_OF_ECMP_NHS = 128000

    # This is the list of encapsulations that will be tested in this script.
    # v6_in_v4 means: V6 payload is encapsulated inside v4 outer layer.
    # This list is used in many locations in the script.
    SUPPORTED_ENCAP_TYPES = ['v4_in_v4', 'v4_in_v6', 'v6_in_v4', 'v6_in_v6']

    # This is the mask values to use for destination
    # in the vnet routes.
    HOST_MASK = {'v4': 32, 'v6': 128}

    OVERLAY_DMAC = "25:35:45:55:65:75"

    def create_vxlan_tunnel(self,
                            duthost,
                            minigraph_data,
                            af,
                            tunnel_name=None,
                            src_ip=None):
        '''
            Function to create a vxlan tunnel. The arguments:
                duthost       : The DUT ansible host object.
                minigraph_data: minigraph facts from the dut host.
                tunnel_name   : A name for the Tunnel, default: tunnel_<AF>
                src_ip        : Source ip address of the tunnel. It has to be a
                                local ip address in the DUT. Default: Loopback
                                ip address.
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

        self.apply_config_in_dut(duthost, config, name="vxlan_tunnel_" + af)
        return tunnel_name

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
            Returns the IP address of the Loopback interface in DUT, from
            minigraph.
            Arguments:
                duthost : DUT Ansible Host object.
                minigraph_data: Minigraph facts from the DUT.
                af : Address Family(v4 or v6).
        '''
        lo_ip = minigraph_data['minigraph_lo_interfaces']
        for intf in lo_ip:
            if isinstance(ip_address(intf['addr']), self.IP_TYPE[af]):
                return intf['addr']

        raise RuntimeError(
            "Couldnot find the {} loopback address"
            "for the DUT:{} from minigraph.".format(af, duthost.hostname))

    def select_required_interfaces(
            self, duthost, number_of_required_interfaces, minigraph_data, af):
        '''
        Pick the required number of interfaces to use for tests.
        These interfaces will be selected based on if they are currently
        running a established BGP.  The interfaces will be picked from the T0
        facing side.
        '''
        bgp_interfaces = self.get_all_interfaces_running_bgp(
            duthost,
            minigraph_data,
            "T0")

        # Randomly pick the interface from the above list
        list_of_bgp_ips = []
        for neigh_ip_address in bgp_interfaces:
            if isinstance(ip_address(neigh_ip_address), self.IP_TYPE[af]):
                list_of_bgp_ips.append(neigh_ip_address)

        ret_interface_list = []
        available_number = len(list_of_bgp_ips)
        # Confirm there are enough interfaces (basicaly more than or equal
        # to the number of vnets).
        if available_number <= number_of_required_interfaces+1:
            raise RuntimeError(
                "There are not enough interfaces needed to perform the test. "
                "We need atleast {} interfaces, but only {} are "
                "available.".format(
                    number_of_required_interfaces+1, available_number))
        for index in range(number_of_required_interfaces):
            neigh_ip_address = list_of_bgp_ips[index]
            current_interface_name = list(
                bgp_interfaces[neigh_ip_address].keys())[0]
            ret_interface_list.append(current_interface_name)

        if ret_interface_list:
            return ret_interface_list
        else:
            raise RuntimeError(
                "There is no Ethernet interface running BGP."
                "Pls run this test on any T1 topology.")

    @classmethod
    def get_portchannels_to_neighbors(cls,
                                      duthost,
                                      neighbor_type,
                                      minigraph_data):
        '''
            A function to get the list of portchannels connected to BGP
            neighbors of given type(T0 or T2).  It returns a list of
            portchannels+minigraph_lag_facts_of_that portchannel.
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
                intf = list(port_struct.keys())[0]
                neighbor = minigraph_data['minigraph_neighbors'][intf]['name']
                match = pattern.search(neighbor)
                if match:
                    # We found an interface that has a given neighbor_type.
                    # Let us use this.
                    return_list[pc_name] = port_struct

        return return_list

    @classmethod
    def get_ethernet_to_neighbors(cls, neighbor_type, minigraph_data):
        '''
            A function to get the list of Ethernet interfaces connected to
            BGP neighbors of given type(T0 or T2). It returns a list of ports.
            Arguments:
                duthost : DUT Ansible Host object
                neighbor_type: T0 or T2.
        '''

        pattern = re.compile("{}$".format(neighbor_type))
        ret_list = []

        for intf in minigraph_data['minigraph_neighbors']:
            if pattern.search(
                    minigraph_data['minigraph_neighbors'][intf]['name']):
                ret_list.append(intf)

        return ret_list

    def assign_intf_ip_address(self, selected_interfaces, af):
        '''
            Calculate an ip address for the selected interfaces. It is just a
            mapping. Nothing is configured.
        '''
        intf_ip_map = {}
        for intf in selected_interfaces:
            address = self.get_ip_address(
                af=af, hostid=self.Constants['DUT_HOSTID'], netid=201)
            intf_ip_map[intf] = address
        return intf_ip_map

    @classmethod
    def get_all_interfaces_running_bgp(cls,
                                       duthost,
                                       minigraph_data,
                                       neighbor_type):
        '''
            Analyze the DUT for bgp and return the a structure that have BGP
            neighbors.
        '''
        bgp_neigh_list = duthost.bgp_facts()['ansible_facts']['bgp_neighbors']
        minigraph_ip_interfaces = minigraph_data['minigraph_interfaces'] +\
            minigraph_data['minigraph_portchannel_interfaces']
        peer_addr_map = {}
        pattern = re.compile("{}$".format(neighbor_type))
        for index in minigraph_ip_interfaces:
            peer_addr_map[index['peer_addr']] =\
                {index['attachto']: index['addr']}

        ret_list = {}
        for index, entry in list(peer_addr_map.items()):
            if bgp_neigh_list[index]['state'] == 'established' and \
                    pattern.search(bgp_neigh_list[index]['description']):
                ret_list[index] = entry

        return ret_list

    def configure_vnet_neighbors(self,
                                 duthost,
                                 intf_to_ip_map,
                                 minigraph_data, af):
        '''
            setup the vnet neighbor ip addresses.
        '''
        family = "IPv4"
        if af == "v6":
            family = "IPv6"

        return_dict = {}

        config_list = []
        for intf, addr in list(intf_to_ip_map.items()):
            # If the given address is "net.1", the return address is "net.101"
            # THE ASSUMPTION HERE IS THAT THE DUT ADDRESSES ARE ENDING IN ".1".
            # addr.decode is only in python2.7
            ptf_ip = ""
            if hasattr(addr, 'decode'):
                # python 2.7
                ptf_ip = str(ip_address(addr.decode())+100)
            else:
                # python 3
                ptf_ip = str(ip_address(addr)+100)

            if "Ethernet" in intf:
                return_dict[intf] = ptf_ip
            elif "PortChannel" in intf:
                for member in self.get_ethernet_ports([intf], minigraph_data):
                    return_dict[member] = ptf_ip

            config_list.append('''"{}|{}": {{
                "family": "{}"
            }}'''.format(intf, ptf_ip, family))

        full_config = '''{
            "NEIGH": {
        ''' + ",\n".join(config_list) + '''\n}\n}'''

        self.apply_config_in_dut(duthost, full_config, name="vnet_nbr_"+af)
        return return_dict

    def create_vnets(
            self,
            duthost,
            tunnel_name,
            vnet_count=1,
            scope=None,
            vni_base=10000,
            vnet_name_prefix="Vnet",
            advertise_prefix='false'):
        '''
            Create the required number of vnets.
            duthost          : AnsibleHost data structure of the DUT.
            tunnel_name      : The VxLAN Tunnel name.
            vnet_count       : Number of vnets to configure.
            scope            : The value for "scope" argument in the config.
                               Only "default" is supported. Or it should not
                               be given at all.
            vni_base         : The starting number for VNI.
            vnet_name_prefix : The prefix for the name of vnets.
        '''
        return_dict = {}
        scope_entry = ""
        if scope:
            scope_entry = '''"scope": "{}",\n'''.format(scope)
        config_list = []
        for cnt in range(vnet_count):
            name = vnet_name_prefix + "-" + str(cnt)
            vni = vni_base+cnt
            return_dict[name] = vni
            config_list.append('''"{}": {{
                "vxlan_tunnel": "{}",
                {}"vni": "{}",
                "peer_list": "",
                "advertise_prefix": "{}",
                "overlay_dmac" : "{}"
            }}'''.format(name, tunnel_name, scope_entry, vni, advertise_prefix, self.OVERLAY_DMAC))

            full_config = '{\n"VNET": {' + ",\n".join(config_list) + '\n}\n}'

        self.apply_config_in_dut(duthost, full_config, "vnets_"+tunnel_name)
        return return_dict

    def setup_vnet_intf(self, selected_interfaces, vnet_list, minigraph_data):
        '''
            Setup the interface(or in other words associate the interface to
            a Vnet.  This will remove the ip address from the interfaces.

            selected_interfaces : The list of interfaces we decided to use.
            vnet_list           : The list of vnets to use. The list of vnets
                                  and interfaces should be of same length.
            minigraph_data      : The minigraph_facts data from DUT.
        '''
        if len(selected_interfaces) != len(vnet_list):
            raise RuntimeError(
                "Different number of interfaces and vnets, not supported yet")

        ret_list = {}
        intf_config_list = []
        po_config_list = []
        for count, intf in enumerate(selected_interfaces):
            config = ('''
                    "{}": {{
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

        return ret_list

    def configure_vxlan_switch(self, duthost, vxlan_port=4789, dutmac=None):
        '''
           Configure the VxLAN parameters for the DUT.
           This step is completely optional.

           duthost: AnsibleHost structure of the DUT.
           vxlan_port : The UDP port to be used for VxLAN traffic.
           dutmac     : The mac address to be configured in the DUT.
        '''
        if dutmac is None:
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
        '''
            Apply the given config data in the SWSS container of the DUT.
            duthost: AnsibleHost structure of the DUT.
            config : The config to be applied in the swss container.
            name   : The name of the config file to be created in the DUT.
        '''
        if self.Constants['DEBUG']:
            filename = name + ".json"
        else:
            filename = name + "-" + str(time.time()) + ".json"

        duthost.copy(content=config, dest="/tmp/{}".format(filename))
        duthost.shell(
            'docker exec -i swss swssconfig /dev/stdin < /tmp/{}'.format(
                filename))
        Logger.info("Wait for %s seconds for the config to take effect.",
                    0.0005*getsizeof(config) + 1)
        time.sleep(int(0.0005*getsizeof(config)) + 1)
        if not self.Constants['KEEP_TEMP_FILES']:
            duthost.shell("rm /tmp/{}".format(filename))

    def get_list_of_nexthops(self, number, af, prefix=100):
        '''
            Get a list of IP addresses to be used as nexthops. This creates a
            pool of dummy nexthops.  The other functions can use this pool to
            assign nexthops to different destinations.
            number : Number of addresses we need.
            af     : Address Family (v4 or v6).
            prefix : The first octet to be used for the addresses.
        '''
        nexthop_list = []
        for _ in range(number):
            nexthop_list.append(
                self.get_ip_address(af=af, netid=prefix, hostid=10))
        return nexthop_list

    def create_vnet_routes(
            self,
            duthost,
            vnet_list,
            dest_af,
            nh_af,
            nhs_per_destination=1,
            number_of_available_nexthops=100,
            number_of_ecmp_nhs=1000,
            dest_net_prefix=150,
            nexthop_prefix=100,
            bfd=False):
        '''
            This configures the VNET_TUNNEL_ROUTES structure. It precalculates
            the required number of destinations based on the given
            "number_of_ecmp_nhs" and the "nhs_per_destination".

            inputs:
                number_of_available_nexthops : Total number of unique
                                               NextHops available for use.
                nhs_per_destination          : Number of ECMP nexthops to use
                                               per destination.
                number_of_ecmp_nhs           : Maximum number of all NextHops
                                               put together(for all
                                               destinations).
        '''
        if number_of_available_nexthops < nhs_per_destination:
            raise RuntimeError(
                "The number of available nexthops ip addresses is not enough "
                "to cover even one destination. Pls rerun with "
                "total_number_of_endpoints(%s) > ecmp_nhs_per_destination(%s)",
                number_of_available_nexthops, nhs_per_destination)

        available_nexthops = self.get_list_of_nexthops(
            number=number_of_available_nexthops,
            af=nh_af, prefix=nexthop_prefix)

        number_of_destinations = int(number_of_ecmp_nhs / nhs_per_destination)
        no_of_dests_per_vnet = int(number_of_destinations / len(vnet_list))
        available_nexthop_count = 0
        dest_to_nh_map = {}
        for vnet in vnet_list:
            for _ in range(no_of_dests_per_vnet):
                dest = self.get_ip_address(af=dest_af, netid=dest_net_prefix)
                my_nhs = []
                for _ in range(nhs_per_destination):
                    my_nhs.append(
                        available_nexthops[
                            available_nexthop_count %
                            number_of_available_nexthops])
                    available_nexthop_count = available_nexthop_count + 1
                    if available_nexthop_count > number_of_ecmp_nhs:
                        break

                try:
                    dest_to_nh_map[vnet]
                except KeyError:
                    dest_to_nh_map[vnet] = {}
                dest_to_nh_map[vnet][dest] = my_nhs

        self.set_routes_in_dut(duthost,
                               dest_to_nh_map,
                               dest_af,
                               "SET",
                               bfd=bfd)
        return dest_to_nh_map

    @classmethod
    def get_outer_layer_version(cls, encap_type):
        '''
            Short function to get the outer layer address family from the
            encap type.
        '''
        match = re.search("in_(v[46])", encap_type)
        if match:
            return match.group(1)
        else:
            raise RuntimeError(
                "Invalid format for encap_type:{}".format(encap_type))

    @classmethod
    def get_payload_version(cls, encap_type):
        '''
            Short function to get the inner layer address family from the
            encap type.
        '''
        match = re.search("(v[46])_in_v", encap_type)
        if match:
            return match.group(1)
        else:
            raise RuntimeError(
                "Invalid format for encap_type:{}".format(encap_type))

    def create_and_apply_config(self,
                                duthost,
                                vnet,
                                dest,
                                mask,
                                nhs,
                                op,
                                bfd=False,
                                profile=""):
        '''
            Create a single destinatoin->endpoint list mapping, and configure
            it in the DUT.
            duthost : AnsibleHost structure for the DUT.
            vnet    : Name of the Vnet.
            dest    : IP(v4/v6) address of the destination.
            mask    : Dest netmask length.
            nhs     : Nexthop list(v4/v6).
            op      : Operation to be done : SET or DEL.

        '''
        config = self.create_single_route(vnet, dest, mask, nhs, op, bfd=bfd, profile=profile)
        str_config = '[\n' + config + '\n]'
        self.apply_config_in_swss(duthost, str_config, op + "_vnet_route")

    @classmethod
    def create_single_route(cls, vnet, dest, mask, nhs, op, bfd=False, profile=""):
        '''
            Create a single route entry for vnet, for the given dest, through
            the endpoints:nhs, op:SET/DEL
        '''
        if bfd:
            config = '''{{
            "VNET_ROUTE_TUNNEL_TABLE:{}:{}/{}": {{
                "endpoint": "{}",
                "endpoint_monitor": "{}",
                "profile" : "{}"
            }},
            "OP": "{}"
        }}'''.format(vnet, dest, mask, ",".join(nhs), ",".join(nhs), profile, op)

        else:
            config = '''{{
            "VNET_ROUTE_TUNNEL_TABLE:{}:{}/{}": {{
                "endpoint": "{}",
                "profile" : "{}"
            }},
            "OP": "{}"
        }}'''.format(vnet, dest, mask, ",".join(nhs), profile, op)

        return config

    def get_ip_address(self, af, hostid=1, netid=100):
        '''
            Calculate an ip address from the given arguments.
            af     : Address Family.
            hostid : The last octet.
            netid  : The first octet.
        '''
        third_octet = self.Address_Count % 255
        second_octet = int(self.Address_Count / 255) % 255
        first_octet = netid + int(self.Address_Count / 65025)
        self.Address_Count = self.Address_Count + 1
        if af == 'v4':
            return "{}.{}.{}.{}".format(
                first_octet, second_octet, third_octet, hostid)
        if af == 'v6':
            # :0: gets removed in the IPv6 addresses.
            # Adding "a" to octets, to avoid it.
            return "fddd:a{}:a{}::a{}:{}".format(
                first_octet, second_octet, third_octet, hostid)

    def set_routes_in_dut(self,
                          duthost,
                          dest_to_nh_map,
                          dest_af,
                          op,
                          bfd=False,
                          mask="",
                          profile=""):
        '''
            Configure Vnet routes in the DUT.
            duthost        : AnsibleHost structure for the DUT.
            dest_to_nh_map : The full map of the destination->Nexthops
                             dictionary.
            dest_af        : Address family of the destionation.
            op             : Operation to be done: SET or DEL.
            bfd            : Enable BFD or not (True/False).
        '''
        if mask is "":
            mask = self.HOST_MASK[dest_af]
        config_list = []
        for vnet in dest_to_nh_map:
            for dest in dest_to_nh_map[vnet]:
                config_list.append(self.create_single_route(
                    vnet,
                    dest,
                    mask,
                    dest_to_nh_map[vnet][dest],
                    op,
                    bfd=bfd,
                    profile=profile))

        full_config = '[' + "\n,".join(config_list) + '\n]'
        self.apply_config_in_swss(duthost, full_config, op+"_routes")

    def get_t2_ports(self, duthost, minigraph_data):
        '''
            In T1 topology, any port connected to the T2 BGP neighbors are
            needed. In T0, any port connected to the T1 BGP neighbors are
            needed.
        '''
        portchannels_to_t2 = self.get_portchannels_to_neighbors(
            duthost,
            "T2",
            minigraph_data)
        list_of_interfaces = []
        if portchannels_to_t2:
            for pc_name in portchannels_to_t2:
                list_of_interfaces.extend(portchannels_to_t2[pc_name])
        else:
            list_of_interfaces = self.get_ethernet_to_neighbors(
                "T2", minigraph_data)

        ret_list = []
        for iface in list_of_interfaces:
            ret_list.append(minigraph_data["minigraph_ptf_indices"][iface])
        return ret_list

    @classmethod
    def bgp_established(cls, duthost, down_list=None):
        '''
            Verify if the BGP state is as per our requirements.
            The BGP neighbors that are listed in the down_list must be down,
            and the rest should be up. If this condition is met, return True,
            else False.

            duthost   : AnsibleHost structure of the DUT.
            down_list : The BGP neighbors that are expected to be down.
        '''
        bgp_facts = duthost.bgp_facts()['ansible_facts']
        if down_list is None:
            down_list = []
        for addr, value in list(bgp_facts['bgp_neighbors'].items()):
            if value['state'] == 'established':
                if addr in down_list:
                    # The neighbor is supposed to be down, and is actually up.
                    Logger.info(
                        "Neighbor %s is established, but should be down.",
                        addr)
                    return False
                else:
                    # The neighbor is supposed to be up, and is actually up.
                    continue
            else:
                if addr in down_list:
                    # The neighbor is supposed to be down, and is actually
                    # down.
                    continue
                else:
                    # The neighbor is supposed to be up, but is actually down.
                    Logger.info(
                        "Neighbor %s is not yet established, has state: %s",
                        addr,
                        value['state'])
                    return False

        # Now wait for the routes to be updated.
        time.sleep(30)
        return True

    @classmethod
    def get_downed_bgp_neighbors(cls, shut_intf_list, minigraph_data):
        '''
            Get the list of bgp neighbors that should be down,
            based on the interfaces that are shutdown.
        '''
        ret_list = []
        for intf in shut_intf_list:
            for m_intf in minigraph_data['minigraph_portchannel_interfaces'] +\
                    minigraph_data['minigraph_interfaces']:
                if m_intf['attachto'] == intf:
                    ret_list.append(m_intf['peer_addr'])
        return ret_list

    @classmethod
    def get_all_bgp_neighbors(cls, minigraph_facts, role):
        '''
            Get the list of BGP neighbors from the minigraph_facts.
            minigraph_facts : Minigraph data from the DUT.
            role            :  The role of the BGP neighbor. T0 or T2.
        '''
        all_neighbors = {}
        for element in minigraph_facts['minigraph_bgp']:
            if role in element['name']:
                try:
                    all_neighbors[element['name']]
                except KeyError:
                    all_neighbors[element['name']] = {}
                if ip_address(element['addr']).version == 4:
                    all_neighbors[element['name']].update(
                        {"v4": element['addr']})
                elif ip_address(element['addr']).version == 6:
                    all_neighbors[element['name']].update(
                        {"v6": element['addr']})
        return all_neighbors

    def get_corresponding_ports(self, shut_intf_list, minigraph_data):
        '''
        This is for tests that shutdown some of the T2 ports.
        This function will check which ports are to be ignored for the encap
        packets coming back to the PTF. If the encap packet comes in any of
        these ports, it is a bug.
        '''
        eth_ifaces_list = []
        for intf in shut_intf_list:
            if "Ethernet" in intf:
                eth_ifaces_list.append(intf)
            elif "PortChannel" in intf:
                for port in self.get_ethernet_ports([intf], minigraph_data):
                    eth_ifaces_list.append(port)
        return_list = [minigraph_data["minigraph_ptf_indices"][iface]
                       for iface in eth_ifaces_list]
        return return_list

    def get_ethernet_ports(self, intf_list, minigraph_data):
        '''
            The given interface list can be either Ethernet or Portchannel.
            This function will return a flat list of Ethernet ports
            corresponding to the given intf_list itself, or members of
            Portchannels.
        '''
        ret_list = []
        for intf in intf_list:
            if "Ethernet" in intf:
                ret_list.append(intf)
            elif "PortChannel" in intf:
                ret_list.extend(
                    minigraph_data['minigraph_portchannels'][intf]['members'])

        return ret_list

    def gather_ptf_indices_t2_neighbor(
            self,
            minigraph_facts,
            all_t2_neighbors,
            t2_neighbor,
            encap_type):
        '''
            Get the list of PTF port indices for the given list of
            t2_neighbors.  In T1 topology, every DUT port is mapped to a port
            in the PTF. This function calculates the list of PTF ports that are
            mapped to the given list of t2_neighbors.
            minigraph_facts  : Minigraph data from the Duthost.
            all_t2_neighbors : All T2 neighbors of the DUT.
            t2_neighbor      : The T2 neighbor for which we need the PTF ports.
            encap_type       : Encap type(v4_in_v4/v4_in_v6/v6_in_v4/v6_in_v6)
        '''
        # All T2 Neighbors VM's name to Neighbor IP Mapping
        all_pcs = minigraph_facts['minigraph_portchannel_interfaces']
        # Neighbor IP to Portchannel interfaces mapping
        pc_to_ip_map = {}
        for each_pc in all_pcs:
            pc_to_ip_map[each_pc['peer_addr']] = each_pc['attachto']
        # Finding the portchannel under shutdown T2 Neighbor
        outer_af = self.get_outer_layer_version(encap_type)
        required_pc = \
            pc_to_ip_map[all_t2_neighbors[t2_neighbor][outer_af].lower()]
        # Finding ethernet interfaces under that specific portchannel
        required_ethernet_interfaces = \
            minigraph_facts['minigraph_portchannels'][required_pc]['members']
        # Finding interfaces with PTF indices
        ret_list = []
        for iface in required_ethernet_interfaces:
            ret_list.append(minigraph_facts["minigraph_ptf_indices"][iface])
        return ret_list

    @classmethod
    def start_bfd_responder(cls, ptfhost, dut_mac, dut_loop_ips, monitor_file):
        '''
            Configure the supervisor in the PTF with BFD responder and start
            the BFD responder.
            ptfhost      : AnsibleHost structure of the PTF container.
            t2_ports     : The list of T2 ports(The BFD responder can take any
                           port actually).
            dut_mac      : Mac address of the DUT.
            dut_loop_ips : IPv4 and IPv6 addresses of the Loopback interface
                           in the DUT.
            monitor_file : The file to be monitored by the BFD responder.
        '''
        ptfhost.copy(dest=monitor_file, content="\n\n\n")

        extra_vars = {
            "bfd_responder_args":
                'dut_mac=u"{}";dut_loop_ips={};monitor_file="{}"'.format(
                    dut_mac,
                    str(dut_loop_ips).replace('\'', '"'),
                    monitor_file)}
        try:
            ptfhost.command('supervisorctl stop bfd_responder')
        except BaseException:
            pass

        ptfhost.host.options["variable_manager"].extra_vars.update(extra_vars)
        script_args = \
            '''dut_mac=u"{}";dut_loop_ips={};monitor_file="{}"'''.format(
                dut_mac, str(dut_loop_ips).replace('\'', '"'), monitor_file)
        supervisor_conf_content = '''
[program:bfd_responder]
command=/root/env-python3/bin/ptf --test-dir /root/ptftests/py3 bfd_responder.BFD_Responder''' +\
            ' --platform-dir /root/ptftests -t' + \
            ''' '{}' --relax  --platform remote
process_name=bfd_responder
stdout_logfile=/tmp/bfd_responder.out.log
stderr_logfile=/tmp/bfd_responder.err.log
redirect_stderr=false
autostart=false
autorestart=true
startsecs=1
numprocs=1
'''.format(script_args)
        ptfhost.copy(
            content=supervisor_conf_content,
            dest='/etc/supervisor/conf.d/bfd_responder.conf')

        ptfhost.command('supervisorctl reread')
        ptfhost.command('supervisorctl update')
        ptfhost.command('supervisorctl start bfd_responder')

    @classmethod
    def stop_bfd_responder(cls, ptfhost):
        '''
            Stop the BFD responder, and clean it up from the supervisor.
        '''
        try:
            ptfhost.command('supervisorctl stop bfd_responder')
        except BaseException:
            pass
        ptfhost.command('supervisorctl remove bfd_responder')

    @classmethod
    def update_monitor_file(cls,
                            ptfhost,
                            monitor_file,
                            intf_list,
                            ip_address_list):
        '''
            Update the BFD responder's list of IP addresses and interfaces to
            respond to.  The bfd_responder will keep reading this file every
            second and update itself.
            ptfhost      : AnsibleHost structure of the PTF container.
            monitor_file : The monitor file of the bfd_responder.
            intf_list    : The list of interface indices in the PTF to work
                           with.
            ip_address_list : The list of IP addresses from the DUT to
                              respond to.
        '''
        ptfhost.copy(
            dest=monitor_file,
            content="{}\n{}\n".format(
                ",".join(map(str, intf_list)),
                ",".join(ip_address_list)))
        time.sleep(3)

    def create_and_apply_priority_config(self,
                                         duthost,
                                         vnet,
                                         dest,
                                         mask,
                                         nhs,
                                         primary,
                                         op):
        '''
            Create a single destinatoin->endpoint list mapping, and configure
            it in the DUT.
            duthost : AnsibleHost structure for the DUT.
            vnet    : Name of the Vnet.
            dest    : IP(v4/v6) address of the destination.
            mask    : Dest netmask length.
            nhs     : Nexthop list(v4/v6).
            primary : list of primary endpoints.
            op      : Operation to be done : SET or DEL.

        '''
        config = self.create_single_priority_route(vnet, dest, mask, nhs, primary, op)
        str_config = '[\n' + config + '\n]'
        self.apply_config_in_swss(duthost, str_config, op + "_vnet_route")

    @classmethod
    def create_single_priority_route(cls, vnet, dest, mask, nhs, primary, op):
        '''
            Create a single route entry for vnet, for the given dest, through
            the endpoints:nhs, op:SET/DEL
        '''
        config = '''{{
        "VNET_ROUTE_TUNNEL_TABLE:{}:{}/{}": {{
            "endpoint": "{}",
            "endpoint_monitor": "{}",
            "primary" : "{}",
            "monitoring" : "custom",
            "adv_prefix" : "{}/{}"
        }},
        "OP": "{}"
        }}'''.format(vnet, dest, mask, ",".join(nhs), ",".join(nhs), ",".join(primary), dest, mask, op)
        return config

    def set_vnet_monitor_state(self, duthost, dest, mask, nh, state):
        duthost.shell("sonic-db-cli STATE_DB HSET 'VNET_MONITOR_TABLE|{}|{}/{}' 'state' '{}'"
                      .format(nh, dest, mask, state))
