#!/usr/bin/env python3

'''Converts SONiC topologies to use fewer cEOSLab peers, based on the roles required
in the topology
'''

from copy import deepcopy
from ipaddress import ip_address
from typing import Dict, List, Union
import yaml

CEOSLAB_INTF_LIMIT = 127  # 128, minus one for backplane interface
BASE_VLAN_ID = 2000


class ListIndentDumper(yaml.Dumper):

    def increase_indent(self, flow: bool = False, indentless: bool = False) -> None:
        return super().increase_indent(flow, False)


class SonicTopoConverger:

    def __init__(self, topology: Dict[str, Union[int, str]], file_out: str) -> None:
        self.topo = topology
        self.converged_topo = {
                "topology": {},
                "configuration_properties": {},
                "configuration": {}}
        self.file_out = file_out
        self.prime_device_mapping = {}
        self.prime_devices = []

    def parse_properties(self) -> None:
        '''
        The base configuration items of the topology must be parsed first, as they
        inform how other sections will be translated.  Most important of these items
        is the roles that each cEOSLab docker peer may fulfill.  At minimum we need
        one instance per role.  These instances are referred to as "prime" instances,
        and will contain the converged configuration of all other instances in the
        input topology.
        '''
        labels = []
        roles_by_label = {}
        config_properties = self.topo["configuration_properties"]
        for label in config_properties:
            if "swrole" in config_properties[label]:
                labels.append(label)
                roles_by_label[label] = config_properties[label]["swrole"]

        # Select a prime device for each role (defined above) and unique BGP ASN
        # combination.  The entire peer topology will be reduced into these devices.
        #
        # cEOSLab peers only support 128 interfaces (with LLDP running).  Each
        # pre-converged peer in the topology will become a single BGP instance
        # running inside a VRF on a primary peer device.  Each VRF will require an
        # downstream link to PTF/exabgp instance/other test infrastructure, and an
        # upstream link the DUT.  This is achieved by creating a backplane interface
        # on each primary peer that is a trunk interface, with each VRF
        # containing a backplane SVI.  So, if the pre-converged peer topology
        # requires more than 127 peers in a single BGP AS, we distribute them across
        # multiple primary peers.
        config = self.topo["configuration"]
        cur_prime_devs = {}
        dev_count = 0
        for device in config:
            create_new_prime = False
            device_properties = config[device]["properties"]

            dev_count += 1

            if dev_count == CEOSLAB_INTF_LIMIT:
                create_new_prime = True
                dev_count = 0

            for label in device_properties:
                if label in labels:
                    if label not in cur_prime_devs or create_new_prime:
                        cur_prime_devs[label] = device
                        self.prime_devices.append(device)
                    prime = cur_prime_devs[label]
                    if prime not in self.prime_device_mapping:
                        self.prime_device_mapping[prime] = []
                    self.prime_device_mapping[prime].append(device)

    def converge_vms(self) -> Dict[str, Union[int, str]]:
        '''
        Helper to converge the "VMs" section of the input topology, where vlans and
        offsets are defined, per cEOSLab instance.
        '''
        prime_rev_map = {}
        for key, names in self.prime_device_mapping.items():
            for name in names:
                prime_rev_map[name] = key

        old_vms = self.topo["topology"]["VMs"]
        vms = {}
        for i, dev in enumerate(self.prime_devices):
            vms[dev] = {"vlans": [], "vm_offset": i}

        for vm_name, vm in old_vms.items():
            prime = prime_rev_map[vm_name]
            for vlan in vm["vlans"]:
                vms[prime]["vlans"].append(vlan)

        return vms

    def modify_l3_address(self, address: str, offset: int) -> str:
        delim = ":" if ":" in address else "."
        octets = address.split(delim)
        addr = octets[:-1] + ["0"]
        addr = ip_address(delim.join(addr))
        return str(addr + offset)

    def converge_peers(self,
                       if_index_mapping: Dict[str, List[int]],
                       offset_mapping: Dict[str, int]) -> Dict[str, Union[int, str]]:
        '''
        Helper to converge the section of the input topology where the actual cEOSLab
        instance configuration is laid out.  This is where interface and BGP
        configuration is translated.
        '''
        peers = self.topo["configuration"]
        convergence_data = {}
        new_peers = {}
        bp_addrs = {}
        for dev in self.prime_devices:
            properties = deepcopy(peers[dev]["properties"])
            asn = peers[dev]["bgp"]["asn"]
            new_peers[dev] = {"properties": properties,
                              "vrf": {},
                              "bgp": {"asn": asn},
                              "intf_mapping": {}}

        # Backplane L3 addresses are laid out for clarity-- addresses with odd
        # least-signifcant octets or hextets are assigned to the interfaces of the
        # PTF container, and those with even least-signifcant octets or hextets are
        # assigned to the cEOSLab containers.  The addresses alternate.  We start at
        # 100 as the IPv4 addresses used for backplane connections in most of the
        # testbed topology files used with this conversion script lie in that range.
        # We use a similar range for IPv6 for simplicity.
        peer_bp_addr_offset = 100
        ptf_bp_addr_offset = 101
        base_v4_addr = "10.10.246.0"
        base_v6_addr = "fc0a::"
        for prime_dev, peer_list in self.prime_device_mapping.items():
            intf_counter_base = 1
            eth_intf_index = 1
            offset = 0
            for i, peer_name in enumerate(peer_list):
                #  For simplicity, VRFs are just peer names.
                vlan_id = BASE_VLAN_ID + offset_mapping[peer_name]
                peer = peers[peer_name]
                vrf_name = peer_name
                peer_intfs = peer["interfaces"]
                orig_intf_map = {}

                intf_index = i + intf_counter_base
                vrf = {f"Vlan{vlan_id}": {}}

                for intf in peer_intfs:
                    if "Ethernet" not in intf:
                        continue
                    eth_intf = f"Ethernet{eth_intf_index}"
                    vrf[eth_intf] = deepcopy(peer_intfs[intf])
                    orig_intf_map[intf] = eth_intf
                    eth_intf_index += 1

                if "Port-Channel1" in peer_intfs:
                    po_intf = f"Port-Channel{intf_index}"
                    orig_intf_map["Port-Channel1"] = po_intf
                    vrf[po_intf] = deepcopy(peer_intfs["Port-Channel1"])
                if "Loopback0" in peer_intfs:
                    lo_intf = f"Loopback{intf_index}"
                    orig_intf_map["Loopback0"] = lo_intf
                    vrf[lo_intf] = deepcopy(peer_intfs["Loopback0"])

                new_peers[prime_dev]["vrf"][vrf_name] = vrf

                bp_addr_data = {}
                v4_addr = peer["bp_interface"].get("ipv4", "10.10.246.0")
                if "ipv4" in peer["bp_interface"]:
                    bp_addr_data["ipv4"] = f"{self.modify_l3_address(base_v4_addr, ptf_bp_addr_offset)}/31"
                    vrf[f"Vlan{vlan_id}"]["ipv4"] = f"{self.modify_l3_address(base_v4_addr, peer_bp_addr_offset)}/31"
                if "ipv6" in peer["bp_interface"]:
                    bp_addr_data["ipv6"] = f"{self.modify_l3_address(base_v6_addr, ptf_bp_addr_offset)}/127"
                    bp_addr_data["router-id"] = f"{self.modify_l3_address(base_v4_addr, ptf_bp_addr_offset)}"
                    vrf[f"Vlan{vlan_id}"]["ipv6"] = f"{self.modify_l3_address(base_v6_addr, peer_bp_addr_offset)}/127"
                if bp_addr_data:
                    bp_addr_data["vlan"] = vlan_id
                    bp_addrs[peer_name] = bp_addr_data

                if not new_peers[prime_dev]["intf_mapping"]:
                    # If we are filling in a prime_dev for the first time, reset the offset
                    offset = 0
                new_peers[prime_dev]["intf_mapping"][vrf_name] = {"offset": offset, "orig_intf_map": orig_intf_map}
                offset += 1
                peer_bp_addr_offset += 2
                ptf_bp_addr_offset += 2

        convergence_data["converged_peers"] = new_peers
        convergence_data["convergence_mapping"] = deepcopy(self.prime_device_mapping)
        convergence_data["interface_index_mapping"] = if_index_mapping
        convergence_data["vm_offset_mapping"] = offset_mapping
        if bp_addrs:
            convergence_data["ptf_backplane_addrs"] = bp_addrs
        return convergence_data

    def converge_topo(self) -> None:
        '''
        Converge the read DUT/cEOSLab topology into the fewest cEOSLab docker
        instances as possible.  The number of containers is based on the roles
        required by the topology

        i.e. a topology with the "tor" and "spine" roles defined with be converged to
        use two cEOSLab docker instances, one per role.
        '''
        new_topo = self.converged_topo["topology"]
        old_topo = self.topo["topology"]

        self.converged_topo["topo_is_multi_vrf"] = True

        # We don't need to change the host_interfaces portion of the passed topo, so
        # copy it over as is.
        key = "host_interfaces"
        if key in old_topo:
            new_topo[key] = old_topo[key].copy()

        key = "VMs"
        # Save off which vm had which interface index as we will need this later
        interface_indexes = {}
        offsets = {}
        for vm, data in self.topo["topology"]["VMs"].items():
            interface_indexes[vm] = data["vlans"]
            offsets[vm] = data["vm_offset"]
        vms = self.converge_vms()
        new_topo[key] = vms

        # The DUT configuration and general configuration properties should be
        # unchanged as well.
        key = "DUT"
        if key in old_topo:
            new_topo[key] = old_topo[key].copy()

        new_topo = self.converged_topo
        old_topo = self.topo
        key = "configuration_properties"
        new_topo[key] = old_topo[key].copy()

        # convergence metadata
        key = "configuration"
        new_topo[key] = old_topo[key].copy()
        new_topo["convergence_data"] = self.converge_peers(interface_indexes, offsets)

    def run(self) -> None:
        self.parse_properties()
        self.converge_topo()
        with open(self.file_out, "w", encoding="utf-8") as out_file:
            yaml.dump(self.converged_topo, out_file,
                      Dumper=ListIndentDumper, sort_keys=False)


def converge_testbed(input_file: str, output_file: str) -> None:
    with open(input_file, "r", encoding="utf-8") as in_file:
        topo = yaml.safe_load(in_file)
    converger = SonicTopoConverger(topo, output_file)
    converger.run()
