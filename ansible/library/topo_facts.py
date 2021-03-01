#!/usr/bin/env python
import os
import traceback
import ipaddress
import csv
from operator import itemgetter
from itertools import groupby
import yaml
import re

DOCUMENTATION = '''
module: topo_facts.py
version_added:  2.0.0.2
short_description: get topology information
options:
    - topo:
      Description: the topology name
      Default: None
      required: True
'''

def parse_vm_vlan_port(vlan):
    """
    parse vm vlan port

    old format (non multi-dut): vlan_index
    new format (multi-dut):     dut_index.vlan_index@ptf_index

    """
    if isinstance(vlan, int):
        dut_index = 0
        vlan_index = vlan
        ptf_index = vlan
    else:
        m = re.match("(\d+)\.(\d+)@(\d+)", vlan)
        (dut_index, vlan_index, ptf_index) = (int(m.group(1)), int(m.group(2)), int(m.group(3)))

    return (dut_index, vlan_index, ptf_index)

def parse_host_interfaces(hifs):
    """
    parse host interfaces

    Support 3 formats:
    1. Legacy format (non multi-dut): vlan_index
    2. new format (multi-dut): dut_index.vlan_index,dut_index.vlan_index
    3. new format (multi-dut): dut_index.vlan_index@ptf_port_index,dut_index.vlan_index@ptf_port_index
    """

    if isinstance(hifs, int):
        dut_index = 0
        vlan_index = int(hifs)

        return [(dut_index, vlan_index)]

    ret = []
    for hif in hifs.split(','):
        indices = tuple([int(x) for x in re.split(r'\.|@', hif.strip())])
        ret.append(indices)   # (dut_index, vlan_index) or (dut_index, vlan_index, ptf_port_index)

    return ret

class ParseTestbedTopoinfo():
    '''
    Parse topology yml file
    '''
    def __init__(self):
        self.vm_topo_config = {}
        self.asic_topo_config = {}

    def parse_topo_defintion(self, topo_definition, po_map, dut_num, type='VMs'):
        dut_asn = topo_definition['configuration_properties']['common']['dut_asn']
        vmconfig = dict()
        for vm in topo_definition['topology'][type]:
            vmconfig[vm] = dict()
            vmconfig[vm]['intfs'] = [[] for i in range(dut_num)]
            if 'properties' in vmconfig[vm]:
                vmconfig[vm]['properties']=topo_definition['configuration'][vm]['properties']
            if type == 'VMs':
                vmconfig[vm]['interface_indexes'] = [[] for i in range(dut_num)]
                for vlan in topo_definition['topology'][type][vm]['vlans']:
                    (dut_index, vlan_index, _) = parse_vm_vlan_port(vlan)
                    vmconfig[vm]['interface_indexes'][dut_index].append(vlan_index)
            if type == 'NEIGH_ASIC':
                vmconfig[vm]['asic_intfs'] = [[] for i in range(dut_num)]
                dut_index = 0
                for asic_intf in topo_definition['topology'][type][vm]['asic_intfs']:
                    vmconfig[vm]['asic_intfs'][dut_index].append(asic_intf)
        
            # physical interface
            for intf in topo_definition['configuration'][vm]['interfaces']:
                if (type == 'VMs' and 'Ethernet' in intf) or \
                   (type == 'NEIGH_ASIC' and re.match("Eth(\d+)-", intf)):
                    dut_index = 0
                    if 'dut_index' in topo_definition['configuration'][vm]['interfaces'][intf]:
                        dut_index = topo_definition['configuration'][vm]['interfaces'][intf]['dut_index']
                    if 'lacp' in topo_definition['configuration'][vm]['interfaces'][intf]:
                        po_map[topo_definition['configuration'][vm]['interfaces'][intf]['lacp']] = dut_index
        
                    vmconfig[vm]['intfs'][dut_index].append(intf)
        
            # ip interface
            vmconfig[vm]['ip_intf'] = [None] * dut_num
            vmconfig[vm]['peer_ipv4'] = [None] * dut_num
            vmconfig[vm]['ipv4mask'] = [None] * dut_num
            vmconfig[vm]['peer_ipv6'] = [None] * dut_num
            vmconfig[vm]['ipv6mask'] = [None] * dut_num
        
        
            for intf in topo_definition['configuration'][vm]['interfaces']:
                dut_index = 0
                if (type == 'VMs' and 'Ethernet' in intf) or \
                   (type == 'NEIGH_ASIC' and re.match("Eth(\d+)-", intf)):
                    if 'dut_index' in topo_definition['configuration'][vm]['interfaces'][intf]:
                        dut_index = topo_definition['configuration'][vm]['interfaces'][intf]['dut_index']
                elif 'Port-Channel' in intf:
                    m = re.search("(\d+)", intf)
                    dut_index = po_map[int(m.group(1))]
        
                if 'ipv4' in topo_definition['configuration'][vm]['interfaces'][intf] and ('loopback' not in intf.lower()):
                    (peer_ipv4, ipv4_mask) = topo_definition['configuration'][vm]['interfaces'][intf]['ipv4'].split('/')
                    vmconfig[vm]['peer_ipv4'][dut_index] = peer_ipv4
                    vmconfig[vm]['ipv4mask'][dut_index] = ipv4_mask
                    vmconfig[vm]['ip_intf'][dut_index] = intf
                if 'ipv6' in topo_definition['configuration'][vm]['interfaces'][intf] and ('loopback' not in intf.lower()):
                    (ipv6_addr, ipv6_mask) = topo_definition['configuration'][vm]['interfaces'][intf]['ipv6'].split('/')
                    vmconfig[vm]['peer_ipv6'][dut_index] = ipv6_addr.upper()
                    vmconfig[vm]['ipv6mask'][dut_index] = ipv6_mask
                    vmconfig[vm]['ip_intf'][dut_index] = intf
        
            # bgp
            vmconfig[vm]['bgp_ipv4'] = [None] * dut_num
            vmconfig[vm]['bgp_ipv6'] = [None] * dut_num
            vmconfig[vm]['bgp_asn'] = topo_definition['configuration'][vm]['bgp']['asn']
            for ipstr in topo_definition['configuration'][vm]['bgp']['peers'][dut_asn]:
                ip = ipaddress.ip_address(ipstr.decode('utf8'))
                for dut_index in range(0, dut_num):
                    if ip.version == 4:
                        # Each VM might not be connected to all the DUT's, so check if this VM is a peer to DUT at dut_index
                        if vmconfig[vm]['peer_ipv4'][dut_index]:
                            ipsubnet_str = vmconfig[vm]['peer_ipv4'][dut_index]+'/'+vmconfig[vm]['ipv4mask'][dut_index]
                            ipsubnet = ipaddress.ip_interface(ipsubnet_str.decode('utf8'))
                            if ip in ipsubnet.network:
                                vmconfig[vm]['bgp_ipv4'][dut_index] = ipstr.upper()
                    elif ip.version == 6:
                        # Each VM might not be connected to all the DUT's, so check if this VM is a peer to DUT at dut_index
                        if vmconfig[vm]['peer_ipv6'][dut_index]:
                            ipsubnet_str = vmconfig[vm]['peer_ipv6'][dut_index]+'/'+vmconfig[vm]['ipv6mask'][dut_index]
                            ipsubnet = ipaddress.ip_interface(ipsubnet_str.decode('utf8'))
                            if ip in ipsubnet.network:
                                vmconfig[vm]['bgp_ipv6'][dut_index] = ipstr.upper()
        return vmconfig

    def get_topo_config(self, topo_name, hwsku):
        CLET_SUFFIX = "-clet"

        if 'ptf32' in topo_name:
            topo_name = 't1'
        if 'ptf64' in topo_name:
            topo_name = 't1-64'
        topo_name = re.sub(CLET_SUFFIX + "$", "", topo_name)
        topo_filename = 'vars/topo_' + topo_name + '.yml'
        asic_topo_filename = 'vars/topo_' + hwsku + '.yml'
        vm_topo_config = dict()
        asic_topo_config = dict()
        po_map = [None] * 16   # maximum 16 port channel interfaces

        ### read topology definition
        if not os.path.isfile(topo_filename):
            raise Exception("cannot find topology definition file under vars/topo_%s.yml file!" % topo_name)
        else:
            with open(topo_filename) as f:
                topo_definition = yaml.load(f)

        if not os.path.isfile(asic_topo_filename):
            asic_definition = {}
        else:
            with open(asic_topo_filename) as f:
                asic_definition = yaml.load(f)

        ### parse topo file specified in vars/ to reverse as dut config
        dut_num = 1
        if 'dut_num' in topo_definition['topology']:
            dut_num = topo_definition['topology']['dut_num']
        vm_topo_config['dut_num'] = dut_num

        if 'VMs' in topo_definition['topology']:
            dut_asn = topo_definition['configuration_properties']['common']['dut_asn']
            vm_topo_config['dut_asn'] = dut_asn
            vm_topo_config['dut_type'] = topo_definition['configuration_properties']['common']['dut_type']
            vm_topo_config['vm'] = self.parse_topo_defintion(topo_definition, po_map, dut_num, 'VMs')

        for asic in asic_definition:
            po_map_asic = [None] * 16   # maximum 16 port channel interfaces
            asic_topo_config[asic] = dict()
            asic_topo_config[asic]['dut_asn'] = asic_definition[asic]['configuration_properties']['common']['dut_asn']
            asic_topo_config[asic]['asic_type'] = asic_definition[asic]['configuration_properties']['common']['asic_type']
            asic_topo_config[asic]['Loopback4096'] = []
            for lo4096 in asic_definition[asic]['configuration_properties']['common']['Loopback4096']:
                asic_topo_config[asic]['Loopback4096'].append(lo4096)

            asic_topo_config[asic]['neigh_asic'] = self.parse_topo_defintion(asic_definition[asic], po_map_asic, 1, 'NEIGH_ASIC')

        vm_topo_config['host_interfaces_by_dut'] = [[] for i in range(dut_num)]
        if 'host_interfaces' in topo_definition['topology']:
            vm_topo_config['host_interfaces'] = topo_definition['topology']['host_interfaces']
            for host_if in topo_definition['topology']['host_interfaces']:
                hifs = parse_host_interfaces(host_if)
                for hif in hifs:
                    vm_topo_config['host_interfaces_by_dut'][hif[0]].append(hif[1])

        vm_topo_config['disabled_host_interfaces_by_dut'] = [[] for i in range(dut_num)]
        if 'disabled_host_interfaces' in topo_definition['topology']:
            vm_topo_config['disabled_host_interfaces'] = topo_definition['topology']['disabled_host_interfaces']
            for host_if in topo_definition['topology']['disabled_host_interfaces']:
                hifs = parse_host_interfaces(host_if)
                for hif in hifs:
                    vm_topo_config['disabled_host_interfaces_by_dut'][hif[0]].append(hif[1])

        if 'DUT' in topo_definition['topology']:
            vm_topo_config['DUT'] = topo_definition['topology']['DUT']
        else:
            vm_topo_config['DUT'] = {}

        self.vm_topo_config = vm_topo_config
        self.asic_topo_config = asic_topo_config
        return vm_topo_config, asic_topo_config


def main():
    module = AnsibleModule(
        argument_spec=dict(
            topo=dict(required=True, default=None),
            hwsku=dict(required=True, default=None),
        ),
        supports_check_mode=True
    )
    m_args = module.params
    topo_name = m_args['topo']
    hwsku = m_args['hwsku']
    try:
        topoinfo = ParseTestbedTopoinfo()
        vm_topo_config, asic_topo_config = topoinfo.get_topo_config(topo_name, hwsku)
        module.exit_json(ansible_facts={'vm_topo_config': vm_topo_config,
                                        'asic_topo_config': asic_topo_config})
    except (IOError, OSError):
        module.fail_json(msg="Can not find topo file for %s" % topo_name)
    except Exception as e:
        module.fail_json(msg=traceback.format_exc())

from ansible.module_utils.basic import *
if __name__== "__main__":
    main()
