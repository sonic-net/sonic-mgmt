#!/usr/bin/env python
import os
import traceback
import ipaddress
import sys
import yaml
import re
from ansible.module_utils.basic import AnsibleModule

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
        m = re.match(r"(\d+)\.(\d+)@(\d+)", vlan)
        (dut_index, vlan_index, ptf_index) = (
            int(m.group(1)), int(m.group(2)), int(m.group(3)))

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
        # (dut_index, vlan_index) or (dut_index, vlan_index, ptf_port_index)
        ret.append(indices)

    return ret


def parse_console_interface(console_interface):
    """
    parse console interface

    Foramt:
    line_number.baud.flow_control_option

    Example:
    27.9600.0
    """
    fields = console_interface.split('.')
    return fields[0], fields[1], fields[2]


class ParseTestbedTopoinfo():
    '''
    Parse topology yml file
    '''

    def __init__(self):
        self.vm_topo_config = {}
        self.asic_topo_config = {}

    def parse_topo_defintion(self, topo_definition, po_map, dut_num, neigh_type='VMs'):
        vmconfig = dict()
        if topo_definition['topology'][neigh_type] is None:
            return vmconfig
        for vm in topo_definition['topology'][neigh_type]:
            vmconfig[vm] = dict()
            vmconfig[vm]['intfs'] = [[] for i in range(dut_num)]
            if 'properties' in vmconfig[vm]:
                # expand properties list into properties dictinary
                property_lst = topo_definition['configuration'][vm]['properties']
                vmconfig[vm]['properties'] = {}
                for p in property_lst:
                    if p in topo_definition['configuration_properties']:
                        vmconfig[vm]['properties'].update(
                            topo_definition['configuration_properties'][p])
            if neigh_type == 'VMs':
                vmconfig[vm]['interface_indexes'] = [[]
                                                     for i in range(dut_num)]
                for vlan in topo_definition['topology'][neigh_type][vm]['vlans']:
                    (dut_index, vlan_index, _) = parse_vm_vlan_port(vlan)
                    vmconfig[vm]['interface_indexes'][dut_index].append(
                        vlan_index)
            if neigh_type == 'NEIGH_ASIC':
                vmconfig[vm]['asic_intfs'] = [[] for i in range(dut_num)]
                dut_index = 0
                for asic_intf in topo_definition['topology'][neigh_type][vm]['asic_intfs']:
                    vmconfig[vm]['asic_intfs'][dut_index].append(asic_intf)

            # physical interface
            if 'configuration' in topo_definition:
                if 'interfaces' in topo_definition['configuration'][vm]:
                    for intf in topo_definition['configuration'][vm]['interfaces']:
                        dut_index = 0
                        if neigh_type == 'NEIGH_ASIC' and re.match(r"Eth(\d+)-", intf):
                            vmconfig[vm]['intfs'][dut_index].append(intf)
                        elif 'Ethernet' in intf:
                            if 'dut_index' in topo_definition['configuration'][vm]['interfaces'][intf]:
                                dut_index = topo_definition['configuration'][vm]['interfaces'][intf]['dut_index']
                            if 'lacp' in topo_definition['configuration'][vm]['interfaces'][intf]:
                                po_map[topo_definition['configuration'][vm]
                                       ['interfaces'][intf]['lacp']] = dut_index
                            vmconfig[vm]['intfs'][dut_index].append(intf)

            # ip interface
            vmconfig[vm]['ip_intf'] = [None] * dut_num
            vmconfig[vm]['peer_ipv4'] = [None] * dut_num
            vmconfig[vm]['ipv4mask'] = [None] * dut_num
            vmconfig[vm]['peer_ipv6'] = [None] * dut_num
            vmconfig[vm]['ipv6mask'] = [None] * dut_num
            vmconfig[vm]['bgp_ipv4'] = [None] * dut_num
            vmconfig[vm]['bgp_ipv6'] = [None] * dut_num
            vmconfig[vm]['bgp_asn'] = None

            if 'configuration' in topo_definition:
                if 'interfaces' in topo_definition['configuration'][vm]:
                    for intf in topo_definition['configuration'][vm]['interfaces']:
                        dut_index = 0
                        if neigh_type == 'NEIGH_ASIC':
                            pass
                        elif 'Ethernet' in intf:
                            if 'dut_index' in topo_definition['configuration'][vm]['interfaces'][intf]:
                                dut_index = topo_definition['configuration'][vm]['interfaces'][intf]['dut_index']
                        elif 'Port-Channel' in intf:
                            m = re.search(r"(\d+)", intf)
                            dut_index = po_map[int(m.group(1))]

                        if (isinstance(topo_definition['configuration'][vm]['interfaces'], dict)
                                and 'ipv4' in topo_definition['configuration'][vm]['interfaces'][intf]
                                and ('loopback' not in intf.lower())):
                            (peer_ipv4, ipv4_mask) = \
                                topo_definition['configuration'][vm]['interfaces'][intf]['ipv4'].split(
                                    '/')
                            vmconfig[vm]['peer_ipv4'][dut_index] = peer_ipv4
                            vmconfig[vm]['ipv4mask'][dut_index] = ipv4_mask
                            vmconfig[vm]['ip_intf'][dut_index] = intf
                        if (isinstance(topo_definition['configuration'][vm]['interfaces'], dict)
                                and 'ipv6' in topo_definition['configuration'][vm]['interfaces'][intf]
                                and ('loopback' not in intf.lower())):
                            (ipv6_addr, ipv6_mask) = \
                                topo_definition['configuration'][vm]['interfaces'][intf]['ipv6'].split(
                                    '/')
                            vmconfig[vm]['peer_ipv6'][dut_index] = ipv6_addr.upper()
                            vmconfig[vm]['ipv6mask'][dut_index] = ipv6_mask
                            vmconfig[vm]['ip_intf'][dut_index] = intf

                # Configuration is provided via cfg_file_loc, no need to go through the topo file
                if "cfg_file_loc" in topo_definition['configuration'][vm]:
                    continue

                # bgp 
                vmconfig[vm]['bgp_asn'] = topo_definition['configuration'][vm]['bgp']['asn']
                dut_asn = topo_definition['configuration_properties']['common']['dut_asn']
                for ipstr in topo_definition['configuration'][vm]['bgp']['peers'][dut_asn]:
                    ip_mask = None
                    if '/' in ipstr:
                        (ipstr, ip_mask) = ipstr.split('/')
                    if sys.version_info < (3, 0):
                        ip = ipaddress.ip_address(ipstr.decode('utf8'))
                    else:
                        ip = ipaddress.ip_address(ipstr)
                    for dut_index in range(0, dut_num):
                        if ip.version == 4:
                            # Each VM might not be connected to all the DUT's,
                            # so check if this VM is a peer to DUT at dut_index
                            if vmconfig[vm]['peer_ipv4'][dut_index]:
                                ipsubnet_str = \
                                    vmconfig[vm]['peer_ipv4'][dut_index] + \
                                    '/'+vmconfig[vm]['ipv4mask'][dut_index]
                                if sys.version_info < (3, 0):
                                    ipsubnet = ipaddress.ip_interface(
                                        ipsubnet_str.decode('utf8'))
                                else:
                                    ipsubnet = ipaddress.ip_interface(
                                        ipsubnet_str)
                                if ip in ipsubnet.network:
                                    vmconfig[vm]['bgp_ipv4'][dut_index] = ipstr.upper()
                            elif neigh_type == "NEIGH_ASIC":
                                vmconfig[vm]['bgp_ipv4'][dut_index] = ipstr.upper()
                                vmconfig[vm]['ipv4mask'][dut_index] = ip_mask if ip_mask else '32'
                        elif ip.version == 6:
                            # Each VM might not be connected to all the DUT's,
                            # so check if this VM is a peer to DUT at dut_index
                            if vmconfig[vm]['peer_ipv6'][dut_index]:
                                ipsubnet_str = \
                                    vmconfig[vm]['peer_ipv6'][dut_index] + \
                                    '/'+vmconfig[vm]['ipv6mask'][dut_index]
                                if sys.version_info < (3, 0):
                                    ipsubnet = ipaddress.ip_interface(
                                        ipsubnet_str.decode('utf8'))
                                else:
                                    ipsubnet = ipaddress.ip_interface(
                                        ipsubnet_str)
                                if ip in ipsubnet.network:
                                    vmconfig[vm]['bgp_ipv6'][dut_index] = ipstr.upper()
                            elif neigh_type == "NEIGH_ASIC":
                                vmconfig[vm]['bgp_ipv6'][dut_index] = ipstr.upper()
                                vmconfig[vm]['ipv6mask'][dut_index] = ip_mask if ip_mask else '128'
        return vmconfig

    def get_topo_config(self, topo_name, hwsku, testbed_name, asics_present, card_type):
        CLET_SUFFIX = "-clet"

        if 'ptf32' in topo_name:
            topo_name = 't1'
        if 'ptf64' in topo_name:
            topo_name = 't1-64'
        topo_name = re.sub(CLET_SUFFIX + "$", "", topo_name)
        topo_filename = 'vars/topo_' + topo_name + '.yml'

        asic_topo_file_candidate_list = []

        if testbed_name:
            asic_topo_file_candidate_list.append(
                'vars/' + testbed_name + '/topo_' + hwsku + '.yml')
        asic_topo_file_candidate_list.append('vars/topo_' + hwsku + '.yml')
        vm_topo_config = dict()
        vm_topo_config['topo_type'] = None
        asic_topo_config = dict()
        po_map = [None] * 16   # maximum 16 port channel interfaces

        asic_topo_filename = None
        for asic_topo_file_path in asic_topo_file_candidate_list:
            if os.path.isfile(asic_topo_file_path):
                asic_topo_filename = asic_topo_file_path
                break

        # read topology definition
        if not os.path.isfile(topo_filename):
            raise Exception(
                "cannot find topology definition file under vars/topo_%s.yml file!" % topo_name)
        else:
            with open(topo_filename) as f:
                topo_definition = yaml.safe_load(f)

        if not asic_topo_filename:
            slot_definition = {}
        else:
            with open(asic_topo_filename) as f:
                slot_definition = yaml.safe_load(f)

        # parse topo file specified in vars/ to reverse as dut config
        dut_num = 1
        if 'dut_num' in topo_definition['topology']:
            dut_num = topo_definition['topology']['dut_num']
        vm_topo_config['dut_num'] = dut_num

        if 'topo_type' in topo_definition['topology']:
            vm_topo_config['topo_type'] = topo_definition['topology']['topo_type']

        if 'VMs' in topo_definition['topology']:
            dut_asn = topo_definition['configuration_properties']['common']['dut_asn']
            vm_topo_config['dut_asn'] = dut_asn
            vm_topo_config['dut_type'] = topo_definition['configuration_properties']['common']['dut_type']
            if 'dut_cluster' in topo_definition['configuration_properties']['common']:
                vm_topo_config['dut_cluster'] = topo_definition['configuration_properties']['common']['dut_cluster']
            vm_topo_config['vm'] = self.parse_topo_defintion(
                topo_definition, po_map, dut_num, 'VMs')

        if 'cable' in topo_name:
            dut_asn = topo_definition['configuration_properties']['common']['dut_asn']
            vm_topo_config['dut_type'] = topo_definition['configuration_properties']['common']['dut_type']
            vm_topo_config['dut_asn'] = dut_asn

        if hwsku == 'Cisco-8111-O64':
            if 't1' in topo_name:
                vm_topo_config['dut_type'] = "BackEndLeafRouter"
            elif 't0' in topo_name:
                vm_topo_config['dut_type'] = "BackEndToRRouter"

        for slot, asic_definition in slot_definition.items():
            asic_topo_config[slot] = dict()
            for asic in asic_definition:
                # maximum 16 port channel interfaces
                po_map_asic = [None] * 16
                asic_topo_config[slot][asic] = dict()
                asic_topo_config[slot][asic]['asic_type'] = \
                    asic_definition[asic]['configuration_properties']['common']['asic_type']
                asic_topo_config[slot][asic]['neigh_asic'] = \
                    self.parse_topo_defintion(
                        asic_definition[asic], po_map_asic, 1, 'NEIGH_ASIC')

        vm_topo_config['host_interfaces_by_dut'] = [[] for i in range(dut_num)]
        if 'host_interfaces' in topo_definition['topology']:
            vm_topo_config['host_interfaces'] = topo_definition['topology']['host_interfaces']
            for host_if in topo_definition['topology']['host_interfaces']:
                hifs = parse_host_interfaces(host_if)
                for hif in hifs:
                    vm_topo_config['host_interfaces_by_dut'][hif[0]].append(
                        hif[1])

        vm_topo_config['disabled_host_interfaces_by_dut'] = [[]
                                                             for i in range(dut_num)]
        if 'disabled_host_interfaces' in topo_definition['topology']:
            vm_topo_config['disabled_host_interfaces'] = topo_definition['topology']['disabled_host_interfaces']
            for host_if in topo_definition['topology']['disabled_host_interfaces']:
                hifs = parse_host_interfaces(host_if)
                for hif in hifs:
                    vm_topo_config['disabled_host_interfaces_by_dut'][hif[0]].append(
                        hif[1])

        if 'console_interfaces' in topo_definition['topology']:
            vm_topo_config['console_interfaces'] = []
            for console_if in topo_definition['topology']['console_interfaces']:
                line, baud, flow_control = parse_console_interface(console_if)
                cif = {}
                cif['line'] = int(line)
                cif['baud'] = int(baud)
                cif['flow_control'] = 'true' if flow_control == '1' else 'false'
                vm_topo_config['console_interfaces'].append(cif)

        if 'DUT' in topo_definition['topology']:
            vm_topo_config['DUT'] = topo_definition['topology']['DUT']
        else:
            vm_topo_config['DUT'] = {}

        if 'devices_interconnect_interfaces' in topo_definition['topology']:
            vm_topo_config['devices_interconnect_interfaces'] = \
                topo_definition['topology']['devices_interconnect_interfaces']
        else:
            vm_topo_config['devices_interconnect_interfaces'] = []

        if 'wan_dut_configuration' in topo_definition:
            vm_topo_config['wan_dut_configuration'] = [None]*dut_num
            for _, v in topo_definition['wan_dut_configuration'].items():
                vm_topo_config['wan_dut_configuration'][v['dut_offset']] = v

        #  In linecard, keep neigh_asic information to only asics_present on supervisor
        if card_type != 'supervisor' and asics_present:
            asic_names_present = []
            for asic in asics_present:
                asic_name = 'ASIC' + str(asic)
                asic_names_present.append(asic_name)
            for slot in asic_topo_config:
                for asic in asic_topo_config[slot]:
                    for neigh_asic in asic_topo_config[slot][asic]['neigh_asic'].keys():
                        if neigh_asic not in asic_names_present:
                            # If neigh_asic is not part of asics_present, delete it.
                            del asic_topo_config[slot][asic]['neigh_asic'][neigh_asic]

        self.vm_topo_config = vm_topo_config
        self.asic_topo_config = asic_topo_config
        return vm_topo_config, asic_topo_config


def main():
    module = AnsibleModule(
        argument_spec=dict(
            topo=dict(required=True, default=None),
            hwsku=dict(required=True, default=None),
            testbed_name=dict(required=True, default=None),
            asics_present=dict(type='list', required=True, default=None),
            card_type=dict(required=True, default=None),
        ),
        supports_check_mode=True
    )
    m_args = module.params
    topo_name = m_args['topo']
    hwsku = m_args['hwsku']
    testbed_name = m_args['testbed_name']
    asics_present = m_args['asics_present']
    card_type = m_args['card_type']
    try:
        topoinfo = ParseTestbedTopoinfo()
        vm_topo_config, asic_topo_config = topoinfo.get_topo_config(topo_name, hwsku, testbed_name,
                                                                    asics_present, card_type)
        module.exit_json(ansible_facts={'vm_topo_config': vm_topo_config,
                                        'asic_topo_config': asic_topo_config})
    except (IOError, OSError):
        module.fail_json(msg="Can not find topo file for %s" % topo_name)
    except Exception:
        module.fail_json(msg=traceback.format_exc())


if __name__ == "__main__":
    main()
