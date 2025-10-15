import pytest
import yaml
from spytest import st, tgapi, SpyTestDict
import re, time
import apis.system.logging as logapi
import apis.routing.bgp as bgpapi
import os
import json
import paramiko
from scp import SCPClient
import ipaddress
import natsort
import apis.routing.ip as ip_obj
import apis.routing.vrf as vrf_obj
import apis.switching.vlan as vlan_obj
import sys
import importlib
import utilities.utils as utils_obj
import threading

def get_cfg_file():
    pattern = r'/([^/.]+)\.py'
    for item in sys.argv:
        match = re.search(pattern, item)
        if match:
            result = match.group(1)
            break
    my_lib = importlib.import_module(result)
    return my_lib.CONFIGS_FILE

config_dict = {}
def get_cfg_dict():

    global config_dict
    if not config_dict:
        CONFIGS_FILE = get_cfg_file()
        dir_path = os.path.dirname(os.path.realpath(__file__))
        with open(dir_path + '/' + CONFIGS_FILE) as f:
            config_dict = yaml.load(f, Loader=yaml.FullLoader)

    config_dict['nodes'] = {'leaf': [], 'spine': [], 'all': [], 'l2l3vni': []}
    for node , node_cfg in config_dict.items():
        if node.startswith('leaf'):
            config_dict['nodes']['leaf'].append(node)
            config_dict['nodes']['all'].append(node)
        elif node.startswith('spine'):
            config_dict['nodes']['spine'].append(node)
            config_dict['nodes']['all'].append(node)
        else:
            continue

        if node_cfg and \
           'l2vni' in node_cfg.keys() and \
           'l3vni' in node_cfg.keys():

            config_dict['nodes']['l2l3vni'].append(node)
    return config_dict

def set_tunnel_counterpoll(action='enable'):
    if action == 'enable':
        cmd = "sudo counterpoll tunnel enable"
    else:
        cmd = "sudo counterpoll tunnel disable"
    return cmd

def generate_l2vni_config(data,l2vni_int_list, ints_dict={}, mode='add'):
    '''
    Generates vlan , vlan memebers and vxlan mapping for l2vni configs

    'data' format (in input yaml file):
    l2vni:
        vlan_start_range: 2   
        count: 4
    or 
    l2vni:
        - vlan_id: 2
          members: [T1P1, PortChannel1]
        - vlan_id: 3
          members: [T1P1]
        - vlan_id: 4
    '''
    output = ''
    # L2VNI configuration
    if not data.get('l2vni'):
        return output

    vxlan_list = list()
    vlan_data = dict()
    vxlan_start_id = 5000
    if type(data['l2vni']) == list:
        for l2vni_item in data['l2vni']:
            if l2vni_item.get('vxlan_id'):
                vxlan_id = l2vni_item['vxlan_id']
            else:
                vxlan_id = vxlan_start_id + l2vni_item['vxlan_id']
            vxlan_list.append(vxlan_id)
            vlan_data[vxlan_id] = dict()
            vlan_data[vxlan_id]['vlan_id'] = l2vni_item['vlan_id']
            vlan_data[vxlan_id]['members'] = list()
            for member_port_id in l2vni_item['members']:
                for port_id, int_name in ints_dict.get('all_port_dict', {}).items():
                    if member_port_id in port_id:
                        break
                else:
                    int_name = member_port_id
                vlan_data[vxlan_id]['members'].append(int_name)

    else:
        #auto gen
        for vlan_id in range(data['l2vni']['vlan_start_range'], 
                          data['l2vni']['vlan_start_range']+data['l2vni']['count']):
            vxlan_id = vlan_id + vxlan_start_id
            vxlan_list.append(vxlan_id)
            vlan_data[vxlan_id] = dict()
            vlan_data[vxlan_id]['members'] = l2vni_int_list
            vlan_data[vxlan_id]['vlan_id'] = vlan_id 
    
    for vxlan_id in vxlan_list:
        cmd = list()
        vlan_id = vlan_data[vxlan_id]['vlan_id']
        cmd.append('sudo config vlan {} {}\n'.format(mode, vlan_id))

        for int_name in vlan_data[vxlan_id]['members']:
            cmd.append('sudo config vlan member {} {} {}\n'.format(mode, vlan_id, int_name))
        cmd.append('sudo config vxlan map {} VXLAN {} {}\n'.format(mode, vlan_id, vxlan_id))
            
        if mode == 'add':
            output += ''.join(cmd)
        else:
            cmd.reverse()
            output += ''.join(cmd)

    return output 

def get_vxlan_mapping(data, mode="add"):
    '''
    Author:Ramsiddarth Ragurajan (rraguraj@cisco.com)
    '''
    output = ''
    if not data.get('l2vni'):
        return output

    vlan_list = list()
    vxlan_list = list()
    vxlan_start_id = 5000
    if type(data['l2vni']) == list:
        for l2vni_item in data['l2vni']:
            vlan_list.append(l2vni_item['vlan_id'])
            if l2vni_item.get('vxlan_id'):
                vxlan_id = l2vni_item['vxlan_id']
            else:
                vxlan_id = vxlan_start_id + l2vni_item['vxlan_id']
            vxlan_list.append(vxlan_id)
    else:
        for vlan_id in range(data['l2vni']['vlan_start_range'], 
                          data['l2vni']['vlan_start_range']+data['l2vni']['count']):
            vlan_list.append(vlan_id)
            vxlan_list.append(vxlan_id + vxlan_start_id)
                
    for vlan_id, vxlan_id in zip(vlan_list, vxlan_list):
        if mode == "add":
            cmd = 'sudo config vxlan map add VXLAN {} {}\n'.format(vlan_id, vxlan_id)
            output += cmd
        elif mode == "del":
            cmd = 'sudo config vxlan map del VXLAN {} {}\n'.format(vlan_id, vxlan_id)
            output += cmd
        else:
            st.banner("unknown action supported add/del")
            st.report_fail('test_case_failed')
    return output

def generate_host_ip(l2vni_intf_dict, version):
    '''
    Author:Ramsiddarth Ragurajan (rraguraj@cisco.com)
    generates host ip for l2vni hosts
    '''
    host_dict = {}
    if version == 'ipv4':
        start_ip =  "20.20.20.10"
        temp_ip = "20.20.20.10"
        
        for node, value in l2vni_intf_dict.items():
            ip_list = []
            for item in value:
                ip_list.append(start_ip)
                start_ip = str(ipaddress.ip_address(unicode(start_ip)) + 256)
            host_dict[node] =  ip_list   
            start_ip = str(ipaddress.ip_address(unicode(temp_ip)) + 10)
    return host_dict

def generate_svi_ip(nodes, version, vni):
    '''
    
    Author:Ramsiddarth Ragurajan (rraguraj@cisco.com)

    returns the list of SVI ip's for l3vni for each vteps based on the l3vni count spefied in dut config file
    Example:
    leaf0:
    l3vni:
        l3_dummy:
            start_vlan: 102
            count: 3 <----
    leaf1:
    l3vni:
        l3_dummy:
            start_vlan: 102
            count: 2 <----

    {'leaf0': ['80.80.80.1', '80.80.81.1', '80.80.82.1'], 'leaf1': ['90.90.90.1', '90.90.91.1']}
    '''
    count = {}
    config_dict = get_cfg_dict()
    for node, config in config_dict.items():
        if node in nodes:
            if type(config['l3vni']) == list:
                count[node] = len(config['l3vni'])
            else:
                count[node] = config['l3vni']['l3_dummy']['count']
    svi_dict ={}
    if version == 'ipv4':
        if vni == 'l3vni':
            temp_ip =  "80.80.80.1"
            ip_start = "80.80.80.1"
        else:
            temp_ip =  "20.20.20.1"
            ip_start = "20.20.20.1"
        for node in nodes:
            temp_list =[]
            for i in range(count[node]):
                temp_list.append(ip_start)
                ip_start = str(ipaddress.ip_address(unicode(ip_start)) + 256)
            ip_start = get_new_ip_range(str(temp_ip))
            temp_ip = ip_start
            svi_dict[node] = temp_list
    elif version == 'ipv6':
        pass
    else:
        print("unknown version")
    return svi_dict

def get_new_ip_range(ip_add):
    '''
    Author:Ramsiddarth Ragurajan (rraguraj@cisco.com)
    returns new ip with new subnet
    input: ip
    Ex: input: 80.80.80.1 output: 90.90.90.1
    '''
    temp_list = ip_add.split('.')
    for i in range(3):
        temp_list[i] = str(int(temp_list[i]) + 10)
    return '.'.join(temp_list)

def generate_l3vni_config(leaf_data, mode='add'):
    '''
    Author: Jigar Sanghrajka (jsanghra@cisco.com)
    
    '''
    output = ''
    if not leaf_data.get('l3vni') or not leaf_data.get('l2vni'):
        return output

    vxlan_list = list()
    vrf_data = dict()
    vxlan_start_id = 5000
    if type(leaf_data['l3vni']) == list:
        for l3vni_item in leaf_data['l3vni']:
            if l3vni_item.get('vxlan_id'):
                vxlan_id = l3vni_item['vxlan_id']
            else:
                vxlan_id = vxlan_start_id + l3vni_item['vxlan_id']
            vxlan_list.append(vxlan_id)
            vrf_data[vxlan_id] = dict()
            vrf_data[vxlan_id]['vrf_id'] = l3vni_item['vrf_id']
            vrf_data[vxlan_id]['bindings'] = l3vni_item['vlan_bindings']
            vrf_data[vxlan_id]['bindings'].append(l3vni_item['vrf_id'])
    else:
        #auto gen
        l2_vlan_id = leaf_data['l2vni']['vlan_start_range']
        for vlan_id in range(leaf_data['l3vni']['l3_dummy']['start_vlan'], 
                          leaf_data['l3vni']['l3_dummy']['start_vlan']+leaf_data['l3vni']['l3_dummy']['count']):
            vxlan_id = vlan_id + vxlan_start_id
            vxlan_list.append(vxlan_id)
            vrf_data[vxlan_id] = dict()
            vrf_data[vxlan_id]['vrf_id'] = vlan_id 
            vrf_data[vxlan_id]['bindings'] = [vlan_id]
            vrf_data[vxlan_id]['bindings'].append(l2_vlan_id)
            vrf_data[vxlan_id]['bindings'].append(l2_vlan_id+1)
            l2_vlan_id += 2

    # L3VNI configuration

    for vxlan_id in vxlan_list:
        cmd = list()
        vrf_id = vrf_data[vxlan_id]['vrf_id']
        cmd.append('sudo config vlan {} {}\n'.format(mode, vrf_id))
        cmd.append('sudo config vrf {} Vrf{}\n'.format(mode, vrf_id))
        for vlan_binding in vrf_data[vxlan_id]['bindings']:
            if mode == 'add':
                cmd.append('sudo config interface vrf bind Vlan{} Vrf{}\n'.format(vlan_binding, vrf_id))
            else:
                cmd.append('sudo config interface vrf unbind Vlan{}\n'.format(vlan_binding))
        cmd.append('sudo config vxlan map {} VXLAN {} {}\n'.format(mode, vrf_id , vxlan_id))
        if mode == 'add':
            cmd.append('sudo config vrf add_vrf_vni_map Vrf{} {}\n'.format(vrf_id, vxlan_id))
        else:
            cmd.append('sudo config vrf del_vrf_vni_map Vrf{} \n'.format(vrf_id))


        if mode == 'add':
            output += ''.join(cmd)
        else:
            cmd.reverse()
            output += ''.join(cmd)

    return output  

def delete_l2vni_config(leaf_data):
    '''
    Author: Jigar Sanghrajka (jsanghra@cisco.com)
    
    '''
    output = ''
    # L2VNI remove configuration
    if leaf_data.get('l2vni'):
        vlan_start = leaf_data['l2vni']['vlan_start_range']
        count = leaf_data['l2vni']['count']

        for i in range(vlan_start, vlan_start + count):
            output += 'sudo config vxlan map del VXLAN {} {}\n'.format(i, 5000 + i)
    return output

def delete_l3vni_config(leaf_data):
    '''
    Author: Jigar Sanghrajka (jsanghra@cisco.com)
    
    '''
    output = ''
    # L3VNI remove configuration
    if leaf_data.get('l3vni'):
        l3_start = leaf_data['l3vni']['l3_dummy']['start_vlan']
        count = leaf_data['l3vni']['l3_dummy']['count']
        
        for i in range(count):
            output += 'sudo config vrf del_vrf_vni_map Vrf{}\n'.format(l3_start + i)
            output += 'sudo config vxlan map del VXLAN {} {}\n'.format(l3_start + i, 5000 + l3_start + i)
            output += 'sudo config vrf del Vrf{}\n'.format(l3_start + i)
    return output     

def generate_port_channel_config(node, config_data, ints_dict, mode='add'):
    '''
    generate port channel configs
    Example:
    sudo config portchannel add PortChannel1
    sudo config portchannel member add PortChannel1 Ethernet1_8
    sudo config portchannel member add PortChannel1 Ethernet1_9
    config data (input file):
    leaf0:
        port_channels:
            - port_channel_num: 1
            member_ids: [T1P2]
    '''
    output = ''
    
    if config_data and not config_data.get('port_channels'):
        return output

    for pc_data in config_data['port_channels']:
        cmd = list()
        cmd.append('sudo config portchannel {} PortChannel{}\n'.format(
            mode, pc_data['port_channel_num']))

        for member_id in pc_data['member_ids']:
            for port_id, int_name in ints_dict['all_port_dict'].items():
                if member_id in port_id:
                    cmd.append('sudo config portchannel member {} PortChannel{} {}\n'.format(
                        mode, pc_data['port_channel_num'], int_name))
                    break
            else:
                cmd.append('sudo config portchannel member {} PortChannel{} {}\n'.format(
                    mode, pc_data['port_channel_num'], member_id))

        if mode == 'add':
            output += ''.join(cmd)
        else:
            cmd.reverse()
            output += ''.join(cmd)

    return output  

def generate_evpn_esi_config(config_data, mode='add'):
    '''
    generate evpn esi configs on port channel
    Example:
    sudo config interface sys-mac add PortChannel3 00:44:33:22:11:33
    sudo config interface evpn-esi add PortChannel3 00:02:03:04:05:06:07:08:09:0c
    config data (input file):
    leaf0:
        port_channels:
            - port_channel_num: 3
            member_ids: [T1P2]
            sys_mac: 00:44:33:22:11:33
            evpn_esi: 00:02:03:04:05:06:07:08:09:0c    
    '''
    output = ''
    
    if config_data and not config_data.get('port_channels'):
        return output

    for pc_data in config_data['port_channels']:
        cmd = list()

        if pc_data.get('sys_mac'):
            mode_cli = 'add' if mode == 'add' else 'remove'
            cmd.append('sudo config interface sys-mac {} PortChannel{} {}\n'.format(
                     mode_cli, pc_data['port_channel_num'], pc_data['sys_mac']) )

        if pc_data.get('evpn_esi'):
            if mode == 'add':
                cmd.append('sudo config interface evpn-esi add PortChannel{} {}\n'.format(
                    pc_data['port_channel_num'], pc_data['evpn_esi'])) 
            else:
                cmd.append('sudo config interface evpn-esi del PortChannel{} \n'.format(
                    pc_data['port_channel_num'])) 

        if mode == 'add':
            output += ''.join(cmd)
        else:
            cmd.reverse()
            output += ''.join(cmd)

    return output  

def generate_epvn_mh_config(node, config_data, mode='add'):
    '''
    generate epvn multi-homing attributes configs
    Example:
    vtysh
    config
    evpn mh redirect-off
    evpn mh mac-holdtime 200
    evpn mh neigh-holdtime 200
    config data (input file):
    global:
        evpn_mh:
            redirect: off
            mac_holdtime: 200
            neigh_holdtime: 200   
    '''
    mode_prfx = '' if mode == 'add' else 'no '
    output = ''
    
    if config_data[node] and not config_data[node].get('port_channels'):
        return output
    if not config_data.get('global') or not config_data['global'].get('evpn_mh'):
        return output

    if config_data['global']['evpn_mh'].get('redirect_off', False):
        output += '{}evpn mh redirect-off\n'.format(mode_prfx)

    if config_data['global']['evpn_mh'].get('mac_holdtime'):
        output += '{}evpn mh mac-holdtime {}\n'.format(
                mode_prfx, config_data['global']['evpn_mh']['mac_holdtime'])

    if config_data['global']['evpn_mh'].get('neigh_holdtime'):
        output += '{}evpn mh neigh-holdtime {}\n'.format(
                mode_prfx, config_data['global']['evpn_mh']['neigh_holdtime'])
    if output:
        output += 'end\n'
        output += 'exit\n'

    return output  

def generate_loopback_config(ip_addr,loopback_int = 'Loopback0'):
    '''
    Author: Jigar Sanghrajka (jsanghra@cisco.com)
    
    '''
    output = 'sudo config interface ip add {} {}\n'.format(loopback_int, ip_addr)
    return output

def delete_loopback_config(ip_addr,loopback_int = 'Loopback0'):
    '''
    Author: Jigar Sanghrajka (jsanghra@cisco.com)
    
    '''
    output = 'sudo config interface ip rem {} {}\n'.format(loopback_int, ip_addr)
    return output

def generate_vxlan_config(ip_addr):
    output = ''
    output += 'sudo config vxlan add VXLAN {}\n'.format(ip_addr)
    output += 'sudo config vxlan evpn_nvo add NVO VXLAN\n'

    return output 

def delete_vxlan_config():
    output = ''
    output += 'sudo config vxlan evpn_nvo del NVO \n'
    output += 'sudo config vxlan del VXLAN \n'
    return output 

def generate_bgp_underlay_config(leaf_data,int_list):
    '''
    Author: Jigar Sanghrajka (jsanghra@cisco.com)
    
    '''
    output = ''
    # BGP underlay configuration
    router_id = leaf_data['router_id']
    as_num = leaf_data['as_num']

    output += 'router bgp {}\n'.format(as_num)
    output += 'bgp router-id {}\n'.format(router_id)
    output += 'no bgp ebgp-requires-policy\n'
    output += 'no bgp default ipv4-unicast\n'
    output += 'bgp disable-ebgp-connected-route-check\n'
    output += 'bgp bestpath as-path multipath-relax\n'
    output += 'neighbor TRANSIT peer-group\n'
    output += 'neighbor TRANSIT remote-as external\n'
    for intf in int_list:
        output += 'neighbor {} interface peer-group TRANSIT\n'.format(intf)
    output += 'address-family ipv4 unicast\n'
    output += 'redistribute connected\n'
    output += 'neighbor TRANSIT activate\n'
    output += 'exit-address-family\n'
    output += 'address-family ipv6 unicast\n'
    output += 'redistribute connected\n'
    output += 'neighbor TRANSIT activate\n'
    output += 'exit-address-family\n'
    output += 'end\n'
    output += 'exit\n'

    return output

def generate_bgp_bfd_underlay_config(leaf_data):
    '''
    Author: Jigar Sanghrajka (jsanghra@cisco.com)
    
    '''
    output = ''
    # BGP BFD underlay configuration
    router_id = leaf_data['router_id']
    as_num = leaf_data['as_num']

    output += 'router bgp {}\n'.format(as_num)
    output += 'bgp router-id {}\n'.format(router_id)
    output += 'neighbor TRANSIT peer-group\n'
    output += 'neighbor TRANSIT remote-as external\n'
    output += 'neighbor TRANSIT bfd\n'
    output += 'neighbor TRANSIT bfd disable-strict-mode\n'
    output += 'end\n'
    output += 'exit\n'

    return output

def generate_bgp_overlay_config(leaf_data):
    '''
    Author: Jigar Sanghrajka (jsanghra@cisco.com)
    
    '''
    output = ''
    # BGP overlay configuration
    router_id = leaf_data['router_id']
    as_num = leaf_data['as_num']
    neighbor_overlays = leaf_data['neigbor_overlay']

    output += 'router bgp {}\n'.format(as_num)
    output += 'bgp router-id {}\n'.format(router_id)
    output += 'neighbor OVERLAY peer-group\n'
    output += 'neighbor OVERLAY remote-as external\n'
    output += 'neighbor OVERLAY disable-connected-check\n'
    output += 'neighbor OVERLAY ebgp-multihop 255\n'
    output += 'neighbor OVERLAY update-source Loopback0\n'
    for neighbor in neighbor_overlays:
        output += 'neighbor {} peer-group OVERLAY\n'.format(neighbor)
    output += 'address-family l2vpn evpn\n'
    output += 'neighbor OVERLAY activate\n'
    output += 'advertise-all-vni\n'
    output += 'advertise ipv4 unicast\n'
    output += 'advertise ipv6 unicast\n'
    output += 'exit-address-family\n'
    output += 'end\n'
    output += 'exit\n'

    return output

def generate_bgp_bfd_overlay_config(leaf_data):
    '''
    Author: Jigar Sanghrajka (jsanghra@cisco.com)
    
    '''
    output = ''
    # BGP overlay configuration
    router_id = leaf_data['router_id']
    as_num = leaf_data['as_num']

    output += 'router bgp {}\n'.format(as_num)
    output += 'bgp router-id {}\n'.format(router_id)
    output += 'neighbor OVERLAY peer-group\n'
    output += 'neighbor OVERLAY remote-as external\n'
    output += 'neighbor OVERLAY bfd\n'
    output += 'neighbor OVERLAY bfd disable-strict-mode\n'
    output += 'end\n'
    output += 'exit\n'

    return output

def generate_bgp_l3vni_config(leaf_data,bgp_info):
    '''
    Author: Jigar Sanghrajka (jsanghra@cisco.com)
    
    '''
    output = ''
    # BGP l3vni configuration
    router_id = bgp_info['router_id']
    as_num = bgp_info['as_num']
    vxlan_list = list()
    vrf_list = list()
    if leaf_data.get('l3vni'):

        vxlan_start_id = 5000
        if type(leaf_data['l3vni']) == list:
            for l3vni_item in leaf_data['l3vni']:
                if l3vni_item.get('vxlan_id'):
                    vxlan_id = l3vni_item['vxlan_id']
                else:
                    vxlan_id = vxlan_start_id + l3vni_item['vxlan_id']
                vxlan_list.append(vxlan_id)
                vrf_list.append(l3vni_item['vrf_id'])
        else:
            #auto gen
            for vlan_id in range(leaf_data['l3vni']['l3_dummy']['start_vlan'], 
                              leaf_data['l3vni']['l3_dummy']['start_vlan']+leaf_data['l3vni']['l3_dummy']['count']):
                vxlan_id = vlan_id + vxlan_start_id
                vxlan_list.append(vxlan_id)
                vrf_list.append(vlan_id)
    elif leaf_data.get('vni'):
        start_vlan = leaf_data['vni']['vlan_start_range']
        count = leaf_data['vni']['count']
        for i in range(count):
            vrf = start_vlan + i
            vrf_list.append(vrf)
            vxlan_list.append(5000 + vrf)
    else:
        st.report_fail("vni information not found in input file")

    # output += 'router bgp {}\n'.format(as_num)
    # output += 'bgp router-id {}\n'.format(router_id)
    for vrf,vni in zip(vrf_list, vxlan_list):
        output += 'router bgp {} vrf Vrf{}\n'.format(as_num, vrf)
        output += 'bgp bestpath as-path multipath-relax\n'
        output += 'address-family ipv4 unicast\n'
        output += 'redistribute connected\n'
        output += 'exit-address-family\n'
        output += 'address-family ipv6 unicast\n'
        output += 'redistribute connected\n'
        output += 'exit-address-family\n'
        output += 'address-family l2vpn evpn\n'
        output += 'advertise ipv4 unicast\n'
        output += 'advertise ipv6 unicast\n'
        output += 'no use-es-l3nhg\n'
        output += 'exit-address-family\n'
        output += 'exit\n'
        output += 'vrf Vrf{}\n'.format(vrf)
        output += 'vni {}\n'.format(vni)
    output += 'end\n'
    output += 'exit\n'

    return output

def generate_bgp_unnumbered_config(int_list):
    '''
    Author: Jigar Sanghrajka (jsanghra@cisco.com)
    
    '''
    output = ''
    # BGP unnumbered configuration
    for interface in int_list:
        output += 'sudo config interface ipv6 enable use-link-local-only {}\n'.format(interface)

    return output

def get_dut_interfaces(var_dict):
    '''
    
    Author:Ramsiddarth Ragurajan (rraguraj@cisco.com)

    returns all the dut interfaces based on input testbed yaml file

    input_param: testbed vars
    ex:
    spine1 {'tgen_port_dict': {},
             'underlay_dict': {'D2D4P1': 'Ethernet8', 'D2D3P1': 'Ethernet0'}, 
             'dut_port_dict': {}}
    spine0 {'tgen_port_dict': {}, 
            'underlay_dict': {'D1D4P1': 'Ethernet8', 'D1D3P1': 'Ethernet0'}, 
            'dut_port_dict': {}}
    leaf1 {'tgen_port_dict': {'T1D4P3': '1/7', 'T1D4P2': '1/4', 'T1D4P1': '1/3'}, 
        'underlay_dict': {'D4D2P1': 'Ethernet8', 'D4D1P1': 'Ethernet0'}, 
        'dut_port_dict': {'D4T1P3': 'Ethernet224', 'D4T1P2': 'Ethernet248', 'D4T1P1': 'Ethernet240'}}
    leaf0 {'tgen_port_dict': {'T1D3P4': '1/6', 'T1D3P1': '1/1', 'T1D3P2': '1/2', 'T1D3P3': '1/5'}, 
            'underlay_dict': {'D3D1P1': 'Ethernet0', 'D3D2P1': 'Ethernet8'}, 
            'dut_port_dict': {'D3T1P4': 'Ethernet232', 'D3T1P1': 'Ethernet240', 'D3T1P2': 'Ethernet248', 'D3T1P3': 'Ethernet224'}

    '''
    final_dict={}
    for node,dut_id in var_dict.dut_ids.items(): 
        final_dict[node]={}
        dut_port_dict={} 
        underlay_dict={} 
        tgen_port_dict={}
        all_port_dict={}
        # dut_id = var_dict.dut_ids[node]
        for key,value in var_dict.items(): 
            if dut_id+'T1' in key:
                dut_port_dict[key]= value
                all_port_dict[key] = value
            if "T1"+dut_id in key:
                tgen_port_dict[key]= value
                all_port_dict[key] = value
            if dut_id in key and "T1" not in key:
                if key != dut_id and dut_id in key[:2]:
                    underlay_dict[key] = value
                    all_port_dict[key] = value
        final_dict[node]['all_port_dict'] = all_port_dict
        final_dict[node]['dut_port_dict'] = dut_port_dict
        final_dict[node]['underlay_dict'] = underlay_dict
        final_dict[node]['tgen_port_dict'] = tgen_port_dict
    return final_dict

def get_config_interfaces_list(var_dict):
    '''
    Author:Ramsiddarth Ragurajan (rraguraj@cisco.com)

    Returns the l2vni, l3vni and underlay interface information for configuration

    Generated based on no of l2vni/l3vni count provided in dut config file and info from testbed yaml file

    Example:
    input from dut_configs_file
    leaf0:
        l2vni:
            vlan_start_range: 501
            count: 1 <--
        l3vni:
            l3_dummy:
                start_vlan: 102
                count: 2 <--
    final_config_dict output:
    {'spine0': {'underlay': ['Ethernet0', 'Ethernet8']}, 
    'spine1': {'underlay': ['Ethernet0', 'Ethernet8']},
     'leaf0': {'underlay': ['Ethernet0', 'Ethernet8'], 'l2vni_int': ['Ethernet240'], 'l3vni_int': ['Ethernet248', 'Ethernet224']}, 
     'leaf1': {'underlay': ['Ethernet8', 'Ethernet0'], 'l2vni_int': ['Ethernet240'], 'l3vni_int': ['Ethernet248', 'Ethernet224']}}
    
    '''
    temp_list =[]
    config_dict={}
    temp_dict = {}
    final_config_dict ={}
    dut_int_data = get_dut_interfaces(var_dict)
    config = get_cfg_dict()
    for key,value in var_dict.dut_ids.items():
        if key in config['nodes']['l2l3vni']:
            temp_dict[key] ={}
            if type(config[key]['l2vni']) == list:
                temp_dict[key]['l2vni_int_count'] = len(config[key]['l2vni'])
            else:
                temp_dict[key]['l2vni_int_count'] = config[key]['l2vni']['count']
    for node in var_dict.dut_ids.keys():
        temp_list=[]
        if node in config['nodes']['spine'] or \
            node in config['nodes']['leaf']:
            final_config_dict[node]={}
            final_config_dict[node]['underlay']={}
            for item,value in dut_int_data[node]['underlay_dict'].items():
                temp_list.append(value)
            final_config_dict[node]['underlay'] = sorted(temp_list)
        if node in config['nodes']['l2l3vni']:
            my_list =[]
            for key in dut_int_data[node]['dut_port_dict'].keys():      
                my_list.append(key)
            sorted_list =sorted(my_list)

            for port in sorted_list:
                 temp_list.append(dut_int_data[node]['dut_port_dict'][port])
            config_dict[node] = temp_list

    for node,value in temp_dict.items():
        final_config_dict[node]['l2vni_int']= config_dict[node][:value['l2vni_int_count']]

    return final_config_dict

def get_interfaces(var_dict,nodes,vni):
    '''
    Gets tgen spytest port alias and gateway

    Author:Ramsiddarth Ragurajan (rraguraj@cisco.com)

    input params: list of leaf nodes
    get interaces from dutconfig 
    get endpoints and gateway
    ('T1D3P2', 'T1D4P2', '80.80.80.1/24', '90.90.90.1/24'), ('T1D3P4', 'T1D4P4', '80.80.81.1/24', '90.90.91.1/24')]

    T1D3P2  --> tgen_src leaf0, T1D4P2 -->tgen_dst leaf1 80.80.80.1/24,90.90.90.1/24' -->  gateway

    '''
    int_config_dict = get_config_interfaces_list(var_dict)
    intf_dict = {}
    sort_intf_dict = {}
    for node in nodes:
        if vni == 'l3vni':
            intf_list = find_port_alias(var_dict,node,int_config_dict[node]['l3vni_int'])
        else:
            intf_list = find_port_alias(var_dict,node,int_config_dict[node]['l2vni_int'])
        intf_dict[node]= intf_list
    keys = list(sorted(intf_dict.keys()))
    for item in keys:
        sort_intf_dict[item] = intf_dict[item]
    return sort_intf_dict

def find_port_alias(var_dict,node,int_list):
    '''
    Author:Ramsiddarth Ragurajan (rraguraj@cisco.com)
    Example:
    input --> ['D1T1P1, 'D3T1P2'] output --> ['T1D1P1','T1D3P2']
    '''
    for key,value in var_dict.items():
        if value == node:
            mykey = key
    mylist=[]
    for i in int_list:
        for key,value in var_dict.items():
            if mykey+"T1" in key and value == i:
                key_list= list(key)
                p1= key_list.pop(2)
                p2= key_list.pop(2)
                key_list.insert(0,p2)
                key_list.insert(0,p1)
                mylist.append("".join(key_list)) 
              
    return mylist

def find_endpoint_pair(intf_dict,vni = None):
    '''
    Author:Ramsiddarth Ragurajan (rraguraj@cisco.com)
    returns the list of tgen and gw ip to be configured for the streams
    l3vni:
    output = [('T1D3P2', 'T1D4P2', '80.80.80.1', '90.90.90.1'), ('T1D3P3', 'T1D4P3', '80.80.81.1', '90.90.91.1')]

    ex: T1D3P2 --> traffic src endpoint
        T1D4P2  --> traffic dst endpoint
        80.80.80.1 --> src gateway
        90.90.90.1 --> dst gateway

    '''
    port_dict = {}
    nodes = list(sorted(intf_dict.keys()))
    for item in nodes:
        port_dict[item] = intf_dict[item]
    tgen_ports = list(port_dict.values())
    if vni == "l3vni":
        gateway_dict={}
        gateway_ip = generate_svi_ip(nodes,'ipv4')
        key = list(sorted(gateway_ip.keys()))
        for item in key:
            gateway_dict[item] = gateway_ip[item]
        out = list(gateway_dict.values())
        output = list(zip(tgen_ports[0],tgen_ports[1],out[0],out[1]))
    elif vni == "l2vni":
        host_dict = generate_host_ip(intf_dict, 'ipv4')
        host_list = list(host_dict.values())
        output = list(zip(tgen_ports[0],tgen_ports[1],host_list[0],host_list[1]))
    else:
        gateway_dict={}
        gateway_ip = generate_svi_ip(nodes,'ipv4')
        key = list(sorted(gateway_ip.keys()))
        for item in key:
            gateway_dict[item] = gateway_ip[item]
        out = list(gateway_dict.values())
        output = list(zip(tgen_ports[0],tgen_ports[1],out[0],out[1]))

    return output

def verify_vtep (nodes):
    '''
    Author:Ramsiddarth Ragurajan (rraguraj@cisco.com)
    remote_vtep_dict ={'leaf1': {'2000:1::2': ['2000:1::1', '2000:1::4']}, 
    'leaf0': {'2000:1::1': ['2000:1::2', '2000:1::3', '2000:1::4']}, 
    'leaf3': {'2000:1::4': ['2000:1::2', '2000:1::3', '2000:1::4']}, 
    'leaf2': {'2000:1::3': ['2000:1::1', '2000:1::4']}}
    get_vtep_info(nodes)[1] = {'leaf1': ['2000:1::2'], 'leaf0': ['2000:1::1'], 'leaf3': ['2000:1::4'], 'leaf2': ['2000:1::3']}
    '''
    flag = True
    remote_vtep_dict = get_expected_remote_vteps()
    for i in range (len(nodes)):
        cli_output = st.show(nodes[i], "show vxlan remotevtep", skip_tmpl=True)
        '''
        [{u'tun_src': u'EVPN', u'total_count': u'', u'vlan': u'', u'tun_status': u'oper_up', u'vni': u'', u'remote_mac': u'', u'dst_vtep': u'2000:1::2', u'src_vtep': u'2000:1::1', u'remote_vtep': u''}, 
        {u'tun_src': u'EVPN', u'total_count': u'', u'vlan': u'', u'tun_status': u'oper_up', u'vni': u'', u'remote_mac': u'', u'dst_vtep': u'2000:1::3', u'src_vtep': u'2000:1::1', u'remote_vtep': u''}, 
        {u'tun_src': u'EVPN', u'total_count': u'', u'vlan': u'', u'tun_status': u'oper_up', u'vni': u'', u'remote_mac': u'', u'dst_vtep': u'2000:1::4', u'src_vtep': u'2000:1::1', u'remote_vtep': u''}]
        '''
        parsed_out = st.parse_show(nodes[i], "show vxlan remotevtep",cli_output, "show_vxlan_remotevtep.tmpl")
        if len(parsed_out) == 0:
            flag = False
            st.log('No remote VTEP found in', nodes[i])
            break
        for src_vtep, values in remote_vtep_dict[nodes[i]].items():
            for item in parsed_out:
                if item['src_vtep'] != src_vtep:
                    st.log('No local vtep {} found in {}'.format(src_vtep,nodes[i]))
                    flag = False
                if item['dst_vtep'] not in values:
                    st.log(' no remote vtep {} found in {}'.format(item['dst_vtep'],nodes[i]))
                    flag = False
                if item['tun_src'] != 'EVPN':
                    flag = False
                    st.log('Unexpected tunnel type {} in {}'.format(item['tun_type'], nodes[i]))
                if item['tun_status'] != 'oper_up':
                    st.log('Tunnel is not in up status in {}'.format(nodes[i]))
                    flag = False
    return flag

def get_vtep_info(nodes):
    '''
    Get local vtep ip list for each node, and list of all vtep ip's in the topo. Generated based on dut_configs.yaml

    Author:Ramsiddarth Ragurajan (rraguraj@cisco.com)

    input params: list of leaf nodes

    vtep_ip_list --> ['10.200.200.200', '10.200.200.100', '10.200.200.201', '10.200.200.101', '10.200.200.202', '10.200.200.203']
    vtep_dict --> {'leaf0': ['10.200.200.200', '10.200.200.100'], 'leaf1': ['10.200.200.201', '10.200.200.101'], 'leaf2': ['10.200.200.202'], 'leaf3': ['10.200.200.203']}
    '''
    vtep_dict ={}
    config_dict = get_cfg_dict()
    for node, config in config_dict.items():
        if node in nodes:
            vtep_dict[node] = (config['nvo']['ip'])
    vtep_ip_list=[]
    for key,value in vtep_dict.items():
        for ip in value:
            vtep_ip_list.append(ip)
    return vtep_ip_list,vtep_dict

def get_remote_vteps(nodes):
    '''
    Get remote vtep ip list for each node, Generated based on dut_configs.yaml

    Author:Ramsiddarth Ragurajan (rraguraj@cisco.com)
    
    input params: list of leaf nodes

    remote_vtep_dict --> {'leaf0': {'10.200.200.200': ['10.200.200.201']}, 'leaf1': {'10.200.200.201': ['10.200.200.200']}}

    '''
    remote_vtep_dict ={}
    config_dict = get_cfg_dict()
    for node, config in config_dict.items():
        if node in nodes:
            remote_vtep_dict[node]={}
            remote_vtep_dict[node][config['loopback']['ip_address']] = config['expected_vteps']

    return remote_vtep_dict  

def delete_bgp_l3vni_config(data,bgp_info):
    '''
    Author: Jigar Sanghrajka (jsanghra@cisco.com)
    
    '''
    output = ''
    # BGP configuration
    as_num = bgp_info['as_num']

    vxlan_list = list()
    vrf_list = list()
    if data.get('l3vni'):

        vxlan_start_id = 5000
        if type(data['l3vni']) == list:
            for l3vni_item in data['l3vni']:
                if l3vni_item.get('vxlan_id'):
                    vxlan_id = l3vni_item['vxlan_id']
                else:
                    vxlan_id = vxlan_start_id + l3vni_item['vxlan_id']
                vxlan_list.append(vxlan_id)
                vrf_list.append(l3vni_item['vrf_id'])
        else:
            #auto gen
            for vlan_id in range(data['l3vni']['l3_dummy']['start_vlan'], 
                              data['l3vni']['l3_dummy']['start_vlan']+data['l3vni']['l3_dummy']['count']):
                vxlan_id = vlan_id + vxlan_start_id
                vxlan_list.append(vxlan_id)
                vrf_list.append(vlan_id)
    elif data.get('vni'):
        start_vlan = data['vni']['vlan_start_range']
        count = data['vni']['count']
        for i in range(count):
            vrf = start_vlan + i
            vrf_list.append(vrf)
            vxlan_list.append(5000 + vrf)
    else:
        st.report_fail("vni information not found in input file")

    for vrf,vni in zip(vrf_list, vxlan_list):
    
        output += 'vrf Vrf{}\n'.format(vrf)
        output += 'no vni {}\n'.format(vni)
        output += 'no router bgp {} vrf Vrf{}\n'.format(as_num, vrf)
    output += 'end\n' 
    output += 'exit\n' 

    return output

def delete_bgp_config(data):
    '''
    Author: Jigar Sanghrajka (jsanghra@cisco.com)
    
    '''
    output = ''
    # BGP configuration
    router_id = data['router_id']
    as_num = data['as_num']
    output += 'no router bgp {}\n'.format(as_num)   
    output += 'end\n' 
    output += 'exit\n' 
    return output

def increment_mac(mac_address):
    """
    Increments a MAC address by 1.
    """
    parts = mac_address.split(':')  
    carry = 1  
    for i in range(len(parts) - 1, -1, -1): 
        val = int(parts[i], 16) + carry  
        parts[i] = format(val % 256, '02x')  
        carry = val // 256  
    return ':'.join(parts)  

def verify_vlanvnimap(nodes):
    '''
    Author: Jigar Sanghrajka (jsanghra@cisco.com)
    
    '''
    expected_vlanvnimap = get_expected_vlanvnimap(nodes)
    # Convert parsed data to dictionary format
    for i in range (len(nodes)):
        cli_output = st.show(nodes[i], "show vxlan vlanvnimap", skip_tmpl=True)
        vlan_vni_mappings = st.parse_show(nodes[i], "show vxlan vlanvnimap",cli_output, "show_vxlan_vlanvnimap.tmpl")
        parsed_out = [[entry['vlan'], entry['vni']] for entry in vlan_vni_mappings]
        if len(parsed_out) == 0:
            st.report_fail('No mapping found', nodes[i])
        parsed_dict = {nodes[i]: [(item[0], item[1]) for item in parsed_out]}
 
        # Check that the leaf exists in the expected data
        if nodes[i] not in expected_vlanvnimap:
            print("Leaf {} not found in expected data.".format(nodes[i]))
            st.report_fail('Leaf name {} not in expected data'.format(nodes[i]))

        if len(expected_vlanvnimap[nodes[i]]) != len(parsed_dict[nodes[i]]):
            print("Mismatch in the length of expected data - length {} and parsed data - length {}".format(len(expected_vlanvnimap[nodes[i]]),len(parsed_dict[nodes[i]])))
            st.report_fail("Mismatch in the length of expected data - length {} and parsed data - length {}".format(len(expected_vlanvnimap[nodes[i]]),len(parsed_dict[nodes[i]])))

        # Check that each key-value pair in the parsed data is in the expected data
        for pair in parsed_dict[nodes[i]]:
            if pair not in expected_vlanvnimap[nodes[i]]:
                st.report_fail("Pair {} not found in expected data for {}.".format(pair,nodes[i]))
                return False

    print("Data verification succeeded.")
    return True

def verify_vrfvnimap(nodes):
    '''
    Author: Jigar Sanghrajka (jsanghra@cisco.com)
    
    '''
    expected_vrfvnimap = get_expected_vrfvnimap(nodes)
    # Convert parsed data to dictionary format
    for i in range (len(nodes)):
        cli_output = st.show(nodes[i], "show vxlan vrfvnimap", skip_tmpl=True)
        vrf_vni_mappings = st.parse_show(nodes[i], "show vxlan vrfvnimap",cli_output, "show_vxlan_vrfvnimap.tmpl")
        parsed_out = [[entry['vrf'], entry['vni']] for entry in vrf_vni_mappings]
        if len(parsed_out) == 0:
            st.report_fail('No mapping found', nodes[i])

        parsed_dict = {nodes[i]: [(item[0], item[1]) for item in parsed_out]}
        # Check that the leaf exists in the expected data
        if nodes[i] not in expected_vrfvnimap:
            print("Leaf {} not found in expected data.".format(nodes[i]))
            return False
        if len(expected_vrfvnimap[nodes[i]]) != len(parsed_dict[nodes[i]]):
            print("Mismatch in the length of expected data - length {} and parsed data - length {}".format(len(expected_vrfvnimap[nodes[i]]),len(parsed_dict[nodes[i]])))
            return False
        # Check that each key-value pair in the parsed data is in the expected data
        for pair in parsed_dict[nodes[i]]:
            if pair not in expected_vrfvnimap[nodes[i]]:
                st.report_fail("Pair {} not found in expected data for {}.".format(pair,nodes[i]))
                return False

    print("Data verification succeeded.")
    return True
 
def generate_vrf_vni(start_vrf, count, offset=5000):
    '''
    Author: Jigar Sanghrajka (jsanghra@cisco.com)

    Function to generate VRF-VNI tuples given a start L3 dummy VLAN and a count
    
    '''
    return [('Vrf' + str(vrf), str(vrf + offset)) for vrf in range(start_vrf, start_vrf + count)]

def generate_vlan_vni(start_vlan, count, offset=0):
    '''
    Author: Jigar Sanghrajka (jsanghra@cisco.com)
    
    Function to generate VLAN-VNI tuples given a start VLAN and a count
    '''
    return [('Vlan' + str(vlan), str(vlan + offset)) for vlan in range(start_vlan, start_vlan + count)]

def get_expected_vlanvnimap(nodes):
    '''
    Author: Jigar Sanghrajka (jsanghra@cisco.com)
    
    '''
    vlan_vni_map = {}
    config_dict = get_cfg_dict()
    for node, leaf_data in config_dict.items():
        if node in nodes:
            # Initialize the list for the current leaf
            vlan_vni_map[node] = []
            # Handle l2vni
            vlan_start_range = leaf_data['l2vni']['vlan_start_range']
            count = leaf_data['l2vni']['count']
            vlan_vni_map[node].extend(generate_vlan_vni(vlan_start_range, count, 5000))
            # Handle l3vni
            l3_dummy_vlan = leaf_data['l3vni']['l3_dummy']['start_vlan']
            l3_dummy_count = leaf_data['l3vni']['l3_dummy']['count']
            vlan_vni_map[node].extend(generate_vlan_vni(l3_dummy_vlan, l3_dummy_count, 5000))

    return vlan_vni_map

def get_expected_vrfvnimap(nodes):
    '''
    Author: Jigar Sanghrajka (jsanghra@cisco.com)
    
    '''
    vrf_vni_map = {}
    config_dict = get_cfg_dict()
    for node, leaf_data in config_dict.items():
        if node in nodes:
            # Initialize the list for the current leaf
            vrf_vni_map[node] = []

            # Handle l3vni
            l3_dummy_vrf = leaf_data['l3vni']['l3_dummy']['start_vlan']
            l3_dummy_count = leaf_data['l3vni']['l3_dummy']['count']
            vrf_vni_map[node].extend(generate_vrf_vni(l3_dummy_vrf, l3_dummy_count))

    return vrf_vni_map

def generate_sag_config(sag_dict,version,enable_on_vlan = True):

    output = ''
    
    for vlan,ip_add in sag_dict.items():
        if version == "ipv6":
            cmd = "sudo config interface ip add Vlan{} {}/64\n".format(vlan, ip_add)
        else:
            cmd = "sudo config interface ip add Vlan{} {}/24\n".format(vlan, ip_add)
        output += cmd
        if enable_on_vlan:
            cmd = "sudo config vlan static-anycast-gateway enable {}\n".format(vlan)
            output += cmd
    return output

def remove_sag_config(sag_dict,version, disable_on_vlan = True):
    output = ''
    for vlan,ip_add in sag_dict.items():
        if disable_on_vlan != True: 
            cmd = "sudo config vlan static-anycast-gateway disable {}\n".format(vlan)
            output += cmd
        if version == "ipv6":
            cmd = "sudo config interface ip remove Vlan{} {}/64\n".format(vlan, ip_add)
            output += cmd
        else:
            cmd = "sudo config interface ip remove Vlan{} {}/24\n".format(vlan, ip_add)
            output += cmd   
    return output

def config_sag_mac(add = True):
    if add:
        output = "sudo config static-anycast-gateway mac_address add 00:11:22:33:44:55"
    else:
        output = "sudo config static-anycast-gateway mac_address del"
    return output

def svi_config(sag_dict,version, mode = 'add'):
    output = ''
    
    for vlan,ip_add in sag_dict.items():
        if mode == 'del':
            if version == "ipv6":
                cmd = "sudo config interface ip remove Vlan{} {}/64\n".format(vlan, ip_add)
            else:
                cmd = "sudo config interface ip remove Vlan{} {}/24\n".format(vlan, ip_add)
        else:
            if version == "ipv6":
                cmd = "sudo config interface ip add Vlan{} {}/64\n".format(vlan, ip_add)
            else:
                cmd = "sudo config interface ip add Vlan{} {}/24\n".format(vlan, ip_add)
        output += cmd
    
    return output

def generate_new_v6_ip(ip_add,vlan):
    temp_list = ip_add.split(':')
    temp_list[1] = str(vlan)
    return ':'.join(temp_list)

def generate_new_v4_ip(ip_add,vlan):
    temp_list = ip_add.split('.')
    temp_list[1] = str(vlan)
    return '.'.join(temp_list)

def generate_svi_ip_sag(config,version,**kwargs):
    '''
    {'leaf0': {2: '8000:2::1', 3: '8000:3::1', 4: '8000:4::1', 5: '8000:5::1'}}
    {'leaf1': {2: '8000:2::1', 3: '8000:3::1'}}
    {'leaf2': {4: '8000:4::1', 5: '8000:5::1'}}
    {'leaf3': {2: '8000:2::1', 3: '8000:3::1', 4: '8000:4::1', 5: '8000:5::1'}}
    '''
    svi_dict ={}
    if config.get('l2vni'):
        if version == 'ipv4':
            if kwargs.get('ip_start'):
                ip_start = kwargs['ip_start']
            else:
                ip_start = "80.2.0.1"
        elif version == 'ipv6':
            if kwargs.get('ip_start'):
                ip_start = kwargs['ip_start']
            else:
                ip_start = "8000:2::1"
        else:
            st.log("unknown version")
        vlan_list = list()
        if type(config['l2vni']) == list:
            for l2vni_item in config['l2vni']:
                vlan_list.append(l2vni_item['vlan_id'])
        else:
            vlan_list = range(config['l2vni']['vlan_start_range'], 
                              config['l2vni']['vlan_start_range']+config['l2vni']['count'])

        for vlan_id in vlan_list:
            if version == 'ipv4':
                new_ip = generate_new_v4_ip(ip_start,vlan_id)
            else:
                new_ip = generate_new_v6_ip(ip_start,vlan_id)
            svi_dict[vlan_id] = new_ip
        new_ip = ip_start
     
    return svi_dict

###Generate host info###
def generate_sag_hosts(l2vni_intf_dict,svi_dict,version = "ipv4", custom_mac_enable = False, 
                       custom_start_mac = "00:00:00:00:99:10", skip_nodes = ['leaf3'], 
                       port_vlan_dict = {}):
    host_dict = {}
    if custom_mac_enable:
        start_mac = custom_start_mac
        temp_mac = custom_start_mac
    else:
        if version == "ipv4":
            start_mac = "00:00:00:00:04:10"
            temp_mac = "00:00:00:00:04:10"
        else:
            start_mac = "00:00:00:00:06:10"
            temp_mac = "00:00:00:00:06:10"

    '''
    svi_dict = {'leaf0': {2: '80.2.0.1', 3: '80.3.0.1', 4: '80.4.0.1', 5: '80.5.0.1'},
    'leaf1': {2: '80.2.0.1', 3: '80.3.0.1'}, 'leaf2': {4: '80.4.0.1', 5: '80.5.0.1'}}
    l2vni_intf_dict = {'leaf1': ['T1D6P1', 'T1D6P2'], 'leaf0': ['T1D5P1', 'T1D5P2'], 
    'leaf3': ['T1D8P1', 'T1D8P2'], 'leaf2': ['T1D7P1', 'T1D7P2']}

    output: 
    {'leaf0': {'T1D5P1': {2: {'vlan': 2, 'gateway': '80.2.0.1', 'host_ip': '80.2.0.10', 'src_mac': '00:02:00:00:00:10'},
      3: {'vlan': 3, 'gateway': '80.3.0.1', 'host_ip': '80.3.0.10', 'src_mac': '00:03:00:00:00:10'}, 
      4: {'vlan': 4, 'gateway': '80.4.0.1', 'host_ip': '80.4.0.10', 'src_mac': '00:04:00:00:00:10'},
        5: {'vlan': 5, 'gateway': '80.5.0.1', 'host_ip': '80.5.0.10', 'src_mac': '00:05:00:00:00:10'}}, 
        'T1D5P2': {2: {'vlan': 2, 'gateway': '80.2.0.1', 'host_ip': '80.2.0.20', 'src_mac': '00:02:00:00:00:11'}, 
        3: {'vlan': 3, 'gateway': '80.3.0.1', 'host_ip': '80.3.0.20', 'src_mac': '00:03:00:00:00:11'}, 
        4: {'vlan': 4, 'gateway': '80.4.0.1', 'host_ip': '80.4.0.20', 'src_mac': '00:04:00:00:00:11'},
          5: {'vlan': 5, 'gateway': '80.5.0.1', 'host_ip': '80.5.0.20', 'src_mac': '00:05:00:00:00:11'}}}, 
          'leaf1': {'T1D6P1': {2: {'vlan': 2, 'gateway': '80.2.0.1', 'host_ip': '80.2.0.40', 'src_mac': '00:02:00:00:00:20'}, 
          3: {'vlan': 3, 'gateway': '80.3.0.1', 'host_ip': '80.3.0.40', 'src_mac': '00:03:00:00:00:20'}}, 
          'T1D6P2': {2: {'vlan': 2, 'gateway': '80.2.0.1', 'host_ip': '80.2.0.50', 'src_mac': '00:02:00:00:00:21'}, 
          3: {'vlan': 3, 'gateway': '80.3.0.1', 'host_ip': '80.3.0.50', 'src_mac': '00:03:00:00:00:21'}}}, 
          'leaf2': {'T1D7P1': {4: {'vlan': 4, 'gateway': '80.4.0.1', 'host_ip': '80.4.0.70', 'src_mac': '00:04:00:00:00:30'}, 
          5: {'vlan': 5, 'gateway': '80.5.0.1', 'host_ip': '80.5.0.70', 'src_mac': '00:05:00:00:00:30'}}, 'T1D7P2': 
          {4: {'vlan': 4, 'gateway': '80.4.0.1', 'host_ip': '80.4.0.80', 'src_mac': '00:04:00:00:00:31'},
            5: {'vlan': 5, 'gateway': '80.5.0.1', 'host_ip': '80.5.0.80', 'src_mac': '00:05:00:00:00:31'}}}}
    '''
    temp_inc = 9
    for node in sorted(svi_dict.keys()):
        values = svi_dict[node]
        if not node in skip_nodes:
            host_dict[node] = {}
            for item in l2vni_intf_dict[node]:
                if type(item) == dict:
                    # port channel type
                    item = item['name']
                host_dict[node][item] = {}
                for vlan, svi_ip in values.items():
                    if port_vlan_dict and vlan not in port_vlan_dict[item]:
                        continue
                    host_dict[node][item][vlan] = {}
                    host_dict[node][item][vlan]['vlan']=vlan
                    host_dict[node][item][vlan]['gateway'] = svi_ip
                    host_dict[node][item][vlan]['host_ip'] = str(ipaddress.ip_address(unicode(svi_ip)) + temp_inc)
                    new_mac = generate_new_mac(start_mac,vlan)
                    host_dict[node][item][vlan]['src_mac'] = new_mac
                start_mac = generate_new_mac(start_mac,inc=1)

                temp_inc+=10
            start_mac = generate_new_mac(temp_mac,inc=10)
            temp_mac = start_mac
            temp_inc+=10    
        
    return host_dict

def generate_new_mac(start_mac,vlan = 0,inc = 0):
    desired_width = 2
    temp_list = start_mac.split(":")
    if len(str(vlan)) > 2:
        out_list = [str(vlan)[i:i+2] for i in range(0, len(str(vlan)), 2)]
        temp_list[1] = str(out_list[0]).zfill(desired_width)
        temp_list[2] = str(out_list[1]).zfill(desired_width)
        temp_list[3] = str(len(str(vlan))).zfill(desired_width)
    else:
        temp_list[1] = str(vlan).zfill(desired_width)
        temp_list[-1]= str(int(temp_list[-1])+inc).zfill(desired_width)
    return ':'.join(temp_list)

###GET topology HANDLES###
def create_topology_handles(l2vni_intf_dict):
   
    topo_handles_dict = {}
    for node in sorted(l2vni_intf_dict.keys()):
        port_ids = l2vni_intf_dict[node]

        topo_handles_dict[node]={}
        for port_id in port_ids:
            #create handles
            if type(port_id) == dict:
                #create lag interface
                topo_handles_dict[node][port_id['name']]={}
                topo_handles_dict[node][port_id['name']]['vport_port_ids'] = port_id['ports']
                tg_handle, handles = create_lag_handle(lag_name=port_id['name'],
                                                           ports=port_id['ports'])
                port_id = port_id['name']
                topo_handles_dict[node][port_id]['tg_handle'] = tg_handle
                topo_handles_dict[node][port_id]['port_handle'] = handles['lag_handle']
                topo_handles_dict[node][port_id]['vport_handles'] = handles['vport_handles']
                #create topology
                device_port = tg_handle.tg_topology_config(
                                            topology_name = """{} {} topology""".format(node,port_id),
                                            lag_handle = handles['lag_handle'])
            else:
                tg_handle, port_handle = tgapi.get_handle_byname(port_id)
                topo_handles_dict[node][port_id]={}
                topo_handles_dict[node][port_id]['tg_handle'] = tg_handle
                topo_handles_dict[node][port_id]['port_handle'] = port_handle
                #create topology
                device_port = tg_handle.tg_topology_config(
                                            topology_name = """{} {} topology""".format(node,port_id),
                                            port_handle = port_handle)
            topology_handle = device_port['topology_handle']
            topo_handles_dict[node][port_id]['topology_handle'] = topology_handle
    
    return topo_handles_dict

def create_device_groups(topo_handles_dict,host_dict,version = "ipv4"): 
    '''
    device_handles = {'T1D6P1': {2: '/topology:1/deviceGroup:1', 3: '/topology:1/deviceGroup:2', 4: '/topology:1/deviceGroup:3', 5: '/topology:1/deviceGroup:4'}, 
    'T1D6P2': {2: '/topology:2/deviceGroup:1', 3: '/topology:2/deviceGroup:2', 4: '/topology:2/deviceGroup:3', 5: '/topology:2/deviceGroup:4'}, 
    'T1D5P2': {2: '/topology:4/deviceGroup:1', 3: '/topology:4/deviceGroup:2', 4: '/topology:4/deviceGroup:3', 5: '/topology:4/deviceGroup:4', 
    6: '/topology:4/deviceGroup:5', 7: '/topology:4/deviceGroup:6', 8: '/topology:4/deviceGroup:7', 9: '/topology:4/deviceGroup:8'},
     'T1D5P1': {2: '/topology:3/deviceGroup:1', 3: '/topology:3/deviceGroup:2', 4: '/topology:3/deviceGroup:3', 5: '/topology:3/deviceGroup:4',
      6: '/topology:3/deviceGroup:5', 7: '/topology:3/deviceGroup:6', 8: '/topology:3/deviceGroup:7', 9: '/topology:3/deviceGroup:8'}, 
      'T1D8P2': {2: '/topology:6/deviceGroup:1', 3: '/topology:6/deviceGroup:2', 4: '/topology:6/deviceGroup:3', 5: '/topology:6/deviceGroup:4', 
      6: '/topology:6/deviceGroup:5', 7: '/topology:6/deviceGroup:6', 8: '/topology:6/deviceGroup:7', 9: '/topology:6/deviceGroup:8'}, 
      'T1D8P1': {2: '/topology:5/deviceGroup:1', 3: '/topology:5/deviceGroup:2', 4: '/topology:5/deviceGroup:3', 5: '/topology:5/deviceGroup:4',
       6: '/topology:5/deviceGroup:5', 7: '/topology:5/deviceGroup:6', 8: '/topology:5/deviceGroup:7', 9: '/topology:5/deviceGroup:8'}, 
       'T1D7P1': {8: '/topology:7/deviceGroup:1', 9: '/topology:7/deviceGroup:2', 6: '/topology:7/deviceGroup:3', 7: '/topology:7/deviceGroup:4'},
        'T1D7P2': {8: '/topology:8/deviceGroup:1', 9: '/topology:8/deviceGroup:2', 6: '/topology:8/deviceGroup:3', 7: '/topology:8/deviceGroup:4'}}

    '''
    device_handles = {}
    ethernet_handles ={}
    idx = 0
    for node in host_dict:
        ethernet_handles[node]={}
        device_handles[node]={}
        for interface in topo_handles_dict[node]:
            if not interface in host_dict[node].keys():
                continue
            device_handles[node][interface]={}
            ethernet_handles[node][interface] = {}
            for vlan, values in host_dict[node][interface].items():
                idx += 1
                device_group = topo_handles_dict[node][interface]['tg_handle'].tg_topology_config(
                    topology_handle= topo_handles_dict[node][interface]['topology_handle'],
                    device_group_name= """{} {} vlan {} Device group #{}""".format(node, version, vlan, idx ),
                    device_group_multiplier = "1",
                    device_group_enabled= "1"
                    )
                deviceGroup_handle = device_group['device_group_handle']
                device_handles[node][interface][vlan]=deviceGroup_handle
                ###Creating ethernet stack for the Device Group###
                l2_protocol = topo_handles_dict[node][interface]['tg_handle'].tg_interface_config(
                    protocol_name= """Ethernet stack #{}""".format(idx),
                    protocol_handle= deviceGroup_handle,mtu= "1500",
                    src_mac_addr= host_dict[node][interface][vlan]['src_mac'],
                    src_mac_addr_step= "00.00.00.00.00.01", 
                    vlan=1,
                    vlan_id=host_dict[node][interface][vlan]['vlan'], 
                    vlan_id_step=1,
                    vlan_id_count=1
                    )
                ethernet_handle = l2_protocol['ethernet_handle']
                ethernet_handles[node][interface][vlan] = ethernet_handle
                st.log("ethernet_handle-->{}".format(ethernet_handle))
                if version == 'ipv4':
                ### Creating IPv4 Stack for the Device Group###
                    l3_protocol = topo_handles_dict[node][interface]['tg_handle'].tg_interface_config(
                        protocol_name= """{} Stack #{}""".format(version, idx),
                        protocol_handle=ethernet_handle,
                        ipv4_resolve_gateway= "1",
                        gateway= host_dict[node][interface][vlan]['gateway'],
                        gateway_step= "0.0.0.0",
                        intf_ip_addr = host_dict[node][interface][vlan]['host_ip'],
                        intf_ip_addr_step= "0.0.0.1"
                        )
                    ipv4_handle = l3_protocol['ipv4_handle']
                    st.log("ipv4_handle-->{}".format(ipv4_handle))
                else:
                    l3_protocol = topo_handles_dict[node][interface]['tg_handle'].tg_interface_config(
                        protocol_name= """{} Stack #{}""".format(version, idx),
                        protocol_handle=ethernet_handle,
                        ipv6_resolve_gateway= "1",
                        ipv6_gateway= host_dict[node][interface][vlan]['gateway'],
                        ipv6_intf_addr = host_dict[node][interface][vlan]['host_ip'],
                        )
                    ipv6_handle = l3_protocol['ipv6_handle']
                    st.log("ipv6_handle-->{}".format(ipv6_handle))
    st.wait(10)
    return device_handles,ethernet_handles

def delete_device_groups(tg_handle, device_handle):
    tg_handle.tg_topology_config(device_group_handle =device_handle, mode = 'destroy')
    
def start_stop_protocols(tg_handle,action):
    status = 0
    action_dict = {"start":"start_all_protocols", "stop":"stop_all_protocols"}
    start_stop_protocol = tg_handle.tg_test_control(action=action_dict[action])
    if start_stop_protocol['status'] == '1':
        status = 1
    # Check to see if all sessions are up after start, if down then flap individual ones
    if action == "start":
        st.wait(20)
        st.log('Checking protocol sessions for DOWN handles after start/stop...')
        res = tg_handle.tg_protocol_info(handle='', mode='aggregate')

        # collect handles that report any sessions_down != '0'
        down_handles = [h for h, v in res.iteritems() if isinstance(v, dict) and v.get('aggregate', {}).get('sessions_down', '0') != '0']

        if down_handles:
            st.log('Flapping protocol sessions for DOWN handles.')
            for hand in down_handles:
                st.log("Stopping handle ")
                tg_handle.tg_test_control(action='stop_protocol', handle=hand)
                st.wait(3)

                st.log("Starting handle")
                tg_handle.tg_test_control(action='start_protocol', handle=hand)
            st.wait(5)

            # Re-check after flaps
            res2 = tg_handle.tg_protocol_info(handle='', mode='aggregate')
            still_down = [h for h, v in res2.iteritems()
                        if isinstance(v, dict) and v.get('aggregate', {}).get('sessions_down', '0') != '0']
            if still_down:
                st.banner("After flap, some sessions are still DOWN")
                status = 2
            else:
                st.log('All protocol sessions UP after flap.')
        else:
            st.log('No DOWN protocol sessions detected.')
    return status 
    
def find_l2_traffic_endpoints(host_info_dict):
    end_point_dict ={}
    #T1D5P1
    leaf0_interface_list = list(host_info_dict['leaf0'].keys())
    for item in leaf0_interface_list:
        if "P1" in item:
            leaf0_ref_interface = item
    leaf0_ref_vlan_list = host_info_dict['leaf0'][leaf0_ref_interface].keys()
    i = 1
    for node, interfaces in host_info_dict.items():
        for interface,values in interfaces.items():
            if interface != leaf0_ref_interface: 
                for vlan in leaf0_ref_vlan_list:
                    if vlan in list(values.keys()):
                        traffic_item = "traffic_item_"+str(i)
                        end_point_dict[traffic_item] = {}
                        end_point_dict[traffic_item]["dir"] = str(vlan)+"-->"+str(values[vlan]['vlan'])
                        end_point_dict[traffic_item]['src_vlan'] = vlan
                        end_point_dict[traffic_item]["src_int"] = leaf0_ref_interface
                        end_point_dict[traffic_item]["src_node"] = 'leaf0'
                        end_point_dict[traffic_item]['dst_vlan'] = vlan
                        end_point_dict[traffic_item]["dst_int"] = interface
                        end_point_dict[traffic_item]["dst_node"] = node
                        i+=1
    return end_point_dict

def find_l3_traffic_endpoints(host_info_dict, vrf_vlan_dict = {"1":[2,3],"2":[4,5],"3":[6,7],"4":[8,9]}):
    '''
    output:
    {'traffic_item_1': {'dir': '2-->3', 'src_vlan': 2, 'src_int': 'T1D5P1', 'dst_vlan': 3, 'dst_int': 'T1D6P1'}, 
    'traffic_item_2': {'dir': '3-->2', 'src_vlan': 3, 'src_int': 'T1D5P1', 'dst_vlan': 2, 'dst_int': 'T1D6P1'}, 
    'traffic_item_3': {'dir': '4-->5', 'src_vlan': 4, 'src_int': 'T1D5P1', 'dst_vlan': 5, 'dst_int': 'T1D6P1'}, 
    'traffic_item_4': {'dir': '5-->4', 'src_vlan': 5, 'src_int': 'T1D5P1', 'dst_vlan': 4, 'dst_int': 'T1D6P1'}, 
    'traffic_item_5': {'dir': '2-->3', 'src_vlan': 2, 'src_int': 'T1D5P1', 'dst_vlan': 3, 'dst_int': 'T1D6P2'}, 
    'traffic_item_6': {'dir': '3-->2', 'src_vlan': 3, 'src_int': 'T1D5P1', 'dst_vlan': 2, 'dst_int': 'T1D6P2'}, 
    'traffic_item_7': {'dir': '4-->5', 'src_vlan': 4, 'src_int': 'T1D5P1', 'dst_vlan': 5, 'dst_int': 'T1D6P2'}, 
    'traffic_item_8': {'dir': '5-->4', 'src_vlan': 5, 'src_int': 'T1D5P1', 'dst_vlan': 4, 'dst_int': 'T1D6P2'}, 
    'traffic_item_9': {'dir': '2-->3', 'src_vlan': 2, 'src_int': 'T1D5P1', 'dst_vlan': 3, 'dst_int': 'T1D5P2'}, 
    'traffic_item_10': {'dir': '3-->2', 'src_vlan': 3, 'src_int': 'T1D5P1', 'dst_vlan': 2, 'dst_int': 'T1D5P2'}, 
    'traffic_item_11': {'dir': '4-->5', 'src_vlan': 4, 'src_int': 'T1D5P1', 'dst_vlan': 5, 'dst_int': 'T1D5P2'}, 
    'traffic_item_12': {'dir': '5-->4', 'src_vlan': 5, 'src_int': 'T1D5P1', 'dst_vlan': 4, 'dst_int': 'T1D5P2'}, 
    'traffic_item_13': {'dir': '6-->7', 'src_vlan': 6, 'src_int': 'T1D5P1', 'dst_vlan': 7, 'dst_int': 'T1D5P2'}, 
    'traffic_item_14': {'dir': '7-->6', 'src_vlan': 7, 'src_int': 'T1D5P1', 'dst_vlan': 6, 'dst_int': 'T1D5P2'}, 
    'traffic_item_15': {'dir': '8-->9', 'src_vlan': 8, 'src_int': 'T1D5P1', 'dst_vlan': 9, 'dst_int': 'T1D5P2'}, 
    'traffic_item_16': {'dir': '9-->8', 'src_vlan': 9, 'src_int': 'T1D5P1', 'dst_vlan': 8, 'dst_int': 'T1D5P2'}, 
    'traffic_item_17': {'dir': '6-->7', 'src_vlan': 6, 'src_int': 'T1D5P1', 'dst_vlan': 7, 'dst_int': 'T1D8P2'}, 
    'traffic_item_18': {'dir': '7-->6', 'src_vlan': 7, 'src_int': 'T1D5P1', 'dst_vlan': 6, 'dst_int': 'T1D8P2'}, 
    'traffic_item_19': {'dir': '8-->9', 'src_vlan': 8, 'src_int': 'T1D5P1', 'dst_vlan': 9, 'dst_int': 'T1D8P2'}, 
    'traffic_item_20': {'dir': '9-->8', 'src_vlan': 9, 'src_int': 'T1D5P1', 'dst_vlan': 8, 'dst_int': 'T1D8P2'}, 
    'traffic_item_21': {'dir': '6-->7', 'src_vlan': 6, 'src_int': 'T1D5P1', 'dst_vlan': 7, 'dst_int': 'T1D8P1'}, 
    'traffic_item_22': {'dir': '7-->6', 'src_vlan': 7, 'src_int': 'T1D5P1', 'dst_vlan': 6, 'dst_int': 'T1D8P1'}, 
    'traffic_item_23': {'dir': '8-->9', 'src_vlan': 8, 'src_int': 'T1D5P1', 'dst_vlan': 9, 'dst_int': 'T1D8P1'}, 
    'traffic_item_24': {'dir': '9-->8', 'src_vlan': 9, 'src_int': 'T1D5P1', 'dst_vlan': 8, 'dst_int': 'T1D8P1'}, 
    'traffic_item_25': {'dir': '6-->7', 'src_vlan': 6, 'src_int': 'T1D5P1', 'dst_vlan': 7, 'dst_int': 'T1D7P1'}, 
    'traffic_item_26': {'dir': '7-->6', 'src_vlan': 7, 'src_int': 'T1D5P1', 'dst_vlan': 6, 'dst_int': 'T1D7P1'}, 
    'traffic_item_27': {'dir': '8-->9', 'src_vlan': 8, 'src_int': 'T1D5P1', 'dst_vlan': 9, 'dst_int': 'T1D7P1'}, 
    'traffic_item_28': {'dir': '9-->8', 'src_vlan': 9, 'src_int': 'T1D5P1', 'dst_vlan': 8, 'dst_int': 'T1D7P1'}, 
    'traffic_item_29': {'dir': '6-->7', 'src_vlan': 6, 'src_int': 'T1D5P1', 'dst_vlan': 7, 'dst_int': 'T1D7P2'}, 
    'traffic_item_30': {'dir': '7-->6', 'src_vlan': 7, 'src_int': 'T1D5P1', 'dst_vlan': 6, 'dst_int': 'T1D7P2'}, 
    'traffic_item_31': {'dir': '8-->9', 'src_vlan': 8, 'src_int': 'T1D5P1', 'dst_vlan': 9, 'dst_int': 'T1D7P2'}, 
    'traffic_item_32': {'dir': '9-->8', 'src_vlan': 9, 'src_int': 'T1D5P1', 'dst_vlan': 8, 'dst_int': 'T1D7P2'}}

    '''
    temp_dict = {}
    leaf0_interface_list = list(host_info_dict['leaf0'].keys())
    for item in leaf0_interface_list:
        if "P1" in item:
            leaf0_ref_interface = item
    leaf0_ref_vlan_list = host_info_dict['leaf0'][leaf0_ref_interface].keys()
    for node, interfaces in host_info_dict.items():
        for interface,int_vlan_attr in interfaces.items():
            temp_dict[interface]={'node': node, 'vrf': {}}
            for vrf, vlan_list in vrf_vlan_dict.items():
                temp_dict[interface]['vrf'][vrf] = []
                for vlan in vlan_list:
                    if int_vlan_attr.get(vlan):
                        temp_dict[interface]['vrf'][vrf].append(vlan)
                if len(temp_dict[interface]['vrf'][vrf]) is 0:
                    temp_dict[interface]['vrf'].pop(vrf)
    l3_endpoint_dict = {}
    def find_pair(src_vlans,dst_vlans):
        pair_dict = {}
        i=1
        for src_vlan in src_vlans:
            for dst_vlan in dst_vlans:
                if src_vlan != dst_vlan:
                    pair_dict[i] = (src_vlan,dst_vlan)
                    i+=1    
        return pair_dict
    i=1
    for interface, val in temp_dict.items():
        dst_node = val['node']
        vrf_dict = val['vrf']
        if interface != leaf0_ref_interface:
            for vrf,vlans in vrf_dict.items():
                pair_dict = find_pair(temp_dict[leaf0_ref_interface]['vrf'][vrf],vlans)
                for cntr, vlan_pair in pair_dict.items():
                    traffic_item = "traffic_item_"+str(i)
                    l3_endpoint_dict[traffic_item] = {}
                    l3_endpoint_dict[traffic_item]["dir"] = str(vlan_pair[0])+"-->"+str(vlan_pair[1])
                    l3_endpoint_dict[traffic_item]['src_vlan'] = vlan_pair[0]
                    l3_endpoint_dict[traffic_item]["src_int"] = leaf0_ref_interface
                    l3_endpoint_dict[traffic_item]["src_node"] = 'leaf0'
                    l3_endpoint_dict[traffic_item]["src_vrf"] = vrf
                    l3_endpoint_dict[traffic_item]['dst_vlan'] = vlan_pair[1]
                    l3_endpoint_dict[traffic_item]["dst_int"] = interface
                    l3_endpoint_dict[traffic_item]["dst_node"] = dst_node
                    l3_endpoint_dict[traffic_item]["dst_vrf"] = vrf
                    i+=1
    return l3_endpoint_dict

def create_traffic_item(device_handles, endpoints, topo_handles, transmit_mode="single_burst",
                        version = "ipv4", udp_header = False, multi_dst = None, name_prfx='TI', 
                        circuit_type='default', rx_all_ports=False, 
                        rate_percent=0, pkts_per_burst=0, frame_size=0):
    '''
    
    Example: endpoints for bum traffic
    {'traffic_item_T1D5P1_4': 
    {'dst_int': 'PortChannel3_D8D7', 'dst_node': 'leaf2', 'dst_mac': '00:99:00:00:00:99', 
    'dst_vlan': 2, 'dst_vrf': 101, 
    'src_vlan': 2, 'src_node': 'leaf0', 'src_int': 'T1D5P1', 'src_mac': '00:02:00:00:04:10', 
    'src_vrf': 101}, 
    'traffic_item_T1D5P1_3': 
    {'dst_int': 'T1D7P1', 'dst_node': 'leaf2', 'dst_mac': '00:99:00:00:00:99', 
    'dst_vlan': 2, 'dst_vrf': 101, 
    'src_vlan': 2, 'src_node': 'leaf0', 'src_int': 'T1D5P1', 'src_mac': '00:02:00:00:04:10', 
    'src_vrf': 101}, 
    }
    '''
    dut_type = check_hw_or_sim(st.get_dut_names()[0])
    if dut_type == 'sim':
        rate = 0.01
        ppb = 100
    else:
        rate = 10
        ppb = 1000
        if rate_percent:
            rate = rate_percent
        if pkts_per_burst:
            ppb = pkts_per_burst
    frame = 500
    if frame_size:
        frame = frame_size
        
    port_handles = {}
    all_handles = []
    for node, interfaces in topo_handles.items():
        for interface,values in interfaces.items():
            port_handles[interface] =values        
            all_handles.append(values['port_handle'])

    stream_handles = {}
    traffic_item_list = natsort.natsorted(set(list(endpoints.keys())))
    i=1
    multi_pointed_traffic_items = list()
    for traffic_item in traffic_item_list:  
        if traffic_item in multi_pointed_traffic_items:
            # this traffic item has been combined with another traffic
            # item with multiple end points
            continue

        name = '{}-{}:'.format(name_prfx,version)
        #name += '{}_'.format(endpoints[traffic_item]['src_node'])
        name += '{}'.format(endpoints[traffic_item]['src_int'])
        if endpoints[traffic_item].get('src_vrf'):
            name += '_vrf{}'.format(endpoints[traffic_item]['src_vrf'])
        name += '_vlan{}--'.format(endpoints[traffic_item]['src_vlan'])
        if circuit_type == 'raw':
            emulation_src_handle = topo_handles[endpoints[traffic_item]['src_node']][endpoints[traffic_item]['src_int']]['port_handle']
        else:
            emulation_src_handle = device_handles[endpoints[traffic_item]['src_int']][endpoints[traffic_item]['src_vlan']]
        tg_handle = port_handles[endpoints[traffic_item]['src_int']]['tg_handle']
        port_handle = port_handles[endpoints[traffic_item]['src_int']]['port_handle']
        if multi_dst:
            dst_vlan = list()
            dst_vrf = list()
            dst_node = list()
            dst_int = list()
            emulation_dst_handle = list()
            emulation_dst_port = list()
            for sim_traffic_item in traffic_item_list:
                flag = False
                if multi_dst == 'vlan' and endpoints[sim_traffic_item]['dst_vlan'] == endpoints[traffic_item]['dst_vlan']:
                    dst_vlan = [str(endpoints[sim_traffic_item]['dst_vlan'])]     
                    flag = True
                elif multi_dst == 'vrf' and endpoints[sim_traffic_item]['dst_vrf'] == endpoints[traffic_item]['dst_vrf'] and \
                                             endpoints[sim_traffic_item]['src_vlan'] == endpoints[traffic_item]['src_vlan']:
                    dst_vrf = [str(endpoints[sim_traffic_item]['dst_vrf'])]
                    dst_vlan.append(str(endpoints[sim_traffic_item]['dst_vlan']))
                    flag = True
            
                if flag:
                    multi_pointed_traffic_items.append(sim_traffic_item)
                    if circuit_type == 'raw':
                        dst_hdl = topo_handles[endpoints[sim_traffic_item]['dst_node']][endpoints[sim_traffic_item]['dst_int']]['port_handle']
                    else:
                        dst_hdl = device_handles[endpoints[sim_traffic_item]['dst_int']][endpoints[sim_traffic_item]['dst_vlan']]
                    emulation_dst_handle.append(dst_hdl)
                    emulation_dst_port.append((endpoints[sim_traffic_item]['dst_int'], dst_hdl))
                    dst_int.append(str(endpoints[sim_traffic_item]['dst_int']))
                    dst_node.append(str(endpoints[sim_traffic_item]['dst_node']))

            dst_node = '_'.join(dst_node)
            dst_vlan = '_'.join(dst_vlan)
            dst_int = '_'.join(dst_int)
            #name += '{}_'.format(dst_node)
            name += '{}'.format(dst_int)
            if dst_vrf:
                dst_vrf = '_'.join(dst_vrf)
                name += '_vrf{}'.format(dst_vrf)
            # name += '_vlan{}'.format(dst_vlan)
        else:
            if circuit_type == 'raw':
                emulation_dst_handle = topo_handles[endpoints[traffic_item]['dst_node']][endpoints[traffic_item]['dst_int']]['port_handle']
            else:
                emulation_dst_handle = device_handles[endpoints[traffic_item]['dst_int']][endpoints[traffic_item]['dst_vlan']]
            emulation_dst_port = [(endpoints[traffic_item]['dst_int'], emulation_dst_handle)]
            #name += '{}_'.format(endpoints[traffic_item]['dst_node'])
            name += '{}'.format(endpoints[traffic_item]['dst_int'])
            if endpoints[traffic_item].get('dst_vrf'):
                name += '_vrf{}'.format(endpoints[traffic_item]['dst_vrf'])
            name += '_vlan{}'.format(endpoints[traffic_item]['dst_vlan'])
    
        kwargs = {
            'name' : name,
            'mode': 'create',
            'bidirectional': 1,
            'transmit_mode': transmit_mode,
            'pkts_per_burst': ppb,
            'rate_percent': rate,
            'circuit_endpoint_type': version,
            'frame_size': frame,
            'emulation_src_handle': emulation_src_handle,
            'emulation_dst_handle': emulation_dst_handle,
            'track_by':  'traffic_item',
        }

        if rx_all_ports: 
            kwargs['emulation_dst_handle'] = list()      
            for dst_handle in all_handles:
                if not dst_handle == kwargs['emulation_src_handle']:
                    kwargs['emulation_dst_handle'].append(dst_handle)      

        if circuit_type == 'raw':
            kwargs['circuit_type'] = 'raw' 
            kwargs['mac_src'] = endpoints[traffic_item]['src_mac']
            kwargs['mac_dst'] = endpoints[traffic_item]['dst_mac']
            kwargs['vlan_id'] = endpoints[traffic_item]['dst_vlan']
            kwargs['src_dest_mesh'] ='one_to_one'
            kwargs['track_by'] = 'endpoint_pair'

        if udp_header:
            kwargs['l4_protocol'] ='udp'
        if transmit_mode == "single_burst" or transmit_mode == "continuous":
            kwargs['transmit_mode'] = transmit_mode
        else:
            #add continous mode support
            st.log("Unknown transmit type")
            return stream_handles

        stream = tg_handle.tg_traffic_config(**kwargs)

        stream_id = stream["stream_id"]
        stream_handles[i] = {}
        stream_handles[i]['stream_id'] = stream_id
        stream_handles[i]['tg_handle'] = tg_handle
        stream_handles[i]['port_handle'] = port_handle
        stream_handles[i]['dst_ports'] = emulation_dst_port
        i+=1
        st.wait(1) 
    return stream_handles

def delete_traffic_item(tg_handle, stream_handle):
    if type(stream_handle) == dict:
        for cntr, streamh in stream_handle.items():
            tg_handle.tg_traffic_config(mode = 'remove', stream_id = streamh['stream_id'])

    else:
        tg_handle.tg_traffic_config(mode = 'remove', stream_id = stream_handle)
    
def check_traffic(streams_info, regenerate_traffic_items = False, mode='traffic_item', action='default', 
                  stop_start_protocols=True, stop_proto_wait=15, start_proto_wait=15, min_perc=99.8, max_perc=100.2 ):
    '''
    Author:Ramsiddarth Ragurajan (rraguraj@cisco.com)
    acions : start/stop/check/default(does start->stop->check)

    '''
    flag = True
    stream_list = []
    line = '-'*80
    for item , values in streams_info.items():
        if values.get('verify_enabled', True):
            stream_list.append(values['stream_id'])
    tg_handle = streams_info[item]['tg_handle']
    ###Enable streams
    if action != 'check':
        tg_handle.tg_traffic_config(mode = 'enable', stream_id = stream_list)

    ###stop/start all protocols###
    if action == 'start' or action == 'default':
        if stop_start_protocols:
            start_stop_protocols(tg_handle,'stop')
            st.wait(stop_proto_wait)
            start_stop_protocols(tg_handle,'start')
            st.wait(start_proto_wait)
        else:
            ###
            res2 = tg_handle.tg_protocol_info(handle='', mode='aggregate')
            protocols_down = [h for h, v in res2.iteritems() if isinstance(v, dict) and v.get('aggregate', {}).get('sessions_down', '0') != '0']
            if protocols_down:
                st.banner("Some sessions are DOWN")
            else:
                st.banner('All protocol sessions UP')
            ###


        ###start traffic###
        if regenerate_traffic_items and action != 'check':
            tg_handle.tg_traffic_control(action='regenerate', stream_handle=stream_list)
            tg_handle.tg_traffic_control(action='apply', stream_handle=stream_list)
            st.wait(10)

        tg_handle.tg_traffic_control(action='run', stream_handle=stream_list)
        st.wait(15)

    if action == 'start':
        return flag

    ###Stop Traffic###
    tg_handle.tg_traffic_control(action='stop', stream_handle=stream_list)
    st.wait(10)

    if action == 'stop':
        return flag

    traffic_stat = tg_handle.tg_traffic_stats(mode= mode, streams=stream_list)
    ###Disable streams .
    tg_handle.tg_traffic_config(mode = 'disable', stream_id = stream_list)

    if mode == 'traffic_item':
        row_format = '|{:20}|{:20}|{:20}|{:15}|'
        for stream_id in traffic_stat['traffic_item'].keys():
            if not stream_id.startswith('TI'): continue

            st.banner("TRAFFIC ITEM {}".format(stream_id))
            st.log(line)
            st.log(row_format.format('Expected Rx', 'Actual Rx', '%', 'Result'))
            st.log(row_format.format('', '', 
                                     '({}%-{}%)'.format(str(min_perc),str(max_perc)), ''))
            st.log(line)
            exp_rx = int(traffic_stat['traffic_item'][stream_id]['tx']['total_pkts'])
            rx = int(traffic_stat['traffic_item'][stream_id]['rx']['total_pkts'])
            perc = rx / float(exp_rx) * 100
            if perc > min_perc and perc < max_perc:
                st.log(row_format.format(str(exp_rx), str(rx), 
                                         '{:.2f}'.format(perc), 'PASS'))
                st.log(line)
                st.log("TRAFFIC ITEM {} PASSED".format(stream_id))
            else:
                st.log(row_format.format(str(exp_rx), str(rx), 
                                         '{:.2f}'.format(perc), 'FAIL'))
                st.log(line)
                st.log("TRAFFIC ITEM {} FAILED".format(stream_id))
                flag = False
                
    elif mode == 'flow':
        row_format = '|{:19}|{:15}|{:15}|{:15}|{:10}|'
        for item , stream_info in streams_info.items():
            stream_id = stream_info['stream_id']
            if not stream_id.startswith('TI'): continue

            stream_result=True
            st.banner("TRAFFIC ITEM {}".format(stream_id))
            st.log(line)
            st.log(row_format.format('Port', 'Expected Rx' , 'Actual Rx', '%', 'Result'))
            st.log(row_format.format('', '', '', 
                                     '({}%-{}%)'.format(str(min_perc),str(max_perc)), ''))
            st.log(line)
            for flow_id, flow_info in traffic_stat['flow'].items():
                port,flow_name = flow_info['flow_name'].split(' ')
                if stream_id == flow_name:
                    rx = int(flow_info['rx']['total_pkts'])
                    for dst_int,dst_handle in stream_info['dst_ports']:
                        if port == dst_int or port == dst_handle:
                            exp_rx = int(flow_info['tx']['total_pkts'])
                            perc = rx / float(exp_rx) * 100
                            result = perc > min_perc and perc < max_perc
                            perc = '{:.2f}'.format(perc)
                            break
                    else:
                        exp_rx = 0
                        if rx == exp_rx: 
                            perc = '100.00' 
                            result = True
                        else:
                            perc = '~'
                            result = False

                    if result:
                        st.log(row_format.format(port, str(exp_rx), str(rx), perc , 'PASS'))
                    else:
                        st.log(row_format.format(port, str(exp_rx), str(rx), perc, 'FAIL'))
                        stream_result = False
            if stream_result:
                st.log(line)
                st.log("TRAFFIC ITEM {} PASSED".format(stream_id))
            else:
                st.log(line)
                st.log("TRAFFIC ITEM {} FAILED".format(stream_id))
                flag = False
                  
    return flag

def create_lag_handle(lag_name, ports):
    lag_vport_list = list()
    port_list = list()
    for port in ports:
        tg, port_handle = tgapi.get_handle_byname(port)
        port_list.append(port_handle)
        vporthandle_status = tg.tg_convert_porthandle_to_vport(port_handle=port_handle)
        vport_handle = vporthandle_status['handle'].split('-')[-1]
        lag_vport_list.append(vport_handle)

    st.log("Creating Lag with ports {}".format(port_list))
    _result_ = tg.tg_emulation_lag_config( mode= "create", port_handle=lag_vport_list, active= "1", 
                                          lag_name= """{}""".format(lag_name),
                                          protocol_type= "lag_port_lacp")
    _result_['vport_handles'] = lag_vport_list
    return (tg , _result_)

def check_hw_or_sim(node):
    dut_type = ""
    cmd_output = st.config(node,"cat /proc/cpuinfo | grep '^model name.: VXR$'")
    try:
        if 'VXR' in str(cmd_output.encode('ascii','ignore')):
            dut_type = "sim"
        else:
            dut_type = "hw"
    except:
        dut_type = "hw"
    return dut_type

def clear_counters(nodes):
    for node in nodes:
        st.config(node, " sonic-clear counters")
        st.config(node, " sonic-clear tunnelcounters")

def show_counters(nodes):
    for node in nodes:
        st.log(st.config(node, " show int counters"))
        st.log(st.config(node, " show vxlan counters"))

def get_cli_out(nodes):
    #sonic
    cmd_list_1 = ["show interfaces status",
                  "show bfd summary",
                  "show mac",
                  "show arp",
                  "show nd",
                  "show vlan brief",
                  "show ip int",
                  "show int portchannel",
                  "show vxlan tunnel",
                  "show vxlan remotemac all",
                  "show vxlan remotevtep",
                  "show vrf",
                  "show ipv6 route vrf all",
                  "show ip route vrf all"]
    #vtysh
    cmd_list_2 = ["do show bgp summary",
                  "do show bgp l2vpn evpn route type 1",
                  "do show bgp l2vpn evpn route type 2",
                  "do show bgp l2vpn evpn route type 3",
                  "do show bgp l2vpn evpn route type 4",
                  "do show bgp l2vpn evpn route type 5"]

    for node in nodes:
        for item in cmd_list_1:
            st.config(node, item)
        for item in cmd_list_2:
            st.config(node, item, type='vtysh', skip_error_check=True)

def delete_vrf(node, vrf_id, only_vtysh=False):
    ##vtysh
    #find vni mapping 
    cli_output = st.show(node, "show vxlan vrfvnimap", skip_tmpl=True)
    parsed_output = st.parse_show(node, "show vxlan vrfvnimap",cli_output, "show_vxlan_vrfvnimap.tmpl")
    ref_vni = ""
    as_num = generate_bgp_underlay_info()[node]['as_num']
    for item in parsed_output:
        if item['vrf'] == vrf_id:
            ref_vni = item['vni']
    cmd = "vrf {}\n".format(vrf_id)
    cmd += "no vni {}\n".format(ref_vni)
    cmd += 'no router bgp {} vrf {}\n'.format(as_num, vrf_id)
    cmd += 'exit\n' 
    st.config(node, cmd, type='vtysh', skip_error_check=True)

    if only_vtysh:
        st.log("Only done in vtysh config")
        return

    ##sonic
    #find interface mapping for vrf and unbind
    cli_output = st.show(node, "show vrf", skip_tmpl=True)
    parsed_output = st.parse_show(node, "show vrf",cli_output, "show_vrf.tmpl")
    for item in parsed_output:
        if item['vrfname'] == vrf_id:
            interface_list = item['interfaces']
    for interface in interface_list:
        vrf_obj.bind_vrf_interface(dut = node, vrf_name = vrf_id, intf_name =interface, config = 'no')
    out = vrf_obj.config_vrf(dut = node, vrf_name = vrf_id, config = 'no')
    return out

def bgp_vrf_config(node, vrf):
    output = ""
    as_num = generate_bgp_underlay_info()[node]['as_num']
    vni = 5000 + int(vrf.split("Vrf")[1])
    output += 'router bgp {} vrf {}\n'.format(as_num, vrf)
    output += 'address-family ipv4 unicast\n'
    output += 'redistribute connected\n'
    output += 'exit-address-family\n'
    output += 'address-family ipv6 unicast\n'
    output += 'redistribute connected\n'
    output += 'exit-address-family\n'
    output += 'address-family l2vpn evpn\n'
    output += 'advertise ipv4 unicast\n'
    output += 'advertise ipv6 unicast\n'
    output += 'exit-address-family\n'
    output += 'exit\n'
    output += 'vrf {}\n'.format(vrf)
    output += 'vni {}\n'.format(vni)
    output += 'end\n'
    output += 'exit\n'
    return output

def generate_bum_handles(bum_info,svi_info,transmit_mode="single_burst",ip_version = "ipv4"):
    '''
    Author:Ramsiddarth Ragurajan (rraguraj@cisco.com)
    bum_info['tg_handle'] = topo_handles[leaf_nodes[0]][l2vni_intf_dict[leaf_nodes[0]][0]]['tg_handle']
    bum_info['topology_handle'] = topo_handles[leaf_nodes[0]][l2vni_intf_dict[leaf_nodes[0]][0]]['topology_handle']
    bum_info['port_handle'] = topo_handles[leaf_nodes[0]][l2vni_intf_dict[leaf_nodes[0]][0]]['port_handle']
    bum_info['dst_port_handles'] = []
    dst_port_handles = ['1/1/3', '1/1/4', '1/1/2', '1/1/5', '1/1/6','1/1/7','1/1/8']
    '''
    bum_handles = {}
    bum_handles['tg_handle'] = bum_info['tg_handle']
    bum_handles['port_handle']  = bum_info['port_handle']
    dut_type = check_hw_or_sim(st.get_dut_names()[0])
    if dut_type == 'sim':
        rate_percent = 0.01
        pkts_per_burst = 100
        transmit_mode = 'single_burst'
    else:
        rate_percent = 1
        pkts_per_burst = 1000
        transmit_mode = transmit_mode
    #choose 1 vlan per VRF fro bum
    config_dict = get_cfg_dict()
    vlan_start_range = config_dict['leaf0']['l2vni']['vlan_start_range']
    count = config_dict['leaf0']['l2vni']['count']
    bum_dict = {"unknown": "00:99:00:00:00:99", "broadcast":"ff:ff:ff:ff:ff:ff", "multicast":"01:00:5e:44:44:44"}
    vlan_list = list(range(vlan_start_range,(count+vlan_start_range),2))
    # start_mac = "00:00:00:00:00:99"
    if transmit_mode == "single_burst":
        if ip_version == "ipv4":
            for vlan in vlan_list:
                bum_handles[vlan] = {}
                for bum_type, value in bum_dict.items():
                    bum_handles[vlan][bum_type] ={}
                    stream = bum_info['tg_handle'].tg_traffic_config(
                        port_handle=bum_info['port_handle'], 
                        port_handle2=bum_info['dst_port_handles'], 
                        mode='create',
                        transmit_mode=transmit_mode, 
                        pkts_per_burst=pkts_per_burst, 
                        rate_percent = rate_percent, 
                        circuit_endpoint_type='ethernet_vlan', 
                        frame_size=1000, 
                        mac_src=svi_info[vlan]['src_mac'], 
                        mac_dst= value,
                        vlan_id = vlan
                        
                        )
                    bum_handles[vlan][bum_type]['stream_id'] = stream["stream_id"]
    return bum_handles

def check_bum_traffic(streams, regenerate_traffic_items = False):
    '''
    Author:Ramsiddarth Ragurajan (rraguraj@cisco.com)
    {2: {'broadcast': {'stream_id': 'TI48-HLTAPI_TRAFFICITEM_540'}, 'unknown': {'stream_id': 'TI49-HLTAPI_TRAFFICITEM_540'}, 
    'multicast': {'stream_id': 'TI50-HLTAPI_TRAFFICITEM_540'}}, 4: {'broadcast': {'stream_id': 'TI51-HLTAPI_TRAFFICITEM_540'}, 
    'unknown': {'stream_id': 'TI52-HLTAPI_TRAFFICITEM_540'}, 'multicast': {'stream_id': 'TI53-HLTAPI_TRAFFICITEM_540'}}, 
    6: {'broadcast': {'stream_id': 'TI54-HLTAPI_TRAFFICITEM_540'}, 'unknown': {'stream_id': 'TI55-HLTAPI_TRAFFICITEM_540'},
    'multicast': {'stream_id': 'TI56-HLTAPI_TRAFFICITEM_540'}}, 8: {'broadcast': {'stream_id': 'TI57-HLTAPI_TRAFFICITEM_540'}, 
    'unknown': {'stream_id': 'TI58-HLTAPI_TRAFFICITEM_540'}, 'multicast': {'stream_id': 'TI59-HLTAPI_TRAFFICITEM_540'}}, 'port_handle': '1/1/1', 'tg_handle': <spytest.tgen.tg.TGIxia object at 0x7ff4c3077d10>}
    '''
    flag = True
    stream_list = []
    streams_info = streams
    tg_handle = streams_info['tg_handle']
    port_handle = streams_info['port_handle']
    for vlan , values in streams_info.items():
        if vlan  != 'port_handle' and vlan != 'tg_handle':
            for traffic_type, handles in values.items():
                stream_list.append(handles['stream_id'])
    #find the no of endpoints from vlan info
    expected_no_of_endpoints = 3
    ###stop/start all protocols###
    start_stop_protocols(tg_handle,'stop')
    st.wait(15)
    start_stop_protocols(tg_handle,'start')
    st.wait(15)
    ###start traffic###
    if regenerate_traffic_items:
        tg_handle.tg_traffic_control(action='regenerate', stream_handle=stream_list)
        tg_handle.tg_traffic_control(action='apply', stream_handle=stream_list)
        st.wait(10)
    tg_handle.tg_traffic_control(action='run', stream_handle=stream_list)
    st.wait(30)
    ###Stop Traffic###
    tg_handle.tg_traffic_control(action='stop', stream_handle=stream_list)
    st.wait(30)
    for traffic_item in stream_list:
        
        traffic_stat = tgapi.get_traffic_stats(tg_handle, mode='streams', port_handle=port_handle, direction='tx', stream_handle=traffic_item)
        st.banner("BUM TRAFFIC ITEM {}".format(traffic_item))
        st.log("Received traffic: {}".format(traffic_stat['rx']['total_packets']))
        st.log("Sent traffic: {}".format(traffic_stat['tx']['total_packets']))
        st.log(traffic_stat['rx']['total_packets']/traffic_stat['tx']['total_packets'])
        if traffic_stat['rx']['total_packets'] == expected_no_of_endpoints*traffic_stat['tx']['total_packets']:
            st.log("BUM TRAFFIC ITEM {} PASSED".format(traffic_item))
        else:
            st.log("BUM TRAFFIC ITEM {} FAILED".format(traffic_item))
            flag = False
                
    return flag


def generate_loopback_ip(version = 'v4'):
    '''
    {'spine0': '1000:1::1', 'spine1': '1000:1::2', 'spine2': '1000:1::3', 'spine3': '1000:1::4', 
    'leaf0': '2000:1::1', 'leaf1': '2000:1::2', 'leaf2': '2000:1::3', 'leaf3': '2000:1::4'}
    '''
    loopback_ip_dict = {}
    if version == 'v4':
        spine_start_ip = "100.0.0.1"
        leaf_start_ip = "200.0.0.1"
    else:
        spine_start_ip = "1000:1::1"
        leaf_start_ip = "2000:1::1"
    config_dict = get_cfg_dict()
    node_list = sorted(list(config_dict['nodes']['all']))
    for node in node_list:
        if "spine" in node:
            loopback_ip_dict[node] = spine_start_ip
            spine_start_ip = str(ipaddress.ip_address(unicode(spine_start_ip)) + 1)
        if "leaf" in node:
            loopback_ip_dict[node] = leaf_start_ip
            leaf_start_ip = str(ipaddress.ip_address(unicode(leaf_start_ip)) + 1)
    return loopback_ip_dict

def generate_bgp_underlay_info():
    '''
    {'spine0': {'router_id': '10.200.200.100', 'as_num': 65100}, 
    'spine1': {'router_id': '10.200.200.101', 'as_num': 65101}, 
    'spine2': {'router_id': '10.200.200.102', 'as_num': 65102}, 
    'spine3': {'router_id': '10.200.200.103', 'as_num': 65103}, 
    'leaf0': {'router_id': '10.200.200.200', 'as_num': 65200}, 
    'leaf1': {'router_id': '10.200.200.200', 'as_num': 65201}, 
    'leaf2': {'router_id': '10.200.200.200', 'as_num': 65202}, 
    'leaf3': {'router_id': '10.200.200.200', 'as_num': 65203}}

    '''
    spine_router_id_start = "10.200.200.100"
    leaf_router_id_start = "10.200.200.200"
    spine_as_no_start = 65100
    leaf_as_no_start = 65200
    bgp_info = {}
    config_dict = get_cfg_dict()
    node_list = sorted(list(config_dict.keys()))
    for node in node_list:
        bgp_info[node] = {}
        if "spine" in node:
            bgp_info[node]["router_id"] = spine_router_id_start
            bgp_info[node]["as_num"] = spine_as_no_start
            spine_as_no_start+=1
            spine_router_id_start = str(ipaddress.ip_address(unicode(spine_router_id_start)) + 1)
        if "leaf" in node:
            bgp_info[node]["router_id"] = leaf_router_id_start
            bgp_info[node]["as_num"] = leaf_as_no_start
            leaf_as_no_start+=1
            leaf_router_id_start = str(ipaddress.ip_address(unicode(leaf_router_id_start)) + 1)
    return bgp_info

def generate_bgp_overlay_info(version = 'v4'):
    '''
    {'spine0': {'router_id': '10.200.200.100', 'as_num': 65100}, 
    'spine1': {'router_id': '10.200.200.101', 'as_num': 65101}, 
    'spine2': {'router_id': '10.200.200.102', 'as_num': 65102}, 
    'spine3': {'router_id': '10.200.200.103', 'as_num': 65103}, 
    'leaf0': {'router_id': '10.200.200.200', 'as_num': 65200, 'neigbor_overlay': ['2000:1::2', '2000:1::3', '2000:1::4']}, 
    'leaf1': {'router_id': '10.200.200.200', 'as_num': 65201, 'neigbor_overlay': ['2000:1::1', '2000:1::3', '2000:1::4']}, 
    'leaf2': {'router_id': '10.200.200.200', 'as_num': 65202, 'neigbor_overlay': ['2000:1::1', '2000:1::2', '2000:1::4']}, 
    'leaf3': {'router_id': '10.200.200.200', 'as_num': 65203, 'neigbor_overlay': ['2000:1::1', '2000:1::2', '2000:1::3']}}

    '''
    loopback_dict = generate_loopback_ip(version = version)
    overlay_dict = generate_bgp_underlay_info()
    ip_list = []
    config_dict = get_cfg_dict()
    for node , ip_addr in loopback_dict.items():
        if node in config_dict['nodes']['l2l3vni']:
            ip_list.append(ip_addr)
    for node , ip_addr in loopback_dict.items():
        if node in config_dict['nodes']['l2l3vni']:
            # overlay_dict[node]={}
            temp_list = []
            for item in ip_list:
                if item != ip_addr:
                    temp_list.append(item)
            overlay_dict[node]['neigbor_overlay']= temp_list
    return overlay_dict

def get_expected_remote_vteps():
    '''
    Author:Ramsiddarth Ragurajan (rraguraj@cisco.com)

    Generate remote vtep list based on the vlan configured
    {'leaf0': ['2000:1::2', '2000:1::3', '2000:1::4'], 
    'leaf1': ['2000:1::1', '2000:1::4'], 
    'leaf2': ['2000:1::1', '2000:1::4'], 
    'leaf3': ['2000:1::1', '2000:1::2', '2000:1::3']}

    '''
    expected_vteps = {}
    vlan_range = {}
    loopback_ip = generate_loopback_ip(st.getenv("vtep"))
    config_dict = get_cfg_dict()
    for node in config_dict['nodes']['l2l3vni']:
        config =  config_dict[node]
        if type(config['l2vni']) == list:
            vlan_range[node] = list()
            for l2vni_item in config['l2vni']:
                vlan_range[node].append(l2vni_item['vlan_id'])
        else:
            vlan_start = config['l2vni']['vlan_start_range']
            count = config['l2vni']['count']
            vlan_range[node] = list(range(vlan_start,vlan_start+count-1))
    for node1 , vlan_list1 in vlan_range.items():
        temp_list =[]
        expected_vteps[node1]={}
        for node2 , vlan_list2 in vlan_range.items():
            if node2 != node1:
                out_list = find_matching_elements(vlan_list1,vlan_list2)
                if len(out_list) !=0:
                    temp_list.append(loopback_ip[node2])
        expected_vteps[node1][loopback_ip[node1]] = temp_list
    return expected_vteps

def find_matching_elements(list1, list2):
    set1 = set(list1)
    set2 = set(list2)
    matching_elements = set1.intersection(set2)
    return list(matching_elements)

def stats_check(traffic_stat):
    flag = True
    st.log("Received traffic: {}".format(traffic_stat['rx']['total_packets']))
    st.log("Sent traffic: {}".format(traffic_stat['tx']['total_packets']))
    st.log(traffic_stat['rx']['total_packets']/traffic_stat['tx']['total_packets'])
    if traffic_stat['rx']['total_packets'] > 0.998*traffic_stat['tx']['total_packets'] and traffic_stat['rx']['total_packets'] < 1.002*traffic_stat['tx']['total_packets']:
        st.log(" TRAFFIC PASSED")
    else:
        st.log("TRAFFIC ITEM FAILED")
        flag = False     
    return flag


"""
This function configures a feature on a list of nodes in parallel using threads. Each thread calls config_feature to 
apply features to a node and logs an error if needed. The inputs needed for this function is the list of nodes and the 
specific feature. 
"""
def config_feature_parallel(nodes,feature):
    threads = []
    def thread_helper(node):
        try:
            config_feature([node], feature)
        except Exception as e:
            st.log("[Error] config_feature failed for node {} with feature {}: {}".format(node, feature, e))
        
    for node in nodes:
        thread = threading.Thread(target=thread_helper, args=(node,))
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()

def config_feature(nodes,feature):
    vars = st.get_testbed_vars()
    if feature in ['loopback', 'nvo', 'delete_loopback']: 
        loopback_ip = generate_loopback_ip(version = st.getenv("vtep"))
    if feature in ['bgp_underlay', 'bgp_bfd_underlay', 'delete_bgp_config','bgp_l3vni_config','delete_bgp_l3vni_config']:
        bgp_info = generate_bgp_underlay_info()
    if feature in ['bgp_overlay', 'bgp_bfd_underlay']:
        overlay_info = generate_bgp_overlay_info(version = st.getenv("vtep"))
    config_dict = get_cfg_dict()
    for node, config in config_dict.items():
        if node in nodes:
            if feature == 'l3vni':
                config_out = generate_l3vni_config(config)
            elif feature == 'l2vni':
                int_config_dict = get_config_interfaces_list(vars)
                dut_int_data = get_dut_interfaces(vars)
                config_out = generate_l2vni_config(config,int_config_dict[node]['l2vni_int'],
                                                   dut_int_data[node])
            elif feature == "sag_v4":
                sag_dict = generate_svi_ip_sag(config,'ipv4')
                if sag_dict != None:
                    config_out = generate_sag_config(sag_dict,'ipv4')
            elif feature == "new_sag_v4":
                sag_dict = generate_svi_ip_sag(config,'ipv4', ip_start = "10.2.0.1")
                if sag_dict != None:
                    config_out = generate_sag_config(sag_dict,'ipv4')
            elif feature == "sag_v6":
                sag_dict = generate_svi_ip_sag(config, 'ipv6')
                if sag_dict != None:
                    config_out = generate_sag_config(sag_dict,'ipv6',enable_on_vlan = False)
            elif feature == "new_sag_v6":
                sag_dict = generate_svi_ip_sag(config,'ipv6', ip_start = "1000:2::1")
                if sag_dict != None:
                    config_out = generate_sag_config(sag_dict,'ipv6',enable_on_vlan = False)
            elif feature == 'loopback':
                    config_out = generate_loopback_config(loopback_ip[node])
            elif feature == 'nvo':
                config_out= generate_vxlan_config(loopback_ip[node])
            elif feature == 'bgp_l3vni_config':
                config_out = generate_bgp_l3vni_config(config,bgp_info[node])
            elif feature == 'bgp_underlay':
                int_config_dict = get_config_interfaces_list(vars)
                config_out = generate_bgp_underlay_config(bgp_info[node],int_config_dict[node]['underlay'])
            elif feature == 'bgp_overlay':
                config_out = generate_bgp_overlay_config(overlay_info[node])
            elif feature == 'bgp_bfd_underlay':
                config_out = generate_bgp_bfd_underlay_config(bgp_info[node])
            elif feature == 'bgp_bfd_overlay':
                config_out = generate_bgp_bfd_overlay_config(overlay_info[node])
            elif feature == 'unnumbered':
                int_config_dict = get_config_interfaces_list(vars)
                config_out = generate_bgp_unnumbered_config(int_config_dict[node]['underlay'])
            elif feature == 'enable_tunnel_counters':
                config_out = set_tunnel_counterpoll()
            elif feature == 'disable_tunnel_counters':
                config_out = set_tunnel_counterpoll(action ='disable')
            elif feature == 'delete_l2vni':
                int_config_dict = get_config_interfaces_list(vars)
                dut_int_data = get_dut_interfaces(vars)
                config_out = generate_l2vni_config(config,int_config_dict[node]['l2vni_int'],
                                                   dut_int_data[node], mode='del')
            elif feature == 'delete_l3vni':
                config_out = generate_l3vni_config(config, mode='del')
            elif feature == 'delete_bgp_l3vni_config':
                config_out = delete_bgp_l3vni_config(config,bgp_info[node])
            elif feature == 'delete_bgp_config':
                config_out = delete_bgp_config(bgp_info[node])
            elif feature == 'delete_vxlan':
                config_out = delete_vxlan_config()
            elif feature == 'delete_loopback':
                config_out = delete_loopback_config(loopback_ip[node])
            elif feature == "delete_sag_v6":
                sag_dict = generate_svi_ip_sag(config, 'ipv6')
                config_out = remove_sag_config(sag_dict,'ipv6', disable_on_vlan = False)
            elif feature == "delete_new_sag_v6":
                sag_dict = generate_svi_ip_sag(config, 'ipv6', ip_start = "1000:2::1")
                config_out = remove_sag_config(sag_dict,'ipv6', disable_on_vlan = False)
            elif feature == "delete_sag_v4":
                sag_dict = generate_svi_ip_sag(config, 'ipv4')
                config_out = remove_sag_config(sag_dict,'ipv4')
            elif feature == "delete_new_sag_v4":
                sag_dict = generate_svi_ip_sag(config, 'ipv4', ip_start = "10.2.0.1")
                config_out = remove_sag_config(sag_dict,'ipv4')
            elif feature == "add_sag_mac":
                config_out = config_sag_mac(add=True)
            elif feature == "del_sag_mac":
                config_out = config_sag_mac(add=False)
            elif feature == "port_channels":
                dut_int_data = get_dut_interfaces(vars)
                config_out = generate_port_channel_config(node, config, dut_int_data[node])
            elif feature == "delete_port_channels":
                dut_int_data = get_dut_interfaces(vars)
                config_out = generate_port_channel_config(node, config, dut_int_data[node], mode='del')
            elif feature == "evpn_esi":
                config_out = generate_evpn_esi_config(config)
            elif feature == "delete_evpn_esi":
                config_out = generate_evpn_esi_config(config, mode='del')
            elif feature == "evpn_mh":
                config_out = generate_epvn_mh_config(node, config_dict)
            elif feature == "delete_evpn_mh":
                config_out = generate_epvn_mh_config(node, config_dict, mode='del')
            if feature in ['bgp_l3vni_config','bgp_underlay','bgp_overlay','delete_bgp_config',
                           'delete_bgp_l3vni_config', 'evpn_mh', 'delete_evpn_mh']:
                config_dut(node, 'bgp', config_out)
            else:
                config_dut(node, 'sonic', config_out, add=True)
                

def config_node(node, config, type=''):
    if type:
        st.config(node, config, type=type, skip_error_check=True, conf=True)
    else:
        st.config(node, config, skip_error_check=True, conf=True)

def config_dut(node, config_domain, config, add=True):
    domain = ''
    if config_domain == 'bgp':
        domain = 'vtysh'
    if add:
        config_node(node, config, domain)

def config_sub_int(interface, vlan, add = True):
    short_name = ("").join(interface.split('ernet'))
    if add:
        cmd = "sudo config subinterface add {0}.{1} {1}".format(short_name, vlan)
    else:
        cmd = "sudo config subinterface del {0}.{1} {1}".format(short_name, vlan)
    return cmd

class VerifyLoop(object):
    """
    Decorator class to retry verification methods
    """
    def __init__(self, vl_retries=1, vl_interval=10, vl_delay=0):
        self.retries = vl_retries
        self.interval = vl_interval
        self.delay = vl_delay

    def __call__(self, org_func, *args, **kwargs):
        def verify_loop( *args, **kwargs):
            retries = kwargs.get('vl_retries', self.retries)
            interval = kwargs.get('vl_interval', self.interval)
            delay = kwargs.get('vl_delay', self.delay)
            retry_cntr = 1
            ret = None
            if delay:
                st.log('Wait {} seconds before execution verification ({})'.format(delay, 
                                                                                    org_func.__name__))
                st.wait(delay)
            while retry_cntr <= retries:
                try:
                    ret = org_func(*args, **kwargs)
                    break
                except Exception as err:
                    if retry_cntr < retries:
                        st.log('Verification ({}) failed. Try {}/{}. '
                               'Retry after {} secs'.format(org_func.__name__,
                                                            retry_cntr, retries, interval))
                        st.wait(interval)
                    else:
                        raise err
                retry_cntr += 1
            return ret
        return verify_loop

def compare_exp_actual_data(exp_data, act_data, id_keys):

    if not exp_data:
        return
    if not act_data:
        raise CompareEmptyData('Actual data empty')
    if not id_keys:
        raise CompareEmptyData('Idenfier keys is empty')
        
    final_result = True
    line = '-'*80
    row_format = '|{:11}|{:29}|{:29}|{:6}|'
    st.log(line)
    st.log(row_format.format('Attribute', 'Expected Value', 'Actual Value', 'Result'))
    st.log(line)
    for exp_row in exp_data:
        exp_keys = exp_row.keys()
        # moving id keys to the begining of list
        for id_key in id_keys:
            exp_keys.remove(id_key)
            exp_keys.insert(0, id_key)

        for act_row in act_data:
                
            # find a matching row  to expected data in actual data
            row_match = True
            for id_key in id_keys:
                exp_keys.remove(id_key)
                exp_keys.insert(0, id_key)
                if not act_row[id_key] == exp_row[id_key]:
                    row_match = False
                    break

            if row_match:
                for exp_key in exp_keys:
                    if act_row[exp_key] == exp_row[exp_key]:
                        result = 'True' 
                    else:
                        result = 'False' 
                        final_result = False

                    st.log(row_format.format(exp_key, exp_row[exp_key], act_row[exp_key],result))

                break
        else:
            # match for expected value not found in actual data
            for id_key in id_keys:
                st.log(row_format.format(id_key, exp_row[id_key], '-', 'Absent'))
            final_result = False
        st.log(line)

    if not final_result:
        raise CompareFailed('Expected values does not match actual values')


class CompareFailed(Exception):
    """Failure when comparing data"""
    pass
class CompareEmptyData(Exception):
    """Empty data found when comparing data"""
    pass
class VerifyBgpIpv4Summary(Exception):
    """Exception when verifying show bgp ipv4 summary """
    pass
class VerifyBgpIpv4Unicast(Exception):
    """Exception when verifying show bgp ipv4 summary """
    pass
class VerifyEvpnEs(Exception):
    """Exception when verifying show evpn es """
    pass

@VerifyLoop()
def verify_bgp_ipv4_summary(dut, neighbor, vrf='default', **kwargs): 
    """
    verify bgp summary output attributes 
    """
    exp_neigh_state = kwargs.get('state', None)
    exp_as_num = kwargs.get('as_num', None)
    bgp_summary = bgpapi.show_bgp_ipv4_summary_vtysh(dut=dut, vrf=vrf)
    neigh_dict = next((neigh for neigh in bgp_summary if neigh['neighbor'] == neighbor), None)

    if not exp_neigh_state is None:
        st.log('Bgp neighbor {} state:: Expected: {} :: Actual: {}'.format(neighbor, exp_neigh_state, neigh_dict['state']))
        if (neigh_dict['state'].isnumeric() and exp_neigh_state == 'down') \
            or (not neigh_dict['state'].isnumeric() and exp_neigh_state == 'up'):
            raise VerifyBgpIpv4Summary('Bgp neighbor state verifcation failed')

    if not exp_as_num is None:
        st.log('Bgp neighbor {} AS:: Expected: {} :: Actual: {}'.format(neighbor, 
                                                                        exp_as_num, 
                                                                        neigh_dict['asn']))
        if not neigh_dict['asn'] == exp_as_num:
            raise VerifyBgpIpv4Summary('Bgp neighbor AS number verifcation failed')


@VerifyLoop()
def verify_bgp_ipv4_unicast_prefix(dut, prefix, vrf='default', route_no=0, **kwargs): 
    """
    verify "show bgp [vrf <vrf>] ipv4 unicast <prefix>" output
    prefix : ipv4 address to use in cli
    vrf : vrf name to use in cli [default: 'default']
    route_no: Route number to compare if multiple routes available [defaul: 0]
    kwargs keys
        as_path : Expected AS path
        prefix_ip : Expected prefix address 
        prefix_mask : Expected prefix mask 
        community : Expected prefix mask 
    """
    exp_as_path = kwargs.get('as_path', None)
    exp_prefix_ip = kwargs.get('prefix_ip', None)
    exp_prefix_mask = kwargs.get('prefix_mask', None)
    exp_community = kwargs.get('community', None)
    if vrf == 'default':
        show_cli = 'show bgp ipv4 unicast {}'.format(prefix)
    else:
        show_cli = 'show bgp vrf {} ipv4 unicast {}'.format(vrf, prefix)

    cli_output = st.show(dut, show_cli , skip_tmpl=True, type="vtysh")
    parsed_output = st.parse_show(dut, show_cli , cli_output, "show_bgp_ipv4v6uni_prefix.tmpl")

    if not parsed_output:
        raise VerifyBgpIpv4Unicast('BGP prefix {} not found'.format(prefix))

    # hack: prefix ip and prefix mask are not getting populated by parse_show
    if not parsed_output[route_no]['prefixip'] or not parsed_output[route_no]['prefixmasklen']:
        match = re.match("BGP routing table entry for (.*)/(.*), .*", cli_output.split('\n')[route_no])
        if match:
            for itm in parsed_output:
                itm['prefixip'] = match.group(1)
                itm['prefixmasklen'] = match.group(2)

    if exp_as_path:
        st.log('Bgp route {} AS path :: Expected: {} :: Actual: {}'.format(prefix, 
                                                                           exp_as_path, 
                                                                           parsed_output[route_no]['peerasn']))
        if not parsed_output[route_no]['peerasn'] == exp_as_path:
            raise VerifyBgpIpv4Unicast('BGP route AS path verification failed')

    if exp_prefix_ip:
        st.log('Bgp route {} Prefix :: Expected: {} :: Actual: {}'.format(prefix, 
                                                                           exp_prefix_ip, 
                                                                           parsed_output[route_no]['prefixip']))
        if not parsed_output[route_no]['prefixip'] == exp_prefix_ip:
            raise VerifyBgpIpv4Unicast('BGP route prefix address match verification failed')

    if exp_prefix_mask:
        st.log('Bgp route {} Prefix Mask Lenght :: Expected: {} :: Actual: {}'.format(prefix, 
                                                                           exp_prefix_mask, 
                                                                           parsed_output[route_no]['prefixmasklen']))
        if not parsed_output[route_no]['prefixmasklen'] == exp_prefix_mask:
            raise VerifyBgpIpv4Unicast('BGP route prefix mask match verification failed')

    if exp_community:
        st.log('Bgp route {} Community :: Expected: {} :: Actual: {}'.format(prefix, 
                                                                           exp_community, 
                                                                           parsed_output[route_no]['community']))
        if not parsed_output[route_no]['community'] == exp_community:
            raise VerifyBgpIpv4Unicast('BGP route comunity match verification failed')


def get_evpn_es(dut):
    """
    parses 'show evpn es' output into data struct below
    cisco@sonic:~$ sudo show evpn es
    Type: B bypass, L local, R remote, N non-DF
    ESI                            Type ES-IF                 VTEPs
    00:02:03:04:05:06:07:08:09:0a  LR   PortChannel1          2000:1::2
    00:02:03:04:05:06:07:08:09:0c  R    -                     2000:1::3,2000:1::4

    Returns:
    [{u'es_if': u'PortChannel1',
      u'esi': u'00:02:03:04:05:06:07:08:09:0a',
      u'type': u'LR',
      u'vteps': u'2000:1::2'},
     {u'es_if': u'-',
      u'esi': u'00:02:03:04:05:06:07:08:09:0c',
      u'type': u'R',
      u'vteps': u'2000:1::3,2000:1::4'}]
    """
    cmd = 'show evpn es'
    cmd_output = st.vtysh_show(dut, cmd, skip_tmpl=True, skip_error_check=False)
    parsed_output = st.parse_show(dut, cmd, cmd_output, 'show_evpn_es.tmpl')

    return parsed_output

def get_expected_evpn_es(dut):
    """
    generates the expected data struct for 'show evpn es' using the data in 
    the config file
    Returns:
        [{'es_if': '-',
        'esi': '00:02:03:04:05:06:07:08:09:0c',
        'type': 'R',
        'vteps': '2000:1::3,2000:1::4'},
        {'es_if': 'PortChannel1',
        'esi': '00:02:03:04:05:06:07:08:09:0a',
        'type': 'LR',
        'vteps': '2000:1::2'}]

    """
    ret_val = list()
    loopback_ip = generate_loopback_ip(st.getenv("vtep"))
    cfg_dict = get_cfg_dict()

    if dut not in cfg_dict['nodes']['l2l3vni']:
        return ret_val
    dut_cfg = cfg_dict[dut]
    dut_esi = list()
    if dut_cfg and dut_cfg.get('port_channels'):
        for pc_cfg in dut_cfg['port_channels']:
            dut_esi.append(pc_cfg['evpn_esi'])

    esi_dict = dict()
    for node,node_cfg in cfg_dict.items():

        if node not in cfg_dict['nodes']['l2l3vni']:
            continue

        for pc_cfg in node_cfg.get('port_channels', []):
            if pc_cfg['evpn_esi'] not in esi_dict.keys():
                esi_dict[pc_cfg['evpn_esi']] = {'esi': pc_cfg['evpn_esi'],
                                                'es_if' : 'PortChannel{}'.format(pc_cfg['port_channel_num']),
                                               'vteps': [loopback_ip[node]]}
            else:
                esi_dict[pc_cfg['evpn_esi']]['vteps'].append(loopback_ip[node])

    for esi, esi_info in esi_dict.items():

        type = 'R'
        es_if = '-'
        sorted_vteps = sorted(esi_info['vteps'])
        if esi_info['esi'] in dut_esi:
            es_if = esi_info['es_if']
            type = 'LR' if loopback_ip[dut] == sorted_vteps[0] else 'LRN'
            sorted_vteps.remove(loopback_ip[dut])
        esi_info['es_if'] = es_if
        esi_info['type'] = type
        esi_info['vteps'] = ','.join(sorted_vteps)
        ret_val.append(esi_info) 

    return ret_val

@VerifyLoop()
def verify_evpn_es(dut, exp_data, id_keys=['esi'], **kwargs): 

    act_data = get_evpn_es(dut)
    compare_exp_actual_data(exp_data, act_data, id_keys)
    return act_data

def get_evpn_es_evi(dut):
    """
    parses 'show evpn es-evi' output into data struct below
    cisco@sonic:~$ show evpn es-evi 
    Type: L local, R remote
    VNI      ESI                            Type
    5030     00:02:03:04:05:06:07:08:09:0a  L   
    5002     00:02:03:04:05:06:07:08:09:0a  L   
    5007     00:02:03:04:05:06:07:08:09:0a  L   
    5004     00:02:03:04:05:06:07:08:09:0a  L   
    5020     00:02:03:04:05:06:07:08:09:0a  L   

    Returns:
    [{u'esi': u'00:02:03:04:05:06:07:08:09:0a', u'type': u'L', u'vni': u'5030'},
    {u'esi': u'00:02:03:04:05:06:07:08:09:0a', u'type': u'L', u'vni': u'5002'},
    {u'esi': u'00:02:03:04:05:06:07:08:09:0a', u'type': u'L', u'vni': u'5007'},
    {u'esi': u'00:02:03:04:05:06:07:08:09:0a', u'type': u'L', u'vni': u'5004'},
    {u'esi': u'00:02:03:04:05:06:07:08:09:0a', u'type': u'L', u'vni': u'5020'}]
    """
    cmd = 'show evpn es-evi'
    cmd_output = st.vtysh_show(dut, cmd, skip_tmpl=True, skip_error_check=False)
    parsed_output = st.parse_show(dut, cmd, cmd_output, 'show_evpn_es_evi.tmpl')

    return parsed_output

def get_expected_evpn_es_evi(dut):
    """
    generates the expected data struct for 'show evpn es-evi' using the data in 
    the config file
    Returns:
    [{'esi': '00:02:03:04:05:06:07:08:09:0c', 'type': 'L', 'vni': '5002'},
    {'esi': '00:02:03:04:05:06:07:08:09:0c', 'type': 'L', 'vni': '5004'},
    {'esi': '00:02:03:04:05:06:07:08:09:0c', 'type': 'L', 'vni': '5006'},
    {'esi': '00:02:03:04:05:06:07:08:09:0c', 'type': 'L', 'vni': '5020'},
    {'esi': '00:02:03:04:05:06:07:08:09:0c', 'type': 'L', 'vni': '5040'}]
    """
    ret_val = list()
    cfg_dict = get_cfg_dict()

    dut_cfg = cfg_dict[dut]
    if dut_cfg and dut_cfg.get('port_channels'):
        for pc_cfg in dut_cfg['port_channels']:
            int_name = 'PortChannel{}'.format(pc_cfg['port_channel_num'])

            for l2vni_info in dut_cfg['l2vni']:
                if int_name in l2vni_info['members']:
                    ret_val.append({
                                'esi': pc_cfg['evpn_esi'],
                                'type': 'L',
                                'vni': str(l2vni_info['vxlan_id'])
                                })

    return ret_val

@VerifyLoop()
def verify_evpn_es_evi(dut, exp_data, id_keys=['esi', 'vni'], **kwargs): 

    act_data = get_evpn_es_evi(dut)
    compare_exp_actual_data(exp_data, act_data, id_keys)
    return act_data

def get_vxlan_vlanvnimap(dut):
    """
    parses 'show vxlan vlanvnimap' output into data struct below
    cisco@sonic:~$ show vxlan vlanvnimap
    +---------+-------+
    | VLAN    |   VNI |
    +=========+=======+
    | Vlan2   |  5002 |
    +---------+-------+
    | Vlan3   |  5003 |
    +---------+-------+
    | Vlan4   |  5004 |
    +---------+-------+
    | Vlan5   |  5005 |
    +---------+-------+
    | Vlan6   |  5006 |
    +---------+-------+

    Returns:
    [{u'vlan': u'Vlan2', u'vni': u'5002'},
    {u'vlan': u'Vlan3', u'vni': u'5003'},
    {u'vlan': u'Vlan4', u'vni': u'5004'},
    {u'vlan': u'Vlan5', u'vni': u'5005'},
    {u'vlan': u'Vlan6', u'vni': u'5006'}]
    """
    cmd = 'show vxlan vlanvnimap'
    cmd_output = st.show(dut, cmd, skip_tmpl=True, skip_error_check=False)
    parsed_output = st.parse_show(dut, cmd, cmd_output, 'show_vxlan_vlanvnimap.tmpl')

    return parsed_output

def get_expected_vxlan_vlanvnimap(dut):
    """
    generates the expected data struct for 'show vxlan vlanvnimap' using the data in 
    the config file
    Returns:
    [{'vlan': 'Vlan2', 'vni': '5002'},
    {'vlan': 'Vlan3', 'vni': '5003'},
    {'vlan': 'Vlan4', 'vni': '5004'},
    {'vlan': 'Vlan5', 'vni': '5005'},
    {'vlan': 'Vlan6', 'vni': '5006'}]
    """
    ret_val = list()
    cfg_dict = get_cfg_dict()

    dut_cfg = cfg_dict[dut]
    if dut_cfg and dut_cfg.get('l2vni'):
        for l2vni_cfg in dut_cfg['l2vni']:
            ret_val.append({
                        'vlan': 'Vlan{}'.format(l2vni_cfg['vlan_id']),
                        'vni': str(l2vni_cfg['vxlan_id'])
                        })
    if dut_cfg and dut_cfg.get('l3vni'):
        for l3vni_cfg in dut_cfg['l3vni']:
            ret_val.append({
                        'vlan': 'Vlan{}'.format(l3vni_cfg['vrf_id']),
                        'vni': str(l3vni_cfg['vxlan_id'])
                        })
    return ret_val

@VerifyLoop()
def verify_vxlan_vlanvnimap(dut, exp_data, id_keys=['vlan'], **kwargs): 

    act_data = get_vxlan_vlanvnimap(dut)
    compare_exp_actual_data(exp_data, act_data, id_keys)
    return act_data

def get_vxlan_vrfvnimap(dut):
    """
    parses 'show vxlan vrfvnimap' output into data struct below
    cisco@sonic:~$ show vxlan vrfvnimap
    +--------+-------+
    | VRF    |   VNI |
    +========+=======+
    | Vrf101 |  5101 |
    +--------+-------+
    | Vrf102 |  5102 |
    +--------+-------+
    | Vrf103 |  5103 |
    +--------+-------+
    Total count : 3

    Returns:
    [{u'vni': u'5101', u'vrf': u'Vrf101'},
    {u'vni': u'5102', u'vrf': u'Vrf102'},
    {u'vni': u'5103', u'vrf': u'Vrf103'}]
    """
    cmd = 'show vxlan vrfvnimap'
    cmd_output = st.show(dut, cmd, skip_tmpl=True, skip_error_check=False)
    parsed_output = st.parse_show(dut, cmd, cmd_output, 'show_vxlan_vrfvnimap.tmpl')

    return parsed_output

def get_expected_vxlan_vrfvnimap(dut):
    """
    generates the expected data struct for 'show vxlan vrfvnimap' using the data in 
    the config file
    Returns:
    [{'vni': '5101', 'vrf': 'Vrf101'},
    {'vni': '5102', 'vrf': 'Vrf102'},
    {'vni': '5103', 'vrf': 'Vrf103'}]
    """
    ret_val = list()
    cfg_dict = get_cfg_dict()

    dut_cfg = cfg_dict[dut]
    if dut_cfg and dut_cfg.get('l3vni'):
        for l3vni_cfg in dut_cfg['l3vni']:
            ret_val.append({
                        'vrf': 'Vrf{}'.format(l3vni_cfg['vrf_id']),
                        'vni': str(l3vni_cfg['vxlan_id'])
                        })
    return ret_val

@VerifyLoop()
def verify_vxlan_vrfvnimap(dut, exp_data, id_keys = ['vrf'], **kwargs): 

    act_data = get_vxlan_vrfvnimap(dut)
    compare_exp_actual_data(exp_data, act_data, id_keys)
    return act_data

def get_vxlan_remotevtep(dut):
    """
    parses 'show vxlan remotevtep' output into data struct below
    cisco@sonic:~$ show vxlan remotevtep
    +-----------+-----------+-------------------+--------------+
    | SIP       | DIP       | Creation Source   | OperStatus   |
    +===========+===========+===================+==============+
    | 2000:1::1 | 1000:1::4 | EVPN              | oper_up      |
    +-----------+-----------+-------------------+--------------+
    | 2000:1::1 | 2000:1::2 | EVPN              | oper_up      |
    +-----------+-----------+-------------------+--------------+
    | 2000:1::1 | 2000:1::3 | EVPN              | oper_up      |
    +-----------+-----------+-------------------+--------------+
    | 2000:1::1 | 2000:1::4 | EVPN              | oper_up      |
    +-----------+-----------+-------------------+--------------+
    Total count : 4


    Returns:
    [{u'dst_vtep': u'1000:1::4',
    u'remote_mac': u'',
    u'remote_vtep': u'',
    u'src_vtep': u'2000:1::1',
    u'total_count': u'',
    u'tun_src': u'EVPN',
    u'tun_status': u'oper_up',
    u'vlan': u'',
    u'vni': u''},
    {u'dst_vtep': u'2000:1::2',
    u'remote_mac': u'',
    u'remote_vtep': u'',
    u'src_vtep': u'2000:1::1',
    u'total_count': u'',
    u'tun_src': u'EVPN',
    u'tun_status': u'oper_up',
    u'vlan': u'',
    u'vni': u''}, ..]
    """
    cmd = 'show vxlan remotevtep'
    cmd_output = st.show(dut, cmd, skip_tmpl=True, skip_error_check=False)
    parsed_output = st.parse_show(dut, cmd, cmd_output, 'show_vxlan_remotevtep.tmpl')

    return parsed_output

def get_expected_vxlan_remotevtep(dut):
    """
    generates the expected data struct for 'show vxlan remotevtep' using the data in 
    the config file
    Returns:
    [{'dst_vtep': '1000:1::4',
    'src_vtep': '2000:1::1',
    'tun_src': 'EVPN',
    'tun_status': 'oper_up'},
    {'dst_vtep': '2000:1::2',
    'src_vtep': '2000:1::1',
    'tun_src': 'EVPN',
    'tun_status': 'oper_up'}, ..]

    """
    ret_val = list()
    loopback_ip = generate_loopback_ip(st.getenv("vtep"))
    cfg_dict = get_cfg_dict()

    if dut not in cfg_dict['nodes']['l2l3vni']:
        return ret_val

    for node in cfg_dict['nodes']['l2l3vni']:
        if node == dut:
            continue
        ret_val.append({
                        'src_vtep': loopback_ip[dut],
                        'dst_vtep': loopback_ip[node],
                        'tun_status': 'oper_up',
                        'tun_src': 'EVPN'
                        })
    return ret_val

@VerifyLoop()
def verify_vxlan_remotevtep(dut, exp_data, id_keys=['dst_vtep'], **kwargs): 

    act_data = get_vxlan_remotevtep(dut)
    compare_exp_actual_data(exp_data, act_data, id_keys)
    return act_data

def get_vxlan_l2nexthopgroup(dut):
    """
    parses 'show vxlan l2nexthopgroup' output into data struct below
    cisco@sonic:~$ show vxlan l2nexthopgroup
    +-----------+-----------+---------------------+
    |       NHG | Tunnels   | LocalMembers        |
    +===========+===========+=====================+
    | 268435458 | 2000:1::2 |                     |
    +-----------+-----------+---------------------+
    | 268435460 | 2000:1::3 |                     |
    +-----------+-----------+---------------------+
    | 268435461 | 2000:1::4 |                     |
    +-----------+-----------+---------------------+
    | 536870913 |           | 268435458           |
    +-----------+-----------+---------------------+
    | 536870915 |           | 268435460,268435461 |
    +-----------+-----------+---------------------+

    Returns:
    [{u'loc_mbrs': u'', u'nbr_grp': u'268435458', u'tunnels': u'2000:1::2'},
    {u'loc_mbrs': u'', u'nbr_grp': u'268435460', u'tunnels': u'2000:1::3'},
    {u'loc_mbrs': u'', u'nbr_grp': u'268435461', u'tunnels': u'2000:1::4'},
    {u'loc_mbrs': u'268435458', u'nbr_grp': u'536870913', u'tunnels': u''},
    {u'loc_mbrs': u'268435460,268435461', u'nbr_grp': u'536870915', u'tunnels': u''}]

    """
    cmd = 'show vxlan l2nexthopgroup'
    cmd_output = st.show(dut, cmd, skip_tmpl=True, skip_error_check=False)
    parsed_output = st.parse_show(dut, cmd, cmd_output, 'show_vxlan_l2nexthopgroup.tmpl')

    return parsed_output

def get_expected_vxlan_l2nexthopgroup(dut):
    """
    generates the expected data struct for 'show vxlan l2nexthopgroup' using the data in 
    the config file
    Returns:
    """
    ret_val = list()
    loopback_ip = generate_loopback_ip(st.getenv("vtep"))
    cfg_dict = get_cfg_dict()

    dut_cfg = cfg_dict[dut]
    if not dut_cfg or not dut_cfg.get('port_channels'):
        return ret_val

    for node , node_cfg in cfg_dict.items():

        if node == dut:
            continue
        
        if node_cfg and node_cfg.get('port_channels'):
            ret_val.append({
                        'tunnels': loopback_ip[node]
                        })
    return ret_val


@VerifyLoop()
def verify_vxlan_l2nexthopgroup(dut, exp_data, id_keys=['nbr_grp'], **kwargs): 

    act_data = get_vxlan_l2nexthopgroup(dut)
    compare_exp_actual_data(exp_data, act_data, id_keys)
    return act_data


def scp_upload(local_path, remote_path, hostaddr, username, password, port=22):
    try:
        # Create an SSH client object
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Connect to the SSH server
        ssh_client.connect(hostaddr, port=port, username=username, password=password)
        
        # Create an SCP client
        with SCPClient(ssh_client.get_transport()) as scp:
            # Upload the local file to the remote path
            scp.put(local_path, remote_path)
        
    finally:
        # Close the SSH connection
        ssh_client.close()    

def scp_download(local_path, remote_path, hostaddr, username, password, port=22):
    try:
        # Create an SSH client object
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Connect to the SSH server
        ssh_client.connect(hostaddr, port=port, username=username, password=password)
        
        # Create an SCP client
        with SCPClient(ssh_client.get_transport()) as scp:
            # Upload the local file to the remote path
            scp.get(remote_path, local_path=local_path)
        
    finally:
        # Close the SSH connection
        ssh_client.close()    

class ConfigDB(object):
    """
    Class to get or set config_db.json values
    exmaple:
        with ConfigDB('leaf2', '192.168.122.235', 'cisco', 'cisco123') as cfgdb:
            cfgdb.set_leaf_value(['DEVICE_METADATA', 'localhost', 'docker_routing_config_mode'], 'split-unified')
            val = cfgdb.get_leaf_value(['DEVICE_METADATA', 'localhost', 'docker_routing_config_mode'])
    """

    def __init__(self, dut, address, username, password):
        self._config_db = {}
        self.dut = dut
        self.address = address
        self.username = username
        self.password = password
        self.temp_db = '__config_db_{}__.json'.format(self.dut)
        self.local_temp_db_path = './' + self.temp_db
        self.remote_temp_db_path = '/home/{}/'.format(self.username) + self.temp_db
        self.remote_db_path = '/etc/sonic/config_db.json'
    
    def __enter__(self): 
        self.read_db()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.write_db()
    
    def read_db(self):
        """
        copy config_db.json from router to local and load json content to class
        """
        try:
            scp_download(local_path=self.local_temp_db_path,
                        remote_path= self.remote_db_path, 
                        hostaddr=self.address,
                        username=self.username, password=self.password)
            with open(self.local_temp_db_path) as fd:
                self._config_db = json.load(fd)
        finally:
            os.system('rm -rf {}'.format(self.local_temp_db_path))

    def write_db(self):
        """
        dump class config db content to json and copy to router and replace existing config_db.json
        on router
        """
        try:
            db_data_json = json.dumps(self._config_db, indent=4, sort_keys=False)
            with open(self.local_temp_db_path, 'w') as fd:
                fd.write(db_data_json)

            scp_upload(local_path=self.local_temp_db_path, 
                        remote_path=self.remote_temp_db_path, 
                        hostaddr=self.address,
                        username=self.username, password=self.password)
            st.show(self.dut, 'sudo cp {} {}'.format(self.remote_temp_db_path,
                                                     self.remote_db_path), skip_tmpl=True)
        finally:
            os.system('rm -rf {}'.format(self.local_temp_db_path))
            st.show(self.dut, 'sudo rm {}'.format(self.remote_temp_db_path), skip_tmpl=True)

    def _find_key_val_dict(self, keys):
        """
        helper funtion to find the dictonary having the find final key value
        keys: keys in list format
        example: ['DEVICE_METADATA', 'localhost', 'docker_routing_config_mode']
        """
        if type(keys) is str:
            keys = [keys]
        if type(keys) is not list:
            raise Exception('Keys not in list format')
        ret_dict = self._config_db
        for key in keys[:-1]:
            ret_dict = ret_dict[key] 
            if type(ret_dict) is not dict:
                raise Exception('Key is a leaf')
        return ret_dict

    def get_leaf_value(self, keys):
        """
        Get the leaf value of config db given heirarchy of keys . 
        keys: keys in list format
        example: ['DEVICE_METADATA', 'localhost', 'docker_routing_config_mode']
        """
        try:
            #find the dict with the final key in 'keys'
            key_dict = self._find_key_val_dict(keys)
            val = key_dict[keys[-1]]
            if type(val) is not unicode:
                raise Exception('Leaf value not string : {}'.format(type(val)))
            return val.encode('utf-8')
        except Exception as err:
            raise Exception('Invalid key: {}'.format(err))

    def set_leaf_value(self, keys, value):
        """
        set the leaf value of confid db given heirarchy of keys . 
        keys: keys in list format
        example: ['DEVICE_METADATA', 'localhost', 'docker_routing_config_mode']
        value: string value 
        """
        try:
            #find the dict with the final key in 'keys'
            key_dict = self._find_key_val_dict(keys)
            key = keys[-1].decode()
            val = str(value).decode()
            key_dict[key] = val
        except Exception as err:
            raise Exception('Invalid key: {}'.format(err))

def get_device_id(device, vars_dict):
    """get device id provided the device name"""
    for name, id in vars_dict.dut_ids.items(): 
        if name == device :
            return id
    else:
        raise Exception('Device {} not found'.format(device)) 

def get_peer_port_id(port_id, vars_dict, node=None, node_id=None):
    """get remote port id for a provided port id """
    port_num_pattern = '([A-Z0-9].*)([A-Z]+[0-9]+)'
    match = re.match(port_num_pattern, port_id)
    if not match:
        raise Exception('Port ID {} not in proper format. \
                        Port number Pn not found'.format(port_id))
    port_num = match.group(2)
    port_id_1node = '([A-Z]+[0-9]+)'
    port_id_2node = '([A-Z]+[0-9]+)([A-Z]+[0-9]+)'

    match_2node =  re.match(port_id_2node, match.group(1))
    match_1node =  re.match(port_id_1node, match.group(1))
    if match_2node:
        node_id = match_2node.group(1)
        peer_id = match_2node.group(2)
    elif match_1node:
        peer_id = match_1node.group(1)
        if not node_id:
            node_id = get_device_id(node, vars_dict)
    else:
        raise Exception('Port ID {} not in proper format.'.format(port_id))
    
    peer_port_id = peer_id+node_id+port_num
    for key in vars_dict.keys():
        if key == peer_port_id:
            # valid peer port id 
            return peer_port_id
    else:
        raise Exception('Derived peer port id {} from port id {} (node: {}/node_id: {}) not defined.'.format(
            peer_port_id, port_id, node, node_id))

def check_core():
    flag = False
    pattern = r'(\w+)\.\d+\.\d+\.core.gz'
    for dut in st.get_dut_names():
        out = st.show(dut, 'ls -l /var/core/', skip_tmpl=True)
        matches = re.findall(pattern, out)
        core_name = "+".join(list(set(matches)))
        if "core.gz" in out:
            st.log("Core present in {}".format(dut))
            flag = True 
            st.collect_core_files(dut, core_name)

    return flag

def enable_debugs():      
    output = ''
    output += "debug zebra kernel\n"
    output += "debug zebra kernel msgdump\n"
    output += "debug zebra rib\n"
    output += "debug zebra rib detailed\n"
    output += "debug zebra vxlan\n"
    output += "debug zebra evpn mh mac\n"
    output += "debug zebra evpn mh es\n"
    output += "debug bgp evpn mh route\n"
    output += "debug bgp evpn mh es\n"
    output += "debug bgp zebra\n"
    output += "debug bgp nht\n"
    output += "debug zebra evpn mh neigh\n"
    output += "debug zebra dplane detailed\n"
    output += "log stdout\n"
    output += "log syslog\n"
    output += "end\nexit\n"
    cmd1 = "swssloglevel -l INFO -c orchagent"
    cmd2 = "swssloglevel -l INFO -c fdbsyncd"
    for dut in st.get_dut_names():
        if "leaf" in dut:
            st.config(dut, output, type='vtysh', skip_error_check=True)
            st.config(dut, cmd1, skip_error_check=True)
            st.config(dut, cmd2, skip_error_check=True)

def get_expected_evpn_type1_routes(dut):
    ret_val = list()
    loopback_ip = generate_loopback_ip(st.getenv("vtep"))
    cfg_dict = get_cfg_dict()

    if dut not in cfg_dict['nodes']['l2l3vni']:
        return ret_val
    
    dut_cfg = cfg_dict[dut]
                    
    evpn_type1_routes = []

    if dut_cfg and dut_cfg.get('port_channels'):
        for pc_cfg in dut_cfg['port_channels']:
            int_name = 'PortChannel{}'.format(pc_cfg['port_channel_num'])

            for l2vni_info in dut_cfg['l2vni']:
                if int_name in l2vni_info['members']:        
                    evpn_type1_routes.append({'esi': pc_cfg['evpn_esi'],
                                              'vni' : str(l2vni_info['vxlan_id']),
                                              'next_hop': loopback_ip[dut]})

    return evpn_type1_routes

def get_actual_evpn_type1_routes(dut):
    cli_output = st.show(dut, "do show bgp l2vpn evpn route type 1",type='vtysh', skip_tmpl=True)
    parsed_output = st.parse_show(dut, "show bgp l2vpn evpn route type 1",cli_output, "show_bgp_l2vpn_evpn_route_type_1.tmpl")
    return parsed_output

@VerifyLoop()
def verify_evpn_type1_routes(dut, exp_es_evi_data, **kwargs):
    st.banner("Checking EVPN Type 1 routes in "+ dut)

    act_type1_routes = get_actual_evpn_type1_routes(dut)
    act_data = []
    for route in act_type1_routes:
        act_data.append({'vni': route['rt'].split(':')[1], 'esi': route['esi'], 'next_hop':route['next_hop']})
    compare_exp_actual_data(exp_es_evi_data, act_data , ['vni', 'esi', 'next_hop'])
    return act_type1_routes
    
def get_expected_evpn_type4_routes(dut, **kwargs):
    ret_val = list()
    loopback_ip = generate_loopback_ip(st.getenv("vtep"))
    cfg_dict = get_cfg_dict()

    if dut not in cfg_dict['nodes']['l2l3vni']:
        return ret_val
    
    dut_cfg = cfg_dict[dut]

    evpn_type4_routes = []
    for pc_cfg in dut_cfg.get('port_channels', []):
        evpn_type4_routes.append({'esi': pc_cfg['evpn_esi'],
                                  'next_hop': loopback_ip[dut]})

    return evpn_type4_routes

def get_actual_evpn_type4_routes(dut):
    cli_output = st.show(dut, "do show bgp l2vpn evpn route type 4",type='vtysh', skip_tmpl=True)
    parsed_output = st.parse_show(dut, "show bgp l2vpn evpn route type 4",cli_output, "show_bgp_l2vpn_evpn_route_type_4.tmpl")
    return parsed_output

@VerifyLoop()
def verify_evpn_type4_routes(dut, exp_type4_routes, **kwargs):
    st.banner("Checking EVPN Type 4 routes in "+ dut)

    act_type4_routes = get_actual_evpn_type4_routes(dut)

    compare_exp_actual_data(exp_type4_routes, act_type4_routes, ['esi', 'next_hop'])
    return act_type4_routes
    
def verify_mac_seq(host_info,mac_move_seq = "",ip = "",host_local_node=[], host_type = 'mac_only', is_mh_host = False):
    leaf_nodes = []
    for dut in st.get_dut_names():
        if "leaf" in dut:
            leaf_nodes.append(dut)
    flag = False
    local_flag = False
    learn_type = ""
    if host_type == 'mac_only':
        mac_addr = host_info
    else:
        mac_addr = host_info['mac']
        ip_addr = host_info['ip']

    for node in leaf_nodes:
        st.banner("inside "+node)
        cli_output = st.show(node, "do show bgp l2vpn evpn route type 2",type='vtysh', skip_tmpl=True)
        parsed_output = st.parse_show(node, "show bgp l2vpn evpn route type 2",cli_output, "show_bgp_l2vpn_evpn_route_type_2.tmpl")
        mac_found = False
        ip_found = False
        for item in parsed_output:
            for key, value in item.items():
                if host_type == 'mac_only':
                    if key == "mac" and value == mac_addr:
                        mac_found = True
                        flag = True
                        if item['ip'] == '':
                            if item['weight'] == '32768':
                                st.log(item)
                                learn_type = 'local'
                                if is_mh_host:
                                    if node in host_local_node :
                                        st.log("mac learnt locally on node: {}".format(node))
                                        local_flag = True 
                                else:   
                                    if node in host_local_node :
                                        st.log("mac learnt locally on expected node: {}".format(node))
                                        local_flag = True
                                    else:
                                        local_flag = False
                                        st.log("mac learnt locally on unexpected node: {}".format(node)) 
                            else:
                                learn_type = 'remote'
                    
                            if item['mm'] != mac_move_seq:
                                flag = False
                                st.log("found wrong sequence id: expected - {} found - {} ".format(mac_move_seq, item['mm']))
                            else:
                                st.log("found correct sequence id: expected-->{}, found -->{} ".format(mac_move_seq, item['mm']))
                            st.log("mac learning : {}".format(learn_type))
                    
                else:
                    if key == "mac" and value == mac_addr:
                        mac_found = True
                        flag = True
                        if item['ip'] == ip_addr:
                            st.log('ip_found')
                            ip_found = True
                            if item['weight'] == '32768':
                                st.log(item)
                                learn_type = 'local'
                                if node in host_local_node :
                                    st.log("mac learnt locally on expected node: {}".format(node))
                                    local_flag = True
                                else:
                                    local_flag = False
                                    st.log("mac learnt locally on unexpected node: {}".format(node))    
                            else:
                                learn_type = 'remote'
                    
                            if item['mm'] != mac_move_seq:
                                flag = False
                                st.log("found wrong sequence id: expected - {} found - {} ".format(mac_move_seq, item['mm']))
                            else:
                                st.log("found correct sequence id: expected-->{}, found -->{} ".format(mac_move_seq, item['mm']))
                            st.log("mac learning : {}".format(learn_type))
    if not mac_found:
        st.banner("Host not found in the table")
        return False
    if flag and local_flag :
        return True
    else:
        return False
            

def get_evpn_timers(dut):
    cli_output = st.show(dut, "show evpn", skip_tmpl=True)
    patterns = {
    "mac-holdtime": r"mac-holdtime:\s*(\d+)s",
    "neigh-holdtime": r"neigh-holdtime:\s*(\d+)s",
    "startup-delay": r"startup-delay:\s*(\d+)s",
    "start-delay-timer": r"start-delay-timer:\s*([^\s,]+)",
    "uplink-cfg-cnt": r"uplink-cfg-cnt:\s*(\d+)",
    "uplink-active-cnt": r"uplink-active-cnt:\s*(\d+)"
    }
    out_dict = {}
    for key, pattern in patterns.items():
        match = re.search(pattern, cli_output)
        if match:
            out_dict[key] = match.group(1)
    return out_dict

def get_mac_agetime(dut):
    cli_output = st.show(dut, "show mac aging-time", skip_tmpl=True)
    match = re.search(r'(\d+)\s+seconds', cli_output)
    if match:
        aging_time = int(match.group(1))
        return aging_time
    
def change_fdb_ageout(ageout_time = "600"):
    # Define the JSON content to be written to the file
    data = [
        {
            "SWITCH_TABLE:switch": {
                "fdb_aging_time": ageout_time
            },
            "OP": "SET"
        }
    ]

    # Specify the filename
    basename = 'ageout.json'
    filename = '/tmp/' + basename

    # Write the JSON content to the file
    with open(filename, 'w') as file:
        json.dump(data, file, indent=4)

    st.log("File {} has been created with the specified content.".format(filename))
    for dut in st.get_dut_names():
        if "leaf" in dut:
            utils_obj.copy_files_to_dut(dut, [filename], '/home/cisco')
            st.config(dut,"docker cp /home/cisco/ageout.json swss:/",sudo=False, split_cmds=False)
            st.config(dut,"docker exec -it swss swssconfig ageout.json",sudo=False, split_cmds=False)
            st.show(dut, 'sonic-db-dump -n APPL_DB -k *SWITCH_TABLE:switch* -y', skip_tmpl=True, skip_error_check=True)

def start_device_group(port):
    tg_handle = handles.values()[0]['tg_handle']
    tmp_handle = handles[port]['int_handle']
    device_group = "/"+"/".join(tmp_handle.split('/',3)[1:3])
    tg_handle.tg_test_control(action="start_protocol", handle=device_group)
    st.wait(10)		##give time to start protocol

def enable_uplink_tracking_configs(nodes, add = True):
    vars = st.get_testbed_vars()
    int_config_dict = get_config_interfaces_list(vars)
    for node in nodes:
        for interface in int_config_dict[node]['underlay']:
            config_out = ""
            config_out += "interface {}\n".format(interface)
            if add:
                config_out += "evpn mh uplink\nend\nexit\n"
            else:
                config_out += "no evpn mh uplink\nend\nexit\n"
            st.config(node, config_out, type='vtysh', skip_error_check=True)

def validate_stats(tg_handle,traffic_item):
    traffic_stat = tg_handle.tg_traffic_stats(mode='traffic_item', streams=traffic_item)
    flag = True 
    for key , values in traffic_stat['traffic_item'].items():
        if key == traffic_item:
            st.banner("TRAFFIC ITEM {}".format(traffic_item))
            st.log("Received traffic: {}".format(values['rx']['total_pkts']))
            st.log("Sent traffic: {}".format(values['tx']['total_pkts']))
            st.log(int(values['rx']['total_pkts'])/int(values['tx']['total_pkts']))
            if int(values['rx']['total_pkts']) > 0.998*int(values['tx']['total_pkts']) and \
                int(values['rx']['total_pkts']) < 1.002*int(values['tx']['total_pkts']):
                st.log(" TRAFFIC ITEM {} PASSED".format(traffic_item))
            else:
                st.log(" TRAFFIC ITEM {} FAILED".format(traffic_item))
                flag = False
    return flag 

def generate_ip_list(start_ip, num_ips=20):
    def increment_ip(ip):
        parts = list(map(int, ip.split('.')))
        parts[3] += 1
        
        for i in range(3, 0, -1):
            if parts[i] > 255:
                parts[i] = 0
                parts[i-1] += 1
        return '.'.join(map(str, parts))
    ip_list = [start_ip]
    for _ in range(num_ips - 1):
        new_ip = increment_ip(ip_list[-1])
        ip_list.append(new_ip)
    return ip_list

def increment_mac_address(mac_address, increment_value = 1):
    mac_int = int(mac_address.replace(":", ""), 16)
    mac_int += increment_value
    mac_int = mac_int & 0xFFFFFFFFFFFF
    new_mac = '{:012X}'.format(mac_int) 
    new_mac = ':'.join(new_mac[i:i+2] for i in range(0, 12, 2))
    return new_mac

def get_vlan_info(test_cfg):
    my_dict ={}
    for item, value in test_cfg.items():
        if "leaf" in item:
            my_dict[item]={}
            my_dict[item]['orphan_vlan_list'] = []
            my_dict[item]['po_vlan_list'] = [] 
            for vlan in value['l2vni']:
                for info , values in vlan.items():
                    if info == "members":
                        for mem in values:
                            if "PortChannel" in mem:
                                my_dict[item]['po_vlan_list'].append(vlan['vlan_id'])
                            else:
                                my_dict[item]['orphan_vlan_list'].append((vlan['vlan_id']))
    return my_dict

def dhcp_relay_config(add = True, src_loopback = True, dhcp_helper = True):


    leaf_nodes=[]
    for dut in st.get_dut_names():
        if "leaf" in dut:
            leaf_nodes.append(dut)
    def config_gen(loopback = "", input_dict ={}, add = True):
        cmd = ""
        for item in input_dict["client_vlans"]:
            if add:
                if src_loopback:
                    cmd += "config vlan dhcp-relay-src add {} {}\n".format(item, loopback)
                if dhcp_helper:
                    for server_vlan in input_dict["server_vlans"]:
                        if server_vlan == 30:
                            cmd += "config vlan dhcp_relay add {} 80.{}.0.89\n".format(item,server_vlan)
                        else:
                            cmd += "config vlan dhcp_relay add {} 80.{}.0.88\n".format(item,server_vlan)
            else:
                if dhcp_helper:
                    for server_vlan in input_dict["server_vlans"]:
                        if server_vlan == 30:
                            cmd += "config vlan dhcp_relay del {} 80.{}.0.89\n".format(item,server_vlan)
                        else:
                            cmd += "config vlan dhcp_relay del {} 80.{}.0.88\n".format(item,server_vlan)
                if src_loopback:
                    cmd += "config vlan dhcp-relay-src del {}\n".format(item)
        return cmd

    i = 1
    input_dict = {"Vrf101": {"client_vlans":[2,3], "server_vlans":[20,30,75]},"Vrf102": {"client_vlans":[5], "server_vlans":[4]}, "Vrf103": {"client_vlans":[6], "server_vlans":[7]}}
    for node in leaf_nodes:
        cmd = ""
        print("inside {}".format(node))
        for count in range(1,4):
            loop = "Loopback10{}".format(str(count))
            if add:
                if not dhcp_helper and not src_loopback:
                    cmd += "config interface vrf bind {} Vrf10{}\n".format(loop,count)
                    cmd += "config interface ip add {} 11{}.111.111.10{}/32\n".format(loop,str(i),str(count))
                
                cmd += config_gen(loopback = loop, input_dict = input_dict["Vrf10"+str(count)]) 
            else:
                cmd += config_gen(loopback = loop, input_dict = input_dict["Vrf10"+str(count)],add = False)
                if not dhcp_helper and not src_loopback:
                    cmd += "config interface vrf unbind {}\n".format(loop,count)
        i += 1
        st.config(node, cmd, skip_error_check=True)
        if not dhcp_helper and not src_loopback:
            if add:
                server_2 = "config vlan dhcp_relay add 5 80.4.0.89\nconfig vlan dhcp_relay add 6 80.7.0.89\n"
            else:
                server_2 = "config vlan dhcp_relay del 5 80.4.0.89\nconfig vlan dhcp_relay del 6 80.7.0.89\n"
            st.config(node, server_2, skip_error_check=True)

def get_client_ip_list(stats):
    ip_list = []
    flag = True
    count = 1
    for key, value in stats['session'].items():
        if value['Address'] == "reserveSlot[Unresolved]":
            flag = False
        else:
            ip_list.append(value['Address'])
        st.log("client{} ip status : {}".format(count,value['Address']))
        count += 1
    return ip_list, flag

def get_type2_route(dut):
    cli_output = st.show(dut, "do show bgp l2vpn evpn route type 2",type='vtysh', skip_tmpl=True)
    parsed_output = st.parse_show(dut, "show bgp l2vpn evpn route type 2",cli_output, "show_bgp_l2vpn_evpn_route_type_2.tmpl")
    return parsed_output

def validate_mac_type2_route(mac_address_list, host_local_node=[], is_mh_host = True):
    leaf_nodes = []
    for dut in st.get_dut_names():
        if "leaf" in dut:
            leaf_nodes.append(dut)
    flag_dict = {}
    parsed_output = {}
    for node in leaf_nodes:
        parsed_output[node] = get_type2_route(node)
    
    for node in leaf_nodes:
        flag_dict[node] = {}
        for mac_info in mac_address_list:
            flag_dict[node][mac_info] = True
            result = verify_type2_route(mac_info, parsed_output= parsed_output[node], host_local_node=host_local_node, is_mh_host=is_mh_host, node=node)
            if not result:
                flag_dict[node][mac_info] = False
                st.error("MAC {} not found in node {}".format(mac_info, node))
    return flag_dict

def verify_type2_route(host_info, parsed_output= [], mac_move_seq = "",ip = "",host_local_node=[], host_type = 'mac_only', is_mh_host = False, node = ""):
    leaf_nodes = []
    for dut in st.get_dut_names():
        if "leaf" in dut:
            leaf_nodes.append(dut)
    flag = False
    local_flag = False
    learn_type = ""
    if host_type == 'mac_only':
        mac_addr = host_info
    else:
        mac_addr = host_info['mac']
        ip_addr = host_info['ip']
    mac_found = False
    ip_found = False
    for item in parsed_output:
        for key, value in item.items():
            if host_type == 'mac_only':
                if key == "mac" and value == mac_addr:
                    mac_found = True
                    flag = True
                    if item['ip'] == '':
                        if item['weight'] == '32768':
                            st.log(item)
                            learn_type = 'local'
                            if is_mh_host:
                                if node in host_local_node :
                                    st.log("mac learnt locally on node: {}".format(node))
                                    local_flag = True 
                            else:   
                                if node in host_local_node :
                                    st.log("mac learnt locally on expected node: {}".format(node))
                                    local_flag = True
                                else:
                                    local_flag = False
                                    st.log("mac learnt locally on unexpected node: {}".format(node)) 
                        else:
                            learn_type = 'remote'
            else:
                if key == "mac" and value == mac_addr:
                    mac_found = True
                    flag = True
                    if item['ip'] == ip_addr:
                        st.log('ip_found')
                        ip_found = True
                        if item['weight'] == '32768':
                            st.log(item)
                            learn_type = 'local'
                            if node in host_local_node :
                                st.log("mac learnt locally on expected node: {}".format(node))
                                local_flag = True
                            else:
                                local_flag = False
                                st.log("mac learnt locally on unexpected node: {}".format(node))    
                        else:
                            learn_type = 'remote'
                    
                        if item['mm'] != mac_move_seq:
                            flag = False
                            st.log("found wrong sequence id: expected - {} found - {} ".format(mac_move_seq, item['mm']))
                        else:
                            st.log("found correct sequence id: expected-->{}, found -->{} ".format(mac_move_seq, item['mm']))
                        st.log("mac learning : {}".format(learn_type))
    if not mac_found:
        st.banner("Host not found in the table")
        return False
    if flag and local_flag :
        return True
    else:
        return False

def get_bgp_summary(dut):
    """
    parses 'show bgp summary' output into data struct below
    sonic# show bgp summary

    IPv4 Unicast Summary (VRF default):
    BGP router identifier 10.200.200.203, local AS number 65203 vrf-id 0
    BGP table version 2
    RIB entries 3, using 576 bytes of memory
    Peers 4, using 2898 KiB of memory
    Peer groups 2, using 128 bytes of memory

    Neighbor        V         AS   MsgRcvd   MsgSent   TblVer  InQ OutQ  Up/Down State/PfxRcd   PfxSnt Desc
    Ethernet1_1     4      65100       402       404        0    0    0 06:28:12            2        2 N/A
    Ethernet1_2     4      65101       405       402        0    0    0 06:28:05            2        2 N/A
    Ethernet1_3     4      65102       403       405        0    0    0 06:28:11            2        2 N/A
    Ethernet1_4     4      65103       406       403        0    0    0 06:28:07            2        2 N/A

    Total number of neighbors 4

    IPv6 Unicast Summary (VRF default):
    BGP router identifier 10.200.200.203, local AS number 65203 vrf-id 0
    BGP table version 14
    RIB entries 15, using 2880 bytes of memory
    Peers 4, using 2898 KiB of memory
    Peer groups 2, using 128 bytes of memory

    Neighbor        V         AS   MsgRcvd   MsgSent   TblVer  InQ OutQ  Up/Down State/PfxRcd   PfxSnt Desc
    Ethernet1_1     4      65100       402       404        0    0    0 06:28:12            7        8 N/A
    Ethernet1_2     4      65101       405       402        0    0    0 06:28:05            7        8 N/A
    Ethernet1_3     4      65102       403       405        0    0    0 06:28:11            7        8 N/A
    Ethernet1_4     4      65103       406       403        0    0    0 06:28:07            7        8 N/A

    Total number of neighbors 4

    L2VPN EVPN Summary (VRF default):
    BGP router identifier 10.200.200.203, local AS number 65203 vrf-id 0
    BGP table version 0
    RIB entries 105, using 20 KiB of memory
    Peers 3, using 2174 KiB of memory
    Peer groups 2, using 128 bytes of memory

    Neighbor        V         AS   MsgRcvd   MsgSent   TblVer  InQ OutQ  Up/Down State/PfxRcd   PfxSnt Desc
    2000:1::1       4      65200      3899      3736        0    0    0 06:28:05          114      168 N/A
    2000:1::2       4      65201      3679      3736        0    0    0 06:28:05          114      168 N/A
    2000:1::3       4      65202      4612      3737        0    0    0 06:28:03          114      168 N/A

    Total number of neighbors 3
    """
    cmd = 'show bgp summary'
    cmd_output = st.vtysh_show(dut, cmd, skip_tmpl=True, skip_error_check=False)
    parsed_output = st.parse_show(dut, cmd, cmd_output, 'show_ip_bgp_summary.tmpl')
    return parsed_output

def get_expected_bgp_summary(dut):
    ret_val = list()
    loopback_ip = generate_loopback_ip(st.getenv("vtep"))
    cfg_dict = get_cfg_dict()
    other_dut = []
    vars = st.get_testbed_vars()
    int_config_dict = get_config_interfaces_list(vars)
    for intf in int_config_dict[dut]['underlay']:
        ret_val.append({"protocol":"IPv4 Unicast", "neighbor":intf, "state":"Up"})
        ret_val.append({"protocol":"IPv6 Unicast", "neighbor":intf, "state":"Up"})

    for d in cfg_dict['nodes']['l2l3vni']:
        if (dut not in d):
            other_dut.append(d)
    for d in other_dut:
        ret_val.append({"protocol":"L2VPN EVPN", "neighbor":loopback_ip[d], "state":"Up"})

    return ret_val

@VerifyLoop()
def verify_bgp_summary(dut, exp_data, **kwargs):
    """
    verify show bgp summary output attributes
    """
    act_data = get_bgp_summary(dut)
    # Change state from number to "up"
    for item in act_data:
        if item['state'].isnumeric():
            item['state'] = 'Up'
    compare_exp_actual_data(exp_data, act_data, ['protocol', 'neighbor', 'state'])

def get_bfd_summary(dut):
    """
    parses 'show bfd summary' output into data struct below
    cisco@sonic:~$ show bfd summary
    Total number of BFD sessions: 4
    Peer Addr                  Interface    Vrf      State    Type          Local Addr                   TX Interval    RX Interval    Multiplier  Multihop      Local Discriminator
    -------------------------  -----------  -------  -------  ------------  -------------------------  -------------  -------------  ------------  ----------  ---------------------
    fe80::7abe:47ff:fe2e:d000  Ethernet1_2  default  Up       async_active  fe80::7aaf:c9ff:fe30:a400            300            300             3  false                           4
    fe80::7ade:27ff:fedc:b000  Ethernet1_3  default  Up       async_active  fe80::7aaf:c9ff:fe30:a400            300            300             3  false                           2
    fe80::7a2a:84ff:fe68:8000  Ethernet1_4  default  Up       async_active  fe80::7aaf:c9ff:fe30:a400            300            300             3  false                           3
    fe80::7acb:a2ff:febb:7000  Ethernet1_1  default  Up       async_active  fe80::7aaf:c9ff:fe30:a400            300            300             3  false                           1
    cisco@sonic:~$
    """
    cmd = 'show bfd summary'
    cmd_output = st.show(dut, cmd, skip_tmpl=True, skip_error_check=False)
    parsed_output = st.parse_show(dut, cmd, cmd_output, 'show_bfd_sum_sonic.tmpl')

    return parsed_output

def get_expected_bfd_summary(dut):
    ret_val = list()
    vars = st.get_testbed_vars()
    int_config_dict = get_config_interfaces_list(vars)
    for intf in int_config_dict[dut]['underlay']:
        ret_val.append({"interface":intf, "state":"Up"})

    return ret_val

@VerifyLoop()
def verify_bfd_summary(dut, exp_data, **kwargs):
    """
    verify show bfd summary output attributes
    """
    act_data = get_bfd_summary(dut)
    compare_exp_actual_data(exp_data, act_data, ['interface', 'state'])
