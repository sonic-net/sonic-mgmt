import pytest
import yaml
from spytest import st, tgapi, SpyTestDict
import re, time
import apis.system.logging as logapi
import apis.system.logging as logapi
import os
import ipaddress
import natsort
import apis.routing.ip as ip_obj
import apis.routing.vrf as vrf_obj
import apis.switching.vlan as vlan_obj
import sys
import importlib

def get_cfg_file():
    pattern = r'/([^/.]+)\.py'
    for item in sys.argv:
        match = re.search(pattern, item)
        if match:
            result = match.group(1)
            break
    my_lib = importlib.import_module(result)
    return my_lib.CONFIGS_FILE

def set_tunnel_counterpoll(action='enable'):
    if action == 'enable':
        cmd = "sudo counterpoll tunnel enable"
    else:
        cmd = "sudo counterpoll tunnel disable"
    return cmd

def generate_l2vni_config(data,l2vni_int_list):
    '''
    Author: Jigar Sanghrajka (jsanghra@cisco.com)
    '''
    output = ''
    # L2VNI configuration
    if data.get('l2vni'):
        vlan_start = data['l2vni']['vlan_start_range']
        count = data['l2vni']['count']
    
        for i in range(count):
            vlan_id = vlan_start + i
            cmd = 'sudo config vlan add {}\n'.format(vlan_id)
            output += cmd
            for item in l2vni_int_list:
                cmd = 'sudo config vlan member add {} {}\n'.format(vlan_id, item)
                output += cmd
            cmd = 'sudo config vxlan map add VXLAN {} {}\n'.format(vlan_id, 5000 + vlan_id)
            output += cmd
    else:
        pass

    return output 

def get_vxlan_mapping(data, mode="add"):
    '''
    Author:Ramsiddarth Ragurajan (rraguraj@cisco.com)
    '''
    output = ''
    if data.get('l2vni'):
        vlan_start = data['l2vni']['vlan_start_range']
        count = data['l2vni']['count']
    for i in range(count):
        vlan_id = vlan_start + i
        if mode == "add":
            cmd = 'sudo config vxlan map add VXLAN {} {}\n'.format(vlan_id, 5000 + vlan_id)
            output += cmd
        elif mode == "del":
            cmd = 'sudo config vxlan map del VXLAN {} {}\n'.format(vlan_id, 5000 + vlan_id)
            output += cmd
        else:
            st.banner("unknown action supported add/del")
            st.report_fail(test_case_failed)
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
    CONFIGS_FILE = get_cfg_file()
    dir_path = os.path.dirname(os.path.realpath(__file__))
    with open(dir_path + '/' + CONFIGS_FILE) as f:
        config_dict = yaml.load(f, Loader=yaml.FullLoader)
        for node, config in config_dict.items(): 
            if node in nodes:
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

def generate_l3vni_config(leaf_data):
    '''
    Author: Jigar Sanghrajka (jsanghra@cisco.com)
    
    '''
    output = ''
    if leaf_data.get('l3vni'):
        # L3VNI configuration
        l3_start = leaf_data['l3vni']['l3_dummy']['start_vlan']
        l3_count = leaf_data['l3vni']['l3_dummy']['count']  

        l2_start = leaf_data['l2vni']['vlan_start_range']
        l2_count = leaf_data['l2vni']['count']
        j = l2_start
        for i in range(l3_count):
            output += 'sudo config vlan add {}\n'.format(l3_start + i)
            output += 'sudo config vrf add Vrf{}\n'.format(l3_start + i)
            output += 'sudo config interface vrf bind Vlan{} Vrf{}\n'.format(j, l3_start + i)
            output += 'sudo config interface vrf bind Vlan{} Vrf{}\n'.format(j+1, l3_start + i)
            j+=2
            output += 'sudo config interface vrf bind Vlan{} Vrf{}\n'.format(l3_start + i, l3_start + i)
            output += 'sudo config vxlan map add VXLAN {} {}\n'.format(l3_start + i, 5000 + l3_start + i)
            output += 'sudo config vrf add_vrf_vni_map Vrf{} {}\n'.format(l3_start + i, 5000 + l3_start + i)
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
    # output += 'neighbor TRANSIT bfd\n'
    output += 'neighbor TRANSIT ebgp-multihop 1\n'
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
    if leaf_data.get('l3vni'):
        start_vlan = leaf_data['l3vni']['l3_dummy']['start_vlan']
        count = leaf_data['l3vni']['l3_dummy']['count']
    elif leaf_data.get('vni'):
        start_vlan = leaf_data['vni']['vlan_start_range']
        count = leaf_data['vni']['count']
    else:
        st.report_fail("vni information not found in input file")

    output += 'router bgp {}\n'.format(as_num)
    output += 'bgp router-id {}\n'.format(router_id)
    for i in range(count):
        vrf = start_vlan + i
        vni = 5000 + vrf
        output += 'router bgp {} vrf Vrf{}\n'.format(as_num, vrf)
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
        output += 'vrf Vrf{}\n'.format(vrf)
        output += 'vni {}\n'.format(vni)
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
        # dut_id = var_dict.dut_ids[node]
        for key,value in var_dict.items(): 
            if dut_id+'T1' in key:
                dut_port_dict[key]= value
            if "T1"+dut_id in key:
                tgen_port_dict[key]= value
            if dut_id in key and "T1" not in key:
                if key != dut_id and dut_id in key[:2]:
                    underlay_dict[key] = value
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
    CONFIGS_FILE = get_cfg_file()
    dir_path = os.path.dirname(os.path.realpath(__file__))
    
    with open(dir_path + '/' + CONFIGS_FILE) as f:
        config = yaml.load(f, Loader=yaml.FullLoader)
        for key,value in var_dict.dut_ids.items():
            if "leaf" in key:
                temp_dict[key] ={}
                if config[key].get('l2vni'):
                    temp_dict[key]['l2vni_int_count'] = config[key]['l2vni']['count']
    for node in var_dict.dut_ids.keys():
        temp_list=[]
        if "spine" in node:
            final_config_dict[node]={}
            final_config_dict[node]['underlay']={}
            for item,value in dut_int_data[node]['underlay_dict'].items():
                temp_list.append(value)
            final_config_dict[node]['underlay'] = sorted(temp_list)
        if "leaf" in node:
            my_list =[]
            for key in dut_int_data[node]['dut_port_dict'].keys():      
                my_list.append(key)
            sorted_list =sorted(my_list)

            for port in sorted_list:
                 temp_list.append(dut_int_data[node]['dut_port_dict'][port])
            config_dict[node] = temp_list
            final_config_dict[node]={}
            final_config_dict[node]['underlay']={}
            temp2_list=[]
            for key,value in dut_int_data[node]['underlay_dict'].items():      
                temp2_list.append(value)
            sorted_list =sorted(temp2_list)
            final_config_dict[node]['underlay'] = sorted(temp2_list)

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
    CONFIGS_FILE = get_cfg_file()
    dir_path = os.path.dirname(os.path.realpath(__file__))
    with open(dir_path + '/' + CONFIGS_FILE) as f:
        config_dict = yaml.load(f, Loader=yaml.FullLoader)
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
    CONFIGS_FILE = get_cfg_file()
    dir_path = os.path.dirname(os.path.realpath(__file__))
    with open(dir_path + '/' + CONFIGS_FILE) as f:
        config_dict = yaml.load(f, Loader=yaml.FullLoader)
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
    router_id = bgp_info['router_id']
    as_num = bgp_info['as_num']
    start_vlan = data['l3vni']['l3_dummy']['start_vlan']
    count = data['l3vni']['l3_dummy']['count']

    
    for i in range(count):
        vrf = start_vlan + i
        vni = 5000 + vrf
        output += 'vrf Vrf{}\n'.format(vrf)
        output += 'no vni {}\n'.format(vni)
        output += 'no router bgp {} vrf Vrf{}\n'.format(as_num, vrf)
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
    CONFIGS_FILE = get_cfg_file()
    dir_path = os.path.dirname(os.path.realpath(__file__))
    with open(dir_path + '/' + CONFIGS_FILE) as f:
        config_dict = yaml.load(f, Loader=yaml.FullLoader)
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
    CONFIGS_FILE = get_cfg_file()
    dir_path = os.path.dirname(os.path.realpath(__file__))
    with open(dir_path + '/' + CONFIGS_FILE) as f:
        config_dict = yaml.load(f, Loader=yaml.FullLoader)
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
        for i in range(config['l2vni']['count']):
            if version == 'ipv4':
                new_ip = generate_new_v4_ip(ip_start,config['l2vni']['vlan_start_range']+i)
            else:
                new_ip = generate_new_v6_ip(ip_start,config['l2vni']['vlan_start_range']+i)
            svi_dict[config['l2vni']['vlan_start_range']+i] = new_ip
        new_ip = ip_start
     
    return svi_dict

###Generate host info###
def generate_sag_hosts(l2vni_intf_dict,svi_dict,version = "ipv4", custom_mac_enable = False, custom_start_mac = "00:00:00:00:99:10"):
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
    for node, values in svi_dict.items():
        if node != 'leaf3':
            host_dict[node] = {}
            for item in l2vni_intf_dict[node]:
                host_dict[node][item] = {}
                for vlan, svi_ip in values.items():
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
    for node, interfaces in l2vni_intf_dict.items():
        topo_handles_dict[node]={}
        for interface in interfaces:
            topo_handles_dict[node][interface]={}
            #create handles
            tg_handle, port_handle = tgapi.get_handle_byname(interface)
            topo_handles_dict[node][interface]['tg_handle'] = tg_handle
            topo_handles_dict[node][interface]['port_handle'] = port_handle

            #create topology
            device_port = tg_handle.tg_topology_config(topology_name = """{} {} topology""".format(node,interface),port_handle = port_handle)
            topology_handle = device_port['topology_handle']
            topo_handles_dict[node][interface]['topology_handle'] = topology_handle
    
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
    for node in host_dict:
        ethernet_handles[node]={}
        device_handles[node]={}
        for interface in topo_handles_dict[node]:
            device_handles[node][interface]={}
            ethernet_handles[node][interface] = {}
            for vlan, values in host_dict[node][interface].items():
                device_group = topo_handles_dict[node][interface]['tg_handle'].tg_topology_config(
                    topology_handle= topo_handles_dict[node][interface]['topology_handle'],
                    device_group_name= """{} device group vlan {}""".format(node,vlan),
                    device_group_multiplier = "1",
                    device_group_enabled= "1"
                    )
                deviceGroup_handle = device_group['device_group_handle']
                device_handles[node][interface][vlan]=deviceGroup_handle
                ###Creating ethernet stack for the Device Group###
                l2_protocol = topo_handles_dict[node][interface]['tg_handle'].tg_interface_config(
                    protocol_name= """Ethernet stack {}""".format(vlan),
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
                st.log("ethernet_handle-->".format(ethernet_handle))
                if version == 'ipv4':
                ### Creating IPv4 Stack for the Device Group###
                    l3_protocol = topo_handles_dict[node][interface]['tg_handle'].tg_interface_config(
                        protocol_name = """IPv4""",
                        protocol_handle=ethernet_handle,
                        ipv4_resolve_gateway= "1",
                        gateway= host_dict[node][interface][vlan]['gateway'],
                        gateway_step= "0.0.0.0",
                        intf_ip_addr = host_dict[node][interface][vlan]['host_ip'],
                        intf_ip_addr_step= "0.0.0.1"
                        )
                    ipv4_handle = l3_protocol['ipv4_handle']
                    st.log("ipv4_handle-->".format(ipv4_handle))
                else:
                    l3_protocol = topo_handles_dict[node][interface]['tg_handle'].tg_interface_config(
                        protocol_name = """IPv6""",
                        protocol_handle=ethernet_handle,
                        ipv6_resolve_gateway= "1",
                        ipv6_gateway= host_dict[node][interface][vlan]['gateway'],
                        ipv6_intf_addr = host_dict[node][interface][vlan]['host_ip'],
                        )
                    ipv6_handle = l3_protocol['ipv6_handle']
                    st.log("ipv6_handle-->".format(ipv6_handle))
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
                        end_point_dict[traffic_item]['dst_vlan'] = vlan
                        end_point_dict[traffic_item]["dst_int"] = interface
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
        for interface,values in interfaces.items():
            temp_dict[interface]={}
            for key, vlan_list in vrf_vlan_dict.items():
                temp_dict[interface][key] = []
                for vlan in vlan_list:
                    if values.get(vlan):
                        temp_dict[interface][key].append(vlan)
                if len(temp_dict[interface][key]) is 0:
                    temp_dict[interface].pop(key)
    l3_endpoint_dict = {}
    def find_pair(list1,list2):
        pair_dict = {}
        i=1
        for item in list1:
            for value in list2:
                if item !=value:
                    pair_dict[i] = (item,value)
                    i+=1    
        return pair_dict
    i=1
    for interface, vrf_list in temp_dict.items():
        if interface !=leaf0_ref_interface:
            for item,values in vrf_list.items():
                pair_dict = find_pair(vrf_list[item],values)
                for item, pair in pair_dict.items():
                    traffic_item = "traffic_item_"+str(i)
                    l3_endpoint_dict[traffic_item] = {}
                    l3_endpoint_dict[traffic_item]["dir"] = str(pair[0])+"-->"+str(pair[1])
                    l3_endpoint_dict[traffic_item]['src_vlan'] = pair[0]
                    l3_endpoint_dict[traffic_item]["src_int"] = leaf0_ref_interface
                    l3_endpoint_dict[traffic_item]['dst_vlan'] = pair[1]
                    l3_endpoint_dict[traffic_item]["dst_int"] = interface
                    i+=1
    return l3_endpoint_dict

def create_traffic_item(device_handles,endpoints,topo_handles, transmit_mode="single_burst",version = "ipv4", udp_header = False):
    '''
    
    '''
    port_handles = {}
    for node, interfaces in topo_handles.items():
        for interface,values in interfaces.items():
            port_handles[interface] =values        
    dut_type = check_hw_or_sim(st.get_dut_names()[0])
    if dut_type == 'sim':
        rate_percent = 0.01
        pkts_per_burst = 100
        transmit_mode = 'single_burst'
    else:
        rate_percent = 10
        pkts_per_burst = 1000
        transmit_mode = transmit_mode
    stream_handles = {}
    traffic_item_list = natsort.natsorted(set(list(endpoints.keys())))
    i=1
    for traffic_item in traffic_item_list:  
        emulation_src_handle = device_handles[endpoints[traffic_item]['src_int']][endpoints[traffic_item]['src_vlan']]
        emulation_dst_handle = device_handles[endpoints[traffic_item]['dst_int']][endpoints[traffic_item]['dst_vlan']]
        tg_handle = port_handles[endpoints[traffic_item]['src_int']]['tg_handle']
        port_handle = port_handles[endpoints[traffic_item]['src_int']]['port_handle']
        port_handle2 = port_handles[endpoints[traffic_item]['dst_int']]['port_handle']
        if transmit_mode == "single_burst":
            if udp_header:
                stream = tg_handle.tg_traffic_config(
                    port_handle = port_handle,
                    port_handle2 = port_handle2,
                    mode='create', 
                    bidirectional=1,
                    transmit_mode=transmit_mode, 
                    pkts_per_burst=pkts_per_burst,
                    rate_percent =rate_percent, 
                    circuit_endpoint_type=version, 
                    frame_size='500', 
                    emulation_src_handle=emulation_src_handle, 
                    emulation_dst_handle=emulation_dst_handle,
                    l4_protocol='udp'
                    )
            else:
                stream = tg_handle.tg_traffic_config(
                    port_handle = port_handle,
                    port_handle2 = port_handle2,
                    mode='create', 
                    bidirectional=1,
                    transmit_mode=transmit_mode, 
                    pkts_per_burst=pkts_per_burst,
                    rate_percent =rate_percent, 
                    circuit_endpoint_type=version, 
                    frame_size='500', 
                    emulation_src_handle=emulation_src_handle, 
                    emulation_dst_handle=emulation_dst_handle
                    )
            stream_id = stream["stream_id"]
            stream_handles[i] = {}
            stream_handles[i]['stream_id'] = stream_id
            stream_handles[i]['tg_handle'] = tg_handle
            stream_handles[i]['port_handle'] = port_handle
            i+=1
            st.wait(1) 
        else:
            #add continous mode support
            st.log("Unknown transmit type")
    return stream_handles

def delete_traffic_item(tg_handle, stream_handle):
    tg_handle.tg_traffic_config(mode = 'remove', stream_id = stream_handle)
    
def check_traffic(streams_info, regenerate_traffic_items = False):
    '''
    Author:Ramsiddarth Ragurajan (rraguraj@cisco.com)

    '''
    flag = True
    stream_list = []
    for item , values in streams_info.items():
        stream_list.append(values['stream_id']) 
    tg_handle = streams_info[1]['tg_handle']
    
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
    
    for traffic_item, values in streams_info.items():
        traffic_stat = tgapi.get_traffic_stats(values['tg_handle'], mode='streams', port_handle=values['port_handle'], direction='tx', stream_handle=values['stream_id'])
        st.banner("BI-DIRECTIONAL TRAFFIC ITEM {}".format(traffic_item))
        st.log("Received traffic: {}".format(traffic_stat['rx']['total_packets']))
        st.log("Sent traffic: {}".format(traffic_stat['tx']['total_packets']))
        st.log(traffic_stat['rx']['total_packets']/traffic_stat['tx']['total_packets'])
        if traffic_stat['rx']['total_packets'] > 0.998*traffic_stat['tx']['total_packets'] and traffic_stat['rx']['total_packets'] < 1.002*traffic_stat['tx']['total_packets']:
            st.log("BI-DIRECTIONAL TRAFFIC ITEM {} PASSED".format(traffic_item))
        else:
            st.log("BI-DIRECTIONAL TRAFFIC ITEM {} FAILED".format(traffic_item))
            flag = False
                  
    return flag

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
    cmd_list_1 = ["show mac", "show arp","show vlan brief","show ip int" ,"show vxlan tunnel" , 
    "show vxlan remotemac all","show vrf", "show ipv6 route vrf all", "show ip route vrf all"]
    #vtysh
    cmd_list_2 = ["do show bgp summary", "do show bgp l2vpn evpn route type 2", "do show bgp l2vpn evpn route type 3", "do show bgp l2vpn evpn route type 5"]

    for node in nodes:
        for item in cmd_list_1:
            st.config(node, item)
        for item in cmd_list_2:
            st.config(node, item, type='vtysh', skip_error_check=True)

def delete_vrf(node, vrf_id):
    ##vtysh
    #find vni mapping 
    cli_output = st.show(node, "show vxlan vrfvnimap", skip_tmpl=True)
    parsed_output = st.parse_show(node, "show vxlan vrfvnimap",cli_output, "show_vxlan_vrfvnimap.tmpl")
    ref_vni = ""
    as_num = generate_bgp_underlay_info()[node]['as_num']
    CONFIGS_FILE = get_cfg_file()
    dir_path = os.path.dirname(os.path.realpath(__file__))
    with open(dir_path + '/' + CONFIGS_FILE) as f:
        config_dict = yaml.load(f, Loader=yaml.FullLoader)
    for item in parsed_output:
        if item['vrf'] == vrf_id:
            ref_vni = item['vni']
    cmd = "vrf {}\n".format(vrf_id)
    cmd += "no vni {}\n".format(ref_vni)
    cmd += 'no router bgp {} vrf {}\n'.format(as_num, vrf_id)
    cmd += 'exit\n' 
    st.config(node, cmd, type='vtysh', skip_error_check=True)

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
    CONFIGS_FILE = get_cfg_file()
    dir_path = os.path.dirname(os.path.realpath(__file__))
    with open(dir_path + '/' + CONFIGS_FILE) as f:
        config_dict = yaml.load(f, Loader=yaml.FullLoader)
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
    CONFIGS_FILE = get_cfg_file()
    dir_path = os.path.dirname(os.path.realpath(__file__))
    with open(dir_path + '/' + CONFIGS_FILE) as f:
        config_dict = yaml.load(f, Loader=yaml.FullLoader)
        node_list = sorted(list(config_dict.keys()))
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
    CONFIGS_FILE = get_cfg_file()
    dir_path = os.path.dirname(os.path.realpath(__file__))
    with open(dir_path + '/' + CONFIGS_FILE) as f:
        config_dict = yaml.load(f, Loader=yaml.FullLoader)
        node_list = sorted(list(config_dict.keys()))
    for node in node_list:
        bgp_info[node] = {}
        if "spine" in node:
            bgp_info[node]["router_id"] = spine_router_id_start
            bgp_info[node]["as_num"] = spine_as_no_start
            spine_as_no_start+=1
            spine_router_id_start = str(ipaddress.ip_address(unicode(spine_router_id_start)) + 1)
        else:
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
    for node , ip_addr in loopback_dict.items():
        if "leaf" in node:
            ip_list.append(ip_addr)
    for node , ip_addr in loopback_dict.items():
        if "leaf" in node:
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
    CONFIGS_FILE = get_cfg_file()
    dir_path = os.path.dirname(os.path.realpath(__file__))
    with open(dir_path + '/' + CONFIGS_FILE) as f:
        config_dict = yaml.load(f, Loader=yaml.FullLoader)
        for node , config in config_dict.items():
            if 'leaf' in node:
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

def config_feature(nodes,feature):
    vars = st.get_testbed_vars()
    if feature in ['loopback', 'nvo', 'delete_loopback']: 
        loopback_ip = generate_loopback_ip(version = st.getenv("vtep"))
    if feature in ['bgp_underlay', 'delete_bgp_config','bgp_l3vni_config','delete_bgp_l3vni_config']:
        bgp_info = generate_bgp_underlay_info()
    if feature == "bgp_overlay":
        overlay_info = generate_bgp_overlay_info(version = st.getenv("vtep"))
    CONFIGS_FILE = get_cfg_file()
    dir_path = os.path.dirname(os.path.realpath(__file__))
    with open(dir_path + '/' + CONFIGS_FILE) as f:
        config_dict = yaml.load(f, Loader=yaml.FullLoader)
        for node, config in config_dict.items():
            if node in nodes:
                print("Inside {}".format(node))
                if feature == 'l3vni':
                    config_out = generate_l3vni_config(config)
                elif feature == 'l2vni':
                    int_config_dict = get_config_interfaces_list(vars) 
                    config_out = generate_l2vni_config(config,int_config_dict[node]['l2vni_int'])
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
                elif feature == 'unnumbered':
                    int_config_dict = get_config_interfaces_list(vars) 
                    config_out = generate_bgp_unnumbered_config(int_config_dict[node]['underlay'])
                elif feature == 'enable_tunnel_counters':
                    config_out = set_tunnel_counterpoll()
                elif feature == 'disable_tunnel_counters':
                    config_out = set_tunnel_counterpoll(action ='disable')
                elif feature == 'delete_l2vni':
                    config_out = delete_l2vni_config(config)
                elif feature == 'delete_l3vni':
                    config_out = delete_l3vni_config(config)
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
                if feature in ['bgp_l3vni_config','bgp_underlay','bgp_overlay','delete_bgp_config','delete_bgp_l3vni_config']:
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