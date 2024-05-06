from spytest import st, tgapi
import yaml
import os
import re


def config_vlan(node, vlan, members = [], vrf = None, add = True):
    config = ''
    if add:
        config = config + 'sudo config vlan add {}\n'.format(vlan)
        for member in members:
            config = config + 'sudo config vlan member add -u {} {}\n'.format(vlan, member)
        if vrf:
            config = config + 'sudo config interface vrf bind {} {}\n'.format('Vlan' + str(vlan), vrf)

    else:
        if vrf:
            config = config + 'sudo config interface vrf unbind {}\n'.format('Vlan' + str(vlan))
        for member in members:
            config = config + 'sudo config vlan member del {} {}\n'.format(vlan, member)
        config = config + 'sudo config vlan del {}\n'.format(vlan)

    st.config(node, config, skip_error_check=False, conf=True)


def config_vxlan_map(node, vxlan, vni, vrf=None, vlan=None, add=True):
    config = ''
    if add:
        if vlan:
            config = config + 'sudo config vxlan map add {} {} {}\n'.format(vxlan, vlan, vni)
        if vrf:
            config = config + 'sudo config vrf add_vrf_vni_map {} {}\n'.format(vrf, vni)
    else:
        if vrf:
            config = config + 'sudo config vrf del_vrf_vni_map {}\n'.format(vrf)
        if vlan:
            config = config + 'sudo config vxlan map del {} {} {}\n'.format(vxlan, vlan, vni)
    st.config(node, config, skip_error_check=False, conf=True)


def config_vrf(node, vrf, add=True):
    config = ''
    if add:
        config = config + 'sudo config vrf add {}'.format(vrf)
    else:
        config = config + 'sudo config vrf del {}'.format(vrf)

    st.config(node, config, skip_error_check=False, conf=True)


def tgen_preconfig(stream_info, traffic_item_type, data):
    '''  
    Author:Ramsiddarth Ragurajan (rraguraj@cisco.com)

    Example:
    traffic_item_type:
    raw  --> Creates unidirectional raw stream and provides the handles (for unidirectional BUM/unicast traffic)
    bounded  --> Creates bidirectional bounded stream and provides the handles (for bidirectional unicast traffic)
    Sample input:
    tgen_preconfig({"src_endpoint": {"port" : "T1D3P1", "host_ip": 10.10.10.5, "gateway": 10.10.10.1, "mac" : 00:00:00:00:00:01 }, 
                    "dst_endpoint" : {"port" : "T1D4P1","host_ip": 10.10.10.10, "gateway": 10.10.10.1, "mac" : 00:00:00:00:00:02 }},"raw")


    returns tgen handle, port handles and stream id for traffic item
    
    '''
    handles = {}
    all_port_handles=[]
    if stream_info.get('src_endpoint') and stream_info.get('dst_endpoint'):
        tg_handle1, port_handle1 = tgapi.get_handle_byname(stream_info['src_endpoint']['port'])
        tg_handle2, port_handle2 = tgapi.get_handle_byname(stream_info['dst_endpoint']['port'])

        all_port_handles.append(port_handle1)
        all_port_handles.append(port_handle2)

        tg_handle1.tg_traffic_control(action='clear_stats', port_handle=[port_handle1, port_handle2])
        ###Tgen interface config###
        res1=tg_handle1.tg_interface_config(port_handle=port_handle1, mode='config', intf_ip_addr=stream_info['src_endpoint']['host_ip'], gateway=stream_info['src_endpoint']['gateway'], src_mac_addr=stream_info['src_endpoint']['mac'], arp_send_req='1')
        int_handle_1= res1['handle']
        res2=tg_handle2.tg_interface_config(port_handle=port_handle2, mode='config', intf_ip_addr=stream_info['dst_endpoint']['host_ip'], gateway=stream_info['dst_endpoint']['gateway'], src_mac_addr=stream_info['dst_endpoint']['mac'], arp_send_req='1')
        int_handle_2 = res2['handle']
        st.wait(60)
        ###PING TEST###
        ping_result = tgapi.verify_ping(src_obj=tg_handle1, port_handle=port_handle1, dev_handle=int_handle_1, dst_ip=stream_info['dst_endpoint']['host_ip'],ping_count='5', exp_count='5')
        if ping_result:
            st.log("Ping succeeded.")
        else:
            st.log("Ping failed")
            st.report_fail("Ping failed between endpoints")
        ### Create Traffic Stream ###
        if traffic_item_type == "bounded":
            ###Bidirectional###
            receive = tg_handle1.tg_traffic_config(port_handle=port_handle1, port_handle2=port_handle2, mode='create', 
                    bidirectional=1, transmit_mode=data.transmit_mode, pkts_per_burst=data.pkts_per_burst,rate_percent = data.rate_percent, circuit_endpoint_type=data.circuit_endpoint_type, 
                    frame_size=data.frame_size, emulation_src_handle=int_handle_1, emulation_dst_handle=int_handle_2)
            stream_id = receive["stream_id"]
            handles = {"tg_handle": tg_handle1,"port_handle1": port_handle1, "port_handle2": port_handle2, "stream_id": stream_id,"all_port_handles": all_port_handles,"traffic_item_type": traffic_item_type}
        elif traffic_item_type == "raw":
            ###Unidirection###
            receive = tg_handle1.tg_traffic_config(port_handle=port_handle1, port_handle2=port_handle2, mode='create', 
                    transmit_mode=data.transmit_mode, pkts_per_burst=data.pkts_per_burst, rate_percent = data.rate_percent, circuit_endpoint_type=data.circuit_endpoint_type, 
                    frame_size=data.frame_size, mac_src=stream_info['src_endpoint']['mac'], mac_dst=stream_info['dst_endpoint']['mac'])
            stream_id = receive["stream_id"]
            handles = {"tg_handle": tg_handle1,"port_handle1": port_handle1, "port_handle2": port_handle2, "stream_id": stream_id,"all_port_handles": all_port_handles,"traffic_item_type": traffic_item_type}
        else:
             st.log("Unknown traffic_item_type")
             st.report_fail("Unknown traffic_item_type")
    else:
        st.log("Missing src or dest endpoints")
        st.report_fail("Missing src or dest endpoints")

    return handles


def traffic_test_burst(_mode,handles):
    '''  
    Author:Ramsiddarth Ragurajan (rraguraj@cisco.com)

    '''
    ### Clear Statistics ###
    handles['tg_handle'].tg_traffic_control(action="clear_stats", port_handle=handles['all_port_handles'])

    ### Send ARP ###
    for item in handles['all_port_handles']:
        handles['tg_handle'].tg_interface_config(port_handle=item, mode='modify', arp_send_req='1')
    ###raw traffic for BUM###
    if handles['traffic_item_type'] == 'raw':
        if _mode == "broadcast":
            dst_mac = "ff:ff:ff:ff:ff:ff"
        elif _mode == "multicast":
            dst_mac = "01:00:5e:44:44:44"
        elif _mode == "unknownunicast":
            dst_mac = "00:44:44:44:44:44"
        ###Modify the destination MAC###
        if _mode != "unicast":
            handles['tg_handle'].tg_traffic_config(port_handle=handles['port_handle1'], port_handle2=handles['port_handle2'], mode='modify', mac_dst=dst_mac, stream_id = handles['stream_id'])
            st.wait(5)
    
    handles['tg_handle'].tg_traffic_control(action='run', stream_handle=handles['stream_id'])
    st.wait(30)
    handles['tg_handle'].tg_traffic_control(action='stop', stream_handle=handles['stream_id'])
    st.wait(5)
    flag = False
    traffic_stat = tgapi.get_traffic_stats(handles['tg_handle'], mode='streams', port_handle=handles['port_handle1'], direction='tx', stream_handle=handles['stream_id'])
    st.log("Received traffic: {}".format(traffic_stat['rx']['total_packets']))
    st.log("Sent traffic: {}".format(traffic_stat['tx']['total_packets']))
    st.log(traffic_stat['rx']['total_packets']/traffic_stat['tx']['total_packets'])
    if traffic_stat['rx']['total_packets'] > 0.998*traffic_stat['tx']['total_packets'] and traffic_stat['rx']['total_packets'] < 1.002*traffic_stat['tx']['total_packets']:
        flag = True
    else:
        flag = False
    return flag


def config_tgen_interface(int_dict):
    '''
    Author:Ramsiddarth Ragurajan (rraguraj@cisco.com)

    input:

    int_dict = {"T1D3P1": {"host_ip": data.tp1d3_ip_addr, "gateway": data.d3tp1_ip_addr, "mac" : data.tp1d3_mac_addr }, 
                "T1D3P2" : {"host_ip": data.tp3d3_ip_addr, "gateway": data.d3tp3_ip_addr, "mac" : data.tp3d3_mac_addr },
                "T1D4P1": {"host_ip": data.tp2d4_ip_addr, "gateway": data.d4tp2_ip_addr, "mac" : data.tp2d4_mac_addr},
                "T1D4P2": {"host_ip": data.tp4d4_ip_addr, "gateway": data.d4tp4_ip_addr, "mac" :data.tp4d4_mac_addr}}

    return values EX:
    {'T1D4P2': {'tg_handle': <spytest.tgen.tg.TGIxia object at 0x7fd22a877950>, 'int_handle': '/topology:1/deviceGroup:1/ethernet:1/ipv4:1/item:1', 'port_handle': '1/1/4'}, 
    'T1D4P1': {'tg_handle': <spytest.tgen.tg.TGIxia object at 0x7fd22a877950>, 'int_handle': '/topology:2/deviceGroup:1/ethernet:1/ipv4:1/item:1', 'port_handle': '1/1/3'}, 
    'T1D3P1': {'tg_handle': <spytest.tgen.tg.TGIxia object at 0x7fd22a877950>, 'int_handle': '/topology:3/deviceGroup:1/ethernet:1/ipv4:1/item:1', 'port_handle': '1/1/1'}, 
    'T1D3P2': {'tg_handle': <spytest.tgen.tg.TGIxia object at 0x7fd22a877950>, 'int_handle': '/topology:4/deviceGroup:1/ethernet:1/ipv4:1/item:1', 'port_handle': '1/1/2'}}
    '''
    handles = {}
    all_port_handles=[]
    for port, values in int_dict.items():
        tg_handle, port_handle = tgapi.get_handle_byname(port)
        res=tg_handle.tg_interface_config(port_handle=port_handle, mode='config', intf_ip_addr=values['host_ip'], gateway=values['gateway'], src_mac_addr=values['mac'], arp_send_req='1')
        int_handle= res['handle']
        handles[port] = {"tg_handle": tg_handle, "port_handle": port_handle,"int_handle": int_handle}
    return handles


def config_traffic_item(stream_list, handles, int_dict, data, ping=True):
    '''
    Author:Ramsiddarth Ragurajan (rraguraj@cisco.com)

    Input --> list of enpoints for which traffic item to be created and handles from config_tgen_interface
    stream_list = [("T1D3P1","T1D4P1"), ("T1D3P1", "T1D3P2"),("T1D3P1", "T1D4P2"),("T1D3P2", "T1D4P2"),("T1D3P2", "T1D4P1")]

    output: traffic_item_dict
    {'T1D3P1<-->T1D4P2': {'stream_id': 'TI2-HLTAPI_TRAFFICITEM_540', 'port_handle': '1/1/1', 'tg_handle': <spytest.tgen.tg.TGIxia object at 0x7f1f54d5ef10>},
     'T1D3P2<-->T1D4P1': {'stream_id': 'TI4-HLTAPI_TRAFFICITEM_540', 'port_handle': '1/1/2', 'tg_handle': <spytest.tgen.tg.TGIxia object at 0x7f1f54d5ef10>}, 
     'T1D3P1<-->T1D4P1': {'stream_id': 'TI0-HLTAPI_TRAFFICITEM_540', 'port_handle': '1/1/1', 'tg_handle': <spytest.tgen.tg.TGIxia object at 0x7f1f54d5ef10>}, 
     'T1D3P2<-->T1D4P2': {'stream_id': 'TI3-HLTAPI_TRAFFICITEM_540', 'port_handle': '1/1/2', 'tg_handle': <spytest.tgen.tg.TGIxia object at 0x7f1f54d5ef10>}, 
     'T1D3P1<-->T1D3P2': {'stream_id': 'TI1-HLTAPI_TRAFFICITEM_540', 'port_handle': '1/1/1', 'tg_handle': <spytest.tgen.tg.TGIxia object at 0x7f1f54d5ef10>}}
    '''
    traffic_item_dict = {}
    for item in stream_list:
        receive = handles[item[0]]["tg_handle"].tg_traffic_config(port_handle=handles[item[0]]["port_handle"], port_handle2=handles[item[1]]["port_handle"], mode='create', 
                    bidirectional=1, transmit_mode=data.transmit_mode, pkts_per_burst=data.pkts_per_burst, rate_percent = data.rate_percent, circuit_endpoint_type=data.circuit_endpoint_type, 
                    frame_size=data.frame_size, emulation_src_handle=handles[item[0]]["int_handle"], emulation_dst_handle=handles[item[1]]["int_handle"])
        stream_id = receive["stream_id"]
        traffic_item_dict[item[0]+"<-->"+item[1]] = {"stream_id":stream_id, "port_handle": handles[item[0]]["port_handle"] , "tg_handle": handles[item[0]]["tg_handle"]}
        st.wait(5)
        if ping:
            ###PING TEST###
            ping_result = tgapi.verify_ping(src_obj=handles[item[0]]["tg_handle"], port_handle=handles[item[0]]["port_handle"], dev_handle=handles[item[0]]["int_handle"], dst_ip=int_dict[item[1]]['host_ip'],ping_count='5', exp_count='5')
            if ping_result:
                st.banner("Ping succeeded between endpoints for stream {} ".format(item[0]+"<-->"+item[0]))
            else:
                st.banner("Ping failed between endpoints for stream {} ".format(item[0]+"<-->"+item[0]))
                st.report_fail("Ping failed between endpoints")
        ### Clear Statistics ###
        handles[item[0]]["tg_handle"].tg_traffic_control(action="clear_stats", port_handle=[handles[item[0]]["port_handle"], handles[item[1]]["port_handle"]]) 
    return traffic_item_dict


def check_traffic(streams_info):
    '''
    Author:Ramsiddarth Ragurajan (rraguraj@cisco.com)

    '''
    flag = True
    for traffic_item, values in streams_info.items(): 
        values['tg_handle'].tg_traffic_control(action='run', stream_handle=values['stream_id'])
        st.wait(30)
        values['tg_handle'].tg_traffic_control(action='stop', stream_handle=values['stream_id'])
        st.wait(5)
        traffic_stat = tgapi.get_traffic_stats(values['tg_handle'], mode='streams', port_handle=values['port_handle'], direction='tx', stream_handle=values['stream_id'])
        st.banner("BI-DIRECTIONAL TRAFFIC BEWTEEN {}".format(traffic_item))
        st.log("Received traffic: {}".format(traffic_stat['rx']['total_packets']))
        st.log("Sent traffic: {}".format(traffic_stat['tx']['total_packets']))
        st.log(traffic_stat['rx']['total_packets']/traffic_stat['tx']['total_packets'])
        if traffic_stat['rx']['total_packets'] > 0.998*traffic_stat['tx']['total_packets'] and traffic_stat['rx']['total_packets'] < 1.002*traffic_stat['tx']['total_packets']:
            st.banner("BI-DIRECTIONAL TRAFFIC BEWTEEN {} PASSED".format(traffic_item))
        else:
            st.banner("BI-DIRECTIONAL TRAFFIC BEWTEEN {} FAILED".format(traffic_item))
            st.report_fail("BI-DIRECTIONAL TRAFFIC BEWTEEN {} FAILED".format(traffic_item))
            flag = False
    return flag


def modify_config_file(config_file,var_dict):
    '''
    Author:Ramsiddarth Ragurajan (rraguraj@cisco.com)
    
    '''
    output_yaml_file = "temp_config.yaml"
    input_yaml_file = config_file
    dir_path = os.path.dirname(os.path.realpath(__file__))+"/"
    result = os.system("cp {0}{1} {0}{2}".format(dir_path,input_yaml_file,output_yaml_file))
    if result != 0:
        st.report_fail("config file copy failed")
    st.wait(2)
    for item, value in var_dict.items():
        if re.match("(D.D.P.)|(D.T.P.)", item):
            find_and_replace(dir_path+output_yaml_file, item, value)
    return dir_path+output_yaml_file


def find_and_replace(file_path, target_string, replacement_string):
    with open(file_path, 'r') as file:
        data = yaml.safe_load(file)
    # Iterate through the YAML data recursively
    def replace_string(obj):
        if isinstance(obj, str):
            return obj.replace(target_string, replacement_string)
        elif isinstance(obj, dict):
            return {key: replace_string(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [replace_string(item) for item in obj]
        else:
            return obj
    updated_data = replace_string(data)
    with open(file_path, 'w') as file:
        yaml.dump(updated_data, file)


def remove_temp_config(updated_config_file):
    os.system("rm {}".format(updated_config_file))


def report_fail(dut, msg=''):
    st.log(msg, dut)
    st.error(msg, dut)
    st.report_fail('test_case_failed', dut)

def verify_vtep_state (vtep_ip_dict):
    leaf0_vtep_ip = vtep_ip_dict["LEAF0_VXLAN_IP"]
    leaf1_vtep_ip = vtep_ip_dict["LEAF1_VXLAN_IP"]

    leaf0_output = st.show('leaf0', "show vxlan remotevtep", skip_tmpl=True)

    leaf0_parsed = st.parse_show('leaf0', "show vxlan remotevtep",
                                 leaf0_output, "show_vxlan_remote.tmpl")

    leaf1_output = st.show('leaf1', "show vxlan remotevtep", skip_tmpl=True)

    leaf1_parsed = st.parse_show('leaf1', "show vxlan remotevtep",
                                 leaf1_output, "show_vxlan_remote.tmpl")

    if len(leaf0_parsed) == 0:
        report_fail('leaf0', msg='No remote VTEP found in leaf0')

    vtep_num = 0
    for path in leaf0_parsed:
        vtep_num += 1
        if path['tun_src'] != 'EVPN':
            report_fail('leaf0', msg='Unexpected tunnel type {} in leaf0'.format(path['tun_src']))
        if path['src_vtep'] != leaf0_vtep_ip:
            report_fail('leaf0', msg='No local vtep {} found in leaf0'.format(leaf0_vtep_ip))
        if path['dst_vtep'] != leaf1_vtep_ip:
            report_fail('leaf0', msg='Unexpected vtep {} found in leaf0'.format(path['dst_vtep']))
        if path['tun_status'] != 'oper_up':
            report_fail('leaf0', msg='Tunnel is not in up status in leaf0')
    if vtep_num != 1:
        report_fail('leaf0', msg='Incorrect number of VTEPs found in leaf0')

    if len(leaf1_parsed) == 0:
        report_fail('leaf1', msg='No remote VTEP found in leaf1')
    vtep_num = 0
    for path in leaf1_parsed:
        vtep_num += 1
        if path['tun_src'] != 'EVPN':
            report_fail('leaf1', msg='Unexpected tunnel type {} in leaf1'.format(path['tun_src']))
        if path['src_vtep'] != leaf1_vtep_ip:
            report_fail('leaf1', msg='No local vtep {} found in leaf1'.format(leaf1_vtep_ip))
        if path['dst_vtep'] != leaf0_vtep_ip:
            report_fail('leaf1', msg='Unexpected vtep {} found in leaf1'.format(path['dst_vtep']))
        if path['tun_status'] != 'oper_up':
            report_fail('leaf1', msg='Tunnel is not in up status in leaf1')
    if vtep_num != 1:
        report_fail('leaf1', msg='Incorrect number of VTEPs found in leaf1')

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

