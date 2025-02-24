from spytest import st, tgapi
import tgen_utils_cmn as tgen_utils
import yaml
import os
import re
import time

NO_OF_RETRIES = 6 
REMOTE_VTEP_COUNT = '1'
NO_OF_BGP_RETRIES = 20

def config_vlan(node, vlan, members = [], vrf = None, add = True, tagged = False):
    config = ''
    if add:
        config = config + 'sudo config vlan add {}\n'.format(vlan)
        for member in members:
            if tagged:
                config = config + 'sudo config vlan member add {} {}\n'.format(vlan, member)
            else:
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

def clear_counters():
    for dut in st.get_dut_names():
        if "leaf" in dut:
            st.show(dut, 'sonic-clear counters', skip_tmpl=True)
            st.show(dut, 'sonic-clear tunnelcounters', skip_tmpl=True)

def verify_ping(handles, dest_ip, count='5'):
    ping_result = tgen_utils.verify_interface_ping(src_obj=handles['tg_handle'], dev_handle=handles['int_handle'], dst_ip=dest_ip, ping_count=count, exp_count=count)
    if ping_result:
        st.log("Ping succeeded.")
    else:
        st.log("Ping failed")
    return ping_result

def tgen_preconfig(stream_info, traffic_item_type, data, addr_family='ipv4'):
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
        if addr_family == 'ipv6':
            res1=tg_handle1.tg_interface_config(port_handle=port_handle1, mode='config', ipv6_intf_addr=stream_info['src_endpoint']['host_ip'], ipv6_prefix_length='64', ipv6_gateway=stream_info['src_endpoint']['gateway'], src_mac_addr=stream_info['src_endpoint']['mac'], arp_send_req='1')
            int_handle_1= res1['handle']
            res2=tg_handle2.tg_interface_config(port_handle=port_handle2, mode='config', ipv6_intf_addr=stream_info['dst_endpoint']['host_ip'], ipv6_prefix_length='64', ipv6_gateway=stream_info['dst_endpoint']['gateway'], src_mac_addr=stream_info['dst_endpoint']['mac'], arp_send_req='1')
            int_handle_2 = res2['handle']
        else:
            res1=tg_handle1.tg_interface_config(port_handle=port_handle1, mode='config', intf_ip_addr=stream_info['src_endpoint']['host_ip'], gateway=stream_info['src_endpoint']['gateway'], src_mac_addr=stream_info['src_endpoint']['mac'], arp_send_req='1')
            int_handle_1= res1['handle']
            res2=tg_handle2.tg_interface_config(port_handle=port_handle2, mode='config', intf_ip_addr=stream_info['dst_endpoint']['host_ip'], gateway=stream_info['dst_endpoint']['gateway'], src_mac_addr=stream_info['dst_endpoint']['mac'], arp_send_req='1')
            int_handle_2 = res2['handle']
        st.wait(60)
        ###PING TEST###
        ping_result = tgen_utils.verify_interface_ping(src_obj=tg_handle1, dev_handle=int_handle_1, dst_ip=stream_info['dst_endpoint']['host_ip'],ping_count='5', exp_count='5')
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
            handles = {"tg_handle": tg_handle1, "int_handle" : int_handle_1, "port_handle1": port_handle1, "port_handle2": port_handle2, "stream_id": stream_id,"all_port_handles": all_port_handles,"traffic_item_type": traffic_item_type}
        elif traffic_item_type == "raw":
            ###Unidirection###
            receive = tg_handle1.tg_traffic_config(port_handle=port_handle1, port_handle2=port_handle2, mode='create', 
                    transmit_mode=data.transmit_mode, pkts_per_burst=data.pkts_per_burst, rate_percent = data.rate_percent, circuit_endpoint_type=data.circuit_endpoint_type, 
                    frame_size=data.frame_size, mac_src=stream_info['src_endpoint']['mac'], mac_dst=stream_info['dst_endpoint']['mac'])
            stream_id = receive["stream_id"]
            handles = {"tg_handle": tg_handle1, "int_handle" : int_handle_1, "port_handle1": port_handle1, "port_handle2": port_handle2, "stream_id": stream_id,"all_port_handles": all_port_handles,"traffic_item_type": traffic_item_type}
        else:
             st.log("Unknown traffic_item_type")
             st.report_fail("Unknown traffic_item_type")
    else:
        st.log("Missing src or dest endpoints")
        st.report_fail("Missing src or dest endpoints")
    return handles

def create_udp_traffic_stream(handles, data, stream_list,timeout=30):
    flag = True
    src_port = stream_list['src_endpoint']['port']
    dst_port = stream_list['dst_endpoint']['port']
    receive = handles[src_port]["tg_handle"].tg_traffic_config(
                    mode='create', transmit_mode=data.transmit_mode,
                    pkts_per_burst=data.pkts_per_burst, rate_percent = data.rate_percent,
                    circuit_endpoint_type=data.circuit_endpoint_type,
                    frame_size=data.frame_size,
                    emulation_src_handle=handles[src_port]["int_handle"],
                    emulation_dst_handle=handles[dst_port]["int_handle"],
                    track_by = 'trackingenabled0',
                    l4_protocol='udp',
                    udp_dst_port_mode='incr',udp_dst_port_count=500,udp_dst_port_step=1,
                    udp_src_port_mode='incr',udp_src_port_count=500,udp_src_port_step=1)
    stream_id = receive["stream_id"]
    return stream_id

def send_udp_traffic(handles, data, stream_list, stream_id, timeout=30):
    src_port = stream_list['src_endpoint']['port']
    dst_port = stream_list['dst_endpoint']['port']
    handles[src_port]["tg_handle"].tg_traffic_control(
                action="clear_stats",
                port_handle=[handles[src_port]["port_handle"],
                handles[dst_port]["port_handle"]])
    traffic_item = src_port+"-->"+dst_port
    handles[src_port]['tg_handle'].tg_traffic_control(action='apply', stream_handle=stream_id)
    handles[src_port]['tg_handle'].tg_traffic_control(action='run', stream_handle=stream_id)
    st.wait(timeout)
    handles[src_port]['tg_handle'].tg_traffic_control(action='stop', stream_handle=stream_id)
    st.wait(5)
    traffic_stat = tgapi.get_traffic_stats(handles[src_port]['tg_handle'], mode='traffic_item', port_handle=handles[src_port]['port_handle'], direction='tx', stream_handle=stream_id)
    st.banner("UNI-DIRECTIONAL TRAFFIC BEWTEEN {}".format(traffic_item))
    st.log("Received traffic: {}".format(traffic_stat['rx']['total_packets']))
    st.log("Sent traffic: {}".format(traffic_stat['tx']['total_packets']))
    st.log(traffic_stat['rx']['total_packets']/traffic_stat['tx']['total_packets'])
    if traffic_stat['rx']['total_packets'] > 0.998*traffic_stat['tx']['total_packets'] and traffic_stat['rx']['total_packets'] < 1.002*traffic_stat['tx']['total_packets']:
        st.banner("UNI-DIRECTIONAL TRAFFIC BEWTEEN {} PASSED".format(traffic_item))
        flag = True
    else:
        st.banner("UNI-DIRECTIONAL TRAFFIC BEWTEEN {} FAILED".format(traffic_item))
        flag = False
    return flag

def delete_udp_traffic_stream(handles, stream_list):
    src_port = stream_list['src_endpoint']['port']
    handles[src_port]['tg_handle'].tg_traffic_control(action='reset')

def create_unicast_udp_traffic_stream_and_send_traffic(handles, data, stream_list):
    flag = True
    stream_id = create_udp_traffic_stream(handles, data, stream_list)
    flag = send_udp_traffic(handles, data, stream_list, stream_id)
    delete_udp_traffic_stream(handles)
    return flag

def create_raw_traffic_stream(src_handle, dst_handle, stream_info, traffic_item_type, data, _mode="unicast"):
    '''
    Author:Garima Mishra
    Sample input:
    create_raw_traffic_stream(
        {'tg_handle': <spytest.tgen.tg.TGIxia object at 0x7f1da6675050>, 'int_handle': '/topology:2/deviceGroup:1/ethernet:1/ipv4:1/item:1', 'port_handle': '1/1/6'},
        {'tg_handle': <spytest.tgen.tg.TGIxia object at 0x7f1da6675050>, 'int_handle': '/topology:2/deviceGroup:1/ethernet:1/ipv4:1/item:2', 'port_handle': '1/1/8'},
        {"src_endpoint": {"port" : "T1D3P1", "host_ip": data.t1d3_ip_addr, "gateway": data.d3t1_ip_addr, "mac" : data.t1d3_mac_addr },
         "dst_endpoint" : {"port" : "T1D4P1","host_ip": data.t1d4_ip_addr, "gateway": data.d4t1_ip_addr, "mac" : data.t1d4_mac_addr }}
         "raw", data)
    '''
    clear_counters()
    lag = False
    port_handle1 = src_handle["port_handle"]
    if "lag_handle" in src_handle.keys():
       port_handle1 = src_handle["lag_handle"]
       lag = True
    port_handle2 = dst_handle["port_handle"]
    if "lag_handle" in dst_handle.keys():
        port_handle2 = dst_handle["lag_handle"]
        lag = True
    if _mode == "broadcast":
        dst_mac = "ff:ff:ff:ff:ff:ff"
    elif _mode == "multicast":
        dst_mac = "01:00:5e:44:44:44"
    elif _mode == "unknownunicast":
        dst_mac = "00:44:44:44:44:44"
    else:
        dst_mac = stream_info['dst_endpoint']['mac']
        st.log("Unicast traffic item mode")
    if traffic_item_type == "raw":
        st.log("Adding traffic stream: {} {}".format(port_handle1, port_handle2))
        if lag:
            receive = src_handle['tg_handle'].tg_traffic_config(
                            emulation_src_handle=port_handle1,
                            emulation_dst_handle=port_handle2, mode='create',
                            transmit_mode=data.transmit_mode, pkts_per_burst=data.pkts_per_burst,
                            rate_percent = data.rate_percent, track_by = 'trackingenabled0',
                            circuit_type="raw", frame_size=data.frame_size,
                            mac_src=stream_info['src_endpoint']['mac'], mac_dst=dst_mac)
        else:
            receive = src_handle['tg_handle'].tg_traffic_config(
                port_handle=port_handle1, port_handle2=port_handle2, mode='create',
                transmit_mode=data.transmit_mode,
                pkts_per_burst=data.pkts_per_burst, rate_percent = data.rate_percent,
                circuit_endpoint_type=data.circuit_endpoint_type,
                frame_size=data.frame_size, mac_src=stream_info['src_endpoint']['mac'],
                mac_dst=stream_info['dst_endpoint']['mac'])
            src_handle['tg_handle'].tg_traffic_config(
                port_handle=port_handle1,
                port_handle2=port_handle2, mode='modify',
                mac_dst=dst_mac, stream_id = receive["stream_id"])
        stream_id = receive["stream_id"]
    else:
        st.log("Unknown traffic_item_type")
        st.report_fail("Unknown traffic_item_type")
    return stream_id

def send_raw_traffic_stream(src_handle, stream_id, reset=True):
    st.wait(5)
    tg_handle = src_handle['tg_handle']
    tg_handle.tg_traffic_control(action='apply', stream_handle=stream_id)
    tg_handle.tg_traffic_control(action='run', stream_handle=stream_id)
    st.wait(30)
    tg_handle.tg_traffic_control(action='stop', stream_handle=stream_id)
    st.wait(5)
    flag = False
    traffic_stat = tgapi.get_traffic_stats(tg_handle, mode='traffic_item', port_handle=src_handle["port_handle"], direction='tx', stream_handle=stream_id)
    st.log("Received traffic: {}".format(traffic_stat['rx']['total_packets']))
    st.log("Sent traffic: {}".format(traffic_stat['tx']['total_packets']))
    st.log(traffic_stat['rx']['total_packets']/traffic_stat['tx']['total_packets'])
    if traffic_stat['rx']['total_packets'] > 0.998*traffic_stat['tx']['total_packets'] and traffic_stat['rx']['total_packets'] < 1.002*traffic_stat['tx']['total_packets']:
        flag = True
    else:
        flag = False
    if reset:
        tg_handle.tg_traffic_control(action='reset')
    return flag

def get_counters(node,cmd = 'show vxlan counters', target_iface = 'VXLAN', r_t_key = 'rx_pkts'):
    tmpl = cmd.strip().replace(" ", "_") + ".tmpl"
    cmd_output = st.show(node, cmd, skip_tmpl=True)
    parsed_output = st.parse_show(node, cmd, cmd_output, tmpl)
    r_t_counter = 0
    for traffic in parsed_output:
        if traffic['iface'] == target_iface:
            r_t_counter = int(traffic[r_t_key].replace(",", ""))
            break

    return r_t_counter


def traffic_test_burst(_mode,handles):
    '''  
    Author:Ramsiddarth Ragurajan (rraguraj@cisco.com)

    '''
    ### Clear Statistics ###
    handles['tg_handle'].tg_traffic_control(action="clear_stats", port_handle=handles['all_port_handles'])
    handles['tg_handle'].tg_traffic_control(action="clear_stats", stream_handle=handles['stream_id'])

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
    handles['tg_handle'].tg_traffic_control(action='apply', stream_handle=handles['stream_id'])
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

def config_lag_interface(lag_name, ports, lag_ip, lag_gateway_ip, lag_mac):
    lag_vport_list = ""
    port_list = ""
    handles = {}
    for port in ports:
        tg, port_handle = tgapi.get_handle_byname(port)
        port_list += port_handle + " "
        vporthandle_status = tg.tg_convert_porthandle_to_vport(port_handle=port_handle)
        vport_handle = vporthandle_status['handle'].split('-')[-1]
        lag_vport_list += vport_handle + " "
    lag_vport_list = "{" + lag_vport_list.rstrip() + "}"
    port_list = port_list.rstrip()
    st.log("Creating Lag with ports {}".format(port_list))
    _result_ = tg.tg_emulation_lag_config( mode= "create", port_handle=lag_vport_list, active= "1", lag_name= """LAG1""",protocol_type= "lag_port_lacp")
    lag_1_handle = _result_['lag_handle']
    st.log("Creating topology config")
    _result_ = tg.tg_topology_config(
        topology_name = 'LAG1',
        lag_handle = lag_1_handle
    )
    if _result_['status'] != '1':
        st.log('topology_config {} creation failed'.format(_result_))
    topology_1_handle = _result_['topology_handle']

    # Creating a device group in topology
    st.log("Creating device group 1 in topology 1")
    _result_ = tg.tg_topology_config(
        topology_handle         = topology_1_handle,
        device_group_name       = 'LAG Device Group',
        device_group_multiplier = '1',
        device_group_enabled    = '1'
    )
    if _result_['status'] != '1':
        st.log('Device Group creation failed {}'.format(_result_))
    deviceGroup_1_handle = _result_['device_group_handle']

    st.log("Creating ethernet stack for the first Device Group")
    _result_ = tg.tg_interface_config(
        protocol_name     = 'Ethernet 1',
        protocol_handle   = deviceGroup_1_handle,
        mtu               = '1500',
        src_mac_addr      = lag_mac
    )
    if _result_['status'] != '1':
        st.log('Ethernet stack creation failed {}'.format(_result_))
    ethernet_1_handle = _result_['ethernet_handle']
    st.log("Creating IPv4 stack for the first Device Group")
    _result_ = tg.tg_interface_config(
        protocol_name     = 'IPv4 1',
        protocol_handle   = ethernet_1_handle,
        gateway           = lag_gateway_ip,
        intf_ip_addr      = lag_ip,
        netmask           = "255.255.255.0"
    )
    if _result_['status'] != '1':
        st.log('IPv4 stack creation failed {}'.format(_result_))
    ipv4_1_handle = _result_['ipv4_handle']
    int_handle = _result_['interface_handle']
    st.wait(10)
    tg.tg_test_control(action='start_protocol', handle=topology_1_handle)
    lag_1_handle_name = "1/1/" + lag_1_handle.split(":")[-1]
    handles[lag_name] = {"tg_handle": tg, "port_handle": lag_1_handle_name,"int_handle": int_handle, "lag_handle": lag_1_handle}
    return handles

def config_tgen_interface(int_dict, addr_family='ipv4'):
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
        if addr_family == 'ipv4':
            res=tg_handle.tg_interface_config(port_handle=port_handle, mode='config', intf_ip_addr=values['host_ip'], gateway=values['gateway'], src_mac_addr=values['mac'], arp_send_req='1')
        else:
            res=tg_handle.tg_interface_config(port_handle=port_handle, mode='config', ipv6_intf_addr=values['host_ip'], ipv6_prefix_length='64', ipv6_gateway=values['gateway'], src_mac_addr=values['mac'], arp_send_req='1')
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
        receive = handles[item[0]]["tg_handle"].tg_traffic_config(
                    port_handle=handles[item[0]]["port_handle"], port_handle2=handles[item[1]]["port_handle"], 
                    mode='create', bidirectional=1, transmit_mode=data.transmit_mode,
                    pkts_per_burst=data.pkts_per_burst, rate_percent = data.rate_percent, 
                    circuit_endpoint_type=data.circuit_endpoint_type, 
                    frame_size=data.frame_size, emulation_src_handle=handles[item[0]]["int_handle"], 
                    emulation_dst_handle=handles[item[1]]["int_handle"])
        stream_id = receive["stream_id"]
        traffic_item_dict[item[0]+"<-->"+item[1]] = {"stream_id":stream_id, "port_handle": handles[item[0]]["port_handle"] , "tg_handle": handles[item[0]]["tg_handle"]}
        st.wait(5)
        if ping:
            ###PING TEST###
            ping_result = tgen_utils.verify_interface_ping(src_obj=handles[item[0]]["tg_handle"], dev_handle=handles[item[0]]["int_handle"], dst_ip=int_dict[item[1]]['host_ip'],ping_count='5', exp_count='5')
            if ping_result:
                st.banner("Ping succeeded between endpoints for stream {} ".format(item[0]+"<-->"+item[1]))
            else:
                st.banner("Ping failed between endpoints for stream {} ".format(item[0]+"<-->"+item[1]))
                st.report_fail("Ping failed between endpoints")
        ### Clear Statistics ###
        handles[item[0]]["tg_handle"].tg_traffic_control(action="clear_stats", port_handle=[handles[item[0]]["port_handle"], handles[item[1]]["port_handle"]]) 
    return traffic_item_dict

def ping_gateway(handles, src_port, gateway_ip, int_handle):
    ping_result = tgen_utils.verify_interface_ping(src_obj=handles[src_port]["tg_handle"], dev_handle=int_handle, dst_ip=gateway_ip,ping_count='5', exp_count='4')
    if ping_result:
        st.banner("Ping succeeded between endpoints for stream {} ".format(src_port+"<-->"+gateway_ip))
    else:
        st.banner("Ping failed between endpoints for stream {} ".format(src_port+"<-->"+gateway_ip))
        return False
    return True

def reset_traffic(streams_info):
    for traffic_item, values in streams_info.items():
        values['tg_handle'].tg_traffic_control(action='reset')

def check_traffic(streams_info, timeout=30):
    '''
    Author:Ramsiddarth Ragurajan (rraguraj@cisco.com)

    '''
    flag = True
    for traffic_item, values in streams_info.items(): 
        values['tg_handle'].tg_traffic_control(action='apply', stream_handle=values['stream_id'])
        values['tg_handle'].tg_traffic_control(action='run', stream_handle=values['stream_id'])
        st.wait(timeout)
        values['tg_handle'].tg_traffic_control(action='stop', stream_handle=values['stream_id'])
        st.wait(5)
        traffic_stat = tgapi.get_traffic_stats(values['tg_handle'], mode='traffic_item', port_handle=values['port_handle'], direction='tx', stream_handle=values['stream_id'])
        st.banner("BI-DIRECTIONAL TRAFFIC BEWTEEN {}".format(traffic_item))
        st.log("Received traffic: {}".format(traffic_stat['rx']['total_packets']))
        st.log("Sent traffic: {}".format(traffic_stat['tx']['total_packets']))
        st.log(traffic_stat['rx']['total_packets']/traffic_stat['tx']['total_packets'])
        if traffic_stat['rx']['total_packets'] > 0.998*traffic_stat['tx']['total_packets'] and traffic_stat['rx']['total_packets'] < 1.002*traffic_stat['tx']['total_packets']:
            st.banner("BI-DIRECTIONAL TRAFFIC BEWTEEN {} PASSED".format(traffic_item))
        else:
            st.banner("BI-DIRECTIONAL TRAFFIC BEWTEEN {} FAILED".format(traffic_item))
            flag = False
    return flag

def cleanup_traffic(int_dict, streams_info, handles):
    for traffic_item, values in streams_info.items(): 
        values['tg_handle'].tg_traffic_control(action='reset', stream_handle=values['stream_id'])

    for port, values in int_dict.items():
        tg_handle, port_handle = tgapi.get_handle_byname(port)
        tg_handle.tg_interface_config(port_handle=port_handle, handle=handles[port]["int_handle"], mode='destroy')

def get_replacement(var_dict, target_string):
    for item, value in var_dict.items():
        if target_string == item:
            return value

    return ''			

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
    for leaf_ip in vtep_ip_dict:
        leaf_vtep_ip = vtep_ip_dict[leaf_ip]
        leaf_parsed = []
        iter = 0
        start_time = time.time()
        leaf = leaf_ip.split("_")[0]
        leaf = leaf.lower()

        while len(leaf_parsed) == 0 and iter < NO_OF_RETRIES:
            if iter > 0:
                st.wait(10)
            leaf_output = st.show(leaf, "show vxlan remotevtep", skip_tmpl=True)

            leaf_parsed = st.parse_show(leaf, "show vxlan remotevtep",
                                     leaf_output, "show_vxlan_remote.tmpl")
            if len(leaf_parsed) == 0:
                iter += 1
                continue
        if iter == NO_OF_RETRIES:
            end_time = time.time()
            st.log("No remote VTEP found on {} after {} secs".format(leaf, end_time-start_time))
            report_fail(leaf, msg='No remote VTEP found in {}'.format(leaf))

        end_time = time.time()
        st.log("Remote VTEP found on {} after {} secs".format(leaf, end_time-start_time))

        vtep_num = 0
        for path in leaf_parsed:
            vtep_num += 1
            if path['tun_src'] != 'EVPN':
                report_fail(leaf, msg='Unexpected tunnel type {} in {}'.format(path['tun_src'], leaf))
            if path['src_vtep'] != leaf_vtep_ip:
                report_fail(leaf, msg='No local vtep {} found in {}'.format(leaf_vtep_ip, leaf))
            if path['dst_vtep'] not in vtep_ip_dict.values():
                report_fail(leaf, msg='Unexpected vtep {} found in {}'.format(path['dst_vtep'], leaf))
            if path['tun_status'] != 'oper_up':
                report_fail(leaf, msg='Tunnel is not in up status in {}'.format(leaf))
        if vtep_num != 1:
            report_fail(leaf, msg='Incorrect number of VTEPs found in {}'.format(leaf))

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

def verify_vtep_state_v6(nodes, LEAF0_VTEP_IP, LEAF1_VTEP_IP):
    '''
    root@sonic:/home/cisco# show vxlan remotevtep
    +---------------------+--------------------+-------------------+--------------+
    | SIP                 | DIP                | Creation Source   | OperStatus   |
    +=====================+====================+===================+==============+
    | fd27::22d:b87f:214b | fd27::280:10f1:25f | EVPN              | oper_up      |
    +---------------------+--------------------+-------------------+--------------+
    Total count : 1

    '''
    for node in ['leaf0', 'leaf1']:
        dut = nodes[node]
        expected_sip = LEAF0_VTEP_IP if node == 'leaf0' else LEAF1_VTEP_IP
        expected_dip = LEAF1_VTEP_IP if node == 'leaf0' else LEAF0_VTEP_IP

        output = st.config(dut, "show vxlan remotevtep")
        output_parsed = st.parse_show(dut, "show vxlan remotevtep", output, "show_vxlan_remote.tmpl")
        iter = 0
        for vtep in output_parsed:
            start_time = time.time()
            while vtep['tun_status'] != 'oper_up' and iter < NO_OF_RETRIES:
                if iter > 0:
                    st.wait(10)
                iter += 1
                output = st.config(dut, "show vxlan remotevtep")
                output_parsed = st.parse_show(dut, "show vxlan remotevtep", output, "show_vxlan_remote.tmpl")
                vtep = output_parsed[0]

            if iter == NO_OF_RETRIES:
                end_time = time.time()
                iter = 0
                if vtep['tun_status'] == 'oper_down':
                    st.log("Tunnel State is not Up after {} secs".format(end_time - start_time))
                    report_fail(dut, msg='Tunnel State is not up. Status : oper_down')
                else:
                    st.log("Tunnel State is not set after {} secs".format(end_time - start_time))
                    report_fail(dut, msg='Tunnel State is not set')

            #Test 1: Verify if the State is UP - oper_up
            if vtep['tun_status'] == 'oper_up':
                end_time = time.time()
                st.log("Tunnel State is up after {} secs Status : oper_up" .format(end_time-start_time), dut)
            # Test 2: Verify SIP and DIP
            if vtep['src_vtep'] == expected_sip:
                st.log("Source vtep validated", dut)
            else:
                report_fail(dut, msg='Source vtep is not as expected. Found {} Expected {}'.format(vtep['src_vtep'], expected_sip))
            if vtep['dst_vtep'] == expected_dip:
                st.log("Destination vtep validated", dut)
            else:
                report_fail(dut, msg='Source vtep is not as expected. Found {} Expected {}'.format(vtep['dst_vtep'], expected_dip))
            # Test 3: Verify if the Total Count is 1
            if vtep['total_count'] == REMOTE_VTEP_COUNT:
                st.log("All remote VTEPs detected", dut)
            else:
                report_fail(dut, msg='Remote Vteps discovered count not as expected. Found {} Expected {}'.format(vtep['total_count'], REMOTE_VTEP_COUNT))

#Explicit ping from gw to host is needed in the L3VNI case
#TODO: we can make this into a fixture once the above known issue is resolved.
def traffic_setup(data, addr_family='ipv4'):
    ### Config tgen interface and get tg handle, port handle and interface handles ###
    if addr_family == 'ipv4':
        int_dict = {"T1D3P1": {"host_ip": data.t1d3_ip_addr, "gateway": data.d3t1_ip_addr, "mac" : data.t1d3_mac_addr },
                "T1D4P1": {"host_ip": data.t1d4_ip_addr, "gateway": data.d4t1_ip_addr, "mac" : data.t1d4_mac_addr}}

    else:
        int_dict = {"T1D3P1": {"host_ip": data.t1d3_ip6_addr, "gateway": data.d3t1_ip6_addr, "mac" : data.t1d3_mac_addr },
                "T1D4P1": {"host_ip": data.t1d4_ip6_addr, "gateway": data.d4t1_ip6_addr, "mac" : data.t1d4_mac_addr}}

    handles = config_tgen_interface(int_dict, addr_family)
    stream_list = [("T1D3P1","T1D4P1")]
    streams = config_traffic_item(stream_list, handles, int_dict, data, ping=True)
    return streams

def configure_nodes(nodes, vrf, leaf0_vlan, leaf0_vlan_ip, leaf1_vlan, leaf1_vlan_ip, dummy_vlan, vni, vars):
    '''
    a. add vrf
    '''
    config_vrf(nodes['leaf0'], vrf)
    config_vrf(nodes['leaf1'], vrf)

    '''
    b. add vlan
    '''
    config_vlan(nodes['leaf0'], leaf0_vlan, members=[vars.D3T1P1], vrf=vrf)
    config_vlan(nodes['leaf1'], leaf1_vlan, members=[vars.D4T1P1], vrf=vrf)

    '''
    c. add dummy vlan
    '''
    config_vlan(nodes['leaf0'], dummy_vlan, vrf=vrf)
    config_vlan(nodes['leaf1'], dummy_vlan, vrf=vrf)

    '''
    d. add vlan to vni map

    e. add vrf to vni map
    '''
    config_vxlan_map(nodes['leaf0'], 'VXLAN', vni, vrf=vrf, vlan=dummy_vlan)
    config_vxlan_map(nodes['leaf1'], 'VXLAN', vni, vrf=vrf, vlan=dummy_vlan)

    '''
    f. add IP address on vlan
    '''
    st.config(nodes['leaf0'], 'sudo config interface ip add {} {}'.format('Vlan' + leaf0_vlan, leaf0_vlan_ip))
    st.config(nodes['leaf1'], 'sudo config interface ip add {} {}'.format('Vlan' + leaf1_vlan, leaf1_vlan_ip))

def verify_bgp(nodes, prefix, src_vtep, expected_l3vni='1000'):
    st.log("Start BGP verification check on {}" .format(src_vtep))
    start_time = time.time()
    iter = 0
    parsed = []
    while len(parsed) == 0 and iter < NO_OF_BGP_RETRIES:
        if iter > 0:
            st.wait(10)
        output = st.show(nodes[src_vtep], 'show bgp l2vpn evpn {}'.format(prefix), type='vtysh', skip_tmpl=True, skip_error_check=True)

        parsed = st.parse_show(nodes[src_vtep], 'show bgp l2vpn evpn {}'.format(prefix),
                             output, 'show_bgp_l2vpn_evpn_prefix.tmpl')
        if len(parsed) == 0:
            iter += 1
            st.error(msg='Found no prefixes advertised to {}'.format(src_vtep))
            continue
        for path in parsed:
            if path['valid'] != 'valid':
                report_fail(nodes[src_vtep], msg='Invalid path found in {}'.format(src_vtep))
            if path['pathevpntype'] != '5':
                report_fail(nodes[src_vtep], msg='Invalid evpn type {0} found in {1}'.format(path['evpntype'], src_vtep))
            if path['vni'] != expected_l3vni:
                report_fail(nodes[src_vtep], msg='Invalid vni found in {}'.format(src_vtep))
    if iter == NO_OF_BGP_RETRIES:
        end_time = time.time()
        st.log("BGP did not convergence , time waited {} secs" .format(end_time-start_time))
        report_fail(nodes[src_vtep], msg='Found no prefixes advertised to {}'.format(src_vtep))
    end_time = time.time()
    st.log("Time taken for BGP convergence:{} secs" .format(end_time-start_time))


def config_multiple_vni(nodes, svi_ips, vrfs):
    '''
    a. add vrf
    '''
    for vrf, value in vrfs.items():
        config_vrf(nodes['leaf0'], vrf)
        config_vrf(nodes['leaf1'], vrf)

    '''
    b. add vlan
    '''
    for vrf, value in vrfs.items():
        config_vlan(nodes['leaf0'], value['vlan'], value['members'], vrf=vrf)
        config_vlan(nodes['leaf1'], value['vlan'], value['members'], vrf=vrf)

    '''
    c. add dummy vlan
    '''
    for vrf, value in vrfs.items():
        config_vlan(nodes['leaf0'], value['dummy_vlan'], vrf=vrf)
        config_vlan(nodes['leaf1'], value['dummy_vlan'], vrf=vrf)

    '''
    d. add vlan to vni map

    e. add vrf to vni map
    '''
    for vrf, value in vrfs.items():
        config_vxlan_map(nodes['leaf0'], 'VXLAN', value['vni'], vrf=vrf, vlan=value['dummy_vlan'])
        config_vxlan_map(nodes['leaf1'], 'VXLAN', value['vni'], vrf=vrf, vlan=value['dummy_vlan'])

    '''
    f. add IP address on vlan
    '''
    for leaf, value in svi_ips.items():
        for v in value:
            st.config(nodes[leaf], 'sudo config interface ip add {} {}'.format('Vlan' + v['vlan'], v['ip']))

def unconfig_multiple_vni(nodes, svi_ips, vrfs, data):
        '''
        f. remove IP address on vlan
        '''
        for leaf, value in svi_ips.items():
            for v in value:
                st.config(nodes[leaf], 'sudo config interface ip rem {} {}'.format('Vlan' + v['vlan'], v['ip']))

        '''
        e. delete vrf to vni map

        d. delete vlan to vni map

        '''
        for vrf, value in vrfs.items():
            config_vxlan_map(nodes['leaf0'], 'VXLAN', value['vni'], vrf=vrf, vlan=value['dummy_vlan'], add=False)
            config_vxlan_map(nodes['leaf1'], 'VXLAN', value['vni'], vrf=vrf, vlan=value['dummy_vlan'], add=False)

        '''
        c. del dummy vlan
        '''
        for vrf, value in vrfs.items():
            config_vlan(nodes['leaf0'], value['dummy_vlan'], vrf=vrf, add=False)
            config_vlan(nodes['leaf1'], value['dummy_vlan'], vrf=vrf, add=False)

        '''
        b. del vlan
        '''
        for vrf, value in vrfs.items():
            config_vlan(nodes['leaf0'], value['vlan'], value['members'], vrf=vrf, add=False)
            config_vlan(nodes['leaf1'], value['vlan'], value['members'], vrf=vrf, add=False)

        '''
        a. del vrf
        '''
        for vrf, value in vrfs.items():
            data.config_vrfs.append(vrf)

def is_ip_neigh_present_in_kernel(nodes, src_vtep, ip):
    output = st.show(nodes[src_vtep], 'ip neigh show | grep {}'.format(ip), skip_tmpl=True, skip_error_check=True)
    parsed = st.parse_show(nodes[src_vtep], 'ip neigh show', output, 'ip_neigh_show.tmpl')
    st.log(parsed)
    if len(parsed) == 0:
        return False
    return True

def is_mac_present_in_kernel(nodes, src_vtep, mac):
    output = st.show(nodes[src_vtep], 'sudo bridge fdb show | grep {}'.format(mac), skip_tmpl=True, skip_error_check=True)
    parsed = st.parse_show(nodes[src_vtep], 'sudo bridge fdb show', output, 'bridge_fdb_show.tmpl')
    st.log(parsed)
    if len(parsed) == 0:
        return False
    return True

def is_mac_no_extern_learn_present_in_kernel(nodes, src_vtep, mac):
    output = st.show(nodes[src_vtep], 'sudo bridge fdb show | grep {}'.format(mac), skip_tmpl=True, skip_error_check=True)
    parsed = st.parse_show(nodes[src_vtep], 'sudo bridge fdb show', output, 'bridge_fdb_show.tmpl')
    st.log(parsed)
    if len(parsed) == 0:
        return False
    for path in parsed:
        if not path['ext_lrn']:
            return True
    return False

def verify_bgp_convergence(nodes, svi_ips, src_vtep, remote_vtep, addr_family='ipv4'):
    st.log("Start BGP convergence check on {}" .format(src_vtep))
    start_time = time.time()
    iter = 0
    for value in svi_ips[remote_vtep]:
        if addr_family == 'ipv4':
            prefix = value['ip'].strip('254/24') + '0'
        else:
            prefix = value['ip'].strip('1/64') + '0' 
        parsed = []
        while len(parsed) == 0 and iter < NO_OF_BGP_RETRIES:
            if iter > 0:
                st.wait(10)
            output = st.show(nodes[src_vtep], 'show bgp l2vpn evpn {}'.format(prefix), type='vtysh', skip_tmpl=True, skip_error_check=True)
            parsed = st.parse_show(nodes[src_vtep], 'show bgp l2vpn evpn {}'.format(prefix),
                        output, 'show_bgp_l2vpn_evpn_prefix.tmpl')
            if len(parsed) == 0:
                 iter += 1
                 st.error(msg='Found no prefixes advertised to {}'.format(src_vtep))
                 continue
            for path in parsed:
                if path['valid'] != 'valid':
                    report_fail(nodes[src_vtep], msg='Invalid path found on {}'.format(src_vtep))
                if path['pathevpntype'] != '5':
                    report_fail(nodes[src_vtep], msg='Invalid evpn type {0} found on {1}'.format(path['evpntype'], src_vtep))
                if path['vni'] != value['vni']:
                    report_fail(nodes[src_vtep], msg='Invalid vni found on {}'.format(src_vtep))
        if iter == NO_OF_BGP_RETRIES:
            end_time = time.time()
            st.log("BGP did not convergence , time waited {} secs" .format(end_time-start_time))
            report_fail(nodes[src_vtep], msg='Found no prefixes advertised to {}'.format(src_vtep))
    end_time = time.time()
    st.log("Time taken for BGP convergence:{} secs" .format(end_time-start_time))
