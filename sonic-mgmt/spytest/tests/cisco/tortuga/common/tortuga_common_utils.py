import os
import json
import yaml
import re

from spytest import st, tgapi
import apis.system.basic as basic_obj
import apis.system.port as papi
import apis.switching.portchannel as portchannel_obj
import apis.routing.ip as ip_obj
import apis.switching.mac as mac_obj
import apis.system.interface as intf_obj
import utilities.utils as utils_obj
from utilities.common import filter_and_select

# Hierarchical Port Naming

def modify_config_file(config_file,var_dict):
    output_yaml_file = "temp_config.yaml"
    input_yaml_file = config_file
    dir_path = os.path.dirname(os.path.realpath(__file__))+"/"
    result = os.system("cp {1} {0}{2}".format(dir_path,input_yaml_file,output_yaml_file))
    if result != 0:
        st.report_fail('msg', "config file copy failed")
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

def check_hw_or_sim(node):
    dut_type = ""
    st.log("Check whether the spytest is being run on Hw or SIM.")
    cmd_output = st.config(node,"cat /proc/cpuinfo | grep '^model name.: VXR$'")
    try:
        if 'VXR' in str(cmd_output.encode('ascii','ignore')):
            st.log("DUT type is SIM")
            dut_type = "sim"
        else:
            st.log("DUT type is HW")
            dut_type = "hw"
    except:
        st.log("Exception case : DUT type HW is taken by default.")
        dut_type = "hw"
    return dut_type

#Tgen wrappers

def get_handles(hdl1,hdl2):
    tg1, tg_ph_1 = tgapi.get_handle_byname(hdl1)
    tg2, tg_ph_2 = tgapi.get_handle_byname(hdl2)
    return (tg1, tg2, tg_ph_1, tg_ph_2)

def get_tx_count(handles, tg_hdl = 'tg_handle_1', port_hdl = 'port_handle_1'):
    stats_tg = handles[tg_hdl].tg_traffic_stats(port_handle=handles[port_hdl],mode='aggregate')
    return stats_tg[handles[port_hdl]]['aggregate']['tx']['total_pkts']

def clear_counters():

    vars = st.get_testbed_vars() 
    dut_list = [vars.D1, vars.D2, vars.D3, vars.D4]

    for _dut in dut_list:
        st.config(_dut, "sudo sonic-clear fdb all")
        st.config(_dut, "sudo sonic-clear rifcounters")
        st.config(_dut, "sudo sonic-clear counters")

def config_ipv4_intf(tg, tg_ph, data, intf_ip_addr, src_mac_addr, gateway, vid):
    intf_args = {}
    if vid:
        intf_args['vlan'] = '1'
        intf_args['vlan_id'] = vid
    res=tg.tg_interface_config(port_handle=tg_ph, mode='config', intf_ip_addr=intf_ip_addr,
        gateway=gateway, src_mac_addr=src_mac_addr, arp_send_req='1', enable_ping_response=1, **intf_args)
    st.log("INTFCONF: "+str(res))
    return res['handle']

def config_ipv6_intf(tg, tg_ph, data, ipv6_intf_addr, src_mac_addr, gateway, vid):
    intf_args = {}
    if vid:
        intf_args['vlan'] = '1'
        intf_args['vlan_id'] = vid
    res=tg.tg_interface_config(port_handle=tg_ph, mode='config', ipv6_intf_addr=ipv6_intf_addr, ipv6_prefix_length='64',
            ipv6_gateway=gateway, src_mac_addr=src_mac_addr, arp_send_req='1', enable_ping_response=1, **intf_args)
    st.log("INTFCONF: "+str(res))
    return res['handle']

def config_ipv4_traffic(tg, tg_ph, data1, data2, mac_src, dst_mac, ip_src_addr, ip_dst_addr, vid):
    traffic_args = {}
    if vid :
        traffic_args['l2_encap'] = 'ethernet_ii_vlan'
        traffic_args['vlan'] = 'enable'
        traffic_args['vlan_id'] = vid

    if hasattr(data1,'pkts_per_burst'): traffic_args['pkts_per_burst'] = data1.pkts_per_burst
    if hasattr(data1,'frame_size'): traffic_args['frame_size'] = data1.frame_size
    if hasattr(data1,'tgen_rate_pps') : traffic_args['rate_pps'] = data1.tgen_rate_pps
    if hasattr(data1,'duration') : traffic_args['duration'] = data1.duration
    if hasattr(data1,'transmit_mode') : traffic_args['transmit_mode'] = data1.transmit_mode

    data1.tr1=tg.tg_traffic_config(port_handle=tg_ph, mode='create', length_mode='fixed', l3_protocol='ipv4',
                mac_dst=dst_mac, mac_src=mac_src, ip_src_addr=ip_src_addr, ip_dst_addr=ip_dst_addr, **traffic_args)

def config_ipv6_traffic(tg, tg_ph, data1, data2, mac_src, dst_mac, ipv6_src_addr, ipv6_dst_addr, vid):
    traffic_args = {}
    if vid :
        traffic_args['l2_encap'] = 'ethernet_ii_vlan'
        traffic_args['vlan'] = 'enable'
        traffic_args['vlan_id'] = vid

    if hasattr(data1,'pkts_per_burst'): traffic_args['pkts_per_burst'] = data1.pkts_per_burst
    if hasattr(data1,'frame_size'): traffic_args['frame_size'] = data1.frame_size
    if hasattr(data1,'tgen_rate_pps') : traffic_args['rate_pps'] = data1.tgen_rate_pps
    if hasattr(data1,'duration') : traffic_args['duration'] = data1.duration
    if hasattr(data1,'transmit_mode') : traffic_args['transmit_mode'] = data1.transmit_mode

    data1.tr1=tg.tg_traffic_config(port_handle=tg_ph, mode='create', length_mode='fixed', l3_protocol='ipv6',
                mac_src=mac_src, mac_dst=dst_mac, ipv6_src_addr=ipv6_src_addr, ipv6_dst_addr=ipv6_dst_addr, **traffic_args)

def verify_ping_helper(tg, tg_ph, handle, dest_ip):
    ping_max_iteration=2
    for iter in range(ping_max_iteration):
        res = tgapi.verify_ping(src_obj=tg, port_handle=tg_ph, dev_handle=handle, dst_ip=dest_ip, ping_count='5', exp_count='5')
        st.log("PING_RES: " + str(res))
        if res:
            st.log("Ping succeeded.")
            return
    st.report_fail('msg', "Ping Failed")

def traffic_test_config(data1, data2, hdl1, hdl2, mode, ipv4, cl_count=True, verify_ping=True, is_l2=False, vlan1='', vlan2='', traffic_type="bounded"):
    data1.my_dut_list = st.get_dut_names()
    data2.my_dut_list = st.get_dut_names()

    if cl_count: clear_counters()

    tg_handler = tgapi.get_handles_byname(hdl1, hdl2)
    tg = tg_handler["tg"]

    vars = st.get_testbed_vars()
    dut_lists = [vars.D1, vars.D2, vars.D3, vars.D4]

    (tg1, tg2, tg_ph_1, tg_ph_2) = get_handles(hdl1, hdl2)

    tg.tg_traffic_control(action="reset", port_handle=tg_handler["tg_ph_list"])
    tg.tg_traffic_control(action="clear_stats", port_handle=tg_handler["tg_ph_list"])

    if ipv4 :
        handle1 = config_ipv4_intf(tg1, tg_ph_1, data1, data1.t1d3_ip_addr, data1.t1d3_mac_addr, data1.t1d3_ip_gateway, vlan1)
        handle2 = config_ipv4_intf(tg2, tg_ph_2, data2, data2.t1d4_ip_addr, data2.t1d4_mac_addr, data2.t1d4_ip_gateway, vlan2)
        # Ping from tgen to tgen.
        if verify_ping:
            verify_ping_helper(tg1, tg_ph_1, handle1, data2.t1d4_ip_addr)
            st.wait(2)
            verify_ping_helper(tg2, tg_ph_2, handle2, data1.t1d3_ip_addr)
    else:
        handle1 = config_ipv6_intf(tg1, tg_ph_1, data1, data1.t1d3_ipv6_addr, data1.t1d3_mac_addr, data1.t1d3_ipv6_gateway, vlan1)
        handle2 = config_ipv6_intf(tg2, tg_ph_2, data2, data2.t1d4_ipv6_addr, data2.t1d4_mac_addr, data2.t1d4_ipv6_gateway, vlan2)
        # Ping from tgen to tgen.
        if verify_ping:
            verify_ping_helper(tg1, tg_ph_1, handle1, data2.t1d4_ipv6_addr)
            st.wait(2)
            verify_ping_helper(tg2, tg_ph_2, handle2, data1.t1d3_ipv6_addr)


    ## Update Traffic Result for Burst Test:

    for _dut in dut_lists:
      papi.clear_interface_counters(_dut)
      st.config(_dut, "sudo sonic-clear counters")

    conn_intf = {"T1D3P1":  vars.D3T1P1,
                 "T1D3P2":  vars.D3T1P2,
                 "T1D4P1":  vars.D4T1P1,
                 "T1D4P2":  vars.D4T1P2}
    if mode == "unicast":
        if is_l2:
            dst_mac1 = data1.t1d3_dest_mac_addr
            dst_mac2 = data2.t1d4_dest_mac_addr
        else :
            dst_mac1 = basic_obj.get_ifconfig_ether(vars.D3, conn_intf[hdl1])
            dst_mac2 = basic_obj.get_ifconfig_ether(vars.D4, conn_intf[hdl2])
    if mode == "broadcast":
        dst_mac1 = "ff:ff:ff:ff:ff:ff"
        dst_mac2 = "ff:ff:ff:ff:ff:ff"
    if mode == "multicast":
        dst_mac1 = "01:00:5e:44:44:44"
        dst_mac2 = "01:00:5e:33:33:33"
    if mode == "unknownunicast":
        dst_mac1 = "00:44:44:44:44:44"
        dst_mac2 = "00:33:33:33:33:33"

    if ipv4 :
        config_ipv4_traffic(tg1, tg_ph_1, data1, data2, data1.t1d3_mac_addr, dst_mac1, data1.t1d3_ip_addr, data2.t1d4_ip_addr, vlan1)
        if traffic_type=="bounded":
            config_ipv4_traffic(tg2, tg_ph_2, data2, data1, data2.t1d4_mac_addr, dst_mac2, data2.t1d4_ip_addr, data1.t1d3_ip_addr, vlan2)
    else:
        config_ipv6_traffic(tg1, tg_ph_1, data1, data2, data1.t1d3_mac_addr, dst_mac1, data1.t1d3_ipv6_addr, data2.t1d4_ipv6_addr, vlan1)
        if traffic_type=="bounded":
            config_ipv6_traffic(tg2, tg_ph_2, data2, data1, data2.t1d4_mac_addr, dst_mac2, data2.t1d4_ipv6_addr, data1.t1d3_ipv6_addr, vlan2)

    handles = {'tg_handle_1': tg1, 'tg_handle_2': tg2, 'port_handle_1': tg_ph_1, 'port_handle_2': tg_ph_2, 'int_handle_1': handle1, 'int_handle_2': handle2}
    return handles

def traffic_start(handles, data1, data2, traffic_type="bounded"):
    vars = st.get_testbed_vars()
    dut_lists = [vars.D1, vars.D2, vars.D3, vars.D4]

    handles['tg_handle_1'].tg_packet_control(port_handle=handles['port_handle_1'], action='start')
    if traffic_type=="bounded":
        handles['tg_handle_2'].tg_packet_control(port_handle=handles['port_handle_2'], action='start')

    handles['tg_handle_1'].tg_traffic_control(action='clear_stats', port_handle=handles['port_handle_1'])
    if traffic_type=="bounded":
        handles['tg_handle_2'].tg_traffic_control(action='clear_stats', port_handle=handles['port_handle_2'])
    st.log("TRAFCONF - TR1: " + str(data1.tr1) + " TR2: " + str(data2.tr1))

    for _dut in dut_lists:
        papi.clear_interface_counters(_dut)
        st.config(_dut, "sudo sonic-clear counters")
        st.wait(1)

    t_run1=handles['tg_handle_1'].tg_traffic_control(action='run', port_handle=handles['port_handle_1'])
    if traffic_type=="bounded":
        t_run2=handles['tg_handle_2'].tg_traffic_control(action='run', port_handle=handles['port_handle_2'])

    st.wait(data1.traffic_run_time)
    if traffic_type=="bounded":
        st.log("TR_CTRL: " + str(t_run1) + "t run2 " + str(t_run2))
    else:
        st.log("TR_CTRL: " + str(t_run1))

def traffic_stop(handles, mode="continuous", traffic_type="bounded"):
    handles['tg_handle_1'].tg_traffic_control(action='stop', port_handle=handles['port_handle_1'])
    if traffic_type=="bounded":
        handles['tg_handle_2'].tg_traffic_control(action='stop', port_handle=handles['port_handle_2'])
    if mode == "continuous":
        st.wait(30)
    else:
        st.wait(5)

def traffic_test_check(handles, d3t1port, d4t1port, data1, data2, rate_limit = False, traffic_type="bounded"):
    vars = st.get_testbed_vars()

    stats_tg1 = handles['tg_handle_1'].tg_traffic_stats(port_handle=handles['port_handle_1'],mode='aggregate')
    total_tg1_tx = stats_tg1[handles['port_handle_1']]['aggregate']['tx']['total_pkts']
    if traffic_type=="bounded":
        total_tg1_rx = stats_tg1[handles['port_handle_1']]['aggregate']['rx']['total_pkts']

    stats_tg2 = handles['tg_handle_2'].tg_traffic_stats(port_handle=handles['port_handle_2'],mode='aggregate')
    if traffic_type=="bounded":
        total_tg2_tx = stats_tg2[handles['port_handle_2']]['aggregate']['tx']['total_pkts']
    total_tg2_rx = stats_tg2[handles['port_handle_2']]['aggregate']['rx']['total_pkts']

    st.log("Tgen Sent Packets on {}: {} and Received Packets on {}: {}".format(d3t1port, total_tg1_tx, d4t1port, total_tg2_rx))
    if traffic_type=="bounded":
        st.log("Tgen Sent Packets on {}: {} and Received Packets on {}: {}".format(d4t1port, total_tg2_tx, d3t1port, total_tg1_rx))

    st.banner("Tgen Sent Packets on {}: {} and Received Packets on {}: {}".format(d3t1port, total_tg1_tx, d4t1port, total_tg2_rx))
    if traffic_type=="bounded":
        st.banner("Tgen Sent Packets on {}: {} and Received Packets on {}: {}".format(d4t1port, total_tg2_tx, d3t1port, total_tg1_rx))

    passed = True
    if rate_limit :
        counters_tg2_avg = int(total_tg2_rx)/data1.duration
        st.log("Tgen Average Rx pps on {} : {}".format(d4t1port, counters_tg2_avg))
        if traffic_type=="bounded":
            counters_tg1_avg = int(total_tg1_rx)/data1.duration
            st.log("Tgen Average Rx pps on {} : {}".format(d3t1port, counters_tg1_avg))
            if  (counters_tg1_avg > data1.higher_pkt_count or counters_tg1_avg < data1.lower_pkt_count or
                counters_tg2_avg > data1.higher_pkt_count or counters_tg2_avg < data1.lower_pkt_count):
                passed = False
        else:
            if  (counters_tg2_avg > data1.higher_pkt_count or counters_tg2_avg < data1.lower_pkt_count):
                passed = False
    else:
        if traffic_type=="bounded":
            if ((int(total_tg1_tx) == 0) or (int(total_tg2_tx) == 0) or
                (abs(int(total_tg1_tx)-int(total_tg2_rx)) > data1.tgen_stats_threshold) or
                (abs(int(total_tg2_tx)-int(total_tg1_rx)) > data1.tgen_stats_threshold)):
              st.log("absolute diff of tg1 tx and tg2 rx : {}".format(abs(int(total_tg1_tx)-int(total_tg2_rx))))
              st.log("absolute diff of tg2 tx and tg1 rx : {}".format(abs(int(total_tg2_tx)-int(total_tg1_rx))))
              passed = False
        else:
            if ((int(total_tg1_tx) == 0) or
                (abs(int(total_tg1_tx)-int(total_tg2_rx)) > data1.tgen_stats_threshold)):
              st.log("absolute diff of tg1 tx and tg2 rx : {}".format(abs(int(total_tg1_tx)-int(total_tg2_rx))))
              passed = False

    dut_lists = [vars.D1, vars.D2, vars.D3, vars.D4]
    for _dut in dut_lists:
        st.show(_dut, "sudo show interface counter", skip_tmpl=True, skip_error_check=True)

    if passed:
        st.report_pass("test_case_passed",  "Traffic Validation Passed")
    else:
        st.log("Traffic Validation Failed")

    return passed

def traffic_cleanup(handles):
    st.log("Test traffic gen Cleanup.")
    handles['tg_handle_1'].tg_interface_config(port_handle=handles['port_handle_1'], handle=handles['int_handle_1'], mode='destroy')
    handles['tg_handle_2'].tg_interface_config(port_handle=handles['port_handle_2'], handle=handles['int_handle_2'], mode='destroy')

# Config functions

def config_node(node, config, type=''):
    if type:
        st.config(node, config, type=type, skip_error_check=False, conf=True)
    else:
        st.config(node, config, skip_error_check=False, conf=True)

def config_static(node, config_domain, add, config_file, device_type = 'sonic'):

    domain = ''
    if config_domain == 'bgp':
        domain = 'vtysh'

    with open(config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        if add:
            cmd = config_list[node][config_domain]['config']
        else:
            cmd = config_list[node][config_domain]['deconfig']
        if device_type == 'linux':
            cmd = ";".join(cmd.splitlines())
        config_node(node, cmd, domain)

# Portchannel wrappers

def portchannel_add_del_member(node, portchannel='', members=[], add=True):
    if not portchannel:
       return

    if add:
        if members:
            cmd = "config acl remove table TORTUGA_ACL_INGRESS"
            st.config(node, cmd)
            cmd = "config acl remove table TORTUGA_ACL_INGRESS_V6"
            st.config(node, cmd)
            #add member interfaces
            for member in members:
                cmd = "sudo config interface ipv6 disable use-link-local-only {}".format(member)
                st.config(node, cmd)
                cmd = "sudo config interface startup {}".format(member)
                st.config(node, cmd)
                if not portchannel_obj.add_portchannel_member(node, portchannel, member) :
                    st.report_fail('msg', "{} add member {} failed".format(portchannel, member))
    else:
        if members:
            #delete member interfaces
            if not portchannel_obj.delete_portchannel_member(node, portchannel, members):
                st.report_fail('msg', "{} delete members failed".format(portchannel))

def portchannel_create_delete(node, portchannel, ipv4_add, ipv6_add, members=[], min_link="", add=True):

    if not portchannel:
       return

    if add:
        #add PortChannelxx
        if not portchannel_obj.create_portchannel(node, portchannel, min_link=min_link):
            st.report_fail('msg', "{} create failed".format(portchannel))

        if ipv4_add:
            ipv4_addr, ipv4_mask = ipv4_add.split('/')
            #add ipv4 address to PortChannelxx
            if_data4 = {'name': portchannel,
                 'ip' : ipv4_addr,
                 'subnet': ipv4_mask,
                 'family': "ipv4"
                }
            if not ip_obj.config_unconfig_interface_ip_addresses(node, [if_data4] , config='add'):
                st.report_fail('msg', "{} ipv4 address add failed".format(portchannel))
        if ipv6_add:
            ipv6_addr, ipv6_mask = ipv6_add.split('/')
            #add ipv6 address to PortChannelxx
            if_data6 = {'name': portchannel,
                'ip' : ipv6_addr,
                'subnet': ipv6_mask,
                'family': "ipv6"
               }
            if not ip_obj.config_unconfig_interface_ip_addresses(node, [if_data6] , config='add'):
                st.report_fail('msg', "{} ipv6 address add failed".format(portchannel))

        if members:
            portchannel_add_del_member(node, portchannel, members, add=True)
    else:
        if members:
            #delete member interfaces
            portchannel_add_del_member(node, portchannel, members, add=False)

        if ipv4_add:
            ipv4_addr, ipv4_mask = ipv4_add.split('/')
            #remove ipv4 address from PortChannelxx
            if_data4 = {'name': portchannel,
                'ip' : ipv4_addr,
                'subnet': ipv4_mask,
                'family': "ipv4"
               }
            if not ip_obj.config_unconfig_interface_ip_addresses(node, [if_data4] , config='remove'):
                  st.report_fail('msg', "{} ipv4 address remove failed".format(portchannel))

        if ipv6_add:
            ipv6_addr, ipv6_mask = ipv6_add.split('/')
            #remove ipv6 address from PortChannelxx
            if_data6 = {'name': portchannel,
                'ip' : ipv6_addr,
                'subnet': ipv6_mask,
                'family': "ipv6"
               }
            if not ip_obj.config_unconfig_interface_ip_addresses(node, [if_data6] , config='remove'):
                  st.report_fail('msg', "{} ipv6 address remove failed".format(portchannel))

        #del PortChannelxx 
        if not portchannel_obj.delete_portchannel(node, [portchannel]):
            st.report_fail('msg', "{} delete failed".format(portchannel))

def check_portchannel_add_del(node, portchannel, members, state='up', add=True):  
    if add:
        if not portchannel_obj.poll_for_portchannel_status(node, portchannel, state):
            st.report_fail('msg', '{} {} state {} check failed'.format(node, portchannel, state))
        if members:
            if not portchannel_obj.verify_portchannel_member(node, portchannel, members, 'add'):
                st.report_fail('msg', "members check failed for {}".format(portchannel))
    else:
        if portchannel_obj.verify_portchannel(node, portchannel):
            st.report_fail('msg', '{} {} still exists'.format(node, portchannel))


def check_portchannel_ip_address(node, portchannel, ip_addr, family, add=True):
    if add:
        if not ip_obj.verify_interface_ip_address(node, portchannel, ip_addr, family=family):
            st.report_fail('msg', "{} {} ip address addition failed".format(node, portchannel))
    else:
        check_type = 'ip' if family=='ipv4' else 'ipv6'
        cmd_output = st.show(node, "sudo show {} interfaces".format(check_type), skip_tmpl=True)
        parsed_output = st.parse_show(node, "sudo show {} interfaces".format(check_type),
                                 cmd_output, "show_ip_interfaces.tmpl")
        for interface_det in parsed_output:
            if interface_det['interface'] == portchannel:
                st.report_fail('msg', "{} {} {} address removal failed".format(node, portchannel, check_type))

# L2 wrappers

# Static Mac config
def config_mac(node, mac, vlan, intf, verify=False):
    #mac_add = '-'.join(mac.split(':'))
    cmd = '''
          docker exec swss sh -c 'echo "[{{\\"FDB_TABLE:Vlan{}:{}\\": {{\\"port\\" : \\"{}\\", \\"type\\" : \\"static\\"}},\\"OP\\": \\"SET\\"}}]" > ./fdb.json'
          docker exec -it swss swssconfig ./fdb.json
          '''.format(vlan, mac, intf)
    st.config(node, cmd)
    st.wait(1)

    if verify:
        if not mac_obj.verify_mac_address_table(node, mac, vlan=vlan, type='Static'):
            st.report_fail('msg', "Static MAC add failed for mac {} host on vlan {} for node {}".format(mac, vlan, node))

# Static Mac delete
def delete_mac(node, mac, vlan, verify=False):
    #mac_add = '-'.join(mac.split(':'))
    cmd = '''
          docker exec swss sh -c 'echo "[{{\\"FDB_TABLE:Vlan{}:{}\\": {{\\"type\\" : \\"static\\"}},\\"OP\\": \\"DEL\\"}}]" > ./fdb.json'
          docker exec -it swss swssconfig ./fdb.json
          '''.format(vlan, mac)
    st.config(node, cmd)
    st.wait(1)

    if verify:
        if mac_obj.verify_mac_address_table(node, mac, vlan=vlan, type='Static'):
            st.report_fail('msg', "Static MAC delete for mac {} failed for host on vlan {} for node {}".format(mac, vlan, node))

# Mac API config_mac_agetime cli "config mac aging_time" is not supported yet
# MAC API get_mac_agetime is community unsupported
def update_mac_aging(node, mac_aging_time, verify=False):
    cmd = '''
          docker exec swss sh -c 'echo "[{{\\"SWITCH_TABLE:switch\\": {{\\"fdb_aging_time\\" : \\"{}\\"}},\\"OP\\": \\"SET\\"}}]" > ./fdb.json'
          docker exec -it swss swssconfig ./fdb.json
          '''.format(mac_aging_time)
    st.config(node, cmd)
    st.wait(1)

    #Verify mac aging time is correctly updated
    if verify:
        cmd = "show mac aging-time"
        cmd_output = st.show(node, cmd, skip_tmpl=True)
        if not cmd_output:
            st.report_fail('msg', "No output generated by mac aging time command")
        if  str(mac_aging_time)+" " not in cmd_output:
            st.report_fail('msg', "Mac aging time update Unsuccessful, expected: {}, got: {}".format(mac_aging_time, int(cmd_output[0]["aging_time"])))
        st.log("Mac aging time update Successful, New mac aging time : {} seconds".format(mac_aging_time))

# Storm Control APIs
def config_storm_control(node, type, action, interface_name, bits_per_sec):
    if action == "add":
        cmd = "config interface storm-control {} {} {} {}".format(action, interface_name, type, bits_per_sec)
    else:
        cmd = "config interface storm-control {} {} {}".format(action, interface_name, type)
    st.config(node, cmd)

# File base FRR configuration
def config_frr(dut, commands):

    if not isinstance(commands, list):
        commands = [commands]

    st.log("Configuring on frr: {}".format(commands))
    with open("/tmp/spytest_frr.conf", "w") as fd:
        fd.write("\n".join(commands))
    st.upload_file_to_dut(dut, "/tmp/spytest_frr.conf", "/tmp/spytest_frr.conf")

    st.config(dut, "docker cp /tmp/spytest_frr.conf bgp:/")
    st.config(dut, "docker exec bgp bash -c 'vtysh -f /spytest_frr.conf'")

DEFAULT_CHECKPOINT_NAME = 'tortuga_spytest'

# Checkpoint APIs
def create_checkpoint(node, cp=DEFAULT_CHECKPOINT_NAME, skip_error_check=False):
    cmds = 'config checkpoint {}'.format(cp)

    st.log("Create Checkpoint: {}".format(cp))
    st.config(node, cmds, skip_error_check=skip_error_check)

def rollback_checkpoint(node, cp=DEFAULT_CHECKPOINT_NAME, skip_error_check=False):
    cmds = 'config rollback {}'.format(cp)

    st.log("Rollback Checkpoint: {}".format(cp))
    st.config(node, cmds, skip_error_check=skip_error_check)

def delete_checkpoint(node, cp=DEFAULT_CHECKPOINT_NAME, skip_error_check=False):
    cmds = 'config delete-checkpoint {}'.format(cp)

    st.log("Delete Checkpoint: {}".format(cp))
    st.config(node, cmds, skip_error_check=skip_error_check)

# L3 RIF Counters
def check_rif_counters(node, intf, rx_ok=None, tx_ok=None):
    result = True
    counters = intf_obj.show_interfaces_counters(dut=node, interface=[intf], rif='yes')
    if not counters:
        st.log("Failed to get the RIF counters for intf {}".format(intf))
        return False
    if rx_ok and int(counters[0]['rx_ok'].replace(',', '')) < rx_ok :
        result = False
    if rx_ok and int(counters[0]['tx_ok'].replace(',', '')) < tx_ok :
        result = False
    return result

#ACL
def create_acl_table(dut, table_name, stage, acl_type, description, ports):
    
    st.log("Creating ACL table")
    acl_table = {
        table_name : {
            "type" : acl_type,
            "policy_desc" : description,
            "ports" : ports,
            "stage" : stage
        }
    }
    acl_table_data = dict()
    acl_table_data["ACL_TABLE"] = acl_table
    acl_table_data = json.dumps(acl_table_data)
    json.loads(acl_table_data)
    st.apply_json2(dut, acl_table_data)

def delete_acl_table(dut, acl_table_name=None):
    st.log("Deleting ACL table")
    command = "sudo config acl remove table"
    if acl_table_name:
        table_name = list([str(e) for e in acl_table_name]) if isinstance(acl_table_name, list) \
            else [acl_table_name]
        commands = ""
        for acl_table in table_name:
            commands += "{} {};".format(command, acl_table)
        if commands:
            st.config(dut, commands)
    else:
        st.config(dut, command)

def clear_acl_counter(dut, acl_table=None, acl_rule=None):
    st.log("Clear ACL Counters")
    command = "aclshow -c"
    if acl_table:
        command += " -t {}".format(acl_table)
    if acl_rule:
        command += " -r {}".format(acl_rule)
    st.config(dut, command)

# DPB 
def configure_dynamic_breakout(node, data, verify="True", undo=False):
    result = True
    for intf, mode in data.items():
        cmd = 'config interface breakout {} {} -yfl'.format(intf, mode)
        st.log("Configuring breakout mode for intf {} : {}".format(intf, mode))
        st.config(node, cmd, skip_error_check=False)
        number_of_breakouts = int(mode[0])
        st.log("Startup the {} new interfaces".format(number_of_breakouts))
        if undo :
            cmd = "config interface startup {}".format(intf)
            st.config(node, cmd, skip_error_check=False)
        else:
            for new_intf in range(1, number_of_breakouts+1):
                cmd = "config interface startup {}".format(intf + '_' + str(new_intf))
                st.config(node, cmd, skip_error_check=False)
        if verify:
            cmd = "show interfaces breakout current-mode {}".format(intf)
            cmd_output = st.show(node, cmd)
            entries = filter_and_select(cmd_output, None, {"interface": intf, 'mode': mode})
            if not entries :
                result = False
                st.log("Breakout mode verification failed for intf {} expected {} got {}".format(intf, mode, entries[0]['mode']))
            else :
                st.log("Successfully verified breakout mode for intf {}".format(intf))
    return result

#Apply Json Config
def apply_json_config(node, file, file_path):
    utils_obj.copy_files_to_dut(node, [file_path], '/home/cisco')
    st.config(node, "config load {} -y".format(file))

#QOS
def verify_queue_counters(node, port, queue_name, param_list, val_list, tol_list):
    result = True
    cmd = "show queue counters {}".format(port)
    cmd_output = st.show(node, cmd)
    entries = filter_and_select(cmd_output, None, {"port": port, "txq": queue_name})
    if entries :
        for param, val, tol in zip(param_list, val_list, tol_list):
            if int(entries[0][param]) <= int(val) + int(tol) and int(entries[0][param]) >= int(val) - int(tol): 
                st.log("Successfully verified queue counter for port {}, queue name {}, param {}".format(port, queue_name, param))
            else:
                result = False
                st.error("Queue Counter verification failed for port {}, queue name {}, param {}, obtained val, {} against expected val {}".format(port, queue_name, param, entries[0][param], val))
    else:
        result = False
        st.error("No queue counter entry found for port {} and {}".format(port, queue_name))
    return result

def verify_queue_and_priority_grp_counters(node, port, watermark_type, param_list, val_list, tol_list, priority_group = None, check_NA=False):
    result = True
    cmd = "show queue watermark {}".format(watermark_type)
    if priority_group:
        cmd = "show priority-group {} {}".format(priority_group, watermark_type)
    cmd_output = st.show(node, cmd)
    entries = filter_and_select(cmd_output, None, {"port": port})
    if entries :
        for param, val, tol in zip(param_list, val_list, tol_list):
            got_val = entries[0][param.lower()]
            if check_NA:
                if got_val == "N/A":
                    st.log("Queue counter is not available as expected")
                else:
                    result = False
                    st.error("Queue counter is available against expectation")
            elif got_val == "N/A":
                result = False
                st.error("Queue counter is not available against expectation")
            else:
                if int(got_val) <= int(val) + int(tol) and int(got_val) >= int(val) - int(tol): 
                    st.log("Successfully verified queue counter for port {}, for {} type {}, param {}".format(port, priority_group, watermark_type, param))
                else:
                    result = False
                    st.log("Queue Counter verification failed for port {}, for {} type {}, param {}, obtained val, {} against expected val {}".format(port, priority_group, watermark_type, param, got_val, val))
    else:
        result = False
        st.log("No queue counter entry found for port {} for {} type {}".format(port, priority_group, watermark_type))
    return result
