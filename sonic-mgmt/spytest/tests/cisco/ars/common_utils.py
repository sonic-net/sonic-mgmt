import os
import yaml
import json
import re
import pytest
from spytest import st, tgapi

def get_handles():
    tg1, tg_ph_1 = tgapi.get_handle_byname("T1D3P1")
    tg2, tg_ph_2 = tgapi.get_handle_byname("T1D4P1")
    return (tg1, tg2, tg_ph_1, tg_ph_2)

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
            find_and_replace(dir_path+output_yaml_file, var_dict, item, value)
    return dir_path+output_yaml_file

def replace_string(obj, var_dict):
    if isinstance(obj, str):
        for item, value in var_dict.items():
            if re.match("(D.D.P.)|(D.T.P.)", item):
                obj = obj.replace(item, value)
        return obj
    elif isinstance(obj, dict):
        return {key: replace_string(value, var_dict) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [replace_string(item, var_dict) for item in obj]
    else:
        return obj

def find_and_replace(file_path, var_dict, target_string, replacement_string):
    with open(file_path, 'r') as file:
        data = yaml.safe_load(file)
    # Iterate through the YAML data recursively
    updated_data = replace_string(data, var_dict)
    with open(file_path, 'w') as file:
        yaml.dump(updated_data, file)

def modify_json_file(json_file, var_dict):
    """
    Takes a JSON file and replaces keywords from var_dict, returns the path to a new JSON file.
    """
    output_json_file = "temp_config.json"
    dir_path = os.path.dirname(os.path.realpath(__file__)) + "/"
    input_json_file = json_file
    result = os.system("cp {1} {0}{2}".format(dir_path, input_json_file, output_json_file))
    if result != 0:
        st.report_fail('msg', "JSON file copy failed")
    st.wait(2)
    file_path = dir_path + output_json_file
    with open(file_path, 'r') as file:
        data = json.load(file)

    updated_data = replace_string(data, var_dict)
    with open(file_path, 'w') as file:
        json.dump(updated_data, file, indent=4)
    return file_path

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

def remove_temp_config(updated_config_file):
    os.system("rm {}".format(updated_config_file))

def reset_tg_interfaces(tg1, tg2, tg_handle_1, tg_handle_2):
    tg1.tg_traffic_control(action='reset', port_handle=[tg_handle_1, tg_handle_2])
    tg2.tg_traffic_control(action='reset', port_handle=[tg_handle_1, tg_handle_2])

def configure_tg_interfaces_v4(tg1, tg2, tg_handle_1, tg_handle_2, data1, data2):
    st.log("Creating Devices & adding IP Addresses along with ARP requests")
    res1 = tg1.tg_interface_config(port_handle=tg_handle_1, mode='config', intf_ip_addr=data1.t1d1_ip_addr, gateway=data1.t1d1_ip_gateway, src_mac_addr=data1.t1d1_mac_addr, arp_send_req='1', enable_ping_response=1)
    st.log("INTFCONF: " + str(res1))
    tg1_interface = res1
    res2 = tg2.tg_interface_config(port_handle=tg_handle_2, mode='config', intf_ip_addr=data2.t1d2_ip_addr, gateway=data2.t1d2_ip_gateway, src_mac_addr=data2.t1d2_mac_addr, arp_send_req='1', enable_ping_response=1)
    st.log("INTFCONF: " + str(res2))
    tg2_interface = res2
    return tg1_interface, tg2_interface

def configure_tg_interfaces_v6(tg1, tg2, tg_handle_1, tg_handle_2, data1, data2):
    st.log("Creating Devices & adding IP Addresses along with ARP requests")
    res1 = tg1.tg_interface_config(port_handle=tg_handle_1, mode='config', ipv6_intf_addr=data1.t1d1_ipv6_addr,ipv6_prefix_length='64', ipv6_gateway=data1.t1d1_ipv6_gateway, src_mac_addr=data1.t1d1_mac_addr, arp_send_req='1', enable_ping_response=1)
    st.log("INTFCONF: " + str(res1))
    tg1_interface = res1
    res2 = tg2.tg_interface_config(port_handle=tg_handle_2, mode='config', ipv6_intf_addr=data2.t1d2_ipv6_addr,ipv6_prefix_length='64', ipv6_gateway=data2.t1d2_ipv6_gateway, src_mac_addr=data2.t1d2_mac_addr, arp_send_req='1', enable_ping_response=1)
    st.log("INTFCONF: " + str(res2))
    tg2_interface = res2
    return tg1_interface, tg2_interface

def verify_ping_helper(tg, tg_handle, tg_interface, dest_ip):
    ping_max_iteration=2
    for iter in range(ping_max_iteration):
        res = tgapi.verify_ping(src_obj=tg, port_handle=tg_handle, dev_handle=tg_interface, dst_ip=dest_ip, ping_count='5', exp_count='5')
        st.log("PING_RES: " + str(res))
        if res:
            st.log("Ping succeeded.")
            return
    st.log('msg', "Ping Failed")

def configure_traffic_streams_BUM(tg1, tg2, tg_handle_1, tg_handle_2, data1, data2):
    st.banner("Configuring BUM Traffic Stream on TGEN port1 towards DUT1")
    trBUM = {}
    trBUM['unicast'] = tg1.tg_traffic_config(port_handle=tg_handle_1, mac_src = data1.t1d1_mac_addr, mac_dst=data2.t1d2_mac_addr,
                                mode='create', high_speed_result_analysis='1', length_mode='fixed', transmit_mode='multi_burst',
                                pkts_per_burst='999', inter_burst_gap="2000000", inter_burst_gap_unit='ns', tx_delay='0',
                                tx_delay_unit='bytes', min_gap_bytes='12')

    trBUM['multicast'] = tg1.tg_traffic_config(port_handle=tg_handle_1, mac_src = data1.t1d1_mac_addr, mac_dst="01:00:5e:44:44:44",
                                mode='create', high_speed_result_analysis='1', length_mode='fixed', transmit_mode='multi_burst',
                                pkts_per_burst='999', inter_burst_gap="2000000", inter_burst_gap_unit='ns', tx_delay='0',
                                tx_delay_unit='bytes', min_gap_bytes='12')

    trBUM['broadcast'] = tg1.tg_traffic_config(port_handle=tg_handle_1, mac_src = data1.t1d1_mac_addr, mac_dst="ff:ff:ff:ff:ff:ff",
                                mode='create', high_speed_result_analysis='1', length_mode='fixed', transmit_mode='multi_burst',
                                pkts_per_burst='999', inter_burst_gap="2000000", inter_burst_gap_unit='ns', tx_delay='0',
                                tx_delay_unit='bytes', min_gap_bytes='12')
    return trBUM

def configure_traffic_streams(tg1, tg2, tg_handle_1, tg_handle_2, tg1_interface, tg2_interface, tcircuit_endpoint_type):
    st.banner("Configuring Traffic Stream on TGEN port1 towards DUT1")
    trBurst = tg1.tg_traffic_config(port_handle=tg_handle_1, emulation_src_handle=tg1_interface['handle'], emulation_dst_handle=tg2_interface['handle'],
                                circuit_endpoint_type=tcircuit_endpoint_type, mode='create', high_speed_result_analysis='1',
                                length_mode='fixed', transmit_mode='multi_burst', pkts_per_burst='999', inter_burst_gap="2000000",
                                inter_burst_gap_unit='ns', tx_delay='0', tx_delay_unit='bytes', min_gap_bytes='12')
    
    trContinuous = tg1.tg_traffic_config(port_handle=tg_handle_1, emulation_src_handle=tg1_interface['handle'], emulation_dst_handle=tg2_interface['handle'],
                                circuit_endpoint_type=tcircuit_endpoint_type, mode='create', high_speed_result_analysis='1', length_mode='fixed',
                                transmit_mode='continuous', rate_percent=10)

    traffic_args = {}
    if tcircuit_endpoint_type == 'ipv4':
        traffic_args = {'ip_dscp': 57}
    else:
        traffic_args = {'ipv6_traffic_class': 228}

    trDSCP1 = tg1.tg_traffic_config(port_handle=tg_handle_1, emulation_src_handle=tg1_interface['handle'], emulation_dst_handle=tg2_interface['handle'],
                                circuit_endpoint_type=tcircuit_endpoint_type, mode='create', high_speed_result_analysis='1', length_mode='fixed', transmit_mode='multi_burst',
                                pkts_per_burst='999', inter_burst_gap="2000000", inter_burst_gap_unit='ns', tx_delay='0', tx_delay_unit='bytes',
                                min_gap_bytes='12', **traffic_args)

    if tcircuit_endpoint_type == 'ipv4':
        traffic_args = {'ip_dscp': 58}
    else:
        traffic_args = {'ipv6_traffic_class': 232}

    trDSCP2 = tg1.tg_traffic_config(port_handle=tg_handle_1, emulation_src_handle=tg1_interface['handle'], emulation_dst_handle=tg2_interface['handle'],
                                circuit_endpoint_type=tcircuit_endpoint_type, mode='create', high_speed_result_analysis='1', length_mode='fixed', transmit_mode='multi_burst',
                                pkts_per_burst='999', inter_burst_gap="2000000", inter_burst_gap_unit='ns', tx_delay='0', tx_delay_unit='bytes',
                                min_gap_bytes='12', **traffic_args)
    
    return trBurst, trContinuous, trDSCP1, trDSCP2

def run_traffic(dut, tg1, tg_handle_1, stream):
    st.config(dut, "sudo -s sonic-clear counters")
    tg1.tg_traffic_control(action="clear_stats", port_handle=tg_handle_1)
    tg1.tg_traffic_control(action='run', handle=stream)
    st.wait(10)
    tg1.tg_traffic_control(action='stop', handle=stream)

def tg_interface_cleanup(tg1, tg2, tg_handle_1, tg_handle_2, tg1_interface, tg2_interface):
    reset_tg_interfaces(tg1, tg2, tg_handle_1, tg_handle_2)
    #st.wait(100)
    tg1.tg_interface_config(port_handle=tg_handle_1, handle=tg1_interface['handle'], mode='destroy')
    #st.wait(100)
    tg2.tg_interface_config(port_handle=tg_handle_2, handle=tg2_interface['handle'], mode='destroy')
    st.wait(100)

def add_ars(dut, global_mode="true", mode="flowlet-quality", idle_time="N/A"):
    cmd = "sudo -s config ars-profile add arsp --enable-all-packets {} --mode {}".format(global_mode, mode)
    if mode == "flowlet-quality":
        cmd += " --idle-time {}".format(idle_time)
    st.config(dut,cmd)
    res = st.show(dut, "show ars-profile")
    expected_values = {"ars_profile_name": "arsp", "enable_all_packets": global_mode, "ars_mode": mode}
    if mode == "flowlet-quality":
        expected_values["ars_idle_time"] = idle_time
    if not check_ars(res, expected_values):
        st.report_fail("test_case_failed_msg", "ARS Value Not SET Appropriately While Adding")
    return

def check_ars(ars, expected_values):
    if len(ars) == 0 and len(expected_values) == 0:
        st.log("ARS Value Set Appropriately")
        return True
    actual_values = ars[0]
    for key in expected_values:
        if actual_values.get(key) != expected_values[key]:
            st.log("Value mismatch for {}: expected {}, got {}".format(key, expected_values[key], actual_values.get(key)))
            return False
    st.log("ARS Value Set Appropriately")
    return True

def del_ars(dut):
    st.config(dut, "sudo -s config ars-profile del arsp")
    res = st.show(dut, "show ars-profile")
    if not check_ars(res, expected_values = []):
        st.report_fail("test_case_failed_msg", "ARS Value Not SET Appropriately While Deleting")
    return

def check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counters, intfrecord, margin = 0.2, packetlosstolerance = 0.001):
    """
    Check if traffic is balanced across multiple interfaces.
    """
    total_count = 0
    interface_counts = []
    stats_tg1 = tg1.tg_traffic_stats(port_handle=tg_handle_1, mode='aggregate')
    stats_tg2 = tg2.tg_traffic_stats(port_handle=tg_handle_2, mode='aggregate')
    tgen_source_port = int(stats_tg1[tg_handle_1]['aggregate']['tx']['total_pkts'])
    tgen_recieve_port = int(stats_tg2[tg_handle_2]['aggregate']['rx']['total_pkts'])
    st.banner("Total Outgoing traffic from Source Port "+str(tgen_source_port))
    st.banner("Total Incoming traffic from Dest Port" + str(tgen_recieve_port))
    for record in counters:
        if record.get('iface') in intfrecord:
            ok_value = int(record.get('tx_ok', '0').replace(',', ''))
            total_count += ok_value
            interface_counts.append(ok_value)
    average_count = tgen_source_port/ len(intfrecord)
    toleranceB = average_count * (1-margin) 
    toleranceA = average_count * (1+margin) 
    st.banner("Average Count per Interface: " + str(average_count))
    for pkt_count in interface_counts:
        if not (toleranceB <= pkt_count <= toleranceA):
            st.banner("Traffic is not evenly Distributed Across Interface " + str(pkt_count) + " is not within the tolerance range [" + str(toleranceB) + ", " + str(toleranceA) + "]")
            return False
    return  int(tgen_source_port) <= int(tgen_recieve_port)*(1+packetlosstolerance)

def check_traffic_single_interface(tg1, tg2, tg_handle_1, tg_handle_2, counters, intfrecord, tolerance = 0.001, packetlosstolerance = 0.001):
    """
    Check if traffic is sent through a single interface.
    """
    tx_ok_count = 0
    stats_tg1 = tg1.tg_traffic_stats(port_handle=tg_handle_1, mode='aggregate')
    stats_tg2 = tg2.tg_traffic_stats(port_handle=tg_handle_2, mode='aggregate')
    tgen_source_port = int(stats_tg1[tg_handle_1]['aggregate']['tx']['total_pkts'])
    tgen_recieve_port = int(stats_tg2[tg_handle_2]['aggregate']['rx']['total_pkts'])
    st.banner("Total Outgoing traffic from Source Port "+ str(tgen_source_port))
    st.banner("Totoal Incoming traffic from Dest Port " + str(tgen_recieve_port))
    for record in counters:
        if record.get('iface') in intfrecord:
            tx_ok_value = int(record.get('tx_ok', '0').replace(',', ''))
            if tx_ok_value >=int(tgen_source_port)*(1-tolerance) : # check if there is single interface carrying 99% of the traffic tolerance 0.01 in case few packet travel through different interface
                tx_ok_count += 1
    return tx_ok_count == 1 and  int(tgen_source_port) <= int(tgen_recieve_port)*(1+packetlosstolerance) # Makes Sure the sending packets from source Always less than recieved packet at Destination Making sure No packet loss

def create_acl_table_and_rule(dut, acl_json_file_path = None):
    st.log("Creating ACL table")
    with open(acl_json_file_path, 'r') as file:
        acl_table_data = json.load(file)
    print(acl_table_data)
    acl_json_string = json.dumps(acl_table_data)
    print(acl_json_string)
    st.apply_json2(dut, acl_json_string)

def delete_acl_table(dut):
    st.log("Deleting ACL table")
    command = "sudo config acl remove table ARS_IPV4"
    st.config(dut, command)