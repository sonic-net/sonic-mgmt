import os
import yaml
import json
import re
import pytest
from spytest import st, tgapi

def reset_tg_interfaces(tg1, tg2, tg_handle_1, tg_handle_2):
    tg1.tg_traffic_control(action='reset', port_handle=[tg_handle_1, tg_handle_2])
    tg2.tg_traffic_control(action='reset', port_handle=[tg_handle_1, tg_handle_2])


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
        st.report_fail("test_case_failed_msg", "ARS Value Not Set Appropriately While Adding")
    return

def check_ars(ars, expected_values):
    # Handle empty output
    if len(ars) == 0 and len(expected_values) == 0:
        st.log("ARS Value Set Appropriately")
        return True
    
    # Handle unexpected empty list when we expect values
    if len(ars) == 0 and len(expected_values) > 0:
        st.log("ERROR: ARS output is empty but expected values were provided: {}".format(expected_values))
        return False
    
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
        st.report_fail("test_case_failed_msg", "ARS Value Not Set Appropriately While Deleting")
    return

def check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counters, intfrecord, margin = 0.25, packetlosstolerance = 0.001):
    """
    Check if traffic is balanced across multiple interfaces.
    """
    total_count = 0
    interface_counts = []
    st.wait(5)
    stats_tg1 = tg1.tg_traffic_stats(port_handle=tg_handle_1, mode='aggregate')
    stats_tg2 = tg2.tg_traffic_stats(port_handle=tg_handle_2, mode='aggregate')
    tgen_source_port = int(stats_tg1[tg_handle_1]['aggregate']['tx']['total_pkts'])
    tgen_receive_port = int(stats_tg2[tg_handle_2]['aggregate']['rx']['total_pkts'])
    st.banner("Total Outgoing traffic from Source Port "+str(tgen_source_port))
    st.banner("Total Incoming traffic from Dest Port" + str(tgen_receive_port))
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
    return  int(tgen_source_port) <= int(tgen_receive_port)*(1+packetlosstolerance)

def check_traffic_single_interface(tg1, tg2, tg_handle_1, tg_handle_2, counters, intfrecord, tolerance = 0.001, packetlosstolerance = 0.001):
    """
    Check if traffic is sent through a single interface.
    """
    tx_ok_count = 0
    st.wait(2)
    stats_tg1 = tg1.tg_traffic_stats(port_handle=tg_handle_1, mode='aggregate')
    stats_tg2 = tg2.tg_traffic_stats(port_handle=tg_handle_2, mode='aggregate')
    tgen_source_port = int(stats_tg1[tg_handle_1]['aggregate']['tx']['total_pkts'])
    tgen_receive_port = int(stats_tg2[tg_handle_2]['aggregate']['rx']['total_pkts'])
    st.banner("Total Outgoing traffic from Source Port "+ str(tgen_source_port))
    st.banner("Total Incoming traffic from Dest Port " + str(tgen_receive_port))
    for record in counters:
        if record.get('iface') in intfrecord:
            tx_ok_value = int(record.get('tx_ok', '0').replace(',', ''))
            if tx_ok_value >=int(tgen_source_port)*(1-tolerance) : # check if there is single interface carrying 99% of the traffic tolerance 0.01 in case few packets travel through different interface
                tx_ok_count += 1
    return tx_ok_count == 1 and  int(tgen_source_port) <= int(tgen_receive_port)*(1+packetlosstolerance) # Makes sure the sending packets from source are always less than received packets at destination, ensuring no packet loss

def run_traffic(stream,tg_handle_1, tg1, data_glob):
    st.config(data_glob.dut1, "sudo -s sonic-clear counters")
    tg1.tg_traffic_control(action="clear_stats", port_handle=tg_handle_1)
    tg1.tg_traffic_control(action='run', handle=stream)
    st.wait(5)
    st.config(data_glob.dut1, "aclshow -a")
    # st.config(data_glob.dut1,"sudo -s show platform npu ars info -s 1")
    # st.config(data_glob.dut1,"sudo -s show platform npu ars flows -s 1")
    st.wait(5)
    tg1.tg_traffic_control(action='stop', handle=stream)


def add_nhg_equal_to_ecmp(data_glob, vars):
    st.config(data_glob.dut1, "sudo -s config ars-portlist add non_global_port_list --ars-profile-name arsp")
    st.config(data_glob.dut1, "sudo -s config ars-portlist-member add "+  vars.D1D3P1 +" --ars-portlist non_global_port_list")
    st.config(data_glob.dut1, "sudo -s config ars-portlist-member add "+  vars.D1D3P2 +" --ars-portlist non_global_port_list")
    st.config(data_glob.dut1, "sudo -s config ars-portlist-member add "+  vars.D1D4P2 +" --ars-portlist non_global_port_list")
    st.config(data_glob.dut1, "sudo -s show ars-portlist-member")

def del_nhg_equal_to_ecmp(data_glob, vars):
    st.config(data_glob.dut1, "sudo -s config ars-portlist-member del "+ vars.D1D3P1)
    st.config(data_glob.dut1, "sudo -s config ars-portlist-member del "+ vars.D1D3P2)
    st.config(data_glob.dut1, "sudo -s config ars-portlist-member del "+ vars.D1D4P2)
    st.config(data_glob.dut1, "sudo -s config ars-portlist delete non_global_port_list")
    st.config(data_glob.dut1, "sudo -s show ars-portlist-member")