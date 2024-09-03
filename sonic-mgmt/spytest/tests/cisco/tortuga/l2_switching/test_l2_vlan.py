import os
import time
import yaml
import pytest
import re
from spytest import st, tgapi, SpyTestDict

import apis.switching.vlan as vapi
import apis.switching.mac as mac_obj

import tortuga_common_utils as common_obj

#TGen Stream Config
data = SpyTestDict()
data.my_dut_list = None

# Define hosts list
data.hosts = ["T1D3P1", "T1D4P1", "T1D3P2", "T1D4P2"]

# hosts data
data.hosts_data = {
    "T1D3P1": {"ip_addr": "10.0.1.1", "mac_addr": "00:00:00:00:10:11"},
    "T1D4P1": {"ip_addr": "10.0.1.2", "mac_addr": "00:00:00:00:10:12"},
    "T1D3P2": {"ip_addr": "10.0.2.1", "mac_addr": "00:00:00:00:10:21"},
    "T1D4P2": {"ip_addr": "10.0.2.2", "mac_addr": "00:00:00:00:10:22"}
}
data.vlan_list = ["10","20","30","40","50"]

##Vlan id 10 stream config
data_vid_10 = SpyTestDict()
data_vid_10.my_dut_list = None
data_vid_10.vlan = "10"
data_vid_10.t1d3_ip_gateway = "10.0.1.10"
data_vid_10.t1d4_ip_gateway = "10.0.1.10"

data_vid_10.t1d3_ip_addr = "10.0.1.1"
data_vid_10.t1d3_mac_addr = "00:0A:03:00:11:01"

data_vid_10.t1d4_ip_addr = "10.0.1.2"
data_vid_10.t1d4_mac_addr = "00:0A:04:00:12:01"

data_vid_10.t1d3_dest_mac_addr = data_vid_10.t1d4_mac_addr
data_vid_10.t1d4_dest_mac_addr = data_vid_10.t1d3_mac_addr

data_vid_10.transmit_mode = 'single_burst'
data_vid_10.pkts_per_burst = "500"
data_vid_10.tgen_stats_threshold = 20
data_vid_10.tgen_rate_pps = '1000'
data_vid_10.tgen_l3_len = '500'
data_vid_10.traffic_run_time = 5
##L2 stream config

##Vlan id 20 stream config
data_vid_20 = SpyTestDict()
data_vid_20.my_dut_list = None
data_vid_20.vlan = "20"
data_vid_20.t1d3_ip_gateway = "10.0.2.20"
data_vid_20.t1d4_ip_gateway = "10.0.2.20"

data_vid_20.t1d3_ip_addr = "10.0.2.1"
data_vid_20.t1d3_ipv6_addr = "10:0:2::1"
data_vid_20.t1d3_mac_addr = "00:0A:05:00:11:01"

data_vid_20.t1d4_ip_addr = "10.0.2.2"
data_vid_20.t1d4_ipv6_addr = "10:0:2::2"
data_vid_20.t1d4_mac_addr = "00:0A:06:00:12:01"

data_vid_20.t1d3_dest_mac_addr = data_vid_20.t1d4_mac_addr
data_vid_20.t1d4_dest_mac_addr = data_vid_20.t1d3_mac_addr

data_vid_20.transmit_mode = 'single_burst'
data_vid_20.pkts_per_burst = "500"
data_vid_20.tgen_stats_threshold = 20
data_vid_20.tgen_rate_pps = '1000'
data_vid_20.tgen_l3_len = '500'
data_vid_20.traffic_run_time = 5
##L2 stream config

# TODO: Parameterize the configs. For now, use static configs
CONFIGS_FILE = 'l2_vlan_config.yaml'

####################
#                  #
#    D1 = spt      #
#    D2 = BR1      #
#    D3 = BR2      #
#    D4 = BR3      #
#    D5 = spt      #
#                  #
####################

#######################################################################
#                                                                     #
#  spt ---Access--- BR1 ---trunk---BR2---trunk----BR3-----Access--spt # 
#                                                                     #
#  spt -- leaf0-----------spine0-------------leaf1 -- spt             #
#                                                                     #
#######################################################################

@pytest.fixture(scope='module', autouse=True)
def setup_teardown_l2_vlan_test():
    global vars
    vars = st.get_testbed_vars()

    global nodes
    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    dir_path = os.path.dirname(os.path.realpath(__file__))
    updated_path = common_obj.modify_config_file(dir_path + '/' + CONFIGS_FILE,vars)

    with open(updated_path) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            st.log("Node: "+ str(node))
            common_obj.config_static(node, 'sonic', True, updated_path)

    count = 5    
    st.show(nodes['spine0'], 'sudo ping -c {} {} -q'.format(count, '10.0.1.2'), skip_tmpl=True, skip_error_check=True)

    yield 'setup_teardown_l2_vlan_test'

    with open(updated_path) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            common_obj.config_static(node, 'sonic', False, updated_path)


def traffic_test_ping(host1, host2, vlan_id = None):
    ret = False
    data.my_dut_list = st.get_dut_names()
 
    common_obj.clear_counters()

    tg_handler = tgapi.get_handles_byname(host1, host2)
    tg = tg_handler["tg"]

    vars = st.get_testbed_vars()
    dut_lists = [vars.D3, vars.D4]

    (tg1,tg2, tg_ph_1,tg_ph_2) = common_obj.get_handles(host1, host2)

    tg.tg_traffic_control(action="reset", port_handle=tg_handler["tg_ph_list"])
    tg.tg_traffic_control(action="clear_stats", port_handle=tg_handler["tg_ph_list"])

    #Tagged VLAN packet from tgen to DUT case
    if vlan_id is not None:
        res=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr=data.hosts_data[host1]["ip_addr"],
            gateway=data.hosts_data[host2]["ip_addr"],src_mac_addr=data.hosts_data[host1]["mac_addr"], arp_send_req='1', enable_ping_response=1,vlan = "1", vlan_id = str(vlan_id))
        st.log("tagged INTFCONF: "+str(res))
        handle1 = res['handle']

        res=tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr=data.hosts_data[host2]["ip_addr"], 
            gateway=data.hosts_data[host1]["ip_addr"],src_mac_addr=data.hosts_data[host2]["mac_addr"], arp_send_req='1',enable_ping_response=1, vlan = "1", vlan_id = str(vlan_id))
        st.log("tagged INTFCONF: "+str(res))
        handle2 = res['handle']
        st.wait(5)

    #untagged packet from tgen to DUT case
    else:   
        res=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr=data.hosts_data[host1]["ip_addr"],
            gateway=data.hosts_data[host2]["ip_addr"],src_mac_addr=data.hosts_data[host1]["mac_addr"], arp_send_req='1', enable_ping_response=1) 
        st.log("untagged INTFCONF: "+str(res))
        handle1 = res['handle']

        res=tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr=data.hosts_data[host2]["ip_addr"], 
            gateway=data.hosts_data[host1]["ip_addr"],src_mac_addr=data.hosts_data[host2]["mac_addr"], arp_send_req='1',enable_ping_response=1)
        st.log("untagged INTFCONF: "+str(res))
        handle2 = res['handle']
        st.wait(5)

    # Ping Between tgen1 to tgen2

    st.banner("Ping from TG1(D3) host1 {} to TG2(D4) host2 {} ".format(host1,host2))

    ping_res1 = tgapi.verify_ping(src_obj=tg, port_handle=tg_handler["tg_ph_1"], dev_handle=handle1,
               dst_ip=data.hosts_data[host2]["ip_addr"], ping_count='10', exp_count='10')
    st.wait(5)
    st.log("########################ping_res1 value #############################")
    print(ping_res1)

    ping_res2 = tgapi.verify_ping(src_obj=tg, port_handle=tg_handler["tg_ph_2"], dev_handle=handle2,
               dst_ip=data.hosts_data[host1]["ip_addr"], ping_count='10', exp_count='10')
    st.wait(5)
    st.log("########################ping_res2 value #############################")
    print(ping_res2)

    ping_res1_result, ping_res2_result = False, False
    ## Update Ping Result for Ping Test:
    if ping_res1 and ping_res2:
        st.log("10 Ping from TG1(D3) to TG2(D4) and vice versa succeeded.")
        ret = True
        ping_res1_result = True
        ping_res2_result = True
    elif ping_res2:
        st.log("test_case_failed 10 Ping TG1(D3) to TG2(D4) failed.")
        ret = False
        ping_res1_result = True
    elif ping_res1:
        st.log("test_case_failed 10 Ping TG2(D4) to TG1(D3) failed.")
        ret = False
        ping_res2_result = True
    else:
        st.log("test_case_failed 10 Both ping from TG1(D3) to TG2(D4) and vice versa failed.")
        ret = False


    st.log(" 10 Ping TG1(D3) <-> TG2(D4) success? : {} ping_res1_result: {} ping_res2_result: {} (passed: True, failed: False) ".format(ret, ping_res1_result, ping_res2_result))
    return ret


#testcase 1
def test_l2_vlan_tagged_untagged_vlan_interface_untagged_ping(setup_teardown_l2_vlan_test):

    """
    Testcase 1 - Untagged interface D3T1P1 part of VLAN 10 and tagged interface VLAN 20, ping (without any tag is sent from Spt)
    Expectation: Packet gets tagged with VLAN between the trunk port and reaches the dst without VLAN tag 
                 and ping success for VLAN 10 case and fails for VLAN 20
    """

    # ping test
    ret_val1 = traffic_test_ping("T1D3P1", "T1D4P1")
    st.wait(1)

    ################# trunk port #################
    #config
    vapi.add_vlan_member(vars.D3, "20", [vars.D3T1P2], tagging_mode=True)
    vapi.add_vlan_member(vars.D4, "20", [vars.D4T1P2], tagging_mode=True)

    #Ping test untagged on trunk
    ret_val2 = traffic_test_ping("T1D3P2","T1D4P2") #ping should be failed
    st.wait(1)

    #deconfig
    vapi.delete_vlan_member(vars.D3, "20", [vars.D3T1P2], tagging_mode=True)
    vapi.delete_vlan_member(vars.D4, "20", [vars.D4T1P2], tagging_mode=True)

    st.log("ret_val1 : "+ str(ret_val1) + "  ret_val2 : "+ str(ret_val2))    

    if(True == ret_val1 and False == ret_val2):
        st.report_pass('msg', "PASS: Testcase#1 Ping between VLAN 10 hosts passed")
    else:
        st.report_fail('msg', "FAIL: Testcase#1 Ping between VLAN 10 hosts failed")


#testcase 2 

def test_l2_vlan_tagged_interface_access_and_trunk_tagged_ping(setup_teardown_l2_vlan_test):

    """
    testcase 2 - tagged ping with VLAN 10 and 20 sent on both access and trunk cases of D3T1P2 member of VLAN 20
    expectation: out of range VLAN tagged packets (here 10) are dropped on trunk intf and same tagged VLAN 20 packets ping should pass

    """

    ################# access port #################
    #config
    vapi.add_vlan_member(vars.D3, "20", [vars.D3T1P2], tagging_mode=False)
    vapi.add_vlan_member(vars.D4, "20", [vars.D4T1P2], tagging_mode=False)
    #Ping test
    ret_val1 = traffic_test_ping("T1D3P2","T1D4P2", vlan_id = "10") #ping should be failed
    ret_val2 = traffic_test_ping("T1D3P2","T1D4P2", vlan_id = "20") #ping should be failed
    st.wait(1)

    #deconfig
    vapi.delete_vlan_member(vars.D3, "20", [vars.D3T1P2], tagging_mode=False)
    vapi.delete_vlan_member(vars.D4, "20", [vars.D4T1P2], tagging_mode=False)


    ################# trunk port #################
    #config
    vapi.add_vlan_member(vars.D3, "20", [vars.D3T1P2], tagging_mode=True)
    vapi.add_vlan_member(vars.D4, "20", [vars.D4T1P2], tagging_mode=True)

    #Ping test
    ret_val3 = traffic_test_ping("T1D3P2","T1D4P2", vlan_id = "20") #ping should be passed
    ret_val4 = traffic_test_ping("T1D3P2","T1D4P2", vlan_id = "10") #ping should be failed
    st.wait(1)

    #deconfig
    vapi.delete_vlan_member(vars.D3, "20", [vars.D3T1P2], tagging_mode=True)
    vapi.delete_vlan_member(vars.D4, "20", [vars.D4T1P2], tagging_mode=True)

    st.log("ret_val1 : "+ str(ret_val1) + "  ret_val2 : "+ str(ret_val2) + "ret_val3 : "+ str(ret_val3) + "  ret_val4 : "+ str(ret_val4))

    if(False == ret_val1 and False == ret_val2 and True == ret_val3 and False == ret_val4):
        st.report_pass('msg', "PASS: Testcase#2 Ping between VLAN 20 hosts passed after new trunk port and tagged packet ping")
    else:
        st.report_fail('msg', "FAIL: Testcase#2 Ping between VLAN 20 hosts failed after new trunk port and tagged packet ping")


#testcase 3,4,7 

def test_l2_vlan_create_and_del_new_vlan_and_vlan_member_acess_and_trunk(setup_teardown_l2_vlan_test):

    """
    testcase 3,4,7 - Adding new VLAN 30 bridge and verify the VLAN delete, New VLAN 20 member D3T1P2 as Access and Trunk added 
    where ping should be passed, also the new bridge addition and deletion doesnt have any effect on other VLAN ping
    expectation: Pings should be passed both in case of Access and Trunk interface with new bridge addition as well as deletion and 
    verify VLAN is deleted in the DB (using show vlan config)

    """

    # VLAN member add and delete for VLAN 20 (untagged)
    vapi.add_vlan_member(vars.D3, "20", [vars.D3T1P2], tagging_mode=False)
    vapi.add_vlan_member(vars.D4, "20", [vars.D4T1P2], tagging_mode=False)

    ret_val = traffic_test_ping("T1D3P2", "T1D4P2")
    st.wait(1)

    vapi.delete_vlan_member(vars.D3, "20", [vars.D3T1P2], tagging_mode=False)
    vapi.delete_vlan_member(vars.D4, "20", [vars.D4T1P2], tagging_mode=False)

    ###########Config##########

    # Create VLAN 30
    vapi.create_vlan(vars.D3, "30")
    vapi.create_vlan(vars.D4, "30")
    vapi.create_vlan(vars.D1, "30")

    # Add VLAN members to VLAN 30 (tagged)
    vapi.add_vlan_member(vars.D1, "30", [vars.D1D3P1, vars.D1D4P1], tagging_mode=True)
    vapi.add_vlan_member(vars.D3, "30", [vars.D3T1P2], tagging_mode=False)
    vapi.add_vlan_member(vars.D3, "30", [vars.D3D1P1], tagging_mode=True)
    vapi.add_vlan_member(vars.D4, "30", [vars.D4T1P2], tagging_mode=False)
    vapi.add_vlan_member(vars.D4, "30", [vars.D4D1P1], tagging_mode=True)

    ret_val1 = traffic_test_ping("T1D3P2", "T1D4P2")
    st.wait(1)

    ###########Deconfig##########

    # Remove VLAN members from VLAN 30
    vapi.delete_vlan_member(vars.D1, "30", [vars.D1D3P1, vars.D1D4P1], tagging_mode=True)
    vapi.delete_vlan_member(vars.D3, "30", [vars.D3T1P2], tagging_mode=False)
    vapi.delete_vlan_member(vars.D3, "30", [vars.D3D1P1], tagging_mode=True)
    vapi.delete_vlan_member(vars.D4, "30", [vars.D4T1P2], tagging_mode=False)
    vapi.delete_vlan_member(vars.D4, "30", [vars.D4D1P1], tagging_mode=True)

    st.log("****** ping test after vlan 30 delete ******")

    # Delete VLAN 30
    vapi.delete_vlan(vars.D3, "30")
    vapi.delete_vlan(vars.D4, "30")
    vapi.delete_vlan(vars.D1, "30")

    ret_val2 = traffic_test_ping("T1D3P2", "T1D4P2")
    st.wait(1)


    # Check VLAN config to see new VLAN got deleted
    cmd = "show vlan config"
    cmd_output = st.config(nodes['spine0'], cmd)
    parsed_output = st.parse_show(nodes['spine0'], cmd, cmd_output, 'show_vlan_config.tmpl')
    st.log("****** Show vlan config logging******")
    st.log(parsed_output)
    st.log("****** End Show vlan config logging******")
    
    #check for VLAN delete
    vid_to_check = "30"
    ret_val3 = any(entry['vid'] == str(vid_to_check) for entry in parsed_output)

    st.log("ret_val1 : {}  ret_val2 : {}  ret_val3 : {}".format(ret_val1, ret_val2, ret_val3))

    if True == ret_val1 and False == ret_val2 and  False == ret_val3:
        st.report_pass('msg', "PASS: Testcase#7 VLAN member and VLAN bridge add delete - Passed after new VLAN member add delete and VLAN add delete")
    else:
        st.report_fail('msg', "FAIL: Testcase#7 VLAN member and VLAN bridge add delete - Failed after new port, VLAN add delete")


#testcase 5,9

def test_l2_vlan_mac_learning_and_mac_aging(setup_teardown_l2_vlan_test):

    """

    #testcase 5,9 - verifying the MAC address of the interfaces connected to the switch are updated in the FDB as dynamic entries and 
    #after MAC AGING time this should be freed up 
    # expectation: After successeful ping the MAC address of hosts are updated on FDB (dynamically) of switch and after MAC AGING timer expiry these
    # MAC addresses got flushed out

    """

    ret_val = traffic_test_ping("T1D3P1", "T1D4P1")
    st.wait(1)
    if(True == ret_val):
        st.log("Ping between VLAN 10 hosts passed")
    else:
        st.log("Ping between VLAN 10 hosts failed")

    #L2 learning and MAC AGING test
    st.log("****** MAC Age testing and L2 learning ******")
    cmd = "show mac"
    cmd_output_mac = st.config(nodes['leaf0'],cmd)
    parsed_output = st.parse_show(nodes['leaf0'], cmd, cmd_output_mac, 'show_mac.tmpl')
    st.log("****** Show mac logging leaf0******")
    st.log(parsed_output)
    st.log("****** End Show mac logging******")

    cmd = "show mac"
    cmd_output_mac = st.config(nodes['leaf1'],cmd)
    parsed_output = st.parse_show(nodes['leaf1'], cmd, cmd_output_mac, 'show_mac.tmpl')
    st.log("****** Show mac logging leaf1******")
    st.log(parsed_output)
    st.log("****** End Show mac logging******")

    cmd = "show mac"
    cmd_output_mac = st.config(nodes['spine0'],cmd)
    parsed_output = st.parse_show(nodes['spine0'], cmd, cmd_output_mac, 'show_mac.tmpl')
    st.log("****** Show mac logging spine0******")
    st.log(parsed_output)
    st.log("****** End Show mac logging******")

    target_mac_address_d3 = str(data.hosts_data["T1D3P1"]["mac_addr"])
    target_mac_address_d4 = str(data.hosts_data["T1D4P1"]["mac_addr"])
    target_mac_address_found_d3, target_mac_address_found_d3 = False, False
    target_mac_address_found_d3 = mac_obj.verify_mac_address(vars.D1, str(data.vlan_list[0]), target_mac_address_d3)
    target_mac_address_found_d4 = mac_obj.verify_mac_address(vars.D1, str(data.vlan_list[0]), target_mac_address_d4)
    if target_mac_address_found_d3 and target_mac_address_found_d4:
        st.log("PASS: Testcase#5,9 The target MAC address d3:{} d4:{} is found in VLAN 10 in the cmd_output.".format(target_mac_address_d3, target_mac_address_d4))
    else:
        st.report_fail('msg', "FAIL: Testcase#5,9 The target MAC address is either not found or not in VLAN 10 in the cmd_output.")

    #MAC AGING to see if L2 entries are cleared

    mac_aging_time_orig = 600
    mac_aging_time_new = 120
    dut_list = [nodes['spine0'], nodes['leaf0'],nodes['leaf1']]
    for dut in dut_list:
        common_obj.update_mac_aging(dut, mac_aging_time_new, verify=True)

    #time_value = mac_obj.get_mac_agetime(vars.D1)#currently not supported can use this once this helper API is fixed

    st.log("Aging time for switch: "+ str(mac_aging_time_new)+ " seconds")
    time.sleep(mac_aging_time_new)
    st.log("Finished sleeping for "+str(mac_aging_time_new)+" seconds")

    cmd = "show mac"
    cmd_output_mac = st.config(nodes['spine0'],cmd)
    parsed_output = st.parse_show(nodes['spine0'], cmd, cmd_output_mac, 'show_mac.tmpl')
    st.log("****** Show mac logging spine0 after MAC AGING timer expiry ******")
    st.log(parsed_output)
    st.log("****** End Show mac logging******")
    target_mac_address_d3 = str(data.hosts_data["T1D3P1"]["mac_addr"])
    target_mac_address_d4 = str(data.hosts_data["T1D4P1"]["mac_addr"])
    target_mac_address_found_d3, target_mac_address_found_d3 = False, False
    target_mac_address_found_d3 = mac_obj.verify_mac_address(vars.D1, str(data.vlan_list[0]), target_mac_address_d3)
    target_mac_address_found_d4 = mac_obj.verify_mac_address(vars.D1, str(data.vlan_list[0]), target_mac_address_d4)

    for dut in dut_list:
        common_obj.update_mac_aging(dut, mac_aging_time_orig, verify=True)

    if target_mac_address_found_d3 or target_mac_address_found_d4:
        st.log("FAIL: MAC Address still found after MAC AGING Timer")
        st.report_fail('msg', "FAIL: Testcase#9 The target MAC address d3:{} d4:{} is found in VLAN 10 in the cmd_output after MAC AGING timer".format(target_mac_address_d3, target_mac_address_d4))
    else:
        st.log("PASS: MAC Address got flushed out after MAC AGING Timer")
        st.report_pass('msg', "PASS: Testcase#9 The target MAC address is either not found or not in VLAN 10 in the cmd_output after MAC AGING")


#testcase 6

def test_l2_vlan_untagged_ping_with_new_interface_add_delete(setup_teardown_l2_vlan_test):

    """
    #testcase 6 - New interface added on the same VLAN 10 
    #expectation: pings before and after adding new interface on the VLAN 10 should be successful on both the interfaces pasrt of VLAN 10

    """

    ret_val1 = traffic_test_ping("T1D3P1","T1D4P1")
    st.log("previous_ret_val1 : "+ str(ret_val1) )

    #access port
    #config
    vapi.add_vlan_member(vars.D3, "10", [vars.D3T1P2], tagging_mode=False)
    vapi.add_vlan_member(vars.D4, "10", [vars.D4T1P2], tagging_mode=False)

    ret_val2 = traffic_test_ping("T1D3P2","T1D4P2")
    st.wait(1)

    #deconfig
    vapi.delete_vlan_member(vars.D3, "10", [vars.D3T1P2], tagging_mode=False)
    vapi.delete_vlan_member(vars.D4, "10", [vars.D4T1P2], tagging_mode=False)


    ret_val1 = traffic_test_ping("T1D3P1","T1D4P1")
    
    st.log("ret_val1 : "+ str(ret_val1) + "  ret_val2 : "+ str(ret_val2))

    if(True == ret_val2 and True == ret_val1):
        st.report_pass('msg', "PASS: Testcase#6 Ping between VLAN 10 hosts passed after new access port addition and also ping is successful after access port deletion")
    else:
        st.report_fail('msg', "FAIL: Testcase#6 Ping between VLAN 10 hosts failed after new access port addition")

#testcase 7
def test_native_vlan(setup_teardown_l2_vlan_test):
    '''
    testcase 7 - Verify Native Vlan support.
    Verify BUM Traffic for Native Vlan.
    Verify unicast Traffic for Trunk Vlan.
    Verify Inter Vlan traffic should fail without any BVI.
    '''

    st.log('Add D3T1P2 and D4T1P2 as access port in Vlan 20')
    vapi.add_vlan_member(nodes['leaf0'], "20", [vars.D3T1P2], tagging_mode=False)
    vapi.add_vlan_member(nodes['leaf1'], "20", [vars.D4T1P2], tagging_mode=False)

    st.log('Update D1D3P1 & D3D1P1 as Native Vlan (Vlan 10) Ports on Trunk between Spine0 and Leaf0.')
    vapi.delete_vlan_member(nodes['spine0'], "10", [vars.D1D3P1], tagging_mode=True)
    vapi.delete_vlan_member(nodes['leaf0'], "10", [vars.D3D1P1], tagging_mode=True)
    vapi.add_vlan_member(nodes['spine0'], "10", [vars.D1D3P1], tagging_mode=False)
    vapi.add_vlan_member(nodes['leaf0'], "10", [vars.D3D1P1], tagging_mode=False)

    traffic_types = ['unicast', 'multicast', 'broadcast']

    st.log('Verify BUM traffic for Native VLAN')
    for traffic_type in traffic_types:
        handles = common_obj.traffic_test_config(data_vid_10, data_vid_10, 'T1D3P1', 'T1D4P1', traffic_type, True, is_l2=True)
        common_obj.traffic_start(handles, data_vid_10, data_vid_10)
        common_obj.traffic_stop(handles, mode='burst')
        if common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P1', data_vid_10, data_vid_10):
            st.log("Traffic verification for Native Vlan for traffic type {} Passed".format(traffic_type))
        else:
            st.report_fail('failed_traffic_verification', "for Native Vlan for traffic type {} ".format(traffic_type))
        common_obj.traffic_cleanup(handles)

    st.log('Verify Trunk Vlan Unicast traffic.')
    handles = common_obj.traffic_test_config(data_vid_20, data_vid_20, 'T1D3P2', 'T1D4P2', 'unicast', True, is_l2=True)
    common_obj.traffic_start(handles, data_vid_20, data_vid_20)
    common_obj.traffic_stop(handles, mode='burst')
    if common_obj.traffic_test_check(handles, 'T1D3P2', 'T1D4P2', data_vid_20, data_vid_20):
        st.log("Traffic verification for Trunk Vlan Passed")
    else:
        st.report_fail('failed_traffic_verification', "for Trunk Vlan")

    #Set the Dest Mac for inter vlan communication
    data_vid_10.t1d3_dest_mac_addr = data_vid_20.t1d4_mac_addr
    data_vid_20.t1d4_dest_mac_addr = data_vid_10.t1d3_mac_addr

    st.log('Verify Inter Vlan Traffic should fail.')
    handles = common_obj.traffic_test_config(data_vid_10, data_vid_20, 'T1D3P1', 'T1D4P2', 'unicast', True, is_l2=True, verify_ping=False)
    common_obj.traffic_start(handles, data_vid_10, data_vid_20)
    common_obj.traffic_stop(handles, mode='burst')
    if not common_obj.traffic_test_check(handles, 'T1D3P1', 'T1D4P2', data_vid_10, data_vid_20):
        st.log("Traffic verification for Inter Vlan traffic Passed")
    else:
        st.report_fail('failed_traffic_verification', "for Inter Vlan traffic")

    data_vid_10.t1d3_dest_mac_addr = data_vid_10.t1d4_mac_addr
    data_vid_20.t1d4_dest_mac_addr = data_vid_20.t1d3_mac_addr

    st.log('Cleanup')
    st.log('Configure D1D3P1 & D3D1P1 as trunk in Vlan 10')
    vapi.delete_vlan_member(nodes['spine0'], "10", [vars.D1D3P1], tagging_mode=False)
    vapi.delete_vlan_member(nodes['leaf0'], "10", [vars.D3D1P1], tagging_mode=False)
    vapi.add_vlan_member(nodes['spine0'], "10", [vars.D1D3P1], tagging_mode=True)
    vapi.add_vlan_member(nodes['leaf0'], "10", [vars.D3D1P1], tagging_mode=True)

    st.log('Remove D3T1P2 and D4T1P2 from Vlan 20')
    vapi.delete_vlan_member(nodes['leaf0'], "20", [vars.D3T1P2], tagging_mode=False)
    vapi.delete_vlan_member(nodes['leaf1'], "20", [vars.D4T1P2], tagging_mode=False)

    st.report_pass('msg', 'test_case 7 : Native Vlan Support passed')
