import os
import yaml
import pytest
import random
from spytest import st, SpyTestDict

import apis.switching.vlan as vlan_obj
import pvst_common_utils as pvst_obj
import apis.system.interface as intf_obj
import tortuga_common_utils as common_obj
import apis.system.port as port_obj
import apis.system.reboot as reboot_obj
import apis.system.basic as basic_obj
from spytest.utils import poll_wait

STP_SCALE_JSON_FILE = "stp_vlan_scale_cfg.json"
STP_SCALE_JSON_FILE_PATH = os.path.dirname(os.path.realpath(__file__)) +  '/' + STP_SCALE_JSON_FILE

@pytest.fixture(scope='function', autouse=True)
def bvi_func_hooks(request):
    data_glob.function_unconfig = False #This var allows cleanup of pre configs and remaining configs in case of TC failures
    yield
    function_unconfig()

def function_unconfig():
    if not data_glob.function_unconfig:
        data_glob.function_unconfig = True
        data_glob.pre_config = False
        st.log('Function config Cleanup')
        dut_list = [data_glob.spine0, data_glob.spine1, data_glob.leaf0, data_glob.leaf1]
        for dut in dut_list:
            for vlan in vlan_obj.get_vlan_list(dut):
                pvst_obj.config_spanning_tree(dut, mode='disable', vlan=vlan)
            vlan_obj.clear_vlan_configuration([dut])

#####################
#                   #
#    D1 = spine0    #
#    D2 = spine1    #
#    D3 = leaf0     #
#    D4 = leaf1     #
#    D5 = host0     #
#    D6 = host1     #
#    D7 = lhost0    #
#    D8 = lhost1    #
#                   #
#####################

@pytest.fixture(scope='module', autouse=True)
def setup_teardown_basic():
    global vars
    global updated_path
    global data_glob
    st.ensure_min_topology("D1D3:2", "D1D4:2", "D2D3:2", "D2D4:2", "D3D5:2", "D3D6:2", "D4D5:2", "D4D6:2", "D3T1:2", "D4T1:2")
    vars = st.get_testbed_vars()

    data_glob = SpyTestDict()
    data_glob.spine0 = vars.D1
    data_glob.spine1 = vars.D2
    data_glob.leaf0 = vars.D3
    data_glob.leaf1 = vars.D4
    data_glob.host0 = vars.D5
    data_glob.host1 = vars.D6
    data_glob.lhost0 = vars.D7
    data_glob.lhost1 = vars.D8
    data_glob.nodes = [vars.D1, vars.D2, vars.D3, vars.D4, vars.D5, vars.D6, vars.D7, vars.D8]
    data_glob.vlan = ['2','3']
    data_glob.default_forward_delay = 15
    data_glob.loop_intfs = ['Ethernet1_13', 'Ethernet1_14']
    data_glob.pre_config = False   #This var allows yaml pre configs
    CONFIGS_FILE = 'stp_transparent_switch_cfg.yaml'
    dir_path = os.path.dirname(os.path.realpath(__file__))
    updated_path = common_obj.modify_config_file(dir_path + '/' + CONFIGS_FILE,vars)

    yield 'setup_teardown_basic'
    common_obj.remove_temp_config(updated_path)

@pytest.fixture()
def setup_teardown_stp(setup_teardown_basic):
    if not data_glob.pre_config:
        with open(updated_path) as c:
            config_list = yaml.load(c, Loader=yaml.FullLoader)
            for node, config in config_list.items():
                for domain, configs in config.items():
                    if domain == 'linux' : 
                        common_obj.config_static(node, domain, True, updated_path, device_type = 'linux')
                    else : 
                        common_obj.config_static(node, domain, True, updated_path)
        

        #wait for STP to converge
        st.wait(2*data_glob.default_forward_delay)

        data_glob.pre_config = True

    yield 'setup_teardown_stp'

    if data_glob.function_unconfig:
        return
    with open(updated_path) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            for domain, configs in config.items():
                    if domain == 'linux' : 
                        common_obj.config_static(node, domain, False, updated_path, device_type = 'linux')
                    else : 
                        common_obj.config_static(node, domain, False, updated_path)

def test_single_leaf_loopback_short_circuit(setup_teardown_stp):

    st.banner("Create a Short Circuit in Vlan 2 and 3 on Leaf0")
    for intf in data_glob.loop_intfs:
        for vlan in data_glob.vlan:
            vlan_obj.add_vlan_member(data_glob.leaf0, vlan, intf, tagging_mode=True)
        intf_obj.interface_noshutdown(data_glob.leaf0, intf, skip_verify=False)

    st.log("Wait for BPDUs to be processed")
    st.wait(5)

    st.banner("STP on Leaf0")
    st.config(data_glob.leaf0, "show spanning-tree")

    st.banner("Verify STP blocks the Shorting")
    for vlan in data_glob.vlan:
        result = False
        for intf in data_glob.loop_intfs:
            expected_dict = {
                'vlan': vlan,'iface' : intf,
                'portstate' : 'BLOCKING'
            }
            result |= pvst_obj.verify_stp_vlan_iface(data_glob.leaf0, **expected_dict)
        if result:
            st.log("Link is blocked successfully for Vlan {}".format(vlan))
        else : 
            st.error("Short circuit is still present for Vlan {}".format(vlan))
            break

    st.banner("Cleanup")
    for intf in data_glob.loop_intfs:
        intf_obj.interface_shutdown(data_glob.leaf0, intf, skip_verify=False)
        for vlan in data_glob.vlan:
            vlan_obj.delete_vlan_member(data_glob.leaf0, vlan, intf, tagging_mode=True)
        
    
    if not result:
        st.report_fail('test_case_failed')
    else:
        data_glob.function_unconfig = True
        st.report_pass('test_case_passed')

def test_single_leaf_loopback_via_bpdu_transparent_device(setup_teardown_stp):

    st.banner("Add D4D7P1 and D4D7P2 to Vlan 2 and 3 on Leaf1")
    for vlan in data_glob.vlan:
        for intf in [vars.D4D7P1, vars.D4D7P2]:
            vlan_obj.add_vlan_member(data_glob.leaf1, vlan, intf, tagging_mode=True)
    
    st.log("Wait for BPDUs to be processed")
    st.wait(10)

    st.banner("STP on Leaf1")
    st.config(data_glob.leaf1, "show spanning-tree")

    st.banner("Verify STP blocks the Single Leaf Loopback after receiving the same BPDU")
    for vlan in data_glob.vlan:
        result = False
        for intf in [vars.D4D7P1, vars.D4D7P2]:
            expected_dict = {
                'vlan': vlan,'iface' : intf,
                'portstate' : 'BLOCKING'
            }
            result |= pvst_obj.verify_stp_vlan_iface(data_glob.leaf1, **expected_dict)
        if result:
            st.log("Link is blocked successfully for Vlan {}".format(vlan))
        else : 
            st.error("Failed to Block loopback via BPDU Transparent Device for Vlan {}".format(vlan))
            break

    st.banner("Cleanup")
    for vlan in data_glob.vlan:
        for intf in [vars.D4D7P1, vars.D4D7P2]:
            vlan_obj.delete_vlan_member(data_glob.leaf1, vlan, intf, tagging_mode=True)

    if not result:
        st.report_fail('test_case_failed')
    else:
        data_glob.function_unconfig = True
        st.report_pass('test_case_passed')

def test_dual_leaf_loopback_via_bpdu_transparent_device(setup_teardown_stp):

    st.banner("Add D3D7P1 on Leaf0 and D4D7P1 on Leaf1 to Vlan 2 and 3 ")
    for vlan in data_glob.vlan:
        vlan_obj.add_vlan_member(data_glob.leaf0, vlan, vars.D3D7P1, tagging_mode=True)
        vlan_obj.add_vlan_member(data_glob.leaf1, vlan, vars.D4D7P1, tagging_mode=True)
    
    st.log("Wait for BPDUs to be processed")
    st.wait(10)

    st.banner("STP on Leaf0")
    st.config(data_glob.leaf0, "show spanning-tree")

    st.banner("STP on Leaf1")
    st.config(data_glob.leaf1, "show spanning-tree")

    st.banner("Verify STP blocks the Dual Leaf Loopback after receiving the same BPDU")
    for vlan in data_glob.vlan:
        result = False
        expected_dict = {
            'vlan': vlan,'iface' : vars.D3D7P1,
            'portstate' : 'BLOCKING'
        }
        result |= pvst_obj.verify_stp_vlan_iface(data_glob.leaf0, **expected_dict)
        expected_dict['iface'] = vars.D4D7P1
        result |= pvst_obj.verify_stp_vlan_iface(data_glob.leaf1, **expected_dict)
        if result:
            st.log("Link is blocked successfully for Vlan {} for dual leaf loopback".format(vlan))
        else : 
            st.error("Failed to Block loopback via couple of BPDU Transparent Device for Vlan {}".format(vlan))
            break

    st.banner("Cleanup")
    for vlan in data_glob.vlan:
        vlan_obj.delete_vlan_member(data_glob.leaf0, vlan, vars.D3D7P1, tagging_mode=True)
        vlan_obj.delete_vlan_member(data_glob.leaf1, vlan, vars.D4D7P1, tagging_mode=True)

    if not result:
        st.report_fail('test_case_failed')
    else:
        data_glob.function_unconfig = True
        st.report_pass('test_case_passed')

def test_active_active_multihoming_with_external_link(setup_teardown_stp):

    st.banner("Add external link between leaf0 and host0 in Vlan 2 and 3")
    for vlan in data_glob.vlan:
        vlan_obj.add_vlan_member(data_glob.leaf0, vlan, vars.D3D5P2, tagging_mode=True)
        vlan_obj.add_vlan_member(data_glob.host0, vlan, vars.D5D3P2, tagging_mode=True)

    st.log("Wait for BPDUs to be processed")
    st.wait(5)

    st.banner("STP on Leaf0")
    st.config(data_glob.leaf0, "show spanning-tree")

    st.banner("STP on Host0")
    st.config(data_glob.host0, "show spanning-tree")

    st.banner("Verify STP blocks the external link while MLAG remains in Forwarding")
    for vlan in data_glob.vlan:
        result = False
        expected_dict = {
            'vlan': vlan,'iface' : vars.D5D3P2,
            'portstate' : 'BLOCKING'
        }
        result |= pvst_obj.verify_stp_vlan_iface(data_glob.host0, **expected_dict)
        expected_dict['iface'] = 'PortChannel01'
        expected_dict['portstate'] = 'FORWARDING'
        result |= pvst_obj.verify_stp_vlan_iface(data_glob.host0, **expected_dict)
        if result:
            st.log("External Link is blocked successfully for Vlan {}".format(vlan))
        else : 
            st.error("Failed to Block external link for Vlan {}".format(vlan))
            break

    st.banner("Cleanup")
    for vlan in data_glob.vlan:
        vlan_obj.delete_vlan_member(data_glob.leaf0, vlan, vars.D3D5P2, tagging_mode=True)
        vlan_obj.delete_vlan_member(data_glob.host0, vlan, vars.D5D3P2, tagging_mode=True)
    
    if not result:
        st.report_fail('test_case_failed')
    else:
        data_glob.function_unconfig = True
        st.report_pass('test_case_passed')

def test_dual_active_active_multihoming_with_downstream_stp(setup_teardown_stp):

    st.banner("Add link between host0 and host1 in Vlan 2 and 3")
    for vlan in data_glob.vlan:
        vlan_obj.add_vlan_member(data_glob.host0, vlan, vars.D5D6P1, tagging_mode=True)
        vlan_obj.add_vlan_member(data_glob.host1, vlan, vars.D6D5P1, tagging_mode=True)

    st.log("Wait for BPDUs to be processed")
    st.wait(5)

    st.banner("STP on Host0")
    st.config(data_glob.host0, "show spanning-tree")

    st.banner("STP on Host1")
    st.config(data_glob.host1, "show spanning-tree")

    st.banner("Verify STP blocks the connected link between Hosts")
    for vlan in data_glob.vlan:
        result = False
        expected_dict = {
            'vlan': vlan,'iface' : vars.D5D6P1,
            'portstate' : 'BLOCKING'
        }
        result_host0 = pvst_obj.verify_stp_vlan_iface(data_glob.host0, **expected_dict)
        expected_dict['iface'] = vars.D6D5P1
        result_host1 = pvst_obj.verify_stp_vlan_iface(data_glob.host1, **expected_dict)
        result = result_host0 ^ result_host1
        if result:
            st.log("Downstream connected link is blocked successfully for Vlan {}".format(vlan))
        else : 
            st.error("Failed to Host connected link for Vlan {}".format(vlan))
            break

    st.banner("Cleanup")
    for vlan in data_glob.vlan:
        vlan_obj.delete_vlan_member(data_glob.host0, vlan, vars.D5D6P1, tagging_mode=True)
        vlan_obj.delete_vlan_member(data_glob.host1, vlan, vars.D6D5P1, tagging_mode=True)
    
    if not result:
        st.report_fail('test_case_failed')
    else:
        data_glob.function_unconfig = True
        st.report_pass('test_case_passed')


def test_dpb_with_STP(setup_teardown_stp):

    result = True 
    st.banner("Configure DPB on non STP member links")
    breakout_mapping = {
        vars.D3D5P2 : '4x100G',
        vars.D3D6P2 : '4x100G'
    }
    if common_obj.configure_dynamic_breakout(data_glob.leaf0, breakout_mapping):
        st.log("Successfully configured DPB with STP configured on Node.")
    else:
        result=False
        st.error("Failed to configure DPB with STP configured on Node.")

    if not result:
        st.report_fail('test_case_failed')

    new_intfs = [vars.D3D5P2 + '_' + str(index) for index in range(1,5)]
    st.banner("Enable STP on breakout links")
    for vlan in data_glob.vlan:
        for new_intf in new_intfs:
            vlan_obj.add_vlan_member(data_glob.leaf0, vlan, new_intf, tagging_mode=True)

    #wait for STP to converge
    st.wait(2*data_glob.default_forward_delay)

    st.banner("Verify STP status for the new intfs")
    for vlan in data_glob.vlan:
        for new_intf in new_intfs:
            result = False
            expected_dict = {
                'vlan': vlan, 'iface' : new_intf,
                'portstate' : 'FORWARDING'
            }
            result |= pvst_obj.verify_stp_vlan_iface(data_glob.leaf0, **expected_dict)
            if result : 
                st.log("Verified STP Status for new intf {} successfully for Vlan {}".format(new_intf, vlan))
            else:
                st.error("Fail to verify STP Status for new intf {} successfully for Vlan {}".format(new_intf, vlan))
                break

    st.banner("Remove Breakout links from Vlans")
    for vlan in data_glob.vlan:
        for new_intf in new_intfs:
            vlan_obj.delete_vlan_member(data_glob.leaf0, vlan, new_intf, tagging_mode=True)

    st.banner("Undo the dynamic breakout")
    breakout_mapping = {
        vars.D3D5P2 : '1x400G',
        vars.D3D6P2 : '1x400G'
    }

    if common_obj.configure_dynamic_breakout(data_glob.leaf0, breakout_mapping, undo = True):
        st.log("Undo DPB successful.")
    else:
        result=False
        st.error("Undo DPB failed.")

    if not result:
        st.report_fail('test_case_failed')

    st.banner("Enable STP on these interfaces")
    for vlan in data_glob.vlan:
        for intf in [vars.D3D5P2, vars.D3D6P2]:
            vlan_obj.add_vlan_member(data_glob.leaf0, vlan, intf, tagging_mode=True)

    #wait for STP to converge
    st.wait(2*data_glob.default_forward_delay)

    for vlan in data_glob.vlan:
        for intf in [vars.D3D5P2, vars.D3D6P2]:
            result = False
            expected_dict = {
                'vlan': vlan, 'iface' : intf,
                'portstate' : 'FORWARDING'
            }
            result |= pvst_obj.verify_stp_vlan_iface(data_glob.leaf0, **expected_dict)
            if result : 
                st.log("Verified STP Status for intf {} successfully for Vlan {}".format(intf, vlan))
            else:
                st.error("Fail to verify STP Status for intf {} successfully for Vlan {}".format(intf, vlan))
                break

    st.banner("Cleanup")
    for vlan in data_glob.vlan:
        for intf in [vars.D3D5P2, vars.D3D6P2]:
            vlan_obj.delete_vlan_member(data_glob.leaf0, vlan, intf, tagging_mode=True)

    if not result:
        st.report_fail('test_case_failed')
    else:
        st.report_pass('test_case_passed')

def test_dpb_scale():

    result = True

    st.banner("Get interface list on leaf1")
    intf_list = port_obj.get_interfaces_all(data_glob.leaf1)

    breakout_mapping = {intf: "4x100G" for intf in intf_list}
    
    st.banner("Configure DPB on all intfs")
    if common_obj.configure_dynamic_breakout(data_glob.leaf1, breakout_mapping):
        st.log("Successfully configured DPB on all intfs.")
    else:
        result=False
        st.error("Failed to configure DPB on all intfs.")

    if not result:
        st.report_fail('test_case_failed')

    st.log("Create Vlan2 on leaf1")
    if vlan_obj.create_vlan(data_glob.leaf1, [data_glob.vlan[0]]):
        st.log("Successfully created Vlan2 on leaf1")
    else:
        st.report_fail("msg", "Failed to create Vlan2 on leaf1")

    st.log("Enable STP on Vlan2")
    if pvst_obj.config_spanning_tree(data_glob.leaf1, mode='enable', vlan=data_glob.vlan[0]):
        st.log("Enabled STP on Vlan {} successfully on {}".format(data_glob.vlan[0], data_glob.leaf1))
    else:
        st.report_fail("msg","Failed to enable STP on Vlan {} on {}".format(data_glob.vlan[0], data_glob.leaf1))

    new_intfs = []
    for intf in intf_list:
        new_intfs += [intf + '_' + str(index) for index in range(1,5)]

    st.banner("Enable STP on breakout links")
    for new_intf in new_intfs:
        vlan_obj.add_vlan_member(data_glob.leaf1, data_glob.vlan[0], new_intf, tagging_mode=True)

    #wait for STP to converge
    st.wait(2*data_glob.default_forward_delay)

    for new_intf in new_intfs:
        result = False
        expected_dict = {
            'vlan': data_glob.vlan[0], 'iface' : new_intf,
            'portstate' : 'FORWARDING'
        }
        result |= pvst_obj.verify_stp_vlan_iface(data_glob.leaf1, **expected_dict)
        if result : 
            st.log("Verified STP Status for intf {} successfully for Vlan {}".format(new_intf, data_glob.vlan[0]))
        else:
            st.error("Fail to verify STP Status for intf {} successfully for Vlan {}".format(new_intf, data_glob.vlan[0]))
            break    

    st.banner("Remove Breakout links from Vlans")
    for new_intf in new_intfs:
        vlan_obj.delete_vlan_member(data_glob.leaf1, data_glob.vlan[0], new_intf, tagging_mode=True)

    st.banner("Cleanup")

    st.log("Disable STP on Vlan2")
    pvst_obj.config_spanning_tree(data_glob.leaf1, mode='disable', vlan=data_glob.vlan[0])

    st.log("Delete Vlan2 on leaf1")
    vlan_obj.delete_vlan(data_glob.leaf1, [data_glob.vlan[0]])

    breakout_mapping = {intf: "1x400G" for intf in intf_list}
    
    st.log("Undo DPB on all intfs")
    if common_obj.configure_dynamic_breakout(data_glob.leaf1, breakout_mapping, undo = True):
        st.log("Successfully Undo DPB on all intfs.")
    else:
        result=False
        st.error("Failed to Undo DPB on all intfs.")

    if not result:
        st.report_fail('test_case_failed')
    else:
        st.report_pass('test_case_passed')

def test_stp_scale():

    st.banner("Config STP Scale Config")
    with open(STP_SCALE_JSON_FILE_PATH) as file:
        stp_cfg_data_string = file.read()

    member_links = [vars.D4D5P1, vars.D4D5P2, vars.D4D6P1, vars.D4D6P2, vars.D4D7P1, vars.D4D7P2]

    stp_cfg_data_string = set_member_links_in_json(stp_cfg_data_string, member_links)

    with open(STP_SCALE_JSON_FILE_PATH, "w") as file:
        file.write(stp_cfg_data_string)

    common_obj.apply_json_config(data_glob.leaf1, STP_SCALE_JSON_FILE, STP_SCALE_JSON_FILE_PATH)

    for vlan in random.sample(range(2, 1002), 10):
        for intf in member_links:
            result = False
            expected_dict = {
                'vlan': vlan, 'iface' : intf,
                'portstate' : 'FORWARDING'
            }
            if not poll_wait(pvst_obj.verify_stp_vlan_iface, 300, data_glob.leaf1, **expected_dict):
                st.error("Fail to verify STP Status for intf {} successfully for Vlan {}".format(intf, vlan))
                break
            else : 
                result = True
                st.log("Verified STP Status for intf {} successfully for Vlan {}".format(intf, vlan)) 
        if not result:
            break
    
    count = basic_obj.get_and_match_docker_count(data_glob.leaf1)
    status = reboot_obj.config_reload(data_glob.leaf1)
    #check docker status
    if not poll_wait(basic_obj.verify_docker_status, 180, data_glob.leaf1, 'Exited'):
        st.error("Post 'config reload', dockers are not auto recovered.")
        result = False
    if result:
        if not poll_wait(basic_obj.get_and_match_docker_count, 180, data_glob.leaf1, count):
            st.error("Post 'config reload', ALL dockers are not UP.")
            result = False

    if not result:
        st.report_fail('test_case_failed')
    else:
        st.report_pass('test_case_passed')

def set_member_links_in_json(stp_cfg_data_string, member_links):
    replacement_dict = {"Member_link_"+str(i+1):member_links[i] for i in range(6)}
    for link,member_link in replacement_dict.items():
        stp_cfg_data_string = stp_cfg_data_string.replace(link, member_link)
    return stp_cfg_data_string

