import os
import pdb
import yaml
import pytest
import re
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
    
    # Detect platform to select appropriate config file
    platform_output = st.show(vars.D4, "show platform summary")
    hwsku = platform_output[0].get('hwsku', '') or platform_output[0].get('HwSKU', '')
    st.log("Detected HwSKU: {}".format(hwsku))
    
    if '8102' in hwsku:
        CONFIGS_FILE = 'stp_transparent_switch_cfg_8102.yaml'
        st.log("Using config file: {}".format(CONFIGS_FILE))
    else:
        CONFIGS_FILE = 'stp_transparent_switch_cfg.yaml'
        st.log("Using default config file: {}".format(CONFIGS_FILE))
    
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

def get_loopback_interfaces_dynamic(device):
        
        st.log("Getting loopback interfaces for device: {}".format(device))
        
        all_links = st.get_dut_links(device)        
        loopback_intfs = []
        
        if isinstance(all_links, list):
            for idx, link in enumerate(all_links):
                if not isinstance(link, (list, tuple)) or len(link) < 3:
                    continue               
                local_port = link[0]
                remote_device = link[1]
                remote_port = link[2]
                                
                if remote_device == device:
                    loopback_intfs.append(local_port)
                    loopback_intfs.append(remote_port)
                    
        if isinstance(all_links, list) and len(all_links) >= 4:
            for i in range(0, len(all_links), 4):
                if i + 3 < len(all_links):
                    dev1 = all_links[i]
                    port1 = all_links[i + 1]
                    dev2 = all_links[i + 2]
                    port2 = all_links[i + 3]
                                        
                    if dev1 == device and dev2 == device:
                        loopback_intfs.append(port1)
                        loopback_intfs.append(port2)
                        st.log("Found loopback link: {} <-> {}".format(port1, port2))
        
        loopback_intfs = list(dict.fromkeys(loopback_intfs))
        
        st.log("Loopback interfaces obtained dynamically: {}".format(loopback_intfs))
        return loopback_intfs


def test_single_leaf_loopback_short_circuit(setup_teardown_stp):

    st.banner("Create a Short Circuit in Vlan 2 and 3 on Leaf0")

    intf_dict = get_loopback_interfaces_dynamic(data_glob.leaf0)
    for intf in intf_dict:
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
        for intf in intf_dict:
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
    for intf in intf_dict:
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
    st.wait(30)

    st.banner("Save original STP costs before modification")

    st.log("Setting Ethernet1_2 cost to 200 on host0")
    st.config(data_glob.host0, "sudo config spanning-tree interface cost {} 200".format(vars.D5D3P2))
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
    intf_data = st.show(data_glob.leaf0, "show interfaces status")

    breakout_mapping = {}

    for entry in intf_data:
        intf = entry.get("interface")
        speed = entry.get("speed", "")

        if intf in [vars.D3D5P2, vars.D3D6P2]:
            if "400G" in speed:
                breakout_mapping[intf] = "4x100G"
            elif "100G" in speed:
                breakout_mapping[intf] = "4x25G"
            elif "800G" in speed:
                breakout_mapping[intf] = "4x200G"
            else:
                st.error("Unsupported speed {} on {}".format(speed, intf))

    st.log("Dynamic breakout mapping: {}".format(breakout_mapping))

    if common_obj.configure_dynamic_breakout(data_glob.leaf0, breakout_mapping):
        st.log("Successfully configured DPB with STP configured on Node.")
    else:
        result=False
        st.error("Failed to configure DPB with STP configured on Node.")

    if not result:
        st.report_fail('test_case_failed')

    new_intfs = []
    for intf in breakout_mapping.keys():
        if intf == vars.D3D5P2:
            st.log(intf)
            if '_' in intf:
                base = intf
                new_intfs.extend(["{}_{}".format(base, idx) for idx in range(1,5)])
            else:
                base_num = int(re.findall(r'\d+', intf)[0])
                new_intfs.extend(["Ethernet{}".format(base_num + idx) for idx in range(4)])
                
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
    for entry in intf_data:
        intf = entry.get("interface")
        speed = entry.get("speed", "")
        
        if intf in [vars.D3D5P2, vars.D3D6P2]:
            if "400G" in speed:
                breakout_mapping[intf] = "1x400G"
            elif "100G" in speed:
                breakout_mapping[intf] = "1x100G"
            elif "800G" in speed:
                breakout_mapping[intf] = "1x800G"
            else:
                st.error("Unsupported speed {} on {}".format(speed, intf))

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

    # Runtime platform check 
    platform_output = st.show(data_glob.leaf1, "show platform summary")
    hwsku = platform_output[0].get('hwsku', '') or platform_output[0].get('HwSKU', '')
    st.log("Detected HwSKU: {}".format(hwsku))
    if 'HF6100-32D' not in hwsku:
        st.log("Test is only applicable for HF6100-32D platform. Current: {}".format(hwsku))
        st.report_pass('test_case_passed')
    result = True

    st.banner("Get interface list on leaf1")
    all_ports = intf_obj.get_all_ports_speed_dict(data_glob.leaf1)
    for key in all_ports:
        intf_list = all_ports[key]
        break

    breakout_mapping = {}
    port_count = 0
    max_ports_to_break = 5
    
    for speed_key, intf_list in all_ports.items():
        for intf in intf_list:
            if port_count >= max_ports_to_break:
                break
            if '400' in str(speed_key):
                breakout_mapping[intf] = "4x100G"
                port_count += 1
            elif '100' in str(speed_key):
                breakout_mapping[intf] = "4x25G"
                port_count += 1
            elif '800' in str(speed_key):
                breakout_mapping[intf] = "4x200G"
                port_count += 1
            else:
                continue
        if port_count >= max_ports_to_break:
            break
    st.banner("Ports being broken down")
    print("DEBUG: breakout_mapping = {}".format(breakout_mapping))

    st.log("Breaking out {} ports. Dynamic breakout mapping: {}".format(port_count, breakout_mapping))
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
    for intf in breakout_mapping.keys():
            if '_' in intf:
                base = intf
                new_intfs.extend(["{}_{}".format(base, idx) for idx in range(1,5)])
            else:
                base_num = int(re.findall(r'\d+', intf)[0])
                new_intfs.extend(["Ethernet{}".format(base_num + idx) for idx in range(4)])

    st.log("New interfaces created: {}".format(new_intfs))
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

    breakout_mapping = {}
    for speed_key, intf_list in all_ports.items():
        for intf in intf_list:
            if '400' in str(speed_key):
                breakout_mapping[intf] = "1x400G"
            elif '100' in str(speed_key):
                breakout_mapping[intf] = "1x100G"
            elif '800' in str(speed_key):
                breakout_mapping[intf] = "1x800G"

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