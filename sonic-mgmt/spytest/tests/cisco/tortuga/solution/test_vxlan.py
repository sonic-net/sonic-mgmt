import os
import yaml
import pytest
from spytest import st, tgapi
import apis.routing.ip as ip_obj
import apis.routing.vrf as vrf_obj
import apis.switching.vlan as vlan_obj
import apis.switching.mac as mac_obj
from spytest.tgen.tg import tgen_obj_dict
import vxlan_helper as vxlan_obj
import ipaddress
import apis.system.interface as interface_obj
import apis.system.basic as basic_obj
import apis.system.reboot as reboot_obj
from spytest.utils import poll_wait

def initialize_variables():
    global vars, nodes, handles
    vars = st.get_testbed_vars()
    nodes = st.get_dut_names()

@pytest.fixture(scope="module", autouse=True)
def choose_config_file():
    global CONFIGS_FILE
    if st.getenv("topo") == "4s4l":
        exp_no_nodes = 8
        CONFIGS_FILE = 'vxlan_4S4L_config_input_file.yaml'
        if len(st.get_dut_names()) != 8:
            st.report_fail('topology_not_matching', "Topology not matching, required {} dut, having {} duts".format(exp_no_nodes,len(st.get_dut_names())))
    elif st.getenv("topo") == "2l":
        exp_no_nodes = 2
        CONFIGS_FILE = "vxlan_2L_config_input_file.yaml"
        if len(st.get_dut_names()) != 2:
            st.report_fail('topology_not_matching', "Topology not matching, required {} dut, having {} duts".format(exp_no_nodes,len(st.get_dut_names())))
    elif st.getenv("topo") == "2s2l":
        exp_no_nodes = 2
        CONFIGS_FILE = "vxlan_2S2L_config_input_file.yaml"
        if len(st.get_dut_names()) != 4:
            st.report_fail('topology_not_matching', "Topology not matching, required {} dut, having {} duts".format(exp_no_nodes,len(st.get_dut_names())))
    else:
        st.report_fail('no_data_found')

@pytest.fixture(scope="module", autouse=True)
def copy_default_config_db():
    initialize_variables()
    cmd = "sudo cp /etc/sonic/config_db.json config_db.json.orig"
    for dut in st.get_dut_names():
        st.config(dut, cmd, skip_error_check=True)

@pytest.fixture(scope="module", autouse=True)
def vxlan_config_hooks(configure_underlay, configure_overlay, configure_l2l3vni):
    global handles
    handles = tgen_preconfig()
        
###VxLAN Configs###
@pytest.fixture(scope="module")
def configure_l2l3vni(request):
    initialize_variables()
    leaf_nodes=[]
    spine_nodes=[]
    for dut in st.get_dut_names():
        if "leaf" in dut:
            leaf_nodes.append(dut)
        else:
            spine_nodes.append(dut)
    vxlan_obj.config_feature(leaf_nodes,'nvo')
    vxlan_obj.config_feature(leaf_nodes,'enable_tunnel_counters')
    vxlan_obj.config_feature(leaf_nodes,'l2vni')
    vxlan_obj.config_feature(leaf_nodes,'l3vni')
    vxlan_obj.config_feature(leaf_nodes,'add_sag_mac')
    vxlan_obj.config_feature(leaf_nodes,'sag_v4')
    vxlan_obj.config_feature(leaf_nodes,'sag_v6')
    vxlan_obj.config_feature(leaf_nodes,'bgp_l3vni_config')
    st.wait(60)
    yield
    vxlan_obj.config_feature(leaf_nodes,'delete_sag_v6')
    vxlan_obj.config_feature(leaf_nodes,'delete_sag_v4')
    vxlan_obj.config_feature(leaf_nodes,'del_sag_mac')
    vxlan_obj.config_feature(leaf_nodes,'delete_bgp_l3vni_config')
    vxlan_obj.config_feature(leaf_nodes,'delete_l3vni')
    vxlan_obj.config_feature(leaf_nodes,'delete_l2vni')
    vxlan_obj.config_feature(st.get_dut_names(),'delete_bgp_config')
    vxlan_obj.config_feature(leaf_nodes,'disable_tunnel_counters')
    vxlan_obj.config_feature(leaf_nodes,'delete_vxlan')
    router_preconfig_cleanup()
    # config save
    for dut in st.get_dut_names(): 
        vxlan_obj.config_dut(dut, 'sonic', "sudo config save -y")
    
@pytest.fixture(scope="module")
def configure_underlay(request): 
    initialize_variables()
    vxlan_obj.config_feature(nodes,'loopback')
    vxlan_obj.config_feature(nodes,'unnumbered')
    vxlan_obj.config_feature(nodes,'bgp_underlay')
    yield
    vxlan_obj.config_feature(nodes,'delete_loopback')

@pytest.fixture(scope="module")
def configure_overlay(request): 
    leaf_nodes=[]
    for dut in st.get_dut_names():
        if "leaf" in dut:
            leaf_nodes.append(dut)
    vxlan_obj.config_feature(leaf_nodes,'bgp_overlay')

def router_preconfig_cleanup():
    vrf_obj.clear_vrf_configuration(st.get_dut_names())
    ip_obj.clear_ip_configuration(st.get_dut_names(), family='all', thread=True, skip_error_check = True)
    vlan_obj.clear_vlan_configuration(st.get_dut_names())

def report_fail(dut, msg=''):
    st.log(msg, dut)
    st.error(msg, dut)
    st.report_fail('test_case_failed', dut)

def tgen_preconfig(**kwargs):
    initialize_variables()
    leaf_nodes=[]
    svi_dict_v4 = {}
    svi_dict_v6 ={}
    for dut in st.get_dut_names():
        if "leaf" in dut and dut != 'leaf3':
            leaf_nodes.append(dut)
    l2vni_intf_dict = vxlan_obj.get_interfaces(vars, leaf_nodes,'l2vni')
    ###Get topology Handles###
    topo_handles = vxlan_obj.create_topology_handles(l2vni_intf_dict)

    dir_path = os.path.dirname(os.path.realpath(__file__))
    with open(dir_path + '/' + CONFIGS_FILE) as f:
        config_dict = yaml.load(f, Loader=yaml.FullLoader)
        for node, config in config_dict.items():
            if 'leaf' in node:
                if kwargs.get('custom_svi_ip'):
                    svi_dict_v4[node] = vxlan_obj.generate_svi_ip_sag(config,'ipv4', ip_start = "10.2.0.1")
                    svi_dict_v6[node] = vxlan_obj.generate_svi_ip_sag(config,'ipv6', ip_start = "1000:2::1")
                else:
                    svi_dict_v4[node] = vxlan_obj.generate_svi_ip_sag(config,'ipv4')
                    svi_dict_v6[node] = vxlan_obj.generate_svi_ip_sag(config,'ipv6')
    v4_host_info_dict = vxlan_obj.generate_sag_hosts(l2vni_intf_dict,svi_dict_v4)
    v6_host_info_dict = vxlan_obj.generate_sag_hosts(l2vni_intf_dict,svi_dict_v6,version="ipv6")
    
    tg_handle = topo_handles[leaf_nodes[0]][l2vni_intf_dict[leaf_nodes[0]][0]]['tg_handle']
    ###CREATE DEVICE GROUPS###
    #ipv4
    out_v4 = vxlan_obj.create_device_groups(topo_handles,v4_host_info_dict)
    v4_node_device_handles = out_v4[0]
    #ipv6
    out_v6 = vxlan_obj.create_device_groups(topo_handles,v6_host_info_dict,version ="ipv6")
    v6_node_device_handles = out_v6[0]
    v4_device_handles = {}
    v6_device_handles = {}
    for node, interfaces in v4_node_device_handles.items():
        for interface,values in interfaces.items():
            v4_device_handles[interface] =values
    for node, interfaces in v6_node_device_handles.items():
        for interface,values in interfaces.items():
            v6_device_handles[interface] =values
    ### start all protocols ###
    start_protocol = vxlan_obj.start_stop_protocols(tg_handle,action='start')
    if start_protocol == 1:
        st.log("protocols started successfully")
    else:
        st.report_tgen_fail('start protocols failed!')
    st.wait(5)
    ### choose traffic item endpoints###
    l2_traffic_endpoints = vxlan_obj.find_l2_traffic_endpoints(v4_host_info_dict)
    l3_traffic_endpoints = vxlan_obj.find_l3_traffic_endpoints(v4_host_info_dict)
    ### create traffic item endpoints###
    stream_handles = {}
    stream_handles['l2_v4'] = vxlan_obj.create_traffic_item(device_handles = v4_device_handles,endpoints=l2_traffic_endpoints,topo_handles=topo_handles)
    stream_handles['l3_v4'] = vxlan_obj.create_traffic_item(device_handles = v4_device_handles,endpoints=l3_traffic_endpoints,topo_handles=topo_handles)
    stream_handles['l2_v6'] = vxlan_obj.create_traffic_item(device_handles = v6_device_handles,endpoints=l2_traffic_endpoints,topo_handles=topo_handles,version = "ipv6")
    stream_handles['l3_v6'] = vxlan_obj.create_traffic_item(device_handles = v6_device_handles,endpoints=l3_traffic_endpoints,topo_handles=topo_handles,version = "ipv6")
    #BUM
    bum_info ={}
    bum_info['tg_handle'] = topo_handles[leaf_nodes[0]][l2vni_intf_dict[leaf_nodes[0]][0]]['tg_handle']
    bum_info['topology_handle'] = topo_handles[leaf_nodes[0]][l2vni_intf_dict[leaf_nodes[0]][0]]['topology_handle']
    bum_info['port_handle'] = topo_handles[leaf_nodes[0]][l2vni_intf_dict[leaf_nodes[0]][0]]['port_handle']
    bum_info['dst_port_handles'] = []
    for node, interfaces in topo_handles.items():
        for interface, values in interfaces.items():
            if values['port_handle'] != bum_info['port_handle']:
                bum_info['dst_port_handles'].append(values['port_handle'])
    svi_info = v4_host_info_dict[leaf_nodes[0]][l2vni_intf_dict[leaf_nodes[0]][0]]
    stream_handles['bum'] = vxlan_obj.generate_bum_handles(bum_info,svi_info)
    stream_handles["topo_handles"] = topo_handles

    return stream_handles

@pytest.fixture(scope = "function", autouse=True)
def pretest():
    global vtep_state
    initialize_variables()
    leaf_nodes=[]
    for dut in st.get_dut_names():
        if "leaf" in dut:
            leaf_nodes.append(dut)
    vtep_state = vxlan_obj.verify_vtep(leaf_nodes)
    if not vtep_state:
        vxlan_obj.get_cli_out(leaf_nodes)
        cmds = ["do show bgp summary, do show run"]
        for dut in st.get_dut_names():
            for cmd in cmds:
                st.config(dut, cmd, type='vtysh', skip_error_check=True)
        pytest.skip("Skipping tests due to vtep state not up")

class TestVxlanBasic():
    
    def test_vtep_state(self):
        st.banner("TEST 1: Verify the expected remote vtep in all leafs  ")
        initialize_variables()
        leaf_nodes=[]
        spine_nodes=[]
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        #check bgp on all nodes
        cmds = ["do show bgp summary, do show run"]
        for dut in st.get_dut_names():
            for cmd in cmds:
                st.config(dut, cmd, type='vtysh', skip_error_check=True)
        vxlan_obj.get_cli_out(leaf_nodes)
        vtep_state = vxlan_obj.verify_vtep(leaf_nodes)
        if vtep_state:
            st.banner("vtep_state test passed")
            st.report_pass('test_case_passed')
        else:
            st.banner("vtep_state test failed")
            st.report_fail("test_case_failed")

    def test_vlanvnimap_state(self):
        st.banner("TEST 2: Verify the expected vlan vni mappings in all leafs")
        initialize_variables()
        leaf_nodes=[]
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        vlan_vnimap_state = vxlan_obj.verify_vlanvnimap(leaf_nodes)
        if vlan_vnimap_state:
            st.banner("vlan_vnimap_state test passed")
            st.report_pass('test_case_passed')
        else:
            st.report_fail("test_case_failed")

    def test_vrfvnimap_state(self):
        st.banner("TEST 3: Verify the expected vrf vni mappings in all leafs")
        initialize_variables()
        leaf_nodes=[]
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        vrf_vnimap_state = vxlan_obj.verify_vrfvnimap(leaf_nodes)
        if vrf_vnimap_state:
            st.banner("vrf_vnimap_state test passed")
            st.report_pass('test_case_passed')
        else:
            st.report_fail("test_case_failed")
 
    def test_all_traffic(self):
        st.banner("TEST 4: Verify Basic Traffic L2/L3 v4/v6")
        initialize_variables()
        leaf_nodes=[]
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        vxlan_obj.get_cli_out(leaf_nodes)
        traffic_result = run_traffic(handles)
        return_result(traffic_result)

    def test_bum_traffic(self):
        st.banner("TEST 5: Verify BUM Traffic")
        initialize_variables()
        leaf_nodes=[]
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        bum_test = vxlan_obj.check_bum_traffic(handles['bum'])
        if bum_test:
            st.banner("BUM test passed")
            st.report_pass('test_case_passed')
        else:
            st.banner("BUM test failed")
            st.report_fail("test_case_failed")

###TRIGGERS####
class TestVxlanBasicTriggers():
    def test_upstream_int_flap(self):
        st.banner("TEST 6:Trigger 1: Verify L2/L3 Traffic after upstream int flap on all leafs")
        initialize_variables()
        dut_int = vxlan_obj.get_dut_interfaces(vars) 
        flap_port_dict = {}
        for node, value in dut_int.items():
            flap_port_list = []
            if "leaf" in node: 
                for port in value['underlay_dict']:
                    flap_port_list.append(vars.get(port))
                flap_port_dict[node] = flap_port_list
        #Flap all upstream ports on all vteps#
        interface_obj.interface_operation_parallel(flap_port_dict, operation='shutdown')
        st.wait(5)
        interface_obj.interface_operation_parallel(flap_port_dict)
        st.wait(10) 
        traffic_result = run_traffic(handles)
        return_result(traffic_result)
        
    def test_host_int_flap(self):
        st.banner("TEST 7:Trigger 2: Verify L2/L3 Traffic after host int flap on all leafs")
        initialize_variables()
        dut_int = vxlan_obj.get_config_interfaces_list(vars) 
        flap_port_dict = {}
        for node, value in dut_int.items():
            flap_port_list = []
            if "leaf" in node: 
                for port in value['l2vni_int']:
                    flap_port_list.append(port)
                flap_port_dict[node] = flap_port_list

        #Flap all upstream ports on all vteps#
        interface_obj.interface_operation_parallel(flap_port_dict, operation='shutdown')
        st.wait(5)
        interface_obj.interface_operation_parallel(flap_port_dict)
        st.wait(5)      
        traffic_result = run_traffic(handles)
        return_result(traffic_result)
        
    def test_bgp_clear(self):
        st.banner("TEST 8:Trigger 3: Verify L2/L3 Traffic after clear bgp on all leafs")
        initialize_variables()
        leaf_nodes=[]
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        vxlan_obj.get_cli_out(leaf_nodes)
        for node in leaf_nodes:
            cmd = "do clear bgp *"
            vxlan_obj.config_dut(node, 'bgp', cmd, add=True)
        st.wait(30)
        vxlan_obj.clear_counters(leaf_nodes)
        traffic_result = run_traffic(handles)
        vxlan_obj.show_counters(leaf_nodes)
        return_result(traffic_result)
        
    def test_clear_fdb(self):
        st.banner("TEST 9:Trigger 4: Verify L2/L3 Traffic after clear fdb on all leafs") 
        initialize_variables()
        leaf_nodes=[]
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        vxlan_obj.get_cli_out(leaf_nodes)
        for node in leaf_nodes:
            st.banner("Clearing fdb in {}".format(node))
            #check for remote mac count on all leafs
            action = mac_obj.clear_mac(node)
            if action:
                st.log("fdb clear successful")
            else:
                st.log("fdb clear failed")
                st.report_fail("test_case_failed")
        #check for remote mac count on all leafs
        traffic_result = run_traffic(handles)
        vxlan_obj.get_cli_out(leaf_nodes)
        #check for remote mac count on all leafs
        return_result(traffic_result)

class TestVxlanSagTriggers():
    def test_del_add_new_sag_mac(self):
        st.banner("TEST 10:Trigger 5: Verify L2/L3 Traffic after del and add new sag mac on all leafs") 
        initialize_variables()
        leaf_nodes=[]
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        vxlan_obj.get_cli_out(leaf_nodes)
        #del sag mac and add new sag mac
        for node in leaf_nodes:
            cmd = "sudo config static-anycast-gateway mac_address del\n"
            cmd += "sudo config static-anycast-gateway mac_address add 00:55:44:33:22:11\n"
            vxlan_obj.config_dut(node, 'sonic', cmd, add=True)
        st.wait(30)
        vxlan_obj.get_cli_out(leaf_nodes)
        traffic_result = run_traffic(handles)
        return_result(traffic_result)
    
    def test_del_add_sag_configs(self):
        st.banner("TEST 11:Trigger 6: Verify L2/L3 Traffic after del and add sag configs on all leafs") 
        initialize_variables()
        leaf_nodes=[]
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        #clear sag config
        vxlan_obj.config_feature(leaf_nodes,'delete_sag_v4')
        vxlan_obj.config_feature(leaf_nodes,'delete_sag_v6')
        vxlan_obj.config_feature(leaf_nodes,'del_sag_mac')
        st.wait(5)
        vxlan_obj.get_cli_out(leaf_nodes)
        #add sag config
        vxlan_obj.config_feature(leaf_nodes,'add_sag_mac')
        vxlan_obj.config_feature(leaf_nodes,'sag_v4')
        vxlan_obj.config_feature(leaf_nodes,'sag_v6')
        st.wait(10)
        vxlan_obj.get_cli_out(leaf_nodes)
        traffic_result = run_traffic(handles)
        return_result(traffic_result)

    def test_del_add_sag_svi_ip(self):
        st.banner("TEST 12:Trigger 7: Verify L2/L3 Traffic after del and add svi_ip on all leafs") 
        initialize_variables()
        leaf_nodes=[]
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        #del sag mac and add new sag mac
        dir_path = os.path.dirname(os.path.realpath(__file__))
        with open(dir_path + '/' + CONFIGS_FILE) as f:
            config_dict = yaml.load(f, Loader=yaml.FullLoader)
            for node, config in config_dict.items():
                if node in leaf_nodes:
                    v4_sag_dict = vxlan_obj.generate_svi_ip_sag(config,'ipv4')
                    output = vxlan_obj.svi_config(v4_sag_dict,'ipv4',mode ='del')
                    vxlan_obj.config_dut(node, 'sonic', output, add=True)
                    v6_sag_dict = vxlan_obj.generate_svi_ip_sag(config,'ipv6')
                    output = vxlan_obj.svi_config(v6_sag_dict,'ipv6',mode ='del')
                    vxlan_obj.config_dut(node, 'sonic', output, add=True)
            vxlan_obj.get_cli_out(leaf_nodes)
            st.wait(10)
            for node, config in config_dict.items():
                if node in leaf_nodes:
                    v4_sag_dict = vxlan_obj.generate_svi_ip_sag(config,'ipv4')
                    output = vxlan_obj.svi_config(v4_sag_dict,'ipv4',mode ='add')
                    vxlan_obj.config_dut(node, 'sonic', output, add=True) 
                    v6_sag_dict = vxlan_obj.generate_svi_ip_sag(config,'ipv6')
                    output = vxlan_obj.svi_config(v6_sag_dict,'ipv6',mode ='add')
                    vxlan_obj.config_dut(node, 'sonic', output, add=True)        
        st.wait(10)
        vxlan_obj.get_cli_out(leaf_nodes)
        traffic_result = run_traffic(handles)
        return_result(traffic_result)

    def test_del_local_mac(self):
        st.banner("TEST 13:Trigger 8: Verify on deleting locally learnt MAC on leaf0, MAC entry is deleted in remote VTEP")
        initialize_variables()
        leaf_nodes=[]
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        vxlan_obj.get_cli_out(leaf_nodes)
        ref_mac_list = mac_obj.get_mac_address_list('leaf0')
        out = st.show('leaf0', "show mac", skip_tmpl=False)
        st.log(out)
        ##Clear fdb on leaf0
        mac_obj.clear_mac('leaf0')
        out = st.show('leaf0', "show mac", skip_tmpl=False)
        st.log(out)
        flag = False
        
        for dut in st.get_dut_names():
            if "leaf" in dut and "leaf0" not in dut:
                cli_output = st.show(dut, "show vxlan remotemac all", skip_tmpl=True)
                parsed_output = st.parse_show(dut, "show vxlan remotemac all",cli_output, "show_vxlan_remotemac_all.tmpl") 
                remote_mac_list = []
                st.log("{} : {}".format(dut, remote_mac_list))
                for item in parsed_output:
                    remote_mac_list.append(item['remote_mac'])
                out_list = []
                for mac in ref_mac_list:
                    if mac in remote_mac_list:
                        st.log("Found mac which is not expected",mac)
                        out_list.append(mac)
                st.banner(out_list)
                st.log(out_list)
                if len(out_list) == 0:
                    flag = True
                    st.log('mac successfully removed on {}'.format(dut))
                else:
                    flag = False
                    st.banner('mac not removed on {}'.format(dut))
        if flag:
            st.report_pass("test_case_passed")
        else:
            st.report_fail("test_case_failed")

    #  Remove/Add VLAN member with SAG remove on all interface and add it back(one vlan)
    def test_remove_add_vlan_member(self):
        st.banner("TEST 14:Trigger 9: Verify. Remove and add back VLAN member with SAG ")
        initialize_variables()
        leaf_nodes=[]
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        int_config_dict = vxlan_obj.get_config_interfaces_list(vars)
        #pick the leaf0 startvlan to be used across leafs for removing the members
        dir_path = os.path.dirname(os.path.realpath(__file__))
        with open(dir_path + '/' + CONFIGS_FILE) as f:
            config_dict = yaml.load(f, Loader=yaml.FullLoader)
            ref_vlan = config_dict["leaf0"]['l2vni']['vlan_start_range']
        selected_leaf_list = []
        for node in leaf_nodes:
            vlan_list = vlan_obj.get_vlan_list(node)
            if str(ref_vlan) in vlan_list:
                selected_leaf_list.append(node)
        st.banner(selected_leaf_list)
        for node in selected_leaf_list:
            port_list = int_config_dict[node]['l2vni_int']
            vlan_obj.delete_vlan_member(node, ref_vlan, port_list, tagging_mode=True, skip_error_check=True, participation_mode="trunk")
        st.wait(10)
        for node in selected_leaf_list:
            port_list = int_config_dict[node]['l2vni_int']
            vlan_obj.add_vlan_member(node, ref_vlan, port_list, tagging_mode=True, skip_error=True)
        
        traffic_result = run_traffic(handles,bum = True)
        return_result(traffic_result)
    
    def test_remove_add_vlan(self):
        st.banner("TEST 15:Trigger 10: Verify. Remove and add back VLAN with SAG ")
        initialize_variables()
        leaf_nodes=[]
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        
        int_config_dict = vxlan_obj.get_config_interfaces_list(vars)
        #pick ref vlan
        dir_path = os.path.dirname(os.path.realpath(__file__))
        with open(dir_path + '/' + CONFIGS_FILE) as f:
            config_dict = yaml.load(f, Loader=yaml.FullLoader)
            ref_vlan = config_dict["leaf0"]['l2vni']['vlan_start_range']
            v4_sag_dict = vxlan_obj.generate_svi_ip_sag(config_dict['leaf0'],'ipv4')
            v6_sag_dict = vxlan_obj.generate_svi_ip_sag(config_dict['leaf0'],'ipv6')
        v4_sag_ip = v4_sag_dict[ref_vlan]
        v6_sag_ip = v6_sag_dict[ref_vlan]
        #Svi interface
        ref_int = "Vlan"+str(ref_vlan)
        #select the leafs which has that vlan
        selected_leaf_list = []
        for node in leaf_nodes:
            vlan_list = vlan_obj.get_vlan_list(node)
            if str(ref_vlan) in vlan_list:
                selected_leaf_list.append(node)
        st.banner(selected_leaf_list)
        data = {'l2vni':{'vlan_start_range':ref_vlan,'count':1}}
        # vxlan_obj.get_cli_out(leaf_nodes)
        ###DELETE VLAN ###
        for node in selected_leaf_list:
            port_list = int_config_dict[node]['l2vni_int']
            #Delete vlan member
            vlan_obj.delete_vlan_member(node, ref_vlan, port_list, tagging_mode=True, skip_error_check=True, participation_mode="trunk")
            #Delete vxlan mapping
            cmd_out = vxlan_obj.delete_l2vni_config(data)
            vxlan_obj.config_dut(node, 'sonic', cmd_out, add=True)
            #Find the vlan interface's vrf
            cli_output = st.show(node, "show vrf", skip_tmpl=True)
            parsed_output = st.parse_show(node, "show vrf",cli_output, "show_vrf.tmpl")
            ref_vrf = ""
            for item in parsed_output:
                for value in item['interfaces']:
                    if value == ref_int:
                        ref_vrf=(item['vrfname'])
            #Remove the vlan interface binding to vrf
            vrf_obj.bind_vrf_interface(dut = node, vrf_name = ref_vrf, intf_name =ref_int, config = 'no')
            #Finally delete vlan
            vlan_obj.delete_vlan(node,[str(ref_vlan)])
        st.wait(10)
        vxlan_obj.get_cli_out(leaf_nodes)
        ###ADD BACK VLAN###
        for node in selected_leaf_list:
            port_list = int_config_dict[node]['l2vni_int']
            #add vlan, vlan member and vxlan mapping
            cmd_out = vxlan_obj.generate_l2vni_config(data,port_list)
            vxlan_obj.config_dut(node, 'sonic', cmd_out, add=True)
            #bind vrf
            vrf_obj.bind_vrf_interface(dut = node, vrf_name = ref_vrf, intf_name =ref_int)
            #add sag configs
            ip_obj.config_ip_addr_interface(node, interface_name=ref_int, ip_address=v4_sag_ip, subnet='24', family="ipv4", config='add', skip_error=True)
            ip_obj.config_ip_addr_interface(node, interface_name=ref_int, ip_address=v6_sag_ip, subnet='64', family="ipv6", config='add', skip_error=True)
            cmd = "sudo config vlan static-anycast-gateway enable {}".format(ref_vlan)
            vxlan_obj.config_dut(node, 'sonic', cmd, add=True)
        vxlan_obj.get_cli_out(leaf_nodes)
        traffic_result = run_traffic(handles, bum = True)
        return_result(traffic_result)

    def test_del_add_vlan_vni(self):
        st.banner("TEST 16:Trigger 11: Verify traffic after del/add vxlan mapping ")
        initialize_variables()
        leaf_nodes=[]
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        dir_path = os.path.dirname(os.path.realpath(__file__))
        with open(dir_path + '/' + CONFIGS_FILE) as f:
            config_dict = yaml.load(f, Loader=yaml.FullLoader)
            for node, config in config_dict.items():
                if node in leaf_nodes:
                    config_out = vxlan_obj.get_vxlan_mapping(config,mode="del")
                    vxlan_obj.config_dut(node, 'sonic', config_out)
            st.wait(10)
            for node, config in config_dict.items():
                if node in leaf_nodes:
                    config_out = vxlan_obj.get_vxlan_mapping(config,mode="add")
                    vxlan_obj.config_dut(node, 'sonic', config_out)
            st.wait(10)
        traffic_result = run_traffic(handles)
        return_result(traffic_result)
 
    def test_remove_add_vrf(self):
        st.banner("TEST 17:Trigger 12: Verify. Remove and add back VRF ")
        initialize_variables()
        leaf_nodes=[]
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        selected_leaf_dict = {}
        #Gather facts
        cli_output = st.show('leaf0', "show vrf", skip_tmpl=True)
        parsed_output = st.parse_show('leaf0', "show vrf",cli_output, "show_vrf.tmpl")
        ref_vrf = parsed_output[0]['vrfname']
        temp_list = []
        for item in parsed_output:
            if item['vrfname'] == ref_vrf:
                for interface in item['interfaces']:
                    if not ref_vrf.split("Vrf")[1] in interface:
                        temp_list.append(interface)
        ref_vlan= int(sorted(temp_list)[0].split("Vlan")[1])
        st.banner("selected vrf is {}".format(ref_vrf))
        
        start_vlan = int(ref_vrf.split("Vrf")[1])
        for node in leaf_nodes:
            cli_output = st.show(node, "show vrf", skip_tmpl=True)
            parsed_output = st.parse_show(node, "show vrf",cli_output, "show_vrf.tmpl")
            for item in parsed_output:
                if item['vrfname'] == ref_vrf:
                    selected_leaf_dict[node]={}
                    selected_leaf_dict[node]['interfaces']=item['interfaces']
        #Del VRF
        for node in selected_leaf_dict:
            out = vxlan_obj.delete_vrf(node, ref_vrf)
            if out:
                st.log("VRF deletion Success")
                st.wait(10)
                #Add back vrf
                #sonic configs
                for node in selected_leaf_dict:
                    leaf_data = {"l3vni":{"l3_dummy":{"start_vlan":start_vlan, "count":1}},"l2vni":{"vlan_start_range":ref_vlan,"count":2}}
                    cmd_out = vxlan_obj.generate_l3vni_config(leaf_data)
                    vxlan_obj.config_dut(node, 'sonic', cmd_out, add=True)
                #sag_config
                dir_path = os.path.dirname(os.path.realpath(__file__))
                with open(dir_path + '/' + CONFIGS_FILE) as f:
                    config_dict = yaml.load(f, Loader=yaml.FullLoader)
                    for node, config in config_dict.items():
                        if node in selected_leaf_dict.keys():
                            v4_sag_dict = vxlan_obj.generate_svi_ip_sag(config,'ipv4') 
                            v6_sag_dict = vxlan_obj.generate_svi_ip_sag(config,'ipv6')
                            if v4_sag_dict != None:
                                new_dict = {}
                                for vlan ,value in v4_sag_dict.items():
                                    if vlan == ref_vlan or vlan == ref_vlan+1:
                                        new_dict[vlan] = value
                                config_out = vxlan_obj.generate_sag_config(new_dict,'ipv4')
                                vxlan_obj.config_dut(node, 'sonic', config_out, add=True)
                            if v6_sag_dict != None:
                                new_dict = {}
                                for vlan ,value in v6_sag_dict.items():
                                    if vlan == ref_vlan or vlan == ref_vlan+1:
                                        new_dict[vlan] = value
                                config_out = vxlan_obj.generate_sag_config(new_dict,'ipv6')
                                vxlan_obj.config_dut(node, 'sonic', config_out, add=True)
                #vtysh configs
                for node in selected_leaf_dict:
                    config_out = vxlan_obj.bgp_vrf_config(node, ref_vrf)
                    vxlan_obj.config_dut(node, 'bgp', config_out)
            else:
                st.banner("VRF deletion Failed")
                st.report_fail("test_case_failed")
        traffic_result = run_traffic(handles)
        return_result(traffic_result)
     
    def test_add_del_new_l2vni(self):
        st.banner("TEST 18:Trigger 13: Create and delete new l2vni and verify traffic ")
        initialize_variables()
        leaf_nodes=[]
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        selected_leaf_list = ['leaf0','leaf1']
        int_config_dict = vxlan_obj.get_config_interfaces_list(vars)
        vlan_data = {'l2vni':{'vlan_start_range':900,'count':1}}
        ###ADD###
        for node in selected_leaf_list:
            port_list = int_config_dict[node]['l2vni_int']
            cmd_out = vxlan_obj.generate_l2vni_config(vlan_data,port_list)
            #add vlan, vlan vni mapping, vlan member
            vxlan_obj.config_dut(node, 'sonic', cmd_out, add=True)
            #add sag ip
            ip_obj.config_ip_addr_interface(node, interface_name="Vlan900", ip_address='111.111.111.1', subnet='24', family="ipv4", config='add', skip_error=True)
            ip_obj.config_ip_addr_interface(node, interface_name="Vlan900", ip_address='111:111:111::1', subnet='64', family="ipv6", config='add', skip_error=True)
            #enable sag on vlan
            cmd = "sudo config vlan static-anycast-gateway enable {}".format(vlan_data['l2vni']['vlan_start_range'])
            vxlan_obj.config_dut(node, 'sonic', cmd, add=True)
        vxlan_obj.get_cli_out(leaf_nodes)
        ###TRAFFIC###
        topo_handles = handles["topo_handles"]

        svi_dict_v4 = {'leaf0':{900:'111.111.111.1'},'leaf1':{900:'111.111.111.1'}}
        svi_dict_v6 = {'leaf0':{900:'111:111:111::1'},'leaf1':{900:'111:111:111::1'}}
        l2vni_intf_dict = vxlan_obj.get_interfaces(vars, leaf_nodes,'l2vni')
        v4_host_info_dict = vxlan_obj.generate_sag_hosts(l2vni_intf_dict,svi_dict_v4,custom_mac_enable = True, custom_start_mac = "00:00:00:00:98:10")
        v6_host_info_dict = vxlan_obj.generate_sag_hosts(l2vni_intf_dict,svi_dict_v6,version="ipv6", custom_mac_enable = True, custom_start_mac = "00:00:00:00:99:10")
        #Create new device groups
        out_v4 = vxlan_obj.create_device_groups(topo_handles,v4_host_info_dict)
        v4_node_device_handles = out_v4[0]
        out_v6 = vxlan_obj.create_device_groups(topo_handles,v6_host_info_dict,version ="ipv6")
        v6_node_device_handles = out_v6[0]
        v4_device_handles = {}
        v6_device_handles = {}
        for node, interfaces in v4_node_device_handles.items():
            for interface,values in interfaces.items():
                v4_device_handles[interface] =values
        for node, interfaces in v6_node_device_handles.items():
            for interface,values in interfaces.items():
                v6_device_handles[interface] =values

        tg_handle = topo_handles[leaf_nodes[0]][l2vni_intf_dict[leaf_nodes[0]][0]]['tg_handle']
        ###Choose traffic endpoints###
        l2_traffic_endpoints = vxlan_obj.find_l2_traffic_endpoints(v4_host_info_dict)
        #Create new handles
        new_stream_handles = {}
        new_stream_handles['new_l2_v4'] = vxlan_obj.create_traffic_item(device_handles = v4_device_handles,endpoints=l2_traffic_endpoints,topo_handles=topo_handles)
        new_stream_handles['new_l2_v6'] = vxlan_obj.create_traffic_item(device_handles = v6_device_handles,endpoints=l2_traffic_endpoints,topo_handles=topo_handles,version = "ipv6")
        st.wait(5)
        flag = True
        for traffic_type, traffic_items in new_stream_handles.items():
            st.banner("Running {}".format(traffic_type))
            traffic_result = vxlan_obj.check_traffic(traffic_items, regenerate_traffic_items = True)
            if traffic_result:
                st.banner("{} traffic passed".format(traffic_type))
            else:
                st.banner("{} traffic failed".format(traffic_type))
                flag = False
        ###DEL###
        for node in selected_leaf_list:
            #disable sag on vlan
            cmd = "sudo config vlan static-anycast-gateway disable {}".format(vlan_data['l2vni']['vlan_start_range'])
            vxlan_obj.config_dut(node, 'sonic', cmd, add=True)
            #del sag ip
            ip_obj.config_ip_addr_interface(node, interface_name="Vlan900", ip_address='111.111.111.1', subnet='24', family="ipv4", config='remove', skip_error=True)
            ip_obj.config_ip_addr_interface(node, interface_name="Vlan900", ip_address='111:111:111::1', subnet='64', family="ipv6", config='remove', skip_error=True)
            #del vlan vni mapping
            config_out = vxlan_obj.delete_l2vni_config(vlan_data)
            vxlan_obj.config_dut(node, 'sonic', config_out, add=True)
            #del member
            port_list = int_config_dict[node]['l2vni_int']
            for item in port_list:
                vlan_obj.delete_vlan_member(node, 900 ,item, tagging_mode=True, skip_error_check=True, participation_mode="trunk")
            #del vlan
            vlan_obj.delete_vlan(node,[900])
        vxlan_obj.get_cli_out(leaf_nodes)
        #Delete Tgen traffic items and device group
        #Traffic item del
        for traffic_type, traffic_items in new_stream_handles.items():
            for key, item in traffic_items.items():
                vxlan_obj.delete_traffic_item(item['tg_handle'],item['stream_id'])
        for port, values in v4_device_handles.items():
            for vlan, dev_grp in values.items():
                vxlan_obj.delete_device_groups(tg_handle,dev_grp)
        for port, values in v6_device_handles.items():
            for vlan, dev_grp in values.items():
                vxlan_obj.delete_device_groups(tg_handle,dev_grp)
        if flag:
            st.report_pass("test_case_passed")
        else:
            st.report_fail("test_case_failed")

    def test_add_del_new_l3vni(self):
        st.banner("TEST 19:Trigger 14: Create new vlan and verify traffic ")
        initialize_variables()
        leaf_nodes=[]
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        selected_leaf_list = ['leaf0','leaf1']
        int_config_dict = vxlan_obj.get_config_interfaces_list(vars)
        vlan_data = {'l2vni':{'vlan_start_range':900,'count':2}}
        l3vni_data = {'l2vni':{'vlan_start_range':900,'count':2},'l3vni':{'l3_dummy':{'start_vlan':999, 'count':1}}}
        bgp_info = vxlan_obj.generate_bgp_underlay_info()
        ###ADD###
        for node in selected_leaf_list:
            port_list = int_config_dict[node]['l2vni_int']
            cmd_out = vxlan_obj.generate_l2vni_config(vlan_data,port_list)
            #add vlan, vlan vni mapping, vlan member
            vxlan_obj.config_dut(node, 'sonic', cmd_out, add=True)
            #Add new vrf
            l3vni_config_out = vxlan_obj.generate_l3vni_config(l3vni_data)
            vxlan_obj.config_dut(node, 'sonic', l3vni_config_out, add=True)
            #add sag ip
            ip_obj.config_ip_addr_interface(node, interface_name="Vlan900", ip_address='111.111.111.1', subnet='24', family="ipv4", config='add', skip_error=True)
            ip_obj.config_ip_addr_interface(node, interface_name="Vlan900", ip_address='111:111:111::1', subnet='64', family="ipv6", config='add', skip_error=True)
            ip_obj.config_ip_addr_interface(node, interface_name="Vlan901", ip_address='111.111.112.1', subnet='24', family="ipv4", config='add', skip_error=True)
            ip_obj.config_ip_addr_interface(node, interface_name="Vlan901", ip_address='111:111:112::1', subnet='64', family="ipv6", config='add', skip_error=True)
            #enable sag on vlan
            cmd = "sudo config vlan static-anycast-gateway enable {}".format(vlan_data['l2vni']['vlan_start_range'])
            vxlan_obj.config_dut(node, 'sonic', cmd, add=True)
            #bgp_l3vni_config
            config_out = vxlan_obj.generate_bgp_l3vni_config(l3vni_data,bgp_info[node])
            vxlan_obj.config_dut(node, 'bgp', config_out)
        vxlan_obj.get_cli_out(leaf_nodes)
        ###Traffic###
        #Generate host info
        topo_handles = handles["topo_handles"]
        svi_dict_v4 = {'leaf0':{900:'111.111.111.1',901:'111.111.112.1'},'leaf1':{900:'111.111.111.1',901:'111.111.112.1'}}
        svi_dict_v6 = {'leaf0':{900:'111:111:111::1',901:'111:111:112::1'},'leaf1':{900:'111:111:111::1',901:'111:111:112::1'}}
        l2vni_intf_dict = vxlan_obj.get_interfaces(vars, leaf_nodes,'l2vni')
        v4_host_info_dict = vxlan_obj.generate_sag_hosts(l2vni_intf_dict,svi_dict_v4,custom_mac_enable = True, custom_start_mac = "00:00:00:00:91:10")
        v6_host_info_dict = vxlan_obj.generate_sag_hosts(l2vni_intf_dict,svi_dict_v6,version="ipv6", custom_mac_enable = True, custom_start_mac = "00:00:00:00:92:10")
        #Create new device groups
        out_v4 = vxlan_obj.create_device_groups(topo_handles,v4_host_info_dict)
        v4_node_device_handles = out_v4[0]
        out_v6 = vxlan_obj.create_device_groups(topo_handles,v6_host_info_dict,version ="ipv6")
        v6_node_device_handles = out_v6[0]
        v4_device_handles = {}
        v6_device_handles = {}
        for node, interfaces in v4_node_device_handles.items():
            for interface,values in interfaces.items():
                v4_device_handles[interface] =values
        for node, interfaces in v6_node_device_handles.items():
            for interface,values in interfaces.items():
                v6_device_handles[interface] =values
        ### start all protocols ###
        tg_handle = topo_handles[leaf_nodes[0]][l2vni_intf_dict[leaf_nodes[0]][0]]['tg_handle']
        l2_traffic_endpoints = vxlan_obj.find_l2_traffic_endpoints(v4_host_info_dict)
        l3_traffic_endpoints = vxlan_obj.find_l3_traffic_endpoints(v4_host_info_dict,vrf_vlan_dict = {"1":[900,901]})
        #disable old streams
        streams = []
        for traffic_type, item in handles.items():
            if traffic_type != 'bum' and traffic_type != "topo_handles":
                for key, value in item.items():
                    streams.append(value['stream_id'])
        tg_handle.tg_traffic_config(mode = 'disable', stream_id = streams)
        #Create new handles
        new_stream_handles = {}
        new_stream_handles['new_l2_v4'] = vxlan_obj.create_traffic_item(device_handles = v4_device_handles,endpoints=l2_traffic_endpoints,topo_handles=topo_handles)
        st.wait(2)
        new_stream_handles['new_l2_v6'] = vxlan_obj.create_traffic_item(device_handles = v6_device_handles,endpoints=l2_traffic_endpoints,topo_handles=topo_handles,version = "ipv6")
        st.wait(2)
        new_stream_handles['new_l3_v4'] = vxlan_obj.create_traffic_item(device_handles = v4_device_handles,endpoints=l3_traffic_endpoints,topo_handles=topo_handles)
        st.wait(2)
        new_stream_handles['new_l3_v6'] = vxlan_obj.create_traffic_item(device_handles = v6_device_handles,endpoints=l3_traffic_endpoints,topo_handles=topo_handles,version = "ipv6")
        st.wait(10)
        #run traffic
        flag = True
        for traffic_type, traffic_items in new_stream_handles.items():
            st.banner("Running {}".format(traffic_type))
            traffic_result = vxlan_obj.check_traffic(traffic_items, regenerate_traffic_items = True)
            if traffic_result:
                st.banner("{} traffic passed".format(traffic_type))
            else:
                st.banner("{} traffic failed".format(traffic_type))
                flag = False
        ###DEL###
        #config cleanup
        for node in selected_leaf_list:
            #disable sag on vlan
            cmd = "sudo config vlan static-anycast-gateway disable {}".format(vlan_data['l2vni']['vlan_start_range'])
            vxlan_obj.config_dut(node, 'sonic', cmd)
            #del sag ip
            ip_obj.config_ip_addr_interface(node, interface_name="Vlan900", ip_address='111.111.111.1', subnet='24', family="ipv4", config='remove', skip_error=True)
            ip_obj.config_ip_addr_interface(node, interface_name="Vlan900", ip_address='111:111:111::1', subnet='64', family="ipv6", config='remove', skip_error=True)
            ip_obj.config_ip_addr_interface(node, interface_name="Vlan901", ip_address='111.111.112.1', subnet='24', family="ipv4", config='remove', skip_error=True)
            ip_obj.config_ip_addr_interface(node, interface_name="Vlan901", ip_address='111:111:112::1', subnet='64', family="ipv6", config='remove', skip_error=True)
            #del bgp l3vni
            config_out = vxlan_obj.delete_bgp_l3vni_config(l3vni_data,bgp_info[node])
            vxlan_obj.config_dut(node, 'bgp', config_out)
            #del sonic l3vni
            config_out = vxlan_obj.delete_l3vni_config(l3vni_data)
            vxlan_obj.config_dut(node, 'sonic', config_out)
            #del vlan vni mapping
            config_out = vxlan_obj.delete_l2vni_config(vlan_data)
            vxlan_obj.config_dut(node, 'sonic', config_out)
            #del member
            port_list = int_config_dict[node]['l2vni_int']
            for item in port_list:
                vlan_obj.delete_vlan_member(node, 900 ,item, tagging_mode=True, skip_error_check=True, participation_mode="trunk")
                vlan_obj.delete_vlan_member(node, 901 ,item, tagging_mode=True, skip_error_check=True, participation_mode="trunk")
            #del vlan
            vlan_obj.delete_vlan(node,[900,901,999])
        vxlan_obj.get_cli_out(leaf_nodes)
        #tgen cleanup
        for traffic_type, traffic_items in new_stream_handles.items():
            for key, item in traffic_items.items():
                vxlan_obj.delete_traffic_item(item['tg_handle'],item['stream_id'])
        for port, values in v4_device_handles.items():
            for vlan, dev_grp in values.items():
                vxlan_obj.delete_device_groups(tg_handle,dev_grp)
        for port, values in v6_device_handles.items():
            for vlan, dev_grp in values.items():
                vxlan_obj.delete_device_groups(tg_handle,dev_grp)
        #enable old streams
        tg_handle.tg_traffic_config(mode = 'enable', stream_id = streams)
        if flag:
            st.report_pass("test_case_passed")
        else:
            st.report_fail("test_case_failed")

    def test_ecmp(self):
        st.banner("TEST 20:Trigger 15: Create new vlan and verify ecmp traffic ")
        initialize_variables()
        leaf_nodes=[]
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        selected_leaf_list = ['leaf0','leaf1']
        int_config_dict = vxlan_obj.get_config_interfaces_list(vars)
        vlan_data = {'l2vni':{'vlan_start_range':900,'count':1}}
        ###ADD###
        for node in selected_leaf_list:
            port_list = int_config_dict[node]['l2vni_int']
            cmd_out = vxlan_obj.generate_l2vni_config(vlan_data,port_list)
            #add vlan, vlan vni mapping, vlan member
            vxlan_obj.config_dut(node, 'sonic', cmd_out, add=True)
            #add sag ip
            ip_obj.config_ip_addr_interface(node, interface_name="Vlan900", ip_address='111.111.111.1', subnet='24', family="ipv4", config='add', skip_error=True)
            ip_obj.config_ip_addr_interface(node, interface_name="Vlan900", ip_address='111:111:111::1', subnet='64', family="ipv6", config='add', skip_error=True)
            #enable sag on vlan
            cmd = "sudo config vlan static-anycast-gateway enable {}".format(vlan_data['l2vni']['vlan_start_range'])
            vxlan_obj.config_dut(node, 'sonic', cmd, add=True)
        ###TRAFFIC###
        topo_handles = handles["topo_handles"]

        svi_dict_v4 = {'leaf0':{900:'111.111.111.1'},'leaf1':{900:'111.111.111.1'}}
        l2vni_intf_dict = vxlan_obj.get_interfaces(vars, leaf_nodes,'l2vni')
        v4_host_info_dict = vxlan_obj.generate_sag_hosts(l2vni_intf_dict,svi_dict_v4,custom_mac_enable = True, custom_start_mac = "00:00:00:00:90:01")

        host_info_dict = {}
        host_info_dict['src'] = {}
        host_info_dict['dst'] = {}
        for node, ports in v4_host_info_dict.items():
            if node == 'leaf0':
                host_info_dict['src'][node] = {}
                for port, value in ports.items():
                    if "P1" in port:
                        host_info_dict['src'][node][port]={}
                        host_info_dict['src'][node][port]= value
                        host_info_dict['src_mac'] = list(value.values())[0]['src_mac']
                        host_info_dict['src_ip'] = list(value.values())[0]['host_ip']
            if node == 'leaf1':
                host_info_dict['dst'][node] = {}
                for port, value in ports.items():
                    if "P1" in port:
                        host_info_dict['dst'][node][port]={}
                        host_info_dict['dst'][node][port] = value
                        host_info_dict['dst_mac'] = list(value.values())[0]['src_mac']
                        host_info_dict['dst_ip'] = list(value.values())[0]['host_ip']
                
        my_topo_handle = {}
        my_topo_handle['src'] = {}
        my_topo_handle['dst'] = {}
        for node ,ports in topo_handles.items():
            if node == 'leaf0':
                for port, value in ports.items():
                    if port == list(host_info_dict['src']['leaf0'].keys())[0]:
                        my_topo_handle['src'][node] = {}
                        my_topo_handle['src'][node][port] = value
                        my_topo_handle['src_port']  = value['port_handle']
            if node == 'leaf1':
                for port, value in ports.items():
                    if 'P1' in port:
                        my_topo_handle['dst'][node] ={}
                        my_topo_handle['dst'][node][port] = value
                        my_topo_handle['dst_port']  = value['port_handle']

        ###Initial Stream ###
        tg_handle = topo_handles[leaf_nodes[0]][l2vni_intf_dict[leaf_nodes[0]][0]]['tg_handle']
        src_dev = vxlan_obj.create_device_groups(my_topo_handle['src'],host_info_dict['src'])
        src_dev_handle = src_dev[0]
        dst_dev = vxlan_obj.create_device_groups(my_topo_handle['dst'],host_info_dict['dst'])
        dst_dev_handle = dst_dev[0]
        stream_list = []
        
        dut_type = vxlan_obj.check_hw_or_sim(selected_leaf_list[0])
        if dut_type == 'hw':
            pkts_per_burst=1000
            rate_percent = 10
        else:
            pkts_per_burst=200
            rate_percent = 0.01
        leaf0_underlay_portlist = int_config_dict['leaf0']['underlay']
        udp_src_no = [25225,60000,65001,45000]
        #choose no of src port no based on no of underlay interfaces
        new_list = udp_src_no[:len(leaf0_underlay_portlist)]
        for udp_src_no in new_list:
            new_raw_stream = tg_handle.tg_traffic_config(
                            port_handle=my_topo_handle['src_port'], 
                            port_handle2=my_topo_handle['dst_port'], 
                            mode='create',
                            transmit_mode='single_burst', 
                            pkts_per_burst=pkts_per_burst, 
                            rate_percent = rate_percent, 
                            circuit_endpoint_type='ipv4', 
                            frame_size=500, 
                            mac_src= host_info_dict['src_mac'], 
                            mac_dst= host_info_dict['dst_mac'],
                            vlan_id = 900,
                            ip_dst_addr = host_info_dict['dst_ip'],
                            ip_src_addr = host_info_dict['src_ip'],
                            l4_protocol = 'udp',
                            udp_src_port = udp_src_no
                            )
            new_stream_id = new_raw_stream['stream_id']
            stream_list.append(new_stream_id)
        
        #stop/start protocols
        vxlan_obj.start_stop_protocols(tg_handle,'stop')
        st.wait(10)
        vxlan_obj.start_stop_protocols(tg_handle,'start')
        st.wait(10)
        #clear dut counters:
        st.show('leaf0', "sonic-clear counters", skip_tmpl=True)
        tg_handle.tg_traffic_control(action='run', stream_handle=stream_list)
        st.wait(30)
        ###Stop Traffic###
        tg_handle.tg_traffic_control(action='stop', stream_handle=stream_list)
        st.wait(30)
        
        #ECMP check
        ecmp_check = True
        cli_output = st.show('leaf0', "show int counters", skip_tmpl=True)
        parsed_out = st.parse_show('leaf0', "show int counters",cli_output, "show_interfaces_counters.tmpl")
        tx_counters = []
        for item in parsed_out:
            if item['iface'] in leaf0_underlay_portlist:
                tx_counters.append(item['tx_ok'])
        
        for value in tx_counters:
            if int(value.replace(",", "")) <= 1.25*(pkts_per_burst) and int(value.replace(",", "")) >= .98*(pkts_per_burst):
                st.banner("Counter value is in expected range ")
            else:
                st.banner(int(value.replace(",", "")))
                st.banner("ECMP Failed")
                ecmp_check =  False
        
        #stats check
        flag = True
        for item in stream_list:
            traffic_stat = tgapi.get_traffic_stats(tg_handle, mode='streams', port_handle=my_topo_handle['src_port'], direction='tx', stream_handle=item)
            #verify stats
            result = vxlan_obj.stats_check(traffic_stat)
            if result :
                st.banner("Traffic passed for {}".format(item))
            else:
                flag = False
                st.banner("Traffic Failed for {}".format(item))
        #Del traffic item and device group
        for item in stream_list:
            vxlan_obj.delete_traffic_item(tg_handle,item)
        vxlan_obj.delete_device_groups(tg_handle,dst_dev_handle.values()[0].values()[0].values()[0])
        vxlan_obj.delete_device_groups(tg_handle,src_dev_handle.values()[0].values()[0].values()[0])

        ###DEL###
        for node in selected_leaf_list:
            #disable sag on vlan
            cmd = "sudo config vlan static-anycast-gateway disable {}".format(vlan_data['l2vni']['vlan_start_range'])
            vxlan_obj.config_dut(node, 'sonic', cmd, add=True)
            #del sag ip
            ip_obj.config_ip_addr_interface(node, interface_name="Vlan900", ip_address='111.111.111.1', subnet='24', family="ipv4", config='remove', skip_error=True)
            ip_obj.config_ip_addr_interface(node, interface_name="Vlan900", ip_address='111:111:111::1', subnet='64', family="ipv6", config='remove', skip_error=True)
            #del vlan vni mapping
            config_out = vxlan_obj.delete_l2vni_config(vlan_data)
            vxlan_obj.config_dut(node, 'sonic', config_out, add=True)
            #del member
            port_list = int_config_dict[node]['l2vni_int']
            for item in port_list:
                vlan_obj.delete_vlan_member(node, 900 ,item, tagging_mode=True, skip_error_check=True, participation_mode="trunk")
            #del vlan
            vlan_obj.delete_vlan(node,[900])
        if not flag:
            st.banner("one or more traffic flows failed")
            st.report_fail("test_case_failed")
        if flag and not ecmp_check:
            st.banner("ECMP Failed")
            st.report_fail("test_case_failed")
        if flag and ecmp_check:
            st.banner("ECMP passed")
            st.report_pass("test_case_passed")

class TestVxlanMacMoveTriggers():

    def check_mm_no(self,cli_output,dst_mac, MM = 1, local = False):
            my_str = "MM:"+str(MM)
            lines = cli_output.split('\n')
            results = []
            flag = False
            for i in range(len(lines)):
                line = lines[i]
                if my_str in line:
                    current_match = line.strip()
                    if i > 0:
                        above_line = lines[i - 2].strip()
                        results.append(above_line)
                        if dst_mac in above_line:
                            flag = True
                        else:
                            st.banner("MAC not found")
                        above_line = lines[i - 1].strip()
                        results.append(above_line)
                        if local:
                            if '32768' in above_line:
                                st.log("mac learnt locally")
                                flag = True
                            else:
                                st.log("mac learnt in remote which is not expected")
                                flag = False
                        else:
                            if '32768' not in above_line:
                                st.log("mac learnt remotely")
                                flag = True
                            else:
                                st.log("mac learnt locally which is not expected")
                                flag = False

                    results.append(current_match)
            for result in results:
                st.banner(result)
            return flag

    def test_mac_move_l2_traffic(self):
        '''
        Add one new vlan
        raw stream 1 traffic between vlan 2 within same leaf
        move host form leaf0 port to leaf1 port1(stop device grp on leaf0 and start on leaf 1)
        raw stream 2 traffic between vlan 2 between  diff leaf
        # add negative traffic check
        '''
        st.banner("TEST 21:Trigger 16: verify mac move")
        initialize_variables()
        leaf_nodes=[]
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        selected_leaf_list = ['leaf0','leaf1']
        dut_type = vxlan_obj.check_hw_or_sim(selected_leaf_list[0])
        if dut_type == 'hw':
            pkts_per_burst=1000
            rate_percent = 10
        else:
            pkts_per_burst=200
            rate_percent = 0.01

        int_config_dict = vxlan_obj.get_config_interfaces_list(vars)
        vlan_data = {'l2vni':{'vlan_start_range':900,'count':1}}
        ###ADD###
        for node in selected_leaf_list:
            port_list = int_config_dict[node]['l2vni_int']
            cmd_out = vxlan_obj.generate_l2vni_config(vlan_data,port_list)
            #add vlan, vlan vni mapping, vlan member
            vxlan_obj.config_dut(node, 'sonic', cmd_out, add=True)
            #add sag ip
            ip_obj.config_ip_addr_interface(node, interface_name="Vlan900", ip_address='111.111.111.1', subnet='24', family="ipv4", config='add', skip_error=True)
            ip_obj.config_ip_addr_interface(node, interface_name="Vlan900", ip_address='111:111:111::1', subnet='64', family="ipv6", config='add', skip_error=True)
            #enable sag on vlan
            cmd = "sudo config vlan static-anycast-gateway enable {}".format(vlan_data['l2vni']['vlan_start_range'])
            vxlan_obj.config_dut(node, 'sonic', cmd, add=True)
        ###TRAFFIC###
        topo_handles = handles["topo_handles"]
        svi_dict_v4 = {'leaf0':{900:'111.111.111.1'},'leaf1':{900:'111.111.111.1'}}
        l2vni_intf_dict = vxlan_obj.get_interfaces(vars, leaf_nodes,'l2vni')
        v4_host_info_dict = vxlan_obj.generate_sag_hosts(l2vni_intf_dict,svi_dict_v4,custom_mac_enable = True, custom_start_mac = "00:00:00:00:25:01")
        host_info_dict = {}
        host_info_dict['src'] = {}
        host_info_dict['dst'] = {}
        host_info_dict['dst1'] = {}
        for node, ports in v4_host_info_dict.items():
            if node == 'leaf0':
                host_info_dict['src'][node] = {}
                host_info_dict['dst'][node] = {}
                for port, value in ports.items():
                    if "P1" in port:
                        host_info_dict['src'][node][port]={}
                        host_info_dict['src'][node][port]= value
                        host_info_dict['src_mac'] = list(value.values())[0]['src_mac']
                        host_info_dict['src_ip'] = list(value.values())[0]['host_ip']
                        # print(list(value.values())[0]['src_mac'])
                    if "P2" in port:
                        host_info_dict['dst'][node][port]={}
                        host_info_dict['dst'][node][port]= value
                        host_info_dict['dst_mac'] = list(value.values())[0]['src_mac']
                        host_info_dict['dst_ip'] = list(value.values())[0]['host_ip']
                        temp_value = value
        for node, ports in v4_host_info_dict.items():
            if node == 'leaf1':
                host_info_dict['dst1'][node] = {}
                for port, value in ports.items():
                    if "P1" in port:
                        host_info_dict['dst1'][node][port]={}
                        host_info_dict['dst1'][node][port] = temp_value
        my_topo_handle = {}
        my_topo_handle['src'] = {}
        my_topo_handle['dst'] = {}
        my_topo_handle['dst1'] = {}
        for node ,ports in topo_handles.items():
            if node == 'leaf0':
                for port, value in ports.items():
                    if port == list(host_info_dict['src']['leaf0'].keys())[0]:
                        my_topo_handle['src'][node] = {}
                        my_topo_handle['src'][node][port] = value
                        my_topo_handle['src_port']  = value['port_handle']
                    if port == list(host_info_dict['dst']['leaf0'].keys())[0]:
                        my_topo_handle['dst'][node] = {}
                        my_topo_handle['dst'][node][port] = value
                        my_topo_handle['dst_port']  = value['port_handle']
            if node == 'leaf1':
                for port, value in ports.items():
                    if 'P1' in port:
                        my_topo_handle['dst1'][node] ={}
                        my_topo_handle['dst1'][node][port] = value
                        my_topo_handle['dst1_port']  = value['port_handle']

        ###Initial Stream ###
        tg_handle = topo_handles[leaf_nodes[0]][l2vni_intf_dict[leaf_nodes[0]][0]]['tg_handle']
        src_dev = vxlan_obj.create_device_groups(my_topo_handle['src'],host_info_dict['src'])
        src_dev_handle = src_dev[0]
        dst_dev = vxlan_obj.create_device_groups(my_topo_handle['dst'],host_info_dict['dst'])
        dst_dev_handle = dst_dev[0]
        new_raw_stream = tg_handle.tg_traffic_config(
                        port_handle=my_topo_handle['src_port'], 
                        port_handle2=my_topo_handle['dst_port'], 
                        mode='create',
                        transmit_mode='single_burst', 
                        pkts_per_burst=pkts_per_burst, 
                        rate_percent = rate_percent, 
                        circuit_endpoint_type='ipv4', 
                        frame_size=500, 
                        mac_src= host_info_dict['src_mac'], 
                        mac_dst= host_info_dict['dst_mac'],
                        vlan_id = 900,
                        ip_dst_addr = host_info_dict['dst_ip'],
                        ip_src_addr = host_info_dict['src_ip']
                        )
        new_stream_id = new_raw_stream['stream_id']
        #stop/start protocols
        vxlan_obj.start_stop_protocols(tg_handle,'stop')
        st.wait(10)
        vxlan_obj.start_stop_protocols(tg_handle,'start')
        st.wait(10)
        tg_handle.tg_traffic_control(action='run', stream_handle=new_stream_id)
        st.wait(30)
        ###Stop Traffic###
        tg_handle.tg_traffic_control(action='stop', stream_handle=new_stream_id)
        st.wait(30)
        traffic_stat = tgapi.get_traffic_stats(tg_handle, mode='streams', port_handle=my_topo_handle['src_port'], direction='tx', stream_handle=new_stream_id)
        #verify stats
        st.banner("Before MAC move")
        result_1 = vxlan_obj.stats_check(traffic_stat)
       
        st.config('leaf0', 'do show bgp l2vpn evpn route vni 5900', type='vtysh', skip_error_check=True)
        st.config('leaf1', 'do show bgp l2vpn evpn route vni 5900', type='vtysh', skip_error_check=True)
        st.config('leaf0', 'do show bgp l2vpn evpn route type 2', type='vtysh', skip_error_check=True)
        st.config('leaf1', 'do show bgp l2vpn evpn route type 2', type='vtysh', skip_error_check=True)
        ###Move the host MAC MOVE 1###
        #Del traffic item and device group
        vxlan_obj.delete_traffic_item(tg_handle,new_stream_id)
        
        vxlan_obj.delete_device_groups(tg_handle,dst_dev_handle.values()[0].values()[0].values()[0])
        # Add device grp on leaf1
        dst1_dev = vxlan_obj.create_device_groups(my_topo_handle['dst1'],host_info_dict['dst1'])
        dst1_dev_handle = dst1_dev[0]
        new_raw_stream_1 = tg_handle.tg_traffic_config(
                        port_handle=my_topo_handle['src_port'], 
                        port_handle2=my_topo_handle['dst1_port'], 
                        mode='create',
                        transmit_mode='single_burst', 
                        pkts_per_burst=pkts_per_burst, 
                        rate_percent = rate_percent, 
                        circuit_endpoint_type='ipv4', 
                        frame_size=500, 
                        mac_src= host_info_dict['src_mac'], 
                        mac_dst= host_info_dict['dst_mac'],
                        vlan_id = 900,
                        ip_dst_addr = host_info_dict['dst_ip'],
                        ip_src_addr = host_info_dict['src_ip']
                        )
        new_stream_id_1 = new_raw_stream_1['stream_id']
        #stop/start protocols
        vxlan_obj.start_stop_protocols(tg_handle,'stop')
        st.wait(10)
        vxlan_obj.start_stop_protocols(tg_handle,'start')
        st.wait(10)
        
        tg_handle.tg_traffic_control(action='run', stream_handle=new_stream_id_1)
        st.wait(30)
        ###Stop Traffic###
        tg_handle.tg_traffic_control(action='stop', stream_handle=new_stream_id_1)
        st.wait(30)
        
        traffic_stat = tgapi.get_traffic_stats(tg_handle, mode='streams', port_handle=my_topo_handle['src_port'], direction='tx', stream_handle=new_stream_id_1)
        #verify stats
        st.banner("After MAC moved to remote lead MM:1")
        result_2 = vxlan_obj.stats_check(traffic_stat)
        st.config('leaf0', 'do show bgp l2vpn evpn route type 2', type='vtysh', skip_error_check=True)
        st.config('leaf1', 'do show bgp l2vpn evpn route type 2', type='vtysh', skip_error_check=True)
        cli_output_1 = st.show('leaf1', "do show bgp l2vpn evpn route type 2",type='vtysh', skip_tmpl=True)
        cli_output_2 = st.show('leaf0', "do show bgp l2vpn evpn route type 2",type='vtysh', skip_tmpl=True)
        mac_move_1 = True
        st.banner("AT Leaf1")
        leaf1_check = self.check_mm_no(cli_output_1,host_info_dict['dst_mac'],1,local = True)
        st.wait(2)
        st.banner("AT Leaf0")
        leaf0_check = self.check_mm_no(cli_output_2,host_info_dict['dst_mac'],1)
        st.wait(2)
        if not (leaf1_check and leaf0_check):
            mac_move_1 = False

        #Del traffic item and device group
        vxlan_obj.delete_traffic_item(tg_handle,new_stream_id_1)
        vxlan_obj.delete_device_groups(tg_handle,dst1_dev_handle.values()[0].values()[0].values()[0])

        ###Move the host: MAC MOVE 2###
        dst_dev = vxlan_obj.create_device_groups(my_topo_handle['dst'],host_info_dict['dst'])
        dst_dev_handle = dst_dev[0]
        new_raw_stream_2 = tg_handle.tg_traffic_config(
                        port_handle=my_topo_handle['src_port'], 
                        port_handle2=my_topo_handle['dst_port'], 
                        mode='create',
                        transmit_mode='single_burst', 
                        pkts_per_burst=pkts_per_burst, 
                        rate_percent = rate_percent, 
                        circuit_endpoint_type='ipv4', 
                        frame_size=500, 
                        mac_src= host_info_dict['src_mac'], 
                        mac_dst= host_info_dict['dst_mac'],
                        vlan_id = 900,
                        ip_dst_addr = host_info_dict['dst_ip'],
                        ip_src_addr = host_info_dict['src_ip']
                        )
        new_stream_id_2 = new_raw_stream_2['stream_id']
        #stop/start protocols
        vxlan_obj.start_stop_protocols(tg_handle,'stop')
        st.wait(10)
        vxlan_obj.start_stop_protocols(tg_handle,'start')
        st.wait(10)
        tg_handle.tg_traffic_control(action='run', stream_handle=new_stream_id_2)
        st.wait(30)
        ###Stop Traffic###
        tg_handle.tg_traffic_control(action='stop', stream_handle=new_stream_id_2)
        st.wait(30)
        traffic_stat = tgapi.get_traffic_stats(tg_handle, mode='streams', port_handle=my_topo_handle['src_port'], direction='tx', stream_handle=new_stream_id_2)
        #verify stats
        st.banner(" MAC move to original leaf")
        result_3 = vxlan_obj.stats_check(traffic_stat)
        st.config('leaf0', 'do show bgp l2vpn evpn route type 2', type='vtysh', skip_error_check=True)
        st.config('leaf1', 'do show bgp l2vpn evpn route type 2', type='vtysh', skip_error_check=True)
        cli_output_1 = st.show('leaf0', "do show bgp l2vpn evpn route type 2",type='vtysh', skip_tmpl=True)
        cli_output_2 = st.show('leaf1', "do show bgp l2vpn evpn route type 2",type='vtysh', skip_tmpl=True)
        mac_move_2 = True
        st.banner("AT Leaf0")
        leaf0_check = self.check_mm_no(cli_output_1,host_info_dict['dst_mac'],2,local = True)
        st.wait(2)
        st.banner("AT Leaf1")
        leaf1_check = self.check_mm_no(cli_output_2,host_info_dict['dst_mac'],2)
        st.wait(2)
        if not (leaf1_check and leaf0_check):
            mac_move_2 = False
        
        vxlan_obj.delete_traffic_item(tg_handle,new_stream_id_2)
        vxlan_obj.delete_device_groups(tg_handle,dst_dev_handle.values()[0].values()[0].values()[0])
        vxlan_obj.delete_device_groups(tg_handle,src_dev_handle.values()[0].values()[0].values()[0])
        ###DEL###
        for node in selected_leaf_list:
            #disable sag on vlan
            cmd = "sudo config vlan static-anycast-gateway disable {}".format(vlan_data['l2vni']['vlan_start_range'])
            vxlan_obj.config_dut(node, 'sonic', cmd, add=True)
            #del sag ip
            ip_obj.config_ip_addr_interface(node, interface_name="Vlan900", ip_address='111.111.111.1', subnet='24', family="ipv4", config='remove', skip_error=True)
            ip_obj.config_ip_addr_interface(node, interface_name="Vlan900", ip_address='111:111:111::1', subnet='64', family="ipv6", config='remove', skip_error=True)
            #del vlan vni mapping
            config_out = vxlan_obj.delete_l2vni_config(vlan_data)
            vxlan_obj.config_dut(node, 'sonic', config_out, add=True)
            #del member
            port_list = int_config_dict[node]['l2vni_int']
            for item in port_list:
                vlan_obj.delete_vlan_member(node, 900 ,item, tagging_mode=True, skip_error_check=True, participation_mode="trunk")
            #del vlan
            vlan_obj.delete_vlan(node,[900])

        if result_1 and result_2 and mac_move_1 and result_3 and mac_move_2:
            st.report_pass("test_case_passed")
        else:
            st.report_fail("test_case_failed")

    def test_mac_move_l3_traffic(self):
        '''
        Add one new vlan
        raw stream 1 traffic between vlan 2 within same leaf
        move host form leaf0 port to leaf1 port1(stop device grp on leaf0 and start on leaf 1)
        raw stream 2 traffic between vlan 2 between  diff leaf
        # add negative traffic check
        '''
        st.banner("TEST 22:Trigger 17:verify mac move and check l3 traffic")
        initialize_variables()
        leaf_nodes=[]
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        selected_leaf_list = ['leaf0','leaf1']
        dut_type = vxlan_obj.check_hw_or_sim(selected_leaf_list[0])
        if dut_type == 'hw':
            pkts_per_burst=1000
            rate_percent = 10
        else:
            pkts_per_burst=200
            rate_percent = 0.01

        int_config_dict = vxlan_obj.get_config_interfaces_list(vars)
        vlan_data = {'l2vni':{'vlan_start_range':900,'count':2}}
        l3vni_data = {'l2vni':{'vlan_start_range':900,'count':2},'l3vni':{'l3_dummy':{'start_vlan':999, 'count':1}}}
        bgp_info = vxlan_obj.generate_bgp_underlay_info()
        ###ADD###
        for node in selected_leaf_list:
            port_list = int_config_dict[node]['l2vni_int']
            cmd_out = vxlan_obj.generate_l2vni_config(vlan_data,port_list)
            #add vlan, vlan vni mapping, vlan member
            vxlan_obj.config_dut(node, 'sonic', cmd_out, add=True)

            #Add new vrf
            l3vni_config_out = vxlan_obj.generate_l3vni_config(l3vni_data)
            vxlan_obj.config_dut(node, 'sonic', l3vni_config_out, add=True)

            #add sag ip
            ip_obj.config_ip_addr_interface(node, interface_name="Vlan900", ip_address='111.111.111.1', subnet='24', family="ipv4", config='add', skip_error=True)
            ip_obj.config_ip_addr_interface(node, interface_name="Vlan901", ip_address='111.111.112.1', subnet='24', family="ipv4", config='add', skip_error=True)
            #enable sag on vlan
            cmd = "sudo config vlan static-anycast-gateway enable {}".format(vlan_data['l2vni']['vlan_start_range'])
            vxlan_obj.config_dut(node, 'sonic', cmd, add=True)
            #bgp_l3vni_config
            config_out = vxlan_obj.generate_bgp_l3vni_config(l3vni_data,bgp_info[node])
            vxlan_obj.config_dut(node, 'bgp', config_out)
        ###TRAFFIC###
        topo_handles = handles["topo_handles"]

        svi_dict_v4 = {'leaf0':{900:'111.111.111.1',901:'111.111.112.1'},'leaf1':{900:'111.111.111.1',901:'111.111.112.1'}}
        l2vni_intf_dict = vxlan_obj.get_interfaces(vars, leaf_nodes,'l2vni')
        v4_host_info_dict = vxlan_obj.generate_sag_hosts(l2vni_intf_dict,svi_dict_v4,custom_mac_enable = True, custom_start_mac = "00:00:00:00:25:01")
        host_info_dict = {}
        host_info_dict['src'] = {}
        host_info_dict['dst'] = {}
        host_info_dict['dst1'] = {}
        for node, ports in v4_host_info_dict.items():
            if node == 'leaf0':
                host_info_dict['src'][node] = {}
                host_info_dict['dst'][node] = {}
                for port, value in ports.items():
                    if "P1" in port:
                        host_info_dict['src'][node][port]={}
                        host_info_dict['src'][node][port]= value
                        host_info_dict['src_mac'] = list(value.values())[1]['src_mac']
                        host_info_dict['src_ip'] = list(value.values())[1]['host_ip']
                        # print(list(value.values())[0]['src_mac'])
                    if "P2" in port:
                        host_info_dict['dst'][node][port]={}
                        host_info_dict['dst'][node][port]= value
                        host_info_dict['dst_mac'] = list(value.values())[0]['src_mac']
                        host_info_dict['dst_ip'] = list(value.values())[0]['host_ip']
                        temp_value = value
        for node, ports in v4_host_info_dict.items():
            if node == 'leaf1':
                host_info_dict['dst1'][node] = {}
                for port, value in ports.items():
                    if "P1" in port:
                        host_info_dict['dst1'][node][port]={}
                        host_info_dict['dst1'][node][port] = temp_value
        my_topo_handle = {}
        my_topo_handle['src'] = {}
        my_topo_handle['dst'] = {}
        my_topo_handle['dst1'] = {}
        for node ,ports in topo_handles.items():
            if node == 'leaf0':
                for port, value in ports.items():
                    if port == list(host_info_dict['src']['leaf0'].keys())[0]:
                        my_topo_handle['src'][node] = {}
                        my_topo_handle['src'][node][port] = value
                        my_topo_handle['src_port']  = value['port_handle']
                    if port == list(host_info_dict['dst']['leaf0'].keys())[0]:
                        my_topo_handle['dst'][node] = {}
                        my_topo_handle['dst'][node][port] = value
                        my_topo_handle['dst_port']  = value['port_handle']
            if node == 'leaf1':
                for port, value in ports.items():
                    if 'P1' in port:
                        my_topo_handle['dst1'][node] ={}
                        my_topo_handle['dst1'][node][port] = value
                        my_topo_handle['dst1_port']  = value['port_handle']
        ###Initial Stream ###
        tg_handle = topo_handles[leaf_nodes[0]][l2vni_intf_dict[leaf_nodes[0]][0]]['tg_handle']
        src_dev = vxlan_obj.create_device_groups(my_topo_handle['src'],host_info_dict['src'])
        src_dev_handle = src_dev[0]
        dst_dev = vxlan_obj.create_device_groups(my_topo_handle['dst'],host_info_dict['dst'])
        dst_dev_handle = dst_dev[0]
        new_raw_stream = tg_handle.tg_traffic_config(
                        port_handle=my_topo_handle['src_port'], 
                        port_handle2=my_topo_handle['dst_port'], 
                        mode='create',
                        transmit_mode='single_burst', 
                        pkts_per_burst=pkts_per_burst, 
                        rate_percent = rate_percent, 
                        circuit_endpoint_type='ipv4', 
                        frame_size=500, 
                        mac_src= host_info_dict['src_mac'], 
                        mac_dst= host_info_dict['dst_mac'],
                        vlan_id = 901,
                        ip_dst_addr = host_info_dict['dst_ip'],
                        ip_src_addr = host_info_dict['src_ip']
                        )
        new_stream_id = new_raw_stream['stream_id']
        #stop/start protocols
        vxlan_obj.start_stop_protocols(tg_handle,'stop')
        st.wait(10)
        vxlan_obj.start_stop_protocols(tg_handle,'start')
        st.wait(10)
        tg_handle.tg_traffic_control(action='run', stream_handle=new_stream_id)
        st.wait(30)
        ###Stop Traffic###
        tg_handle.tg_traffic_control(action='stop', stream_handle=new_stream_id)
        st.wait(30)
        traffic_stat = tgapi.get_traffic_stats(tg_handle, mode='streams', port_handle=my_topo_handle['src_port'], direction='tx', stream_handle=new_stream_id)
        #verify stats
        st.banner("Before MAC move")
        result_1 = vxlan_obj.stats_check(traffic_stat)
       
        st.config('leaf0', 'do show bgp l2vpn evpn route vni 5900', type='vtysh', skip_error_check=True)
        st.config('leaf1', 'do show bgp l2vpn evpn route vni 5900', type='vtysh', skip_error_check=True)
        st.config('leaf0', 'do show bgp l2vpn evpn route type 2', type='vtysh', skip_error_check=True)
        st.config('leaf1', 'do show bgp l2vpn evpn route type 2', type='vtysh', skip_error_check=True)
        ###Move the host MAC MOVE 1###
        #Del traffic item and device group
        vxlan_obj.delete_traffic_item(tg_handle,new_stream_id)
        
        vxlan_obj.delete_device_groups(tg_handle,dst_dev_handle.values()[0].values()[0].values()[0])
        # list(list(dst_dev_handle.values())[0].values())[0]
        # Add device grp on leaf1
        dst1_dev = vxlan_obj.create_device_groups(my_topo_handle['dst1'],host_info_dict['dst1'])
        dst1_dev_handle = dst1_dev[0]
        new_raw_stream_1 = tg_handle.tg_traffic_config(
                        port_handle=my_topo_handle['src_port'], 
                        port_handle2=my_topo_handle['dst1_port'], 
                        mode='create',
                        transmit_mode='single_burst', 
                        pkts_per_burst=pkts_per_burst, 
                        rate_percent = rate_percent, 
                        circuit_endpoint_type='ipv4', 
                        frame_size=500, 
                        mac_src= host_info_dict['src_mac'], 
                        mac_dst= host_info_dict['dst_mac'],
                        vlan_id = 901,
                        ip_dst_addr = host_info_dict['dst_ip'],
                        ip_src_addr = host_info_dict['src_ip']
                        )
        new_stream_id_1 = new_raw_stream_1['stream_id']
        #stop/start protocols
        vxlan_obj.start_stop_protocols(tg_handle,'stop')
        st.wait(10)
        vxlan_obj.start_stop_protocols(tg_handle,'start')
        st.wait(10)
        
        tg_handle.tg_traffic_control(action='run', stream_handle=new_stream_id_1)
        st.wait(30)
        ###Stop Traffic###
        tg_handle.tg_traffic_control(action='stop', stream_handle=new_stream_id_1)
        st.wait(30)
        
        traffic_stat = tgapi.get_traffic_stats(tg_handle, mode='streams', port_handle=my_topo_handle['src_port'], direction='tx', stream_handle=new_stream_id_1)
        #verify stats
        st.banner("After MAC moved to remote lead MM:1")
        result_2 = vxlan_obj.stats_check(traffic_stat)
        st.config('leaf0', 'do show bgp l2vpn evpn route type 2', type='vtysh', skip_error_check=True)
        st.config('leaf1', 'do show bgp l2vpn evpn route type 2', type='vtysh', skip_error_check=True)
        cli_output_1 = st.show('leaf1', "do show bgp l2vpn evpn route type 2",type='vtysh', skip_tmpl=True)
        cli_output_2 = st.show('leaf0', "do show bgp l2vpn evpn route type 2",type='vtysh', skip_tmpl=True)
        mac_move_1 = True
        st.banner("At Leaf1")
        leaf1_check = self.check_mm_no(cli_output_1,host_info_dict['dst_mac'],1,local = True)
        st.banner("At Leaf0")
        leaf0_check = self.check_mm_no(cli_output_2,host_info_dict['dst_mac'],1)
        if not (leaf1_check and leaf0_check):
            mac_move_1 = False
        #Del traffic item and device group
        vxlan_obj.delete_traffic_item(tg_handle,new_stream_id_1)
        vxlan_obj.delete_device_groups(tg_handle,dst1_dev_handle.values()[0].values()[0].values()[0])
        st.wait(5)
        ###Move the host: MAC MOVE 2###
        dst_dev = vxlan_obj.create_device_groups(my_topo_handle['dst'],host_info_dict['dst'])
        dst_dev_handle = dst_dev[0]
        new_raw_stream_2 = tg_handle.tg_traffic_config(
                        port_handle=my_topo_handle['src_port'], 
                        port_handle2=my_topo_handle['dst_port'], 
                        mode='create',
                        transmit_mode='single_burst', 
                        pkts_per_burst=pkts_per_burst, 
                        rate_percent = rate_percent, 
                        circuit_endpoint_type='ipv4', 
                        frame_size=500, 
                        mac_src= host_info_dict['src_mac'], 
                        mac_dst= host_info_dict['dst_mac'],
                        vlan_id = 901,
                        ip_dst_addr = host_info_dict['dst_ip'],
                        ip_src_addr = host_info_dict['src_ip']
                        )
        new_stream_id_2 = new_raw_stream_2['stream_id']
        #stop/start protocols
        vxlan_obj.start_stop_protocols(tg_handle,'stop')
        st.wait(10)
        vxlan_obj.start_stop_protocols(tg_handle,'start')
        st.wait(10)
        tg_handle.tg_traffic_control(action='run', stream_handle=new_stream_id_2)
        st.wait(30)
        ###Stop Traffic###
        tg_handle.tg_traffic_control(action='stop', stream_handle=new_stream_id_2)
        st.wait(30)
        traffic_stat = tgapi.get_traffic_stats(tg_handle, mode='streams', port_handle=my_topo_handle['src_port'], direction='tx', stream_handle=new_stream_id_2)
        #verify stats
        st.banner(" MAC move to original leaf")
        result_3 = vxlan_obj.stats_check(traffic_stat)
        st.config('leaf0', 'do show bgp l2vpn evpn route type 2', type='vtysh', skip_error_check=True)
        st.config('leaf1', 'do show bgp l2vpn evpn route type 2', type='vtysh', skip_error_check=True)
        cli_output_1 = st.show('leaf0', "do show bgp l2vpn evpn route type 2",type='vtysh', skip_tmpl=True)
        cli_output_2 = st.show('leaf1', "do show bgp l2vpn evpn route type 2",type='vtysh', skip_tmpl=True)
        mac_move_2 = True
        st.banner("At Leaf0")
        leaf0_check = self.check_mm_no(cli_output_1,host_info_dict['dst_mac'],2,local = True)
        st.banner("At Leaf1")
        leaf1_check = self.check_mm_no(cli_output_2,host_info_dict['dst_mac'],2)
        if not (leaf1_check and leaf0_check):
            mac_move_2 = False
        
        vxlan_obj.delete_traffic_item(tg_handle,new_stream_id_2)
        vxlan_obj.delete_device_groups(tg_handle,dst_dev_handle.values()[0].values()[0].values()[0])
        vxlan_obj.delete_device_groups(tg_handle,src_dev_handle.values()[0].values()[0].values()[0])
        ###DEL###
        for node in selected_leaf_list:
            #remove bgp_l3vni_config
            config_out = vxlan_obj.delete_bgp_l3vni_config(l3vni_data,bgp_info[node])
            vxlan_obj.config_dut(node, 'bgp', config_out)
            #disable sag on vlan
            cmd = "sudo config vlan static-anycast-gateway disable {}".format(vlan_data['l2vni']['vlan_start_range'])
            vxlan_obj.config_dut(node, 'sonic', cmd, add=True)
            #del sag ip
            ip_obj.config_ip_addr_interface(node, interface_name="Vlan900", ip_address='111.111.111.1', subnet='24', family="ipv4", config='remove', skip_error=True)
            ip_obj.config_ip_addr_interface(node, interface_name="Vlan901", ip_address='111.111.112.1', subnet='24', family="ipv4", config='remove', skip_error=True)
            #remove l3vni
            l3vni_del_config_out = vxlan_obj.delete_l3vni_config(l3vni_data)
            vxlan_obj.config_dut(node, 'sonic', l3vni_del_config_out, add=True)
            #del vlan vni mapping
            config_out = vxlan_obj.delete_l2vni_config(vlan_data)
            vxlan_obj.config_dut(node, 'sonic', config_out, add=True)
            #del member
            port_list = int_config_dict[node]['l2vni_int']
            for item in port_list:
                vlan_obj.delete_vlan_member(node, 900 ,item, tagging_mode=True, skip_error_check=True, participation_mode="trunk")
            #del vlan
            vlan_obj.delete_vlan(node,[900])

        if result_1 and result_2 and mac_move_1 and result_3 and mac_move_2:
            st.report_pass("test_case_passed")
        else:
            st.report_fail("test_case_failed")

    def test_mac_freeze(self):
        '''
        
        '''
        st.banner("TEST 23:Trigger 18: duplicate mac move detection ")
        initialize_variables()
        leaf_nodes=[]
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        selected_leaf_list = ['leaf0','leaf1']
        dut_type = vxlan_obj.check_hw_or_sim(selected_leaf_list[0])
        if dut_type == 'hw':
            pkts_per_burst=1000
            rate_percent = 10
        else:
            pkts_per_burst=200
            rate_percent = 0.01
        
        int_config_dict = vxlan_obj.get_config_interfaces_list(vars)
        vlan_data = {'l2vni':{'vlan_start_range':900,'count':1}}
        bgp_info = vxlan_obj.generate_bgp_underlay_info()
        
        ###ADD###
        for node in selected_leaf_list:
            port_list = int_config_dict[node]['l2vni_int']
            cmd_out = vxlan_obj.generate_l2vni_config(vlan_data,port_list)
            #add vlan, vlan vni mapping, vlan member
            vxlan_obj.config_dut(node, 'sonic', cmd_out, add=True)
            #add sag ip
            ip_obj.config_ip_addr_interface(node, interface_name="Vlan900", ip_address='111.111.111.1', subnet='24', family="ipv4", config='add', skip_error=True)
            ip_obj.config_ip_addr_interface(node, interface_name="Vlan900", ip_address='111:111:111::1', subnet='64', family="ipv6", config='add', skip_error=True)
            #enable sag on vlan
            cmd = "sudo config vlan static-anycast-gateway enable {}".format(vlan_data['l2vni']['vlan_start_range'])
            vxlan_obj.config_dut(node, 'sonic', cmd, add=True)
            #Mac freeze config
            bgp_cmd = "router bgp {}\naddress-family l2vpn evpn\n".format(bgp_info[node]['as_num'])
            bgp_cmd+= "dup-addr-detection max-moves 4 time 200\ndup-addr-detection freeze 60\nexit\n"
            vxlan_obj.config_dut(node, 'bgp', bgp_cmd)
        
        ###TRAFFIC###
        topo_handles = handles["topo_handles"]

        svi_dict_v4 = {'leaf0':{900:'111.111.111.1'},'leaf1':{900:'111.111.111.1'}}
        l2vni_intf_dict = vxlan_obj.get_interfaces(vars, leaf_nodes,'l2vni')
        v4_host_info_dict = vxlan_obj.generate_sag_hosts(l2vni_intf_dict,svi_dict_v4,custom_mac_enable = True, custom_start_mac = "00:00:00:00:25:01")
        host_info_dict = {}
        host_info_dict['src'] = {}
        host_info_dict['dst'] = {}
        host_info_dict['dst1'] = {}
        for node, ports in v4_host_info_dict.items():
            if node == 'leaf0':
                host_info_dict['src'][node] = {}
                host_info_dict['dst'][node] = {}
                for port, value in ports.items():
                    if "P1" in port:
                        host_info_dict['src'][node][port]={}
                        host_info_dict['src'][node][port]= value
                        host_info_dict['src_mac'] = list(value.values())[0]['src_mac']
                        host_info_dict['src_ip'] = list(value.values())[0]['host_ip']
                    if "P2" in port:
                        host_info_dict['dst'][node][port]={}
                        host_info_dict['dst'][node][port]= value
                        host_info_dict['dst_mac'] = list(value.values())[0]['src_mac']
                        host_info_dict['dst_ip'] = list(value.values())[0]['host_ip']
                        temp_value = value
        for node, ports in v4_host_info_dict.items():
            if node == 'leaf1':
                host_info_dict['dst1'][node] = {}
                for port, value in ports.items():
                    if "P1" in port:
                        host_info_dict['dst1'][node][port]={}
                        host_info_dict['dst1'][node][port] = temp_value
        my_topo_handle = {}
        my_topo_handle['src'] = {}
        my_topo_handle['dst'] = {}
        my_topo_handle['dst1'] = {}
        for node ,ports in topo_handles.items():
            if node == 'leaf0':
                for port, value in ports.items():
                    if port == list(host_info_dict['src']['leaf0'].keys())[0]:
                        my_topo_handle['src'][node] = {}
                        my_topo_handle['src'][node][port] = value
                        my_topo_handle['src_port']  = value['port_handle']
                    if port == list(host_info_dict['dst']['leaf0'].keys())[0]:
                        my_topo_handle['dst'][node] = {}
                        my_topo_handle['dst'][node][port] = value
                        my_topo_handle['dst_port']  = value['port_handle']
            if node == 'leaf1':
                for port, value in ports.items():
                    if 'P1' in port:
                        my_topo_handle['dst1'][node] ={}
                        my_topo_handle['dst1'][node][port] = value
                        my_topo_handle['dst1_port']  = value['port_handle']
        ###Initial Stream ###
        tg_handle = topo_handles[leaf_nodes[0]][l2vni_intf_dict[leaf_nodes[0]][0]]['tg_handle']
        src_dev = vxlan_obj.create_device_groups(my_topo_handle['src'],host_info_dict['src'])
        src_dev_handle = src_dev[0]
        dst_dev = vxlan_obj.create_device_groups(my_topo_handle['dst'],host_info_dict['dst'])
        dst_dev_handle = dst_dev[0]
        new_raw_stream = tg_handle.tg_traffic_config(
                        port_handle=my_topo_handle['src_port'], 
                        port_handle2=my_topo_handle['dst_port'], 
                        mode='create',
                        transmit_mode='single_burst', 
                        pkts_per_burst=pkts_per_burst, 
                        rate_percent = rate_percent, 
                        circuit_endpoint_type='ipv4', 
                        frame_size=500, 
                        mac_src= host_info_dict['src_mac'], 
                        mac_dst= host_info_dict['dst_mac'],
                        vlan_id = 900,
                        ip_dst_addr = host_info_dict['dst_ip'],
                        ip_src_addr = host_info_dict['src_ip']
                        )
        new_stream_id = new_raw_stream['stream_id']
        #stop/start protocols
        vxlan_obj.start_stop_protocols(tg_handle,'stop')
        st.wait(20)
        vxlan_obj.start_stop_protocols(tg_handle,'start')
        st.wait(20)
        tg_handle.tg_traffic_control(action='run', stream_handle=new_stream_id)
        st.wait(30)
        ###Stop Traffic###
        tg_handle.tg_traffic_control(action='stop', stream_handle=new_stream_id)
        st.wait(30)
        traffic_stat = tgapi.get_traffic_stats(tg_handle, mode='streams', port_handle=my_topo_handle['src_port'], direction='tx', stream_handle=new_stream_id)
        #verify stats
        st.banner("Before MAC move")
        result_1 = vxlan_obj.stats_check(traffic_stat)
       
        st.config('leaf0', 'do show bgp l2vpn evpn route vni 5900', type='vtysh', skip_error_check=True)
        st.config('leaf1', 'do show bgp l2vpn evpn route vni 5900', type='vtysh', skip_error_check=True)
        st.config('leaf0', 'do show bgp l2vpn evpn route type 2', type='vtysh', skip_error_check=True)
        st.config('leaf1', 'do show bgp l2vpn evpn route type 2', type='vtysh', skip_error_check=True)
        ###Move the host multiple times###
        i = 1
        j = 1
        flag = True
        while i <=6:
            mac_move = False
            vxlan_obj.delete_device_groups(tg_handle,dst_dev_handle.values()[0].values()[0].values()[0])
            
            dst1_dev = vxlan_obj.create_device_groups(my_topo_handle['dst1'],host_info_dict['dst1'])
            dst1_dev_handle = dst1_dev[0]
            vxlan_obj.start_stop_protocols(tg_handle,'stop')
            st.wait(10)
            vxlan_obj.start_stop_protocols(tg_handle,'start')
            st.wait(10)
            st.config('leaf0', 'do show bgp l2vpn evpn route type 2', type='vtysh', skip_error_check=True)
            st.config('leaf1', 'do show bgp l2vpn evpn route type 2', type='vtysh', skip_error_check=True)
            cli_output = st.show('leaf1', "do show bgp l2vpn evpn route type 2",type='vtysh', skip_tmpl=True)
            mac_move = self.check_mm_no(cli_output,host_info_dict['dst_mac'],j,local = True)
            
            #local to leaf1
            if i <=4:
                j+=1
            if not mac_move:
                flag = False
                st.banner("mac not moved as expected")
            i+=1
            vxlan_obj.delete_device_groups(tg_handle,dst1_dev_handle.values()[0].values()[0].values()[0])
            dst_dev = vxlan_obj.create_device_groups(my_topo_handle['dst'],host_info_dict['dst'])
            vxlan_obj.start_stop_protocols(tg_handle,'stop')
            st.wait(10)
            vxlan_obj.start_stop_protocols(tg_handle,'start')
            st.wait(10)
            dst_dev_handle = dst_dev[0]
            if i <=4:
                j+=1
            i+=1
            #local to leaf0
            cli_output = st.show('leaf0', "do show bgp l2vpn evpn route type 2",type='vtysh', skip_tmpl=True)
            mac_move = self.check_mm_no(cli_output,host_info_dict['dst_mac'],j,local = True)
            if not mac_move:
                flag = False
                st.banner("mac not moved as expected")
        #check traffic
        tg_handle.tg_traffic_control(action='run', stream_handle=new_stream_id)
        st.wait(30)
        ###Stop Traffic###
        tg_handle.tg_traffic_control(action='stop', stream_handle=new_stream_id)
        st.wait(30)
        traffic_stat = tgapi.get_traffic_stats(tg_handle, mode='streams', port_handle=my_topo_handle['src_port'], direction='tx', stream_handle=new_stream_id)
        #verify stats
        st.banner("After mac freeze")
        result_2 = vxlan_obj.stats_check(traffic_stat)
        
        #####
        vxlan_obj.delete_traffic_item(tg_handle,new_stream_id)
        vxlan_obj.delete_device_groups(tg_handle,dst_dev_handle.values()[0].values()[0].values()[0])
        vxlan_obj.delete_device_groups(tg_handle,src_dev_handle.values()[0].values()[0].values()[0])
        ###DEL###
        for node in selected_leaf_list:
            #disable sag on vlan
            cmd = "sudo config vlan static-anycast-gateway disable {}".format(vlan_data['l2vni']['vlan_start_range'])
            vxlan_obj.config_dut(node, 'sonic', cmd, add=True)
            #del sag ip
            ip_obj.config_ip_addr_interface(node, interface_name="Vlan900", ip_address='111.111.111.1', subnet='24', family="ipv4", config='remove', skip_error=True)
            ip_obj.config_ip_addr_interface(node, interface_name="Vlan900", ip_address='111:111:111::1', subnet='64', family="ipv6", config='remove', skip_error=True)
            #del vlan vni mapping
            config_out = vxlan_obj.delete_l2vni_config(vlan_data)
            vxlan_obj.config_dut(node, 'sonic', config_out, add=True)
            #del member
            port_list = int_config_dict[node]['l2vni_int']
            for item in port_list:
                vlan_obj.delete_vlan_member(node, 900 ,item, tagging_mode=True, skip_error_check=True, participation_mode="trunk")
            #del vlan
            vlan_obj.delete_vlan(node,[900])

        if result_1 and result_2 and mac_move:
            st.report_pass("test_case_passed")
        else:
            st.report_fail("test_case_failed")

class TestVxlanChangeSviIpTrigger():
    def test_del_add_new_sag_ip(self):
        st.banner("TEST 24:Trigger 19: Change svi ip and check traffic ")
        initialize_variables()
        leaf_nodes=[]
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        #del old tgen configs
        global handles, new_handles
        cleanup_tgen(handles)
        #clear sag config
        vxlan_obj.config_feature(leaf_nodes,'delete_sag_v4')
        vxlan_obj.config_feature(leaf_nodes,'delete_sag_v6')
        st.wait(30)
        vxlan_obj.get_cli_out(leaf_nodes)
        #add sag config
        vxlan_obj.config_feature(leaf_nodes,'new_sag_v4')
        vxlan_obj.config_feature(leaf_nodes,'new_sag_v6')
        st.wait(30)
        vxlan_obj.get_cli_out(leaf_nodes)
        #add new tgen configs
        new_handles = tgen_preconfig(custom_svi_ip = True)
        
        #check traffic
        def check_traffic_results(tgen_han):
            traffic_result = run_traffic(tgen_han)
            flag = True
            for traffic_type , result in traffic_result.items():
                if result == True :
                    st.banner("{} traffic passed".format(traffic_type))
                else:
                    st.banner("{} traffic failed".format(traffic_type))
                    flag = False
            return flag
        result_1 = check_traffic_results(new_handles)
        ###Revert to original configs###
        #clear new sag config
        vxlan_obj.config_feature(leaf_nodes,'delete_new_sag_v4')
        vxlan_obj.config_feature(leaf_nodes,'delete_new_sag_v6')
        st.wait(30)
        vxlan_obj.get_cli_out(leaf_nodes)

        #add back original config
        vxlan_obj.config_feature(leaf_nodes,'sag_v4')
        vxlan_obj.config_feature(leaf_nodes,'sag_v6')
        st.wait(30)
        vxlan_obj.get_cli_out(leaf_nodes)

        #clean tgen
        cleanup_tgen(new_handles)
        handles =  tgen_preconfig()
        result_2 = check_traffic_results(handles)

        if not result_1:
            st.banner("Traffic failed after svi ip change")
            st.report_fail("test_case_failed")
        elif not result_2:
            st.banner("Traffic failed after reverting svi ip change")
            st.report_fail("test_case_failed")
        else:
            st.report_pass("test_case_passed")

@pytest.fixture(scope="class")
def setup_cleanup_for_static():
    #tgen cleanup
    global handles
    cleanup_tgen(handles)
    #config cleanup
    initialize_variables()
    leaf_nodes=[]
    for dut in st.get_dut_names():
        if "leaf" in dut:
            leaf_nodes.append(dut)
    vxlan_obj.config_feature(leaf_nodes,'delete_sag_v6')
    vxlan_obj.config_feature(leaf_nodes,'delete_sag_v4')
    vxlan_obj.config_feature(leaf_nodes,'del_sag_mac')
    vxlan_obj.config_feature(leaf_nodes,'delete_bgp_l3vni_config')
    vxlan_obj.config_feature(leaf_nodes,'delete_l3vni')
    vxlan_obj.config_feature(leaf_nodes,'delete_l2vni')
    # router_preconfig_cleanup()
    vrf_obj.clear_vrf_configuration(st.get_dut_names())
    vlan_obj.clear_vlan_configuration(st.get_dut_names())
    yield
    initialize_variables()
    leaf_nodes=[]
    for dut in st.get_dut_names():
        if "leaf" in dut:
            leaf_nodes.append(dut)
    vxlan_obj.config_feature(leaf_nodes,'l2vni')
    vxlan_obj.config_feature(leaf_nodes,'l3vni')
    vxlan_obj.config_feature(leaf_nodes,'add_sag_mac')
    vxlan_obj.config_feature(leaf_nodes,'sag_v4')
    vxlan_obj.config_feature(leaf_nodes,'sag_v6')
    vxlan_obj.config_feature(leaf_nodes,'bgp_l3vni_config')
    # global handles
    handles = tgen_preconfig()
    st.wait(60)

@pytest.mark.usefixtures("setup_cleanup_for_static")
class TestVxlanStaticRoute():
    def test_static_route_routed_interface(self):
        st.banner("TEST 25:Trigger 20: static route behind routed interface /recursive")
        #Add l2vni
        leaf_nodes=[]
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        selected_leaf_list = ['leaf0','leaf1']
        for dut in selected_leaf_list:
            st.show(dut,"show vxlan remotevtep", skip_tmpl=True)
        dut_type = vxlan_obj.check_hw_or_sim(selected_leaf_list[0])
        if dut_type == 'hw':
            pkts_per_burst=1000
            rate_percent = 10
        else:
            pkts_per_burst=200
            rate_percent = 0.01
        int_config_dict = vxlan_obj.get_config_interfaces_list(vars)
        
        vlan_data = {'l2vni':{'vlan_start_range':900,'count':1}}
        l3vni_data = {'l2vni':{'vlan_start_range':900,'count':1},'l3vni':{'l3_dummy':{'start_vlan':999, 'count':1}}}
        bgp_info = vxlan_obj.generate_bgp_underlay_info()
        ###ADD###
        for node in selected_leaf_list:
            port_list = []
            port_list.append(int_config_dict[node]['l2vni_int'][0])
            cmd_out = vxlan_obj.generate_l2vni_config(vlan_data,port_list)
            #add vlan, vlan vni mapping, vlan member
            vxlan_obj.config_dut(node, 'sonic', cmd_out, add=True)
            #Add new vrf
            l3vni_config_out = vxlan_obj.generate_l3vni_config(l3vni_data)
            vxlan_obj.config_dut(node, 'sonic', l3vni_config_out, add=True)
            #add sag ip
            ip_obj.config_ip_addr_interface(node, interface_name="Vlan900", ip_address='111.111.111.1', subnet='24', family="ipv4", config='add', skip_error=True)
            ip_obj.config_ip_addr_interface(node, interface_name="Vlan901", ip_address='111.111.112.1', subnet='24', family="ipv4", config='add', skip_error=True)
            #enable sag on vlan
            cmd = "sudo config static-anycast-gateway mac_address add 00:55:44:33:22:11\n"
            vxlan_obj.config_dut(node, 'sonic', cmd, add=True)
            cmd = "sudo config vlan static-anycast-gateway enable {}".format(vlan_data['l2vni']['vlan_start_range'])
            vxlan_obj.config_dut(node, 'sonic', cmd, add=True)
            #bgp_l3vni_config
            config_out = vxlan_obj.generate_bgp_l3vni_config(l3vni_data,bgp_info[node])
            vxlan_obj.config_dut(node, 'bgp', config_out)
        #redistribute static
        cmd = "router bgp {} vrf Vrf999\n".format(bgp_info['leaf0']['as_num'])
        cmd += "address-family ipv4 unicast\nredistribute static\nexit"
        vxlan_obj.config_dut('leaf0', 'bgp', cmd)
        #config routed interface and add to vrf
        selected_port = []
        selected_port.append(int_config_dict['leaf0']['l2vni_int'][1])
        #bind vrf
        vrf_obj.bind_vrf_interface(dut = 'leaf0', vrf_name = 'Vrf999', intf_name =selected_port)
        ip_obj.config_ip_addr_interface('leaf0', interface_name=selected_port, ip_address='192.168.1.1', subnet='24', family="ipv4", config='add', skip_error=True)
        #add static route
        cmd = "vrf Vrf999\nip route 60.60.60.1/32 192.168.1.2\nexit"
        vxlan_obj.config_dut('leaf0', 'bgp', cmd)
        #create traffic handles
        l2vni_intf_dict = vxlan_obj.get_interfaces(vars, selected_leaf_list,'l2vni')
        #{'leaf1': ['T1D6P1', 'T1D6P2'], 'leaf0': ['T1D5P1', 'T1D5P2']}
        topo_handles = vxlan_obj.create_topology_handles(l2vni_intf_dict)
        svi_dict_v4 = {'leaf0':{900:'111.111.111.1'},'leaf1':{900:'111.111.111.1'}}
        v4_host_info_dict = vxlan_obj.generate_sag_hosts(l2vni_intf_dict,svi_dict_v4,custom_mac_enable = True, custom_start_mac = "00:00:00:00:35:01")
        #create host info dict
        host_info_dict = {}
        host_info_dict['src'] = {}
        host_info_dict['dst'] = {}
        for node, ports in v4_host_info_dict.items():
            if node == 'leaf1':
                host_info_dict['src'][node] = {}
                for port, value in ports.items():
                    if "P1" in port:
                        host_info_dict['src'][node][port]={}
                        host_info_dict['src'][node][port] = value
                        host_info_dict['src_mac'] = list(value.values())[0]['src_mac']
                        host_info_dict['src_ip'] = list(value.values())[0]['host_ip']
        my_topo_handle = {}
        my_topo_handle['src'] = {}
        my_topo_handle['dst'] = {}
        for node ,ports in topo_handles.items():
            if node == 'leaf1':
                for port, value in ports.items():
                    if 'P1' in port:
                        my_topo_handle['src'][node] ={}
                        my_topo_handle['src'][node][port] = value
                        my_topo_handle['src_port']  = value['port_handle']
            if node == 'leaf0':
                for port, value in ports.items():
                    if 'P2' in port:
                        my_topo_handle['dst'][node] = {}
                        my_topo_handle['dst'][node][port] = value
                        my_topo_handle['dst_port']  = value['port_handle']
        tg_handle = topo_handles[leaf_nodes[0]][l2vni_intf_dict[leaf_nodes[0]][0]]['tg_handle']
        src_dev = vxlan_obj.create_device_groups(my_topo_handle['src'],host_info_dict['src'])
        src_dev_handle = src_dev[0]
        static_topo_handle = ""
        for key, value in my_topo_handle.items():
            if key == "dst":
                for node ,port in value.items():
                    static_topo_handle = port[list(port.keys())[0]]['topology_handle']
        device_group = tg_handle.tg_topology_config(
                    topology_handle= static_topo_handle,
                    device_group_name= """static src device group  """,
                    device_group_multiplier = "1",
                    device_group_enabled= "1"
                    )
        deviceGroup_handle = device_group['device_group_handle']
        ###Creating ethernet stack for the Device Group###
        l2_protocol = tg_handle.tg_interface_config(
            protocol_name= """Ethernet stack """,
            protocol_handle= deviceGroup_handle,mtu= "1500",
            src_mac_addr= '00:90:00:03:36:01',
            src_mac_addr_step= "00.00.00.00.00.01"
        )
        ethernet_handle = l2_protocol['ethernet_handle']
        ### Creating IPv4 Stack for the Device Group###
        l3_protocol = tg_handle.tg_interface_config(
            protocol_name = """IPv4""",
            protocol_handle=ethernet_handle,
            ipv4_resolve_gateway= "1",
            gateway= '192.168.1.1',
            gateway_step= "0.0.0.0",
            intf_ip_addr = '192.168.1.2',
            intf_ip_addr_step= "0.0.0.1"
            )
        ipv4_handle = l3_protocol['ipv4_handle']
        st.log("ipv4_handle-->".format(ipv4_handle))
        ######
        new_raw_stream = tg_handle.tg_traffic_config(
                        port_handle=my_topo_handle['src_port'], 
                        port_handle2=my_topo_handle['dst_port'], 
                        mode='create',
                        transmit_mode='single_burst', 
                        pkts_per_burst=pkts_per_burst, 
                        rate_percent = rate_percent, 
                        circuit_endpoint_type='ipv4', 
                        frame_size=500, 
                        mac_src= host_info_dict['src_mac'], 
                        mac_dst= ' 00:55:44:33:22:11',
                        vlan_id = 900,
                        ip_dst_addr = '60.60.60.1',
                        ip_src_addr = host_info_dict['src_ip']
                        )
        new_stream_id = new_raw_stream['stream_id']
        vxlan_obj.start_stop_protocols(tg_handle,'start')
        st.wait(10)
        for dut in selected_leaf_list: 
            ip_obj.verify_ip_route(dut, vrf_name = 'all')
        tg_handle.tg_traffic_control(action='run', stream_handle=new_stream_id)
        st.wait(30)
        ###Stop Traffic###
        tg_handle.tg_traffic_control(action='stop', stream_handle=new_stream_id)
        st.wait(30)
        traffic_stat = tgapi.get_traffic_stats(tg_handle, mode='streams', port_handle=my_topo_handle['src_port'], direction='tx', stream_handle=new_stream_id)
        result_1 = vxlan_obj.stats_check(traffic_stat)
        #Remove config
        cmd = "vrf Vrf999\nno ip route 60.60.60.1/32 192.168.1.2\nexit"
        vxlan_obj.config_dut('leaf0', 'bgp', cmd)
        for dut in selected_leaf_list: 
            ip_obj.verify_ip_route(dut, vrf_name = 'all')
        #Change to recursive:
        cmd = "vrf Vrf999\nip route 60.60.60.1/32 80.80.80.1\nip route 80.80.80.1/32 192.168.1.2\nexit"
        vxlan_obj.config_dut('leaf0', 'bgp', cmd)
        for dut in selected_leaf_list: 
            ip_obj.verify_ip_route(dut, vrf_name = 'all')
        tg_handle.tg_traffic_control(action='run', stream_handle=new_stream_id)
        st.wait(30)
        ###Stop Traffic###
        tg_handle.tg_traffic_control(action='stop', stream_handle=new_stream_id)
        st.wait(30)
        traffic_stat = tgapi.get_traffic_stats(tg_handle, mode='streams', port_handle=my_topo_handle['src_port'], direction='tx', stream_handle=new_stream_id)
        result_2 = vxlan_obj.stats_check(traffic_stat)

        #Remove config
        cmd = "vrf Vrf999\nno ip route 60.60.60.1/32 80.80.80.1\nno ip route 80.80.80.1/32 192.168.1.2\nexit"
        vxlan_obj.config_dut('leaf0', 'bgp', cmd)
        
        #rem static route
        for node in selected_leaf_list:
        
        #remove bgp_l3vni_config
            config_out = vxlan_obj.delete_bgp_l3vni_config(l3vni_data,bgp_info[node])
            vxlan_obj.config_dut(node, 'bgp', config_out)
        #remove sag configs
            cmd = "sudo config vlan static-anycast-gateway disable {}".format(vlan_data['l2vni']['vlan_start_range'])
            vxlan_obj.config_dut(node, 'sonic', cmd, add=True)
            cmd = "sudo config static-anycast-gateway mac_address del"
            vxlan_obj.config_dut(node, 'sonic', cmd, add=True)
        #remove l3vni
            l3vni_del_config_out = vxlan_obj.delete_l3vni_config(l3vni_data)
            vxlan_obj.config_dut(node, 'sonic', l3vni_del_config_out, add=True)
        #remove l2vni
            l2vni_del_config_out = vxlan_obj.delete_l2vni_config(vlan_data)
            vxlan_obj.config_dut(node, 'sonic', l2vni_del_config_out, add=True)
        vlan_obj.clear_vlan_configuration(selected_leaf_list)
        #tgen cleanup
        for node, ports in topo_handles.items():
            for port, value in ports.items():
                tg_handle.tg_traffic_control(action='reset', port_handle=value['port_handle'])
                tg_handle.tg_topology_config(topology_handle =value['topology_handle'], mode = 'destroy')
        
        if result_1 and result_2 :
            st.banner("Traffic passed for single static route and recursive static route")
            st.report_pass("test_case_passed")
        if not result_1 and not result_2 :
            st.banner("Traffic failed for single static route and recursive static route")
            st.report_pass("test_case_passed")
        if not result_1:
            st.banner("Traffic Failed for static route")
            st.report_fail("test_case_failed")
        if not result_2:
            st.banner("Traffic Failed for recursive static route")
            st.report_fail("test_case_failed")

    def test_static_route_svi_interface(self):
        st.banner("TEST 26:Trigger 21: static route behind svi interface / recursive")
        #Add l2vni
        leaf_nodes=[]
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        selected_leaf_list = ['leaf0','leaf1']
        for dut in selected_leaf_list:
            st.show(dut,"show vxlan remotevtep", skip_tmpl=True)
        dut_type = vxlan_obj.check_hw_or_sim(selected_leaf_list[0])
        if dut_type == 'hw':
            pkts_per_burst=1000
            rate_percent = 10
        else:
            pkts_per_burst=200
            rate_percent = 0.01
        int_config_dict = vxlan_obj.get_config_interfaces_list(vars)
        
        vlan_data = {'l2vni':{'vlan_start_range':900,'count':1}}
        l3vni_data = {'l2vni':{'vlan_start_range':900,'count':1},'l3vni':{'l3_dummy':{'start_vlan':999, 'count':1}}}
        bgp_info = vxlan_obj.generate_bgp_underlay_info()
        ###ADD###
        for node in selected_leaf_list:
            port_list = []
            port_list.append(int_config_dict[node]['l2vni_int'][0])
            cmd_out = vxlan_obj.generate_l2vni_config(vlan_data,port_list)
            #add vlan, vlan vni mapping, vlan member
            vxlan_obj.config_dut(node, 'sonic', cmd_out, add=True)
            #Add new vrf
            l3vni_config_out = vxlan_obj.generate_l3vni_config(l3vni_data)
            vxlan_obj.config_dut(node, 'sonic', l3vni_config_out, add=True)
            #add sag ip
            ip_obj.config_ip_addr_interface(node, interface_name="Vlan900", ip_address='111.111.111.1', subnet='24', family="ipv4", config='add', skip_error=True)
            #enable sag on vlan
            cmd = "sudo config static-anycast-gateway mac_address add 00:55:44:33:22:11\n"
            vxlan_obj.config_dut(node, 'sonic', cmd, add=True)
            cmd = "sudo config vlan static-anycast-gateway enable {}".format(vlan_data['l2vni']['vlan_start_range'])
            vxlan_obj.config_dut(node, 'sonic', cmd, add=True)
            #bgp_l3vni_config
            config_out = vxlan_obj.generate_bgp_l3vni_config(l3vni_data,bgp_info[node])
            vxlan_obj.config_dut(node, 'bgp', config_out)
        #redistribute static
        cmd = "router bgp {} vrf Vrf999\n".format(bgp_info['leaf0']['as_num'])
        cmd += "address-family ipv4 unicast\nredistribute static\nexit"
        vxlan_obj.config_dut('leaf0', 'bgp', cmd)
        #config svi interface and add to vrf
        selected_port = []
        selected_port.append(int_config_dict['leaf0']['l2vni_int'][1])
        vlan_obj.create_vlan('leaf0',[950])
        vlan_obj.add_vlan_member('leaf0', 950, selected_port, tagging_mode=False, skip_error=True)
        #bind vrf
        vrf_obj.bind_vrf_interface(dut = 'leaf0', vrf_name = 'Vrf999', intf_name ='Vlan950')
        ip_obj.config_ip_addr_interface('leaf0', interface_name="Vlan950", ip_address='192.168.1.1', subnet='24', family="ipv4", config='add', skip_error=True)
        #add static route
        cmd = "vrf Vrf999\nip route 60.60.60.1/32 192.168.1.2\nexit"
        vxlan_obj.config_dut('leaf0', 'bgp', cmd)
        #create traffic handles
        l2vni_intf_dict = vxlan_obj.get_interfaces(vars, selected_leaf_list,'l2vni')
        #{'leaf1': ['T1D6P1', 'T1D6P2'], 'leaf0': ['T1D5P1', 'T1D5P2']}
        topo_handles = vxlan_obj.create_topology_handles(l2vni_intf_dict)
        svi_dict_v4 = {'leaf0':{900:'111.111.111.1'},'leaf1':{900:'111.111.111.1'}}
        v4_host_info_dict = vxlan_obj.generate_sag_hosts(l2vni_intf_dict,svi_dict_v4,custom_mac_enable = True, custom_start_mac = "00:00:00:00:35:01")
        #create host info dict
        
        host_info_dict = {}
        host_info_dict['src'] = {}
        host_info_dict['dst'] = {}
        for node, ports in v4_host_info_dict.items():
            if node == 'leaf1':
                host_info_dict['src'][node] = {}
                for port, value in ports.items():
                    if "P1" in port:
                        host_info_dict['src'][node][port]={}
                        host_info_dict['src'][node][port] = value
                        host_info_dict['src_mac'] = list(value.values())[0]['src_mac']
                        host_info_dict['src_ip'] = list(value.values())[0]['host_ip']
        my_topo_handle = {}
        my_topo_handle['src'] = {}
        my_topo_handle['dst'] = {}
        for node ,ports in topo_handles.items():
            if node == 'leaf1':
                for port, value in ports.items():
                    if 'P1' in port:
                        my_topo_handle['src'][node] ={}
                        my_topo_handle['src'][node][port] = value
                        my_topo_handle['src_port']  = value['port_handle']
            if node == 'leaf0':
                for port, value in ports.items():
                    if 'P2' in port:
                        my_topo_handle['dst'][node] = {}
                        my_topo_handle['dst'][node][port] = value
        tg_handle = topo_handles[leaf_nodes[0]][l2vni_intf_dict[leaf_nodes[0]][0]]['tg_handle']
        src_dev = vxlan_obj.create_device_groups(my_topo_handle['src'],host_info_dict['src'])
        src_dev_handle = src_dev[0]
        static_topo_handle = ""
        for key, value in my_topo_handle.items():
            if key == "dst":
                for node ,port in value.items():
                    static_topo_handle = port[list(port.keys())[0]]['topology_handle']
        device_group = tg_handle.tg_topology_config(
                    topology_handle= static_topo_handle,
                    device_group_name= """static src device group  """,
                    device_group_multiplier = "1",
                    device_group_enabled= "1"
                    )
        deviceGroup_handle = device_group['device_group_handle']
        ###Creating ethernet stack for the Device Group###
        l2_protocol = tg_handle.tg_interface_config(
            protocol_name= """Ethernet stack """,
            protocol_handle= deviceGroup_handle,mtu= "1500",
            src_mac_addr= '00:90:00:03:36:01',
            src_mac_addr_step= "00.00.00.00.00.01"
        )
        ethernet_handle = l2_protocol['ethernet_handle']
        ### Creating IPv4 Stack for the Device Group###
        l3_protocol = tg_handle.tg_interface_config(
            protocol_name = """IPv4""",
            protocol_handle=ethernet_handle,
            ipv4_resolve_gateway= "1",
            gateway= '192.168.1.1',
            gateway_step= "0.0.0.0",
            intf_ip_addr = '192.168.1.2',
            intf_ip_addr_step= "0.0.0.1"
            )
        ipv4_handle = l3_protocol['ipv4_handle']
        st.log("ipv4_handle-->".format(ipv4_handle))
        ######
        new_raw_stream = tg_handle.tg_traffic_config(
                        port_handle=my_topo_handle['src_port'], 
                        port_handle2=my_topo_handle['dst_port'], 
                        mode='create',
                        transmit_mode='single_burst', 
                        pkts_per_burst=pkts_per_burst, 
                        rate_percent = rate_percent, 
                        circuit_endpoint_type='ipv4', 
                        frame_size=500, 
                        mac_src= host_info_dict['src_mac'], 
                        mac_dst= ' 00:55:44:33:22:11',
                        vlan_id = 900,
                        ip_dst_addr = '60.60.60.1',
                        ip_src_addr = host_info_dict['src_ip']
                        )
        new_stream_id = new_raw_stream['stream_id']
        vxlan_obj.start_stop_protocols(tg_handle,'start')
        st.wait(10)
        tg_handle.tg_traffic_control(action='run', stream_handle=new_stream_id)
        st.wait(30)
        ###Stop Traffic###
        tg_handle.tg_traffic_control(action='stop', stream_handle=new_stream_id)
        st.wait(30)
        traffic_stat = tgapi.get_traffic_stats(tg_handle, mode='streams', port_handle=my_topo_handle['src_port'], direction='tx', stream_handle=new_stream_id)
        result_1 = vxlan_obj.stats_check(traffic_stat)
        #Remove config
        cmd = "vrf Vrf999\nno ip route 60.60.60.1/32 192.168.1.2\nexit"
        vxlan_obj.config_dut('leaf0', 'bgp', cmd)

        #Change to recursive:
        cmd = "vrf Vrf999\nip route 60.60.60.1/32 80.80.80.1\nip route 80.80.80.1/32 192.168.1.2\nexit"
        vxlan_obj.config_dut('leaf0', 'bgp', cmd)
        tg_handle.tg_traffic_control(action='run', stream_handle=new_stream_id)
        st.wait(30)
        ###Stop Traffic###
        tg_handle.tg_traffic_control(action='stop', stream_handle=new_stream_id)
        st.wait(30)
        traffic_stat = tgapi.get_traffic_stats(tg_handle, mode='streams', port_handle=my_topo_handle['src_port'], direction='tx', stream_handle=new_stream_id)
        result_2 = vxlan_obj.stats_check(traffic_stat)
        #rem static route
        cmd = "vrf Vrf999\nno ip route 60.60.60.1/32 80.80.80.1\nno ip route 80.80.80.1/32 192.168.1.2\nexit"
        vxlan_obj.config_dut('leaf0', 'bgp', cmd)
        
        for node in selected_leaf_list:
        #remove bgp_l3vni_config
            config_out = vxlan_obj.delete_bgp_l3vni_config(l3vni_data,bgp_info[node])
            vxlan_obj.config_dut(node, 'bgp', config_out)
        #remove sag configs
            cmd = "sudo config vlan static-anycast-gateway disable {}".format(vlan_data['l2vni']['vlan_start_range'])
            vxlan_obj.config_dut(node, 'sonic', cmd, add=True)
            cmd = "sudo config static-anycast-gateway mac_address del"
            vxlan_obj.config_dut(node, 'sonic', cmd, add=True)

        #remove l3vni
            l3vni_del_config_out = vxlan_obj.delete_l3vni_config(l3vni_data)
            vxlan_obj.config_dut(node, 'sonic', l3vni_del_config_out, add=True)
        #remove l2vni
            l2vni_del_config_out = vxlan_obj.delete_l2vni_config(vlan_data)
            vxlan_obj.config_dut(node, 'sonic', l2vni_del_config_out, add=True)
        vlan_obj.clear_vlan_configuration(selected_leaf_list)
        #tgen cleanup
        for node, ports in topo_handles.items():
            for port, value in ports.items():
                tg_handle.tg_traffic_control(action='reset', port_handle=value['port_handle'])
                tg_handle.tg_topology_config(topology_handle =value['topology_handle'], mode = 'destroy')
        
        if result_1 and result_2 :
            st.banner("Traffic passed for single static route and recursive static route")
            st.report_pass("test_case_passed")
        if not result_1 and not result_2 :
            st.banner("Traffic failed for single static route and recursive static route")
            st.report_pass("test_case_passed")
        if not result_1:
            st.banner("Traffic Failed for static route")
            st.report_fail("test_case_failed")
        if not result_2:
            st.banner("Traffic Failed for recursive static route")
            st.report_fail("test_case_failed")

    def test_static_route_routed_interface_local_traffic(self):
        st.banner("TEST 27:Trigger 22: static route behind local svi interface / recursive local leaf traffic")
        #Add l2vni
        leaf_nodes=[]
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        selected_leaf_list = ['leaf0','leaf1']
        for dut in selected_leaf_list:
            st.show(dut,"show vxlan remotevtep", skip_tmpl=True)
        dut_type = vxlan_obj.check_hw_or_sim(selected_leaf_list[0])
        if dut_type == 'hw':
            pkts_per_burst=1000
            rate_percent = 10
        else:
            pkts_per_burst=200
            rate_percent = 0.01
        int_config_dict = vxlan_obj.get_config_interfaces_list(vars)
        
        vlan_data = {'l2vni':{'vlan_start_range':900,'count':1}}
        l3vni_data = {'l2vni':{'vlan_start_range':900,'count':1},'l3vni':{'l3_dummy':{'start_vlan':999, 'count':1}}}
        bgp_info = vxlan_obj.generate_bgp_underlay_info()
        ###ADD###
        for node in selected_leaf_list:
            port_list = []
            port_list.append(int_config_dict[node]['l2vni_int'][0])
            cmd_out = vxlan_obj.generate_l2vni_config(vlan_data,port_list)
            #add vlan, vlan vni mapping, vlan member
            vxlan_obj.config_dut(node, 'sonic', cmd_out, add=True)
            #Add new vrf
            l3vni_config_out = vxlan_obj.generate_l3vni_config(l3vni_data)
            vxlan_obj.config_dut(node, 'sonic', l3vni_config_out, add=True)
            #add sag ip
            ip_obj.config_ip_addr_interface(node, interface_name="Vlan900", ip_address='111.111.111.1', subnet='24', family="ipv4", config='add', skip_error=True)
            ip_obj.config_ip_addr_interface(node, interface_name="Vlan901", ip_address='111.111.112.1', subnet='24', family="ipv4", config='add', skip_error=True)
            #enable sag on vlan
            cmd = "sudo config static-anycast-gateway mac_address add 00:55:44:33:22:11\n"
            vxlan_obj.config_dut(node, 'sonic', cmd, add=True)
            cmd = "sudo config vlan static-anycast-gateway enable {}".format(vlan_data['l2vni']['vlan_start_range'])
            vxlan_obj.config_dut(node, 'sonic', cmd, add=True)
            #bgp_l3vni_config
            config_out = vxlan_obj.generate_bgp_l3vni_config(l3vni_data,bgp_info[node])
            vxlan_obj.config_dut(node, 'bgp', config_out)
        #redistribute static
        cmd = "router bgp {} vrf Vrf999\n".format(bgp_info['leaf0']['as_num'])
        cmd += "address-family ipv4 unicast\nredistribute static\nexit"
        vxlan_obj.config_dut('leaf0', 'bgp', cmd)
        #config routed interface and add to vrf
        selected_port = []
        selected_port.append(int_config_dict['leaf0']['l2vni_int'][1])
        #bind vrf
        vrf_obj.bind_vrf_interface(dut = 'leaf0', vrf_name = 'Vrf999', intf_name =selected_port)
        ip_obj.config_ip_addr_interface('leaf0', interface_name=selected_port, ip_address='192.168.1.1', subnet='24', family="ipv4", config='add', skip_error=True)
        #add static route
        cmd = "vrf Vrf999\nip route 60.60.60.1/32 192.168.1.2\nexit"
        vxlan_obj.config_dut('leaf0', 'bgp', cmd)
        #create traffic handles
        l2vni_intf_dict = vxlan_obj.get_interfaces(vars, selected_leaf_list,'l2vni')
        #{'leaf1': ['T1D6P1', 'T1D6P2'], 'leaf0': ['T1D5P1', 'T1D5P2']}
        topo_handles = vxlan_obj.create_topology_handles(l2vni_intf_dict)
        svi_dict_v4 = {'leaf0':{900:'111.111.111.1'},'leaf1':{900:'111.111.111.1'}}
        v4_host_info_dict = vxlan_obj.generate_sag_hosts(l2vni_intf_dict,svi_dict_v4,custom_mac_enable = True, custom_start_mac = "00:00:00:00:35:01")
        #create host info dict
        host_info_dict = {}
        host_info_dict['src'] = {}
        host_info_dict['dst'] = {}
        for node, ports in v4_host_info_dict.items():
            if node == 'leaf0':
                host_info_dict['src'][node] = {}
                for port, value in ports.items():
                    if "P1" in port:
                        host_info_dict['src'][node][port]={}
                        host_info_dict['src'][node][port] = value
                        host_info_dict['src_mac'] = list(value.values())[0]['src_mac']
                        host_info_dict['src_ip'] = list(value.values())[0]['host_ip']
        my_topo_handle = {}
        my_topo_handle['src'] = {}
        my_topo_handle['dst'] = {}
        for node ,ports in topo_handles.items():
            if node == 'leaf0':
                for port, value in ports.items():
                    if 'P1' in port:
                        my_topo_handle['src'][node] ={}
                        my_topo_handle['src'][node][port] = value
                        my_topo_handle['src_port']  = value['port_handle']
                    if 'P2' in port:
                        my_topo_handle['dst'][node] = {}
                        my_topo_handle['dst'][node][port] = value
                        my_topo_handle['dst_port']  = value['port_handle']
        tg_handle = topo_handles[leaf_nodes[0]][l2vni_intf_dict[leaf_nodes[0]][0]]['tg_handle']
        src_dev = vxlan_obj.create_device_groups(my_topo_handle['src'],host_info_dict['src'])
        src_dev_handle = src_dev[0]
        static_topo_handle = ""
        for key, value in my_topo_handle.items():
            if key == "dst":
                for node ,port in value.items():
                    static_topo_handle = port[list(port.keys())[0]]['topology_handle']
        device_group = tg_handle.tg_topology_config(
                    topology_handle= static_topo_handle,
                    device_group_name= """static src device group  """,
                    device_group_multiplier = "1",
                    device_group_enabled= "1"
                    )
        deviceGroup_handle = device_group['device_group_handle']
        ###Creating ethernet stack for the Device Group###
        l2_protocol = tg_handle.tg_interface_config(
            protocol_name= """Ethernet stack """,
            protocol_handle= deviceGroup_handle,mtu= "1500",
            src_mac_addr= '00:90:00:03:36:01',
            src_mac_addr_step= "00.00.00.00.00.01"
        )
        ethernet_handle = l2_protocol['ethernet_handle']
        ### Creating IPv4 Stack for the Device Group###
        l3_protocol = tg_handle.tg_interface_config(
            protocol_name = """IPv4""",
            protocol_handle=ethernet_handle,
            ipv4_resolve_gateway= "1",
            gateway= '192.168.1.1',
            gateway_step= "0.0.0.0",
            intf_ip_addr = '192.168.1.2',
            intf_ip_addr_step= "0.0.0.1"
            )
        ipv4_handle = l3_protocol['ipv4_handle']
        st.log("ipv4_handle-->".format(ipv4_handle))
        ######
        new_raw_stream = tg_handle.tg_traffic_config(
                        port_handle=my_topo_handle['src_port'], 
                        port_handle2=my_topo_handle['dst_port'], 
                        mode='create',
                        transmit_mode='single_burst', 
                        pkts_per_burst=pkts_per_burst, 
                        rate_percent = rate_percent, 
                        circuit_endpoint_type='ipv4', 
                        frame_size=500, 
                        mac_src= host_info_dict['src_mac'], 
                        mac_dst= ' 00:55:44:33:22:11',
                        vlan_id = 900,
                        ip_dst_addr = '60.60.60.1',
                        ip_src_addr = host_info_dict['src_ip']
                        )
        new_stream_id = new_raw_stream['stream_id']
        vxlan_obj.start_stop_protocols(tg_handle,'start')
        st.wait(10)
        for dut in selected_leaf_list: 
            ip_obj.verify_ip_route(dut, vrf_name = 'all')
        tg_handle.tg_traffic_control(action='run', stream_handle=new_stream_id)
        st.wait(30)
        ###Stop Traffic###
        tg_handle.tg_traffic_control(action='stop', stream_handle=new_stream_id)
        st.wait(30)
        traffic_stat = tgapi.get_traffic_stats(tg_handle, mode='streams', port_handle=my_topo_handle['src_port'], direction='tx', stream_handle=new_stream_id)
        result_1 = vxlan_obj.stats_check(traffic_stat)
        #Remove config
        cmd = "vrf Vrf999\nno ip route 60.60.60.1/32 192.168.1.2\nexit"
        vxlan_obj.config_dut('leaf0', 'bgp', cmd)
        for dut in selected_leaf_list: 
            ip_obj.verify_ip_route(dut, vrf_name = 'all')
        #Change to recursive:
        cmd = "vrf Vrf999\nip route 60.60.60.1/32 80.80.80.1\nip route 80.80.80.1/32 192.168.1.2\nexit"
        vxlan_obj.config_dut('leaf0', 'bgp', cmd)
        for dut in selected_leaf_list: 
            ip_obj.verify_ip_route(dut, vrf_name = 'all')
        tg_handle.tg_traffic_control(action='run', stream_handle=new_stream_id)
        st.wait(30)
        ###Stop Traffic###
        tg_handle.tg_traffic_control(action='stop', stream_handle=new_stream_id)
        st.wait(30)
        traffic_stat = tgapi.get_traffic_stats(tg_handle, mode='streams', port_handle=my_topo_handle['src_port'], direction='tx', stream_handle=new_stream_id)
        result_2 = vxlan_obj.stats_check(traffic_stat)
        #Remove config
        cmd = "vrf Vrf999\nno ip route 60.60.60.1/32 80.80.80.1\nno ip route 80.80.80.1/32 192.168.1.2\nexit"
        vxlan_obj.config_dut('leaf0', 'bgp', cmd)
        
        #rem static route
        for node in selected_leaf_list:
        #remove bgp_l3vni_config
            config_out = vxlan_obj.delete_bgp_l3vni_config(l3vni_data,bgp_info[node])
            vxlan_obj.config_dut(node, 'bgp', config_out)
        #remove sag configs
            cmd = "sudo config vlan static-anycast-gateway disable {}".format(vlan_data['l2vni']['vlan_start_range'])
            vxlan_obj.config_dut(node, 'sonic', cmd, add=True)
            cmd = "sudo config static-anycast-gateway mac_address del"
            vxlan_obj.config_dut(node, 'sonic', cmd, add=True)

        #remove l3vni
            l3vni_del_config_out = vxlan_obj.delete_l3vni_config(l3vni_data)
            vxlan_obj.config_dut(node, 'sonic', l3vni_del_config_out, add=True)
        #remove l2vni
            l2vni_del_config_out = vxlan_obj.delete_l2vni_config(vlan_data)
            vxlan_obj.config_dut(node, 'sonic', l2vni_del_config_out, add=True)
        vlan_obj.clear_vlan_configuration(selected_leaf_list)
        #tgen cleanup
        for node, ports in topo_handles.items():
            for port, value in ports.items():
                tg_handle.tg_traffic_control(action='reset', port_handle=value['port_handle'])
                tg_handle.tg_topology_config(topology_handle =value['topology_handle'], mode = 'destroy')
        
        if result_1 and result_2 :
            st.banner("Traffic passed for single static route and recursive static route")
            st.report_pass("test_case_passed")
        if not result_1 and not result_2 :
            st.banner("Traffic failed for single static route and recursive static route")
            st.report_pass("test_case_passed")
        if not result_1:
            st.banner("Traffic Failed for static route")
            st.report_fail("test_case_failed")
        if not result_2:
            st.banner("Traffic Failed for recursive static route")
            st.report_fail("test_case_failed")

class TestVxlanReloadTriggers():

    def test_config_reload(self):
        st.banner("TEST 28:Trigger 23: Verify traffic after config reload ")
        initialize_variables()
        leaf_nodes=[]
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        selected_dut = leaf_nodes[0]
        #config save sonic and frr
        reboot_obj.config_save(selected_dut)
        vxlan_obj.config_dut(selected_dut,"bgp", "do write") 
        count = basic_obj.get_and_match_docker_count(selected_dut)
        status = reboot_obj.config_reload(selected_dut)
        if status:
            st.banner("config reload cmd success!")
        else:
            st.banner("config reload cmd failed!")
            st.report_fail("test_case_failed")
        #change hostname to sonic
        vxlan_obj.config_dut(selected_dut,"sonic", "sudo hostname sonic") 

        #check docker status
        result = True
        if not poll_wait(basic_obj.verify_docker_status, 180, selected_dut, 'Exited'):
            st.error("Post 'config reload', dockers are not auto recovered.")
            result = False
        if result:
            if not poll_wait(basic_obj.get_and_match_docker_count, 180, selected_dut, count):
                st.error("Post 'config reload', ALL dockers are not UP.")
                st.report_fail("test_case_failed")
        st.wait(180)
        #check vtep status 
        vtep_state = vxlan_obj.verify_vtep(leaf_nodes)
        if vtep_state:
            st.banner("All remote vteps are found")
        else:
            st.banner("Not all or no remote vteps are found")
            st.report_fail(test_case_failed)
    
        vxlan_obj.get_cli_out(leaf_nodes)
        traffic_result = run_traffic(handles)
        return_result(traffic_result)

    def test_reboot(self):
        st.banner("TEST 29:Trigger 24: Verify traffic after config reload ")
        initialize_variables()
        leaf_nodes=[]
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        selected_dut = leaf_nodes[0]
        # reboot_obj.config_save(selected_dut)
        vxlan_obj.config_dut(selected_dut,"bgp", "do write") 
        count = basic_obj.get_and_match_docker_count(selected_dut)
        status = reboot_obj.config_save_reboot(selected_dut)
        #change hostname to sonic
        vxlan_obj.config_dut(selected_dut,"sonic", "sudo hostname sonic")
        #check docker status
        result = True
        if not poll_wait(basic_obj.verify_docker_status, 180, selected_dut, 'Exited'):
            st.error("Post 'config reload', dockers are not auto recovered.")
            result = False
        if result:
            if not poll_wait(basic_obj.get_and_match_docker_count, 180, selected_dut, count):
                st.error("Post 'config reload', ALL dockers are not UP.")
                st.report_fail("test_case_failed")
        st.wait(300)
        #check vtep status 
        vtep_state = vxlan_obj.verify_vtep(leaf_nodes)
        if vtep_state:
            st.banner("All remote vteps are found")
        else:
            st.banner("Not all or no remote vteps are found")
            st.report_fail(test_case_failed)
        vxlan_obj.get_cli_out(leaf_nodes)
        traffic_result = run_traffic(handles)
        return_result(traffic_result)
        
#######TGEN CLeanup#######        
def cleanup_tgen(tg_han):
    port_handles = []
    topology_handles = []
    stream_handles = tg_han.get('topo_handles',{})
    for node, values in stream_handles.items():
        for port, value in values.items():
            port_handles.append(value['port_handle'])
            topology_handles.append(value['topology_handle'])
            tg_handle = value['tg_handle']
    tg_handle.tg_traffic_control(action='reset', port_handle=port_handles)
    for topology in topology_handles:
        tg_handle.tg_topology_config(topology_handle =topology, mode = 'destroy')

#######DUT config#######        
def return_result(traffic_result):
    flag = True
    for traffic_type , result in traffic_result.items():
        if result == True :
            st.banner("{} traffic passed".format(traffic_type))
        else:
            st.banner("{} traffic failed".format(traffic_type))
            flag = False
    if flag:
        st.report_pass("test_case_passed")
    else:
        #check bgp on all nodes
        cmds = ["do show bgp summary, do show run"]
        for dut in st.get_dut_names:
            for cmd in cmds:
                st.config(dut, cmd, type='vtysh', skip_error_check=True)
        st.report_fail("test_case_failed")

def run_traffic(traffic_handles, bum = False):
    traffic_result = {}
    if not bum:
        for traffic_type, traffic_items in traffic_handles.items():
            if traffic_type != 'bum' and traffic_type != "topo_handles":
                st.banner("Running {}".format(traffic_type))
                traffic_result[traffic_type] = vxlan_obj.check_traffic(traffic_items, regenerate_traffic_items = True)
    else:
        for traffic_type, traffic_items in traffic_handles.items():
            if traffic_type != 'bum' and traffic_type != "topo_handles":
                st.banner("Running {}".format(traffic_type))
                traffic_result[traffic_type] = vxlan_obj.check_traffic(traffic_items, regenerate_traffic_items = True)
            if traffic_type == 'bum':
                traffic_result[traffic_type] = vxlan_obj.check_bum_traffic(handles['bum'])
    return traffic_result