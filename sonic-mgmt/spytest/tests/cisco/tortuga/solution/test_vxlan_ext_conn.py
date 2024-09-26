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
    nodes = []
    for dut in st.get_dut_names():
        if 'spine' in dut or 'leaf' in dut:
            nodes.append(dut)
    
@pytest.fixture(scope="module", autouse=True)
def choose_config_file():
    global CONFIGS_FILE
    if st.getenv("topo") == "4s4l":
        exp_no_nodes = 9
        CONFIGS_FILE = 'vxlan_4S4L_config_input_file_ext_conn.yaml'
        if len(st.get_dut_names()) != 9:
            st.report_fail('topology_not_matching', "Topology not matching, required {} dut, having {} duts".format(exp_no_nodes,len(st.get_dut_names())))
    else:
        st.report_fail('no_data_found')
        
@pytest.fixture(scope="module", autouse=True)
def vxlan_config_hooks(configure_underlay, configure_overlay, configure_l2l3vni):
    global handles

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

@pytest.fixture(scope="class")
def configure_external_router(request):
    initialize_variables()
    selected_dut = ""
    for dut in st.get_dut_names():
        if "external" in dut:
            selected_dut = dut
    cli_output = st.show('leaf2', "show vrf", skip_tmpl=True)
    parsed_output = st.parse_show('leaf2', "show vrf",cli_output, "show_vrf.tmpl")
    ref_vrf = parsed_output[0]['vrfname']
    
    #config loopback
    ip_obj.config_ip_addr_interface(selected_dut, interface_name="Loopback0", ip_address='30.100.100.100', subnet='32', family="ipv4", config='add', skip_error=True)
    #Config Vrf
    vrf_obj.config_vrf(dut = selected_dut, vrf_name = ref_vrf, config = 'yes')
    # find the port connected to leaf
    ext_dut_id = vars.dut_ids['external_router']
    leaf2_dut_id = vars.dut_ids['leaf2']
    for node,dut_id in vars.dut_ids.items():
        if dut_id == ext_dut_id or dut_id == leaf2_dut_id :
            for key,value in vars.items():
                if ext_dut_id+leaf2_dut_id in key:
                    ext_dut_int = value
                if leaf2_dut_id+ext_dut_id in key:
                    leaf2_int = value
                if ext_dut_id+"T1P1" in key:
                    ext_tgen_int = value
    #find the port connected to VM host
    #Config ip address on interfaces
    vrf_obj.bind_vrf_interface(dut = 'leaf2', vrf_name = ref_vrf, intf_name =leaf2_int)
    ip_obj.config_ip_addr_interface('leaf2', interface_name=leaf2_int, ip_address='21.1.1.1', subnet='24', family="ipv4", config='add', skip_error=True)
    vrf_obj.bind_vrf_interface(dut = selected_dut, vrf_name = ref_vrf, intf_name =ext_dut_int)
    ip_obj.config_ip_addr_interface(selected_dut, interface_name=ext_dut_int, ip_address='21.1.1.2', subnet='24', family="ipv4", config='add', skip_error=True)
    #config external host int
    vrf_obj.bind_vrf_interface(dut = selected_dut, vrf_name = ref_vrf, intf_name =ext_tgen_int)
    ip_obj.config_ip_addr_interface(selected_dut, interface_name=ext_tgen_int, ip_address='42.1.1.1', subnet='24', family="ipv4", config='add', skip_error=True)

    #configure bgp on leaf2
    leaf2_asn_no = str(vxlan_obj.generate_bgp_underlay_info()['leaf2']['as_num'])
    cmd = "router bgp {} vrf {}\nbgp router-id 50.50.50.2\n".format(leaf2_asn_no, ref_vrf)
    cmd += "no bgp ebgp-requires-policy\nno bgp network import-check\n"
    cmd += "neighbor 21.1.1.2 remote-as 65203\nexit\n"
    st.banner(cmd)
    vxlan_obj.config_dut('leaf2', 'bgp', cmd)
    #configure bgp on external router
    cmd = "router bgp 65203 vrf {}\nbgp router-id 50.50.50.1\nno bgp ebgp-requires-policy\nno bgp network import-check\n".format(ref_vrf)
    cmd += "neighbor 21.1.1.1 remote-as {}\n".format(leaf2_asn_no)
    cmd += "address-family ipv4 unicast\nnetwork 42.1.1.0/24\nexit-address-family\nexit"
    vxlan_obj.config_dut(selected_dut, 'bgp', cmd)
    st.wait(10)
    cmd = "show bgp vrf {} summary".format(ref_vrf)
    st.show('leaf2', cmd, type='vtysh', skip_tmpl=True)
    st.show(selected_dut, cmd, type='vtysh', skip_tmpl=True)
    yield
    cli_output = st.show('leaf2', "show vrf", skip_tmpl=True)
    parsed_output = st.parse_show('leaf2', "show vrf",cli_output, "show_vrf.tmpl")
    ref_vrf = parsed_output[0]['vrfname']
    ###unconfig on leaf2
    #bgp
    leaf2_asn_no = str(vxlan_obj.generate_bgp_underlay_info()['leaf2']['as_num'])
    cmd = "no router bgp {} vrf {}".format(leaf2_asn_no, ref_vrf)
    ###unconfig external router
    #bgp
    cmd = "no router bgp 65203 vrf {}".format(ref_vrf)
    vxlan_obj.config_dut(selected_dut, 'bgp', cmd)
    #sonic
    vrf_obj.config_vrf(dut = selected_dut, vrf_name = ref_vrf, config = 'no')

@pytest.fixture
def tgen_preconfig_1():
    initialize_variables()
    
    #Src port selection
    selected_leaf_list = ['leaf0']
    dut_type = vxlan_obj.check_hw_or_sim(selected_leaf_list[0])
    if dut_type == 'hw':
        pkts_per_burst=1000
        rate_percent = 10
    else:
        pkts_per_burst=200
        rate_percent = 0.01
    intf = vxlan_obj.get_interfaces(vars, selected_leaf_list,'l2vni')['leaf0']
    for item in intf:
        if "P1" in item:
            src_port =item
    #Dst port selection
    tgen_ports = dict(vars.tgen_ports)
    ext_dut_id = vars.dut_ids['external_router']
    for key in tgen_ports:
        if ext_dut_id in key and "P1" in key:
            dst_port = key
    intf = {'leaf0':[src_port],'external_router':[dst_port]}
    
    topo_handles = vxlan_obj.create_topology_handles(intf)
    tg_handle = topo_handles['leaf0'][list(topo_handles['leaf0'].keys())[0]]['tg_handle'] 
    #Create device groups
    device_group_1 = tg_handle.tg_topology_config(
                    topology_handle= topo_handles['leaf0'][list(topo_handles['leaf0'].keys())[0]]['topology_handle'],
                    device_group_name= """leaf0 src device group  """,
                    device_group_multiplier = "1",
                    device_group_enabled= "1"
                    )
    deviceGroup_handle_1 = device_group_1['device_group_handle']
    device_group_2 = tg_handle.tg_topology_config(
                    topology_handle= topo_handles['external_router'][list(topo_handles['external_router'].keys())[0]]['topology_handle'],
                    device_group_name= """external dst device group  """,
                    device_group_multiplier = "1",
                    device_group_enabled= "1"
                    )
    deviceGroup_handle_2 = device_group_2['device_group_handle']
    
    #create eth stack
    #get vlan variable
    l2_protocol_1 = tg_handle.tg_interface_config(
            protocol_name= """Ethernet stack 1 """,
            protocol_handle= deviceGroup_handle_1,mtu= "1500",
            src_mac_addr= '00:10:00:00:10:20',
            src_mac_addr_step= "00.00.00.00.00.01",
            vlan=1,
            vlan_id=2, 
            vlan_id_step=1,
            vlan_id_count=1
        )
    ethernet_handle_1 = l2_protocol_1['ethernet_handle']
    l2_protocol_2 = tg_handle.tg_interface_config(
            protocol_name= """Ethernet stack 2 """,
            protocol_handle= deviceGroup_handle_2,mtu= "1500",
            src_mac_addr= '00:10:00:00:10:30',
            src_mac_addr_step= "00.00.00.00.00.01"
        )
    ethernet_handle_2 = l2_protocol_2['ethernet_handle']
    
    #create v4 stack
    #get ip variable
    l3_protocol_1 = tg_handle.tg_interface_config(
            protocol_name = """IPv4""",
            protocol_handle=ethernet_handle_1,
            ipv4_resolve_gateway= "1",
            gateway= '80.2.0.1',
            gateway_step= "0.0.0.0",
            intf_ip_addr = '80.2.0.10',
            intf_ip_addr_step= "0.0.0.1"
            )
    ipv4_handle_1 = l3_protocol_1['ipv4_handle']
    
    l3_protocol_2 = tg_handle.tg_interface_config(
            protocol_name = """IPv4""",
            protocol_handle=ethernet_handle_2,
            ipv4_resolve_gateway= "1",
            gateway= '42.1.1.1',
            gateway_step= "0.0.0.0",
            intf_ip_addr = '42.1.1.2',
            intf_ip_addr_step= "0.0.0.1"
            )
    ipv4_handle_2 = l3_protocol_2['ipv4_handle']
    
    vxlan_obj.start_stop_protocols(tg_handle,'start')
    st.wait(10)

    #create traffic item
    stream = tg_handle.tg_traffic_config(
                    port_handle = topo_handles['leaf0'][list(topo_handles['leaf0'].keys())[0]]['port_handle'],
                    port_handle2 = topo_handles['external_router'][list(topo_handles['external_router'].keys())[0]]['port_handle'],
                    mode='create', 
                    bidirectional=1,
                    transmit_mode='single_burst', 
                    pkts_per_burst=pkts_per_burst,
                    rate_percent =rate_percent, 
                    circuit_endpoint_type='ipv4', 
                    frame_size='500', 
                    emulation_src_handle=deviceGroup_handle_1, 
                    emulation_dst_handle=deviceGroup_handle_2
                    )
    stream_id = stream["stream_id"]
    stream_handles = {}
    stream_handles[1] = {}
    stream_handles[1]['stream_id'] = stream_id
    stream_handles[1]['tg_handle'] = tg_handle
    stream_handles[1]['port_handle'] = topo_handles['leaf0'][list(topo_handles['leaf0'].keys())[0]]['port_handle']
    yield stream_handles
    #cleanup tgen
    tg_handle.tg_traffic_control(action='reset', port_handle=stream_handles[1]['port_handle'])
    topology_handles = [topo_handles['leaf0'][list(topo_handles['leaf0'].keys())[0]]['topology_handle'], topo_handles['external_router'][list(topo_handles['external_router'].keys())[0]]['topology_handle']]
    for topology in topology_handles:
        tg_handle.tg_topology_config(topology_handle =topology, mode = 'destroy')

@pytest.mark.usefixtures('configure_external_router', 'tgen_preconfig_1')
class TestSingleTenant():
    '''
    ebgp via routed interface

    '''
    @pytest.fixture(autouse=True)
    def init_fixtures(self, request):
        self.handles = request.getfixturevalue('tgen_preconfig_1')
        
    def test_basic_traffic_check(self):
        st.banner("Base Traffic check")
        initialize_variables()
        traffic_result = vxlan_obj.check_traffic(self.handles)
        if traffic_result:
            st.banner("traffic between vxlan host and ext host passed")
            st.report_pass('test_case_passed')
        else:
            st.banner("traffic between vxlan host and ext host failed")
            st.report_fail("test_case_failed")

    def test_external_bgp_interface_flap(self):
        st.banner("Flap the interface between border leaf and external router at border leaf")
        initialize_variables()
        ext_dut_id = vars.dut_ids['external_router']
        leaf2_dut_id = vars.dut_ids['leaf2']
        for node,dut_id in vars.dut_ids.items():
            if dut_id == ext_dut_id or dut_id == leaf2_dut_id :
                for key,value in vars.items():
                    if leaf2_dut_id+ext_dut_id in key:
                        leaf2_int = value
        interface_obj.interface_shutdown('leaf2',leaf2_int)
        st.wait(2)
        interface_obj.interface_noshutdown('leaf2',leaf2_int)
        st.wait(2)
        traffic_result = vxlan_obj.check_traffic(self.handles)
        if traffic_result:
            st.banner("traffic between vxlan host and ext host passed")
            st.report_pass('test_case_passed')
        else:
            st.banner("traffic between vxlan host and ext host failed")
            st.report_fail("test_case_failed")

    def test_external_router_host_interface_flap(self):
        st.banner("Flap the external host interface")
        initialize_variables()
        ext_dut_id = vars.dut_ids['external_router']
        for node,dut_id in vars.dut_ids.items():
            if dut_id == ext_dut_id :
                for key,value in vars.items():
                    if ext_dut_id+"T1P1" in key:
                        ext_tgen_int = value
        interface_obj.interface_shutdown('external_router',ext_tgen_int)
        st.wait(2)
        interface_obj.interface_noshutdown('external_router',ext_tgen_int)
        st.wait(2)
        traffic_result = vxlan_obj.check_traffic(self.handles)
        if traffic_result:
            st.banner("traffic between vxlan host and ext host passed")
            st.report_pass('test_case_passed')
        else:
            st.banner("traffic between vxlan host and ext host failed")
            st.report_fail("test_case_failed")
    
    def test_config_reload(self):
        st.banner("reload BL")
        initialize_variables()
        leaf_nodes=[]
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        selected_dut = 'leaf2'
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
        traffic_result = vxlan_obj.check_traffic(self.handles)
        if traffic_result:
            st.banner("traffic between vxlan host and ext host passed after BL reload")
            st.report_pass('test_case_passed')
        else:
            st.banner("traffic between vxlan host and ext host failed after BL reload")
            st.report_fail("test_case_failed")

    def test_reboot(self):
        st.banner("reboot BL ")
        initialize_variables()
        leaf_nodes=[]
        for dut in st.get_dut_names():
            if "leaf" in dut:
                leaf_nodes.append(dut)
        selected_dut = 'leaf2'
        vxlan_obj.config_dut(selected_dut,"bgp", "do write") 
        count = basic_obj.get_and_match_docker_count(selected_dut)
        status = reboot_obj.config_save_reboot(selected_dut)
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
        traffic_result = vxlan_obj.check_traffic(self.handles)
        if traffic_result:
            st.banner("traffic between vxlan host and ext host passed after BL reboot")
            st.report_pass('test_case_passed')
        else:
            st.banner("traffic between vxlan host and ext host failed after BL reboot")
            st.report_fail("test_case_failed")