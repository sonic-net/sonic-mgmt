import os
import yaml
import pytest
from spytest import st, tgapi
import apis.routing.ip as ip_obj
import apis.routing.vrf as vrf_obj
import apis.routing.bgp as bgp_obj
import apis.switching.vlan as vlan_obj
from spytest.tgen.tg import tgen_obj_dict
import vxlan_helper as vxlan_obj
from spytest.utils import poll_wait


@pytest.fixture(scope="module", autouse=True)
def initialize_variables():
    global vars, nodes, leaf_nodes, handles
    vars = st.get_testbed_vars()
    nodes = st.get_dut_names()
    leaf_nodes = []
    for dut in nodes:
        if "leaf" in dut:
            leaf_nodes.append(dut)


@pytest.fixture(scope="module", autouse=True)
def choose_config_file():
    global CONFIGS_FILE
    if st.getenv("topo", "2s3l") == "2s3l":
        exp_no_nodes = 5
        CONFIGS_FILE = "vxlan_fabric_extension_input.yaml"
        if len(st.get_dut_names()) != 5:
            st.report_fail('topology_not_matching', "Topology not matching, required {} dut, having {} duts".format(exp_no_nodes,len(st.get_dut_names())))
    else:
        st.report_fail('no_data_found')


def tgen_preconfig(**kwargs):

    svi_dict_v4 = {}
    svi_dict_v6 ={}
    l2vni_intf_dict = vxlan_obj.get_interfaces(vars, leaf_nodes,'l2vni')
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
    start_protocol = vxlan_obj.start_stop_protocols(tg_handle,action='start', start_wait=5)

    if start_protocol == 1:
        st.log("protocols started successfully")
    else:
        st.report_tgen_fail('start protocols failed!')

    ### choose traffic item endpoints###
    l2_traffic_endpoints = vxlan_obj.find_l2_traffic_endpoints(v4_host_info_dict)
    l3_traffic_endpoints = vxlan_obj.find_l3_traffic_endpoints(v4_host_info_dict)

    v4_device_handles_single_leaf = {key: v4_device_handles[key] for key in ['T1D3P1', 'T1D3P2'] if key in v4_device_handles}
    v6_device_handles_single_leaf = {key: v6_device_handles[key] for key in ['T1D3P1', 'T1D3P2'] if key in v6_device_handles}

    l2_traffic_endpoints_single_leaf = {key: value for key, value in l2_traffic_endpoints.items() if value['dst_int'] == 'T1D3P2'}
    l3_traffic_endpoints_single_leaf = {key: value for key, value in  l3_traffic_endpoints.items() if value['dst_int'] == 'T1D3P2'}

    keys_to_extract = ['T1D3P1', 'T1D4P1', 'T1D4P2']
    v4_device_handles_two_leaf = {key:  v4_device_handles[key] for key in keys_to_extract if key in  v4_device_handles}
    v6_device_handles_two_leaf = {key:  v6_device_handles[key] for key in keys_to_extract if key in  v6_device_handles}

    l2_traffic_endpoints_two_leaf = {key: value for key, value in l2_traffic_endpoints.items() if value['dst_int'] in ['T1D4P1', 'T1D4P2']}
    l3_traffic_endpoints_two_leaf = {key: value for key, value in l3_traffic_endpoints.items() if value['dst_int'] in ['T1D4P1', 'T1D4P2']} 

    keys_to_extract = ['T1D3P1', 'T1D5P1', 'T1D5P2']
    v4_device_handles_extra_leaf = {key: v4_device_handles[key] for key in keys_to_extract if key in v4_device_handles}
    v6_device_handles_extra_leaf = {key: v6_device_handles[key] for key in keys_to_extract if key in v6_device_handles}

    l2_traffic_endpoints_extra_leaf = {key: value for key, value in l2_traffic_endpoints.items() if value['dst_int'] in ['T1D5P1', 'T1D5P2']}
    l3_traffic_endpoints_extra_leaf = {key: value for key, value in l3_traffic_endpoints.items() if value['dst_int'] in ['T1D5P1', 'T1D5P2']}

    ### create traffic item endpoints###
    stream_handles_single_leaf = {}
    rate_percent = 1
    stream_handles_single_leaf['l2_v4'] = vxlan_obj.create_traffic_item(device_handles = v4_device_handles_single_leaf,
                                                                        endpoints=l2_traffic_endpoints_single_leaf,
                                                                        topo_handles=topo_handles,
                                                                        rate_percent=rate_percent,
                                                                        name_prfx='l2_v4',
                                                                        transmit_mode='continuous')
    stream_handles_single_leaf['l3_v4'] = vxlan_obj.create_traffic_item(device_handles = v4_device_handles_single_leaf,
                                                                        endpoints=l3_traffic_endpoints_single_leaf,
                                                                        topo_handles=topo_handles,
                                                                        rate_percent=rate_percent,
                                                                        name_prfx='l3_v4',
                                                                        transmit_mode='continuous')
    stream_handles_single_leaf['l2_v6'] = vxlan_obj.create_traffic_item(device_handles = v6_device_handles_single_leaf,
                                                                        endpoints=l2_traffic_endpoints_single_leaf,
                                                                        topo_handles=topo_handles,
                                                                        version = "ipv6",
                                                                        rate_percent=rate_percent,
                                                                        name_prfx='l2_v6',
                                                                        transmit_mode='continuous')
    stream_handles_single_leaf['l3_v6'] = vxlan_obj.create_traffic_item(device_handles = v6_device_handles_single_leaf,
                                                                        endpoints=l3_traffic_endpoints_single_leaf,
                                                                        topo_handles=topo_handles,
                                                                        version = "ipv6",
                                                                        rate_percent=rate_percent,
                                                                        name_prfx='l3_v6',
                                                                        transmit_mode='continuous')
    stream_handles_single_leaf["topo_handles"] = topo_handles

    stream_handles_two_leaf = {}
    stream_handles_two_leaf['l2_v4'] = vxlan_obj.create_traffic_item(device_handles = v4_device_handles_two_leaf,
                                                                    endpoints=l2_traffic_endpoints_two_leaf,
                                                                    topo_handles=topo_handles,
                                                                    rate_percent=rate_percent,
                                                                    name_prfx='l2_v4',
                                                                    transmit_mode='continuous')
    stream_handles_two_leaf['l3_v4'] = vxlan_obj.create_traffic_item(device_handles = v4_device_handles_two_leaf,
                                                                    endpoints=l3_traffic_endpoints_two_leaf,
                                                                    topo_handles=topo_handles,
                                                                    rate_percent=rate_percent,
                                                                    name_prfx='l3_v4',
                                                                    transmit_mode='continuous')
    stream_handles_two_leaf['l2_v6'] = vxlan_obj.create_traffic_item(device_handles = v6_device_handles_two_leaf,
                                                                    endpoints=l2_traffic_endpoints_two_leaf,
                                                                    topo_handles=topo_handles,
                                                                    version = "ipv6",
                                                                    rate_percent=rate_percent,
                                                                    name_prfx='l2_v6',
                                                                    transmit_mode='continuous')
    stream_handles_two_leaf['l3_v6'] = vxlan_obj.create_traffic_item(device_handles = v6_device_handles_two_leaf,
                                                                    endpoints=l3_traffic_endpoints_two_leaf,
                                                                    topo_handles=topo_handles,
                                                                    version = "ipv6",
                                                                    rate_percent=rate_percent,
                                                                    name_prfx='l3_v6',
                                                                    transmit_mode='continuous')
    stream_handles_two_leaf["topo_handles"] = topo_handles

    stream_handles_extra_leaf = {}
    stream_handles_extra_leaf['l2_v4'] = vxlan_obj.create_traffic_item(device_handles = v4_device_handles_extra_leaf,
                                                                      endpoints=l2_traffic_endpoints_extra_leaf,
                                                                      topo_handles=topo_handles,
                                                                      rate_percent=rate_percent,
                                                                      name_prfx='l2_v4',
                                                                      transmit_mode='continuous')
    stream_handles_extra_leaf['l3_v4'] = vxlan_obj.create_traffic_item(device_handles = v4_device_handles_extra_leaf,
                                                                      endpoints=l3_traffic_endpoints_extra_leaf,
                                                                      topo_handles=topo_handles,
                                                                      rate_percent=rate_percent,
                                                                      name_prfx='l3_v4',
                                                                      transmit_mode='continuous')
    stream_handles_extra_leaf['l2_v6'] = vxlan_obj.create_traffic_item(device_handles = v6_device_handles_extra_leaf,
                                                                      endpoints=l2_traffic_endpoints_extra_leaf,
                                                                      topo_handles=topo_handles,
                                                                      version = "ipv6",
                                                                      rate_percent=rate_percent,
                                                                      name_prfx='l2_v6',
                                                                      transmit_mode='continuous')
    stream_handles_extra_leaf['l3_v6'] = vxlan_obj.create_traffic_item(device_handles = v6_device_handles_extra_leaf,
                                                                      endpoints=l3_traffic_endpoints_extra_leaf,
                                                                      topo_handles=topo_handles,
                                                                      version = "ipv6",
                                                                      rate_percent=rate_percent,
                                                                      name_prfx='l3_v6',
                                                                      transmit_mode='continuous')
    stream_handles_extra_leaf["topo_handles"] = topo_handles

    return stream_handles_single_leaf, stream_handles_two_leaf,stream_handles_extra_leaf


def configure_l2l3vni(leaf_nodes):

    vxlan_obj.config_feature(leaf_nodes,'enable_tunnel_counters')
    vxlan_obj.config_feature(leaf_nodes,'loopback')
    vxlan_obj.config_feature(leaf_nodes,'nvo')
    vxlan_obj.config_feature(leaf_nodes,'l2vni')
    vxlan_obj.config_feature(leaf_nodes,'l3vni')
    vxlan_obj.config_feature(leaf_nodes,'add_sag_mac')
    vxlan_obj.config_feature(leaf_nodes,'sag_v4')
    vxlan_obj.config_feature(leaf_nodes,'sag_v6')
    st.wait(30)

def unconfigure_l2l3vni(leaf_nodes):

    st.banner('unconfig')
    vxlan_obj.config_feature(leaf_nodes,'delete_sag_v6')
    vxlan_obj.config_feature(leaf_nodes,'delete_sag_v4')
    vxlan_obj.config_feature(leaf_nodes,'del_sag_mac')
    vxlan_obj.config_feature(leaf_nodes,'delete_bgp_l3vni_config')
    vxlan_obj.config_feature(leaf_nodes,'delete_l3vni')
    vxlan_obj.config_feature(leaf_nodes,'delete_l2vni')
    vxlan_obj.config_feature(leaf_nodes,'delete_vxlan')
    vxlan_obj.config_feature(leaf_nodes,'disable_tunnel_counters')
    vxlan_obj.config_feature(nodes,'delete_loopback')
    st.banner('common cleanup')
    router_preconfig_cleanup()
    # config save
    for dut in st.get_dut_names(): 
        vxlan_obj.config_dut(dut, 'sonic', "sudo config save -y")

def router_preconfig_cleanup():
    vrf_obj.clear_vrf_configuration(st.get_dut_names())
    ip_obj.clear_ip_configuration(st.get_dut_names(), family='all', thread=True, skip_error_check = True)
    vlan_obj.clear_vlan_configuration(st.get_dut_names())

def run_traffic(traffic_handles, check_stats = False):
    traffic_result = {}
    for traffic_type, traffic_items in traffic_handles.items():
        if traffic_type != 'bum' and traffic_type not in ['topo_handles']:
            st.banner("Running {}".format(traffic_type))
            if not check_stats:
                traffic_result[traffic_type] = vxlan_obj.check_traffic(traffic_items, action = "start_check", 
                                                                       stop_start_protocols = "start_only")
            else:
                traffic_result[traffic_type] = vxlan_obj.check_traffic(traffic_items, action = "check")
    return traffic_result

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
        st.report_fail("test_case_failed")

def configure_underlay(nodes):
    vxlan_obj.config_feature(nodes,'loopback')
    vxlan_obj.config_feature(nodes,'bgp_underlay')

def configure_overlay(leaf_nodes):
    vxlan_obj.config_feature(leaf_nodes,'bgp_overlay')

def test_setup():

    try:
        leaf_nodes = ['leaf0','leaf1','leaf2']
        st.banner('configure l2l3vni on all leafs')
        configure_l2l3vni(leaf_nodes)
        st.wait(30)
        st.banner('TGEN PRECONFIG')
        global handles_single_leaf, handles_two_leaf, handles_extra_leaf

        handles_single_leaf, handles_two_leaf, handles_extra_leaf = tgen_preconfig()

        vxlan_obj.get_cli_out(leaf_nodes)
        st.report_pass("test_case_passed")

    except Exception as e:
        st.banner(e)
        st.report_fail("test_case_failed")
        
@pytest.mark.dependency()
def test_single_leaf():
    st.banner("traffic_test_single_leaf_start")
    traffic_result = run_traffic(handles_single_leaf)
    return_result(traffic_result)
    st.banner("traffic_test_single_leaf_end")
 
    
@pytest.mark.dependency(depends=["test_single_leaf"])
def test_two_leaf():

    st.banner('two_leaf Fabric extension start!')
    leaf_nodes = ['leaf0', 'leaf1']
    leaf0_leaf_links = []
    leaf1_leaf_links = []

    for node in leaf_nodes:
        links = st.get_dut_links(node)
        for link in links:
            if 'leaf1' in link and node == 'leaf0':
                leaf0_leaf_links.append(link[0])
            elif 'leaf0' in link and node == 'leaf1':
                leaf1_leaf_links.append(link[0])

    config_unnumbered_leaf0 = vxlan_obj.generate_bgp_unnumbered_config(leaf0_leaf_links)
    vxlan_obj.config_dut(leaf_nodes[0], 'sonic', config_unnumbered_leaf0, add=True)
    config_unnumbered_leaf1 = vxlan_obj.generate_bgp_unnumbered_config(leaf1_leaf_links)
    vxlan_obj.config_dut(leaf_nodes[1], 'sonic', config_unnumbered_leaf1, add=True)
    configure_underlay(leaf_nodes)
    configure_overlay(leaf_nodes)
    bgp_info = vxlan_obj.generate_bgp_underlay_info()
    dir_path = os.path.dirname(os.path.realpath(__file__))
    with open(dir_path + '/' + CONFIGS_FILE) as f:
        config_dict = yaml.load(f, Loader=yaml.FullLoader)

        for node, l3vni_data in config_dict.items():
            if 'leaf' in node and node == 'leaf0' or node == 'leaf1':
                config_out = vxlan_obj.generate_bgp_l3vni_config(l3vni_data,bgp_info[node])
                vxlan_obj.config_dut(node, 'bgp', config_out)
    st.wait(60)
    
    vxlan_obj.get_cli_out(leaf_nodes)
    
    # check stats for leaf0
    st.banner("traffic_check_single_leaf start ")
    traffic_result = run_traffic(handles_single_leaf, check_stats = True) 
    return_result(traffic_result)
    st.banner("traffic_check_single_leaf end")

    # stopping leaf0 traffic
    st.banner('stopping leaf0 traffic')
    tg_handle = handles_single_leaf['topo_handles']['leaf0']['T1D3P1']['tg_handle']
    sing_leaf_stream_list = []
    for traffic_type, values in handles_single_leaf.items():
        if traffic_type not in ['topo_handles']:
            for traffic_item, value2 in values.items():
                sing_leaf_stream_list.append(value2['stream_id'])
    tg_handle.tg_traffic_control(action='stop', stream_handle=sing_leaf_stream_list)

    vxlan_obj.start_stop_protocols(tg_handle,action='stop')
    st.wait(5)
    vxlan_obj.start_stop_protocols(tg_handle,action='start', start_wait=5)
    # regenerate traffic items for leaf0-leaf1 case
    
    st.banner('regenerating traffic items for leaf0-leaf1 case')
    tg_handle = handles_two_leaf['topo_handles']['leaf0']['T1D3P1']['tg_handle']
    stream_list = []
    for traffic_type, values in handles_single_leaf.items():
        if traffic_type not in ['topo_handles']:
            for traffic_item, value2 in values.items():
                stream_list.append(value2['stream_id'])
    for traffic_type, values in handles_two_leaf.items():
        if traffic_type not in ['topo_handles']:
            for traffic_item, value2 in values.items():
                stream_list.append(value2['stream_id'])
    tg_handle.tg_traffic_control(action='regenerate', stream_handle=stream_list)
    st.wait(20)
    tg_handle.tg_traffic_control(action='apply', stream_handle=stream_list)
    st.wait(20)
    # run traffic between leaf0 - leaf1
    st.banner("traffic_test_two_leaf start")
    traffic_result = run_traffic(handles_two_leaf)
    result = return_result(traffic_result)
    
    st.banner("traffic_test_two_leaf end")
    st.banner('two_leaf Fabric extension end')

    #start traffic on leaf0 within leaf0
    traffic_result = run_traffic(handles_single_leaf)
    return_result(traffic_result)

@pytest.mark.dependency(depends=["test_two_leaf"])
def test_2s2l_leaf_traffic_via_leaf():

    spine_nodes = []
    for node in nodes:
        if 'spine' in node:
            spine_nodes.append(node)
    
    vxlan_obj.config_feature(spine_nodes,'loopback')

    # extracting intf. for 'use-link-local-only' on spines to leafs (leaf0, leaf1)
    spine0_leaf_links = []
    spine1_leaf_links = []

    for node in spine_nodes:
        if node == 'spine0':
            links = st.get_dut_links(node)
        elif node == 'spine1':
            links = st.get_dut_links(node)

        for link in links:
            if 'leaf0' in link or 'leaf1' in link:
                if node == 'spine0':
                    spine0_leaf_links.append(link[0])
                elif node == 'spine1':
                    spine1_leaf_links.append(link[0])

    config_unnumbered_spine0 = vxlan_obj.generate_bgp_unnumbered_config(spine0_leaf_links)
    vxlan_obj.config_dut(spine_nodes[0], 'sonic', config_unnumbered_spine0, add=True)
    config_unnumbered_spine1 = vxlan_obj.generate_bgp_unnumbered_config(spine1_leaf_links)
    vxlan_obj.config_dut(spine_nodes[1], 'sonic', config_unnumbered_spine1, add=True)

    configure_underlay(spine_nodes)

    # extracting intf. for 'use-link-local-only' on leafs (leaf0, leaf1) to spines
    leaf_nodes = ['leaf0', 'leaf1']

    leaf0_spine_links = []
    leaf1_spine_links = []

    for node in leaf_nodes:
        if node == 'leaf0':
            links = st.get_dut_links(node)
        elif node == 'leaf1':
            links = st.get_dut_links(node)

        for link in links:
            if 'spine0' in link or 'spine1' in link:
                if node == 'leaf0':
                    leaf0_spine_links.append(link[0])
                elif node == 'leaf1':
                    leaf1_spine_links.append(link[0])

    config_unnumbered_leaf0 = vxlan_obj.generate_bgp_unnumbered_config(leaf0_spine_links)
    vxlan_obj.config_dut(leaf_nodes[0], 'sonic', config_unnumbered_leaf0, add=True)
    config_unnumbered_leaf1 = vxlan_obj.generate_bgp_unnumbered_config(leaf1_spine_links)
    vxlan_obj.config_dut(leaf_nodes[1], 'sonic', config_unnumbered_leaf1, add=True)

    bgp_info = vxlan_obj.generate_bgp_underlay_info()

    for node in leaf_nodes:
        as_num = bgp_info[node]['as_num']
        cmd = "router bgp {}\n".format(as_num)
        if node == 'leaf0':
            for link in leaf0_spine_links:
                cmd += "neighbor {} interface peer-group TRANSIT\n".format(link)
        elif node == 'leaf1':
            for link in leaf1_spine_links:
                cmd += "neighbor {} interface peer-group TRANSIT\n".format(link)
        vxlan_obj.config_dut(node, 'bgp', cmd, add=True)

    #check traffic -->still leaf0 leaf1 underlay is best path
    st.banner("traffic_test_two_leaf start underlay between leaf0 and leaf1 still up -->start")
    traffic_result = run_traffic(handles_two_leaf, check_stats = True) 
    st.banner("traffic_test_two_leaf end underlay between leaf0 and leaf1 still up -->end")
    vxlan_obj.get_cli_out(leaf_nodes)
    return_result(traffic_result)
    

@pytest.mark.dependency(depends=["test_2s2l_leaf_traffic_via_leaf"])
def test_2s2l_traffic_via_spine():
    #remove the underlay between leaf0 and leaf1
    leaf_nodes = ['leaf0', 'leaf1']
    leaf0_leaf_links = []
    leaf1_leaf_links = []

    for node in leaf_nodes:
        links = st.get_dut_links(node)
        for link in links:
            if 'leaf1' in link and node == 'leaf0':
                leaf0_leaf_links.append(link[0])
            elif 'leaf0' in link and node == 'leaf1':
                leaf1_leaf_links.append(link[0])

    bgp_info = vxlan_obj.generate_bgp_underlay_info()
    leaf0_spine_links = []
    leaf1_spine_links = []
    for node in leaf_nodes:
        as_num = bgp_info[node]['as_num']
        cmd = "router bgp {}\n".format(as_num)
        if node == 'leaf0':
            for link in leaf0_leaf_links:
                cmd += "no neighbor {} interface peer-group TRANSIT\n".format(link)
        elif node == 'leaf1':
            for link in leaf1_leaf_links:
                cmd += "no neighbor {} interface peer-group TRANSIT\n".format(link)
        vxlan_obj.config_dut(node, 'bgp', cmd, add=True)


    vxlan_obj.get_cli_out(leaf_nodes)

    
    # check stats for traffic between leaf0-leaf1
    st.banner("traffic_test_two_leaf start -->traffic over spine--> start")
    traffic_result = run_traffic(handles_two_leaf, check_stats = True)
    return_result(traffic_result)
    st.banner("traffic_test_two_leaf end -->traffic over spine -->end")
    

    # check stats for traffic on leaf0
    st.banner("traffic_check_single_leaf start")
    traffic_result = run_traffic(handles_single_leaf, check_stats = True) 
    return_result(traffic_result)
    st.banner("traffic_check_single_leaf end")

    st.banner('two_spine_two_leaf Fabric extension end')

def test_leaf_addition():
    st.banner('leaf addition Fabric extension start')

    leaf_nodes = ['leaf2']
    '''
    # stopping leaf0 and leaf0-leaf1 Traffic/Traffic Items
    tg_handle = stream_handles_single_leaf['topo_handles']['leaf0']['T1D3P1']['tg_handle']
    stream_list = []
    for traffic_type, values in stream_handles_single_leaf.items():
        if traffic_type not in ['topo_handles', 'v4_device_handles', 'v6_device_handles', 'v4_host_info_dict', 'v6_host_info_dict']:
            for traffic_item, value2 in values.items():
                stream_list.append(value2['stream_id'])
    for traffic_type, values in stream_handles_two_leaf.items():
        if traffic_type != 'topo_handles':
            for traffic_item, value2 in values.items():
                stream_list.append(value2['stream_id'])
    tg_handle.tg_traffic_control(action='stop', stream_handle=stream_list)

    # handles_extra_leaf = tgen_preconfig_extra_leaf()

    st.banner("traffic_test_single_leaf_start")
    traffic_result = run_traffic(handles_single_leaf)
    return_result(traffic_result)

    st.banner("traffic_test_two_leaf_start")
    traffic_result = run_traffic(handles_two_leaf)
    return_result(traffic_result)
    '''
    # code for extracting intf. for 'use-link-local-only' on leaf2
    leaf2_spine_links = [] # ['Ethernet1_1', 'Ethernet1_2']

    links = st.get_dut_links(leaf_nodes[0]) # [['Ethernet1_1', 'spine0', 'Ethernet1_3'], ['Ethernet1_2', 'spine1', 'Ethernet1_3']]
    for link in links:
        if 'spine0' in link or 'spine1' in link:
            leaf2_spine_links.append(link[0])

    config_unnumbered_leaf2 = vxlan_obj.generate_bgp_unnumbered_config(leaf2_spine_links)
    vxlan_obj.config_dut(leaf_nodes[0], 'sonic', config_unnumbered_leaf2, add=True)

    # underlay 
    configure_underlay(leaf_nodes)

    # overlay
    configure_overlay(leaf_nodes)

    bgp_info = vxlan_obj.generate_bgp_underlay_info()

    # l3vni_data extraction for "generate_bgp_l3vni_config" proc.
    dir_path = os.path.dirname(os.path.realpath(__file__))
    with open(dir_path + '/' + CONFIGS_FILE) as f:
        config_dict = yaml.load(f, Loader=yaml.FullLoader)

        for node, l3vni_data in config_dict.items():
            if 'leaf' in node and node == 'leaf2':
                config_out = vxlan_obj.generate_bgp_l3vni_config(l3vni_data,bgp_info[node])
                vxlan_obj.config_dut(node, 'bgp', config_out)
    
    spine_nodes = [] # ['spine0', 'spine1']n
    for node in nodes:
        if 'spine' in node:
            spine_nodes.append(node)

    # extracting intf. for 'use-link-local-only' on spines to leafs (leaf0, leaf1)
    spine0_leaf2_links = [] # ['Ethernet1_3']
    spine1_leaf2_links = [] # ['Ethernet1_3']

    for node in spine_nodes:
        if node == 'spine0':
            links = st.get_dut_links(node)
        elif node == 'spine1':
            links = st.get_dut_links(node)

        for link in links:
            if 'leaf2' in link:
                if node == 'spine0':
                    spine0_leaf2_links.append(link[0])
                elif node == 'spine1':
                    spine1_leaf2_links.append(link[0])

    config_unnumbered_spine0 = vxlan_obj.generate_bgp_unnumbered_config(spine0_leaf2_links)
    vxlan_obj.config_dut(spine_nodes[0], 'sonic', config_unnumbered_spine0, add=True)
    config_unnumbered_spine1 = vxlan_obj.generate_bgp_unnumbered_config(spine1_leaf2_links)
    vxlan_obj.config_dut(spine_nodes[1], 'sonic', config_unnumbered_spine1, add=True)

    bgp_info = vxlan_obj.generate_bgp_underlay_info()

    # leaf2 TRANSIT intfs. towards spine0/1
    as_num = bgp_info[leaf_nodes[0]]['as_num']
    cmd = "router bgp {}\n".format(as_num)
    for link in leaf2_spine_links:
        cmd += "neighbor {} interface peer-group TRANSIT\n".format(link)
    cmd += "neighbor OVERLAY ebgp-multihop 255\n"
    vxlan_obj.config_dut(leaf_nodes[0], 'bgp', cmd, add=True)

    
    # need to add vtep IP into peer-group overlay on all leafs        
    vtep_addr = vxlan_obj.generate_bgp_overlay_info(version='v6')
        
    leaf_nodes = ['leaf0', 'leaf1', 'leaf2']
    for node in leaf_nodes:
        as_num = bgp_info[node]['as_num']
        remote_vtep = vtep_addr[node]['neigbor_overlay']
        if node == 'leaf2':
            cmd = "router bgp {}\n".format(as_num)
            for vtep in remote_vtep:
                cmd += "neighbor {} peer-group OVERLAY\n".format(vtep)
        if node == 'leaf1':
            cmd = "router bgp {}\n".format(as_num)
            for vtep in remote_vtep:
                cmd += "neighbor {} peer-group OVERLAY\n".format(vtep)
        if node == 'leaf0':
            cmd = "router bgp {}\n".format(as_num)
            for vtep in remote_vtep:
                cmd += "neighbor {} peer-group OVERLAY\n".format(vtep)
        vxlan_obj.config_dut(node, 'bgp', cmd, add=True)
    
    st.wait(30)

    vxlan_obj.get_cli_out(leaf_nodes)

    # check stats for leaf0
    st.banner("traffic_check_single_leaf start")
    traffic_result = run_traffic(handles_single_leaf, check_stats = True)
    return_result(traffic_result)
    st.banner("traffic_check_single_leaf end")

    # check stats for leaf0 - leaf1
    st.banner("traffic_check_two_leaf start")
    traffic_result = run_traffic(handles_two_leaf, check_stats = True) 
    return_result(traffic_result)
    st.banner("traffic_check_two_leaf end")

    #stop traffic on leaf0 and bet leaf0 leaf1
    tg_handle = handles_single_leaf['topo_handles']['leaf0']['T1D3P1']['tg_handle']
    stream_list = []
    for traffic_type, values in handles_single_leaf.items():
        if traffic_type not in ['topo_handles']:
            for traffic_item, value2 in values.items():
                stream_list.append(value2['stream_id'])
    for traffic_type, values in handles_two_leaf.items():
        if traffic_type not in ['topo_handles']:
            for traffic_item, value2 in values.items():
                stream_list.append(value2['stream_id'])
    tg_handle.tg_traffic_control(action='stop', stream_handle=stream_list)

    #regen traffic for leaf2 items
    stream_list = []
    for traffic_type, values in handles_extra_leaf.items():
        if traffic_type not in ['topo_handles']:
            for traffic_item, value2 in values.items():
                stream_list.append(value2['stream_id'])
    vxlan_obj.start_stop_protocols(tg_handle,action='stop')
    st.wait(5)
    vxlan_obj.start_stop_protocols(tg_handle,action='start', start_wait=5)
    tg_handle.tg_traffic_control(action='regenerate', stream_handle=stream_list)
    st.wait(20)
    tg_handle.tg_traffic_control(action='apply', stream_handle=stream_list)
    st.wait(20)

    # check stats for leaf0 - leaf2
    st.banner("traffic_check_extra_leaf start")
    traffic_result = run_traffic(handles_extra_leaf) 
    return_result(traffic_result)
    st.banner("traffic_check_extra_leaf end")

def test_common_cleanup():
    try:
        unconfigure_l2l3vni(leaf_nodes)
        bgp_obj.cleanup_router_bgp(nodes)
        st.report_pass("test_case_passed")
    
    except Exception as e:
        st.banner(e)
        st.report_fail("test_case_failed")