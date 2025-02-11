import os
import yaml
import json
import pytest
from spytest import st, tgapi, SpyTestDict
import vxlan_utils as vxlan_obj
import apis.system.basic as basic_obj
import utilities.utils as utils_obj
import tortuga_common_utils as common_obj

##
##  Topology : 2 Spine + 2 Leafs + 2 Host
##
##  SD1 -- Spine0   - D1
##  SD2 -- Spine1   - D2
##
##  SD3 -- Leaf0  - D3
##  SD4 -- Leaf1  - D4
##
##
CONFIGS_FILE = 'vxlan_l2vni_v6_vtep_configs_template.yaml'
ACL_JSON_FILE = "acl_v4_v6_rules.json"
ACL_JSON_FILE_PATH = os.path.dirname(os.path.realpath(__file__)) +  '/' + ACL_JSON_FILE

data = SpyTestDict()
data.my_dut_list = None
data.local = None
data.remote = None
data.d3t1_ip6_addr = "2001::2"
data.t1d3_ip6_addr = "2001::1"
data.t1d3_mac_addr = "00:0a:01:00:11:01"
data.d4t1_ip6_addr = "2001::4"
data.t1d4_ip6_addr = "2001::3"
data.t1d4_mac_addr = "00:0a:01:00:12:01"
data.pkts_per_burst = "500"
data.mask = "24"
data.counters_threshold = 10
data.tgen_stats_threshold = 20
data.tgen_rate_pps = '1000'
data.tgen_l3_len = '500'
data.traffic_run_time = 20
data.clear_parallel = True
data.transmit_mode = "single_burst"
data.rate_percent = "0.01"
data.circuit_endpoint_type = "ipv6"
data.frame_size = "100"
data.vlan_id = "100"
data.acl = {
    'TORTUGA_ACL_INGRESS' : 'L3',
    'TORTUGA_ACL_INGRESS_V6' : 'L3V6'
}

data_v4 = SpyTestDict()
data_v4.t1d3_ip_addr = "1.1.1.1"
data_v4.t1d3_mac_addr = "00:0a:01:00:11:01"
data_v4.t1d4_ip_addr = "1.1.1.2"
data_v4.t1d4_mac_addr = "00:0a:01:00:12:01"
data_v4.transmit_mode = "single_burst"
data_v4.pkts_per_burst = "500"
data_v4.rate_percent = "0.01"
data_v4.circuit_endpoint_type = "ipv4"
data_v4.frame_size = "100"

REMOTE_VTEP_COUNT = '1'
SPINE0_VTEP_IP = 'fd27::2cb:8b5a:196'
SPINE1_VTEP_IP = 'fd27::234:377f:6b3'
LEAF0_VTEP_IP  = 'fd27::280:10f1:25f'
LEAF1_VTEP_IP  = 'fd27::22d:b87f:214b'

def config_node(node, config, type='', skip_errors=False):
    if type:
        st.config(node, config, type=type, skip_error_check = skip_errors, conf=True)
    else:
        st.config(node, config, skip_error_check = skip_errors, conf=True)

def report_fail(dut, msg=''):
    st.log(msg, dut)
    st.error(msg, dut)
    st.report_fail(msg, dut)

def config_static(node, config_domain, add=True):
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    domain = ''
    if config_domain == 'bgp':
        domain = 'vtysh'

    with open(updated_config_file) as c: 
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        if add:
            config_node(nodes[node], config_list[node][config_domain]['config'], domain)
        else:
            config_node(nodes[node], config_list[node][config_domain]['deconfig'], domain, skip_errors=True)

@pytest.fixture(scope='module', autouse=True)
def setup_and_teardown():
    global handles
    global vars
    global nodes

    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2

    global updated_config_file
    updated_config_file = vxlan_obj.modify_config_file(CONFIGS_FILE,vars)

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            config_static(node, 'sonic')
            config_static(node, 'bgp')

    # sleep for 40 seconds for BGP to converge
    st.wait(40)
    ###Get TGEN Handles ###
    handles = vxlan_obj.tgen_preconfig({"src_endpoint": {"port" : "T1D3P1", "host_ip": data.t1d3_ip6_addr, "gateway": data.d3t1_ip6_addr, "mac" : data.t1d3_mac_addr },
                                        "dst_endpoint" : {"port" : "T1D4P1","host_ip": data.t1d4_ip6_addr, "gateway": data.d4t1_ip6_addr, "mac" : data.t1d4_mac_addr }},
                                        "raw",data, 'ipv6')
    if handles == False:
        st.report_fail('tgen preconfig failed')

    yield 'setup_and_teardown'
    
    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            config_static(node, 'bgp', add=False)
            config_static(node, 'sonic', add=False)

    #router_preconfig_cleanup()
    vxlan_obj.remove_temp_config(updated_config_file)

def test_v6_vtep_basic():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    # Test remote vtep status on LEAF0 and LEAF1
    vxlan_obj.verify_vtep_state_v6(nodes, LEAF0_VTEP_IP, LEAF1_VTEP_IP)

    #Traffic Test
    result = run_traffic_test(handles)
    if result:
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')
   
def test_v6_vtep_delete_add_sonic():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    
    st.banner("Removing sonic configs on LEAF0")
    test_node = 'leaf0'
    config_static(test_node, 'sonic', add=False)
    st.wait(10)
    config_static(test_node, 'sonic', add=True)
    st.wait(40)
    st.banner("Restored sonic configs on LEAF0")
    
    vxlan_obj.verify_vtep_state_v6(nodes, LEAF0_VTEP_IP, LEAF1_VTEP_IP)

    result = run_traffic_test(handles)
    if result:
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')
    
def test_v6_vtep_delete_add_bgp():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    st.banner("Removing BGP configs on LEAF1")
    test_node = 'leaf1'
    config_static(test_node, 'bgp', add=False)
    st.wait(10)
    config_static(test_node, 'bgp', add=True)
    st.wait(40)
    st.banner("Restored BGP configs on LEAF1")

    vxlan_obj.verify_vtep_state_v6(nodes, LEAF0_VTEP_IP, LEAF1_VTEP_IP)

    result = run_traffic_test(handles)
    if result:
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')
    
def test_v6_vtep_delete_add_all_configs():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    st.banner("Removed Sonic & BGP configs on LEAF0")
    test_node = 'leaf0'
    config_static(test_node, 'bgp', add=False)
    config_static(test_node, 'sonic', add=False)
    st.wait(10)
    config_static(test_node, 'sonic', add=True)
    config_static(test_node, 'bgp', add=True)
    st.wait(40)
    st.banner("Restored BGP Sonic & configs on LEAF1")

    vxlan_obj.verify_vtep_state_v6(nodes, LEAF0_VTEP_IP, LEAF1_VTEP_IP)

    result = run_traffic_test(handles)
    if result:
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')
 
def test_v6_vtep_port_flap():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    st.banner("Flapping Spine links on LEAF0")
    st.config(nodes['leaf0'], "config interface shutdown {}".format(vars.D3D1P1))
    st.config(nodes['leaf0'], "config interface shutdown {}".format(vars.D3D2P1))
    st.wait(10)
    st.config(nodes['leaf0'], "config interface startup {}".format(vars.D3D1P1))
    st.config(nodes['leaf0'], "config interface startup {}".format(vars.D3D2P1))
    st.wait(40)
    st.banner("Spine links restored on LEAF0")

    vxlan_obj.verify_vtep_state_v6(nodes, LEAF0_VTEP_IP, LEAF1_VTEP_IP)

    result = run_traffic_test(handles)
    if result:
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')

def verify_vlanvnimap(nodes):
    expected_vlanvnimap = {'leaf0': [('Vlan2', '2222'), ('Vlan100', '2727'), ('Vlan3', '3333'), ('Vlan4', '4444')],
            'leaf1': [('Vlan2', '2222'), ('Vlan100', '2727'), ('Vlan3', '3333'), ('Vlan4', '4444')]}
    
    #Convert parsed data to dictionary format
    for k, v in nodes.items():
        cli_output = st.show(nodes[k], "show vxlan vlanvnimap", skip_tmpl=True)
        vlan_vni_mappings = st.parse_show(nodes[k], "show vxlan vlanvnimap",cli_output, "show_vxlan_vlanvnimap.tmpl")
        parsed_out = [[entry['vlan'], entry['vni']] for entry in vlan_vni_mappings]
        if len(parsed_out) == 0:
            st.report_fail('No mapping found', nodes[k])
        
        parsed_dict = {nodes[k]: [(item[0], item[1]) for item in parsed_out]}

        # Check that the leaf exists in the expected data
        if nodes[k] not in expected_vlanvnimap:
            st.error("Leaf {} not found in expected data.".format(nodes[k]))
            st.report_fail('Leaf name {} not in expected data'.format(nodes[k]))

        if len(expected_vlanvnimap[nodes[k]]) != len(parsed_dict[nodes[k]]):
            print("Mismatch in the length of expected data - length {} and parsed data - length {}".format(len(expected_vlanvnimap[nodes[k]]),len(parsed_dict[nodes[k]])))
            st.report_fail("Mismatch in the length of expected data - length {} and parsed data - length {}".format(len(expected_vlanvnimap[nodes[k]]),len(parsed_dict[nodes[k]])))

        # Check that each key-value pair in the parsed data is in the expected data
        for pair in parsed_dict[nodes[k]]:
            if pair not in expected_vlanvnimap[nodes[k]]:
                st.report_fail("Pair {} not found in expected data for {}.".format(pair,nodes[k]))
    st.log("Vlan VNI mapping validated")
 
def test_v6_vtep_multiple_vni():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    l2vni = {'vlan2' : {'vlan' : '2', 'members' : [vars.D3T1P2], 'vni' : '2222'},
             'vlan3' : {'vlan' : '3', 'members' : [vars.D3T1P2], 'vni' : '3333'},
             'vlan4' : {'vlan' : '4', 'members' : [vars.D3T1P2], 'vni' : '4444'}}
    try:
        # Start Configuration
        '''
        a. add vlan
        '''
        for _,value in l2vni.items():
            vxlan_obj.config_vlan(nodes['leaf0'], value['vlan'],  value['members'], tagged=True)
            vxlan_obj.config_vlan(nodes['leaf1'], value['vlan'],  value['members'], tagged=True)

        '''
        b. add vlan to vni map
        '''
        for _,value in l2vni.items():
            vxlan_obj.config_vxlan_map(nodes['leaf0'], 'Vtep', value['vni'], vlan=value['vlan'])
            vxlan_obj.config_vxlan_map(nodes['leaf1'], 'Vtep', value['vni'], vlan=value['vlan'])

        # sleep for 30 seconds for BGP to converge
        st.wait(30)
	#Validate vlan vni mapping control plane
        verify_vlanvnimap(nodes)         

        vxlan_obj.verify_vtep_state_v6(nodes, LEAF0_VTEP_IP, LEAF1_VTEP_IP)

        leaf0_output = st.show(nodes['leaf0'], 'show bgp l2vpn evpn vni', type='vtysh', skip_tmpl=True, skip_error_check=True)
        leaf0_parsed = st.parse_show(nodes['leaf0'], 'show bgp l2vpn evpn vni', leaf0_output, 'show_bgp_l2vpn_evpn_vni.tmpl')

        leaf1_output = st.show(nodes['leaf1'], 'show bgp l2vpn evpn vni', type='vtysh', skip_tmpl=True, skip_error_check=True)
        leaf1_parsed = st.parse_show(nodes['leaf1'], 'show bgp l2vpn evpn vni', leaf1_output, 'show_bgp_l2vpn_evpn_vni.tmpl')

        vlans = ['2222', '3333', '4444', '2727']
        for path in leaf0_parsed:
            if path['vlan_id'] not in vlans:
                report_fail(nodes['leaf0'], msg='Vlan not found')
            if path['vni_type'] != 'L2':
                report_fail(nodes['leaf0'], msg='Vlan Type is not L2')

        for path in leaf1_parsed:
            if path['vlan_id'] not in vlans:
                report_fail(nodes['leaf1'], msg='Vlan not found')
            if path['vni_type'] != 'L2':
                report_fail(nodes['leaf1'], msg='Vlan Type is not L2')

        result = run_traffic_test(handles)
        if result:
            st.report_pass('test_case_passed')
        else:
            st.report_fail('test_case_failed')
    
    except Exception as e:
        report_fail("", msg=e)
    
    finally:
        '''
        b. remove vlan to vni map
        '''
        for _,value in l2vni.items():
            vxlan_obj.config_vxlan_map(nodes['leaf0'], 'Vtep', value['vni'], vlan=value['vlan'], add=False)
            vxlan_obj.config_vxlan_map(nodes['leaf1'], 'Vtep', value['vni'], vlan=value['vlan'], add=False)

        '''
        a. remove vlan
        '''
        for _,value in l2vni.items():
            vxlan_obj.config_vlan(nodes['leaf0'], value['vlan'],  value['members'], add=False)
            vxlan_obj.config_vlan(nodes['leaf1'], value['vlan'],  value['members'], add=False)

def test_v6_vtep_acl():
    st.banner("Config ACL Table")
    for acl_table,acl_table_type in data.acl.items():
        common_obj.create_acl_table(nodes['leaf1'], acl_table, "INGRESS", acl_table_type, "ingress-acl", [vars.D4D1P1,vars.D4D2P1])

    st.banner("Config ACL rules")
    with open(ACL_JSON_FILE_PATH) as file:
        acl_rules_data_string = file.read()

    acl_rules_data_string = set_ip_in_json(acl_rules_data_string)

    with open(ACL_JSON_FILE_PATH, "w") as file:
        file.write(acl_rules_data_string)

    st.log("Copy the Json file to Leaf1")
    utils_obj.copy_files_to_dut(nodes['leaf1'], [ACL_JSON_FILE_PATH], '/home/cisco')
    st.config(nodes['leaf1'], "config acl update full {}".format(ACL_JSON_FILE))
    st.config(nodes['leaf1'], "counterpoll acl enable")

    st.banner("ACL Table")
    st.config(nodes['leaf1'], "show acl table")

    st.banner("ACL Rules")
    st.config(nodes['leaf1'], "show acl rule")

    vxlan_obj.verify_vtep_state_v6(nodes, LEAF0_VTEP_IP, LEAF1_VTEP_IP)

    st.banner("Verify ACL stats for {} Traffic".format('V6 Unknown unicast'))
    result = run_specific_traffic_test('unknownunicast', handles)

    result &= verify_acl_stats(nodes['leaf1'], data.pkts_per_burst)

    st.banner("Verify V6 Host ping over V6 tunnel with V6 ACL configured ")
    result &= vxlan_obj.verify_ping(handles, data.t1d4_ip6_addr)

    st.banner("Verify V4 Host ping over V6 tunnel with V4 ACL configured ")
    handles_v4 = vxlan_obj.tgen_preconfig({"src_endpoint": {"port" : "T1D3P1", "host_ip": data_v4.t1d3_ip_addr, "gateway": data_v4.t1d4_ip_addr, "mac" : data_v4.t1d3_mac_addr }, 
                                        "dst_endpoint" : {"port" : "T1D4P1","host_ip": data_v4.t1d4_ip_addr, "gateway": data_v4.t1d3_ip_addr, "mac" : data_v4.t1d4_mac_addr }},
                                        "raw",data_v4)

    if handles_v4 == False:
        result = False
        st.log('PreConfig failure for V4 over V6')

    st.banner("ACL Cleanup")
    for acl_table,acl_table_type in data.acl.items():
        command = "acl-loader delete {}".format(acl_table)
        st.config(nodes['leaf1'], command)
        common_obj.delete_acl_table(nodes['leaf1'], acl_table_name=acl_table)

    if result:
        st.report_pass('test_case_passed')
    else:
        st.report_fail('test_case_failed')

def set_ip_in_json(acl_rules_data_string):

    leaf1_link_local_address = basic_obj.get_ifconfig_inet6(nodes['leaf1'], vars.D4D1P1)[0].rstrip()
    spine0_link_local_address = basic_obj.get_ifconfig_inet6(nodes['spine0'], vars.D1D4P1)[0].rstrip()
    spine1_link_local_address = basic_obj.get_ifconfig_inet6(nodes['spine1'], vars.D2D4P1)[0].rstrip()

    replacement_dict = {
        "leaf0_vtep_address" : LEAF0_VTEP_IP,
        "leaf1_vtep_address" : LEAF1_VTEP_IP,
        "leaf1_link_local_address" : leaf1_link_local_address,
        "spine0_link_local_address" : spine0_link_local_address,
        "spine1_link_local_address" : spine1_link_local_address
    }
    for ip_string,ip in replacement_dict.items():
        acl_rules_data_string = acl_rules_data_string.replace(ip_string, ip)
    return acl_rules_data_string

def verify_acl_stats(dut, expected_pkts):
    st.config(dut, "aclshow -a")
    command = "sudo -s aclshow -t TORTUGA_ACL_INGRESS_V6 -r RULE_46"
    output = st.show(dut, command)
    if not output:
        st.log("No ACL Counters found for the given table and rule.")
        return False
    if int(output[0]["packetscnt"]) >= int(expected_pkts) and int(output[0]["packetscnt"]) <= 1.04 * int(expected_pkts):
        st.banner("ACL verification passed")
    else : 
        st.banner("ACL verification failed")
        return False
    return True
 
def clear_counters():
    for dut in st.get_dut_names():
        if "leaf" in dut:
            st.config(dut, " sonic-clear counters")
            st.config(dut, " sonic-clear tunnelcounters")
            common_obj.clear_acl_counter(dut)

def get_cli_out():
    cmds = ["show mac", "show arp", "show int counters", "show vxlan counters"]
    for dut in st.get_dut_names():
        if "leaf" in dut:
            for item in cmds:
                output = st.config(dut, item)
                st.log(output)

def run_specific_traffic_test(item, handles):
    clear_counters()
    get_cli_out()
    result = vxlan_obj.traffic_test_burst(item,handles)
    st.wait(5)
    get_cli_out()
    return result

def run_traffic_test(handles):
    # traffic test
    flag = False
    for item in ['unicast', "broadcast", "unknownunicast", "multicast"]:
        result = run_specific_traffic_test(item, handles)
        if result:
            st.banner("{} traffic test passed".format(item))
            flag = True
        else:
            st.banner("{} traffic test failed".format(item))
            flag = False
    return flag
