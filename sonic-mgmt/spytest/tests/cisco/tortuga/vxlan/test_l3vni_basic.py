import os
import yaml
import pytest
from spytest import st, tgapi, SpyTestDict
import apis.routing.ip as ip_obj
import apis.switching.vlan as vlan_obj
import vxlan_utils as vxlan_obj
import time

## config: eBGP + ECMP
##  Topology : 1x Spine + 2 Leafs
##  SD1 -- Spine0  - D1
##  SD2 -- Leaf0   - D3
##  SD4 -- Leaf1   - D4

## tgen Stream Config
data = SpyTestDict()
data.config_vrfs = []
CONFIGS_FILE = 'vxlan_l3vni_config_template.yaml'
LEAF0_VXLAN_IP = '10.200.200.200'
LEAF1_VXLAN_IP = '10.200.200.201'

@pytest.fixture(scope="module", autouse=True)
def initial_setup():
    vars = st.get_testbed_vars()
    ### Check dut is HW or SIM ###
    dut_type = vxlan_obj.check_hw_or_sim(st.get_dut_names()[0])

    if  dut_type == "sim":
        data.transmit_mode = "single_burst"
        data.pkts_per_burst = "500"
        ### Using lower line rate for SIM tgen ###
        data.rate_percent = "0.01"
        data.circuit_endpoint_type = "ipv4"
        data.frame_size = "100"
    else:
        data.mode ="create"
        data.transmit_mode = "single_burst"
        data.pkts_per_burst = "2000"
        data.rate_percent = "10"
        data.circuit_endpoint_type = "ipv4"
        data.frame_size = "1000"
    yield

def config_node(node, config, type=''):
    if type:
        st.config(node, config, type=type, skip_error_check=False, conf=True)
    else:
        st.config(node, config, skip_error_check=False, conf=True)

def config_static(node, config_domain, add=True):
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    domain = ''
    if config_domain == 'bgp':
        domain = 'vtysh'

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        if add:
            config_node(nodes[node], config_list[node][config_domain]['config'], domain)
        else:
            config_node(nodes[node], config_list[node][config_domain]['deconfig'], domain)

def report_fail(dut, msg=''):
    st.log(msg, dut)
    st.error(msg, dut)
    st.report_fail('test_case_failed', dut)

def router_preconfig_cleanup():
    ip_obj.clear_ip_configuration(st.get_dut_names(), family='all', thread=True)
    vlan_obj.clear_vlan_configuration(st.get_dut_names())

#Maintained as a function level fixture since we need to clean up bgp/vrf configs at end of each testcase
@pytest.fixture(scope="function", autouse=True)
def vxlan_config_hooks():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    global updated_config_file
    updated_config_file = vxlan_obj.modify_config_file(CONFIGS_FILE,vars)

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            config_static(node, 'sonic')
            st.wait(2)
            config_static(node, 'bgp')
    yield vxlan_config_hooks

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in reversed(config_list.items()):
            config_static(node, 'bgp', add=False)
            st.wait(2)
            config_static(node, 'sonic', add=False)

    for vrf in data.config_vrfs:
        vxlan_obj.config_vrf(nodes['leaf0'], vrf, add=False)
        vxlan_obj.config_vrf(nodes['leaf1'], vrf, add=False)
    data.config_vrfs = []

    vxlan_obj.remove_temp_config(updated_config_file)


def l3_traffic_test(data, addr_family='ipv4'):

    st.banner("Start to test VxLAN L3  with ping and traffic")
    
    ## Verify Vtep state
    vxlan_obj.verify_vtep_state({"LEAF0_VXLAN_IP":LEAF0_VXLAN_IP,"LEAF1_VXLAN_IP":LEAF1_VXLAN_IP})
    ## Run Traffic: Bi-directional Burst of 100 Packets
    streams_dict = vxlan_obj.traffic_setup(data, 'ipv4')
    st.log(streams_dict)
    result = vxlan_obj.check_traffic(streams_dict)
    
    return result

def unconfigure_nodes(nodes, vrf, leaf0_vlan, leaf0_vlan_ip, leaf1_vlan, leaf1_vlan_ip, dummy_vlan, vni, vars):
    '''
    f. remove IP address on vlan
    '''
    st.config(nodes['leaf0'], 'sudo config interface ip rem {} {}'.format('Vlan' + leaf0_vlan, leaf0_vlan_ip))
    st.config(nodes['leaf1'], 'sudo config interface ip rem {} {}'.format('Vlan' + leaf1_vlan, leaf1_vlan_ip))

    '''
    e. delete vrf to vni map

    d. delete vlan to vni map

    '''
    vxlan_obj.config_vxlan_map(nodes['leaf0'], 'VXLAN', vni, vrf=vrf, vlan=dummy_vlan, add=False)
    vxlan_obj.config_vxlan_map(nodes['leaf1'], 'VXLAN', vni, vrf=vrf, vlan=dummy_vlan, add=False)

    '''
    c. remove dummy vlan
    '''
    vxlan_obj.config_vlan(nodes['leaf0'], dummy_vlan, vrf=vrf, add=False)
    vxlan_obj.config_vlan(nodes['leaf1'], dummy_vlan, vrf=vrf, add=False)

    '''
    b. remove vlan
    '''
    vxlan_obj.config_vlan(nodes['leaf0'], leaf0_vlan, members=[vars.D3T1P1], vrf=vrf, add=False)
    vxlan_obj.config_vlan(nodes['leaf1'], leaf1_vlan, members=[vars.D4T1P1], vrf=vrf, add=False)

    '''
    a. delete vrf
    '''

    data.config_vrfs.append(vrf)

def test_l3vni_basic_config():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
     
    leaf0_vlan_ip = '100.100.100.254/24'
    leaf1_vlan_ip = '100.100.101.254/24'
    leaf0_vlan = '2'
    leaf1_vlan = '3'
    
    vrf = 'Vrf01'
    vni = '1000'
    dummy_vlan = '100'
    
    try:

    	#Start configuration
    	vxlan_obj.configure_nodes(nodes, vrf, leaf0_vlan, leaf0_vlan_ip, leaf1_vlan, leaf1_vlan_ip, dummy_vlan, vni, vars)
    	
    	# Start Verification
    	leaf0_vrf_prefix = '100.100.100.0'
        leaf1_vrf_prefix = '100.100.101.0'
    	
        vxlan_obj.verify_bgp(nodes, leaf1_vrf_prefix, 'leaf0')
        vxlan_obj.verify_bgp(nodes, leaf0_vrf_prefix, 'leaf1')

    	#Run Traffic test
    	data.d3t1_ip_addr = "100.100.100.254"
    	data.t1d3_ip_addr = "100.100.100.1" #Leaf0 Host
    	data.t1d3_mac_addr = "00:0a:01:00:11:01"

    	data.d4t1_ip_addr = "100.100.101.254"
    	data.t1d4_ip_addr = "100.100.101.1" #Leaf1 Host
    	data.t1d4_mac_addr = "00:0a:01:00:12:02"
    
    	result = l3_traffic_test(data, 'ipv4')
    	if result:
            st.report_pass("test_case_passed", "test_l3vni_basic_with_traffic passed")
    	else:
            st.report_fail("test_case_failed", "test_l3vni_basic__with_traffic failed")
      
    except Exception as e:
        report_fail("", msg=e)
    finally:
    	unconfigure_nodes(nodes, vrf, leaf0_vlan, leaf0_vlan_ip, leaf1_vlan, leaf1_vlan_ip, dummy_vlan, vni, vars)


def test_l3vni_multiple_vni():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    vrfs = { 'Vrf02' : { 'vlan' : '2', 'members' : [vars.D3T1P1], 'vni' : '2000', 'dummy_vlan' : '200'},
             'Vrf03' : { 'vlan' : '3', 'members' : [vars.D3T1P2], 'vni' : '3000', 'dummy_vlan' : '300' },
             'Vrf04' : { 'vlan' : '4', 'members' : [vars.D3T1P3], 'vni' : '4000', 'dummy_vlan' : '400' }}

    svi_ips = { 'leaf0' : [ { 'vlan' : '2', 'ip' : '100.100.102.254/24', 'vni' : '2000' },
                            { 'vlan' : '3', 'ip' : '100.100.103.254/24', 'vni' : '3000' },
                            { 'vlan' : '4', 'ip' : '100.100.104.254/24', 'vni' : '4000' } ],
                'leaf1' : [ { 'vlan' : '2', 'ip' : '100.100.112.254/24', 'vni' : '2000' },
                            { 'vlan' : '3', 'ip' : '100.100.113.254/24', 'vni' : '3000' },
                            { 'vlan' : '4', 'ip' : '100.100.114.254/24', 'vni' : '4000' } ]}
    try:
        # Start configuration
        vxlan_obj.config_multiple_vni(nodes, svi_ips, vrfs) 

        # sleep for 60 seconds for BGP to converge
        st.wait(60)
        # Start Verification
        for value in svi_ips['leaf1']:
            prefix = value['ip'].strip('254/24') + '0'
            output = st.show(nodes['leaf0'], 'show bgp l2vpn evpn {}'.format(prefix), type='vtysh', skip_tmpl=True, skip_error_check=True)

            parsed = st.parse_show(nodes['leaf0'], 'show bgp l2vpn evpn {}'.format(prefix),
                               output, 'show_bgp_l2vpn_evpn_prefix.tmpl')

            if len(parsed) == 0:
                report_fail(nodes['leaf0'], msg='Found no prefixes advertised to Leaf0')

            for path in parsed:
                if path['valid'] != 'valid':
                    report_fail(nodes['leaf0'], msg='Invalid path found in leaf0')
                if path['pathevpntype'] != '5':
                    report_fail(nodes['leaf0'], msg='Invalid evpn type {} found in leaf0'.format(path['evpntype']))
                if path['vni'] != value['vni']:
                    report_fail(nodes['leaf0'], msg='Invalid vni found in leaf0')

        for value in svi_ips['leaf0']:
            prefix = value['ip'].strip('254/24') + '0'
            output = st.show(nodes['leaf1'], 'show bgp l2vpn evpn {}'.format(prefix), type='vtysh', skip_tmpl=True, skip_error_check=True)

            parsed = st.parse_show(nodes['leaf1'], 'show bgp l2vpn evpn {}'.format(prefix),
                               output, 'show_bgp_l2vpn_evpn_prefix.tmpl')

            if len(parsed) == 0:
                report_fail(nodes['leaf1'], msg='Found no prefixes advertised to Leaf0')

            for path in parsed:
                if path['valid'] != 'valid':
                    report_fail(nodes['leaf1'], msg='Invalid path found in leaf1')
                if path['pathevpntype'] != '5':
                    report_fail(nodes['leaf1'], msg='Invalid evpn type {} found in leaf1'.format(path['evpntype']))
                if path['vni'] != value['vni']:
                    report_fail(nodes['leaf1'], msg='Invalid vni found in leaf1')
    
        #Run Traffic test
        data.d3t1_ip_addr = "100.100.102.254"
        data.t1d3_ip_addr = "100.100.102.200"
        data.t1d3_mac_addr = "00:0a:01:00:11:01"
    
        data.d4t1_ip_addr = "100.100.112.254"
        data.t1d4_ip_addr = "100.100.112.200"
        data.t1d4_mac_addr = "00:0a:01:00:12:02"
    
        result = l3_traffic_test(data, 'ipv4')
        if result:
            st.report_pass("test_case_passed", "test_l3vni_basic_with_traffic passed")
        else:
            st.report_fail("test_case_failed", "test_l3vni_basic_with_traffic failed")
    except Exception as e:
        report_fail("", msg=e)
    finally:
        vxlan_obj.unconfig_multiple_vni(nodes, svi_ips, vrfs, data)

def test_l3vni_multiple_vni_load():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2

    vrfs = { 'Vrf02' : { 'vlan' : '2', 'members' : [vars.D3T1P1], 'vni' : '2000', 'dummy_vlan' : '200'},
             'Vrf03' : { 'vlan' : '3', 'members' : [vars.D3T1P2], 'vni' : '3000', 'dummy_vlan' : '300' },
             'Vrf04' : { 'vlan' : '4', 'members' : [vars.D3T1P3], 'vni' : '4000', 'dummy_vlan' : '400' }}

    svi_ips = { 'leaf0' : [ { 'vlan' : '2', 'ip' : '100.100.102.254/24', 'vni' : '2000' },
                            { 'vlan' : '3', 'ip' : '100.100.103.254/24', 'vni' : '3000' },
                            { 'vlan' : '4', 'ip' : '100.100.104.254/24', 'vni' : '4000' } ],
                'leaf1' : [ { 'vlan' : '2', 'ip' : '100.100.112.254/24', 'vni' : '2000' },
                            { 'vlan' : '3', 'ip' : '100.100.113.254/24', 'vni' : '3000' },
                            { 'vlan' : '4', 'ip' : '100.100.114.254/24', 'vni' : '4000' } ]}

    try:
        # Start initial configuration
        vxlan_obj.config_multiple_vni(nodes, svi_ips, vrfs)
        '''
        BGP convergence verification is different here because of intermittent failure seen where
        convergence took more time in issue state.
        Logic: Check for 20 iterations of sleep 10 seconds and bail out if it still doesn't converge
        '''
        vxlan_obj.verify_bgp_convergence(nodes, svi_ips, 'leaf0', 'leaf1', 'ipv4')
        vxlan_obj.verify_bgp_convergence(nodes, svi_ips, 'leaf1', 'leaf0', 'ipv4')
    
        '''
        Save config to a file before unconfiguring. The same saved file will be used for load operation
        '''
        for k,v in nodes.items():
            filename = "/tmp/config-db-{}.json".format(k)
            st.config(v, "config save {} -y".format(filename), skip_error_check=True)

        '''
        f. remove IP address on vlan
        '''
        for leaf, value in svi_ips.items():
            for v in value:
                st.config(nodes[leaf], 'sudo config interface ip rem {} {}'.format('Vlan' + v['vlan'], v['ip']))

        '''
        e. delete vrf to vni map

        d. delete vlan to vni map

        '''
        for vrf, value in vrfs.items():
            vxlan_obj.config_vxlan_map(nodes['leaf0'], 'VXLAN', value['vni'], vrf=vrf, vlan=value['dummy_vlan'], add=False)
            vxlan_obj.config_vxlan_map(nodes['leaf1'], 'VXLAN', value['vni'], vrf=vrf, vlan=value['dummy_vlan'], add=False)

        '''
        c. del dummy vlan
        '''
        for vrf, value in vrfs.items():
            vxlan_obj.config_vlan(nodes['leaf0'], value['dummy_vlan'], vrf=vrf, add=False)
            vxlan_obj.config_vlan(nodes['leaf1'], value['dummy_vlan'], vrf=vrf, add=False)

        '''
        b. del vlan
        '''
        for vrf, value in vrfs.items():
            vxlan_obj.config_vlan(nodes['leaf0'], value['vlan'], value['members'], vrf=vrf, add=False)
            vxlan_obj.config_vlan(nodes['leaf1'], value['vlan'], value['members'], vrf=vrf, add=False)

        '''
        Remove BGP before vrf is removed
        '''
        dir_path = os.path.dirname(os.path.realpath(__file__))

        with open(updated_config_file) as c:
            config_list = yaml.load(c, Loader=yaml.FullLoader)
            for node, config in config_list.items():
                if 'spine' not in node:
                    config_static(node, 'bgp', add=False)

        '''
        a. del vrf
        '''
        for vrf, value in vrfs.items():
            vxlan_obj.config_vrf(nodes['leaf0'], vrf, add=False)
            vxlan_obj.config_vrf(nodes['leaf1'], vrf, add=False)

        '''
        Remove SONiC Config too
        '''
        dir_path = os.path.dirname(os.path.realpath(__file__))

        with open(updated_config_file) as c:
            config_list = yaml.load(c, Loader=yaml.FullLoader)
            for node, config in config_list.items():
                if 'spine' not in node:
                    config_static(node, 'sonic', add=False)

        # sleep for 30 seconds for BGP to converge
        st.wait(30)

        ############# Start adding configuration back #############

        '''
        Add BGP back
        '''
        with open(updated_config_file) as c:
            config_list = yaml.load(c, Loader=yaml.FullLoader)
            for node, config in config_list.items():
                if 'spine' not in node:
                    config_static(node, 'bgp')

        '''
        Now load config from already saved config file
        '''
        for k,v in nodes.items():
            filename = "/tmp/config-db-{}.json".format(k)
            st.config(v, "config load {} -y".format(filename), skip_error_check=True)

        vxlan_obj.verify_bgp_convergence(nodes, svi_ips, 'leaf0', 'leaf1', 'ipv4')
        vxlan_obj.verify_bgp_convergence(nodes, svi_ips, 'leaf1', 'leaf0', 'ipv4')

        #Run Traffic test
        # Run Traffic: Bi-directional Ping and Burst of 500 Packet
        data.d3t1_ip_addr = "100.100.102.254"
        data.t1d3_ip_addr = "100.100.102.200"
        data.t1d3_mac_addr = "00:0a:01:00:11:01"

        data.d4t1_ip_addr = "100.100.112.254"
        data.t1d4_ip_addr = "100.100.112.200"
        data.t1d4_mac_addr = "00:0a:01:00:12:02"

        result = l3_traffic_test(data, 'ipv4')
        if result:
            st.report_pass("test_case_passed", "test_l3vni_basic_with_traffic passed")
        else:
            st.report_fail("test_case_failed", "test_l3vni_basic__with_traffic failed")

    except Exception as e:
        report_fail("", msg=e)
    finally:
        vxlan_obj.unconfig_multiple_vni(nodes, svi_ips, vrfs, data)

@pytest.mark.skip(reason="Delete VRF, puts Leaf0 in a bad state")
def test_l3vni_remove_add_bgp():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2

    leaf0_vlan_ip = '100.100.100.254/24'
    leaf1_vlan_ip = '100.100.101.254/24'

    leaf0_vlan = '2'
    leaf1_vlan = '3'

    vrf = 'Vrf01'
    vni = '1000'
    dummy_vlan = '100'
    try:
        # Start configuration
        vxlan_obj.configure_nodes(nodes, vrf, leaf0_vlan, leaf0_vlan_ip, leaf1_vlan, leaf1_vlan_ip, dummy_vlan, vni, vars)

        # Start Verification
        leaf0_vrf_prefix = '100.100.100.0'
        leaf1_vrf_prefix = '100.100.101.0'

        vxlan_obj.verify_bgp(nodes, leaf1_vrf_prefix, 'leaf0')
        vxlan_obj.verify_bgp(nodes, leaf0_vrf_prefix, 'leaf1')

        #######
        # a. Remove vrf vni mapping
        # b. Remove BGP
        # c. Check if the routes are withdrawn
        # d. Add vrf vni mapping
        # e. Add BGP
        # f. Check if the routes are back
        ######
        '''
        a. Remove l3vni mapping
        '''
        vxlan_obj.config_vxlan_map(nodes['leaf0'], 'VXLAN', vni, vrf=vrf, vlan=dummy_vlan, add=False)
        vxlan_obj.config_vxlan_map(nodes['leaf1'], 'VXLAN', vni, vrf=vrf, vlan=dummy_vlan, add=False)

        '''
        b. Remove BGP
        '''
        dir_path = os.path.dirname(os.path.realpath(__file__))

        with open(updated_config_file) as c:
            config_list = yaml.load(c, Loader=yaml.FullLoader)
            for node, config in config_list.items():
                if 'spine' not in node:
                    config_static(node, 'bgp', add=False)

        # sleep for 60 seconds for BGP to converge
        st.wait(60)

        '''
        c. Check if the routes are withdrawn
        '''
        # Start Verification
        leaf0_vrf_prefix = '100.100.100.0'
        leaf1_vrf_prefix = '100.100.101.0'

        leaf0_output = st.show(nodes['leaf0'], 'show bgp l2vpn evpn {}'.format(leaf1_vrf_prefix), type='vtysh', skip_tmpl=True, skip_error_check=True)

        leaf1_output = st.show(nodes['leaf1'], 'show bgp l2vpn evpn {}'.format(leaf0_vrf_prefix), type='vtysh', skip_tmpl=True, skip_error_check=True)

        if 'No BGP process is configured' not in leaf0_output:
            report_fail(nodes['leaf0'], msg='Found prefixes {}'.format(leaf0_output))

        if 'No BGP process is configured' not in leaf1_output:
            report_fail(nodes['leaf1'], msg='Found prefixes {}'.format(leaf1_output))

        '''
        d. add vlan to vni map
        '''
        vxlan_obj.config_vxlan_map(nodes['leaf0'], 'VXLAN', vni, vrf=vrf, vlan=dummy_vlan)
        vxlan_obj.config_vxlan_map(nodes['leaf1'], 'VXLAN', vni, vrf=vrf, vlan=dummy_vlan)

        '''
        e. Add BGP
        '''
        with open(updated_config_file) as c:
            config_list = yaml.load(c, Loader=yaml.FullLoader)
            for node, config in config_list.items():
                if 'spine' not in node:
                    config_static(node, 'bgp')

        '''
        f. Check if the routes are back
        '''
        # Start Verification
        leaf0_vrf_prefix = '100.100.100.0'
        leaf1_vrf_prefix = '100.100.101.0'

        vxlan_obj.verify_bgp(nodes, leaf1_vrf_prefix, 'leaf0')
        vxlan_obj.verify_bgp(nodes, leaf0_vrf_prefix, 'leaf1')

        #Tgen Stream Config
        data.d3t1_ip_addr = "100.100.100.254"
        data.t1d3_ip_addr = "100.100.100.1" #leaf0 host
        data.t1d3_mac_addr = "00:0a:01:00:11:01"

        data.d4t1_ip_addr = "100.100.101.254"
        data.t1d4_ip_addr = "100.100.101.1" #Leaf1 Host
        data.t1d4_mac_addr = "00:0a:01:00:12:02" 

        result = l3_traffic_test(data, 'ipv4')
        if result:
            st.report_pass("test_case_passed", "test_l3vni_basic_with_traffic passed")
        else:
            st.report_fail("test_case_failed", "test_l3vni_basic__with_traffic failed")
    except Exception as e:
        report_fail("", msg=e)
    finally:
        unconfigure_nodes(nodes, vrf, leaf0_vlan, leaf0_vlan_ip, leaf1_vlan, leaf1_vlan_ip, dummy_vlan, vni, vars)
