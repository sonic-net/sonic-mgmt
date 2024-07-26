import os
import yaml
import pytest
from spytest import st, tgapi, SpyTestDict
import apis.routing.ip as ip_obj
import apis.switching.vlan as vlan_obj
import vxlan_utils as vxlan_obj
import time

## config: eBGP + ECMP
##  Topology : 2x Spine + 2 Leafs
##
##  SD1 -- Spine0  - D1
##  SD1 -- Spine1  - D2
##  SD2 -- Leaf0   - D3
##  SD4 -- Leaf1   - D4

## tgen Stream Config
data = SpyTestDict()
data.config_vrfs = []

data.my_dut_list = None
data.local = None
data.remote = None

NO_OF_RETRIES = 9 

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
        data.circuit_endpoint_type = "ipv6"
        data.frame_size = "100"
    else:
        data.mode ="create"
        data.transmit_mode = "single_burst"
        data.pkts_per_burst = "2000"
        data.rate_percent = "10"
        data.circuit_endpoint_type = "ipv6"
        data.frame_size = "1000"
    yield

data.d3t1_ip_addr = "100.100.100.254"
data.t1d3_ip_addr = "100.100.100.200"
data.d3t1_ip6_addr = "2002:db8:1::1"
data.t1d3_ip6_addr = "2002:db8:1::2"
data.t1d3_mac_addr = "00:0a:01:00:11:01"

data.d4t1_ip_addr = "100.100.101.254"
data.t1d4_ip_addr = "100.100.101.200"
data.d4t1_ip6_addr = "2003:db8:1::1"
data.t1d4_ip6_addr = "2003:db8:1::2"
data.t1d4_mac_addr = "00:0a:01:00:12:01"
data.pkts_per_burst = "500"
data.mask = "24"
data.counters_threshold = 10
data.tgen_stats_threshold = 20
data.tgen_rate_pps = '1000'
data.tgen_l3_len = '500'
data.traffic_run_time = 20
data.clear_parallel = True

REMOTE_VTEP_COUNT = '1'
SPINE0_VTEP_IP = '2001:db8:1::1'
LEAF0_VTEP_IP  = '2001:db8:1::2'
LEAF1_VTEP_IP  = '2001:db8:1::3'

CONFIGS_FILE = 'vxlan_l3vni_v6_vtep_config_template.yaml'

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
    st.wait(60)
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

def verify_vtep_state(nodes):
    '''
    root@sonic:/home/cisco# show vxlan remotevtep
    +---------------------+--------------------+-------------------+--------------+
    | SIP                 | DIP                | Creation Source   | OperStatus   |
    +=====================+====================+===================+==============+
    | fd27::22d:b87f:214b | fd27::280:10f1:25f | EVPN              | oper_up      |
    +---------------------+--------------------+-------------------+--------------+
    Total count : 1

    '''
    for node in ['leaf0', 'leaf1']:
        dut = nodes[node]
        expected_sip = LEAF0_VTEP_IP if node == 'leaf0' else LEAF1_VTEP_IP
        expected_dip = LEAF1_VTEP_IP if node == 'leaf0' else LEAF0_VTEP_IP
        
        output = st.config(dut, "show vxlan remotevtep")
        output_parsed = st.parse_show(dut, "show vxlan remotevtep", output, "show_vxlan_remote.tmpl")
        iter = 0
        for vtep in output_parsed:
            start_time = time.time()
            while vtep['tun_status'] != 'oper_up' and iter < NO_OF_RETRIES:
                iter += 1
                st.wait(10)
                output = st.config(dut, "show vxlan remotevtep")
                output_parsed = st.parse_show(dut, "show vxlan remotevtep", output, "show_vxlan_remote.tmpl")
                vtep = output_parsed[0]
            
            if iter == NO_OF_RETRIES:
                end_time = time.time()
                iter = 0
                if vtep['tun_status'] == 'oper_down':
                    st.log("Tunnel State is not Up after {} secs".format(end_time - start_time))
                    report_fail(dut, msg='Tunnel State is not up. Status : oper_down')
                else:
                    st.log("Tunnel State is not set after {} secs".format(end_time - start_time))
                    report_fail(dut, msg='Tunnel State is not set')
            
            #Test 1: Verify if the State is UP - oper_up 
            if vtep['tun_status'] == 'oper_up':
                end_time = time.time()
                st.log("Tunnel State is up after {} secs Status : oper_up" .format(end_time-start_time), dut)
            # Test 2: Verify SIP and DIP
            if vtep['src_vtep'] == expected_sip:
                st.log("Source vtep validated", dut)
            else:
                report_fail(dut, msg='Source vtep is not as expected. Found {} Expected {}'.format(vtep['src_vtep'], expected_sip))
            if vtep['dst_vtep'] == expected_dip:
                st.log("Destination vtep validated", dut)
            else:
                report_fail(dut, msg='Source vtep is not as expected. Found {} Expected {}'.format(vtep['dst_vtep'], expected_dip))

            # Test 3: Verify if the Total Count is 1
            if vtep['total_count'] == REMOTE_VTEP_COUNT:
                st.log("All remote VTEPs detected", dut)
            else:
                report_fail(dut, msg='Remote Vteps discovered count not as expected. Found {} Expected {}'.format(vtep['total_count'], REMOTE_VTEP_COUNT))

def configure_and_validate_basic_l3vni(overlay_afamily):
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2

    if overlay_afamily == 'ipv6':
        leaf0_vlan_ip = '2002:db8:1::1/64'
        leaf1_vlan_ip = '2003:db8:1::1/64'
    else:
        leaf0_vlan_ip = '100.100.100.254/24'
        leaf1_vlan_ip = '100.100.101.254/24'

    leaf0_vlan = '2'
    leaf1_vlan = '3'

    vrf = 'Vrf01'
    vni = '1000'
    dummy_vlan = '100'

    # Start configuration
    '''
    a. add vrf
    '''
    vxlan_obj.config_vrf(nodes['leaf0'], vrf)
    vxlan_obj.config_vrf(nodes['leaf1'], vrf)

    '''
    b. add vlan
    '''
    vxlan_obj.config_vlan(nodes['leaf0'], leaf0_vlan, members=[vars.D3T1P1], vrf=vrf)
    vxlan_obj.config_vlan(nodes['leaf1'], leaf1_vlan, members=[vars.D4T1P1], vrf=vrf)

    '''
    c. add dummy vlan
    '''
    vxlan_obj.config_vlan(nodes['leaf0'], dummy_vlan, vrf=vrf)
    vxlan_obj.config_vlan(nodes['leaf1'], dummy_vlan, vrf=vrf)

    '''
    d. add vlan to vni map

    e. add vrf to vni map
    '''
    vxlan_obj.config_vxlan_map(nodes['leaf0'], 'VXLAN', vni, vrf=vrf, vlan=dummy_vlan)
    vxlan_obj.config_vxlan_map(nodes['leaf1'], 'VXLAN', vni, vrf=vrf, vlan=dummy_vlan)

    '''
    f. add IP address on vlan
    '''
    st.config(nodes['leaf0'], 'sudo config interface ip add {} {}'.format('Vlan' + leaf0_vlan, leaf0_vlan_ip))
    st.config(nodes['leaf1'], 'sudo config interface ip add {} {}'.format('Vlan' + leaf1_vlan, leaf1_vlan_ip))

    # Start Verification
    if overlay_afamily == 'ipv6':
        leaf0_vrf_prefix = '2002:db8:1::'
        leaf1_vrf_prefix = '2003:db8:1::'
    else:
        leaf0_vrf_prefix = '100.100.100.0'
        leaf1_vrf_prefix = '100.100.101.0'

    vxlan_obj.verify_bgp(nodes, leaf1_vrf_prefix, 'leaf0')
    vxlan_obj.verify_bgp(nodes, leaf0_vrf_prefix, 'leaf1')

def deconfigure_basic_l3vni(overlay_afamily):
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2

    if overlay_afamily == 'ipv6':
        leaf0_vlan_ip = '2002:db8:1::1/64'
        leaf1_vlan_ip = '2003:db8:1::1/64'
    else:
        leaf0_vlan_ip = '100.100.100.254/24'
        leaf1_vlan_ip = '100.100.101.254/24'

    leaf0_vlan = '2'
    leaf1_vlan = '3'

    vrf = 'Vrf01'
    vni = '1000'
    dummy_vlan = '100'

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

# v6 over v6 tests
def test_l3vni_v6_v6_vtep_basic_config():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2

    try:
        #Configure and Validate basic l3vni configs and route exchanges
        configure_and_validate_basic_l3vni('ipv6')

        #Run traffic test
        data.d3t1_ip6_addr = "2002:db8:1::1"
        data.t1d3_ip6_addr = "2002:db8:1::2"
        data.d4t1_ip6_addr = "2003:db8:1::1"
        data.t1d4_ip6_addr = "2003:db8:1::2"
    
        st.banner("Start to test VxLAN V6 L3 with ping and traffic")
    
        #Test remote vtep status on LEAF0 and LEAF1
        verify_vtep_state(nodes)
        ##Run Traffic: Bi-directional Burst of 100 Packets
        streams_dict = vxlan_obj.traffic_setup(data, 'ipv6')
        st.log(streams_dict)
        result = vxlan_obj.check_traffic(streams_dict)

        if result:
            st.report_pass("test_case_passed", "test_l3vni_v6_v6_vtep_basic_config passed")
        else:
            st.report_fail("test_case_failed", "test_l3vni_v6_v6_vtep_basic_config failed")

    except Exception as e:
        report_fail("", msg=e)
    finally:
        #Deconfigure basic l3vni configs
        deconfigure_basic_l3vni('ipv6')
   
def test_l3vni_v6_v6_vtep_multiple_vni():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2

    vrfs = { 'Vrf02' : { 'vlan' : '2', 'members' : [vars.D3T1P1], 'vni' : '2000', 'dummy_vlan' : '200'},
             'Vrf03' : { 'vlan' : '3', 'members' : [vars.D3T1P2], 'vni' : '3000', 'dummy_vlan' : '300' },
             'Vrf04' : { 'vlan' : '4', 'members' : [vars.D3T1P3], 'vni' : '4000', 'dummy_vlan' : '400' }}

    svi_ips = { 'leaf0' : [ { 'vlan' : '2', 'ip' : '2002:db8:1::1/64', 'vni' : '2000' },
                            { 'vlan' : '3', 'ip' : '2003:db8:1::1/64', 'vni' : '3000' },
                            { 'vlan' : '4', 'ip' : '2004:db8:1::1/64', 'vni' : '4000' } ],
                'leaf1' : [ { 'vlan' : '2', 'ip' : '2112:db8:1::1/64', 'vni' : '2000' },
                            { 'vlan' : '3', 'ip' : '2113:db8:1::1/64', 'vni' : '3000' },
                            { 'vlan' : '4', 'ip' : '2114:db8:1::1/64', 'vni' : '4000' } ]}
    try:
        #Start configuration
        vxlan_obj.config_multiple_vni(nodes, svi_ips, vrfs)

        #Start Verification
        vxlan_obj.verify_bgp_convergence(nodes, svi_ips, 'leaf0', 'leaf1', 'ipv6')
        vxlan_obj.verify_bgp_convergence(nodes, svi_ips, 'leaf0', 'leaf1', 'ipv6')

        st.banner("Start to test VxLAN V6 L3 with ping and traffic inter leaf")
    
        #Run traffic test
        data.d3t1_ip6_addr = "2002:db8:1::1"
        data.t1d3_ip6_addr = "2002:db8:1::2"
        data.d4t1_ip6_addr = "2112:db8:1::1"
        data.t1d4_ip6_addr = "2112:db8:1::2"

        st.banner("Start to test VxLAN V6 L3 with ping and traffic")

        #Test remote vtep status on LEAF0 and LEAF1
        verify_vtep_state(nodes)
        ##Run Traffic: Bi-directional Burst of 100 Packets
        streams_dict = vxlan_obj.traffic_setup(data, 'ipv6')
        st.log(streams_dict)
        result = vxlan_obj.check_traffic(streams_dict)

        if result:
            st.report_pass("test_case_passed", "test_l3vni_v6_v6_vtep_multiple_vni passed")
        else:
            st.report_fail("test_case_failed", "test_l3vni_v6_v6_vtep_multiple_vni failed")
    
    except Exception as e:
        report_fail("", msg=e)
    finally:
        vxlan_obj.unconfig_multiple_vni(nodes, svi_ips, vrfs, data)

def test_l3vni_v6_v6_vtep_multiple_vni_load():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2

    vrfs = { 'Vrf02' : { 'vlan' : '2', 'members' : [vars.D3T1P1], 'vni' : '2000', 'dummy_vlan' : '200'},
             'Vrf03' : { 'vlan' : '3', 'members' : [vars.D3T1P2], 'vni' : '3000', 'dummy_vlan' : '300' },
             'Vrf04' : { 'vlan' : '4', 'members' : [vars.D3T1P3], 'vni' : '4000', 'dummy_vlan' : '400' }}

    svi_ips = { 'leaf0' : [ { 'vlan' : '2', 'ip' : '2002:db8:1::1/64', 'vni' : '2000' },
                            { 'vlan' : '3', 'ip' : '2003:db8:1::1/64', 'vni' : '3000' },
                            { 'vlan' : '4', 'ip' : '2004:db8:1::1/64', 'vni' : '4000' } ],
                'leaf1' : [ { 'vlan' : '2', 'ip' : '2112:db8:1::1/64', 'vni' : '2000' },
                            { 'vlan' : '3', 'ip' : '2113:db8:1::1/64', 'vni' : '3000' },
                            { 'vlan' : '4', 'ip' : '2114:db8:1::1/64', 'vni' : '4000' } ]}

    try:
        #Start configuration
        vxlan_obj.config_multiple_vni(nodes, svi_ips, vrfs)

        #Start Verification
        vxlan_obj.verify_bgp_convergence(nodes, svi_ips, 'leaf0', 'leaf1', 'ipv6')
        vxlan_obj.verify_bgp_convergence(nodes, svi_ips, 'leaf0', 'leaf1', 'ipv6')

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

        #sleep for 30 seconds for BGP to converge
        st.wait(60)

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

        #Start Verification
        vxlan_obj.verify_bgp_convergence(nodes, svi_ips, 'leaf0', 'leaf1', 'ipv6')
        vxlan_obj.verify_bgp_convergence(nodes, svi_ips, 'leaf0', 'leaf1', 'ipv6')

        #Run traffic test
        data.d3t1_ip6_addr = "2002:db8:1::1"
        data.t1d3_ip6_addr = "2002:db8:1::2"
        data.d4t1_ip6_addr = "2112:db8:1::1"
        data.t1d4_ip6_addr = "2112:db8:1::2"

        st.banner("Start to test VxLAN V6 L3 with ping and traffic")

        #Test remote vtep status on LEAF0 and LEAF1
        verify_vtep_state(nodes)

        ##Run Traffic: Bi-directional Burst of 100 Packets
        streams_dict = vxlan_obj.traffic_setup(data, 'ipv6')
        st.log(streams_dict)
        result = vxlan_obj.check_traffic(streams_dict)

        if result:
            st.report_pass("test_case_passed", "test_l3vni_v6_v6_vtep_multiple_vni_load passed")
        else:
            st.report_fail("test_case_failed", "test_l3vni_v6_v6_vtep_multiple_vni_load failed")

    except Exception as e:
        report_fail("", msg=e)
    finally:
        vxlan_obj.unconfig_multiple_vni(nodes, svi_ips, vrfs, data)

@pytest.mark.skip(reason="Delete VRF, puts Leaf0 in a bad state")
def test_l3vni_v6_v6_vtep_remove_add_bgp():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2

    leaf0_vlan_ip = '2002:db8:1::1/64'
    leaf1_vlan_ip = '2003:db8:1::1/64'

    leaf0_vlan = '2'
    leaf1_vlan = '3'

    vrf = 'Vrf01'
    vni = '1000'
    dummy_vlan = '100'

    try:

        #Configure and validate basic l3vni and route exchanges
        configure_and_validate_basic_l3vni('ipv6')
        
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

        #sleep for 60 seconds for BGP to converge
        st.wait(60)

        '''
        c. Check if the routes are withdrawn
        '''
        #Start Verification
        leaf0_vrf_prefix = '2002:db8:1::'
        leaf1_vrf_prefix = '2003:db8:1::'

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
        #Start Verification
        leaf0_vrf_prefix = '2002:db8:1::'
        leaf1_vrf_prefix = '2003:db8:1::'
        
        vxlan_obj.verify_bgp(nodes, leaf1_vrf_prefix, 'leaf0')
        vxlan_obj.verify_bgp(nodes, leaf0_vrf_prefix, 'leaf1')

        #Run traffic test
        data.d3t1_ip6_addr = "2002:db8:1::1"
        data.t1d3_ip6_addr = "2002:db8:1::2"
        data.d4t1_ip6_addr = "2003:db8:1::1"
        data.t1d4_ip6_addr = "2003:db8:1::2"

        st.banner("Start to test VxLAN V6 L3 with ping and traffic")

        #Test remote vtep status on LEAF0 and LEAF1
        verify_vtep_state(nodes)
        ##Run Traffic: Bi-directional Burst of 100 Packets
        streams_dict = vxlan_obj.traffic_setup(data, 'ipv6')
        st.log(streams_dict)
        result = vxlan_obj.check_traffic(streams_dict)

        if result:
            st.report_pass("test_case_passed", "test_l3vni_v6_v6_vtep_remove_add_bgp passed")
        else:
            st.report_fail("test_case_failed", "test_l3vni_v6_v6_vtep_remove_add_bgp failed")

    except Exception as e:
        report_fail("", msg=e)
    finally:
        #Deconfigure basic l3vni configs
        deconfigure_basic_l3vni('ipv6')

def test_l3vni_v6_v6_vtep_port_flap():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2

    leaf0_vlan_ip = '2002:db8:1::1/64'
    leaf1_vlan_ip = '2003:db8:1::1/64'

    leaf0_vlan = '2'
    leaf1_vlan = '3'

    vrf = 'Vrf01'
    vni = '1000'
    dummy_vlan = '100'
    
    try:
        #Configure and validate basic l3vni and route exchanges
        configure_and_validate_basic_l3vni('ipv6')
        
        st.banner("Flapping Spine links on LEAF0")
        st.config(nodes['leaf0'], "config interface shutdown {}".format(vars.D3D1P1))
        st.config(nodes['leaf0'], "config interface shutdown {}".format(vars.D3D2P1))
        st.wait(10)

        '''
        Check if the routes are withdrawn
        '''
        #Start Verification
        leaf0_output = st.config(nodes['leaf0'], "show vxlan remotevtep")
        leaf0_parsed = st.parse_show(nodes['leaf0'], "show vxlan remotevtep", leaf0_output, "show_vxlan_remote.tmpl")

        for vtep in leaf0_parsed:
            if vtep['total_count'] == 0:
                st.log("Remote VTEP is not seen anymore", nodes['leaf0'])

        #Bringup the spine interfaces
        st.config(nodes['leaf0'], "config interface startup {}".format(vars.D3D1P1))
        st.config(nodes['leaf0'], "config interface startup {}".format(vars.D3D2P1))
        st.wait(60)
        st.banner("Spine links restored on LEAF0")
        #Start Verification if routes are back
        leaf0_output = st.config(nodes['leaf0'], "show vxlan remotevtep")
        leaf0_parsed = st.parse_show(nodes['leaf0'], "show vxlan remotevtep", leaf0_output, "show_vxlan_remote.tmpl")

        for vtep in leaf0_parsed:
            if vtep['total_count'] == 1:
                st.log("Remote VTEP is seen now", nodes['leaf0'])

        leaf0_vrf_prefix = '2002:db8:1::'
        leaf1_vrf_prefix = '2003:db8:1::'
        vxlan_obj.verify_bgp(nodes, leaf1_vrf_prefix, 'leaf0')
        vxlan_obj.verify_bgp(nodes, leaf0_vrf_prefix, 'leaf1')

        #Run traffic test
        data.d3t1_ip6_addr = "2002:db8:1::1"
        data.t1d3_ip6_addr = "2002:db8:1::2"
        data.d4t1_ip6_addr = "2003:db8:1::1"
        data.t1d4_ip6_addr = "2003:db8:1::2"

        st.banner("Start to test VxLAN V6 L3 with ping and traffic")
        #Test remote vtep status on LEAF0 and LEAF1
        verify_vtep_state(nodes)
        ##Run Traffic: Bi-directional Burst of 100 Packets
        streams_dict = vxlan_obj.traffic_setup(data, 'ipv6')
        st.log(streams_dict)
        result = vxlan_obj.check_traffic(streams_dict)

        if result:
            st.report_pass("test_case_passed", "test_l3vni_v6_v6_vtep_port_flap passed")
        else:
            st.report_fail("test_case_failed", "test_l3vni_v6_v6_vtep_port_flap failed")
    
    except Exception as e:
        report_fail("", msg=e)
    
    finally:
        #Deconfigure basic l3vni configs
        deconfigure_basic_l3vni('ipv6')

# v4 over v6 tests
#
# TODO: We shouldn't be duplicating test cases. However, pytest parameterization is not working. This is
# a temporary work around till the time parameterization is actually made to work.
# Previously these tests failed due to zebra crash. 
def test_l3vni_v4_v6_vtep_basic_config():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    
    try:
        #Configure and Validate basic l3vni configs and route exchanges
        configure_and_validate_basic_l3vni('ipv4')
        #Run traffic test
        #v4 hosts
        data.d3t1_ip_addr = "100.100.100.254"
        data.t1d3_ip_addr = "100.100.100.200"
        data.t1d3_mac_addr = "00:0a:01:00:11:01"

        data.d4t1_ip_addr = "100.100.101.254"
        data.t1d4_ip_addr = "100.100.101.200"
        data.t1d4_mac_addr = "00:0a:01:00:12:01"
        data.circuit_endpoint_type = "ipv4"

        #Test remote vtep status on LEAF0 and LEAF1
        verify_vtep_state(nodes)

        ##Run Traffic: Bi-directional Burst of 100 Packets
        streams_dict = vxlan_obj.traffic_setup(data, 'ipv4')
        st.log(streams_dict)
        result = vxlan_obj.check_traffic(streams_dict)

        if result:
            st.report_pass("test_case_passed", "test_l3vni_v4_v6_vtep_basic_config passed")
        else:
            st.report_fail("test_case_failed", "test_l3vni_v4_v6_vtep_basic_config failed")

    except Exception as e:
        report_fail("", msg=e)
    finally:
        #Deconfigure basic l3vni configs
        deconfigure_basic_l3vni('ipv4')
  
def test_l3vni_v4_v6_vtep_multiple_vni():
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
        #Start configuration
        vxlan_obj.config_multiple_vni(nodes, svi_ips, vrfs)

        #Start Verification
        vxlan_obj.verify_bgp_convergence(nodes, svi_ips, 'leaf0', 'leaf1')
        vxlan_obj.verify_bgp_convergence(nodes, svi_ips, 'leaf1', 'leaf0')
    
        #Run traffic test
        #v4 hosts
        data.circuit_endpoint_type = "ipv4"

        data.d3t1_ip_addr = "100.100.102.254"
        data.t1d3_ip_addr = "100.100.102.200"
        data.t1d3_mac_addr = "00:0a:01:00:11:01"

        data.d4t1_ip_addr = "100.100.112.254"
        data.t1d4_ip_addr = "100.100.112.200"
        data.t1d4_mac_addr = "00:0a:01:00:12:02"

        #Test remote vtep status on LEAF0 and LEAF1
        verify_vtep_state(nodes)
        ##Run Traffic: Bi-directional Burst of 100 Packets
        streams_dict = vxlan_obj.traffic_setup(data, 'ipv4')
        st.log(streams_dict)
        result = vxlan_obj.check_traffic(streams_dict)

        if result:
            st.report_pass("test_case_passed", "test_l3vni_basic_with_traffic passed")
        else:
            st.report_fail("test_case_failed", "test_l3vni_basic__with_traffic failed")

    except Exception as e:
        report_fail("", msg=e)
    finally:
        vxlan_obj.unconfig_multiple_vni(nodes, svi_ips, vrfs, data)

def test_l3vni_v4_v6_vtep_multiple_vni_load():
    vars = st.get_testbed_vars()
    data.circuit_endpoint_type = "ipv4"
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
        #Start configuration
        vxlan_obj.config_multiple_vni(nodes, svi_ips, vrfs)

        #Start Verification
        vxlan_obj.verify_bgp_convergence(nodes, svi_ips, 'leaf0', 'leaf1')
        vxlan_obj.verify_bgp_convergence(nodes, svi_ips, 'leaf1', 'leaf0')

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

        #sleep for 30 seconds for BGP to converge
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

        vxlan_obj.verify_bgp_convergence(nodes, svi_ips, 'leaf0', 'leaf1')
        vxlan_obj.verify_bgp_convergence(nodes, svi_ips, 'leaf1', 'leaf0')

        #Run traffic test
        #v4 hosts
        data.circuit_endpoint_type = "ipv4"

        data.d3t1_ip_addr = "100.100.102.254"
        data.t1d3_ip_addr = "100.100.102.200"
        data.t1d3_mac_addr = "00:0a:01:00:11:01"

        data.d4t1_ip_addr = "100.100.112.254"
        data.t1d4_ip_addr = "100.100.112.200"
        data.t1d4_mac_addr = "00:0a:01:00:12:02"

        #Test remote vtep status on LEAF0 and LEAF1
        verify_vtep_state(nodes)

        ##Run Traffic: Bi-directional Burst of 100 Packets
        streams_dict = vxlan_obj.traffic_setup(data, 'ipv4')
        st.log(streams_dict)
        result = vxlan_obj.check_traffic(streams_dict)

        if result:
            st.report_pass("test_case_passed", "test_l3vni_v4_v6_vtep_multiple_vni_load passed")
        else:
            st.report_fail("test_case_failed", "test_l3vni_v4_v6_vtep_multiple_vni_load failed")

    except Exception as e:
        report_fail("", msg=e)
    finally:
        vxlan_obj.unconfig_multiple_vni(nodes, svi_ips, vrfs, data)

@pytest.mark.skip(reason="Delete VRF, puts Leaf0 in a bad state")
def test_l3vni_v4_v6_vtep_remove_add_bgp():
    vars = st.get_testbed_vars()
    data.circuit_endpoint_type = "ipv4"
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
        #Configure and validate basic l3vni and route exchanges
        configure_and_validate_basic_l3vni('ipv4')

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

        #sleep for 60 seconds for BGP to converge
        st.wait(60)

        '''
        c. Check if the routes are withdrawn
        '''
        #Start Verification
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
                config_static(node, 'bgp')

        '''
        f. Check if the routes are back
        '''
        #Start Verification
        leaf0_vrf_prefix = '100.100.100.0'
        leaf1_vrf_prefix = '100.100.101.0'

        vxlan_obj.verify_bgp(nodes, leaf1_vrf_prefix, 'leaf0')
        vxlan_obj.verify_bgp(nodes, leaf0_vrf_prefix, 'leaf1')

        #Run traffic test
        #v4 hosts
        data.d3t1_ip_addr = "100.100.100.254"
        data.t1d3_ip_addr = "100.100.100.200"
        data.t1d3_mac_addr = "00:0a:01:00:11:01"

        data.d4t1_ip_addr = "100.100.101.254"
        data.t1d4_ip_addr = "100.100.101.200"
        data.t1d4_mac_addr = "00:0a:01:00:12:01"
        data.circuit_endpoint_type = "ipv4"

        #Test remote vtep status on LEAF0 and LEAF1
        verify_vtep_state(nodes)

        ##Run Traffic: Bi-directional Burst of 100 Packets
        streams_dict = vxlan_obj.traffic_setup(data, 'ipv4')
        st.log(streams_dict)
        result = vxlan_obj.check_traffic(streams_dict)

        if result:
            st.report_pass("test_case_passed", "test_l3vni_v4_v6_vtep_remove_add_bgp passed")
        else:
            st.report_fail("test_case_failed", "test_l3vni_v4_v6_vtep_remove_add_bgp failed")

    except Exception as e:
        report_fail("", msg=e)
    finally:
        #Deconfigure basic l3vni configs
        deconfigure_basic_l3vni('ipv4')

def test_l3vni_v4_v6_vtep_port_flap():
    vars = st.get_testbed_vars()
    data.circuit_endpoint_type = "ipv4"
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
        #Configure and validate basic l3vni and route exchanges
        configure_and_validate_basic_l3vni('ipv4')

        st.banner("Flapping Spine links on LEAF0")
        st.config(nodes['leaf0'], "config interface shutdown {}".format(vars.D3D1P1))
        st.config(nodes['leaf0'], "config interface shutdown {}".format(vars.D3D2P1))
        st.wait(10)

        '''
        Check if the routes are withdrawn
        '''
        #Start Verification
        leaf0_output = st.config(nodes['leaf0'], "show vxlan remotevtep")
        leaf0_parsed = st.parse_show(nodes['leaf0'], "show vxlan remotevtep", leaf0_output, "show_vxlan_remote.tmpl")

        for vtep in leaf0_parsed:
            if vtep['total_count'] == 0:
                st.log("Remote VTEP is not seen anymore", nodes['leaf0'])

        #Bringup the spine interfaces
        st.config(nodes['leaf0'], "config interface startup {}".format(vars.D3D1P1))
        st.config(nodes['leaf0'], "config interface startup {}".format(vars.D3D2P1))
        st.wait(60)
        st.banner("Spine links restored on LEAF0")

        #Start Verification if routes are back
        leaf0_output = st.config(nodes['leaf0'], "show vxlan remotevtep")
        leaf0_parsed = st.parse_show(nodes['leaf0'], "show vxlan remotevtep", leaf0_output, "show_vxlan_remote.tmpl")

        for vtep in leaf0_parsed:
            if vtep['total_count'] == 1:
                st.log("Remote VTEP is seen now", nodes['leaf0'])

        leaf0_vrf_prefix = '100.100.100.0'
        leaf1_vrf_prefix = '100.100.101.0'

        vxlan_obj.verify_bgp(nodes, leaf1_vrf_prefix, 'leaf0')
        vxlan_obj.verify_bgp(nodes, leaf0_vrf_prefix, 'leaf1')
 
        #Run traffic test
        #v4 hosts
        data.d3t1_ip_addr = "100.100.100.254"
        data.t1d3_ip_addr = "100.100.100.200"
        data.t1d3_mac_addr = "00:0a:01:00:11:01"

        data.d4t1_ip_addr = "100.100.101.254"
        data.t1d4_ip_addr = "100.100.101.200"
        data.t1d4_mac_addr = "00:0a:01:00:12:01"
        data.circuit_endpoint_type = "ipv4"

        #Test remote vtep status on LEAF0 and LEAF1
        verify_vtep_state(nodes)

        ##Run Traffic: Bi-directional Burst of 100 Packets
        streams_dict = vxlan_obj.traffic_setup(data, 'ipv4')
        st.log(streams_dict)
        result = vxlan_obj.check_traffic(streams_dict)

        if result:
            st.report_pass("test_case_passed", "test_l3vni_v4_v6_vtep_port_flap passed")
        else:
            st.report_fail("test_case_failed", "test_l3vni_v4_v6_vtep_port_flap failed")
    
    except Exception as e:
        report_fail("", msg=e)
    
    finally:
        #Deconfigure basic l3vni configs
        deconfigure_basic_l3vni('ipv4')

