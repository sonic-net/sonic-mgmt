import os
import yaml
import pytest
from spytest import st, tgapi, SpyTestDict
import apis.routing.ip as ip_obj
import apis.switching.vlan as vlan_obj
import vxlan_utils as vxlan_obj
import apis.system.interface as intfapi
import time

## config: eBGP + ECMP
##  Topology : 1x Spine + 2 Leafs
##  SD1 -- Spine0  - D1
##  SD2 -- Leaf0   - D3
##  SD4 -- Leaf1   - D4

## tgen Stream Config
data = SpyTestDict()
data.config_vrfs = []
CONFIGS_FILE = 'udf_qpid_l3vni_config_template.yaml'
LEAF0_VXLAN_IP = '10.200.200.200'
LEAF1_VXLAN_IP = '10.200.200.201'

RDMA_DST_PORT       = 4791
NON_RDMA_DST_PORT   = 4792

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
@pytest.fixture(scope="module", autouse=True)
def vxlan_config_hooks():
    global handles
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    global updated_config_file
    updated_config_file = vxlan_obj.modify_config_file(CONFIGS_FILE,vars)

    leaf0_vlan_ip = '100.100.100.254/24'
    leaf1_vlan_ip = '100.100.101.254/24'
    leaf0_vlan = '2'
    leaf1_vlan = '3'
    vrf = 'Vrf01'
    vni = '1000'
    dummy_vlan = '100'
    try:
        # Initial configuration
        with open(updated_config_file) as c:
            config_list = yaml.load(c, Loader=yaml.FullLoader)
            for node, config in config_list.items():
                config_static(node, 'sonic')
                st.wait(2)
                config_static(node, 'bgp')

        # Additional configuration for test_l3vni_basic_config
  
        # Start configuration
        vxlan_obj.configure_nodes(nodes, vrf, leaf0_vlan, leaf0_vlan_ip, leaf1_vlan, leaf1_vlan_ip, dummy_vlan, vni, vars)

        # Start Verification
        leaf0_vrf_prefix = '100.100.100.0'
        leaf1_vrf_prefix = '100.100.101.0'

        vxlan_obj.verify_bgp(nodes, leaf1_vrf_prefix, 'leaf0')
        vxlan_obj.verify_bgp(nodes, leaf0_vrf_prefix, 'leaf1')

        st.wait(40)

        # Run Traffic test
        data.d3t1_ip_addr = "100.100.100.254"
        data.t1d3_ip_addr = "100.100.100.1"  # Leaf0 Host
        data.t1d3_mac_addr = "00:0a:01:00:11:01"

        data.d4t1_ip_addr = "100.100.101.254"
        data.t1d4_ip_addr = "100.100.101.1"  # Leaf1 Host
        data.t1d4_mac_addr = "00:0a:01:00:12:02"

        ###Get TGEN Handles ###
        handles = vxlan_obj.tgen_preconfig({"src_endpoint": {"port" : "T1D3P1", "host_ip": data.t1d3_ip_addr, "gateway": data.d3t1_ip_addr, "mac" : data.t1d3_mac_addr }, 
                                        "dst_endpoint" : {"port" : "T1D4P1","host_ip": data.t1d4_ip_addr, "gateway": data.d4t1_ip_addr, "mac" : data.t1d4_mac_addr }},
                                        "raw",data)

        if handles == False:
            st.report_fail('tgen preconfig failed')

        yield vxlan_config_hooks
    finally:
        # Clenup configuration
        st.banner("Start to cleanup VxLAN L3 configuration")
    
        # Unconfigure nodes
        unconfigure_nodes(nodes, vrf, leaf0_vlan, leaf0_vlan_ip, leaf1_vlan, leaf1_vlan_ip, dummy_vlan, vni, vars)

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


def create_rdma_traffic_stream(handles, data, qpid, is_rdma):
    if is_rdma:
        dst_port = RDMA_DST_PORT
    else:
        dst_port = NON_RDMA_DST_PORT

    # Create a traffic stream for RDMA traffic
    receive = handles["tg_handle"].tg_traffic_config(
                    mode = 'create', transmit_mode = 'continuous',
                    rate_percent = data.rate_percent,
                    circuit_endpoint_type=data.circuit_endpoint_type,
                    frame_size = '128',
                    emulation_src_handle=handles["int_handle"],
                    emulation_dst_handle=handles["int_handle2"],
                    l4_protocol = 'udp',
                    udp_dst_port = dst_port,
                    udp_src_port = 63,
                    data_pattern_mode = 'fixed',
                    data_pattern = qpid
                    )
    
    stream_id = receive["stream_id"]
    return stream_id

def send_rdma_traffic(handles, stream_id, timeout=10):
    
    handles['tg_handle'].tg_traffic_control(action='apply', stream_handle=stream_id)
    handles['tg_handle'].tg_traffic_control(action='run', stream_handle=stream_id)
    st.wait(timeout)

    handles['tg_handle'].tg_traffic_control(action='stop', stream_handle=stream_id)
    st.wait(5)

def test_rdma_traffic_with_enabled_qpid():
    # qpid filed is located at offset 6 in the RDMA packet
    qpid = '0000000000F2000000000000'

    rdma_traffic_1 = create_rdma_traffic_stream(handles, data, qpid, True)
    qpid = '0000000000F2100000000000'
    rdma_traffic_2 = create_rdma_traffic_stream(handles, data, qpid, True)
    vars = st.get_testbed_vars()
    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    intf_data = SpyTestDict()
    properties = ['tx_ok']
    intf_data.port_list = [vars.D3D1P1, vars.D3D2P1]
    counters_1 = intfapi.get_interface_counter_value(vars.D3, intf_data.port_list, properties)
    st.config(vars.D3, "sudo config platform cisco udf-hash set -qpid")
    vxlan_obj.verify_ping(handles, data.d3t1_ip_addr, count='3')
    st.wait(5)
    send_rdma_traffic(handles, rdma_traffic_1, timeout=5)

    send_rdma_traffic(handles, rdma_traffic_2, timeout=5)
    st.wait(10)
    counters_2 = intfapi.get_interface_counter_value(vars.D3, intf_data.port_list, properties)
    count = 0
    for each_port in intf_data.port_list:
        for each_property in properties:
            value_1 = counters_1[each_port][each_property]
            value_2 = counters_2[each_port][each_property]
            print("tx_ok_1:{0}, tx_ok_2:{1}, change:{2} on ports:{3}".format(value_1, value_2, value_2-value_1, each_port))
            if (value_2 - value_1) > 100:
                count += 1

    if (count < 2):
        st.report_fail("test_case_failed", "test_rdma_traffic_with_enabled_qpid()")
    else:
        st.report_pass("test_case_passed", "test_rdma_traffic_with_enabled_qpid()")

def test_rdma_traffic_with_disabled_qpid():
    # qpid filed is located at offset 6 in the RDMA packet
    qpid = '0000000000F2000000000000'

    rdma_traffic_1 = create_rdma_traffic_stream(handles, data, qpid, True)
    qpid = '0000000000F2100000000000'
    rdma_traffic_2 = create_rdma_traffic_stream(handles, data, qpid, True)
    vars = st.get_testbed_vars()
    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    intf_data = SpyTestDict()
    properties = ['tx_ok']
    intf_data.port_list = [vars.D3D1P1, vars.D3D2P1]
    counters_1 = intfapi.get_interface_counter_value(vars.D3, intf_data.port_list, properties)
    st.config(vars.D3, "sudo config platform cisco udf-hash clear")
    vxlan_obj.verify_ping(handles, data.d3t1_ip_addr, count='3')
    st.wait(5)
    send_rdma_traffic(handles, rdma_traffic_1, timeout=5)

    send_rdma_traffic(handles, rdma_traffic_2, timeout=5)
    st.wait(10)
    counters_2 = intfapi.get_interface_counter_value(vars.D3, intf_data.port_list, properties)
    count = 0
    for each_port in intf_data.port_list:
        for each_property in properties:
            value_1 = counters_1[each_port][each_property]
            value_2 = counters_2[each_port][each_property]
            print("tx_ok_1:{0}, tx_ok_2:{1}, change:{2} on ports:{3}".format(value_1, value_2, value_2-value_1, each_port))
            if (value_2 - value_1) > 100:
                count += 1

    if (count > 1):
        st.report_fail("test_case_failed", "test_rdma_traffic_with_disabled_qpid()")
    else:
        st.report_pass("test_case_passed", "test_rdma_traffic_with_disabled_qpid()")

def test_non_rdma_traffic_with_enabled_qpid():
    # qpid filed is located at offset 6 in the RDMA packet
    qpid = '0000000000F2000000000000'

    rdma_traffic_1 = create_rdma_traffic_stream(handles, data, qpid, False)
    qpid = '0000000000F2100000000000'
    rdma_traffic_2 = create_rdma_traffic_stream(handles, data, qpid, False)
    vars = st.get_testbed_vars()
    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4

    intf_data = SpyTestDict()
    properties = ['tx_ok']
    intf_data.port_list = [vars.D3D1P1, vars.D3D2P1]
    counters_1 = intfapi.get_interface_counter_value(vars.D3, intf_data.port_list, properties)
    st.config(vars.D3, "sudo config platform cisco udf-hash set -qpid")
    vxlan_obj.verify_ping(handles, data.d3t1_ip_addr, count='3')
    st.wait(5)
    send_rdma_traffic(handles, rdma_traffic_1, timeout=5)

    send_rdma_traffic(handles, rdma_traffic_2, timeout=5)
    st.wait(10)
    counters_2 = intfapi.get_interface_counter_value(vars.D3, intf_data.port_list, properties)
    count = 0
    for each_port in intf_data.port_list:
        for each_property in properties:
            value_1 = counters_1[each_port][each_property]
            value_2 = counters_2[each_port][each_property]
            print("tx_ok_1:{0}, tx_ok_2:{1}, change:{2} on ports:{3}".format(value_1, value_2, value_2-value_1, each_port))
            if (value_2 - value_1) > 100:
                count += 1

    if (count > 1):
        st.report_fail("test_case_failed", "test_non_rdma_traffic_with_enabled_qpid()")
    else:
        st.report_pass("test_case_passed", "test_non_rdma_traffic_with_enabled_qpid()")
