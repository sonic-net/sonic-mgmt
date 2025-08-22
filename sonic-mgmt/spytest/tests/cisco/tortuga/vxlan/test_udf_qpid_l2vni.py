import os
import yaml
import pytest

from spytest import st, tgapi, SpyTestDict
import apis.routing.ip as ip_obj
import apis.switching.vlan as vlan_obj
import vxlan_utils as vxlan_obj
import apis.system.interface as intfapi

##
## config: eBGP + ECMP
##  Topology : 2x Spine + 2 Leafs
##
##  SD1 -- Spine0  - D1
##  SD1 -- Spine1  - D2
##  SD2 -- Leaf0   - D3
##  SD4 -- Leaf1   - D4
##

## tgen Stream Config
data = SpyTestDict()

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
    st.log("Module config done")

data.d3t1_ip_addr = "1.1.1.3"
data.t1d3_ip_addr = "1.1.1.2"
data.t1d3_mac_addr = "00:0a:01:00:11:01"

data.d4t1_ip_addr = "1.1.1.2"
data.t1d4_ip_addr = "1.1.1.3"
data.t1d4_mac_addr = "00:0a:01:00:12:01"

CONFIGS_FILE = 'udf_qpid_l2vni_config_template.yaml'
LEAF0_VXLAN_IP = '10.200.200.200'
LEAF1_VXLAN_IP = '10.200.200.201'

RDMA_DST_PORT       = 4791
NON_RDMA_DST_PORT   = 4792

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

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            config_static(node, 'sonic')
            st.wait(2)
            config_static(node, 'bgp')
    st.wait(60)
    ###Get TGEN Handles ###
    handles = vxlan_obj.tgen_preconfig({"src_endpoint": {"port" : "T1D3P1", "host_ip": data.t1d3_ip_addr, "gateway": data.d3t1_ip_addr, "mac" : data.t1d3_mac_addr }, 
                                        "dst_endpoint" : {"port" : "T1D4P1","host_ip": data.t1d4_ip_addr, "gateway": data.d4t1_ip_addr, "mac" : data.t1d4_mac_addr }},
                                        "raw",data)
    if handles == False:
        st.report_fail('tgen preconfig failed')
    yield vxlan_config_hooks

    with open(updated_config_file) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in reversed(config_list.items()):
            config_static(node, 'bgp', add=False)
            st.wait(2)
            config_static(node, 'sonic', add=False)
    #router_preconfig_cleanup()
    vxlan_obj.remove_temp_config(updated_config_file)

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
    
def test_l2vni_vtep_setup ():
    vars = st.get_testbed_vars()

    nodes = {}
    nodes['spine0'] = vars.D1
    nodes['spine1'] = vars.D2
    nodes['leaf0'] = vars.D3
    nodes['leaf1'] = vars.D4
    
    vxlan_obj.verify_vtep_state({"LEAF0_VXLAN_IP":LEAF0_VXLAN_IP,"LEAF1_VXLAN_IP":LEAF1_VXLAN_IP})
    st.report_pass('test_case_passed')

def test_rdma_traffic_with_enabled_qpid():
    # qpid filed is located at offset 6 in the RDMA packet
    qpid = '0000000000F2000000000000'

    rdma_traffic_1 = create_rdma_traffic_stream(handles, data, qpid, True)
    qpid = '0000000000F2200000000000'
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
    qpid = '0000000000F2200000000000'
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
    qpid = '0000000000F2200000000000'
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
