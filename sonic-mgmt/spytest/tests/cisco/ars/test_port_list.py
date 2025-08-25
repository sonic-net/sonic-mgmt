import os
import yaml
import pytest
from spytest import st, tgapi, SpyTestDict
import apis.routing.ip as ipapi
import tests.cisco.tortuga.common.tortuga_common_utils as common_obj
import apis.system.interface as interface_obj
import ars_common_utils

# Tgen config
data = SpyTestDict()
data.t1d1_ipv6_addr = "2001:200:1::2" #Source IPv6
data.t1d1_ip_addr = "200.200.1.2" #source IPv4
data.t1d1_mac_addr = "00:0A:03:00:11:01" #source Mac
data.t1d2_ipv6_addr = "2001:100:1::2"
data.t1d2_ip_addr = "200.100.1.2"
data.t1d2_mac_addr = "00:0A:04:00:12:01"
data.t1d1_ipv6_gateway = "2001:200:1::1" #source Gateway ipv6
data.t1d2_ipv6_gateway = "2001:100:1::1"
data.t1d1_ip_gateway = "200.200.1.1" #source Gateway ipv4
data.t1d2_ip_gateway = "200.100.1.1"
data.tgen1_asn = "65205"
data.tgen2_asn = "65206"
data.v6_mask="64"
f_size='1024'
t_mode='create'
t_l4_protocol="tcp"
t_tcp_src_port=1002
t_high_speed_result_analysis='1'
# Tgen config

@pytest.fixture(scope='module', autouse=True)
def setup_teardown_basic():
    global vars, updated_path, data_glob
    global tg1, tg2, tg_handle_1, tg_handle_2
    global trC1, trB1, trB1M
    initialize_globals()
    with open(updated_path) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            for domain, configs in config.items():
                common_obj.config_static(node, domain, True, updated_path)
    interface_obj.interface_shutdown(vars.D1, vars.D1D2P5, skip_verify=False)
    yield 'setup_teardown_basic'
    with open(updated_path) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            for domain, configs in config.items():
                common_obj.config_static(node, domain, False, updated_path)
    interface_obj.interface_noshutdown(vars.D1, vars.D1D2P5, skip_verify=False)
    common_obj.remove_temp_config(updated_path)

def initialize_globals():
    global vars, data_glob, tg1, tg2, tg_handle_1, tg_handle_2, updated_path
    vars = st.get_testbed_vars()
    tg1, tg2, tg_handle_1, tg_handle_2 = get_handles()
    data_glob = SpyTestDict()
    data_glob.nodes = [vars.D1, vars.D2]
    data_glob.dut1 = data_glob.nodes[0]
    data_glob.dut2 = data_glob.nodes[1]
    data.dut_asn_list = {data_glob.dut1: "65200", data_glob.dut2: "65201"}
    data_glob.interfaces = [ vars.D1D2P1, vars.D1D2P2, vars.D1D2P3, vars.D1D2P4, vars.D1D2P7, vars.D1D2P8]
    CONFIGS_FILE = 'ars_basic_cfg.yaml'
    dir_path = os.path.dirname(os.path.realpath(__file__))
    updated_path = common_obj.modify_config_file(f'{dir_path}/{CONFIGS_FILE}', vars)

def configure_tg_interfaces_v6():
    global tg1_interface, tg2_interface
    st.log("Creating Devices & adding IP Addresses along with ARP requests")
    res1 = tg1.tg_interface_config(port_handle=tg_handle_1, mode='config', ipv6_intf_addr=data.t1d1_ipv6_addr,ipv6_prefix_length='64', ipv6_gateway=data.t1d1_ipv6_gateway, src_mac_addr=data.t1d1_mac_addr, arp_send_req='1')
    st.log("INTFCONF: " + str(res1))
    tg1_interface = res1
    res2 = tg2.tg_interface_config(port_handle=tg_handle_2, mode='config', ipv6_intf_addr=data.t1d2_ipv6_addr,ipv6_prefix_length='64', ipv6_gateway=data.t1d2_ipv6_gateway, src_mac_addr=data.t1d2_mac_addr, arp_send_req='1')
    st.log("INTFCONF: " + str(res2))
    tg2_interface = res2

def configure_tg_interfaces_v4():
    global tg1_interface, tg2_interface
    st.log("Creating Devices & adding IP Addresses along with ARP requests")
    res1 = tg1.tg_interface_config(port_handle=tg_handle_1, mode='config', intf_ip_addr=data.t1d1_ip_addr, gateway=data.t1d1_ip_gateway, src_mac_addr=data.t1d1_mac_addr, arp_send_req='1')
    st.log("INTFCONF: " + str(res1))
    tg1_interface = res1
    res2 = tg2.tg_interface_config(port_handle=tg_handle_2, mode='config', intf_ip_addr=data.t1d2_ip_addr, gateway=data.t1d2_ip_gateway, src_mac_addr=data.t1d2_mac_addr, arp_send_req='1')
    st.log("INTFCONF: " + str(res2))
    tg2_interface = res2

@pytest.fixture(scope = 'class')
def fixture_v6():
    ars_common_utils.reset_tg_interfaces(tg1, tg2, tg_handle_1, tg_handle_2)
    configure_tg_interfaces_v6()
    ping_dut_interface_from_tg(dst_ip1 ="2001:200:1::1", dst_ip2="2001:100:1::1")
    configure_bgp_v6()
    configure_traffic_streams('ipv6')
    yield
    tg1.tg_traffic_config(mode = 'disable', stream_id =trB1['stream_id']) 
    tg1.tg_traffic_config(mode = 'disable', stream_id =trC1['stream_id'])
    tg1.tg_traffic_config(mode = 'disable', stream_id =trB1M['stream_id'])
    tg1.tg_emulation_bgp_control(handle=bgp_rtr1['handle'], mode='stop')
    tg2.tg_emulation_bgp_control(handle=bgp_rtr2['handle'], mode='stop')
    ars_common_utils.reset_tg_interfaces(tg1, tg2, tg_handle_1, tg_handle_2)
    st.wait(5)
    tg1.tg_interface_config(port_handle=tg_handle_1, handle=tg1_interface['handle'], mode='destroy')
    st.wait(5)
    tg2.tg_interface_config(port_handle=tg_handle_2, handle=tg2_interface['handle'], mode='destroy')
    st.wait(5)

@pytest.fixture(scope = 'class')
def fixture_v4():
    ars_common_utils.reset_tg_interfaces(tg1, tg2, tg_handle_1, tg_handle_2)
    configure_tg_interfaces_v4()
    ping_dut_interface_from_tg(dst_ip1 ="200.200.1.1", dst_ip2="200.100.1.1")
    configure_bgp_v4()
    configure_traffic_streams('ipv4')
    yield
    tg1.tg_traffic_config(mode = 'disable', stream_id =trB1['stream_id']) 
    tg1.tg_traffic_config(mode = 'disable', stream_id =trC1['stream_id'])
    tg1.tg_traffic_config(mode = 'disable', stream_id =trB1M['stream_id'])
    tg1.tg_emulation_bgp_control(handle=bgp_rtr1['handle'], mode='stop')
    tg2.tg_emulation_bgp_control(handle=bgp_rtr2['handle'], mode='stop')
    ars_common_utils.reset_tg_interfaces(tg1, tg2, tg_handle_1, tg_handle_2)
    st.wait(5)
    tg1.tg_interface_config(port_handle=tg_handle_1, handle=tg1_interface['handle'], mode='destroy')
    st.wait(5)
    tg2.tg_interface_config(port_handle=tg_handle_2, handle=tg2_interface['handle'], mode='destroy')
    st.wait(5)

def configure_bgp_v6():
    st.banner("Configuring BGP on TGEN-T1D1P1 towards DUT1")
    global bgp_rtr1, bgp_route, Dest_NG, Src_NG, bgp_rtr2
    bgp_rtr1 = tg1.tg_emulation_bgp_config(handle=tg1_interface['handle'],
                                           mode='enable', active_connect_enable='1',
                                           local_as=data.tgen1_asn, remote_as=data.dut_asn_list[data_glob.dut1], remote_ipv6_addr=data.t1d1_ipv6_gateway,ip_version='6',
                                           enable_4_byte_as='1', graceful_restart_enable='1')
    tg1.tg_emulation_bgp_control(handle=bgp_rtr1['handle'], mode='start')
    st.wait(2)
    st.banner("Configuring BGP on TGEN-T1D2P1 towards DUT2")
    bgp_rtr2 = tg2.tg_emulation_bgp_config(handle=tg2_interface['handle'],
                                           mode='enable', active_connect_enable='1',
                                           local_as=data.tgen2_asn, remote_as=data.dut_asn_list[data_glob.dut2], remote_ipv6_addr=data.t1d2_ipv6_gateway,ip_version='6',
                                           enable_4_byte_as='1', graceful_restart_enable='1')
    tg2.tg_emulation_bgp_control(handle=bgp_rtr2['handle'], mode='start')
    st.wait(2)
    # Destination Network group
    bgp_route = tg2.tg_emulation_bgp_route_config(handle=bgp_rtr2['handle'], mode='add', num_routes='1', prefix='2001:db8::20:20:20', ip_version='6')  
    tg2.tg_emulation_bgp_control(handle=bgp_rtr2['handle'], mode='start')
    st.wait(2)
    st.banner("Prefix advertisement MultiFlow ")
    # Destination Network group Multi Flow
    Dest_NG= tg2.tg_emulation_bgp_route_config(handle=bgp_rtr2['handle'], mode='add', num_routes='512',  prefix='2001:db8:20:21::1' , ip_version='6', ipv6_prefix_length= '128', route_ip_addr_step='::1')  
    tg2.tg_emulation_bgp_control(handle=bgp_rtr2['handle'], mode='start')
    st.wait(2)
    # Souce Network group Multi Flow
    Src_NG = tg1.tg_emulation_bgp_route_config(handle=bgp_rtr1['handle'], mode='add', num_routes='512', prefix='2001:db8:10:11::1', ip_version='6', ipv6_prefix_length= '128', route_ip_addr_step='::1')
    tg1.tg_emulation_bgp_control(handle=bgp_rtr1['handle'], mode='start')
    st.wait(2)

def configure_bgp_v4():
    st.banner("Configuring BGP on TGEN-T1D1P1 towards DUT1")
    global bgp_rtr1, bgp_route, Dest_NG, Src_NG, bgp_rtr2
    bgp_rtr1 = tg1.tg_emulation_bgp_config(handle=tg1_interface['handle'],
                                           mode='enable', active_connect_enable='1',
                                           local_as=data.tgen1_asn, remote_as=data.dut_asn_list[data_glob.dut1], remote_ip_addr=data.t1d1_ip_gateway,
                                           enable_4_byte_as='1', graceful_restart_enable='1')
    tg1.tg_emulation_bgp_control(handle=bgp_rtr1['handle'], mode='start')
    st.wait(2)
    st.banner("Configuring BGP on TGEN-T1D2P1 towards DUT2")
    bgp_rtr2 = tg2.tg_emulation_bgp_config(handle=tg2_interface['handle'],
                                           mode='enable', active_connect_enable='1',
                                           local_as=data.tgen2_asn, remote_as=data.dut_asn_list[data_glob.dut2], remote_ip_addr=data.t1d2_ip_gateway,
                                           enable_4_byte_as='1', graceful_restart_enable='1')
    tg2.tg_emulation_bgp_control(handle=bgp_rtr2['handle'], mode='start')
    st.wait(2)
    # Destination Network group
    bgp_route = tg2.tg_emulation_bgp_route_config(handle=bgp_rtr2['handle'], mode='add', num_routes='1', prefix='20.20.20.1')  
    tg2.tg_emulation_bgp_control(handle=bgp_rtr2['handle'], mode='start')
    st.wait(2)
    st.banner("Prefix advertisement MultiFlow ")
    # Destination Network group Multi Flow
    Dest_NG= tg2.tg_emulation_bgp_route_config(handle=bgp_rtr2['handle'], mode='add', num_routes='512', prefix='20.20.21.1', prefix_step='0.0.0.1')  
    tg2.tg_emulation_bgp_control(handle=bgp_rtr2['handle'], mode='start')
    st.wait(2)
    # Souce Network group Multi Flow
    Src_NG = tg1.tg_emulation_bgp_route_config(handle=bgp_rtr1['handle'], mode='add', num_routes='512', prefix='10.10.11.1', prefix_step = '0.0.0.1')
    tg1.tg_emulation_bgp_control(handle=bgp_rtr1['handle'], mode='start')
    st.wait(2)

def configure_traffic_streams(tcircuit_endpoint_type):
    st.banner("Configuring Traffic Stream on TGEN port1 towards DUT1")
    global trB1, trC1, trB1M, trC1M
    trB1 = tg1.tg_traffic_config(port_handle=tg_handle_1, emulation_src_handle=tg1_interface['handle'],
                                 emulation_dst_handle=bgp_route['handle'], circuit_endpoint_type=tcircuit_endpoint_type, mode=t_mode,
                                 high_speed_result_analysis='1', frame_size='1024', transmit_mode='multi_burst',
                                 pkts_per_burst='999', inter_burst_gap='2000000', inter_burst_gap_unit='ns', tx_delay='0', tx_delay_unit='bytes',
                                 min_gap_bytes='12')
    trC1 = tg1.tg_traffic_config(port_handle=tg_handle_1, emulation_src_handle=tg1_interface['handle'],
                                 emulation_dst_handle=bgp_route['handle'], circuit_endpoint_type=tcircuit_endpoint_type, mode=t_mode, l4_protocol=t_l4_protocol, tcp_src_port=t_tcp_src_port,
                                 high_speed_result_analysis=t_high_speed_result_analysis, frame_size=f_size, transmit_mode='continuous', rate_percent=99.5)
    trB1M = tg1.tg_traffic_config(port_handle=tg_handle_1, emulation_src_handle= Src_NG['handle'],
                                emulation_dst_handle=Dest_NG['handle'], circuit_endpoint_type=tcircuit_endpoint_type, mode=t_mode, l4_protocol=t_l4_protocol, tcp_src_port=t_tcp_src_port,
                                high_speed_result_analysis=t_high_speed_result_analysis, frame_size=f_size, transmit_mode='multi_burst',
                                pkts_per_burst='999', inter_burst_gap='20000000', inter_burst_gap_unit='ns', tx_delay='0', tx_delay_unit='bytes',
                                min_gap_bytes='12')
    trC1M = tg1.tg_traffic_config(port_handle=tg_handle_1, emulation_src_handle= Src_NG['handle'],
                                emulation_dst_handle=Dest_NG['handle'], circuit_endpoint_type=tcircuit_endpoint_type, mode=t_mode, l4_protocol=t_l4_protocol, tcp_src_port=t_tcp_src_port,
                                high_speed_result_analysis=t_high_speed_result_analysis, frame_size=f_size, transmit_mode='continuous', rate_percent=99.5)

def get_handles():
    tg1, tg_ph_1 = tgapi.get_handle_byname("T1D1P1")
    tg2, tg_ph_2 = tgapi.get_handle_byname("T1D2P1")
    return (tg1, tg2, tg_ph_1, tg_ph_2)

def ping_dut_interface_from_tg(dst_ip1 , dst_ip2):
    res1 = tgapi.verify_ping(src_obj=tg1, port_handle=tg_handle_1, dev_handle=tg1_interface['handle'],
                            dst_ip=dst_ip1, ping_count='1', exp_count='1')
    res2 = tgapi.verify_ping(src_obj=tg2, port_handle=tg_handle_2, dev_handle=tg2_interface['handle'],
                            dst_ip=dst_ip2, ping_count='1', exp_count='1')
    if res1 and res2:
        st.log("Ping succeeded.")
    else:
        st.warn("Ping failed.")

@pytest.mark.usefixtures('fixture_v4')
class Test_IPV4_config_ars():
    def test_nhg_equal_ecmp_flowlet_withburst(self):
        st.banner("Test NHG member equal to ECMP for Flowlet with Burst: ARS expected to enable and traffic distirbuted")
        stream = trB1['stream_id']
        ars_common_utils.add_ars(data_glob.dut1, global_mode="false", mode="flowlet-quality", idle_time="1000")
        ars_common_utils.add_nhg_equal_to_ecmp(data_glob, vars)
        ars_common_utils.run_traffic(stream,tg_handle_1, tg1, data_glob)
        counter1 = st.show(data_glob.dut1, "sudo -s show interface counters")
        ars_common_utils.del_nhg_equal_to_ecmp(data_glob, vars)
        ars_common_utils.del_ars(data_glob.dut1)
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter1, data_glob.interfaces):
            st.banner("Test Failed: traffic load is not Distributed")
            st.report_fail("test_case_failed_msg", "Traffic pass thorugh single interface")
        st.banner("Test Passed: Traffic Load Distributed Evenly")
        st.report_pass('test_case_passed')

    def test_nhg_less_ecmp_flowlet_withburst(self):
        st.banner("Test NHG member less ECMP for Flowlet with Burst: ARS expected to disable and traffic not distirbuted")
        stream = trB1['stream_id']
        ars_common_utils.add_ars(data_glob.dut1, global_mode="false", mode="flowlet-quality", idle_time="1000")
        ars_common_utils.add_nhg_equal_to_ecmp(data_glob, vars)
        st.config(data_glob.dut1, "sudo -s config ars-portlist-member del "+ vars.D1D2P8)
        ars_common_utils.run_traffic(stream,tg_handle_1, tg1, data_glob)
        counter1 = st.show(data_glob.dut1, "sudo -s show interface counters")
        st.config(data_glob.dut1, "sudo -s config ars-portlist-member add " + vars.D1D2P8 + " --ars-portlist non_global_port_list")
        ars_common_utils.del_nhg_equal_to_ecmp(data_glob, vars)
        ars_common_utils.del_ars(data_glob.dut1)
        if not ars_common_utils.check_traffic_single_interface(tg1, tg2, tg_handle_1, tg_handle_2, counter1, data_glob.interfaces):
            st.banner("Failed: traffic pass through Multiple Interface")
            st.report_fail("test_case_failed_msg","Traffic does not flow thorugh single interface")
        st.banner("Passed: Traffic passes through Single Interface")
        st.report_pass('test_case_passed')

    def test_nhg_greater_ecmp_flowlet_withburst(self):
        st.banner("Test NHG member greater than ECMP for Flowlet with Burst: ARS expected to enable and traffic distirbuted")
        stream = trB1['stream_id']
        ars_common_utils.add_ars(data_glob.dut1, global_mode="false", mode="flowlet-quality", idle_time="1000")
        ars_common_utils.add_nhg_equal_to_ecmp(data_glob, vars)
        st.config(data_glob.dut1, "sudo -s config ars-portlist-member add " + vars.D1D2P5 + " --ars-portlist non_global_port_list")
        ars_common_utils.run_traffic(stream,tg_handle_1, tg1, data_glob)
        counter1 = st.show(data_glob.dut1, "sudo -s show interface counters")
        st.config(data_glob.dut1, "sudo -s config ars-portlist-member del "+ vars.D1D2P5)
        ars_common_utils.del_nhg_equal_to_ecmp(data_glob, vars)
        ars_common_utils.del_ars(data_glob.dut1)
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter1, data_glob.interfaces):
            st.banner("Test Failed: traffic load is not Distributed")
            st.report_fail("test_case_failed_msg", "Traffic pass thorugh single interface")
        st.banner("Test Passed: Traffic Load Distributed Evenly")
        st.report_pass('test_case_passed')

    def test_nhg_equal_ecmp_perpacket_withburst(self):
        st.banner("Test NHG member equal to ECMP for Perpacket with Burst: ARS expected to enable and traffic distirbuted")
        stream = trB1['stream_id']
        ars_common_utils.add_ars(data_glob.dut1, global_mode="false", mode="per-packet-quality")
        ars_common_utils.add_nhg_equal_to_ecmp(data_glob, vars)
        ars_common_utils.run_traffic(stream,tg_handle_1, tg1, data_glob)
        counter1 = st.show(data_glob.dut1, "sudo -s show interface counters")
        ars_common_utils.del_nhg_equal_to_ecmp(data_glob, vars)
        ars_common_utils.del_ars(data_glob.dut1)
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter1, data_glob.interfaces):
            st.banner("Test Failed: traffic load is not Distributed")
            st.report_fail("test_case_failed_msg", "Traffic pass thorugh single interface")
        st.banner("Test Passed: Traffic Load Distributed Evenly")
        st.report_pass('test_case_passed')

    def test_nhg_less_ecmp_perpacket_withburst(self):
        st.banner("Test NHG member less ECMP for Perpacket With Burst: ARS expected to disable and traffic not distirbuted")
        stream = trB1['stream_id']
        ars_common_utils.add_ars(data_glob.dut1, global_mode="false", mode="per-packet-quality")
        ars_common_utils.add_nhg_equal_to_ecmp(data_glob, vars)
        st.config(data_glob.dut1, "sudo -s config ars-portlist-member del " + vars.D1D2P8)
        ars_common_utils.run_traffic(stream,tg_handle_1, tg1, data_glob)
        counter1 = st.show(data_glob.dut1, "sudo -s show interface counters")
        st.config(data_glob.dut1, "sudo -s config ars-portlist-member add " + vars.D1D2P8 + " --ars-portlist non_global_port_list")
        ars_common_utils.del_nhg_equal_to_ecmp(data_glob, vars)
        ars_common_utils.del_ars(data_glob.dut1)
        if not ars_common_utils.check_traffic_single_interface(tg1, tg2, tg_handle_1, tg_handle_2, counter1, data_glob.interfaces):
            st.banner("Failed: traffic pass through Multiple Interface")
            st.report_fail("test_case_failed_msg","Traffic does not flow thorugh single interface")
        st.banner("Passed: Traffic passes through Single Interface")
        st.report_pass('test_case_passed')

    def test_nhg_greater_ecmp_perpacket_withburst(self):
        st.banner("Test NHG member greater than ECMP for perpacket With Burst: ARS expected to enable and traffic distirbuted")
        stream = trB1['stream_id']
        ars_common_utils.add_ars(data_glob.dut1, global_mode="false", mode="per-packet-quality")
        ars_common_utils.add_nhg_equal_to_ecmp(data_glob, vars)
        st.config(data_glob.dut1, "sudo -s config ars-portlist-member add " + vars.D1D2P5 +" --ars-portlist non_global_port_list")
        ars_common_utils.run_traffic(stream,tg_handle_1, tg1, data_glob)
        counter1 = st.show(data_glob.dut1, "sudo -s show interface counters")
        st.config(data_glob.dut1, "sudo -s config ars-portlist-member del "+ vars.D1D2P5)
        ars_common_utils.del_nhg_equal_to_ecmp(data_glob, vars)
        ars_common_utils.del_ars(data_glob.dut1)
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter1, data_glob.interfaces):
            st.banner("Test Failed: traffic load is not Distributed")
            st.report_fail("test_case_failed_msg", "Traffic pass thorugh single interface")
        st.banner("Test Passed: Traffic Load Distributed Evenly")
        st.report_pass('test_case_passed')

    def test_nhg_equal_ecmp_flowlet_multiflow_with_and_without_burst(self):
        st.banner("Test NHG member equal to ECMP for MultiFlow Flowlet With Burst: ARS expected to enable and traffic distirbuted")
        stream = trB1M['stream_id']
        ars_common_utils.add_ars(data_glob.dut1, global_mode="false", mode="flowlet-quality", idle_time="1000")
        ars_common_utils.add_nhg_equal_to_ecmp(data_glob, vars)
        ars_common_utils.run_traffic(stream,tg_handle_1, tg1, data_glob)
        counter1 = st.show(data_glob.dut1, "sudo -s show interface counters")
        ars_common_utils.del_nhg_equal_to_ecmp(data_glob, vars)
        ars_common_utils.del_ars(data_glob.dut1)
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter1, data_glob.interfaces):
            st.banner("Test Failed: traffic load is not Distributed")
            st.report_fail("test_case_failed_msg", "Traffic pass thorugh single interface")
        stream = trC1M['stream_id']
        ars_common_utils.add_ars(data_glob.dut1, global_mode="false", mode="flowlet-quality", idle_time="1000")
        ars_common_utils.add_nhg_equal_to_ecmp(data_glob, vars)
        ars_common_utils.run_traffic(stream,tg_handle_1, tg1, data_glob)
        counter1 = st.show(data_glob.dut1, "sudo -s show interface counters")
        ars_common_utils.del_nhg_equal_to_ecmp(data_glob, vars)
        ars_common_utils.del_ars(data_glob.dut1)
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter1, data_glob.interfaces):
            st.banner("Test Failed: traffic load is not Distributed")
            st.report_fail("test_case_failed_msg", "Traffic pass thorugh single interface")
        st.banner("Test Passed: Traffic Load Distributed Evenly")
        st.report_pass('test_case_passed')

    def test_nhg_equal_ecmp_perpacket_multiflow_with_and_without_burst(self):
        st.banner("Test NHG member equal to ECMP for MultiFlow perpacket with Burst: ARS expected to enable and traffic distirbuted")
        stream = trB1M['stream_id']
        ars_common_utils.add_ars(data_glob.dut1, global_mode="false", mode="per-packet-quality")
        ars_common_utils.add_nhg_equal_to_ecmp(data_glob, vars)
        ars_common_utils.run_traffic(stream,tg_handle_1, tg1, data_glob)
        counter1 = st.show(data_glob.dut1, "sudo -s show interface counters")
        ars_common_utils.del_nhg_equal_to_ecmp(data_glob, vars)
        ars_common_utils.del_ars(data_glob.dut1)
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter1, data_glob.interfaces):
            st.banner("Test Failed: traffic load is not Distributed")
            st.report_fail("test_case_failed_msg", "Traffic pass thorugh single interface")
        stream = trC1M['stream_id']
        ars_common_utils.add_ars(data_glob.dut1, global_mode="false", mode="per-packet-quality")
        ars_common_utils.add_nhg_equal_to_ecmp(data_glob, vars)
        ars_common_utils.run_traffic(stream,tg_handle_1, tg1, data_glob)
        counter1 = st.show(data_glob.dut1, "sudo -s show interface counters")
        ars_common_utils.del_nhg_equal_to_ecmp(data_glob, vars)
        ars_common_utils.del_ars(data_glob.dut1)
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter1, data_glob.interfaces):
            st.banner("Test Failed: traffic load is not Distributed")
            st.report_fail("test_case_failed_msg", "Traffic pass thorugh single interface")
        st.banner("Test Passed: Traffic Load Distributed Evenly")
        st.report_pass('test_case_passed')

    def test_nhg_equal_ecmp_flowlet_without_burst(self):
        st.banner("Test NHG member equal to ECMP Flowlet Without Burst: ARS expected to enable and traffic not distirbuted")
        stream = trC1['stream_id']
        ars_common_utils.add_ars(data_glob.dut1, global_mode="false", mode="flowlet-quality", idle_time="1000")
        ars_common_utils.add_nhg_equal_to_ecmp(data_glob, vars)
        ars_common_utils.run_traffic(stream,tg_handle_1, tg1, data_glob)
        counter1 = st.show(data_glob.dut1, "sudo -s show interface counters")
        ars_common_utils.del_nhg_equal_to_ecmp(data_glob, vars)
        ars_common_utils.del_ars(data_glob.dut1)
        if not ars_common_utils.check_traffic_single_interface(tg1, tg2, tg_handle_1, tg_handle_2, counter1, data_glob.interfaces):
            st.banner("Failed: traffic pass through Multiple Interface")
            st.report_fail("test_case_failed_msg","Traffic does not flow thorugh single interface")
        st.banner("Passed: Traffic passes through Single Interface")
        st.report_pass('test_case_passed')

    def test_nhg_equal_ecmp_perpacket_without_burst(self):
        st.banner("Test NHG member equal to ECMP for Perpacket Without Burst: ARS expected to enable and traffic distirbuted")
        stream = trC1['stream_id']
        ars_common_utils.add_ars(data_glob.dut1, global_mode="false", mode="per-packet-quality")
        ars_common_utils.add_nhg_equal_to_ecmp(data_glob, vars)
        ars_common_utils.run_traffic(stream,tg_handle_1, tg1, data_glob)
        counter1 = st.show(data_glob.dut1, "sudo -s show interface counters")
        ars_common_utils.del_nhg_equal_to_ecmp(data_glob, vars)
        ars_common_utils.del_ars(data_glob.dut1)
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter1, data_glob.interfaces):
            st.banner("Test Failed: traffic load is not Distributed")
            st.report_fail("test_case_failed_msg", "Traffic pass thorugh single interface")
        st.banner("Test Passed: Traffic Load Distributed Evenly")
        st.report_pass('test_case_passed')

@pytest.mark.usefixtures('fixture_v6')
class Test_IPV6_config_ars():
    def test_nhg_equal_ecmp_flowlet_withburst_v6(self):
        st.banner("Test NHG member equal to ECMP for Flowlet With Burst: ARS expected to enable and traffic distirbuted")
        stream = trB1['stream_id']
        ars_common_utils.add_ars(data_glob.dut1, global_mode="false", mode="flowlet-quality", idle_time="1000")
        ars_common_utils.add_nhg_equal_to_ecmp(data_glob, vars)
        ars_common_utils.run_traffic(stream,tg_handle_1, tg1, data_glob)
        counter1 = st.show(data_glob.dut1, "sudo -s show interface counters")
        ars_common_utils.del_nhg_equal_to_ecmp(data_glob, vars)
        ars_common_utils.del_ars(data_glob.dut1)
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter1, data_glob.interfaces):
            st.banner("Test Failed: traffic load is not Distributed")
            st.report_fail("test_case_failed_msg", "Traffic pass thorugh single interface")
        st.banner("Test Passed: Traffic Load Distributed Evenly")
        st.report_pass('test_case_passed')

    def test_nhg_less_ecmp_flowlet_withburst_v6(self):
        st.banner("Test NHG member less ECMP for Flowlet With Burst: ARS expected to disable and traffic not distirbuted")
        stream = trB1['stream_id']
        ars_common_utils.add_ars(data_glob.dut1, global_mode="false", mode="flowlet-quality", idle_time="1000")
        ars_common_utils.add_nhg_equal_to_ecmp(data_glob, vars)
        st.config(data_glob.dut1, "sudo -s config ars-portlist-member del "+ vars.D1D2P8)
        ars_common_utils.run_traffic(stream,tg_handle_1, tg1, data_glob)
        counter1 = st.show(data_glob.dut1, "sudo -s show interface counters")
        st.config(data_glob.dut1, "sudo -s config ars-portlist-member add " + vars.D1D2P8 +" --ars-portlist non_global_port_list")
        ars_common_utils.del_nhg_equal_to_ecmp(data_glob, vars)
        ars_common_utils.del_ars(data_glob.dut1)
        if not ars_common_utils.check_traffic_single_interface(tg1, tg2, tg_handle_1, tg_handle_2, counter1, data_glob.interfaces):
            st.banner("Failed: traffic pass through Multiple Interface")
            st.report_fail("test_case_failed_msg","Traffic does not flow thorugh single interface")
        st.banner("Passed: Traffic passes through Single Interface")
        st.report_pass('test_case_passed')

    def test_nhg_greater_ecmp_flowlet_withburst_v6(self):
        st.banner("Test NHG member greater than ECMP for Flowlet with Burst: ARS expected to enable and traffic distirbuted")
        stream = trB1['stream_id']
        ars_common_utils.add_ars(data_glob.dut1, global_mode="false", mode="flowlet-quality", idle_time="1000")
        ars_common_utils.add_nhg_equal_to_ecmp(data_glob, vars)
        st.config(data_glob.dut1, "sudo -s config ars-portlist-member add " + vars.D1D2P5 + " --ars-portlist non_global_port_list")
        ars_common_utils.run_traffic(stream,tg_handle_1, tg1, data_glob)
        counter1 = st.show(data_glob.dut1, "sudo -s show interface counters")
        st.config(data_glob.dut1, "sudo -s config ars-portlist-member del "+ vars.D1D2P5)
        ars_common_utils.del_nhg_equal_to_ecmp(data_glob, vars)
        ars_common_utils.del_ars(data_glob.dut1)
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter1, data_glob.interfaces):
            st.banner("Test Failed: traffic load is not Distributed")
            st.report_fail("test_case_failed_msg", "Traffic pass thorugh single interface")
        st.banner("Test Passed: Traffic Load Distributed Evenly")
        st.report_pass('test_case_passed')

    def test_nhg_equal_ecmp_perpacket_withburst_v6(self):
        st.banner("Test NHG member equal to ECMP for Perpacket with Burst: ARS expected to enable and traffic distirbuted")
        stream = trB1['stream_id']
        ars_common_utils.add_ars(data_glob.dut1, global_mode="false", mode="per-packet-quality")
        ars_common_utils.add_nhg_equal_to_ecmp(data_glob, vars)
        ars_common_utils.run_traffic(stream,tg_handle_1, tg1, data_glob)
        counter1 = st.show(data_glob.dut1, "sudo -s show interface counters")
        ars_common_utils.del_nhg_equal_to_ecmp(data_glob, vars)
        ars_common_utils.del_ars(data_glob.dut1)
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter1, data_glob.interfaces):
            st.banner("Test Failed: traffic load is not Distributed")
            st.report_fail("test_case_failed_msg", "Traffic pass thorugh single interface")
        st.banner("Test Passed: Traffic Load Distributed Evenly")
        st.report_pass('test_case_passed')

    def test_nhg_less_ecmp_perpacket_withburst_v6(self):
        st.banner("Test NHG member less ECMP for Perpacket with Burst: ARS expected to disable and traffic not distirbuted")
        stream = trB1['stream_id']
        ars_common_utils.add_ars(data_glob.dut1, global_mode="false", mode="per-packet-quality")
        ars_common_utils.add_nhg_equal_to_ecmp(data_glob, vars)
        st.config(data_glob.dut1, "sudo -s config ars-portlist-member del "+ vars.D1D2P8)
        ars_common_utils.run_traffic(stream,tg_handle_1, tg1, data_glob)
        counter1 = st.show(data_glob.dut1, "sudo -s show interface counters")
        st.config(data_glob.dut1, "sudo -s config ars-portlist-member add "+ vars.D1D2P8 +" --ars-portlist non_global_port_list")
        ars_common_utils.del_nhg_equal_to_ecmp(data_glob, vars)
        ars_common_utils.del_ars(data_glob.dut1)
        if not ars_common_utils.check_traffic_single_interface(tg1, tg2, tg_handle_1, tg_handle_2, counter1, data_glob.interfaces):
            st.banner("Failed: traffic pass through Multiple Interface")
            st.report_fail("test_case_failed_msg","Traffic does not flow thorugh single interface")
        st.banner("Passed: Traffic passes through Single Interface")
        st.report_pass('test_case_passed')

    def test_nhg_greater_ecmp_perpacket_withburst_v6(self):
        st.banner("Test NHG member greater than ECMP for perpacket with Burst: ARS expected to enable and traffic distirbuted")
        stream = trB1['stream_id']
        ars_common_utils.add_ars(data_glob.dut1, global_mode="false", mode="per-packet-quality")
        ars_common_utils.add_nhg_equal_to_ecmp(data_glob, vars)
        st.config(data_glob.dut1, "sudo -s config ars-portlist-member add "+ vars.D1D2P5 +" --ars-portlist non_global_port_list")
        ars_common_utils.run_traffic(stream,tg_handle_1, tg1, data_glob)
        counter1 = st.show(data_glob.dut1, "sudo -s show interface counters")
        st.config(data_glob.dut1, "sudo -s config ars-portlist-member del "+ vars.D1D2P5)
        ars_common_utils.del_nhg_equal_to_ecmp(data_glob, vars)
        ars_common_utils.del_ars(data_glob.dut1)
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter1, data_glob.interfaces):
            st.banner("Test Failed: traffic load is not Distributed")
            st.report_fail("test_case_failed_msg", "Traffic pass thorugh single interface")
        st.banner("Test Passed: Traffic Load Distributed Evenly")
        st.report_pass('test_case_passed')

    def test_nhg_equal_ecmp_flowlet_multiflow_with_and_without_burst_v6(self):
        st.banner("Test NHG member equal to ECMP for MultiFlow Flowlet with Burst: ARS expected to enable and traffic distirbuted")
        stream = trB1M['stream_id']
        ars_common_utils.add_ars(data_glob.dut1, global_mode="false", mode="flowlet-quality", idle_time="1000")
        ars_common_utils.add_nhg_equal_to_ecmp(data_glob, vars)
        ars_common_utils.run_traffic(stream,tg_handle_1, tg1, data_glob)
        counter1 = st.show(data_glob.dut1, "sudo -s show interface counters")
        ars_common_utils.del_nhg_equal_to_ecmp(data_glob, vars)
        ars_common_utils.del_ars(data_glob.dut1)
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter1, data_glob.interfaces):
            st.banner("Test Failed: traffic load is not Distributed")
            st.report_fail("test_case_failed_msg", "Traffic does not pass thorugh single interface")
        stream = trC1M['stream_id']
        ars_common_utils.add_ars(data_glob.dut1, global_mode="false", mode="flowlet-quality", idle_time="1000")
        ars_common_utils.add_nhg_equal_to_ecmp(data_glob, vars)
        ars_common_utils.run_traffic(stream,tg_handle_1, tg1, data_glob)
        counter1 = st.show(data_glob.dut1, "sudo -s show interface counters")
        ars_common_utils.del_nhg_equal_to_ecmp(data_glob, vars)
        ars_common_utils.del_ars(data_glob.dut1)
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter1, data_glob.interfaces):
            st.banner("Test Failed: traffic load is not Distributed")
            st.report_fail("test_case_failed_msg", "Traffic pass thorugh single interface")
        st.banner("Test Passed: Traffic Load Distributed Evenly")
        st.report_pass('test_case_passed')

    def test_nhg_equal_ecmp_perpacket_multiflow_with_and_without_burst_v6(self):
        st.banner("Test NHG member equal to ECMP for MultiFlow perpacket with Burst: ARS expected to enable and traffic distirbuted")
        stream = trB1M['stream_id']
        ars_common_utils.add_ars(data_glob.dut1, global_mode="false", mode="per-packet-quality")
        ars_common_utils.add_nhg_equal_to_ecmp(data_glob, vars)
        ars_common_utils.run_traffic(stream,tg_handle_1, tg1, data_glob)
        counter1 = st.show(data_glob.dut1, "sudo -s show interface counters")
        ars_common_utils.del_nhg_equal_to_ecmp(data_glob, vars)
        ars_common_utils.del_ars(data_glob.dut1)
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter1, data_glob.interfaces):
            st.banner("Test Failed: traffic load is not Distributed")
            st.report_fail("test_case_failed_msg", "Traffic pass thorugh single interface")
        stream = trC1M['stream_id']
        ars_common_utils.add_ars(data_glob.dut1, global_mode="false", mode="per-packet-quality")
        ars_common_utils.add_nhg_equal_to_ecmp(data_glob, vars)
        ars_common_utils.run_traffic(stream,tg_handle_1, tg1, data_glob)
        counter1 = st.show(data_glob.dut1, "sudo -s show interface counters")
        ars_common_utils.del_nhg_equal_to_ecmp(data_glob, vars)
        ars_common_utils.del_ars(data_glob.dut1)
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter1, data_glob.interfaces):
            st.banner("Test Failed: traffic load is not Distributed")
            st.report_fail("test_case_failed_msg", "Traffic pass thorugh single interface")
        st.banner("Test Passed: Traffic Load Distributed Evenly")
        st.report_pass('test_case_passed')

    def test_nhg_equal_ecmp_flowlet_without_burst_v6(self):
        st.banner("Test NHG member equal to ECMP Flowlet Without Burst: ARS expected to enable and traffic not distirbuted")
        stream = trC1['stream_id']
        ars_common_utils.add_ars(data_glob.dut1, global_mode="false", mode="flowlet-quality", idle_time="1000")
        ars_common_utils.add_nhg_equal_to_ecmp(data_glob, vars)
        ars_common_utils.run_traffic(stream,tg_handle_1, tg1, data_glob)
        counter1 = st.show(data_glob.dut1, "sudo -s show interface counters")
        ars_common_utils.del_nhg_equal_to_ecmp(data_glob, vars)
        ars_common_utils.del_ars(data_glob.dut1)
        if not ars_common_utils.check_traffic_single_interface(tg1, tg2, tg_handle_1, tg_handle_2, counter1, data_glob.interfaces):
            st.banner("Failed: traffic pass through Multiple Interface")
            st.report_fail("test_case_failed_msg","Traffic does not flow thorugh single interface")
        st.banner("Passed: Traffic passes through Single Interface")
        st.report_pass('test_case_passed')

    def test_nhg_equal_ecmp_perpacket_without_burst_v6(self):
        st.banner("Test NHG member equal to ECMP for Perpacket Without Burst: ARS expected to enable and traffic distirbuted")
        stream = trC1['stream_id']
        ars_common_utils.add_ars(data_glob.dut1, global_mode="false", mode="per-packet-quality")
        ars_common_utils.add_nhg_equal_to_ecmp(data_glob, vars)
        ars_common_utils.run_traffic(stream,tg_handle_1, tg1, data_glob)
        counter1 = st.show(data_glob.dut1, "sudo -s show interface counters")
        ars_common_utils.del_nhg_equal_to_ecmp(data_glob, vars)
        ars_common_utils.del_ars(data_glob.dut1)
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter1, data_glob.interfaces):
            st.banner("Test Failed: traffic load is not Distributed")
            st.report_fail("test_case_failed_msg", "Traffic pass thorugh single interface")
        st.banner("Test Passed: Traffic Load Distributed Evenly")
        st.report_pass('test_case_passed')