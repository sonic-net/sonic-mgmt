import os
import yaml
import pytest
from spytest import st, tgapi, SpyTestDict
import tests.cisco.tortuga.common.tortuga_common_utils as common_obj
import apis.system.interface as interface_obj
import ars_common_utils

# Tgen config
data = SpyTestDict()
data.t1d1_ipv6_addr = "2001:200:1::2" #source IPv6
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

IPv4_subnet_24_Ipv6_subnet_64_config = 'ars_basic_cfg.yaml'
@pytest.fixture(scope='module', autouse=True, params=[IPv4_subnet_24_Ipv6_subnet_64_config])
def setup_teardown_basic(request):
    global vars, updated_path, data_glob
    global tg1, tg2, tg_handle_1, tg_handle_2
    global trC1, trB1, trB2, trB4, trB5, trB1M
    config_file = request.param
    initialize_globals(config_file)
    with open(updated_path) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            for domain, config in config.items():
                common_obj.config_static(node, domain, True, updated_path)
    yield 'setup_teardown_basic'
    with open(updated_path) as c:
        config_list = yaml.load(c, Loader=yaml.FullLoader)
        for node, config in config_list.items():
            for domain, config in config.items():
                common_obj.config_static(node, domain, False, updated_path)
    common_obj.remove_temp_config(updated_path)

def initialize_globals(config_file):
    global vars, data_glob, tg1, tg2, tg_handle_1, tg_handle_2, updated_path
    vars = st.get_testbed_vars()
    tg1, tg2, tg_handle_1, tg_handle_2 = get_handles()
    data_glob = SpyTestDict()
    data_glob.nodes = [vars.D1, vars.D2]
    data_glob.dut1 = data_glob.nodes[0]
    data_glob.dut2 = data_glob.nodes[1]
    data_glob.interfaces = [vars.D1D2P1, vars.D1D2P2, vars.D1D2P3, vars.D1D2P4,  vars.D1D2P5, vars.D1D2P7, vars.D1D2P8]
    data.dut_asn_list = {data_glob.dut1: "65200", data_glob.dut2: "65201"}
    dir_path = os.path.dirname(os.path.realpath(__file__))
    updated_path = common_obj.modify_config_file(f'{dir_path}/{config_file}', vars)

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
    tg1.tg_traffic_config(mode = 'disable', stream_id =trB2['stream_id'])
    tg1.tg_traffic_config(mode = 'disable', stream_id =trB4['stream_id'])
    tg1.tg_traffic_config(mode = 'disable', stream_id =trB5['stream_id'])
    tg1.tg_traffic_config(mode = 'disable', stream_id =trB1M['stream_id'])
    tg1.tg_traffic_config(mode = 'disable', stream_id =trC1M['stream_id'])
    tg1.tg_emulation_bgp_control(handle=bgp_rtr1['handle'], mode='stop')
    tg2.tg_emulation_bgp_control(handle=bgp_rtr2['handle'], mode='stop')
    ars_common_utils.reset_tg_interfaces(tg1, tg2, tg_handle_1, tg_handle_2)
    st.wait(30)
    tg1.tg_interface_config(port_handle=tg_handle_1, handle=tg1_interface['handle'], mode='destroy')
    st.wait(30)
    tg2.tg_interface_config(port_handle=tg_handle_2, handle=tg2_interface['handle'], mode='destroy')
    st.wait(30)

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
    tg1.tg_traffic_config(mode = 'disable', stream_id =trB2['stream_id'])
    tg1.tg_traffic_config(mode = 'disable', stream_id =trB4['stream_id'])
    tg1.tg_traffic_config(mode = 'disable', stream_id =trB5['stream_id'])
    tg1.tg_traffic_config(mode = 'disable', stream_id =trB1M['stream_id'])
    tg1.tg_traffic_config(mode = 'disable', stream_id =trC1M['stream_id'])
    tg1.tg_emulation_bgp_control(handle=bgp_rtr1['handle'], mode='stop')
    tg2.tg_emulation_bgp_control(handle=bgp_rtr2['handle'], mode='stop')
    ars_common_utils.reset_tg_interfaces(tg1, tg2, tg_handle_1, tg_handle_2)
    st.wait(30)
    tg1.tg_interface_config(port_handle=tg_handle_1, handle=tg1_interface['handle'], mode='destroy')
    st.wait(30)
    tg2.tg_interface_config(port_handle=tg_handle_2, handle=tg2_interface['handle'], mode='destroy')
    st.wait(30)

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
    Dest_NG= tg2.tg_emulation_bgp_route_config(handle=bgp_rtr2['handle'], mode='add', num_routes='512',  prefix='2001:db8:20:21::1' , ip_version='6',ipv6_prefix_length= '128' , route_ip_addr_step='::1')  
    tg2.tg_emulation_bgp_control(handle=bgp_rtr2['handle'], mode='start')
    st.wait(2)
    # Souce Network group Multi Flow
    Src_NG = tg1.tg_emulation_bgp_route_config(handle=bgp_rtr1['handle'], mode='add', num_routes='512', prefix='2001:db8:10:11::1', ip_version='6', ipv6_prefix_length= '128' , route_ip_addr_step='::1')
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
    global trB1, trB2, trB4, trB5, trC1, trB1M, trC1M
    trB1, trB2, trB4, trB5 = None, None, None, None
    traffic_map = { "trB1": "2000000", "trB2": "3000000", "trB4": "200000", "trB5": "400000"}
    for key, param in traffic_map.items():
        result = tg1.tg_traffic_config( port_handle=tg_handle_1, emulation_src_handle=tg1_interface['handle'], emulation_dst_handle=bgp_route['handle'],
        circuit_endpoint_type=tcircuit_endpoint_type, mode=t_mode, l4_protocol=t_l4_protocol, tcp_src_port=t_tcp_src_port, high_speed_result_analysis=t_high_speed_result_analysis,
        frame_size=f_size, transmit_mode='multi_burst', pkts_per_burst='999', inter_burst_gap=param,
        inter_burst_gap_unit='ns', tx_delay='0', tx_delay_unit='bytes', min_gap_bytes='12')
        traffic_map[key] = result
    trB1, trB2, trB4, trB5 = traffic_map["trB1"], traffic_map["trB2"], traffic_map["trB4"], traffic_map["trB5"]
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

def run_traffic_multiple_stream(stream, check_type='single'):
    ars_common_utils.run_traffic(stream,tg_handle_1, tg1, data_glob)
    counter = st.show(data_glob.dut1, "sudo -s show interface counters ")
    if check_type == 'single':
        if not ars_common_utils.check_traffic_single_interface(tg1, tg2, tg_handle_1, tg_handle_2, counter, data_glob.interfaces):
            return False
    else:
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter, data_glob.interfaces):
            return False
    return True

def verify_single_interface_traffic(counter, intfrecord):
    tx_ok_count = sum(1 for record in counter if record.get('iface') in intfrecord and int(record.get('tx_ok', '0').replace(',', '')) >= 1000)
    if tx_ok_count != 1:
        st.report_fail("test_case_failed_msg", "Traffic Load does not Pass through single interface on ARS Disable")

def verify_traffic_distribution(counter, intfrecord, tolerance_factor=0.4):
    total_count = 0
    interface_counts = []
    for record in counter:
        if record.get('iface') in intfrecord:
            ok_value = int(record.get('tx_ok', '0').replace(',', ''))
            total_count += ok_value
            interface_counts.append(ok_value)
    if not interface_counts:
        st.report_fail("test_case_failed_msg", "No traffic data available for the specified interfaces")
    average_count = total_count / len(intfrecord)
    toleranceB = average_count * (1 - tolerance_factor)  # Lower bound
    toleranceA = average_count * (1 + tolerance_factor)  # Upper bound
    for pkt_count in interface_counts:
        if not (toleranceB <= pkt_count <= toleranceA):
            st.report_fail("test_case_failed_msg", "Traffic Load does not Distributed Evenly with ARS Enable")

@pytest.mark.usefixtures('fixture_v6')
class Test_IPV6_config_ars():
    def test_ars_then_nhg_flowlet_v6(self):
        st.banner("Verify traffic distribution on NHG created after ARS config Flowlet: Traffic is expected to be load balanced after NHG is created, Ars oid should be getting attached to it.")
        ars_common_utils.add_ars(data_glob.dut1, global_mode="true", mode="flowlet-quality", idle_time="1000")
        #Configure Ixia Prefix Next Hop Group
        dest_G = tg2.tg_emulation_bgp_route_config(handle=bgp_rtr2['handle'], mode='add', num_routes='1',prefix='2002:db8::15:20:20', ip_version='6')  
        tg2.tg_emulation_bgp_control(handle=bgp_rtr2['handle'], mode='start')
        st.wait(5)
        trB7 = tg1.tg_traffic_config(port_handle=tg_handle_1, emulation_src_handle=tg1_interface['handle'], emulation_dst_handle=dest_G['handle'], 
                                circuit_endpoint_type='ipv6', mode='create', l4_protocol="tcp", tcp_src_port=1002,
                                high_speed_result_analysis='1', frame_size='1024', transmit_mode='multi_burst',
                                    pkts_per_burst='999', inter_burst_gap='2000000', inter_burst_gap_unit='ns', tx_delay='0', tx_delay_unit='bytes',
                                    min_gap_bytes='12')
        stream = trB7['stream_id']
        ars_common_utils.run_traffic(stream,tg_handle_1, tg1, data_glob)
        ars_common_utils.del_ars(data_glob.dut1)
        counter = st.show(data_glob.dut1,"sudo -s show interface counters ")
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter, data_glob.interfaces):
            st.banner("Test Failed: traffic load is not Distributed")
            st.report_fail("test_case_failed_msg", " traffic load is not Distributed")
        st.banner("Test Passed: Traffic Load Distributed Evenly")
        st.report_pass('test_case_passed')

    def test_singleflow_without_burst_flowlet_v6(self):
        st.banner("Testing Single Flow Without Bursts Flowlet: Traffic Expected to flow thorugh single interface for Continuous Traffic")
        stream = trC1['stream_id']
        ars_common_utils.add_ars(data_glob.dut1, global_mode="true", mode="flowlet-quality", idle_time="1000")
        ars_common_utils.run_traffic(stream,tg_handle_1, tg1, data_glob)
        ars_common_utils.del_ars(data_glob.dut1)
        counter = st.show(data_glob.dut1, "sudo -s show interface counters")
        if not ars_common_utils.check_traffic_single_interface(tg1, tg2, tg_handle_1, tg_handle_2, counter, data_glob.interfaces):
            st.banner("Failed: traffic pass through Multiple Interface")
            st.report_fail("test_case_failed_msg","traffic pass through Multiple Interface")
        st.banner("Passed: Traffic passes through Single Interface")
        st.report_pass('test_case_passed')

    def test_ars_traffic_intransit_flowlet_v6(self):
        st.banner("Test Add and Remove when traffic is being sent through, making sure traffic no distributed (on removal) and distributed (on adding ARS) Flowlet")
        stream = trB1['stream_id']
        # Disabling ARS in Running traffic
        st.banner("Disabling ARS in Running traffic")
        ars_common_utils.add_ars(data_glob.dut1, global_mode="true", mode="flowlet-quality", idle_time="1000")
        tg1.tg_traffic_control(action="clear_stats", port_handle=tg_handle_1)
        tg1.tg_traffic_control(action='run', handle=stream)
        ars_common_utils.del_ars(data_glob.dut1)
        st.config(data_glob.dut1, "sudo -s sonic-clear counters")
        st.wait(2)
        counter = st.show(data_glob.dut1, "sudo -s show interface counters")
        tg1.tg_traffic_control(action='stop', handle=stream)
        verify_single_interface_traffic(counter, data_glob.interfaces)
        # Adding ARS in Running traffic
        st.banner("Adding ARS in Running traffic")
        tg1.tg_traffic_control(action="clear_stats", port_handle=tg_handle_1)
        tg1.tg_traffic_control(action='run', handle=stream)
        st.banner("ARS Enable")
        ars_common_utils.add_ars(data_glob.dut1, global_mode="true", mode="flowlet-quality", idle_time="1000")
        st.config(data_glob.dut1, "sudo -s sonic-clear counters")
        st.wait(2)
        counter = st.show(data_glob.dut1, "sudo -s show interface counters")
        tg1.tg_traffic_control(action='stop', handle=stream)
        ars_common_utils.del_ars(data_glob.dut1)
        verify_traffic_distribution(counter, data_glob.interfaces)
        st.banner("test ARS in traffic transit Passed")
        st.report_pass('test_case_passed')

    def test_burst_time_lower_idle_timegap_flowlet_v6(self):
        st.banner("TEST Burst time gap in IXIA set to values lower than the idle time gap Flowlet: Traffic Expected to Pass through Single interface for Burst Time Lower than idle Time gap") # idle time Gap 1 milisecond
        test_failcount = 0
        streams = [trB4['stream_id'], trB5['stream_id']] # streams with burst time 200K 400K (0.2 Mili second , 0.4 Mili Second)
        for stream in streams:
            ars_common_utils.add_ars(data_glob.dut1, global_mode="true", mode="flowlet-quality", idle_time="1000")
            if not run_traffic_multiple_stream(stream):
                test_failcount+=1
            ars_common_utils.del_ars(data_glob.dut1)
        if test_failcount > 0:
            st.banner("Test Failed: For Burst Time Lower than idle Time Gap")
            st.report_fail("test_case_failed_msg", "Traffic does not Pass through Single interface for Burst Time Lower than idle Time gap")
        else:
            st.banner("Passed: Traffic Pass through single interface")
            st.report_pass('test_case_passed')

    def test_burst_time_higher_idle_timegap_flowlet_v6(self):
        st.banner("TestBurst time in IXIA set to values higher than the idle time gap Flowlet: Traffic Expected to Distribute for Burst TIme Higher than idle Time Gap")
        test_failcount = 0
        streams = [trB1['stream_id'], trB2['stream_id']]
        for stream in streams:
            ars_common_utils.add_ars(data_glob.dut1, global_mode="true", mode="flowlet-quality", idle_time="1000")
            if not run_traffic_multiple_stream(stream, 'balanced'):
                test_failcount += 1
            ars_common_utils.del_ars(data_glob.dut1)
        if test_failcount > 0:
            st.banner("Test Failed: For idle time more than Burst gap")
            st.report_fail("test_case_failed_msg", "Traffic does not Distribute for Burst Time Higher than idle Time Gap")
        else:
            st.banner("Test Passed: Traffic is Load Distributed Evenly")
            st.report_pass('test_case_passed')

    def test_continuous_traffic_various_idle_timegap_flowlet_v6(self):
        st.banner("Test Various idle Time GAP Single Continous Traffic Flow Flowlet: Traffic Expected to Pass through single interface for various time gap")
        idleTimeGapArray = ["100", "800"]
        stream = trC1["stream_id"]
        test_failcount = 0
        for i in range(0, 2):
            timegap =idleTimeGapArray[i]
            ars_common_utils.add_ars(data_glob.dut1, global_mode="true", mode="flowlet-quality", idle_time= timegap)
            res = st.show(data_glob.dut1, "sudo show ars-profile")
            expected_values = {'ars_profile_name': 'arsp', 'enable_all_packets': 'true', 'ars_mode': 'flowlet-quality', 'ars_idle_time': timegap }
            if not ars_common_utils.check_ars(res, expected_values):
                st.report_fail("test_case_failed_msg", "ARS Value Not SET Appropriately While Adding")
            if not run_traffic_multiple_stream(stream):
                test_failcount+=1
            ars_common_utils.del_ars(data_glob.dut1)
        if test_failcount > 0:
            st.banner("Test Failed: Various idle Time GAP Single Continous Traffic Flow")
            st.report_fail("test_case_failed_msg", "Traffic does not Pass through single interface for various time gap")
        else:
            st.banner("Test Passed: Traffic Pass through single interface")
            st.report_pass('test_case_passed')

    
    def test_multiple_flow_with_and_without_burst_flowlet_v6(self):
        st.banner("Test Multiple Flow With and Without Burst Flowlet: Traffic Expected to Distribute for MultiFlow Burst traffic")
        st.show(data_glob.dut1, "sudo show ars-profile")
        stream1 = trB1M['stream_id']
        st.banner("Starting to RUN traffic Multi Flow Burst Mode")
        ars_common_utils.add_ars(data_glob.dut1, global_mode="true", mode="flowlet-quality", idle_time="1000")
        ars_common_utils.run_traffic(stream1,tg_handle_1, tg1, data_glob)
        ars_common_utils.del_ars(data_glob.dut1)
        counter = st.show(data_glob.dut1, "sudo -s show interface counters")
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter, data_glob.interfaces):
            st.banner("Test Failed: traffic load not distributed")
            st.report_fail("test_case_failed_msg", "Traffic does not Distribute for MultiFlow Burst Mode Traffic")
        stream2 = trC1M['stream_id']
        st.banner("Starting to RUN traffic Multi Flow without Burst Mode")
        ars_common_utils.add_ars(data_glob.dut1, global_mode="true", mode="per-packet-quality")
        ars_common_utils.run_traffic(stream2,tg_handle_1, tg1, data_glob)
        ars_common_utils.del_ars(data_glob.dut1)
        counter = st.show(data_glob.dut1, "sudo -s show interface counters")
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter, data_glob.interfaces):
            st.banner("Test Failed: traffic load not distributed")
            st.report_fail("test_case_failed_msg", "Traffic does not Distribute for MultiFlow Burst Mode Traffic")

        # Traffic should pass through ECMP after ARS disable
        ars_common_utils.run_traffic(stream1, tg_handle_1, tg1, data_glob)
        counter = st.show(data_glob.dut1, "sudo -s show interface counters")
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter, data_glob.interfaces, margin= 0.5):
            st.banner("Test Failed: traffic load not distributed")
            st.report_fail("test_case_failed_msg", "Traffic does not Distribute for MultiFlow after ARS Disable traffic")

        ars_common_utils.run_traffic(stream2, tg_handle_1, tg1, data_glob)
        counter = st.show(data_glob.dut1, "sudo -s show interface counters")
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter, data_glob.interfaces, margin= 0.5):
            st.banner("Test Failed: traffic load not distributed")
            st.report_fail("test_case_failed_msg", "Traffic does not Distribute for MultiFlow after ARS Disable traffic") 
        st.banner("Test Passed: for Multi Flow With and without Burst Flowlet mode")
        st.report_pass('test_case_passed')

    def test_ars_traffic_intransit_perpacket_v6(self):
        st.banner("(Perpacket) Test Add and Remove when traffic is being sent through, making sure traffic no distributed (on removal) and distributed (on adding ARS)")
        stream = trB1['stream_id']
        # Disabling ARS in Running traffic
        st.banner("Disabling ARS in Running traffic")
        ars_common_utils.add_ars(data_glob.dut1, global_mode="true", mode="per-packet-quality")
        tg1.tg_traffic_control(action="clear_stats", port_handle=tg_handle_1)
        st.config(data_glob.dut1, "sudo -s sonic-clear counters")
        tg1.tg_traffic_control(action='run', handle=stream)
        ars_common_utils.del_ars(data_glob.dut1)
        st.config(data_glob.dut1, "sudo -s sonic-clear counters")
        st.wait(2)
        tg1.tg_traffic_control(action='stop', handle=stream)
        counter = st.show(data_glob.dut1, "sudo -s show interface counters")
        verify_single_interface_traffic(counter,data_glob.interfaces)
        # Adding ARS in Running traffic
        st.banner("Adding ARS in Running traffic")
        tg1.tg_traffic_control(action="clear_stats", port_handle=tg_handle_1)
        st.config(data_glob.dut1, "sudo -s sonic-clear counters")
        tg1.tg_traffic_control(action='run', handle=stream)
        st.banner("ARS Enable")
        ars_common_utils.add_ars(data_glob.dut1, global_mode="true", mode="per-packet-quality")
        st.config(data_glob.dut1, "sudo -s sonic-clear counters")
        st.wait(2)
        tg1.tg_traffic_control(action='stop', handle=stream)
        counter = st.show(data_glob.dut1, "sudo -s show interface counters")
        ars_common_utils.del_ars(data_glob.dut1)
        verify_traffic_distribution(counter,data_glob.interfaces)
        st.banner("test ARS in traffic transit Passed")
        st.report_pass('test_case_passed')

    def test_singleflow_continuous_perpacket_v6(self):
        st.banner("(perpacket)Testing Single Flow Without Bursts : Traffic Expected to flow thorugh single interface for Continuous Traffic")
        stream = trC1['stream_id']
        ars_common_utils.add_ars(data_glob.dut1, global_mode="true", mode="per-packet-quality")
        ars_common_utils.run_traffic(stream,tg_handle_1, tg1, data_glob)
        ars_common_utils.del_ars(data_glob.dut1)
        counter = st.show(data_glob.dut1, "sudo -s show interface counters")
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter, data_glob.interfaces):
            st.banner("Failed traffic load is not Distributed")
            st.report_fail("test_case_failed_msg","Traffic does not Distribute among interface when ARS Enable")
        st.banner("Passed: Traffic Load Distributed Evenly")
        st.report_pass('test_case_passed')

    def test_ars_then_nhg_perpacket_v6(self):
        st.banner("(perpacket)Verify traffic distribution on NHG created after ARS config: Traffic is expected to be load balanced after NHG is created, Ars oid should be getting attached to it.")
        ars_common_utils.add_ars(data_glob.dut1, global_mode="true", mode="per-packet-quality")
        #Configure Ixia Prefix Next Hop Group
        dest_G = tg2.tg_emulation_bgp_route_config(handle=bgp_rtr2['handle'], mode='add', num_routes='1',prefix='2001:db8::15:20:20', ip_version='6')  
        tg2.tg_emulation_bgp_control(handle=bgp_rtr2['handle'], mode='start')
        st.wait(5)
        trB7 = tg1.tg_traffic_config(port_handle=tg_handle_1, emulation_src_handle=tg1_interface['handle'], emulation_dst_handle=dest_G['handle'], 
                                circuit_endpoint_type='ipv6', mode='create', l4_protocol="tcp", tcp_src_port=1002,
                                high_speed_result_analysis='1', frame_size='1024', transmit_mode='multi_burst',
                                    pkts_per_burst='999', inter_burst_gap='2000000', inter_burst_gap_unit='ns', tx_delay='0', tx_delay_unit='bytes',
                                    min_gap_bytes='12')
        stream = trB7['stream_id']
        ars_common_utils.run_traffic(stream,tg_handle_1, tg1, data_glob)
        ars_common_utils.del_ars(data_glob.dut1)
        counter = st.show(data_glob.dut1, "sudo -s show interface counters")
        tg1.tg_traffic_config(mode = 'disable', stream_id =trB7['stream_id'])
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter, data_glob.interfaces):
            st.banner("Test Failed: traffic load is not Distributed")
            st.report_fail("test_case_failed_msg", "Traffic does not pass thorugh single interface on Config ARS before Ixia Prefixes")
        st.banner("Test Passed: Traffic Load Distributed Evenly")
        st.report_pass('test_case_passed')


    def test_multiple_flow_with_and_without_burst_perpacket_v6(self):
        st.banner("(perpacket) Test Multiple Flow With and without Burst: Traffic Expected to Distribute for MultiFlow Burst traffic")
        st.show(data_glob.dut1, "sudo show ars-profile")
        stream1 = trB1M['stream_id']
        # Multi Flow Burst Mode
        st.banner("Starting to RUN traffic Multi Flow Burst Mode")
        ars_common_utils.add_ars(data_glob.dut1, global_mode="true", mode="per-packet-quality")
        ars_common_utils.run_traffic(stream1, tg_handle_1, tg1, data_glob)
        ars_common_utils.del_ars(data_glob.dut1)
        counter = st.show(data_glob.dut1, "sudo -s show interface counters")
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter, data_glob.interfaces):
            st.banner("Test Failed: traffic load not distributed")
            st.report_fail("test_case_failed_msg", "Traffic does not Distribute for MultiFlow Burst Mode Traffic")
        stream2 = trC1M['stream_id']
        st.banner("Starting to RUN traffic Multi Flow without Burst Mode")
        ars_common_utils.add_ars(data_glob.dut1, global_mode="true", mode="per-packet-quality")
        ars_common_utils.run_traffic(stream2, tg_handle_1, tg1, data_glob)
        ars_common_utils.del_ars(data_glob.dut1)
        counter = st.show(data_glob.dut1, "sudo -s show interface counters")
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter, data_glob.interfaces):
            st.banner("Test Failed: traffic load not distributed")
            st.report_fail("test_case_failed_msg", "Traffic does not Distribute for MultiFlow Burst Mode Traffic")
        # Traffic should pass through ECMP after ARS disable
        ars_common_utils.run_traffic(stream1, tg_handle_1, tg1, data_glob)
        counter = st.show(data_glob.dut1, "sudo -s show interface counters")
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter, data_glob.interfaces, margin= 0.5):
            st.banner("Test Failed: traffic load not distributed")
            st.report_fail("test_case_failed_msg", "Traffic does not Distribute for MultiFlow after ARS Disable traffic")

        ars_common_utils.run_traffic(stream2, tg_handle_1, tg1, data_glob)
        counter = st.show(data_glob.dut1, "sudo -s show interface counters")
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter, data_glob.interfaces, margin= 0.5):
            st.banner("Test Failed: traffic load not distributed")
            st.report_fail("test_case_failed_msg", "Traffic does not Distribute for MultiFlow after ARS Disable traffic") 
        st.banner("Test Passed: for Multi Flow With and without Burst mode")
        st.report_pass('test_case_passed')

    def test_bring_down_one_nhop_member_flowlet_v6(self):
        st.banner("IN TEST Bring Down One Interface Flowlet: Traffic is expected to Distribute on ARS Enable Before and After Interface Shutdown")
        stream = trB1['stream_id']
        st.config(data_glob.dut1, "sudo -s sonic-clear counters")
        ars_common_utils.add_ars(data_glob.dut1, global_mode="true", mode="flowlet-quality", idle_time="1000")
        ars_common_utils.run_traffic(stream, tg_handle_1, tg1, data_glob)
        counter = st.show(data_glob.dut1, "sudo -s show interface counters")
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter, data_glob.interfaces):
            st.banner("Test Failed: traffic load not distributed")
            st.report_fail("test_case_failed_msg", "Traffic does not Distribute on ARS Enable Before Interface Shutdown")
        st.config(data_glob.dut1, "sudo -s sonic-clear counters")
        #Bring down one interface 
        interface_obj.interface_shutdown(vars.D1, vars.D1D2P1, skip_verify=False)
        st.wait(2)
        ars_common_utils.run_traffic(stream, tg_handle_1, tg1, data_glob)
        ars_common_utils.del_ars(data_glob.dut1)
        counter = st.show(data_glob.dut1, "sudo -s show interface counters ")
        interface_obj.interface_noshutdown(vars.D1, vars.D1D2P1, skip_verify=False)
        st.wait(20)
        intfrecord =[vars.D1D2P2, vars.D1D2P3, vars.D1D2P4, vars.D1D2P5, vars.D1D2P7, vars.D1D2P8]
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter, intfrecord):
            st.banner("Test Failed: traffic load not distributed")
            st.report_fail("test_case_failed_msg", "Traffic does not Distribute on ARS Enable after Interface Shutdown")
        st.wait(50)
        st.banner("Test Passed Traffic is Load Distributed Evenly Even after bringing down interface")
        st.report_pass('test_case_passed')

    def test_bring_down_one_nhop_member_perpacket_v6(self):
        st.banner("IN TEST Bring Down One Interface Perpacket: Traffic is expected to Distribute on ARS Enable Before and After Interface Shutdown")
        stream = trB1['stream_id']
        st.config(data_glob.dut1, "sudo -s sonic-clear counters")
        ars_common_utils.add_ars(data_glob.dut1, global_mode="true", mode="per-packet-quality")
        ars_common_utils.run_traffic(stream, tg_handle_1, tg1, data_glob)
        counter = st.show(data_glob.dut1, "sudo -s show interface counters ")
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter, data_glob.interfaces):
            st.banner("Test Failed: traffic load not distributed")
            st.report_fail("test_case_failed_msg", "Traffic does not Distribute on ARS Enable Before Interface Shutdown")
        st.config(data_glob.dut1, "sudo -s sonic-clear counters")
        #Bring down one interface 
        interface_obj.interface_shutdown(vars.D1, vars.D1D2P1, skip_verify=False)
        st.wait(2)
        ars_common_utils.run_traffic(stream, tg_handle_1, tg1, data_glob)
        ars_common_utils.del_ars(data_glob.dut1)
        counter = st.show(data_glob.dut1, "sudo -s show interface counters ")
        interface_obj.interface_noshutdown(vars.D1, vars.D1D2P1, skip_verify=False)
        st.wait(50)
        intfrecord =[vars.D1D2P2, vars.D1D2P3, vars.D1D2P4, vars.D1D2P5, vars.D1D2P7, vars.D1D2P8]
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter, intfrecord):
            st.banner("Test Failed: traffic load not distributed")
            st.report_fail("test_case_failed_msg", "Traffic does not Distribute on ARS Enable after Interface Shutdown")
        st.banner("Test Passed Traffic is Load Distributed Evenly Even after bringing down interface")
        st.report_pass('test_case_passed')
        

@pytest.mark.usefixtures('fixture_v4')
class Test_IPV4_config_ars():
    def test_ars_then_nhg_perpacket_v4(self):
        st.banner("(perpacket) Verify traffic distribution on NHG created after ARS config Flowlet: Traffic is expected to be load balanced after NHG is created, Ars oid should be getting attached to it.")
        ars_common_utils.add_ars(data_glob.dut1, global_mode="true", mode="per-packet-quality")
        #Configure Ixia Prefix Next Hop Group
        dest_G = tg2.tg_emulation_bgp_route_config(handle=bgp_rtr2['handle'], mode='add', num_routes='1', prefix='19.20.20.1')  
        tg2.tg_emulation_bgp_control(handle=bgp_rtr2['handle'], mode='start')
        st.wait(5)
        trB7 = tg1.tg_traffic_config(port_handle=tg_handle_1, emulation_src_handle=tg1_interface['handle'], emulation_dst_handle=dest_G['handle'], 
                                circuit_endpoint_type='ipv4', mode='create', l4_protocol="tcp", tcp_src_port=1002,
                                high_speed_result_analysis='1', frame_size='1024', transmit_mode='multi_burst',
                                    pkts_per_burst='999', inter_burst_gap='2000000', inter_burst_gap_unit='ns', tx_delay='0', tx_delay_unit='bytes',
                                    min_gap_bytes='12')
        stream = trB7['stream_id']
        ars_common_utils.run_traffic(stream, tg_handle_1, tg1, data_glob)
        ars_common_utils.del_ars(data_glob.dut1)
        counter = st.show(data_glob.dut1, "sudo -s show interface counters")
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter, data_glob.interfaces):
            st.banner("Test Failed: traffic load is not Distributed")
            st.report_fail("test_case_failed_msg", "Traffic does not pass thorugh single interface on Config ARS before Ixia Prefixes")
        st.banner("Test Passed: Traffic Load Distributed Evenly")
        st.report_pass('test_case_passed')

    def test_ars_then_nhg_flowlet_v4(self):
        st.banner("Verify traffic distribution on NHG created after ARS config Flowlet: Traffic is expected to be load balanced after NHG is created, Ars oid should be getting attached to it.")
        ars_common_utils.add_ars(data_glob.dut1, global_mode="true", mode="flowlet-quality", idle_time="1000")
        #Configure Ixia Prefix Next Hop Group
        dest_G = tg2.tg_emulation_bgp_route_config(handle=bgp_rtr2['handle'], mode='add', num_routes='1', prefix='18.20.20.1')  
        tg2.tg_emulation_bgp_control(handle=bgp_rtr2['handle'], mode='start')
        st.wait(5)
        trB7 = tg1.tg_traffic_config(port_handle=tg_handle_1, emulation_src_handle=tg1_interface['handle'], emulation_dst_handle=dest_G['handle'], 
                                circuit_endpoint_type='ipv4', mode='create', l4_protocol="tcp", tcp_src_port=1002,
                                high_speed_result_analysis='1', frame_size='1024', transmit_mode='multi_burst',
                                    pkts_per_burst='999', inter_burst_gap='2000000', inter_burst_gap_unit='ns', tx_delay='0', tx_delay_unit='bytes',
                                    min_gap_bytes='12')
        stream = trB7['stream_id']
        ars_common_utils.run_traffic(stream, tg_handle_1, tg1, data_glob)
        ars_common_utils.del_ars(data_glob.dut1)
        counter = st.show(data_glob.dut1, "sudo -s show interface counters")
        tg1.tg_traffic_config(mode = 'disable', stream_id =trB7['stream_id'])
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter, data_glob.interfaces):
            st.banner("Test Failed: traffic load is not Distributed")
            st.report_fail("test_case_failed_msg", "Traffic pass thorugh single interface on Config ARS before Ixia Prefixes")
        st.banner("Test Passed: Traffic Load Distributed Evenly")
        st.report_pass('test_case_passed')

    def test_singleflow_without_burst_flowlet_v4(self):
        st.banner("Testing Single Flow Without Bursts Flowlet: Traffic Expected to flow thorugh single interface for Continuous Traffic")
        stream = trC1['stream_id']
        ars_common_utils.add_ars(data_glob.dut1, global_mode="true", mode="flowlet-quality", idle_time="1000")
        ars_common_utils.run_traffic(stream, tg_handle_1, tg1, data_glob)
        ars_common_utils.del_ars(data_glob.dut1)
        counter = st.show(data_glob.dut1, "sudo -s show interface counters")
        if not ars_common_utils.check_traffic_single_interface(tg1, tg2, tg_handle_1, tg_handle_2, counter, data_glob.interfaces):
            st.banner("Failed: traffic pass through Multiple Interface")
            st.report_fail("test_case_failed_msg","Traffic does not flow thorugh single interface for Continuous Traffic")
        st.banner("Passed: Traffic passes through Single Interface")
        st.report_pass('test_case_passed')

    def test_ars_traffic_intransit_flowlet_v4(self):
        st.banner("Test Add and Remove when traffic is being sent through, making sure traffic no distributed (on removal) and distributed (on adding ARS) Flowlet")
        stream = trB1['stream_id']
        # Disabling ARS in Running traffic
        st.banner("Disabling ARS in Running traffic")
        ars_common_utils.add_ars(data_glob.dut1, global_mode="true", mode="flowlet-quality", idle_time="1000")
        tg1.tg_traffic_control(action="clear_stats", port_handle=tg_handle_1)
        tg1.tg_traffic_control(action='run', handle=stream)
        ars_common_utils.del_ars(data_glob.dut1)
        st.config(data_glob.dut1, "sudo -s sonic-clear counters")
        st.wait(2)
        counter = st.show(data_glob.dut1, "sudo -s show interface counters")
        tg1.tg_traffic_control(action='stop', handle=stream)
        verify_single_interface_traffic(counter, data_glob.interfaces)
        # Adding ARS in Running traffic
        st.banner("Adding ARS in Running traffic")
        tg1.tg_traffic_control(action="clear_stats", port_handle=tg_handle_1)
        tg1.tg_traffic_control(action='run', handle=stream)
        st.banner("ARS Enable")
        ars_common_utils.add_ars(data_glob.dut1, global_mode="true", mode="flowlet-quality", idle_time="1000")
        st.config(data_glob.dut1, "sudo -s sonic-clear counters")
        st.wait(2)
        counter = st.show(data_glob.dut1, "sudo -s show interface counters")
        tg1.tg_traffic_control(action='stop', handle=stream)
        ars_common_utils.del_ars(data_glob.dut1)
        verify_traffic_distribution(counter, data_glob.interfaces)
        st.banner("test ARS in traffic transit Passed")
        st.report_pass('test_case_passed')

    def test_burst_time_lower_idle_timegap_flowlet_v4(self):
        st.banner("TEST Burst time gap in IXIA set to values lower than the idle time gap Flowlet: Traffic Expected to Pass through Single interface for Burst Time Lower than idle Time gap") # idle time Gap 1 milisecond
        test_failcount = 0
        streams = [trB4['stream_id'], trB5['stream_id']] # streams with burst time 200K 400K (0.2 Mili second , 0.4 Mili Second)
        for stream in streams:
            ars_common_utils.add_ars(data_glob.dut1, global_mode="true", mode="flowlet-quality", idle_time="1000")
            if not run_traffic_multiple_stream(stream):
                test_failcount+=1
            ars_common_utils.del_ars(data_glob.dut1)
        if test_failcount > 0:
            st.banner("Test Failed: For Burst Time Lower than idle Time Gap")
            st.report_fail("test_case_failed_msg", "Traffic does not Pass through Single interface for Burst Time Lower than idle Time gap")
        else:
            st.banner("Passed: Traffic Pass through single interface")
            st.report_pass('test_case_passed')

    def test_burst_time_higher_idle_timegap_flowlet_v4(self):
        st.banner("TestBurst time in IXIA set to values higher than the idle time gap Flowlet: Traffic Expected to Distribute for Burst TIme Higher than idle Time Gap")
        test_failcount = 0
        streams = [trB1['stream_id'], trB2['stream_id']]
        for stream in streams:
            ars_common_utils.add_ars(data_glob.dut1, global_mode="true", mode="flowlet-quality", idle_time="1000")
            if not run_traffic_multiple_stream(stream, 'balanced'):
                test_failcount += 1
            ars_common_utils.del_ars(data_glob.dut1)
        if test_failcount > 0:
            st.banner("Test Failed: For idle time more than Burst gap")
            st.report_fail("test_case_failed_msg", "Traffic does not Distribute for Burst TIme Higher than idle Time Gap")
        else:
            st.banner("Test Passed: Traffic is Load Distributed Evenly")
            st.report_pass('test_case_passed')

    def test_multiple_flow_with_and_without_burst_flowlet_v4(self):
        st.banner("Test Multiple Flow With and without Burst Flowlet: Traffic Expected to Distribute for MultiFlow Burst traffic")
        st.show(data_glob.dut1, "sudo show ars-profile")
        stream1 = trB1M['stream_id']
        # Multi Flow Burst Mode
        st.banner("Starting to RUN traffic Multi Flow Burst Mode")
        ars_common_utils.add_ars(data_glob.dut1, global_mode="true", mode="flowlet-quality", idle_time="1000")
        ars_common_utils.run_traffic(stream1, tg_handle_1, tg1, data_glob)
        ars_common_utils.del_ars(data_glob.dut1)
        counter = st.show(data_glob.dut1, "sudo -s show interface counters")
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter, data_glob.interfaces):
            st.banner("Test Failed: traffic load not distributed")
            st.report_fail("test_case_failed_msg", "Traffic does not Distribute for MultiFlow Burst Mode Traffic")   
        stream2 = trC1M['stream_id']
        st.banner("Starting to RUN traffic Multi Flow without Burst Mode")
        ars_common_utils.add_ars(data_glob.dut1, global_mode="true", mode="flowlet-quality", idle_time="1000")
        ars_common_utils.run_traffic(stream2, tg_handle_1, tg1, data_glob)
        ars_common_utils.del_ars(data_glob.dut1)
        counter = st.show(data_glob.dut1, "sudo -s show interface counters")
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter, data_glob.interfaces):
            st.banner("Test Failed: traffic load not distributed")
            st.report_fail("test_case_failed_msg", "Traffic does not Distribute for MultiFlow Burst Mode Traffic")   
        # Traffic should pass through ECMP after ARS disable
        ars_common_utils.run_traffic(stream1, tg_handle_1, tg1, data_glob)
        counter = st.show(data_glob.dut1, "sudo -s show interface counters")
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter, data_glob.interfaces, margin= 0.5):
            st.banner("Test Failed: traffic load not distributed")
            st.report_fail("test_case_failed_msg", "Traffic does not Distribute for MultiFlow after ARS Disable traffic")

        ars_common_utils.run_traffic(stream2, tg_handle_1, tg1, data_glob)
        counter = st.show(data_glob.dut1, "sudo -s show interface counters")
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter, data_glob.interfaces, margin= 0.5):
            st.banner("Test Failed: traffic load not distributed")
            st.report_fail("test_case_failed_msg", "Traffic does not Distribute for MultiFlow after ARS Disable traffic") 
        st.banner("Test Passed: for Multi Flow With Burst mode")
        st.report_pass('test_case_passed')

    def test_continuous_traffic_various_idle_timegap_flowlet_v4(self):
        st.banner("Test Various idle Time GAP Single Continous Traffic Flow Flowlet: Traffic Expected to Pass through single interface for various time gap")
        idleTimeGapArray = ["100", "800"]
        stream = trC1["stream_id"]
        test_failcount = 0
        for i in range(0, 2):
            timegap =idleTimeGapArray[i]
            ars_common_utils.add_ars(data_glob.dut1, global_mode="true", mode="flowlet-quality", idle_time= timegap)
            res = st.show(data_glob.dut1, "sudo show ars-profile")
            expected_values = {'ars_profile_name': 'arsp', 'enable_all_packets': 'true', 'ars_mode': 'flowlet-quality', 'ars_idle_time': timegap }
            if not ars_common_utils.check_ars(res, expected_values):
                st.report_fail("test_case_failed_msg", "ARS Value Not SET Appropriately While Adding")
            if not run_traffic_multiple_stream(stream):
                test_failcount+=1
            ars_common_utils.del_ars(data_glob.dut1)
        if test_failcount > 0:
            st.banner("Test Failed: Various idle Time GAP Single Continous Traffic Flow")
            st.report_fail("test_case_failed_msg", "Traffic does not Pass through single interface for various time gap")
        else:
            st.banner("Test Passed: Traffic Pass through single interface")
            st.report_pass('test_case_passed')

    def test_ars_traffic_intransit_perpacket_v4(self):
        st.banner("(Perpacket) Test Add and Remove when traffic is being sent through, making sure traffic no distributed (on removal) and distributed (on adding ARS)")
        stream = trB1['stream_id']
        # Disabling ARS in Running traffic
        st.banner("Disabling ARS in Running traffic")
        ars_common_utils.add_ars(data_glob.dut1, global_mode="true", mode="per-packet-quality")
        tg1.tg_traffic_control(action="clear_stats", port_handle=tg_handle_1)
        st.config(data_glob.dut1, "sudo -s sonic-clear counters")
        tg1.tg_traffic_control(action='run', handle=stream)
        ars_common_utils.del_ars(data_glob.dut1)
        st.config(data_glob.dut1, "sudo -s sonic-clear counters")
        st.wait(2)
        tg1.tg_traffic_control(action='stop', handle=stream)
        counter = st.show(data_glob.dut1, "sudo -s show interface counters")
        verify_single_interface_traffic(counter, data_glob.interfaces)
        # Adding ARS in Running traffic
        st.banner("Adding ARS in Running traffic")
        tg1.tg_traffic_control(action="clear_stats", port_handle=tg_handle_1)
        st.config(data_glob.dut1, "sudo -s sonic-clear counters")
        tg1.tg_traffic_control(action='run', handle=stream)
        st.banner("ARS Enable")
        ars_common_utils.add_ars(data_glob.dut1, global_mode="true", mode="per-packet-quality")
        st.config(data_glob.dut1, "sudo -s sonic-clear counters")
        st.wait(2)
        tg1.tg_traffic_control(action='stop', handle=stream)
        counter = st.show(data_glob.dut1, "sudo -s show interface counters")
        ars_common_utils.del_ars(data_glob.dut1)
        verify_traffic_distribution(counter, data_glob.interfaces)
        st.banner("test ARS in traffic transit Passed")
        st.report_pass('test_case_passed')

    def test_singleflow_continuous_perpacket_v4(self):
        st.banner("(perpacket)Testing Single Flow Without Bursts : Traffic Expected to Distribute Across Interface")
        stream = trC1['stream_id']
        ars_common_utils.add_ars(data_glob.dut1, global_mode="true", mode="per-packet-quality")
        ars_common_utils.run_traffic(stream, tg_handle_1, tg1, data_glob)
        ars_common_utils.del_ars(data_glob.dut1)
        counter = st.show(data_glob.dut1, "sudo -s show interface counters")
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter, data_glob.interfaces):
            st.banner("Failed traffic load is not Distributed")
            st.report_fail("test_case_failed_msg","Traffic does not Distribute among interface when ARS Enable")
        st.banner("Passed: Traffic Load Distributed Evenly")
        st.report_pass('test_case_passed')


    def test_multiple_flow_with_and_without_burst_perpacket_v4(self):
        st.banner("(perpacket)Test Multiple Flow With Burst: Traffic Expected to Distribute for MultiFlow Burst traffic")
        st.show(data_glob.dut1, "sudo show ars-profile")
        stream1 = trB1M['stream_id']
        # Multi Flow Burst Mode
        st.banner("Starting to RUN traffic Multi Flow Burst Mode")
        ars_common_utils.add_ars(data_glob.dut1, global_mode="true", mode="per-packet-quality")
        ars_common_utils.run_traffic(stream1, tg_handle_1, tg1, data_glob)
        ars_common_utils.del_ars(data_glob.dut1)
        counter = st.show(data_glob.dut1, "sudo -s show interface counters")
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter, data_glob.interfaces):
            st.banner("Test Failed: traffic load not distributed")
            st.report_fail("test_case_failed_msg", "Traffic does not Distribute for MultiFlow Burst Mode Traffic")
        stream2 = trC1M['stream_id']
        st.banner("Starting to RUN traffic Multi Flow without Burst Mode")
        ars_common_utils.add_ars(data_glob.dut1, global_mode="true", mode="per-packet-quality")
        ars_common_utils.run_traffic(stream2, tg_handle_1, tg1, data_glob)
        ars_common_utils.del_ars(data_glob.dut1)
        counter = st.show(data_glob.dut1, "sudo -s show interface counters")
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter, data_glob.interfaces):
            st.banner("Test Failed: traffic load not distributed")
            st.report_fail("test_case_failed_msg", "Traffic does not Distribute for MultiFlow Burst Mode Traffic")
        # Traffic should pass through ECMP after ARS disable
        ars_common_utils.run_traffic(stream1, tg_handle_1, tg1, data_glob)
        counter = st.show(data_glob.dut1, "sudo -s show interface counters")
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter, data_glob.interfaces, margin= 0.5):
            st.banner("Test Failed: traffic load not distributed")
            st.report_fail("test_case_failed_msg", "Traffic does not Distribute for MultiFlow after ARS Disable traffic")

        ars_common_utils.run_traffic(stream2, tg_handle_1, tg1, data_glob)
        counter = st.show(data_glob.dut1, "sudo -s show interface counters")
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter, data_glob.interfaces, margin= 0.5):
            st.banner("Test Failed: traffic load not distributed")
            st.report_fail("test_case_failed_msg", "Traffic does not Distribute for MultiFlow after ARS Disable traffic") 
        st.banner("Test Passed: for Multi Flow With Burst mode")
        st.report_pass('test_case_passed')

    def test_bring_down_one_nhop_member_flowlet_v4(self):
        st.banner("IN TEST Bring Down One Interface Flowlet: Traffic is expected to Distribute on ARS Enable Before and After Interface Shutdown")
        stream = trB1['stream_id']
        st.config(data_glob.dut1, "sudo -s sonic-clear counters")
        ars_common_utils.add_ars(data_glob.dut1, global_mode="true", mode="flowlet-quality", idle_time="1000")
        ars_common_utils.run_traffic(stream, tg_handle_1, tg1, data_glob)
        counter = st.show(data_glob.dut1, "sudo -s show interface counters")
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter, data_glob.interfaces):
            st.banner("Test Failed: traffic load not distributed")
            ars_common_utils.del_ars(data_glob.dut1)
            st.report_fail("test_case_failed_msg", "Traffic does not Distribute on ARS Enable Before Interface Shutdown")
        st.config(data_glob.dut1, "sudo -s sonic-clear counters")
        #Bring down one interface 
        interface_obj.interface_shutdown(vars.D1, vars.D1D2P1, skip_verify=False)
        st.wait(2)
        ars_common_utils.run_traffic(stream, tg_handle_1, tg1, data_glob)
        ars_common_utils.del_ars(data_glob.dut1)
        counter = st.show(data_glob.dut1, "sudo -s show interface counters")
        interface_obj.interface_noshutdown(vars.D1, vars.D1D2P1, skip_verify=False)
        st.wait(20)
        intfrecord =[vars.D1D2P2, vars.D1D2P3, vars.D1D2P4, vars.D1D2P5, vars.D1D2P7, vars.D1D2P8]
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter, intfrecord):
            st.banner("Test Failed: traffic load not distributed")
            ars_common_utils.del_ars(data_glob.dut1)
            st.report_fail("test_case_failed_msg", "Traffic does not Distribute on ARS Enable after Interface Shutdown")
        st.wait(50)
        st.banner("Test Passed Traffic is Load Distributed Evenly Even after bringing down interface")
        st.report_pass('test_case_passed')

    def test_bring_down_one_nhop_member_perpacket_v4(self):
        st.banner("IN TEST Bring Down One Interface Perpacket: Traffic is expected to Distribute on ARS Enable Before and After Interface Shutdown")
        stream = trB1['stream_id']
        st.config(data_glob.dut1, "sudo -s sonic-clear counters")
        ars_common_utils.add_ars(data_glob.dut1, global_mode="true", mode="per-packet-quality")
        ars_common_utils.run_traffic(stream, tg_handle_1, tg1, data_glob)
        counter = st.show(data_glob.dut1, "sudo -s show interface counters")
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter, data_glob.interfaces):
            st.banner("Test Failed: traffic load not distributed")
            ars_common_utils.del_ars(data_glob.dut1)
            st.report_fail("test_case_failed_msg", "Traffic does not Distribute on ARS Enable Before Interface Shutdown")
        st.config(data_glob.dut1, "sudo -s sonic-clear counters")
        #Bring down one interface 
        interface_obj.interface_shutdown(vars.D1, vars.D1D2P1, skip_verify=False)
        st.wait(2)
        ars_common_utils.run_traffic(stream, tg_handle_1, tg1, data_glob)
        ars_common_utils.del_ars(data_glob.dut1)
        counter = st.show(data_glob.dut1, "sudo -s show interface counters")
        interface_obj.interface_noshutdown(vars.D1, vars.D1D2P1, skip_verify=False)
        st.wait(20)
        intfrecord =[vars.D1D2P2, vars.D1D2P3, vars.D1D2P4, vars.D1D2P5, vars.D1D2P7, vars.D1D2P8]
        if not ars_common_utils.check_traffic_balanced(tg1, tg2, tg_handle_1, tg_handle_2, counter, intfrecord):
            st.banner("Test Failed: traffic load not distributed")
            ars_common_utils.del_ars(data_glob.dut1)
            st.report_fail("test_case_failed_msg", "Traffic does not Distribute on ARS Enable after Interface Shutdown")
        st.wait(50)
        st.banner("Test Passed Traffic is Load Distributed Evenly Even after bringing down interface")
        st.report_pass('test_case_passed')
        