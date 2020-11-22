import time
import pytest

from spytest import st, tgapi, SpyTestDict

import apis.system.basic as basic
import apis.routing.ip as ipapi
import apis.switching.vlan as vlanapi
import apis.routing.dhcp_relay as dhcp_relay

data = SpyTestDict()
data.vlan = '10'
data.vlan_routing = 'Vlan' + data.vlan
data.ipv4_addr_D1T1P1 = '21.1.1.1'
data.ipv4_addr_D1T1P2 = '22.1.1.1'
data.ipv4_addr_D1P1T1 = '21.1.1.100'
data.ipv4_addr_D1P2T1 = '22.1.1.100'
data.netmask = '24'
data.ipv6_addr_D1T1P1 = '2001:1::1'
data.ipv6_addr_D1T1P2 = '2001:2::1'
data.ipv6_addr_D1P1T1 = '2001:1::100'
data.ipv6_addr_D1P2T1 = '2001:2::100'
data.ipv6_netmask = '64'


def get_handles():
    st.ensure_min_topology("D1T1:2")
    tg1, tg_ph_1 = tgapi.get_handle_byname("T1D1P1")
    tg2, tg_ph_2 = tgapi.get_handle_byname("T1D1P2")
    return (tg1, tg2, tg_ph_1, tg_ph_2)


@pytest.fixture(scope="module", autouse=True)
def tgen_ut_module_hooks(request):
    global vars, tg1, tg2, tg_ph_1, tg_ph_2
    vars = st.ensure_min_topology("D1T1:2")
    (tg1, tg2, tg_ph_1, tg_ph_2) = get_handles()
    yield


@pytest.fixture(scope="function", autouse=True)
def tgen_ut_func_hooks(request):
    if 'test_dhcp_emulation' in request.node.name:
        tgen_ut_dhcp_config(config='yes')
    if 'test_dhcpv6_emulation' in request.node.name:
        tgen_ut_dhcp_config(config='yes', family='ipv6')

    yield
    if 'test_dhcp_emulation' in request.node.name:
        tgen_ut_dhcp_config(config='no')
    if 'test_dhcpv6_emulation' in request.node.name:
        tgen_ut_dhcp_config(config='no', family='ipv6')


def tgen_ut_dhcp_config(config='yes', family='ipv4'):
    if config == 'yes':
        if family == 'ipv4':
            '''
            ipapi.config_ip_addr_interface(vars.D1, vars.D1T1P2, '1.1.1.2', data.netmask)
            ipapi.config_ip_addr_interface(vars.D1, vars.D1T1P1, '192.168.0.1', data.netmask)
            dhcp_relay.dhcp_relay_config_add(vars.D1, interface=vars.D1T1P1, IP='1.1.1.1')
            '''
            # Vlan config
            vlanapi.create_vlan(vars.D1, data.vlan)
            vlanapi.add_vlan_member(vars.D1, data.vlan, vars.D1T1P1, tagging_mode=True)
            ipapi.config_ip_addr_interface(vars.D1, data.vlan_routing, '192.168.0.1', data.netmask)
            ipapi.config_ip_addr_interface(vars.D1, vars.D1T1P2, '1.1.1.2', data.netmask)
            dhcp_relay.dhcp_relay_config_add(vars.D1, interface=data.vlan_routing, IP='1.1.1.1')

        else:
            '''
            ipapi.config_ip_addr_interface(vars.D1, vars.D1T1P1, '3000::1', data.ipv6_netmask, family='ipv6')
            ipapi.config_ip_addr_interface(vars.D1, vars.D1T1P2, '2000::1', data.ipv6_netmask, family='ipv6')
            dhcp_relay.dhcp_relay_config_add(vars.D1, interface=vars.D1T1P1, IP='2000::2', family='ipv6')
            '''
            # Vlan Config
            vlanapi.create_vlan(vars.D1, data.vlan)
            vlanapi.add_vlan_member(vars.D1, data.vlan, vars.D1T1P1, tagging_mode=True)
            ipapi.config_ip_addr_interface(vars.D1, data.vlan_routing, '3000::1', data.ipv6_netmask, family='ipv6')
            ipapi.config_ip_addr_interface(vars.D1, vars.D1T1P2, '2000::1', data.ipv6_netmask, family='ipv6')
            dhcp_relay.dhcp_relay_config_add(vars.D1, interface=data.vlan_routing, IP='2000::2', family='ipv6')
    else:
        if family == 'ipv4':
            '''
            dhcp_relay.dhcp_relay_config_remove(vars.D1, interface=vars.D1T1P1, IP='1.1.1.1')
            ipapi.delete_ip_interface(vars.D1, vars.D1T1P2, '1.1.1.2', data.netmask)
            ipapi.delete_ip_interface(vars.D1, vars.D1T1P1, '192.168.0.1', data.netmask)
            '''
            # Vlan unconfig
            dhcp_relay.dhcp_relay_config_remove(vars.D1, interface=data.vlan_routing, IP='1.1.1.1')
            ipapi.delete_ip_interface(vars.D1, vars.D1T1P2, '1.1.1.2', data.netmask)
            ipapi.delete_ip_interface(vars.D1, data.vlan_routing, '192.168.0.1', data.netmask)
            vlanapi.delete_vlan_member(vars.D1, data.vlan, vars.D1T1P1)
            vlanapi.delete_vlan(vars.D1, data.vlan)

        else:
            '''
            dhcp_relay.dhcp_relay_config_remove(vars.D1, interface=vars.D1T1P1, IP='2000::2', family='ipv6')
            ipapi.delete_ip_interface(vars.D1, vars.D1T1P1, '3000::1', data.ipv6_netmask, family='ipv6')
            ipapi.delete_ip_interface(vars.D1, vars.D1T1P2, '2000::1', data.ipv6_netmask, family='ipv6')
            '''
            # Vlan Unconfig
            dhcp_relay.dhcp_relay_config_remove(vars.D1, interface=data.vlan_routing, IP='2000::2', family='ipv6')
            ipapi.delete_ip_interface(vars.D1, vars.D1T1P2, '2000::1', data.ipv6_netmask, family='ipv6')
            ipapi.delete_ip_interface(vars.D1, data.vlan_routing, '3000::1', data.ipv6_netmask, family='ipv6')
            vlanapi.delete_vlan_member(vars.D1, data.vlan, vars.D1T1P1)
            vlanapi.delete_vlan(vars.D1, data.vlan)


@pytest.mark.tgen1
def test_ut_tgen_link_states():

    status_1 = tg1.tg_interface_control(mode="check_link", desired_status='up', port_handle=tg_ph_1)
    status_2 = tg2.tg_interface_control(mode="check_link", desired_status='up', port_handle=tg_ph_2)
    st.log("{} Link Status = {}".format(tg_ph_1, status_1))
    st.log("{} Link Status = {}".format(tg_ph_2, status_2))
    st.report_pass("operation_successful")


@pytest.mark.tgen1
def test_basic_stats():
    #reset statistics and delete if any existing streamblocks
    for action in ['reset','clear_stats']:
        tg1.tg_traffic_control(action=action,port_handle=tg_ph_1)
        tg2.tg_traffic_control(action=action,port_handle=tg_ph_2)

    #creating streamblock
    stream1 = tg1.tg_traffic_config(mac_src='00.00.00.00.00.01', mac_dst='00.00.00.00.00.02', rate_pps='100',
                                    mode='create', vlan_id='10', duration='10', frame_size='256',
                                    port_handle=tg_ph_1, transmit_mode='continuous', l2_encap='ethernet_ii_vlan')

    #send contiuous traffic for 10 seconds with 100 packets per second
    tg1.tg_traffic_control(action='run', stream_handle=stream1['stream_id'], duration='10')

    #sleeing for 10 seconds before verifying Rx side packets per second
    #st.wait(10)

    vars = st.get_testbed_vars()
    traffic_details = {
            '1': {
                'tx_ports' : [vars.T1D1P1],
                'tx_obj' : [tg1],
                'exp_ratio' : [1],
                'rx_ports' : [vars.T1D1P2],
                'rx_obj' : [tg2],
                },
            }
    result1 = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_rate')

    tg1.tg_traffic_control(action='stop', stream_handle=stream1['stream_id'])

    result2 = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count')

    if result1 and result2:
        st.report_pass("operation_successful")
    else:
        st.report_fail("operation_failed")


@pytest.mark.tgen1
def test_stream_reuse():
    #reset statistics and delete if any existing streamblocks
    for action in ['reset','clear_stats']:
        tg1.tg_traffic_control(action=action,port_handle=tg_ph_1)
        tg2.tg_traffic_control(action=action,port_handle=tg_ph_2)

    stream1 = tg1.tg_traffic_config(mac_src='00.00.00.00.00.01', mac_dst='00.00.00.00.00.02', rate_pps='10',
                                    mode='create', vlan_id='10', vlan='enable', frame_size='64', duration='2',
                                    port_handle=tg_ph_1, transmit_mode='continuous', l2_encap='ethernet_ii_vlan')

    #send contiuous traffic for 2 seconds with 10 packets per second
    tg1.tg_traffic_control(action='run', stream_handle=stream1['stream_id'], duration='2')
    #st.wait(5)

    vars = st.get_testbed_vars()
    traffic_details = {
            '1': {
                'tx_ports' : [vars.T1D1P1],
                'tx_obj' : [tg1],
                'exp_ratio' : [1],
                'rx_ports' : [vars.T1D1P2],
                'rx_obj' : [tg2],
                },
            }
    tg1.tg_traffic_control(action='stop', stream_handle=stream1['stream_id'])
    result1 = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count')

    #clear the stats
    tg1.tg_traffic_control(action='clear_stats',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='clear_stats',port_handle=tg_ph_2)
    #st.wait(5)

    # start the traffic again
    tg1.tg_traffic_control(action='run',stream_handle=stream1['stream_id'],duration='2')
    #st.wait(5)
    tg1.tg_traffic_control(action='stop', stream_handle=stream1['stream_id'])
    result2 = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count')

    if result1 and result2:
        st.report_pass("operation_successful")
    else:
        st.report_fail("operation_failed")


@pytest.mark.tgen1
def test_aggregate_stats():
    #reset statistics and delete if any existing streamblocks
    for action in ['reset','clear_stats']:
        tg1.tg_traffic_control(action=action,port_handle=tg_ph_1)
        tg2.tg_traffic_control(action=action,port_handle=tg_ph_2)

    # for stream level stats verificaion, it is required to define rx port handle in 'port_handle2'
    stream1 = tg1.tg_traffic_config(mac_src = '00.00.00.00.00.01',mac_dst='00.00.00.00.00.02',rate_pps='10',mode='create',\
                  port_handle=tg_ph_1,transmit_mode='continuous',l2_encap='ethernet_ii_vlan',vlan_id='10',vlan='enable',\
                  frame_size='64',duration='2',port_handle2=tg_ph_2)
    stream_id1 = stream1['stream_id']

    #send contiuous traffic for 2 seconds with 10 packets per second
    tg1.tg_traffic_control(action='run', stream_handle=stream_id1, duration = '2')
    #st.wait(5)

    vars = st.get_testbed_vars()
    traffic_details = {
            '1': {
                'tx_ports' : [vars.T1D1P1],
                'tx_obj' : [tg1],
                'exp_ratio' : [1],
                'rx_ports' : [vars.T1D1P2],
                'rx_obj' : [tg2],
                'stream_list' : [[stream_id1]],
                },
    }
    tg1.tg_traffic_control(action='stop', stream_handle=stream_id1)
    # verify traffic mode stream level
    streamResult = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='streamblock', comp_type='packet_count')
    if streamResult:
        st.log('traffic verification passed for mode streamblock')
    else:
        st.log('traffic verification failed for mode streamblock')


@pytest.mark.tgen1
def test_basic_capture_tcp():
    #reset statistics and delete if any existing streamblocks
    for action in ['reset','clear_stats']:
        tg1.tg_traffic_control(action=action,port_handle=tg_ph_1)
        tg2.tg_traffic_control(action=action,port_handle=tg_ph_2)

    stream1 = tg1.tg_traffic_config(mac_src='00.00.00.00.00.01', mac_dst='00.00.00.00.00.02', rate_pps='10',
                                    mode='create', vlan_id='10', vlan='enable', tcp_dst_port='33333',
                                    port_handle=tg_ph_1, transmit_mode='continuous', l2_encap='ethernet_ii_vlan',
                                    frame_size='128', duration='2', l3_protocol='ipv4', ip_src_addr=data.ipv4_addr_D1P1T1,
                                    ip_dst_addr=data.ipv4_addr_D1P2T1, l4_protocol='tcp', tcp_src_port='32222')

    stream_id1 = stream1['stream_id']

    # start capture
    tg2.tg_packet_control(port_handle=tg_ph_2,action='start')

    #send traffic for 2 seconds with 10 packets per second
    tg1.tg_traffic_control(action='run', stream_handle=stream_id1, duration='2')
    #st.wait(5)

    tg1.tg_traffic_control(action='stop', stream_handle=stream_id1)
    #stop capture
    #st.wait(5)
    tg2.tg_packet_control(port_handle=tg_ph_2,action='stop')
    #st.wait(5)

    # save the captured packets into a variable
    pkts_captured = tg2.tg_packet_stats(port_handle=tg_ph_2,format='var')

    # import pdb
    # pdb.set_trace()
    #verify the capture packets having source mac '00:00:00:00:00:01' and vlan '000A'
    #tgapi.validate_packet_captures supports - Ethernet, IP, IPv6, TCP, UDP and VLAN header. Support for other headers will be added on need basis.
    # Here are the field details for each header type
    '''

        frame_format = {
            'ETH': {
                'h_name': 'Ethernet',
                'fname_list': ['Ethernet','Source','Destination','Type'],
                },
            'VLAN': {
                'h_name': '1Q Virtual LAN',
                'fname_list': ['1Q Virtual LAN','CFI','ID','Priority','Type'],
                },
            'IP': {
                'h_name': 'Internet Protocol',
                'fname_list':  ['Version','Total Length','Source','Destination','Protocol','Time to live','Header Length','Identification','Precedence', 'Differentiated Services Codepoint', 'Reliability','Explicit Congestion Notification', 'Fragment offset', 'More fragments'],
                },
            'IP6': {
                'h_name': 'Internet Protocol Version 6$',
                'fname_list':  [],
                },
            'TCP': {
                'h_name': 'Transmission Control Protocol',
                'fname_list': ['Source Port','Destination Port'],
                },
            'UDP': {
                'h_name': 'User Datagram Protocol',
                'fname_list': ['Source Port','Destination Port'],
                },
            }
    '''
    capture_result = tgapi.validate_packet_capture(tg_type=tg2.tg_type, pkt_dict=pkts_captured,
                                             header_list=['ETH:Source', 'IP:Source', 'TCP:Source Port', 'VLAN:ID'],
                                             offset_list=[6, 14, 50, 14],
                                             value_list=['00:00:00:00:00:01', data.ipv4_addr_D1P1T1, '7DDE', '000a'])

    if capture_result:
        st.report_pass("operation_successful")
    else:
        st.report_fail("operation_failed")


@pytest.mark.tgen1
def test_basic_capture():
    #reset statistics and delete if any existing streamblocks
    for action in ['reset','clear_stats']:
        tg1.tg_traffic_control(action=action,port_handle=tg_ph_1)
        tg2.tg_traffic_control(action=action,port_handle=tg_ph_2)

    stream1 = tg1.tg_traffic_config(mac_src='00.00.00.00.00.01', mac_dst='00.00.00.00.00.02', rate_pps='100',
                                    mode='create', vlan_id='10', vlan='enable', udp_dst_port='33333',
                                    port_handle=tg_ph_1, transmit_mode='continuous', l2_encap='ethernet_ii_vlan',
                                    frame_size='128', duration='2', l3_protocol='ipv6', ipv6_src_addr='2001::100',
                                    ipv6_dst_addr='2002::100', l4_protocol='udp', udp_src_port='32222')
    stream_id1 = stream1['stream_id']

    # start capture
    tg2.tg_packet_control(port_handle=tg_ph_2, action='start')

    # send traffic for 2 seconds with 10 packets per second
    tg1.tg_traffic_control(action='run', stream_handle=stream_id1, duration='2')
    # st.wait(5)

    tg1.tg_traffic_control(action='stop', stream_handle=stream_id1)
    # stop capture
    # st.wait(5)
    tg2.tg_packet_control(port_handle=tg_ph_2, action='stop')
    # st.wait(5)

    # save the captured packets into a variable
    # Use 'output_type' option in packet_stats API to convert capture packet values into Hex Dump on Ixia(To get output identical to STC).
    # This method is preferable to validate all type of capture packets.
    pkts_captured = tg2.tg_packet_stats(port_handle=tg_ph_2, format='var', output_type='hex')

    #verify the capture packets having source mac '00:00:00:00:00:01' and vlan '000A'
    capture_result =  tgapi.validate_packet_capture(tg_type=tg2.tg_type,pkt_dict=pkts_captured,offset_list=[6,14],value_list=['00:00:00:00:00:01','000a'])

    # start capture
    tg2.tg_packet_control(port_handle=tg_ph_2, action='start')

    # send traffic for 2 seconds with 10 packets per second
    tg1.tg_traffic_control(action='run', stream_handle=stream_id1, duration='2')
    # st.wait(5)

    tg1.tg_traffic_control(action='stop', stream_handle=stream_id1)
    # stop capture
    # st.wait(5)
    tg2.tg_packet_control(port_handle=tg_ph_2, action='stop')
    # st.wait(5)

    # Use parameter 'var_num_frames' to capture more than 20(default) packets
    pkts_captured = tg2.tg_packet_stats(port_handle=tg_ph_2, format='var', output_type='hex', var_num_frames=50)

    # verify the capture packets having source mac '00:00:00:00:00:01' and vlan '000A'
    capture_result1 = tgapi.validate_packet_capture(tg_type=tg2.tg_type, pkt_dict=pkts_captured, offset_list=[6, 14],
                                                   value_list=['00:00:00:00:00:01', '000a'], var_num_frames=50)

    if capture_result and capture_result1:
        st.report_pass("operation_successful")
    else:
        st.report_fail("operation_failed")


@pytest.mark.tgen1
def test_protocol_field_set_packets():

    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)

    # Create an IGMP join packet for group 225.1.1.1 and start the stream
    stream = tg1.tg_traffic_config(port_handle=tg_ph_1, mode='create', transmit_mode='continuous', length_mode='fixed',
                                   rate_pps=1, l2_encap='ethernet_ii', mac_src='00:0a:01:00:00:01',
                                   mac_dst='01:00:5e:01:01:01', l3_protocol='ipv4', ip_src_addr='11.1.1.1',
                                   ip_dst_addr='225.1.1.1', ip_protocol=2, l4_protocol='igmp', igmp_msg_type='report',
                                   igmp_group_addr='225.1.1.1', high_speed_result_analysis=0)
    tg1.tg_traffic_control(action='run', stream_handle=stream['stream_id'])

    # Start the packet capture on TG2
    #tg2.tg_packet_config_buffers(port_handle=tg_ph_2,capture_mode = 'trigger')
    #tg2.tg_packet_config_triggers(port_handle=tg_ph_2,capture_trigger=1)
    tg2.tg_packet_control(port_handle=tg_ph_2, action='start')
    #st.wait(10)
    tg2.tg_packet_control(port_handle=tg_ph_2, action='stop')

    tg1.tg_traffic_control(action='run', stream_handle=stream['stream_id'])

    # Save the captured file to a variable
    packet_dict = tg1.tg_packet_stats(port_handle=tg_ph_2,format='var')

    #verify captured packets have DMAC as 01005e010101 ,Dest_ip as 225.1.1.1 and protocol to 2(IGMP)
    ret_val =  tgapi.validate_packet_capture(tg_type=tg2.tg_type,pkt_dict=packet_dict,header_list=['ETH:Destination','IP:Destination','IP:Protocol'],\
                                       offset_list=[0,30,23],value_list=['01:00:5E:01:01:01','225.1.1.1','02'])
    if ret_val is False:
        st.log("No IGMP packets received on tg2")
        st.report_fail("operation_failed")
    else:
        st.log("IGMP join packets are received on TG2")
        st.report_pass("operation_successful")


@pytest.mark.tgen1
def test_custom_filter_L3_standard():


    tg1.tg_traffic_control(action='reset', port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset', port_handle=tg_ph_2)

    src_handle = tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr=data.ipv4_addr_D1P1T1,
                                         gateway=data.ipv4_addr_D1T1P1, netmask='255.255.255.0')
    src = src_handle['handle']
    dst_handle = tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr=data.ipv4_addr_D1P2T1,
                                         gateway=data.ipv4_addr_D1T1P2, netmask='255.255.255.0')
    dst = dst_handle['handle']

    #Configure stream with TOS set to Priority-1
    stream_tos_prio = tg1.tg_traffic_config(port_handle=tg_ph_1,mode='create', transmit_mode='continuous', length_mode='fixed', \
                      rate_pps=10,l2_encap='ethernet_ii', mac_src='00:0a:01:00:00:01', mac_dst='3c:2c:99:8b:33:eb',l3_protocol='ipv4',ip_precedence=1, \
                      ip_src_addr='11.1.1.2', ip_dst_addr='11.1.2.2', mac_discovery_gw='11.1.1.1',high_speed_result_analysis=0,\
                      track_by='trackingenabled0 ipv4Precedence0',ip_precedence_tracking=1,emulation_src_handle=src,emulation_dst_handle=dst)
    stream1 = stream_tos_prio['stream_id']
    # Configure stream with TOS set to Routine-0
    stream_tos_routine = tg1.tg_traffic_config(port_handle=tg_ph_1,mode='create', transmit_mode='continuous', length_mode='fixed', \
                         rate_pps=10,l2_encap='ethernet_ii', mac_src='00:0a:01:00:00:01', mac_dst='3c:2c:99:8b:33:eb',l3_protocol='ipv4',ip_precedence=0,\
                         ip_src_addr='11.1.1.2', ip_dst_addr='11.1.2.2', mac_discovery_gw='11.1.1.1',high_speed_result_analysis=0,\
                         track_by='trackingenabled0 ipv4Precedence0',ip_precedence_tracking=1,\
                         emulation_src_handle=src,emulation_dst_handle=dst)
    stream2 = stream_tos_routine['stream_id']

    # First, Initiate analyzer filter on the rx port
    tg2.tg_traffic_control(action='run', stream_handle=stream2, get='tos')
    #Start both streams on tg1
    tg1.tg_traffic_control(action='run', stream_handle=stream1)

    vars = st.get_testbed_vars()
    traffic_details = {
            '1': {
                'tx_ports' : [vars.T1D1P1],
                'tx_obj' : [tg1],
                'exp_ratio' : [1],
                'rx_ports' : [vars.T1D1P2],
                'rx_obj' : [tg2],
                'stream_list' : [(stream1,stream2)],
                'filter_param' : [('prec','prec')],
                'filter_val'  : [('1','0')],
                }
            }

    #st.wait(15)
    #verify analyzer filter statistics
    filterResult = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='filter', comp_type='packet_rate')

    tg1.tg_traffic_control(action='stop', stream_handle=stream1)
    tg2.tg_traffic_control(action='stop', stream_handle=stream2)

    filterResult1 = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='filter', comp_type='packet_count')

    if filterResult and filterResult1:
        st.log("ALL packets with Precedence -0 and Precedence-1 received on TG2")
        st.report_pass("operation_successful")
    else:
        st.log("Drop seen on TG2 for Packets with precedence 0 or 1")
        st.report_fail("operation_failed")
    # Stop the traffic
    tg1.tg_traffic_control(action='stop', port_handle=tg_ph_1)


@pytest.mark.tgen1
def test_simulate_cable_disconnect():
    tg1.tg_interface_control(mode="break_link", port_handle=tg_ph_1)
    #st.wait(5)
    st.log("checking link status after break_link")
    status = tg1.tg_interface_control(mode="check_link", desired_status='down', port_handle=tg_ph_1)
    tg1.tg_interface_control(mode="restore_link", port_handle=tg_ph_1)
    #st.wait(5)
    st.log("checking link status after restore link")
    status1 = tg1.tg_interface_control(mode="check_link", desired_status='up', port_handle=tg_ph_1)

    if status and status1:
        st.report_pass("operation_successful")
    else:
        st.report_fail("operation_failed")


@pytest.mark.tgen1
def test_port_operation():
    #reset statistics and delete if any existing streamblocks
    for action in ['reset','clear_stats']:
        tg1.tg_traffic_control(action=action,port_handle=tg_ph_1)
        tg2.tg_traffic_control(action=action,port_handle=tg_ph_2)

    #create 3 streamblocks
    stream1 = tg1.tg_traffic_config(mac_src = '00.00.00.00.00.01',mac_dst='00.00.00.00.00.02',rate_pps='5',mode='create',\
                  port_handle=tg_ph_1,transmit_mode='continuous',l2_encap='ethernet_ii_vlan',vlan_id='10')
    tg1.tg_traffic_config(mac_src = '00.00.00.00.00.03',mac_dst='00.00.00.00.00.04',rate_pps='5',mode='create',\
                  port_handle=tg_ph_1,transmit_mode='continuous',l2_encap='ethernet_ii_vlan',vlan_id='10')
    tg1.tg_traffic_config(mac_src = '00.00.00.00.00.05',mac_dst='00.00.00.00.00.06',rate_pps='5',mode='create',\
                  port_handle=tg_ph_1,transmit_mode='continuous',l2_encap='ethernet_ii_vlan',vlan_id='10')

    # delete one of the stream
    st.log("delete one of the streamblock")
    tg1.tg_traffic_config(mode='remove',stream_id=stream1['stream_id'],port_handle=tg_ph_1)
    # delete all other streams
    st.log("delete all the streamblocks")
    tg1.tg_traffic_config(mode='reset',port_handle=tg_ph_1)

    st.report_pass("operation_successful")


@pytest.mark.tgen1
def test_basic_stats_filter():
    tg1.tg_traffic_control(action='reset', port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset', port_handle=tg_ph_2)

    #Configure L2 stream with vlan-id 100; to track statistics based on vlan \
    # pls specify 'vlan_id_tracking' and 'track_by' parameter
    stream_vlan_100 = tg1.tg_traffic_config(port_handle=tg_ph_1, mode='create', transmit_mode='continuous', \
            length_mode='fixed', rate_pps=10,l2_encap='ethernet_ii_vlan',vlan_id='100', \
            mac_src='00:0a:01:00:00:01', mac_dst='00:0a:02:00:00:01',high_speed_result_analysis=0,\
            track_by='trackingenabled0 vlanVlanId0',vlan_id_tracking=1,port_handle2=tg_ph_2)
    stream1 = stream_vlan_100['stream_id']

    #Start L2 traffic on tg1 and apply vlan_id analayzer filter on tg2
    tg2.tg_traffic_control(action='run', port_handle=tg_ph_2, get='vlan_id')
    tg1.tg_traffic_control(action='run', stream_handle=stream1)

    #st.wait(10)

    # Stop the traffic and analyzers
    tg1.tg_traffic_control(action='stop', port_handle=tg_ph_2)
    tg1.tg_traffic_control(action='stop', stream_handle=stream1)
    #st.wait(10)

    #get tx-pkt count for each streams on tg1
    vars = st.get_testbed_vars()
    traffic_details = {
            '1': {
                'tx_ports' : [vars.T1D1P1],
                'tx_obj' : [tg1],
                'exp_ratio' : [1],
                'rx_ports' : [vars.T1D1P2],
                'rx_obj' : [tg2],
                'stream_list' : [(stream1)],
                'filter_param' : [('vlan')],
                'filter_val'  : [('100')],
                }
            }

    #verify analyzer filter statistics
    filterResult = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='filter', comp_type='packet_count')
    if filterResult:
        st.report_pass("tgen_vlan_packets_received", 100, "TG2")
    else:
        st.report_fail("tgen_vlan_packets_dropped", 100, "TG2")


@pytest.mark.tgen1
def test_traffic_burst_random():
    #reset statistics and delete if any existing streamblocks
    for action in ['reset','clear_stats']:
        tg1.tg_traffic_control(action=action,port_handle=tg_ph_1)
        tg2.tg_traffic_control(action=action,port_handle=tg_ph_2)

    #creating streamblock with single burst with 10 packets
    stream1 = tg1.tg_traffic_config(mac_src='00.00.00.00.00.01', mac_dst='00.00.00.00.00.20', rate_pps='10',
                                    mode='create', frame_size_max='256', pkts_per_burst='10', high_speed_result_analysis='0',
                                    port_handle=tg_ph_1, transmit_mode='single_burst', length_mode='random',)

    # start capture
    tg2.tg_packet_control(port_handle=tg_ph_2,action='start')

    #send burst traffic with single burst of 10 packets
    tg1.tg_traffic_control(action='run',stream_handle=stream1['stream_id'])
    #st.wait(10)
    tg1.tg_traffic_control(action='stop', stream_handle=stream1['stream_id'])
    #stop capture
    tg2.tg_packet_control(port_handle=tg_ph_2,action='stop')
    packet_dict = tg2.tg_packet_stats(port_handle=tg_ph_2,format='var')
    ret_val =  tgapi.validate_packet_capture(tg_type=tg2.tg_type,pkt_dict=packet_dict,header_list=['ETH:Destination'],offset_list=[0],value_list=['00:00:00:00:00:20'])

    if ret_val:
        st.report_pass("msg", "The RX with Destination Mac 00:00:00:00:20 is received")
    else:
        st.report_fail("msg", "The RX with Destination Mac 00:00:00:00:20 is not received")


@pytest.mark.tgen1
def test_multiple_streams():
    vars = st.get_testbed_vars()
    traffic_details = {
            '1': {
                'tx_ports' : [vars.T1D1P1],
                'tx_obj' : [tg1],
                'exp_ratio' : [1],
                'rx_ports' : [vars.T1D1P2],
                'rx_obj' : [tg2],
                },
            }

    #reset statistics and delete if any existing streamblocks
    for action in ['reset','clear_stats']:
        tg1.tg_traffic_control(action=action,port_handle=tg_ph_1)
        tg2.tg_traffic_control(action=action,port_handle=tg_ph_2)

    #Creating stream 1
    stream1 = tg1.tg_traffic_config(mac_src = '00.00.00.00.00.01',mac_dst='00.00.00.00.00.02',rate_pps='10',mode='create',\
                  port_handle=tg_ph_1,transmit_mode='continuous',frame_size='64',duration='2')
    stream_id1 = stream1['stream_id']

    #send contiuous traffic for 2 seconds with 10 packets per second
    tg1.tg_traffic_control(action='run', stream_handle=stream_id1, duration='2')
    #st.wait(5)
    tg1.tg_traffic_control(action='stop', stream_handle=stream_id1)
    ret_val = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count')
    if ret_val:
        st.report_pass("msg", "Expected packets are received on TG2")
    else:
        st.report_fail("msg", "Expected packets are not received on TG2")

    #Disable the stream 1
    #tg1.tg_traffic_config(mode='disable',port_handle=tg_ph_1,stream_id=stream_id1)
    tg1.tg_traffic_config(mode='disable',stream_id=stream_id1)
    #st.wait(15)

    tg1.tg_traffic_control(action='clear_stats',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='clear_stats',port_handle=tg_ph_2)

    #Creating stream 2
    stream2 = tg1.tg_traffic_config(mac_src = '00.00.00.00.00.03',mac_dst='00.00.00.00.00.04',rate_pps='10',mode='create',\
                  port_handle=tg_ph_1,transmit_mode='continuous',frame_size='128',duration='2')
    stream_id2 = stream2['stream_id']

    #send contiuous traffic for 2 seconds with 10 packets per second
    tg1.tg_traffic_control(action='run', stream_handle=stream_id2, duration='2')
    #st.wait(15)
    tg1.tg_traffic_control(action='stop', stream_handle=stream_id2)
    ret_val = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count')
    if ret_val:
        st.report_pass("msg", "Expected packets are received on TG2")
    else:
        st.report_fail("msg", "Expected packets are not received on TG2")

    #Disable the stream 2
    #tg1.tg_traffic_config(mode='disable',port_handle=tg_ph_1,stream_id=stream_id2)
    tg1.tg_traffic_config(mode='disable',stream_id=stream_id2)
    #st.wait(15)

    tg1.tg_traffic_control(action='clear_stats',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='clear_stats',port_handle=tg_ph_2)
    #enable the stream 1
    #tg1.tg_traffic_config(mode='enable',port_handle=tg_ph_1,stream_id=stream_id1)
    tg1.tg_traffic_config(mode='enable',stream_id=stream_id1)
    #st.wait(15)

    #send contiuous traffic for 2 seconds with 10 packets per second
    tg1.tg_traffic_control(action='run', stream_handle=stream_id1, duration='2')
    #st.wait(15)
    tg1.tg_traffic_control(action='stop', stream_handle=stream_id1)
    ret_val = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count')
    if ret_val:
        st.report_pass("msg", "Expected packets are received on TG2")
    else:
        st.report_fail("msg", "Expected packets are not received on TG2")


@pytest.mark.tgen1
def test_ipv6_traffic():

    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)

    tr1=tg1.tg_traffic_config(port_handle=tg_ph_1, mode='create', transmit_mode='continuous',\
            length_mode='fixed', rate_pps=100, l3_protocol='ipv6', mac_src='00:0a:01:00:00:01',\
            mac_discovery_gw=data.ipv6_addr_D1T1P1, ipv6_src_addr=data.ipv6_addr_D1P1T1, ipv6_dst_addr=data.ipv6_addr_D1P2T1)
    st.log("TRAFCONF: "+str(tr1))
    tr2=tg2.tg_traffic_config(port_handle=tg_ph_2, mode='create', transmit_mode='continuous',\
            length_mode='fixed', rate_pps=200, l3_protocol='ipv6', mac_src='00:0b:01:00:00:01', \
            mac_discovery_gw=data.ipv6_addr_D1T1P2, ipv6_src_addr=data.ipv6_addr_D1P2T1, ipv6_dst_addr=data.ipv6_addr_D1P1T1)
    st.log("TRAFCONF: "+str(tr2))

    res=tg1.tg_traffic_control(action='run', handle=tr1['stream_id'])
    st.log("TR_CTRL: "+str(res))
    res=tg2.tg_traffic_control(action='run', handle=tr2['stream_id'])
    st.log("TR_CTRL: "+str(res))
    #st.wait(15)
    res=tg1.tg_traffic_control(action='stop', handle=tr1['stream_id'])
    st.log("TR_CTRL: "+str(res))
    res=tg2.tg_traffic_control(action='stop', handle=tr2['stream_id'])
    st.log("TR_CTRL: "+str(res))

    st.log("IPv6 packets are sent on tg1")
    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)
    st.report_pass("operation_successful")


@pytest.mark.tgen1
def test_ipv4_bgp():

    # Config 2 IPV4 interfaces on DUT.

    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)

    h1=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr=data.ipv4_addr_D1P1T1,\
            gateway=data.ipv4_addr_D1T1P1, src_mac_addr='00:0a:01:00:00:01', arp_send_req='1')
    st.log("INTFCONF: "+str(h1))

    bgp_conf=tg1.tg_emulation_bgp_config(handle=h1['handle'], mode='enable', active_connect_enable='1',\
                                            local_as='100', remote_as='100', remote_ip_addr=data.ipv4_addr_D1T1P1)
    st.log("BGPCONF: "+str(bgp_conf))

    bgp_ctrl=tg1.tg_emulation_bgp_control(handle=bgp_conf['handle'], mode='start')
    st.log("BGPCTRL: "+str(bgp_ctrl))

    #verify BGP session comes up in DUT
    st.log("BGP neighborship established.")
    #st.wait(10)
    bgp_ctrl=tg1.tg_emulation_bgp_control(handle=bgp_conf['handle'], mode='stop')
    st.log("BGPCTRL: "+str(bgp_ctrl))

    #verify BGP session down in the DUT
    st.log("BGP neighborship teardown.")

    res=tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    st.log("PORTRESET: "+str(res))

    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)
    st.report_pass("operation_successful")


@pytest.mark.tgen1
def test_ipv6_bgp():
    # Config 2 IPV6 interfaces on DUT.

    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)

    h1=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', ipv6_intf_addr=data.ipv6_addr_D1P1T1,\
        ipv6_prefix_length='64', ipv6_gateway=data.ipv6_addr_D1T1P1, src_mac_addr='00:0a:01:00:00:01', arp_send_req='1')
    st.log("INTFCONF: "+str(h1))

    bgp_conf=tg1.tg_emulation_bgp_config(handle=h1['handle'], mode='enable', ip_version='6',\
            active_connect_enable='1', local_as='100', remote_as='100', remote_ipv6_addr=data.ipv6_addr_D1T1P1)
    st.log("BGPCONF: "+str(bgp_conf))

    bgp_ctrl=tg1.tg_emulation_bgp_control(handle=bgp_conf['handle'], mode='start')
    st.log("BGPCTRL: "+str(bgp_ctrl))
    #verify BGP session comes up in DUT
    st.log("BGP neighborship established.")
    #st.wait(10)
    bgp_ctrl=tg1.tg_emulation_bgp_control(handle=bgp_conf['handle'], mode='stop')
    st.log("BGPCTRL: "+str(bgp_ctrl))
    # verify BGP session is DOWN in DUT
    st.log("BGP neighborship teardown.")

    res=tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    st.log("PORTRESET: "+str(res))

    st.log("BGP neighborship established.")
    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)
    st.report_pass("operation_successful")


@pytest.mark.tgen1
def test_ipv4_ping():
    # Config 2 IPV4 interfaces on DUT.
    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)

    h1=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr=data.ipv4_addr_D1P1T1,\
                    gateway=data.ipv4_addr_D1T1P1, src_mac_addr='00:0a:01:00:00:01', arp_send_req='1')
    st.log("INTFCONF: "+str(h1))
    h2=tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr=data.ipv4_addr_D1P2T1,\
                    gateway=data.ipv4_addr_D1T1P2, src_mac_addr='00:0b:01:00:00:01', arp_send_req='1')
    st.log("INTFCONF: "+str(h2))

    #st.wait(5)
    # Ping from tgen to DUT.
    res=tgapi.verify_ping(src_obj=tg1, port_handle=tg_ph_1, dev_handle=h1['handle'], dst_ip=data.ipv4_addr_D1T1P1,\
                                                                ping_count='6', exp_count='6')
    st.log("PING_RES: "+str(res))
    if res:
        st.log("Ping succeeded.")
    else:
        st.log("Ping failed.")

    #st.wait(5)
    # Host_to_host bound traffic.
    tr1=tg1.tg_traffic_config(port_handle=tg_ph_1, emulation_src_handle=h1['handle'],\
            emulation_dst_handle=h2['handle'], circuit_endpoint_type='ipv4', mode='create',\
                                transmit_mode='continuous', length_mode='fixed', rate_pps=100)
    st.log("TR_CONF: "+str(tr1))
    res=tg1.tg_traffic_control(action='run', handle=tr1['stream_id'])
    st.log("TR_CTRL: "+str(res))

    # Verified counters at the DUT.
    #st.wait(5)
    res=tg1.tg_traffic_control(action='stop', handle=tr1['stream_id'])
    st.log("TR_CTRL: "+str(res))

    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)
    st.report_pass("operation_successful")


@pytest.mark.tgen1
def test_ipv6_ping():
    # Config 2 IPV6 interfaces on DUT.

    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)

    h1=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', ipv6_intf_addr=data.ipv6_addr_D1P1T1,\
        ipv6_prefix_length='64', ipv6_gateway=data.ipv6_addr_D1T1P1, src_mac_addr='00:0a:01:00:00:01', arp_send_req='1')
    st.log("INTFCONF: "+str(h1))
    h2=tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', ipv6_intf_addr=data.ipv6_addr_D1P2T1,\
        ipv6_prefix_length='64', ipv6_gateway=data.ipv6_addr_D1T1P2, src_mac_addr='00:0b:01:00:00:01', arp_send_req='1')
    st.log("INTFCONF: "+str(h2))

    #st.wait(5)
    # Ping from tgen to DUT.
    res=tgapi.verify_ping(src_obj=tg1, port_handle=tg_ph_1, dev_handle=h1['handle'], dst_ip=data.ipv6_addr_D1T1P1,\
                                                                    ping_count='6', exp_count='6')
    st.log("PING_RES: "+str(res))
    if res:
        st.log("Ping succeeded.")
    else:
        st.log("Ping failed.")

    #st.wait(5)
    # Host_to_host bound traffic.
    tr1=tg1.tg_traffic_config(port_handle=tg_ph_1, emulation_src_handle=h1['handle'], \
        emulation_dst_handle=h2['handle'], circuit_endpoint_type='ipv6', mode='create',\
                        transmit_mode='continuous', length_mode='fixed', rate_pps=100)
    st.log("TR_CONF: "+str(tr1))
    res=tg1.tg_traffic_control(action='run', handle=tr1['stream_id'])
    st.log("TR_CTRL: "+str(res))
    # Verified counters at the DUT.
    #st.wait(5)
    res=tg1.tg_traffic_control(action='stop', handle=tr1['stream_id'])
    st.log("TR_CTRL: "+str(res))

    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)
    st.report_pass("operation_successful")


@pytest.mark.tgen1
def test_tcp_traffic():
    # Config 2 IPV4 interfaces on DUT. Config Static arp for 2nd interface.

    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)

    # Make sure to give proper mac_dst.
    tr1 = tg1.tg_traffic_config(port_handle=tg_ph_1, mode='create', transmit_mode='continuous', length_mode='fixed',
                                rate_pps=100, mac_src='00:0a:01:00:00:01', mac_dst='00:01:85:48:E0:12',
                                l3_protocol='ipv4', ip_src_addr=data.ipv4_addr_D1P1T1, ip_dst_addr=data.ipv4_addr_D1P2T1,
                                l4_protocol='tcp', tcp_src_port='32222', tcp_dst_port='33333',
                                tcp_src_port_mode='increment', tcp_src_port_count='10')
    st.log("TrafConf: "+str(tr1))
    res=tg1.tg_traffic_control(action='run', handle=tr1['stream_id'])
    st.log("TrafControl: "+str(res))
    # Verified in the DUT.
    #st.wait(5)
    res=tg1.tg_traffic_control(action='run', handle=tr1['stream_id'])
    st.log("TrafControl: "+str(res))
    #st.wait(5)
    # Deleting the stream.
    tr1=tg1.tg_traffic_config(port_handle=tg_ph_1, mode='reset')
    st.log("TrafConf: "+str(tr1))

    st.log("TCP packets are routed to tg2.")
    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)
    st.report_pass("operation_successful")


@pytest.mark.tgen1
def test_udp_traffic():
    # Config 2 IPV4 interfaces on DUT. Config Static arp for 2nd interface.

    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)

    # Make sure to give proper mac_dst.
    tr1 = tg1.tg_traffic_config(port_handle=tg_ph_1, mode='create', transmit_mode='continuous', length_mode='fixed',
                                rate_pps=100, mac_src='00:0a:01:00:00:01', mac_dst='60:9c:9f:5a:f3:2b',
                                l3_protocol='ipv4', ip_src_addr=data.ipv4_addr_D1P1T1, ip_dst_addr=data.ipv4_addr_D1P2T1,
                                l4_protocol='udp', udp_src_port='32222', udp_dst_port='33333',
                                udp_src_port_mode='increment', udp_src_port_count='100')
    st.log("TrafConf: "+str(tr1))
    res=tg1.tg_traffic_control(action='run', handle=tr1['stream_id'])
    st.log("TrafControl: "+str(res))
    # Verified in the DUT.
    #st.wait(5)
    res=tg1.tg_traffic_control(action='stop', handle=tr1['stream_id'])
    st.log("TrafControl: "+str(res))
    #st.wait(5)
    # Deleting the stream.
    tr1=tg1.tg_traffic_config(port_handle=tg_ph_1, mode='reset')
    st.log("TrafConf: "+str(tr1))

    st.log("UDP packets are routed to tg2.")
    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)
    st.report_pass("operation_successful")


@pytest.mark.tgen1
def test_ipv4_bgpproc():
    # Config 2 IPV4 interfaces on DUT.
    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)

    h1 = tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr=data.ipv4_addr_D1P1T1,
                                 gateway=data.ipv4_addr_D1T1P1, src_mac_addr='00:0a:01:00:00:01', arp_send_req='1')
    st.log("INTFCONF: " + str(h1))
    h2 = tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr=data.ipv4_addr_D1P2T1,
                                 gateway=data.ipv4_addr_D1P2T1, src_mac_addr='00:0b:01:00:00:01', arp_send_req='1')
    st.log("INTFCONF: " + str(h2))

    # Configuring BGP device on top of interface.
    # Initializing dict_vars for easy readability.
    conf_var = { 'mode'                  : 'enable',
                 'active_connect_enable' : '1',
                 'local_as'              : '100',
                 'remote_as'             : '100',
                 'remote_ip_addr'        : data.ipv4_addr_D1T1P1
               }
    route_var = { 'mode'       : 'add',
                  'num_routes' : '10',
                  'prefix'     : '121.1.1.0'
                }
    ctrl_start = { 'mode' : 'start'}
    ctrl_stop = { 'mode' : 'stop'}

    # Configuring the BGP router.
    bgp_rtr1 = tgapi.tg_bgp_config(tg = tg1,
        handle    = h1['handle'],
        conf_var  = conf_var,
        route_var = route_var,
        ctrl_var  = ctrl_start)

    st.log("BGP_HANDLE: "+str(bgp_rtr1))
    # Verified at neighbor.
    st.log("BGP neighborship established.")
    #st.wait(10)

    # Withdraw the routes.
    ctrl1=tg1.tg_bgp_routes_control(handle=bgp_rtr1['conf']['handle'], route_handle=bgp_rtr1['route'][0]['handle'], mode='withdraw')
    st.log("TR_CTRL: "+str(ctrl1))
    #st.wait(10)
    ctrl1=tg1.tg_bgp_routes_control(handle=bgp_rtr1['conf']['handle'], route_handle=bgp_rtr1['route'][0]['handle'], mode='readvertise')
    st.log("TR_CTRL: "+str(ctrl1))
    #st.wait(10)

    # Configuring bound stream host_to_routeHandle.
    tr1 = tg2.tg_traffic_config(port_handle=tg_ph_2, emulation_src_handle=h2['handle'],
                                emulation_dst_handle=bgp_rtr1['route'][0]['handle'], circuit_endpoint_type='ipv4',
                                mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=500)
    st.log("BOUND_STREAM: "+str(tr1))
    res=tg2.tg_traffic_control(action='run', handle=tr1['stream_id'])
    st.log("TrafControl: "+str(res))
    # Verified at the DUT.
    #st.wait(15)
    res=tg1.tg_traffic_control(action='stop', handle=tr1['stream_id'])
    st.log("TR_CTRL: "+str(res))
    #st.wait(10)

    bgp_rtr2 = tgapi.tg_bgp_config(tg = tg1,
        handle    = bgp_rtr1['conf']['handle'],
        ctrl_var  = ctrl_stop)
    st.log("BGP_HANDLE: "+str(bgp_rtr2))
    st.log("BGP neighborship teardown.")

    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)
    st.report_pass("operation_successful")


@pytest.mark.tgen1
def test_ipv4_bgp_route():
    # Config 2 IPV4 interfaces on DUT.

    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)

    # Configuring Interface.
    h1 = tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr=data.ipv4_addr_D1P1T1,
                                 gateway=data.ipv4_addr_D1T1P1, src_mac_addr='00:0a:01:00:00:01', arp_send_req='1')
    st.log("INTFCONF: " + str(h1))
    h2 = tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr=data.ipv4_addr_D1P2T1,
                                 gateway=data.ipv4_addr_D1T1P2, src_mac_addr='00:0b:01:00:00:01', arp_send_req='1')
    st.log("INTFCONF: " + str(h2))

    # Configuring BGP device on top of interface.
    bgp_conf = tg1.tg_emulation_bgp_config(handle=h1['handle'], mode='enable', active_connect_enable='1',
                                           local_as='100', remote_as='100', remote_ip_addr=data.ipv4_addr_D1T1P1)
    st.log("BGPCONF: " + str(bgp_conf))

    # Adding routes to BGP device.
    bgp_route=tg1.tg_emulation_bgp_route_config(handle=bgp_conf['handle'], mode='add', num_routes='10', prefix='121.1.1.0')
    st.log("BGPROUTE: "+str(bgp_route))

    # Starting the BGP device.
    bgp_ctrl=tg1.tg_emulation_bgp_control(handle=bgp_conf['handle'], mode='start')
    st.log("BGPCTRL: "+str(bgp_ctrl))
    # Verified at neighbor.
    st.log("BGP neighborship established.")
    #st.wait(10)

    # Withdraw the routes.
    ctrl1=tg1.tg_bgp_routes_control(handle=bgp_conf['handle'], route_handle=bgp_route['handle'], mode='withdraw')
    st.log("TR_CTRL: "+str(ctrl1))
    #st.wait(10)
    ctrl1=tg1.tg_bgp_routes_control(handle=bgp_conf['handle'], route_handle=bgp_route['handle'], mode='readvertise')
    st.log("TR_CTRL: "+str(ctrl1))
    #st.wait(10)

    # Configuring bound stream host_to_routeHandle.
    tr1 = tg2.tg_traffic_config(port_handle=tg_ph_2, emulation_src_handle=h2['handle'],
                                emulation_dst_handle=bgp_route['handle'], circuit_endpoint_type='ipv4', mode='create',
                                transmit_mode='continuous', length_mode='fixed', rate_pps=500)
    st.log("BOUND_STREAM: "+str(tr1))
    res=tg2.tg_traffic_control(action='run', handle=tr1['stream_id'])
    st.log("TrafControl: "+str(res))
    # Verified at the DUT.
    #st.wait(15)
    res=tg1.tg_traffic_control(action='stop', handle=tr1['stream_id'])
    st.log("TR_CTRL: "+str(res))
    #st.wait(10)

    bgp_ctrl=tg1.tg_emulation_bgp_control(handle=bgp_conf['handle'], mode='stop')
    st.log("BGPCTRL: "+str(bgp_ctrl))
    st.log("BGP neighborship teardown.")

    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)
    st.report_pass("operation_successful")


@pytest.mark.tgen1
def test_ipv6_bgp_route():
    # Config 2 IPV6 interfaces on DUT.

    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)

    h1 = tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', ipv6_intf_addr=data.ipv6_addr_D1P1T1,
                                 ipv6_prefix_length='64', ipv6_gateway=data.ipv6_addr_D1T1P1,
                                 src_mac_addr='00:0a:01:00:00:01', arp_send_req='1')
    st.log("INTFCONF: " + str(h1))
    h2 = tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', ipv6_intf_addr=data.ipv6_addr_D1P2T1,
                                 ipv6_prefix_length='64', ipv6_gateway=data.ipv6_addr_D1T1P2,
                                 src_mac_addr='00:0b:01:00:00:01', arp_send_req='1')
    st.log("INTFCONF: " + str(h2))

    # Configuring BGP device on top of interface.
    bgp_conf = tg1.tg_emulation_bgp_config(handle=h1['handle'], mode='enable', ip_version='6',
                                           active_connect_enable='1', local_as='100', remote_as='100',
                                           remote_ipv6_addr=data.ipv6_addr_D1T1P1)
    st.log("BGPCONF: " + str(bgp_conf))

    # Adding routes to BGP device.
    bgp_route = tg1.tg_emulation_bgp_route_config(handle=bgp_conf['handle'], mode='add', ip_version='6',
                                                  num_routes='10', prefix='2121:1::')
    st.log("BGPROUTE: " + str(bgp_route))

    # Starting the BGP device.
    bgp_ctrl=tg1.tg_emulation_bgp_control(handle=bgp_conf['handle'], mode='start')
    st.log("BGPCTRL: "+str(bgp_ctrl))
    # Verified at neighbor.
    st.log("BGP neighborship established.")
    #st.wait(10)

    # Withdraw the routes.
    ctrl1=tg1.tg_bgp_routes_control(handle=bgp_conf['handle'], route_handle=bgp_route['handle'], mode='withdraw')
    st.log("TR_CTRL: "+str(ctrl1))
    #st.wait(10)
    ctrl1=tg1.tg_bgp_routes_control(handle=bgp_conf['handle'], route_handle=bgp_route['handle'], mode='readvertise')
    st.log("TR_CTRL: "+str(ctrl1))
    #st.wait(10)

    # Configuring bound stream host_to_routeHandle.
    tr1 = tg2.tg_traffic_config(port_handle=tg_ph_2, emulation_src_handle=h2['handle'],
                                emulation_dst_handle=bgp_route['handle'], circuit_endpoint_type='ipv6', mode='create',
                                transmit_mode='continuous', length_mode='fixed', rate_pps=500)
    st.log("BOUND_STREAM: "+str(tr1))
    res=tg2.tg_traffic_control(action='run', handle=tr1['stream_id'])
    st.log("TrafControl: "+str(res))
    # Verified at the DUT.
    #st.wait(15)
    res=tg1.tg_traffic_control(action='stop', handle=tr1['stream_id'])
    st.log("TR_CTRL: "+str(res))
    #st.wait(10)

    bgp_ctrl=tg1.tg_emulation_bgp_control(handle=bgp_conf['handle'], mode='stop')
    st.log("BGPCTRL: "+str(bgp_ctrl))
    st.log("BGP neighborship teardown.")

    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)
    st.report_pass("operation_successful")


@pytest.mark.tgen1
def test_ipv4_multihost():
    # Config 2 IPV4 interfaces on DUT.

    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)

    h1 = tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr=data.ipv4_addr_D1P1T1, gateway=data.ipv4_addr_D1T1P1,
                                 src_mac_addr='00:0a:01:01:00:01', arp_send_req='1', count='10', gateway_step='0.0.0.0')
    st.log("INTFCONF: " + str(h1))

    # st.wait(5)

    # Checking with bound stream to only 1 host out of multi-host.
    h2 = tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr=data.ipv4_addr_D1P2T1, gateway=data.ipv4_addr_D1T1P2,
                                 src_mac_addr='00:0b:01:00:00:01', arp_send_req='1')

    st.log("INTFCONF: "+str(h2))
    tr1 = tg2.tg_traffic_config(port_handle=tg_ph_2, emulation_dst_handle=h1['handle'][4],
                                emulation_src_handle=h2['handle'], circuit_endpoint_type='ipv4', mode='create',
                                transmit_mode='continuous', length_mode='fixed', rate_pps=100)
    st.log("TR_CONF: "+str(tr1))
    res=tg1.tg_traffic_control(action='run', handle=tr1['stream_id'])
    st.log("TR_CTRL: "+str(res))
    # Verified ARP and counters at the DUT.
    #st.wait(5)
    res=tg1.tg_traffic_control(action='stop', handle=tr1['stream_id'])
    st.log("TR_CTRL: "+str(res))

    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)
    st.report_pass("operation_successful")


@pytest.mark.tgen1
def test_arpnd():
    # Config 2 IPV4 interfaces on DUT.

    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)

    h2=tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr=data.ipv4_addr_D1P2T1, gateway=data.ipv4_addr_D1T1P2, src_mac_addr='00:0b:01:00:00:01', arp_send_req='1')
    st.log("INTFCONF: "+str(h2))

    #st.wait(5)
    # Verify arp is resolved in the dut.
    # clear arp no-refresh
    res=tg2.tg_arp_control(handle=h2['handle'], arp_target='all')
    st.log("ARP_CTRL: "+str(res))
    #st.wait(5)

    # Verify arp is resolved in the dut.

    # Repeating for IPv6 host.
    h2a=tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', ipv6_intf_addr=data.ipv6_addr_D1P2T1, ipv6_prefix_length='64', ipv6_gateway=data.ipv6_addr_D1T1P2, src_mac_addr='00:0b:01:00:00:01', arp_send_req='1')
    st.log("INTFCONF: "+str(h2a))
    #st.wait(5)

    # Verify nd is resolved in the dut.
    # clear ipv6 nei no-refresh
    res=tg2.tg_arp_control(handle=h2a['handle'], arp_target='all')
    st.log("ARP_CTRL: "+str(res))
    #st.wait(5)

    # Verify nd is resolved in the dut.

    tg1.tg_traffic_config(port_handle=tg_ph_1, mode='reset')
    tg2.tg_traffic_config(port_handle=tg_ph_2, mode='reset')
    st.report_pass("operation_successful")

@pytest.mark.tgen1
def test_ipv4_bgproutescale():
    # Config 2 IPV4 interfaces on DUT. One is Ve interface.

    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)

    h1=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr=data.ipv4_addr_D1P1T1, gateway=data.ipv4_addr_D1T1P1, src_mac_addr='00:0a:01:01:00:01', arp_send_req='1', vlan='1', vlan_id='10')
    st.log("INTFCONF: "+str(h1))
    h2=tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr=data.ipv4_addr_D1P2T1, gateway=data.ipv4_addr_D1T1P2, src_mac_addr='00:0b:01:00:00:01', arp_send_req='1')
    st.log("INTFCONF: "+str(h2))

    # Scale notes:
    # BGP IPv4 - routes - 128000 succeeded.
    # Traffic - only upto 16384 (by default).
    # Use enable_stream_only_gen='0', then traffic to 128000 working.

    # Configuring BGP device on top of interface.
    conf_var = { 'mode'                  : 'enable',
                 'active_connect_enable' : '1',
                 'local_as'              : '200',
                 'remote_as'             : '100',
                 'remote_ip_addr'        : data.ipv4_addr_D1T1P1
               }
    route_var = { 'mode'       : 'add',
                  'num_routes' : '128000',
                  'prefix'     : '121.1.1.0',
                  'as_path'    : 'as_seq:1'
                }
    ctrl_start = { 'mode' : 'start'}
    ctrl_stop = { 'mode' : 'stop'}

    # Configuring the BGP router.
    bgp_rtr1 = tgapi.tg_bgp_config(tg = tg1,
        handle    = h1['handle'],
        conf_var  = conf_var,
        route_var = route_var,
        ctrl_var  = ctrl_start)

    st.log("BGP_HANDLE: "+str(bgp_rtr1))
    # Verified at neighbor.
    st.log("BGP neighborship established.")
    #st.wait(10)

    # Configuring bound stream host_to_routeHandle.
    tr1 = tg2.tg_traffic_config(port_handle=tg_ph_2, emulation_src_handle=h2['handle'],
                                emulation_dst_handle=bgp_rtr1['route'][0]['handle'], circuit_endpoint_type='ipv4',
                                mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=512000,
                                enable_stream_only_gen='0')
    st.log("BOUND_STREAM: "+str(tr1))
    res=tg2.tg_traffic_control(action='run', handle=tr1['stream_id'])
    st.log("TrafControl: "+str(res))
    # Verified at the DUT.
    #st.wait(15)
    res=tg1.tg_traffic_control(action='stop', handle=tr1['stream_id'])
    st.log("TR_CTRL: "+str(res))
    #st.wait(10)

    bgp_rtr2 = tgapi.tg_bgp_config(tg = tg1,
        handle    = bgp_rtr1['conf']['handle'],
        ctrl_var  = ctrl_stop)
    st.log("BGP_HANDLE: "+str(bgp_rtr2))
    st.log("BGP neighborship teardown.")

    res=tg2.tg_traffic_config(mode='remove',port_handle=tg_ph_2, stream_id=tr1['stream_id'])
    st.log("TR_CFG: "+str(res))

    #st.wait(5)

    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)
    st.report_pass("operation_successful")

@pytest.mark.tgen1
def test_ipv4_hostscale():
    # Config 2 IPV4 interfaces on DUT. One is Ve interface.

    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)

    # There is spirent issue due to which this do not work for more than 255.
    h1 = tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr='21.1.1.10', gateway=data.ipv4_addr_D1T1P1,
                                 src_mac_addr='00:0a:01:01:00:01', arp_send_req='1', count='100',
                                 gateway_step='0.0.0.0', netmask='255.255.0.0', vlan='1', vlan_id='10',
                                 vlan_id_step='0')
    st.log("INTFCONF: "+str(h1))
    # Variations
    #h1=tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr='21.1.1.10', gateway=data.ipv4_addr_D1T1P1, src_mac_addr='00:0a:01:01:00:01', arp_send_req='1', count='3', gateway_step='0.0.0.0', netmask='255.255.0.0', vlan='1', vlan_id='10', intf_ip_addr_step='0.0.1.0', vlan_id_step='0')
    #h2=tg2.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr='22.1.1.10', gateway=data.ipv4_addr_D1T1P2, src_mac_addr='00:0b:01:00:00:01', arp_send_req='1', count='3', gateway_step='0.0.0.0', netmask='255.255.0.0', intf_ip_addr_step='0.0.1.0')
    #st.wait(10)

    # Cleanup.
    # Group ports from same DUT together.
    # Call differently for different DUTs.
    res=tg2.tg_interface_config(port_handle=[tg_ph_1, tg_ph_2], mode='destroy')
    st.log("CLEANUP: "+str(res))

    st.report_pass("operation_successful")

@pytest.mark.tgen1
def test_ipv4_arpscale():
    # Config 2 IPV4 interfaces on DUT. 2nd interface is with /16 mask.

    tg1.tg_traffic_control(action='reset',port_handle=tg_ph_1)
    tg2.tg_traffic_control(action='reset',port_handle=tg_ph_2)

    # For arp.
    # Working till 16000. Doesnt work beyond 16384.
    # No use of using enable_stream_only_gen, high_speed_result_analysis.
    tr2 = tg2.tg_traffic_config(mac_dst='ff:ff:ff:ff:ff:ff', rate_pps='200', mode='create', port_handle=tg_ph_2,
                                transmit_mode='continuous', l3_protocol='arp', arp_src_hw_addr='00.00.00.00.00.01',
                                arp_src_hw_mode='increment', arp_src_hw_count='3000', arp_dst_hw_mode='fixed',
                                arp_operation='arpRequest', ip_src_addr='22.1.1.10', ip_dst_addr=data.ipv4_addr_D1T1P2,
                                length_mode='fixed', enable_stream_only_gen='0', ip_src_step='0.0.0.1',
                                ip_src_count='3000', ip_src_mode='increment')
    st.log("TR_CFG: "+str(tr2))

    res=tg2.tg_traffic_control(action='run', handle=tr2['stream_id'])
    st.log("TrafControl: "+str(res))
    # Give the sleep time as per rate and count.
    time.sleep(20)
    res=tg2.tg_traffic_control(action='stop', handle=tr2['stream_id'])
    st.log("TrafControl: "+str(res))

    tg1.tg_traffic_config(port_handle=tg_ph_1, mode='reset')
    tg2.tg_traffic_config(port_handle=tg_ph_2, mode='reset')
    st.report_pass("operation_successful")


@pytest.mark.tgen1
def test_custom_filter():



    #reset statistics and delete if any existing streamblocks
    for action in ['reset','clear_stats']:
        tg1.tg_traffic_control(action=action,port_handle=tg_ph_1)
        tg2.tg_traffic_control(action=action,port_handle=tg_ph_2)

    tr1 = tg1.tg_traffic_config(mac_src='00.00.00.00.11.22', mac_dst='00.00.00.00.44.55', rate_pps='5000', mode='create',
                          port_handle=tg_ph_1, transmit_mode='continuous', l2_encap='ethernet_ii_vlan', vlan_id='10',
                          vlan='enable', frame_size='512', l3_protocol='ipv4', ip_src_addr=data.ipv4_addr_D1P1T1,
                          ip_dst_addr='22.1.2.150', l4_protocol='tcp', tcp_src_port='32222', tcp_dst_port='33333',
                          high_speed_result_analysis=0)

    tr2 = tg1.tg_traffic_config(mac_src='00.00.00.00.11.33', mac_dst='00.00.00.00.44.55', rate_pps='5000', mode='create',
                          port_handle=tg_ph_1, transmit_mode='continuous', l2_encap='ethernet_ii_vlan', vlan_id='10',
                          vlan='enable', frame_size='512', l3_protocol='ipv4', ip_src_addr='31.1.1.200',
                          ip_dst_addr='32.1.2.150', l4_protocol='udp', udp_src_port='42222', udp_dst_port='43333',
                          high_speed_result_analysis=0)

    #Create two filters of 16 bits each, on port 2 - filters for source mac and dest mac
    tg2.tg_custom_filter_config(mode='create',port_handle=tg_ph_2,pattern_offset1=4,pattern_offset2=10,pattern1='4455',pattern2='1122')

    #Start and then stop traffic
    tg1.tg_traffic_control(action='run',handle=[tr1['stream_id'], tr2['stream_id']])
    #st.wait(5)
    tg1.tg_traffic_control(action='stop',handle=[tr1['stream_id'], tr2['stream_id']])

    #validate the traffic sent and filtered traffic
    vars = st.get_testbed_vars()
    traffic_details = {
            '1': {
                'tx_ports' : [vars.T1D1P1],
                'tx_obj' : [tg1],
                'exp_ratio' : [0.5],
                'rx_ports' : [vars.T1D1P2],
                'rx_obj' : [tg2],
                },
            }
    result1 = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='custom_filter', comp_type='packet_count')
    print(result1)

    if result1:
        st.report_pass("operation_successful")
    else:
        st.report_fail("operation_failed")


    #tg2.tg_save_xml(filename='/home/cs403178/config_filter_4.xml')
    for action in ['clear_stats']:
        tg1.tg_traffic_control(action=action,port_handle=tg_ph_1)
        tg2.tg_traffic_control(action=action,port_handle=tg_ph_2)

    #Create one filter of 16 bits, on port 2 - filters for dest IP
    tg2.tg_custom_filter_config(mode='create',port_handle=tg_ph_2,pattern_offset1=36,pattern1='0296')

    #Start and then stop traffic
    tg1.tg_traffic_control(action='run', handle=[tr1['stream_id'], tr2['stream_id']])
    # st.wait(5)
    tg1.tg_traffic_control(action='stop', handle=[tr1['stream_id'], tr2['stream_id']])

    #validate the traffic sent and filtered traffic
    #get the filter stats
    #res = tg2.tg_custom_filter_config(mode='getStats',port_handle=tg_ph_2)
    #tg2.tg_save_xml(filename='/home/cs403178/config_filter_5.xml')

    traffic_details = {
            '1': {
                'tx_ports' : [vars.T1D1P1],
                'tx_obj' : [tg1],
                'exp_ratio' : [1],
                'rx_ports' : [vars.T1D1P2],
                'rx_obj' : [tg2],
                },
            }
    result1 = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='custom_filter', comp_type='packet_count')
    print(result1)

    if result1:
        st.report_pass("operation_successful")
    else:
        st.report_fail("operation_failed")


@pytest.mark.tgen1
def test_igmp_host_emulation():

    h1 = tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr=data.ipv4_addr_D1P1T1, gateway=data.ipv4_addr_D1T1P1,
                                 arp_send_req='1', vlan='1', vlan_id='10', vlan_id_step='0', gateway_step='0.0.0.0')
    h2 = tg1.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr=data.ipv4_addr_D1P2T1, gateway=data.ipv4_addr_D1T1P2,
                                 arp_send_req='1')
    # IGMPv3 Host config
    session_conf1 = {'mode': 'create',
                     'igmp_version': 'v3'
                     }
    group_conf1 = {'mode': 'create',
                   'num_groups': '10',
                   'ip_addr_start': '225.1.1.1',
                   }
    source_conf1 = {'mode': 'create',
                    'num_sources': '10',
                    'ip_addr_start': '11.1.1.1',
                    }
    igmp_group_conf1 = {'mode': 'create',
                        'g_filter_mode': 'include'
                        }

    igmp_host1 = tgapi.tg_igmp_config(tg=tg1,
                                handle=h1['handle'],
                                session_var=session_conf1,
                                group_var=group_conf1,
                                source_var=source_conf1,
                                igmp_group_var=igmp_group_conf1)

    st.log("Host Details: {}".format(igmp_host1))

    igmp_ctrl = tg1.tg_emulation_igmp_control(handle=igmp_host1['session']['host_handle'], mode='start')
    st.log("igmp_join: {}".format(igmp_ctrl))

    igmp_ctrl = tg1.tg_emulation_igmp_control(handle=igmp_host1['config']['group_handle'], mode='join')
    st.log("igmp_join: {}".format(igmp_ctrl))

    igmp_ctrl = tg1.tg_emulation_igmp_control(handle=igmp_host1['config']['group_handle'], mode='leave')
    st.log("igmp_leave: {}".format(igmp_ctrl))

    igmp_ctrl = tg1.tg_emulation_igmp_control(handle=igmp_host1['session']['host_handle'], mode='stop')
    st.log("igmp_join: {}".format(igmp_ctrl))

    # Delete session
    ses = tg1.tg_emulation_igmp_config(handle=igmp_host1['session']['host_handle'], mode='delete')
    st.log("Session_delete_Status: {}".format(ses))

    # IGMPv2 Host config
    session_conf2 = {'mode': 'create',
                     'igmp_version': 'v2'
                     }
    group_conf2 = {'mode': 'create',
                   'num_groups': '10',
                   'ip_addr_start': '225.1.1.1',
                   }
    igmp_group_conf2 = {'mode': 'create',
                        'g_filter_mode': 'include'
                        }

    igmp_host2 = tgapi.tg_igmp_config(tg=tg1,
                                handle=h1['handle'],
                                session_var=session_conf2,
                                group_var=group_conf2,
                                igmp_group_var=igmp_group_conf2)

    st.log("Host Details: {}".format(igmp_host2))

    igmp_ctrl = tg1.tg_emulation_igmp_control(handle=igmp_host2['session']['host_handle'], mode='start')
    st.log("igmp_join: {}".format(igmp_ctrl))

    igmp_ctrl = tg1.tg_emulation_igmp_control(handle=igmp_host2['config']['group_handle'], mode='join')
    st.log("igmp_join: {}".format(igmp_ctrl))

    igmp_ctrl = tg1.tg_emulation_igmp_control(handle=igmp_host2['config']['group_handle'], mode='leave')
    st.log("igmp_leave: {}".format(igmp_ctrl))

    igmp_ctrl = tg1.tg_emulation_igmp_control(handle=igmp_host2['session']['host_handle'], mode='stop')
    st.log("igmp_join: {}".format(igmp_ctrl))

    # Delete session
    ses = tg1.tg_emulation_igmp_config(handle=igmp_host2['session']['host_handle'], mode='delete')
    st.log("Session_delete_Status: {}".format(ses))

    # IGMPv2 Querier Config
    querier_config = tg1.tg_emulation_igmp_querier_config(handle=h2['handle'], mode='create')
    st.log("Querier Config Details: {}".format(querier_config))
    querier_control = tg1.tg_igmp_querier_control(mode='start', handle=querier_config['handle'])
    st.log("Querier Control Details: {}".format(querier_control))

    # IGMPv3 Host Config with emulation APIs
    session = tg1.tg_emulation_igmp_config(handle=h1['handle'], mode='create', igmp_version='v3')
    group = tg1.tg_emulation_multicast_group_config(mode='create', ip_addr_start='225.1.1.1', num_groups=5)
    source = tg1.tg_emulation_multicast_source_config(mode='create', ip_addr_start=data.ipv4_addr_D1P1T1, num_sources=5)
    config = tg1.tg_emulation_igmp_group_config(mode='create', session_handle=session['host_handle'],
                                                group_pool_handle=group['mul_group_handle'], g_filter_mode='include',
                                                source_pool_handle=source['mul_source_handle'])
    st.log(
        "Host Handles:\n 'session': {}\n'group': {}\n'source': {}\nconfig: {}\n".format(session, group, source, config))
    igmp_ctrl = tg1.tg_emulation_igmp_control(handle=session['host_handle'], mode='start')
    st.log("igmp_join: {}".format(igmp_ctrl))
    igmp_join = tg1.tg_emulation_igmp_control(mode='join', handle=config['group_handle'])
    st.log("igmp_join: {}".format(igmp_join))
    igmp_leave = tg1.tg_emulation_igmp_control(mode='leave', handle=config['group_handle'])
    st.log("igmp_leave: {}".format(igmp_leave))

    # Delete session
    ses = tg1.tg_emulation_igmp_config(handle=session['host_handle'], mode='delete')
    st.log("Session_delete_Status: {}".format(ses))

    # IGMPv2 Host Config with emulation APIs
    session = tg1.tg_emulation_igmp_config(handle=h1['handle'], mode='create')
    group = tg1.tg_emulation_multicast_group_config(mode='create', ip_addr_start='225.1.1.1', num_groups=5)
    config = tg1.tg_emulation_igmp_group_config(mode='create', session_handle=session['host_handle'],
                                                group_pool_handle=group['mul_group_handle'], g_filter_mode='include')
    st.log("Host Handles:\n 'session': {}\n'group': {}\n'config': {}\n".format(session, group, config))
    igmp_ctrl = tg1.tg_emulation_igmp_control(handle=session['host_handle'], mode='start')
    st.log("igmp_join: {}".format(igmp_ctrl))
    igmp_join = tg1.tg_emulation_igmp_control(mode='join', handle=config['group_handle'])
    st.log("igmp_join: {}".format(igmp_join))
    igmp_leave = tg1.tg_emulation_igmp_control(mode='leave', handle=config['group_handle'])
    st.log("igmp_leave: {}".format(igmp_leave))

    # Bound stream traffic config
    tr1 = tg1.tg_traffic_config(port_handle=tg_ph_2, emulation_src_handle=h2['handle'],
                                emulation_dst_handle=group['handle'], circuit_endpoint_type='ipv4', mode='create',
                                transmit_mode='continuous', length_mode='fixed', rate_pps=100)
    st.log("Traffic Details: {}".format(tr1))

    # Delete session
    ses = tg1.tg_emulation_igmp_config(handle=session['host_handle'], mode='delete')
    st.log("Session_delete_Status: {}".format(ses))

    querier_delete = tg1.tg_emulation_igmp_querier_config(handle=querier_config['handle'], mode='delete')
    st.log("Querier Delete Details: {}".format(querier_delete))

    st.report_pass("test_case_passed")


@pytest.mark.tgen1
def test_igmp_snooping_host_emulation():

    h1 = tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr=data.ipv4_addr_D1P1T1, gateway=data.ipv4_addr_D1T1P1,
                                 arp_send_req='1', vlan='1', vlan_id='10', vlan_id_step='0', gateway_step='0.0.0.0',
                                 ipv4_resolve_gateway=0)
    h2 = tg1.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr=data.ipv4_addr_D1P2T1, gateway=data.ipv4_addr_D1T1P2,
                                 arp_send_req='1', ipv4_resolve_gateway=0)

    # IGMPv3 Querier Config
    querier_config = tg1.tg_emulation_igmp_querier_config(handle=h2['handle'], mode='create', igmp_version='v3')
    st.log("Querier Config Details: {}".format(querier_config))
    querier_control = tg1.tg_igmp_querier_control(mode='start', handle=querier_config['handle'])
    st.log("Querier Control Details: {}".format(querier_control))

    # IGMPv3 Host Config with emulation APIs
    session = tg1.tg_emulation_igmp_config(handle=h1['handle'], mode='create', igmp_version='v3')
    group = tg1.tg_emulation_multicast_group_config(mode='create', ip_addr_start='225.1.1.1', num_groups=5,
                                                    ip_prefix_len=24, ip_addr_step_val=10, ip_addr_step='0.0.10.0')
    source = tg1.tg_emulation_multicast_source_config(mode='create', ip_addr_start=data.ipv4_addr_D1P1T1, num_sources=5,
                                                      ip_prefix_len=16, ip_addr_step_val=11, ip_addr_step='0.11.0.0')
    config = tg1.tg_emulation_igmp_group_config(mode='create', session_handle=session['host_handle'],
                                                group_pool_handle=group['mul_group_handle'], g_filter_mode='include',
                                                source_pool_handle=source['mul_source_handle'])
    st.log(
        "Host Handles:\n 'session': {}\n'group': {}\n'source': {}\nconfig: {}\n".format(session, group, source, config))
    igmp_ctrl = tg1.tg_emulation_igmp_control(handle=session['host_handle'], mode='start')
    st.log("igmp_join: {}".format(igmp_ctrl))
    igmp_join = tg1.tg_emulation_igmp_control(mode='join', handle=config['group_handle'])
    st.log("igmp_join: {}".format(igmp_join))
    igmp_leave = tg1.tg_emulation_igmp_control(mode='leave', handle=config['group_handle'])
    st.log("igmp_leave: {}".format(igmp_leave))

    # Delete session
    ses = tg1.tg_emulation_igmp_config(handle=session['host_handle'], mode='delete')
    st.log("Session_delete_Status: {}".format(ses))

    st.report_pass("test_case_passed")


@pytest.mark.tgen1
def test_ospf_host_emulation():

    # Routing interface configuration
    h1 = tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr=data.ipv4_addr_D1P1T1, gateway=data.ipv4_addr_D1T1P1,
                                 arp_send_req='1', vlan='1', vlan_id='10', vlan_id_step='0', gateway_step='0.0.0.0',
                                 control_plane_mtu='9100')
    '''
    h1 = tg1.tg_interface_config(port_handle=tg_ph_1, mode='config', intf_ip_addr=data.ipv4_addr_D1P1T1, gateway=data.ipv4_addr_D1T1P1,
                                 arp_send_req='1', control_plane_mtu='9100')
    '''
    st.log("INTFCONF: " + str(h1))
    h2 = tg1.tg_interface_config(port_handle=tg_ph_2, mode='config', intf_ip_addr=data.ipv4_addr_D1P2T1, gateway=data.ipv4_addr_D1T1P2,
                                 arp_send_req='1')
    st.log("INTFCONF: " + str(h1))

    # Creating OSPF router session
    ospf_ses = tg1.tg_emulation_ospf_config(handle=h1['handle'], mode='create', session_type='ospfv2', router_id='1.1.1.1',
                                            area_id='0.0.0.0', gateway_ip_addr=data.ipv4_addr_D1T1P1, network_type = 'broadcast',
                                            max_mtu='9100')
    st.log("OSPF Session: " + str(ospf_ses))

    # OSPF Route configuration
    # Summary prefixes
    IA = tg1.tg_emulation_ospf_route_config(mode='create', type='summary_routes', handle=ospf_ses['handle'],
                                            summary_number_of_prefix='10', summary_prefix_start='201.1.0.0',
                                            summary_prefix_length='24', summary_prefix_metric='10',
                                            router_id='101.1.0.0')
    st.log("Summary Routes: " + str(IA))
    # External TYpe-1 prefixes
    E1 = tg1.tg_emulation_ospf_route_config(mode='create', type='ext_routes', handle=ospf_ses['handle'],
                                            external_number_of_prefix='10', external_prefix_start='202.1.0.0',
                                            external_prefix_length='24', external_prefix_type='1',
                                            router_id='102.1.0.0')
    st.log("External Type-1 Routes: " + str(E1))
    # External TYpe-2 prefixes
    E2 = tg1.tg_emulation_ospf_route_config(mode='create', type='ext_routes', handle=ospf_ses['handle'],
                                            external_number_of_prefix='10', external_prefix_start='203.1.0.0',
                                            external_prefix_length='24', external_prefix_type='2',
                                            router_id='103.1.0.0')
    st.log("External Type-2 Routes: " + str(E2))

    # OSPF LSA generation
    # External TYpe-1 LSA
    ext1_lsa = tg1.tg_ospf_lsa_config(external_number_of_prefix='10', external_prefix_start='20.1.0.0',
                                      external_prefix_length='32', type='ext_pool', external_prefix_type='1',
                                      external_prefix_metric='1', handle=ospf_ses['handle'], mode='create')
    st.log("External Type-1 LSAs: " + str(ext1_lsa))
    # External TYpe-2 LSA
    ext2_lsa = tg1.tg_ospf_lsa_config(external_number_of_prefix='10', external_prefix_start='30.1.0.0',
                                      external_prefix_length='32', type='ext_pool', external_prefix_type='2',
                                      external_prefix_metric='1', handle=ospf_ses['handle'], mode='create')
    st.log("External Type-1 LSAs: " + str(ext2_lsa))
    # Summary LSA
    sum_lsa = tg1.tg_ospf_lsa_config(summary_number_of_prefix='10', summary_prefix_start='50.1.0.0',
                                     summary_prefix_length='32', type='summary_pool',
                                     summary_prefix_metric='1', handle=ospf_ses['handle'], mode='create')
    st.log("Summary LSAs: " + str(sum_lsa))

    # Start OSPF protocol
    ctrl = tg1.tg_emulation_ospf_control(mode='start', handle=ospf_ses['handle'])

    # st.wait(20)
    # tg1.tg_emulation_ospfv2_info(handle=ospf_ses['handle'])
    # tg1.tg_emulation_ospf_info(handle=ospf_ses['handle'])

    # Bound stream traffic configuration
    tr1 = tg2.tg_traffic_config(port_handle=tg_ph_2, emulation_src_handle=h2['handle'], duration='10',
                                emulation_dst_handle=IA['handle'], circuit_endpoint_type='ipv4',
                                mode='create', transmit_mode='continuous', length_mode='fixed', rate_pps=500)
    st.log("Bound Stream: " + str(tr1))
    stream_id1 = tr1['stream_id']

    # send contiuous traffic for 2 seconds with 10 packets per second
    tg1.tg_traffic_control(action='run', port_handle=tg_ph_2, duration='10')
    # st.wait(10)

    vars = st.get_testbed_vars()
    traffic_details = {
        '1': {
            'tx_ports': [vars.T1D1P2],
            'tx_obj': [tg2],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D1P1],
            'rx_obj': [tg1],
            'stream_list': [[stream_id1]],
        },
    }

    res = tg1.tg_traffic_control(action='stop', handle=tr1['stream_id'])
    st.log("CTRL: " + str(res))

    # verify traffic mode aggregate
    aggrResult = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count')

    if aggrResult:
        st.log('traffic verification passed for mode aggregate')
    else:
        st.log('traffic verification failed for mode aggregate')

    if aggrResult:
        st.report_pass("operation_successful")
    else:
        st.report_fail("operation_failed")

    # Delete OSPF Route Config
    IA_del = tg1.tg_emulation_ospf_route_config(mode='delete', handle=IA['handle'])
    st.log("CTRL: " + str(IA_del))

    # Stop OSPF protocol
    ctrl = tg1.tg_emulation_ospf_control(mode='stop', handle=ospf_ses['handle'])
    st.log("CTRL: " + str(ctrl))

    # Delete OSPF protocol session
    res = tg1.tg_emulation_ospf_config(handle=ospf_ses['handle'], mode='delete')
    st.log("Delete OSPF Session: " + str(res))

    st.report_pass("test_case_passed")


@pytest.mark.tgen_dhcpv4
def test_dhcp_emulation():
    '''
    config interface ip add Ethernet0 192.168.0.1/24
    config interface ip add Ethernet1 1.1.1.2/24
    config interface ip dhcp-relay add Ethernet0 1.1.1.1

    Server | 1.1.1.1-----1.1.1.2 |DUT| 192.168.0.1 ----- | Client
    '''

    # DHCP Server Config with relay agent
    dut_mac = basic.get_ifconfig_ether(vars.D1, vars.D1T1P1)
    s_conf = tg1.tg_emulation_dhcp_server_config(mode='create', ip_version='4', encapsulation='ETHERNET_II',
                                                 ipaddress_count='3000', ipaddress_pool='1.1.1.3', port_handle=tg_ph_2,
                                                 count='1', local_mac='00:10:95:00:00:01', ip_address='1.1.1.1',
                                                 ip_gateway='1.1.1.2', remote_mac=dut_mac)
    st.log("DHCP Server Config: {}".format(s_conf))
    s_relay_config = tg1.tg_emulation_dhcp_server_relay_agent_config(mode='create',
                                                                     handle=s_conf['dhcp_handle'],
                                                                     relay_agent_ipaddress_count='2000',
                                                                     relay_agent_ipaddress_pool='192.168.0.2',
                                                                     relay_agent_ipaddress_step='0.0.0.1',
                                                                     prefix_length='12')
    st.log("DHCP Relay Agent Config: {}".format(s_relay_config))
    s_con = tg1.tg_emulation_dhcp_server_control(action='connect', dhcp_handle=s_conf['dhcp_handle'])
    st.log("DHCP Server Control: {}".format(s_con))
    st.wait(5)
    # DHCP Client Config(Port Based)
    conf = tg1.tg_emulation_dhcp_config(mode='create', port_handle=tg_ph_1)
    st.log("DHCP Client: {}".format(s_con))
    '''
    # Default optional list: opt_list = ['1','6','15','33','44']
    group = tg1.tg_emulation_dhcp_group_config(handle=conf['handles'], mode='create', encap='ethernet_ii',
                                               num_sessions='2000', mac_addr='00:10:94:00:00:01',
                                               dhcp_range_ip_type=4, ipv4_gateway_address='192.168.0.1')
    st.log("DHCP Group Config: {}".format(s_con))
    '''
    group = tg1.tg_emulation_dhcp_group_config(handle=conf['handles'], mode='create', encap='ethernet_ii_vlan', vlan_id_count = '20',
                                               num_sessions='20', mac_addr='00:10:94:00:00:01', vlan_id = 10, vlan_ether_type = '0x8100',
                                               dhcp_range_ip_type=4, ipv4_gateway_address='192.168.0.1',vlan_id_step=0, gateway_addresses=1)
    st.log("DHCP Group Config: {}".format(s_con))

    cont = tg1.tg_emulation_dhcp_control(port_handle=tg_ph_1, action="bind", handle=group['handle'])
    st.log("DHCP Client Control: {}".format(cont))

    cont = tg1.tg_emulation_dhcp_control(port_handle=tg_ph_1, action="rebind", handle=group['handle'])
    st.log("DHCP Client Control: {}".format(cont))

    cont = tg1.tg_emulation_dhcp_control(port_handle=tg_ph_1, action="renew", handle=group['handle'])
    st.log("DHCP Client Control: {}".format(cont))

    cont = tg1.tg_emulation_dhcp_control(port_handle=tg_ph_1, action="release", handle=group['handle'])
    st.log("DHCP Client Control: {}".format(cont))

    # tg1.tg_emulation_dhcp_stats(port_handle=tg_ph_1, handle=conf['handles'], mode='aggregate')

    tg1.tg_emulation_dhcp_config(mode='reset', handle=conf['handles'])
    tg1.tg_emulation_dhcp_server_config(mode='reset', handle=s_conf['dhcp_handle'])
    st.report_pass("test_case_passed")

@pytest.mark.tgen_dhcpv6
def test_dhcpv6_emulation():
    '''
    config interface ip add Ethernet0 3000::1/64
    config interface ip add Ethernet1 2000::1/64
    config interface ip dhcp-relay add Ethernet0 2000::2

    Server | 2000::2-----2000::1 |DUT| 3000::1 ----- | Client
    '''

    # DHCPv6 Server Config with relay agent
    #dut_mac = basic.get_ifconfig_ether(vars.D1, vars.D1T1P1)
    dhcpv6_serv = tg1.tg_emulation_dhcp_server_config(mode='create', ip_version='6', encapsulation='ethernet_ii',
                                                      prefix_pool_step='1', prefix_pool_per_server='2000',
                                                      prefix_pool_start_addr='3000::', prefix_pool_prefix_length='64',
                                                      addr_pool_addresses_per_server='2000',
                                                      addr_pool_start_addr='3000::2', addr_pool_prefix_length='64',
                                                      addr_pool_step_per_server='1', port_handle=tg_ph_2,
                                                      server_emulation_mode='DHCPV6', local_ipv6_prefix_len='64',
                                                      local_ipv6_addr='2000::2', gateway_ipv6_addr='2000::1', count='1',
                                                      mac_addr='00:10:94:00:00:04')
    st.log("DHCPv6 Server Config: {}".format(dhcpv6_serv))

    ctrl_serv = tg1.tg_emulation_dhcp_server_control(dhcp_handle=dhcpv6_serv['dhcp_handle'], action='connect',
                                                     ip_version='6')
    st.log("DHCPv6 Server Control: {}".format(ctrl_serv))

    dhcpv6_handle = tg1.tg_emulation_dhcp_config(mode='create', ip_version='6', port_handle=tg_ph_1)
    st.log("DHCPv6 Client: {}".format(dhcpv6_handle))
    '''
    dhcpv6_group = tg1.tg_emulation_dhcp_group_config(mode='create', dhcp_range_ip_type='6', encap='ethernet_ii',
                                                      handle=dhcpv6_handle['handles'],
                                                      client_mac_addr='00:10:01:00:00:01',
                                                      dhcp6_client_mode='DHCPV6', gateway_ipv6_addr='3000::1',
                                                      num_sessions='2000', mac_addr='00:10:94:00:00:05')
    st.log("DHCPv6 Group Config: {}".format(dhcpv6_group))
    '''
    dhcpv6_group = tg1.tg_emulation_dhcp_group_config(mode='create', dhcp_range_ip_type='6', encap='ethernet_ii_vlan',
                                                      handle=dhcpv6_handle['handles'], vlan_cfi = 0,
                                                      client_mac_addr='00:10:01:00:00:01', vlan_id = 10,
                                                      dhcp6_client_mode='DHCPV6', gateway_ipv6_addr='3000::1',
                                                      num_sessions='2000', mac_addr='00:10:94:00:00:05', vlan_id_step=0)
    st.log("DHCPv6 Group Config: {}".format(dhcpv6_group))
    '''
    group = tg1.tg_emulation_dhcp_group_config(handle=conf['handles'], mode='create', encap='ethernet_ii_vlan', vlan_id_count = '20',
                                               num_sessions='20', mac_addr='00:10:94:00:00:01', vlan_id = 10, vlan_ether_type = '0x8100',
                                               dhcp_range_ip_type=4, ipv4_gateway_address='192.168.0.1',vlan_id_step=0, gateway_addresses=1)
    st.log("DHCP Group Config: {}".format(s_con))
    '''
    ctrl_client = tg1.tg_emulation_dhcp_control(port_handle=tg_ph_1, action='bind', ip_version='6',
                                              handle=dhcpv6_group['dhcpv6_handle'])
    st.log("DHCP Client Control: {}".format(ctrl_client))

    ctrl_client = tg1.tg_emulation_dhcp_control(port_handle=tg_ph_1, action='rebind', ip_version='6',
                                                handle=dhcpv6_group['dhcpv6_handle'])
    st.log("DHCP Client Control: {}".format(ctrl_client))

    ctrl_client = tg1.tg_emulation_dhcp_control(port_handle=tg_ph_1, action='renew', ip_version='6',
                                                handle=dhcpv6_group['dhcpv6_handle'])
    st.log("DHCP Client Control: {}".format(ctrl_client))

    ctrl_client = tg1.tg_emulation_dhcp_control(port_handle=tg_ph_1, action='release', ip_version='6',
                                                handle=dhcpv6_group['dhcpv6_handle'])
    st.log("DHCP Client Control: {}".format(ctrl_client))

    tg1.tg_emulation_dhcp_config(mode='reset', handle=dhcpv6_handle['handles'], ip_version=6)
    tg1.tg_emulation_dhcp_server_config(mode='reset', handle=dhcpv6_serv['dhcp_handle'], ip_version=6)

    st.report_pass("test_case_passed")


