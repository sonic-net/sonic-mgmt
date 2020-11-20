import pytest
from spytest import st, tgapi

from tests.qos.qos_map import verify_counter_cpu_asic_bcm

import apis.system.basic as basic_obj
import apis.routing.ip as ip_obj
import apis.common.asic as asicapi
from  apis.system.sflow import enable_disable_config, add_del_collector
import apis.qos.copp as copp_obj
import apis.routing.ip_helper as ip_helper_obj
copp_data = dict()


@pytest.fixture(scope="module", autouse=True)
def copp_module_hooks(request):
    global vars, tg, tg_ph_1, d1_p1,hw_constants, deviation_percentage, d1_p1_mac, copp_data
    vars = st.ensure_min_topology("D1T1:1")
    hw_constants  = st.get_datastore(vars.D1 , "constants", "default")
    st.debug("hw_constants: {}".format(hw_constants))
    tg, tg_ph_1 = tgapi.get_handle_byname("T1D1P1")
    d1_p1 = vars.D1T1P1
    deviation_percentage = 0.05
    ret_val = copp_obj.get_copp_config(dut= vars.D1, table_name='all')
    if ret_val:
        copp_data = ret_val
    else:
        st.report_fail('module_config_failed', 'show copp config command failed')
    # Get the DUT mac address
    d1_p1_mac = basic_obj.get_ifconfig(vars.D1, d1_p1)[0]['mac']
    # Config the routing interface
    ip_obj.config_ip_addr_interface(dut=vars.D1, interface_name=d1_p1, ip_address='1.1.1.2', subnet='24')
    yield
    # Un-configure the routing interface
    ip_obj.delete_ip_interface(dut=vars.D1, interface_name=d1_p1, ip_address='1.1.1.2', subnet='24')

@pytest.fixture(scope="function", autouse=True)
def copp_func_hooks(request):
    asicapi.clear_counters(vars.D1)
    yield

def retrun_group_dict(copp_data,copp_group):
    for each in copp_data:
        if copp_group in each:
            return copp_data[each]['value']

def sflow_copp_config_undo():
    copp_obj.set_copp_config(vars.D1, ["COPP_TABLE:trap.group.sflow", "cbs", "16000"],
                    ["COPP_TABLE:trap.group.sflow", "cir", "16000"])
    st.log("performing reboot")
    st.reboot(vars.D1)

def sflow_unconfig():
    enable_disable_config(vars.D1, interface=False, interface_name=None, action="enable",
                                cli_type="klish")
    add_del_collector(vars.D1, collector_name="collector_1", ip_address="1.1.1.1",
                            port_number=None, action="add", cli_type="klish")

@pytest.mark.copp
def test_ft_copp_lldp():
    """
    scenario : Verify CoPP functionality for lldp
    Author : vishnuvardhan.talluri@broadcom.com
    :return:
    """
    success = True
    st.log("testcase to verify COPP for lldp")
    copp_cir_lldp = hw_constants['COPP_CIR_LLDP']
    sent_rate_pps = copp_cir_lldp * 2
    deviation = copp_cir_lldp * deviation_percentage
    copp_queue = retrun_group_dict(copp_data, 'lldp')['queue']
    tg.tg_traffic_control(action='reset', port_handle=[tg_ph_1])
    st.log('sending lldp packets for {}pps and expecting rate limit to {}pps '.format(sent_rate_pps,copp_cir_lldp))
    tg_stream_handle = tg.tg_traffic_config(port_handle=tg_ph_1, mac_src="00:11:97:2F:8E:82", mac_dst="01:80:C2:00:00:0E",
                         mode='create', transmit_mode='continuous', l2_encap='ethernet_ii',
                         data_pattern='02 07 04 00 11 97 2F 8E 80 04 07 03 00 11 97 2F 8E 82 06 02 00 78 00 00 00 00 '
                                      '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
                         ethernet_value='88CC',rate_pps=sent_rate_pps)['stream_id']
    st.log("send lldp packets and verify cpu counter")
    tg.tg_traffic_control(action='run', stream_handle=[tg_stream_handle])
    st.wait(5)
    if not verify_counter_cpu_asic_bcm(dut=vars.D1, queue=copp_queue, value=copp_cir_lldp, tol=deviation):
        st.error('CPU counter check for rate limiting  lldp to {}pps is failed'.format(copp_cir_lldp))
        success = False
    tg.tg_traffic_control(action='stop', stream_handle=[tg_stream_handle])
    if success:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")


def test_ft_copp_lacp():
    """
    scenario : Verify CoPP functionality for lacp
    Author : vishnuvardhan.talluri@broadcom.com
    :return:
    """
    success = True
    copp_cir_lacp = hw_constants['COPP_CIR_LACP']
    sent_rate_pps = copp_cir_lacp * 2
    deviation = copp_cir_lacp * deviation_percentage
    copp_queue = retrun_group_dict(copp_data, 'lacp')['queue']
    st.log("testcase to verify COPP for lacp")
    tg.tg_traffic_control(action='reset', port_handle=[tg_ph_1])
    st.log('sending lacp packets for {}pps and expecting rate limit to {}pps '.format(sent_rate_pps,copp_cir_lacp))

    tg_stream_handle = tg.tg_traffic_config(port_handle=tg_ph_1, mac_src="D8:C4:97:72:73:5F", mac_dst="01:80:C2:00:00:02",
                         mode='create', transmit_mode='continuous', data_pattern_mode='fixed',l2_encap='ethernet_ii',
                         data_pattern='01 01 01 14 FF FF D8 C4 97 72 73 5F 00 07 00 FF 00 20 85 00 00 00 02 14 00 00 '
                                      '00 00 00 00 00 00 00 00 00 00 00 00 02 00 00 00 03 10 00 00 00 00 00 00 00 00 '
                                      '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                                      '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                                      '00 00 00 00 00 00', ethernet_value='8809', rate_pps=sent_rate_pps)['stream_id']
    st.log("send lacp request and verify cpu counter")
    tg.tg_traffic_control(action='run', stream_handle=[tg_stream_handle])
    st.wait(5)
    if not verify_counter_cpu_asic_bcm(dut=vars.D1, queue=copp_queue, value=copp_cir_lacp, tol=deviation):
        st.error('CPU counter check for rate limiting  lacp to {}pps is failed'.format(copp_cir_lacp))
        success = False
    tg.tg_traffic_control(action='stop', stream_handle=[tg_stream_handle])
    if success:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")


@pytest.mark.copp
def test_ft_copp_dhcp():
    """
    scenario : Verify CoPP functionality for dhcp
    Author : vishnuvardhan.talluri@broadcom.com
    :return:
    """
    success = True
    copp_cir_dhcp = hw_constants['COPP_CIR_DHCP']
    sent_rate_pps = copp_cir_dhcp * 2
    deviation = copp_cir_dhcp * deviation_percentage
    copp_queue = retrun_group_dict(copp_data,'dhcp')['queue']
    st.log("testcase to verify COPP for dhcp")
    tg.tg_traffic_control(action='reset', port_handle=[tg_ph_1])
    st.log('sending dhcp packets for {}pps and expecting rate limit to {}pps '.format(sent_rate_pps,copp_cir_dhcp))

    tg_stream_handle = tg.tg_traffic_config(port_handle=[tg_ph_1], mac_src="00:13:5F:1F:F2:80", mac_dst="33:33:00:01:00:02",
                         l3_protocol='ipv6', mode='create', transmit_mode='continuous',
                         rate_pps=sent_rate_pps, data_pattern='01 D1 49 5E 00 08 00 02 00 78 00 01 00 0A 00 03 00 01 00 13 '
                                                      '5F 1F F2 80 00 06 00 06 00 19 00 17 00 18 00 19 00 0C 00 33 '
                                                      '00 01 00 00 00 00 00 00 00 00', frame_size=116,
                         ipv6_dst_addr="FF02:0:0:0:0:0:1:2", ipv6_src_addr="FE80:0:0:0:201:5FF:FE00:500",
                         ipv6_next_header=17, ipv6_traffic_class=224,l4_protocol='udp',udp_dst_port=546,
                         udp_src_port=547, ipv6_hop_limit=255)['stream_id']
    st.log("send dhcpv6 solicit and verify cpu counter")
    tg.tg_traffic_control(action='run', stream_handle=[tg_stream_handle])
    st.wait(5)
    if not verify_counter_cpu_asic_bcm(dut=vars.D1, queue=copp_queue, value=copp_cir_dhcp, tol=deviation):
        st.error('CPU counter check for rate limiting  dhcp to {}pps is failed'.format(copp_cir_dhcp))
        success = False
    tg.tg_traffic_control(action='stop', stream_handle=[tg_stream_handle])

    if success:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")


@pytest.mark.copp
def test_ft_copp_arp():
    """
    scenario : Verify CoPP functionality for arp
    Author : vishnuvardhan.talluri@broadcom.com
    :return:
    """
    success = True
    copp_cir_arp = hw_constants['COPP_CIR_ARP']
    sent_rate_pps = copp_cir_arp * 2
    deviation = copp_cir_arp * deviation_percentage
    copp_queue = retrun_group_dict(copp_data, 'arp')['queue']
    st.log("testcase to verify COPP for arp")

    tg.tg_traffic_control(action='reset', port_handle=[tg_ph_1])
    st.log('sending ARP packets for {}pps and expecting rate limit to {}pps '.format(sent_rate_pps,copp_cir_arp))

    tg_stream_handle = tg.tg_traffic_config(port_handle=[tg_ph_1], mac_src="00:00:00:11:11:80", mac_dst="FF:FF:FF:FF:FF:FF",
                         mode='create', transmit_mode='continuous',rate_pps=sent_rate_pps, l2_encap='ethernet_ii',
                         l3_protocol='arp', arp_src_hw_addr="00:00:00:11:11:80", arp_dst_hw_addr="00:00:00:00:00:00",
                         arp_operation='arpRequest', ip_src_addr='1.1.1.1', ip_dst_addr='1.1.1.2')['stream_id']
    st.log("send ARP request and verify cpu counter")
    tg.tg_traffic_control(action='run', stream_handle=[tg_stream_handle])
    st.wait(5)
    if not verify_counter_cpu_asic_bcm(dut=vars.D1, queue=copp_queue, value=copp_cir_arp, tol=deviation):
        st.error('CPU counter check for rate limiting  arp to {}pps is failed'.format(copp_cir_arp))
        success = False
    tg.tg_traffic_control(action='stop', stream_handle=[tg_stream_handle])

    if success:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")


@pytest.mark.copp
def test_copp_ndp():
    """
    scenario : Verify that IPv6 NDP control packets are getting rate-limited in CoPP with srtcm policer
    Author : vishnuvardhan.talluri@broadcom.com
    :return:
    """
    success = True
    copp_cir_ndp = hw_constants['COPP_CIR_NDP']
    sent_rate_pps = copp_cir_ndp * 2
    deviation = copp_cir_ndp * deviation_percentage
    st.log("testcase to verify COPP for ndp")

    tg.tg_traffic_control(action='reset', port_handle=[tg_ph_1])
    st.log('sending ndp packets for {}pps and expecting rate limit to {}pps '.format(sent_rate_pps,copp_cir_ndp))

    tg_stream_handle = tg.tg_traffic_config(port_handle=[tg_ph_1], mac_src="00:0a:01:01:23:01", mac_dst="b8:6a:97:ca:bb:98",
                         l3_protocol='ipv6', mode='create', transmit_mode='continuous',
                         rate_pps=sent_rate_pps, data_pattern='FF FF', l4_protocol="icmp",
                         ipv6_dst_addr="fe80::ba6a:97ff:feca:bb98", ipv6_src_addr="2001::2",
                         ipv6_next_header=58, icmp_target_addr='2001::2', icmp_type=136, icmp_ndp_nam_o_flag=0,
                         icmp_ndp_nam_r_flag=1, icmp_ndp_nam_s_flag=1, ipv6_hop_limit=255)['stream_id']
    st.log("send ndp discover and verify cpu counter")
    tg.tg_traffic_control(action='run', stream_handle=[tg_stream_handle])
    st.wait(5)
    if not verify_counter_cpu_asic_bcm(dut=vars.D1, queue='3', value=copp_cir_ndp, tol=deviation):
        st.error('CPU counter check for rate limiting  NDP to {}pps is failed'.format(copp_cir_ndp))
        success = False
    tg.tg_traffic_control(action='stop', stream_handle=[tg_stream_handle])

    if success:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")


@pytest.mark.copp
def test_ft_copp_bgp():
    """
    scenario : Verify CoPP functionality for bgp
    Author : vishnuvardhan.talluri@broadcom.com
    :return:
    """
    success = True
    st.log("testcase to verify COPP for bgp")
    copp_cir_bgp = hw_constants['COPP_CIR_BGP']
    sent_rate_pps = copp_cir_bgp * 2
    deviation = copp_cir_bgp * deviation_percentage
    copp_queue = retrun_group_dict(copp_data, 'bgp')['queue']
    tg.tg_traffic_control(action='reset', port_handle=[tg_ph_1])
    st.log('sending bgp packets for {}pps and expecting rate limit to {}pps '.format(sent_rate_pps,copp_cir_bgp))
    tg_stream_handle = tg.tg_traffic_config(port_handle=tg_ph_1, mac_src="E4:F0:04:38:07:DA", mac_dst=d1_p1_mac,
                         mode='create', transmit_mode='continuous',
                         data_pattern='FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF 00 2D 01 04 00 C8 00 5A 05 05 '
                                      '05 05 10 02 0E 01 04 00 01 00 01 02 00 41 04 00 00 00 C8',
                         rate_pps=sent_rate_pps, l3_protocol='ipv4', ip_protocol=6, ip_src_addr='1.1.1.1',
                         l4_protocol='tcp', ip_precedence=5, frame_size=103,
                         ip_dst_addr='1.1.1.2', tcp_dst_port=179, tcp_src_port=54821, tcp_window=115,
                         tcp_seq_num=1115372998, tcp_ack_num=1532875182,tcp_ack_flag=1, tcp_psh_flag=1, ip_ttl=1)['stream_id']
    st.log("send bgp open packets and verify cpu counter")
    tg.tg_traffic_control(action='run', stream_handle=[tg_stream_handle])
    st.wait(5)
    if not verify_counter_cpu_asic_bcm(dut=vars.D1,queue=copp_queue,value=copp_cir_bgp,tol=deviation):
        st.error('CPU counter check for rate limiting bgp to {}pps is failed'.format(copp_cir_bgp))
        success = False
    tg.tg_traffic_control(action='stop', stream_handle=[tg_stream_handle])

    if success:
        st.report_pass("test_case_passed")
    else:
        st.report_fail("test_case_failed")

@pytest.mark.copp
def test_ft_copp_igmp():
    """
    scenario : Verify CoPP functionality for igmp
    Author : sreenivasula.reddy@broadcom.com
    :return:
    """
    success = True
    copp_cir_igmp = hw_constants['COPP_CIR_IGMP']
    sent_rate_pps = copp_cir_igmp * 2
    deviation = copp_cir_igmp * deviation_percentage
    copp_queue = retrun_group_dict(copp_data, 'igmp')['queue']
    st.log("testcase to verify COPP for igmp")

    tg.tg_traffic_control(action='reset', port_handle=[tg_ph_1])
    st.log('sending igmp packets for {}pps and expecting rate limit to {}pps '.format(sent_rate_pps, copp_cir_igmp))

    tg_stream_handle = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create', transmit_mode='continuous',
                         length_mode='fixed', rate_pps=sent_rate_pps, mac_src='00:01:05:00:1A:00',
                         mac_dst='01:00:5e:01:01:02', ethernet_value='8100',
                         data_pattern_mode='fixed', l2_encap='ethernet_ii',
                         data_pattern='0C 74 08 00 46 00 00 20 00 00 00 00 01 02 2D CA 15 01 01 '
                                      '0A E0 01 01 02 94 04 00 00 16 64 08 98 E0 01 01 02 00 01 '
                                      '02 03 04 05 06 07 08 09 0A 0B 0C 0D 99 2C 9E 39')['stream_id']
    st.log("send igmp query packet and verify cpu counter")
    tg.tg_traffic_control(action='run', stream_handle=[tg_stream_handle])
    st.wait(5)
    if not verify_counter_cpu_asic_bcm(dut=vars.D1, queue=copp_queue, value=copp_cir_igmp, tol=deviation):
        st.error('CPU counter check for rate limiting igmp to {}pps is failed'.format(copp_cir_igmp))
        success = False
    tg.tg_traffic_control(action='stop', stream_handle=[tg_stream_handle])
    if success:
        st.report_pass("igmp_rate_limit_status", copp_cir_igmp, "passed")
    else:
        st.report_fail("igmp_rate_limit_status", copp_cir_igmp, "failed")

@pytest.mark.copp
def test_ft_copp_sflow():
    """
    scenario : Verify CoPP functionality for sflow
    Author : sreenivasula.reddy@broadcom.com
    :return:
    """
    success = True
    copp_obj.set_copp_config(vars.D1,["COPP_TABLE:trap.group.sflow", "cbs", "600"], ["COPP_TABLE:trap.group.sflow", "cir", "600"])
    st.log("performing reboot")
    st.reboot(vars.D1)
    try:
        enable_disable_config(vars.D1, interface=False, interface_name=None, action="enable",
                                   cli_type="klish")
        add_del_collector(vars.D1, collector_name="collector_1", ip_address="1.1.1.1",
                                port_number=None, action="add", cli_type="klish")
    except Exception as e:
        st.log(e)
        st.report_fail("exception_observed", e)
    copp_cir_sflow = hw_constants['COPP_CIR_SFLOW']
    sent_rate_pps = "921828"
    deviation = copp_cir_sflow * deviation_percentage
    st.log("testcase to verify COPP for sflow")
    tg.tg_traffic_control(action='reset', port_handle=[tg_ph_1])
    st.log('sending packets for {}pps and expecting rate limit to {}pps '.format(sent_rate_pps, copp_cir_sflow))
    tg_stream_handle = tg.tg_traffic_config(mac_src='00.00.00.00.00.01', mac_dst='00.00.00.00.00.02', rate_pps=sent_rate_pps, mode='create', \
                      port_handle=tg_ph_1, transmit_mode='continuous', l2_encap='ethernet_ii_vlan', vlan_id='10')['stream_id']
    tg.tg_traffic_control(action='run', stream_handle=[tg_stream_handle])
    st.wait(5)
    if not verify_counter_cpu_asic_bcm(dut=vars.D1, queue='8', value=copp_cir_sflow, tol=deviation):
        st.error('CPU counter check for rate limiting igmp to {}pps is failed'.format(copp_cir_sflow))
        success = False
    tg.tg_traffic_control(action='stop', stream_handle=[tg_stream_handle])
    if success:
        sflow_copp_config_undo()
        sflow_unconfig()
        st.report_pass("sflow_rate_limit_status", copp_cir_sflow, "passed")
    else:
        sflow_copp_config_undo()
        sflow_unconfig()
        st.report_fail("sflow_rate_limit_status", copp_cir_sflow, "failed")



# IP helper case: RtIpHeAdFn011
def test_ft_copp_udp():
    """
    scenario : Verify CoPP functionality for UDP
    Author :
    :return:
    """
    success = True
    config_rate_limit_value = 5000
    st.log("test case to verify COPP for UDP broadcast packets")
    st.log("On DUT enable IP helper globally")
    ip_helper_obj.config(vars.D1, helper_status='enable')
    st.log("Configuring rate limit value {} for UDP broadcast packets.".format(config_rate_limit_value))
    ip_helper_obj.config(vars.D1, rate_limit_val=config_rate_limit_value)
    if not ip_helper_obj.verify(vars.D1, 'forward_protocol', verify_list=[{'forwarding': 'Enabled',
                                                                           'enable_ports': ['TFTP', 'NTP', 'DNS',
                                                                                            'TACACS',
                                                                                            'NetBios-Name-Server',
                                                                                            'NetBios-Datagram-Server',
                                                                                            ], 'rate_limit': str(config_rate_limit_value)}]):
        st.report_fail("UDP_forwarding_status_verification_failed")
    st.log("Configure IP helper address {} on interface {}".format("2.2.2.2", vars.D1T1P1))
    # noinspection PyInterpreter
    ip_helper_obj.config(vars.D1, action_str='add', intf_name=vars.D1T1P1, ip_address="2.2.2.2")
    copp_cir_udp = config_rate_limit_value
    sent_rate_pps = copp_cir_udp * 2
    deviation = copp_cir_udp * deviation_percentage
    tg.tg_traffic_control(action='reset', port_handle=[tg_ph_1])
    st.log('sending UDP packets for {}pps and expecting rate limit to {}pps '.format(sent_rate_pps, copp_cir_udp))
    tg_stream_handle = tg.tg_traffic_config(port_handle=[tg_ph_1], mac_src="00:00:00:11:22:33", mac_dst="FF:FF:FF:FF:FF:FF",
                         mode='create', transmit_mode='continuous',
                         data_pattern='00 03 01 00 00 01 00 00 00 00 00 00 06 67 6f 6f 67 6c 65 03 63 6f 6d 00 00 01 00 01',
                         rate_pps=sent_rate_pps, l3_protocol='ipv4', ip_protocol=17, ip_src_addr='1.1.1.1',
                         l4_protocol='udp', ip_dst_addr='255.255.255.255', udp_dst_port='53', udp_src_port=54821)['stream_id']

    st.log("send UDP broadcast packets and verify CPU counter")
    tg.tg_traffic_control(action='run', stream_handle=[tg_stream_handle])
    st.wait(5)
    if not verify_counter_cpu_asic_bcm(dut=vars.D1, queue='2', value=copp_cir_udp, tol=deviation):
        st.error('CPU counter check for rate limiting udp to {} pps is failed'.format(copp_cir_udp))
        success = False
    tg.tg_traffic_control(action='stop', stream_handle=[tg_stream_handle])

    ip_helper_obj.config(vars.D1, rate_limit_val=600)
    ip_helper_obj.config(vars.D1, action_str='remove', intf_name=vars.D1T1P1, ip_address="2.2.2.2")
    st.log("On DUT Disable IP helper globally")
    ip_helper_obj.config(vars.D1, cli_type='click', helper_status='disable')

    msg_str = "UDP broadcast rate limit"
    if success:
        st.report_pass("IP_helper_test_case_msg_status", msg_str, "passed")
    else:
        st.report_fail("IP_helper_test_case_msg_status", msg_str, "failed")

