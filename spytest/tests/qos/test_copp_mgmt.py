import pytest
from spytest import st, tgapi
from tests.qos.qos_map import verify_counter_cpu_asic_bcm
import apis.system.basic as basic_obj
import apis.system.interface as intf
import apis.routing.ip as ip_obj
import apis.routing.sag as sag
import apis.common.asic as asicapi
from apis.system.sflow import enable_disable_config, add_del_collector
import apis.qos.copp as copp_obj
import apis.routing.ip_helper as ip_helper_obj
import apis.switching.vlan as Vlan
import apis.routing.evpn as Evpn
import apis.system.sflow as sflow1
import apis.system.reboot as reboot
import apis.qos.qos_shaper as shaper

@pytest.fixture(scope="module", autouse=True)
def copp_module_hooks(request):
    global vars, tg, tg_ph_1, tg_ph_2,d1_p2, d1_p1, deviation_percentage, d1_p1_mac, \
        d1d2_p1, d2d1_p1, policy
    vars = st.ensure_min_topology("D1T1:2","D1D2:1")
    tg, tg_ph_1 = tgapi.get_handle_byname("T1D1P1")
    tg, tg_ph_2 = tgapi.get_handle_byname("T1D1P2")
    d1d2_p1 = vars.D1D2P1
    d2d1_p1 = vars.D2D1P1
    d1_p1 = vars.D1T1P1
    d1_p2 = vars.D1T1P2
    deviation_percentage = 0.05

    hdrMsg("Module config STEP 1: Check default system copp policy")
    policy = copp_obj.verify_policy_type_copp(vars.D1,return_output="yes")
    if isinstance(policy,bool):
        hdrMsg("FAIL : show cpolicy type copp does not return valid o/p, so aborting scrip run")
        st.report_fail("base_config_verification_failed")

    hdrMsg("Module config STEP 2: Display each CoPP Flow Group, CoPP Action Group, Trap-queue & CIR present in system by default")
    for entry in policy:
        st.log("CoPP Flow group = {}, CoPP Action Group = {}, Trap Queue = {}, CIR = {}".format(entry['copp_fgroup'], \
            entry['copp_agroup'],entry['trap_queue'],entry['cir']))

    hdrMsg("Module config STEP 3: Get the DUT mac address")
    d1_p1_mac = basic_obj.get_ifconfig(vars.D1, d1_p1)[0]['mac']

    hdrMsg("Module config STEP 4: Configiure the routing interface")
    ip_obj.config_ip_addr_interface(dut=vars.D1, interface_name=d1_p1, ip_address='1.1.1.2', subnet='24')
    copp_obj.config_copp_burst_rxrate(vars.D1,rx_rate=100000,rx_burst_rate=10000,skip_error=True)
    yield

    hdrMsg("Module un-config STEP 1: Un-configure the routing interface")
    ip_obj.delete_ip_interface(dut=vars.D1, interface_name=d1_p1, ip_address='1.1.1.2', subnet='24')
    copp_obj.config_copp_burst_rxrate(vars.D1,rx_rate=30000,rx_burst_rate=3000,skip_error=True)

@pytest.fixture(scope="function", autouse=True)
def copp_func_hooks(request):
    hdrMsg("Clearing the CPU queue counters")
    asicapi.clear_counters(vars.D1)
    copp_obj.clear_cpu_queue_counters(vars.D1)
    yield
    if st.get_func_name(request) == 'test_ft_coppmgmt_burst_lldp' and tg.tg_type=='ixia':
        tg.tg_interface_config(mode='modify', port_handle=[tg_ph_1, tg_ph_2], transmit_mode='advanced')

def sflow_unconfig():
    hdrMsg("Un-configure SFLOW config")
    enable_disable_config(vars.D1, interface=False, interface_name=None, action="disable")
    sflow1.config_attributes(vars.D1,interface_name=d1_p1,sample_rate="256",no_form="yes")
    add_del_collector(vars.D1, collector_name="", ip_address="1.1.1.1",
                            port_number=None, action="del")

@pytest.mark.copp_mgmt
def test_ft_coppmgmt_lldp():
    success = True
    hdrMsg("TestCase Copp312: Verify CoPP functionality for LLDP")

    hdrMsg("STEP 1: Check the CoPP LLDP class CIR and CPU queue")
    copp_cir_lldp, sent_rate_pps, deviation, copp_queue = get_cir_queue("copp-system-lldp")

    tg.tg_traffic_control(action='reset', port_handle=[tg_ph_1])

    hdrMsg('STEP 2: Sending lldp packets for {} pps and expecting rate limit to {} pps '.format(sent_rate_pps,copp_cir_lldp))
    tg_stream_handle = tg.tg_traffic_config(port_handle=tg_ph_1, mac_src="00:11:97:2F:8E:82", mac_dst="01:80:C2:00:00:0E",
                         mode='create', transmit_mode='continuous', l2_encap='ethernet_ii',
                         data_pattern='02 07 04 00 11 97 2F 8E 80 04 07 03 00 11 97 2F 8E 82 06 02 00 78 00 00 00 00 '
                                      '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
                         ethernet_value='88CC',rate_pps=sent_rate_pps)['stream_id']

    hdrMsg("STEP 3: Check the system status")
    if not basic_obj.poll_for_system_status(vars.D1,iteration=5, delay=2):
        st.error("System is not in ready state")
        st.report_fail("test_case_failed")

    hdrMsg("STEP 4: Send lldp packets")
    tg.tg_traffic_control(action='run', stream_handle=[tg_stream_handle])
    st.wait(5,"Waiting for 5 secs after sending traffic")

    hdrMsg("STEP 5: Verify cpu counter for LLDP packets")
    if not verify_counter_cpu_asic_bcm(dut=vars.D1, queue=copp_queue, value=copp_cir_lldp, tol=deviation):
        st.error('CPU counter check for rate limiting  lldp to {} pps is failed'.format(copp_cir_lldp))
        success = False

    hdrMsg("STEP 6: Verify cpu counter for LLDP packets using show CPU queue PPS counters")
    tolerance = (copp_cir_lldp*10)/100
    if not copp_obj.verify_cpu_queue_pkt_rate(vars.D1,queue_id=copp_queue,exp_rate=copp_cir_lldp,tolerance=tolerance):
        st.error('CPU counter check for rate limiting LLDP to {} pps is failed'.format(copp_cir_lldp))

    stop_traffic_dump_debug(tg_stream_handle,success)

    dict1 = copp_obj.get_cpu_queue_counters(dut=vars.D1,queue_id=copp_queue,param="pps")
    dict1_1 = copp_obj.get_cpu_queue_counters(dut=vars.D1,queue_id=copp_queue,param="bps")
    copp_obj.clear_cpu_queue_counters(vars.D1,queue_id=copp_queue)
    st.wait(15,"Waiting for clear CPU queue to reflect correct status after polling interval of 10 sec")
    dict2 = copp_obj.get_cpu_queue_counters(dut=vars.D1,queue_id=copp_queue,param="pps")
    dict2_1 = copp_obj.get_cpu_queue_counters(dut=vars.D1,queue_id=copp_queue,param="bps")

    if int(dict2['pps']) == 0 or int(dict2['pps']) < int(dict1['pps']):
        st.log("show queue counters interface CPU queue {} PPS and {} PPS verified PASS".format(dict1['pps'],dict2['pps']))
    else:
        st.error("show queue counters interface CPU queue {} PPS failed, rate reduced from {} to {}".format(copp_queue,int(dict1['pps']),int(dict2['pps'])))
        success = False

    if int(dict2_1['bps']) == 0 or int(dict2_1['bps']) < int(dict1_1['bps']):
        st.log("show queue counters interface CPU queue {} BPS and {} BPS  verified PASS".format(dict1_1['bps'],dict2_1['bps']))
    else:
        st.error("show queue counters interface CPU queue {} BPS failed, rate reduced from {} to {}".format(copp_queue,int(dict1_1['bps']),int(dict2_1['bps'])))
        success = False

    if success:
        st.report_pass("test_case_passed","Copp312")
    else:
        st.report_fail("test_case_failed","Copp312")

@pytest.mark.copp_mgmt
def test_ft_coppmgmt_lacp():
    success = True
    hdrMsg("TestCase Copp313: Verify CoPP functionality for LACP")

    hdrMsg("STEP 1: Check the CoPP LACP class CIR and CPU queue")
    copp_cir_lacp, sent_rate_pps, deviation, copp_queue = get_cir_queue("copp-system-lacp")

    tg.tg_traffic_control(action='reset', port_handle=[tg_ph_1])
    hdrMsg('STEP 2: Sending lacp packets for {} pps and expecting rate limit to {} pps '.format(sent_rate_pps,copp_cir_lacp))

    tg_stream_handle = tg.tg_traffic_config(port_handle=tg_ph_1, mac_src="D8:C4:97:72:73:5F", mac_dst="01:80:C2:00:00:02",
                         mode='create', transmit_mode='continuous', data_pattern_mode='fixed',l2_encap='ethernet_ii',
                         data_pattern='01 01 01 14 FF FF D8 C4 97 72 73 5F 00 07 00 FF 00 20 85 00 00 00 02 14 00 00 '
                                      '00 00 00 00 00 00 00 00 00 00 00 00 02 00 00 00 03 10 00 00 00 00 00 00 00 00 '
                                      '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                                      '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                                      '00 00 00 00 00 00', ethernet_value='8809', rate_pps=sent_rate_pps)['stream_id']

    hdrMsg("STEP 3: Check the system status")
    if not basic_obj.poll_for_system_status(vars.D1,iteration=5, delay=2):
        st.error("System is not in ready state")
        st.report_fail("test_case_failed")

    hdrMsg("STEP 4: Send lacp request")
    tg.tg_traffic_control(action='run', stream_handle=[tg_stream_handle])
    st.wait(5,"Waiting for 5 secs after sending traffic")

    hdrMsg("STEP 5: Verify cpu counter for LACP packets")
    if not verify_counter_cpu_asic_bcm(dut=vars.D1, queue=copp_queue, value=copp_cir_lacp, tol=deviation):
        st.error('CPU counter check for rate limiting LACP to {} pps is failed'.format(copp_cir_lacp))
        success = False

    hdrMsg("STEP 6: Verify cpu counter for LACP packets using show CPU queue no of pkts counts ")
    tolerance = (copp_cir_lacp*10)/100
    if not copp_obj.verify_cpu_queue_pkt_rate(vars.D1,queue_id=copp_queue,exp_rate=copp_cir_lacp,tolerance=tolerance,from_pkts_count="yes"):
        st.error('CPU counter check for rate limiting LACP to {} pps is failed'.format(copp_cir_lacp))
        success = False

    hdrMsg("STEP 6: Verify cpu counter for LACP packets using show CPU queue PPS field")
    if not copp_obj.verify_cpu_queue_pkt_rate(vars.D1,queue_id=copp_queue,exp_rate=copp_cir_lacp,tolerance=tolerance):
        st.error('CPU counter check for rate limiting LACP to {} pps is failed'.format(copp_cir_lacp))
        success = False

    stop_traffic_dump_debug(tg_stream_handle,success)

    if success:
        st.report_pass("test_case_passed","Copp313")
    else:
        st.report_fail("test_case_failed","Copp313")


@pytest.mark.copp_mgmt
def test_ft_coppmgmt_dhcp():
    success = True
    hdrMsg("TestCase Copp314: Verify COPP for dhcp")

    hdrMsg("STEP 1: Check the CoPP DHCP class CIR and CPU queue")
    copp_cir_dhcp, sent_rate_pps, deviation, copp_queue = get_cir_queue("copp-system-dhcp")

    tg.tg_traffic_control(action='reset', port_handle=[tg_ph_1])

    hdrMsg('STEP 2: Sending dhcp packets for {} pps and expecting rate limit to {} pps '.format(sent_rate_pps,copp_cir_dhcp))
    tg_stream_handle = tg.tg_traffic_config(port_handle=[tg_ph_1], mac_src="00:13:5F:1F:F2:80", mac_dst="33:33:00:01:00:02",
                         l3_protocol='ipv6', mode='create', transmit_mode='continuous',
                         rate_pps=sent_rate_pps, data_pattern='01 D1 49 5E 00 08 00 02 00 78 00 01 00 0A 00 03 00 01 00 13 '
                                                      '5F 1F F2 80 00 06 00 06 00 19 00 17 00 18 00 19 00 0C 00 33 '
                                                      '00 01 00 00 00 00 00 00 00 00', frame_size=116,
                         ipv6_dst_addr="FF02:0:0:0:0:0:1:2", ipv6_src_addr="FE80:0:0:0:201:5FF:FE00:500",
                         ipv6_next_header=17, ipv6_traffic_class=224,l4_protocol='udp',udp_dst_port=546,
                         udp_src_port=547, ipv6_hop_limit=255)['stream_id']

    hdrMsg("STEP 3: Check the system status")
    if not basic_obj.poll_for_system_status(vars.D1,iteration=5, delay=2):
        st.error("System is not in ready state")
        st.report_fail("test_case_failed")

    hdrMsg("STEP 4: Send dhcpv6 solicit..")
    tg.tg_traffic_control(action='run', stream_handle=[tg_stream_handle])
    st.wait(5,"Waiting for 5 secs after sending traffic")

    hdrMsg("STEP 5: Verify cpu counter for DHCP packets")
    if not verify_counter_cpu_asic_bcm(dut=vars.D1, queue=copp_queue, value=copp_cir_dhcp, tol=deviation):
        st.error('CPU counter check for rate limiting  dhcp to {} pps is failed'.format(copp_cir_dhcp))
        success = False

    hdrMsg("STEP 6: Verify cpu counter for DHCP packets using show CPU queue counters")
    tolerance = (copp_cir_dhcp*10)/100
    if not copp_obj.verify_cpu_queue_pkt_rate(vars.D1,queue_id=copp_queue,exp_rate=copp_cir_dhcp,tolerance=tolerance):
        st.error('CPU counter check for rate limiting DHCP to {} pps is failed'.format(copp_cir_dhcp))

    stop_traffic_dump_debug(tg_stream_handle,success)

    if success:
        st.report_pass("test_case_passed","Copp314")
    else:
        st.report_fail("test_case_failed","Copp314")


@pytest.mark.copp_mgmt
def test_ft_coppmgmt_arp():
    success = True
    hdrMsg("TestCase Copp317: Verify COPP for arp")

    hdrMsg("STEP 1: Check the CoPP ARP class CIR and CPU queue")
    copp_cir_arp, sent_rate_pps, deviation, copp_queue = get_cir_queue("copp-system-arp")

    hdrMsg('STEP 2: Sending ARP packets for {} pps and expecting rate limit to {} pps '.format(sent_rate_pps,copp_cir_arp))
    tg.tg_traffic_control(action='reset', port_handle=[tg_ph_1])
    tg_stream_handle = tg.tg_traffic_config(port_handle=[tg_ph_1], mac_src="00:00:00:11:11:80", mac_dst="FF:FF:FF:FF:FF:FF",
                         mode='create', transmit_mode='continuous',rate_pps=sent_rate_pps, l2_encap='ethernet_ii',
                         l3_protocol='arp', arp_src_hw_addr="00:00:00:11:11:80", arp_dst_hw_addr="00:00:00:00:00:00",
                         arp_operation='arpRequest', ip_src_addr='1.1.1.1', ip_dst_addr='1.1.1.2')['stream_id']

    hdrMsg("STEP 3: Check the system status")
    if not basic_obj.poll_for_system_status(vars.D1,iteration=5, delay=2):
        st.error("System is not in ready state")
        st.report_fail("test_case_failed")

    hdrMsg("STEP 4: Send ARP request packets..")
    tg.tg_traffic_control(action='run', stream_handle=[tg_stream_handle])
    st.wait(5,"Waiting for 5 secs after sending traffic")

    hdrMsg("STEP 5: Verify cpu counter for ARP packets")
    if not verify_counter_cpu_asic_bcm(dut=vars.D1, queue=copp_queue, value=copp_cir_arp, tol=deviation):
        st.error('CPU counter check for rate limiting  arp to {} pps is failed'.format(copp_cir_arp))
        success = False

    hdrMsg("STEP 6: Verify cpu counter for ARP packets using show CPU queue counters")
    tolerance = (copp_cir_arp*10)/100
    if not copp_obj.verify_cpu_queue_pkt_rate(vars.D1,queue_id=copp_queue,exp_rate=copp_cir_arp,tolerance=tolerance):
        st.error('CPU counter check for rate limiting ARP to {} pps is failed'.format(copp_cir_arp))

    stop_traffic_dump_debug(tg_stream_handle,success)

    if success:
        st.report_pass("test_case_passed","Copp317")
    else:
        st.report_fail("test_case_failed","Copp317")


@pytest.mark.copp_mgmt
def test_ft_coppmgmt_ndp():
    success = True
    hdrMsg("TestCase Copp318: Verify COPP for ndp")

    hdrMsg("STEP 1: Check the CoPP NDP class CIR and CPU queue")
    copp_cir_ndp, sent_rate_pps, deviation, copp_queue = get_cir_queue("copp-system-arp")

    tg.tg_traffic_control(action='reset', port_handle=[tg_ph_1])
    hdrMsg('STEP 2: Sending ndp packets for {} pps and expecting rate limit to {} pps '.format(sent_rate_pps,copp_cir_ndp))

    tg_stream_handle = tg.tg_traffic_config(port_handle=[tg_ph_1], mac_src="00:0a:01:01:23:01", mac_dst="b8:6a:97:ca:bb:98",
                         l3_protocol='ipv6', mode='create', transmit_mode='continuous',
                         rate_pps=sent_rate_pps, data_pattern='FF FF', l4_protocol="icmp",
                         ipv6_dst_addr="fe80::ba6a:97ff:feca:bb98", ipv6_src_addr="2001::2",
                         ipv6_next_header=58, icmp_target_addr='2001::2', icmp_type=136, icmp_ndp_nam_o_flag=0,
                         icmp_ndp_nam_r_flag=1, icmp_ndp_nam_s_flag=1, ipv6_hop_limit=255)['stream_id']

    hdrMsg("STEP 3: Check the system status")
    if not basic_obj.poll_for_system_status(vars.D1,iteration=5, delay=2):
        st.error("System is not in ready state")
        st.report_fail("test_case_failed")

    hdrMsg("STEP 4: Send ndp discover and verify cpu counter")
    tg.tg_traffic_control(action='run', stream_handle=[tg_stream_handle])
    st.wait(5,"Waiting for 5 secs after sending traffic")

    hdrMsg("STEP 5: Verify cpu counter for ND packets")
    if not verify_counter_cpu_asic_bcm(dut=vars.D1, queue=copp_queue, value=copp_cir_ndp, tol=deviation):
        st.error('CPU counter check for rate limiting  NDP to {} pps is failed'.format(copp_cir_ndp))
        success = False

    hdrMsg("STEP 6: Verify cpu counter for ND packets using show CPU queue counters")
    tolerance = (copp_cir_ndp*10)/100
    if not copp_obj.verify_cpu_queue_pkt_rate(vars.D1,queue_id=copp_queue,exp_rate=copp_cir_ndp,tolerance=tolerance):
        st.error('CPU counter check for rate limiting ND to {} pps is failed'.format(copp_cir_ndp))

    stop_traffic_dump_debug(tg_stream_handle,success)

    if success:
        st.report_pass("test_case_passed","Copp318")
    else:
        st.report_fail("test_case_failed","Copp318")


@pytest.mark.copp_mgmt
def test_ft_coppmgmt_bgp():
    success = True
    hdrMsg("TestCase Copp319: Verify COPP for bgp")

    hdrMsg("STEP 1: Check the CoPP BGP class CIR and CPU queue")
    copp_cir_bgp, sent_rate_pps, deviation, copp_queue = get_cir_queue("copp-system-bgp")

    hdrMsg('STEP 2: Sending bgp packets for {} pps and expecting rate limit to {} pps '.format(sent_rate_pps,copp_cir_bgp))
    tg.tg_traffic_control(action='reset', port_handle=[tg_ph_1])
    tg_stream_handle = tg.tg_traffic_config(port_handle=tg_ph_1, mac_src="E4:F0:04:38:07:DA", mac_dst=d1_p1_mac,
                         mode='create', transmit_mode='continuous',
                         data_pattern='FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF 00 2D 01 04 00 C8 00 5A 05 05 '
                                      '05 05 10 02 0E 01 04 00 01 00 01 02 00 41 04 00 00 00 C8',
                         rate_pps=sent_rate_pps, l3_protocol='ipv4', ip_protocol=6, ip_src_addr='1.1.1.1',
                         l4_protocol='tcp', ip_precedence=5, frame_size=103,
                         ip_dst_addr='1.1.1.2', tcp_dst_port=179, tcp_src_port=54821, tcp_window=115,
                         tcp_seq_num=1115372998, tcp_ack_num=1532875182,tcp_ack_flag=1, tcp_psh_flag=1, ip_ttl=1)['stream_id']

    hdrMsg("STEP 3: Check the system status")
    if not basic_obj.poll_for_system_status(vars.D1,iteration=5, delay=2):
        st.error("System is not in ready state")
        st.report_fail("test_case_failed")

    hdrMsg("STEP 4: Send bgp open packets and verify cpu counter")
    tg.tg_traffic_control(action='run', stream_handle=[tg_stream_handle])
    st.wait(5,"Waiting for 5 secs after sending traffic")

    hdrMsg("STEP 5: Verify cpu counter for BGP packets")
    if not verify_counter_cpu_asic_bcm(dut=vars.D1,queue=copp_queue,value=copp_cir_bgp,tol=deviation):
        st.error('CPU counter check for rate limiting bgp to {} pps is failed'.format(copp_cir_bgp))
        success = False

    hdrMsg("STEP 6: Verify cpu counter for BGP packets using show CPU queue counters")
    tolerance = (copp_cir_bgp*10)/100
    if not copp_obj.verify_cpu_queue_pkt_rate(vars.D1,queue_id=copp_queue,exp_rate=copp_cir_bgp,tolerance=tolerance):
        st.error('CPU counter check for rate limiting BGP to {} pps is failed'.format(copp_cir_bgp))

    stop_traffic_dump_debug(tg_stream_handle,success)

    if success:
        st.report_pass("test_case_passed","Copp319")
    else:
        st.report_fail("test_case_failed","Copp319")

@pytest.mark.copp_mgmt
def test_ft_coppmgmt_igmp():
    success = True
    hdrMsg("TestCase Copp325: Verify COPP for igmp")

    ip_obj.delete_ip_interface(dut=vars.D1, interface_name=d1_p1, ip_address='1.1.1.2', subnet='24')
    Vlan.create_vlan(vars.D1,"3188")
    Vlan.add_vlan_member(vars.D1,"3188",d1_p1,True)
    ip_obj.config_ip_addr_interface(dut=vars.D1, interface_name="Vlan3188", ip_address='1.1.1.2', subnet='24')

    hdrMsg("STEP 1: Check the CoPP IGMP class CIR and CPU queue")
    copp_cir_igmp, sent_rate_pps, deviation, copp_queue = get_cir_queue("copp-system-igmp")

    tg.tg_traffic_control(action='reset', port_handle=[tg_ph_1])
    hdrMsg('STEP 2: Sending igmp packets for {} pps and expecting rate limit to {} pps '.format(sent_rate_pps, copp_cir_igmp))

    tg_stream_handle = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create', transmit_mode='continuous',
                         length_mode='fixed', rate_pps=sent_rate_pps, mac_src='00:01:05:00:1A:00',
                         mac_dst='01:00:5e:01:01:02', ethernet_value='8100',
                         data_pattern_mode='fixed', l2_encap='ethernet_ii',
                         data_pattern='0C 74 08 00 46 00 00 20 00 00 00 00 01 02 2D CA 15 01 01 '
                                      '0A E0 01 01 02 94 04 00 00 16 64 08 98 E0 01 01 02 00 01 '
                                      '02 03 04 05 06 07 08 09 0A 0B 0C 0D 99 2C 9E 39')['stream_id']

    hdrMsg("STEP 3: Check the system status")
    if not basic_obj.poll_for_system_status(vars.D1,iteration=5, delay=2):
        st.error("System is not in ready state")
        st.report_fail("test_case_failed")

    hdrMsg("STEP 4: Send igmp query packet and verify cpu counter")
    tg.tg_traffic_control(action='run', stream_handle=[tg_stream_handle])
    st.wait(5,"Waiting for 5 secs after sending traffic")

    hdrMsg("STEP 5: Verify cpu counter for IGMP packets")
    if not verify_counter_cpu_asic_bcm(dut=vars.D1, queue=copp_queue, value=copp_cir_igmp, tol=deviation):
        st.error('CPU counter check for rate limiting igmp to {} pps is failed'.format(copp_cir_igmp))
        success = False

    hdrMsg("STEP 6: Verify cpu counter for IGMP packets using show CPU queue counters")
    tolerance = (copp_cir_igmp*10)/100
    if not copp_obj.verify_cpu_queue_pkt_rate(vars.D1,queue_id=copp_queue,exp_rate=copp_cir_igmp,tolerance=tolerance):
        st.error('CPU counter check for rate limiting IGMP to {} pps is failed'.format(copp_cir_igmp))

    stop_traffic_dump_debug(tg_stream_handle,success)

    ip_obj.delete_ip_interface(dut=vars.D1, interface_name="Vlan3188", ip_address='1.1.1.2', subnet='24')
    Vlan.delete_vlan_member(vars.D1,"3188",d1_p1,True)
    Vlan.delete_vlan(vars.D1,"3188")
    ip_obj.config_ip_addr_interface(dut=vars.D1, interface_name=d1_p1, ip_address='1.1.1.2', subnet='24')

    if success:
        st.report_pass("test_case_passed","Copp325")
    else:
        st.report_fail("test_case_failed","Copp325")

@pytest.mark.copp_mgmt
def test_ft_user_sflow():
    success = True
    hdrMsg("TestCase Copp371: Verify COPP for sflow")
    hdrMsg("STEP 1: Configure SFLOW attributes.")
    sflow1.config_attributes(vars.D1,interface_name=d1_p1,sample_rate="256")

    hdrMsg("STEP 2: Remove default CoPP sflow class from default CoPP Policy")
    copp_obj.bind_class_action_copp_policy(vars.D1,classifier="copp-system-sflow",action_group="copp-system-sflow",config="no")

    if st.get_ui_type() in ['rest-put', 'rest-patch', 'rest-post']:
        hdrMsg("STEP 3-a: Create ARP user CoPP class ")
        if not copp_obj.config_copp_classifier(vars.D1,classifier_name="copp-user-arp",protocol_trap_id=["arp_req"],copp_group="copp-user-arp-action"):
            st.log("ARP user CoPP class creation failed through rest URI")
        else:
            st.log("ARP user CoPP class creation success through rest URI")

        hdrMsg("STEP 3-b: Create ARP user CoPP action group")
        if not copp_obj.config_copp_action_group(vars.D1,copp_action_group="copp-user-arp-action",
                                          trap_action="COPY",trap_priority="10",trap_queue="10",
                                          cir="3100",cbs="3170"):
            st.log("ARP user CoPP action creation failed through rest URI")
        else:
            st.log("ARP user CoPP action creation success through rest URI")
        hdrMsg("STEP 4: Bind sflow copp trap or class-map with with sflow copp group or copp action group")
        if not copp_obj.config_coppgroup_copptrap_viarest(vars.D1,classifier_name="copp-user-sflow", \
              protocol_trap_id=["sample_packet"],copp_action_group="copp-user-sflow", \
              trap_priority="3",trap_queue="3",cir="6000",cbs="6070",trap_action="trap"):
            st.log("Binding of class-map and action group to system copp policy failed through rest URI")
        else:
            st.log("Binding of class-map and action group to system copp policy success through rest URI")
    else:
        hdrMsg("STEP 3: Create sflow user CoPP class and user CoPP action group to be applied to default CoPP Policy")
        copp_obj.config_copp_classifier(vars.D1,classifier_name="copp-user-sflow",protocol_trap_id=["sample_packet"])
        copp_obj.config_copp_action_group(vars.D1,copp_action_group="copp-user-sflow-action",trap_queue="3",cir="6000", \
            cbs="6070",trap_action="trap")
        hdrMsg("STEP 4: Applied  SFLOW user CoPP class and user CoPP action group to default CoPP Policy")
        copp_obj.bind_class_action_copp_policy(vars.D1,classifier="copp-user-sflow",action_group="copp-user-sflow-action")

    if st.get_ui_type() in ['rest-put', 'rest-patch', 'rest-post']:
        hdrMsg("STEP 5: Verify user defined ARP class-map/copp-trap and user defined copp-action-group/copp-group binding to system CoPP Policy")
        res = copp_obj.verify_policy_type_copp(dut=vars.D1,copp_fgroup="copp-user-arp",copp_agroup="copp-user-arp-action", \
            cir="3100",cbs="3170",trap_queue="10",trap_priority="10")
        hdrMsg("STEP 5: Verify user defined SFLOW class-map/copp-trap and user defined copp-action-group/copp-group binding to system CoPP Policy")
        res = copp_obj.verify_policy_type_copp(dut=vars.D1,copp_fgroup="copp-user-sflow",copp_agroup="copp-user-sflow", \
            cir="6000",cbs="6070",trap_queue="3")
    else:
        hdrMsg("STEP 5: Verify SFLOW user CoPP class-map and user CoPP action group binding to system CoPP Policy")
        res = copp_obj.verify_policy_type_copp(dut=vars.D1,copp_fgroup="copp-user-sflow",copp_agroup="copp-user-sflow-action", \
            cir="6000",cbs="6070",trap_queue="3")
    if not res:
        st.log("STEP 5: FAIL User defined CIR, CBS do not show up in show policy type copp O/P")
        success = False

    try:
        enable_disable_config(vars.D1, interface=False, interface_name=None, action="enable")
        add_del_collector(vars.D1, collector_name="", ip_address="1.1.1.1",
                                port_number=None, action="add")
    except Exception as e:
        st.log(e)
        st.report_fail("exception_observed", e)

    hdrMsg("STEP 6: Check the CoPP SFLOW class CIR and CPU queue")
    copp_cir_sflow = copp_obj.get_copp_applied_policy_param(dut=vars.D1,copp_fgroup="copp-user-sflow",param="cir")
    deviation = copp_cir_sflow * deviation_percentage
    copp_queue = copp_obj.get_copp_applied_policy_param(dut=vars.D1,copp_fgroup="copp-user-sflow",param="trap_queue")

    tg.tg_traffic_control(action='reset', port_handle=[tg_ph_1])
    tg_stream_handle = tg.tg_traffic_config(mac_src='00.00.00.00.00.01', mac_dst='00.00.00.00.00.02', rate_percent=100, mode='create', \
                      port_handle=tg_ph_1, transmit_mode='continuous', l2_encap='ethernet_ii_vlan', vlan_id='10')['stream_id']

    hdrMsg("STEP 7: Check the system status")
    if not basic_obj.poll_for_system_status(vars.D1,iteration=5, delay=2):
        st.error("System is not in ready state")
        st.report_fail("test_case_failed")

    hdrMsg('STEP 8: Sending packets for 100% line rate and expecting rate limit to {} pps '.format(copp_cir_sflow))
    tg.tg_traffic_control(action='run', stream_handle=[tg_stream_handle])
    st.wait(5,"Waiting for 5 secs after sending traffic")

    if st.get_ui_type() in ['rest-put', 'rest-patch', 'rest-post']:
        if not copp_obj.verify_copp_actions(dut=vars.D1,copp_agroup="copp-user-arp-action",trap_action="copy",cir="3100",cbs="3170",trap_queue="10"):
            st.log("Verify ARP action-group/copp-group failed through rest URI")
        else:
            st.log("Verify ARP action-group/copp-group success through rest URI")
        if not copp_obj.verify_copp_actions(dut=vars.D1,copp_agroup="copp-user-sflow",trap_action="trap",cir="6000",cbs="6070",trap_queue="3"):
            st.log("Verify SFLOW action-group/copp-group failed through rest URI")
        else:
            st.log("Verify SFLOW action-group/copp-group success through rest URI")

    hdrMsg("STEP 9: Verify cpu counter for SFLOW packets using bcmcmd")
    if not verify_counter_cpu_asic_bcm(dut=vars.D1, queue=copp_queue, value=copp_cir_sflow, tol=deviation):
        st.error('CPU counter check for rate limiting sflow to {} pps is failed'.format(copp_cir_sflow))
        success = False

    hdrMsg("STEP 10: Verify cpu counter for SFLOW packets using show CPU queue counters")
    tolerance = (copp_cir_sflow*10)/100
    if not copp_obj.verify_cpu_queue_pkt_rate(vars.D1,queue_id=copp_queue,exp_rate=copp_cir_sflow,tolerance=tolerance):
        st.error('CPU counter check for rate limiting sflow to {} pps is failed'.format(copp_cir_sflow))

    hdrMsg("STEP 11: Stopping the SFLOW packets")
    stop_traffic_dump_debug(tg_stream_handle,success)

    hdrMsg("STEP 12: Remove CoPP user class and action binding to syetem copp policy")
    copp_obj.bind_class_action_copp_policy(vars.D1,classifier="copp-user-sflow",action_group="copp-user-sflow-action",config="no")

    if st.get_ui_type() in ['rest-put', 'rest-patch', 'rest-post']:
        hdrMsg("STEP 13-a: Delete user defined ARP action-group/copp-group")
        if not copp_obj.config_copp_action_group(vars.D1,copp_action_group="copp-user-arp-action",
                                          trap_action="COPY",trap_priority="10",trap_queue="10",
                                          cir="3100",cbs="3170",config="no"):
            st.log("User defined ARP action-group/copp-group deletion failed through rest URI")
        else:
            st.log("User defined ARP action-group/copp-group deletion success through rest URI")

        hdrMsg("STEP 13-b: Delete user defined ARP class-map/copp-trap")
        if not copp_obj.config_copp_classifier(vars.D1,classifier_name="copp-user-arp",protocol_trap_id=["arp_req"],config="no"):
            st.log("User defined ARP class-map/copp-trap deletion failed through rest URI")
        else:
            st.log("User defined ARP class-map/copp-trap deletion success through rest URI")

        hdrMsg("STEP 13-c: Delete user defined SFLOW class-map/copp-trap")
        if not copp_obj.config_copp_classifier(vars.D1,classifier_name="copp-user-sflow",protocol_trap_id=["sample_packet"],config="no"):
            st.log("User defined SFLOW class-map/copp-trap deletion failed through rest URI")
        else:
            st.log("User defined SFLOW class-map/copp-trap deletion success through rest URI")

        hdrMsg("STEP 13-d: Delete user defined SFLOW action-group/copp-group")
        if not copp_obj.config_copp_action_group(vars.D1,copp_action_group="copp-user-sflow",config="no"):
            st.log("User defined SFLOW action-group/copp-group deletion failed through rest URI")
        else:
            st.log("User defined SFLOW action-group/copp-group deletion success through rest URI")
    else:
        hdrMsg("STEP 13: Remove CoPP user class and action group binding")
        copp_obj.config_copp_action_group(vars.D1,copp_action_group="copp-user-sflow-action",trap_queue="3",cir="6000",cbs="6070",config="no")
        copp_obj.config_copp_classifier(vars.D1,classifier_name="copp-user-sflow",protocol_trap_id=["sflow"],config="no")

    hdrMsg("STEP 14: Apply CoPP deafult class and action binding to syetem copp policy")
    copp_obj.bind_class_action_copp_policy(vars.D1,classifier="copp-system-sflow",action_group="copp-system-sflow")

    if success:
        sflow_unconfig()
        st.report_pass("test_case_passed","Copp371")
    else:
        sflow_unconfig()
        st.report_fail("test_case_failed","Copp371")

@pytest.mark.copp_mgmt
def test_ft_coppmgmt_udp():
    success = True
    hdrMsg("TestCase Copp372: Verify COPP for UDP broadcast packets")
    config_rate_limit_value = 5000

    result = copp_obj.verify_qos_scheduler_policy(dut=vars.D1,queue="2",return_output="yes")
    queue1 = int(result['pir'])
    queue1 = (queue1*1000)/8

    hdrMsg("STEP 1: Changing the queue shaper value to support higher CoPP rate limit 5000 PPS for queues 2")
    shaper_data = {'policy_name': "copp-scheduler-policy", 'shaper_data': [{'queue': "2", 'pir': "625000", 'meter_type': 'bytes'}]}
    if not shaper.apply_queue_shaping_config(vars.D1, shaper_data):
        st.log("Config of the queue shaper value to support higher CoPP rate limit 5000 PPS PPS for queues 2 failed")
        success = False

    hdrMsg("STEP 2: On DUT enable IP helper globally")
    ip_helper_obj.config(vars.D1, helper_status='enable')

    hdrMsg("STEP 3: Configuring rate limit value {} for UDP broadcast packets.".format(config_rate_limit_value))
    ip_helper_obj.config(vars.D1, rate_limit_val=config_rate_limit_value)

    if not copp_obj.verify_qos_scheduler_policy(dut=vars.D1,queue="2",sch_policy_name="copp-scheduler-policy",pir="5000"):
        st.log("Change of the queue shaper value to support higher CoPP rate limit 5000 PPS for queues 2 FAIL")
        success = False

    if not ip_helper_obj.verify(vars.D1, forward_protocol='', verify_list=[{'forwarding': 'Enabled',
                                                                           'enable_ports': ['TFTP', 'NTP', 'DNS',
                                                                                            'TACACS',
                                                                                            'NetBios-Name-Server',
                                                                                            'NetBios-Datagram-Server',
                                                                                            ], 'rate_limit': str(config_rate_limit_value)}]):
        st.report_fail("UDP_forwarding_status_verification_failed")

    hdrMsg("STEP 4: Configure IP helper address {} on interface {}".format("2.2.2.2", vars.D1T1P1))
    ip_helper_obj.config(vars.D1, action_str='add', intf_name=vars.D1T1P1, ip_address="2.2.2.2")
    copp_cir_udp = config_rate_limit_value
    sent_rate_pps = copp_cir_udp * 2
    deviation = copp_cir_udp * deviation_percentage
    tg.tg_traffic_control(action='reset', port_handle=[tg_ph_1])

    hdrMsg('STEP 5: Sending UDP packets for {} pps and expecting rate limit to {} pps '.format(sent_rate_pps, copp_cir_udp))
    tg_stream_handle = tg.tg_traffic_config(port_handle=[tg_ph_1], mac_src="00:00:00:11:22:33", mac_dst="FF:FF:FF:FF:FF:FF",
                         mode='create', transmit_mode='continuous',
                         data_pattern='00 03 01 00 00 01 00 00 00 00 00 00 06 67 6f 6f 67 6c 65 03 63 6f 6d 00 00 01 00 01',
                         rate_pps=sent_rate_pps, l3_protocol='ipv4', ip_protocol=17, ip_src_addr='1.1.1.1',
                         l4_protocol='udp', ip_dst_addr='255.255.255.255', udp_dst_port='53', udp_src_port=54821)['stream_id']

    hdrMsg("STEP 6: Check the system status")
    if not basic_obj.poll_for_system_status(vars.D1,iteration=5, delay=2):
        st.error("System is not in ready state")
        st.report_fail("test_case_failed")

    hdrMsg("STEP 7: Send UDP broadcast packets and verify CPU counter")
    tg.tg_traffic_control(action='run', stream_handle=[tg_stream_handle])
    st.wait(5,"Waiting for 5 secs after sending traffic")

    hdrMsg("STEP 8: Verify cpu counter for UDP packets using show CPU queue counters")
    if not verify_counter_cpu_asic_bcm(dut=vars.D1, queue='2', value=copp_cir_udp, tol=deviation):
        st.error('CPU counter check for rate limiting udp to {} pps is failed'.format(copp_cir_udp))
        success = False

    hdrMsg("STEP 9: Verify cpu counter for UDP packets using show CPU queue counters")
    tolerance = (copp_cir_udp*10)/100
    if not copp_obj.verify_cpu_queue_pkt_rate(vars.D1,queue_id="2",exp_rate=copp_cir_udp,tolerance=tolerance):
        st.error('CPU counter check for rate limiting UDP to {} pps is failed'.format(copp_cir_udp))

    ip_helper_obj.config(vars.D1, rate_limit_val=600)
    ip_helper_obj.config(vars.D1, action_str='remove', intf_name=vars.D1T1P1, ip_address="2.2.2.2")

    hdrMsg("STEP 10: On DUT Disable IP helper globally")
    ip_helper_obj.config(vars.D1, cli_type='click', helper_status='disable')

    stop_traffic_dump_debug(tg_stream_handle,success)

    hdrMsg("STEP 11: Restoring the queue shaper value to default value for queues 2 ")
    shaper_data = {'policy_name': "copp-scheduler-policy", 'shaper_data': [{'queue': "2", 'pir':queue1, 'meter_type': 'bytes'}]}
    if not shaper.apply_queue_shaping_config(vars.D1, shaper_data):
        st.log("Restoring the queue shaper value to default value failed for queues 2")

    if success:
        st.report_pass("test_case_passed","Copp372")
    else:
        st.report_fail("test_case_failed","Copp372")

@pytest.mark.copp_mgmt
def test_ft_coppmgmt_burst_lldp():
    success = True
    hdrMsg("TestCase Copp323_2: Copp323,Copp324: Verify CoPP functionality for LLDP with user defined class and action")
    result = copp_obj.verify_qos_scheduler_policy(dut=vars.D1,queue="10",return_output="yes")
    queue1 = int(result['pir'])
    queue1 = (queue1*1000)/8
    result = copp_obj.verify_qos_scheduler_policy(dut=vars.D1,queue="11",return_output="yes")
    queue2 = int(result['pir'])
    queue2 = (queue2*1000)/8

    hdrMsg("STEP 1: Changing the queue shaper value to support higher CoPP rate limit 1250 PPS and 1850 PPS for queues 10 and 11 ")
    shaper_data = {'policy_name': "copp-scheduler-policy", 'shaper_data': [{'queue': "10", 'pir': "162500", 'meter_type': 'bytes'}, \
                   {'queue': "11", 'pir': "237500", 'meter_type': 'bytes'}]}
    if not shaper.apply_queue_shaping_config(vars.D1, shaper_data):
        st.log("Config of the queue shaper value to support higher CoPP rate limit 1300 PPS and 1900 PPS for queues 10 and 11 failed")
        success = False

    hdrMsg("STEP 2: Remove default CoPP lldp class from default CoPP Policy")
    copp_obj.bind_class_action_copp_policy(vars.D1,classifier="copp-system-lldp",action_group="copp-system-lldp",config="no")

    if not copp_obj.verify_qos_scheduler_policy(dut=vars.D1,queue="10",sch_policy_name="copp-scheduler-policy",pir="1300"):
        st.log("Change of the queue shaper value to support higher CoPP rate limit 1300 PPS for queues 10 FAIL")
        success = False
    if not copp_obj.verify_qos_scheduler_policy(dut=vars.D1,queue="11",sch_policy_name="copp-scheduler-policy",pir="1900"):
        st.log("Change of the queue shaper value to support higher CoPP rate limit 1900 PPS for queues 11 FAIL")
        success = False

    hdrMsg("STEP 3: Create LLDP user CoPP class and user CoPP action group to be applied to default CoPP Policy")
    copp_obj.config_copp_classifier(vars.D1,classifier_name="copp-user-lldp",protocol_trap_id=["lldp"])
    copp_obj.config_copp_action_group(vars.D1,copp_action_group="copp-user-lldp-action",trap_queue="10",cir="1250",cbs="1250",trap_action="trap")
    copp_obj.config_copp_action_group(vars.D1,copp_action_group="copp-user-lldp-action1",trap_queue="11",cir="1850",cbs="1850",trap_action="trap")

    hdrMsg("STEP 4: Applied LLDP user CoPP class and user CoPP action group to default CoPP Policy")
    copp_obj.bind_class_action_copp_policy(vars.D1,classifier="copp-user-lldp",action_group="copp-user-lldp-action")

    hdrMsg("STEP 5: Verify LLDP user CoPP class and user CoPP action group binding to system CoPP Policy")
    res = copp_obj.verify_policy_type_copp(dut=vars.D1,copp_fgroup="copp-user-lldp",copp_agroup="copp-user-lldp-action", \
        cir="1250",cbs="1250",trap_queue="10",trap_action="trap")
    if not res:
        st.log("STEP 5: FAIL User defined CIR 5250 PPS, CBS 5270 PPS do not show up in show policy type copp O/P")
        success = False

    hdrMsg("STEP 6: Get the LLDP CIR and queue ID from show polciy type copp output")
    copp_cbs_lldp = copp_obj.get_copp_applied_policy_param(dut=vars.D1,copp_fgroup="copp-user-lldp",param="cbs")
    copp_queue = copp_obj.get_copp_applied_policy_param(dut=vars.D1,copp_fgroup="copp-user-lldp",param="trap_queue")

    tg.tg_traffic_control(action='reset', port_handle=[tg_ph_1])
    if tg.tg_type == 'ixia':
        tg.tg_interface_config(mode='modify', port_handle=[tg_ph_1, tg_ph_2], transmit_mode='stream')

    hdrMsg('STEP 7: Sending lldp packets for {} pps and expecting rate limit to {} pps '.format("100% line rate",copp_cbs_lldp))
    tg_stream_handle = tg.tg_traffic_config(port_handle=tg_ph_1, mac_src="00:11:97:2F:8E:82", mac_dst="01:80:C2:00:00:0E",
                         mode='create', transmit_mode='multi_burst', l2_encap='ethernet_ii',burst_loop_count="20",pkts_per_burst="100",
                         data_pattern='02 07 04 00 11 97 2F 8E 80 04 07 03 00 11 97 2F 8E 82 06 02 00 78 00 00 00 00 '
                                      '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
                         ethernet_value='88CC',rate_percent=100, global_stream_control='iterations', global_stream_control_iterations=1)['stream_id']

    hdrMsg("STEP 8: Check the system status")
    if not basic_obj.poll_for_system_status(vars.D1,iteration=5, delay=2):
        st.error("System is not in ready state")
        st.report_fail("test_case_failed")

    hdrMsg("STEP 9: Send lldp packets")
    tg.tg_traffic_control(action='run', stream_handle=[tg_stream_handle])
    st.wait(5,"Waiting for 5 secs after sending traffic")

    hdrMsg("STEP 10: Verify cpu counter for LLDP burst traffic with action group 1")
    dict1 = copp_obj.get_cpu_queue_counters(dut=vars.D1,queue_id=copp_queue,param="pkts_count")
    drop1 = int(dict1['pkts_count'])

    st.wait(5,"Waiting for 5 secs to collect another sample for action group1")
    dict1 = copp_obj.get_cpu_queue_counters(dut=vars.D1,queue_id=copp_queue,param="pkts_count")
    drop1_1 = int(dict1['pkts_count'])

    tolerance = (copp_cbs_lldp*12)/100
    if drop1_1 < (copp_cbs_lldp + tolerance) and drop1_1 > (copp_cbs_lldp - tolerance):
        st.log('CPU counter rate check for rate limiting LLDP to {} pps is passed'.format(copp_cbs_lldp))
    else:
        st.error('CPU counter rate check for rate limiting LLDP to {} pps is failed, count shown {}'.format(copp_cbs_lldp,drop1_1))

    count1 = copp_obj.get_show_c_cpuq_counter(vars.D1,queue=copp_queue)
    if count1 < (copp_cbs_lldp + tolerance) and count1 > (copp_cbs_lldp - tolerance):
        st.log('show c count check for rate limiting LLDP to {} pps is passed'.format(copp_cbs_lldp))
    else:
        st.error('show c count check for rate limiting LLDP to {} pps is failed, count shown {}'.format(copp_cbs_lldp,count1))

    hdrMsg("STEP 11: Remove CoPP user class and action group 1 binding to syetem copp policy")
    copp_obj.bind_class_action_copp_policy(vars.D1,classifier="copp-user-lldp",action_group="copp-user-lldp-action",config="no")

    hdrMsg("STEP 12: Applied LLDP user CoPP class and user CoPP action group 2 to default CoPP Policy")
    copp_obj.bind_class_action_copp_policy(vars.D1,classifier="copp-user-lldp",action_group="copp-user-lldp-action1")

    st.wait(5,"waiting for 5 sec before new class comes to effect")
    copp_cbs_lldp = copp_obj.get_copp_applied_policy_param(dut=vars.D1,copp_fgroup="copp-user-lldp",param="cbs")
    copp_queue = copp_obj.get_copp_applied_policy_param(dut=vars.D1,copp_fgroup="copp-user-lldp",param="trap_queue")

    hdrMsg("STEP 13: Send lldp packets")
    tg.tg_traffic_control(action='stop', stream_handle=[tg_stream_handle])
    copp_obj.clear_cpu_queue_counters(vars.D1)

    tg.tg_traffic_control(action='run', stream_handle=[tg_stream_handle])
    st.wait(15,"Waiting for 15 secs after sending traffic")

    hdrMsg("STEP 14: Verify cpu counter for LLDP burst traffic with action group 2")
    dict2 = copp_obj.get_cpu_queue_counters(dut=vars.D1,queue_id=copp_queue,param="pkts_count")
    drop2 = int(dict2['pkts_count'])

    st.wait(5,"Waiting for 5 secs to collect another sample for action group 2")
    dict2 = copp_obj.get_cpu_queue_counters(dut=vars.D1,queue_id=copp_queue,param="pkts_count")
    drop2_1 = int(dict2['pkts_count'])

    hdrMsg("STEP 15: Verify LLDP burst bytes count should increase as CBS rate limit is increased from 1250 PPS to 1850 PPS")
    if drop2 > drop1:
        st.log('PASS: LLDP bursty traffic allowed bytes increased as expected from {} PPS to {} PPS'.format(drop1,drop2))
    else:
        st.error('FAIL: LLDP bursty traffic allowed bytes not increased as expected from {} PPS to {} PPS'.format(drop1,drop2))
        success = False

    if drop2_1 > drop1_1:
        st.log('PASS: LLDP bursty traffic allowed bytes increased as expected from {} PPS to {} PPS'.format(drop1_1,drop2_1))
    else:
        st.error('FAIL: LLDP bursty traffic allowed bytes not increased as expected from {} PPS to {} PPS'.format(drop1_1,drop2_1))
        success = False

    tolerance = (1850*10)/100
    if drop2 < (1850 + tolerance) and drop2 > (1850 - tolerance):
        st.log('CPU counter rate check for rate limiting LLDP to {} pps is passed'.format("1850"))
    else:
        st.error('CPU counter rate check for rate limiting LLDP to {} pps is failed, count shown {}'.format("1850",drop2))

    count2 = copp_obj.get_show_c_cpuq_counter(vars.D1,queue=copp_queue)
    if count2 < (copp_cbs_lldp + tolerance) and count2 > (copp_cbs_lldp - tolerance):
        st.log('show c count check for rate limiting LLDP to {} pps is passed'.format(copp_cbs_lldp))
    else:
        st.error('show c count check for rate limiting LLDP to {} pps is failed, count shown {}'.format(copp_cbs_lldp,count2))
        success = False

    stop_traffic_dump_debug(tg_stream_handle,success)

    hdrMsg("STEP 16: Remove CoPP user class and action binding to syetem copp policy")
    copp_obj.bind_class_action_copp_policy(vars.D1,classifier="copp-user-lldp",action_group="copp-user-lldp-action1",config="no")

    hdrMsg("STEP 17: Remove CoPP user class and action group binding")
    copp_obj.config_copp_action_group(vars.D1,copp_action_group="copp-user-lldp-action",trap_queue="10",cir="1250",cbs="1250",config="no")
    copp_obj.config_copp_action_group(vars.D1,copp_action_group="copp-user-lldp-action1",trap_queue="11",cir="1850",cbs="1850",config="no")
    copp_obj.config_copp_classifier(vars.D1,classifier_name="copp-user-lldp",protocol_trap_id=["lldp"],config="no")

    hdrMsg("STEP 18: Apply default CoPP LLDP class and action group binding to syetem copp policy")
    copp_obj.bind_class_action_copp_policy(vars.D1,classifier="copp-system-lldp",action_group="copp-system-lldp")

    hdrMsg("STEP 19: Restoring the queue shaper value to default value for queues 10 and 11 ")
    shaper_data = {'policy_name': "copp-scheduler-policy", 'shaper_data': [{'queue': "10", 'pir':queue1, 'meter_type': 'bytes'}, \
                   {'queue': "11", 'pir':queue2, 'meter_type': 'bytes'}]}
    if not shaper.apply_queue_shaping_config(vars.D1, shaper_data):
        st.log("Restoring the queue shaper value to default value failed for queues 10 and 11")

    if success:
        st.report_pass("test_case_passed","Copp323_2")
    else:
        st.report_fail("test_case_failed","Copp323_2")

@pytest.mark.copp_mgmt
def test_cli_copp_classifiers():
    success = True
    hdrMsg("TestCase Copp311: Verify default global CoPP classifiers using the CLI show classifier match-type copp")

    dict = {"copp-system-arp": ["arp_req","arp_resp","neigh_discovery"]}
    dict["copp-system-bfd"] = ["bfd","bfdv6"]
    dict["copp-system-bgp"] = ["bgp","bgpv6"]
    dict["copp-system-dhcp"] = ["dhcp","dhcpv6"]
    dict["copp-system-iccp"] = ["iccp"]
    dict["copp-system-icmp"] = ["icmp","icmpv6"]
    dict["copp-system-igmp"] = ["igmp_query"]
    dict["copp-system-ip2me"] = ["ip2me"]
    dict["copp-system-lacp"] = ["lacp"]
    dict["copp-system-lldp"] = ["lldp"]

    hdrMsg("STEP 1: Verifying default global CoPP classifiers and its associated match protocol one by one")
    for classif in dict:
        for proto in dict[classif]:
            no_of_proto = len(dict[classif])
            if copp_obj.verify_classifier_match_type_copp(dut=vars.D1,copp_class=[classif]*no_of_proto,protocol=dict[classif]):
                st.log("PASS: classfier {} and match protocol {} found".format(classif,proto))
            else:
                st.log("FAIL: classfier {} and match protocol {} NOT found".format(classif,proto))
                success = False

    if not success:
        hdrMsg("Test case Fails so dumping debug commands")
        copp_obj.debug_copp_config(vars.D1)

    if success:
        st.report_pass("test_case_passed","Copp311")
    else:
        st.report_fail("test_case_failed","Copp311")


@pytest.mark.copp_mgmt
def test_cli_copp_protocols():
    success = True
    hdrMsg("TestCase Copp3110: Verify default global CoPP protocols using CLI show copp protocols")

    # "igmp_leave","igmp_v1_report" and "eapol" protocols are not supported in SAI
    list1 = ["stp","lacp","lldp","pvrst","igmp_query","iccp","ip2me","arp_req","arp_resp"]

    hdrMsg("STEP 1: Verifying default global CoPP classifier based match protocols one by one")
    if copp_obj.verify_copp_protocols(dut=vars.D1,protocol=list1):
        st.log("PASS: classfier match protocols found")
    else:
        st.log("FAIL: classfier match protocols NOT found")
        success = False

    if not success:
        hdrMsg("Test case Fails so dumping debug commands")
        copp_obj.debug_copp_config(vars.D1)

    if success:
        st.report_pass("test_case_passed","Copp3110")
    else:
        st.report_fail("test_case_failed","Copp3110")

@pytest.mark.copp_mgmt
def test_cli_copp_actions():
    success = True
    hdrMsg("TestCase Copp3111: Verify default global CoPP action groups using CLI show copp actions")

    dict = {}
    dict["action_group"] = "copp-system-arp"
    dict["trap_action"] = "copy"
    dict["trap_priority"] = "10"
    dict["trap_queue"] = "10"
    dict["cir"] = "3000"
    dict["cbs"] = "3000"
    dict["meter_type"] = "packets"
    dict["meter_mode"] = "sr_tcm"
    dict["red_action"] = "drop"

    hdrMsg("STEP 1: Verifying default global CoPP action groups")
    if copp_obj.verify_copp_actions(dut=vars.D1,copp_agroup=dict["action_group"],trap_action=dict["trap_action"],
            trap_priority=dict["trap_priority"],trap_queue=dict["trap_queue"],cir=dict["cir"],cbs=dict["cbs"],
            meter_type=dict["meter_type"],policer_mode=dict["meter_mode"],pol_red_action=dict["red_action"]):
        st.log("PASS: global CoPP action groups found")
    else:
        st.log("FAIL: global CoPP action groups NOT found")
        success = False

    if not success:
        hdrMsg("Test case Fails so dumping debug commands")
        copp_obj.debug_copp_config(vars.D1)

    if success:
        st.report_pass("test_case_passed","Copp3111")
    else:
        st.report_fail("test_case_failed","Copp3111")

@pytest.mark.copp_mgmt
def test_cli_policy_type_copp():
    success = True
    hdrMsg("TestCase Copp3112: Verify default global system CoPP policy using CLI show policy type copp")

    dict = {}
    dict["flow_group"] = "copp-system-arp"
    dict["action_group"] = "copp-system-arp"
    dict["trap_action"] = "copy"
    dict["trap_priority"] = "10"
    dict["trap_queue"] = "10"
    dict["cir"] = "3000"
    dict["cbs"] = "3000"
    dict["meter_type"] = "packets"
    dict["meter_mode"] = "sr_tcm"
    dict["red_action"] = "drop"

    hdrMsg("STEP 1: Verifying default global system CoPP policy")
    if copp_obj.verify_policy_type_copp(dut=vars.D1,copp_agroup=dict["action_group"],trap_action=dict["trap_action"],
            trap_priority=dict["trap_priority"],trap_queue=dict["trap_queue"],cir=dict["cir"],cbs=dict["cbs"],
            meter_type=dict["meter_type"],policer_mode=dict["meter_mode"],pol_red_action=dict["red_action"],
            copp_fgroup=dict["flow_group"]):
        st.log("PASS: default global system CoPP policy found")
    else:
        st.log("FAIL: default global system CoPP policy match failed")
        success = False

    if not success:
        hdrMsg("Test case Fails so dumping debug commands")
        copp_obj.debug_copp_config(vars.D1)

    if success:
        st.report_pass("test_case_passed","Copp3112")
    else:
        st.report_fail("test_case_failed","Copp3112")

@pytest.mark.copp_mgmt
def test_cli_copp_class():
    success = True
    hdrMsg("TestCase Copp3113: Verify default copp classfiers using the CLI show copp classifiers")

    dict = {"copp-system-arp": ["arp_req","arp_resp","neigh_discovery"]}
    dict["copp-system-bfd"] = ["bfd","bfdv6"]
    dict["copp-system-bgp"] = ["bgp","bgpv6"]
    dict["copp-system-dhcp"] = ["dhcp","dhcpv6"]

    hdrMsg("STEP 1: Verifying show copp classifiers CLI")
    for classif in dict:
        for proto in dict[classif]:
            no_of_proto = len(dict[classif])
            if copp_obj.verify_copp_classifiers(dut=vars.D1,copp_class=[classif]*no_of_proto,protocol=dict[classif]):
                st.log("PASS: show copp classfier {} and match protocol {} found".format(classif,proto))
            else:
                st.log("FAIL: show copp classfier {} and match protocol {} NOT found".format(classif,proto))
                success = False

    if not success:
        hdrMsg("Test case Fails so dumping debug commands")
        copp_obj.debug_copp_config(vars.D1)

    if success:
        st.report_pass("test_case_passed","Copp3113")
    else:
        st.report_fail("test_case_failed","Copp3113")

@pytest.mark.copp_mgmt
def test_cli_copp_policy():
    success = True
    hdrMsg("TestCase Copp3114: Verify the CLI show copp policy ")

    dict = {}
    dict["flow_group"] = "copp-system-arp"
    dict["action_group"] = "copp-system-arp"
    dict["trap_action"] = "copy"
    dict["trap_priority"] = "10"
    dict["trap_queue"] = "10"
    dict["cir"] = "3000"
    dict["cbs"] = "3000"
    dict["meter_type"] = "packets"
    dict["meter_mode"] = "sr_tcm"
    dict["red_action"] = "drop"

    hdrMsg("STEP 1: Verifying show copp policy CLI")
    if copp_obj.verify_copp_policy(dut=vars.D1,trap_action=dict["trap_action"],
            trap_priority=dict["trap_priority"],trap_queue=dict["trap_queue"],cir=dict["cir"],cbs=dict["cbs"],
            meter_type=dict["meter_type"],policer_mode=dict["meter_mode"],pol_red_action=dict["red_action"],
            copp_fgroup=dict["flow_group"]):
        st.log("PASS: default global system CoPP policy found through show copp policy CLI")
    else:
        st.log("FAIL: default global system CoPP policy or show copp policy CLI shows incorrect entry")
        success = False

    if not success:
        hdrMsg("Test case Fails so dumping debug commands")
        copp_obj.debug_copp_config(vars.D1)

    if success:
        st.report_pass("test_case_passed","Copp3114")
    else:
        st.report_fail("test_case_failed","Copp3114")

@pytest.mark.copp_mgmt
def test_ft_coppmgmt_subnet():
    success = True
    hdrMsg("TestCase Copp373: Verify CoPP functionality for subnet traffic")

    result = copp_obj.verify_qos_scheduler_policy(dut=vars.D1,queue="6",return_output="yes")
    queue1 = int(result['pir'])
    queue1 = (queue1*1000)/8

    hdrMsg("STEP 1: Changing the queue shaper value to support higher CoPP rate limit 3000 PPS for queues 6")
    shaper_data = {'policy_name': "copp-scheduler-policy", 'shaper_data': [{'queue': "6", 'pir': "375000", 'meter_type': 'bytes'}]}
    if not shaper.apply_queue_shaping_config(vars.D1, shaper_data):
        st.log("Config of the queue shaper value to support higher CoPP rate limit 3000 PPS PPS for queues 6 failed")
        success = False

    hdrMsg("STEP 2: Check the CoPP subnet class CIR and CPU queue")
    copp_cir_subnet, sent_rate_pps, deviation, copp_queue = get_cir_queue("copp-system-subnet")

    if not copp_obj.verify_qos_scheduler_policy(dut=vars.D1,queue="6",sch_policy_name="copp-scheduler-policy",pir="3000"):
        st.log("Change of the queue shaper value to support higher CoPP rate limit 3000 PPS for queues 6 FAILED")
        success = False

    hdrMsg("STEP 3: Configure ip address b/w D1 and D2 to send subnet packets")
    ip_obj.config_ip_addr_interface(dut=vars.D1, interface_name=d1d2_p1, ip_address='2.2.2.2', subnet='24')
    ip_obj.config_ip_addr_interface(dut=vars.D2, interface_name=d2d1_p1, ip_address='2.2.2.1', subnet='24')

    tg.tg_traffic_control(action='reset', port_handle=[tg_ph_1])

    hdrMsg('STEP 4: Sending subnet packets at {} pps and expecting rate limit to {} pps '.format(sent_rate_pps,copp_cir_subnet))
    tg_stream_handle = tg.tg_traffic_config(port_handle=tg_ph_1, mac_src="00:00:00:11:11:79", mac_dst=d1_p1_mac,
                         mode='create', transmit_mode='continuous', l2_encap='ethernet_ii',frame_size='128',
                         ip_src_addr='1.1.1.1',ip_dst_addr='2.2.2.10',l3_protocol='ipv4',l3_length='512',
                         mac_discovery_gw="1.1.1.2",rate_pps=sent_rate_pps)['stream_id']

    hdrMsg("STEP 5: Check the system status")
    if not basic_obj.poll_for_system_status(vars.D1,iteration=5, delay=2):
        st.error("System is not in ready state")
        st.report_fail("test_case_failed")

    hdrMsg("STEP 6: Send subnet packets")
    tg.tg_traffic_control(action='run', stream_handle=[tg_stream_handle])
    st.wait(5,"Waiting for 5 secs after sending traffic")

    hdrMsg("STEP 7: Verify cpu counter for subnet traffic packets")
    if not verify_counter_cpu_asic_bcm(dut=vars.D1, queue=copp_queue, value=copp_cir_subnet, tol=deviation):
        st.error('CPU counter check for rate limiting  subnet to {} pps is failed'.format(copp_cir_subnet))
        success = False

    hdrMsg("STEP 9: Verify cpu counter for subnet traffic using show CPU queue counters")
    tolerance = (copp_cir_subnet*10)/100
    if not copp_obj.verify_cpu_queue_pkt_rate(vars.D1,queue_id=copp_queue,exp_rate=copp_cir_subnet,tolerance=tolerance):
        st.error('CPU counter check for rate limiting subnet traffic to {} pps is failed'.format(copp_cir_subnet))

    stop_traffic_dump_debug(tg_stream_handle,success)

    ip_obj.delete_ip_interface(dut=vars.D1, interface_name=d1d2_p1, ip_address='2.2.2.2', subnet='24')
    ip_obj.delete_ip_interface(dut=vars.D2, interface_name=d2d1_p1, ip_address='2.2.2.1', subnet='24')

    hdrMsg("STEP 10: Restoring the queue shaper value to default value for queues 6 ")
    shaper_data = {'policy_name': "copp-scheduler-policy", 'shaper_data': [{'queue': "6", 'pir':queue1, 'meter_type': 'bytes'}]}
    if not shaper.apply_queue_shaping_config(vars.D1, shaper_data):
        st.log("Restoring the queue shaper value to default value failed for queues 6")

    if success:
        st.report_pass("test_case_passed","Copp373")
    else:
        st.report_fail("test_case_failed","Copp374")

@pytest.mark.copp_mgmt
def test_ft_coppmgmt_ip2me():
    success = True
    hdrMsg("TestCase Copp374: Verify CoPP functionality for IP2ME traffic")

    hdrMsg("STEP 1: Check the CoPP ip2me class CIR and CPU queue")
    copp_cir_ip2me, sent_rate_pps, deviation, copp_queue = get_cir_queue("copp-system-ip2me")

    hdrMsg("STEP 2: Configure ip address b/w D1 and D2 to send ip2me traffic")
    ip_obj.config_ip_addr_interface(dut=vars.D1, interface_name=d1_p2, ip_address='3.3.3.2', subnet='24')

    tg.tg_traffic_control(action='reset', port_handle=[tg_ph_1])
    tg.tg_traffic_control(action='reset', port_handle=[tg_ph_2])

    hdrMsg("STEP 3: Send ARP packet from other TG port")
    han = tg.tg_interface_config(port_handle=tg_ph_2, mode='config',intf_ip_addr='3.3.3.1',
                                 gateway="3.3.3.2", arp_send_req='1',
                                 gateway_step='0.0.0.0',intf_ip_addr_step='0.0.0.1', count=1,
                                 src_mac_addr='00:00:11:01:01:01')
    host1 = han["handle"]
    tg.tg_arp_control(handle=host1, arp_target='all')

    hdrMsg('STEP 4: Sending ip2me packets at {} pps and expecting rate limit to {} pps '.format(sent_rate_pps,copp_cir_ip2me))
    tg_stream_handle = tg.tg_traffic_config(port_handle=tg_ph_1, mac_src="00:00:00:11:11:79", mac_dst=d1_p1_mac,
                         mode='create', transmit_mode='continuous', l2_encap='ethernet_ii',frame_size='1000',
                         ip_src_addr='1.1.1.1',ip_dst_addr='3.3.3.2',l3_protocol='ipv4',l3_length='512',
                         mac_discovery_gw="1.1.1.2",rate_pps=sent_rate_pps)['stream_id']

    hdrMsg("STEP 5: Check the system status")
    if not basic_obj.poll_for_system_status(vars.D1,iteration=5, delay=2):
        st.error("System is not in ready state")
        st.report_fail("test_case_failed")

    hdrMsg("STEP 6: Send ip2me routing packets")
    tg.tg_traffic_control(action='run', stream_handle=[tg_stream_handle])
    st.wait(5,"Waiting for 5 secs after sending traffic")

    hdrMsg("STEP 7: Verify cpu counter for IP2ME traffic")
    if not verify_counter_cpu_asic_bcm(dut=vars.D1, queue=copp_queue, value=copp_cir_ip2me, tol=deviation):
        st.error('CPU counter check for rate limiting L3 MTU violation traffic to {} pps is failed'.format(copp_cir_ip2me))
        success = False

    hdrMsg("STEP 8: Verify cpu counter for IP2ME traffic using show CPU queue counters")
    tolerance = (copp_cir_ip2me*10)/100
    if not copp_obj.verify_cpu_queue_pkt_rate(vars.D1,queue_id=copp_queue,exp_rate=copp_cir_ip2me,tolerance=tolerance):
        st.error('CPU counter check for rate limiting L3 MTU violation traffic to {} pps is failed'.format(copp_cir_ip2me))

    stop_traffic_dump_debug(tg_stream_handle,success)

    ip_obj.delete_ip_interface(dut=vars.D1, interface_name=d1_p2, ip_address='3.3.3.2', subnet='24')

    if success:
        st.report_pass("test_case_passed","Copp374")
    else:
        st.report_fail("test_case_failed","Copp374")

@pytest.mark.copp_mgmt
def test_ft_coppmgmt_mtu():
    success = True
    hdrMsg("TestCase Copp375: Verify CoPP functionality for MTU traffic")

    hdrMsg("STEP 1: Check the CoPP L3 MTU class CIR and CPU queue")
    copp_cir_mtu, sent_rate_pps, deviation, copp_queue = get_cir_queue("copp-system-mtu")

    hdrMsg("STEP 2: Configure ip address b/w D1 and D2 to send mtu packets")
    ip_obj.config_ip_addr_interface(dut=vars.D1, interface_name=d1_p2, ip_address='3.3.3.2', subnet='24')
    intf.interface_properties_set(vars.D1,d1_p1,"mtu","4000",False,False)
    intf.interface_properties_set(vars.D1,d1_p2,"mtu","2000",False,False)

    tg.tg_traffic_control(action='reset', port_handle=[tg_ph_1])
    tg.tg_traffic_control(action='reset', port_handle=[tg_ph_2])

    hdrMsg("STEP 3: Send ARP request from dest TG port")
    han = tg.tg_interface_config(port_handle=tg_ph_2, mode='config',intf_ip_addr='3.3.3.1',
                                 gateway="3.3.3.2", arp_send_req='1',
                                 gateway_step='0.0.0.0',intf_ip_addr_step='0.0.0.1', count=1,
                                 src_mac_addr='00:00:11:01:01:01')
    host1 = han["handle"]
    tg.tg_arp_control(handle=host1, arp_target='all')

    hdrMsg('STEP 4: Sending L3 MTU packets at {} pps and expecting rate limit to {} pps '.format(sent_rate_pps,copp_cir_mtu))
    tg_stream_handle = tg.tg_traffic_config(port_handle=tg_ph_1, mac_src="00:00:00:11:11:79", mac_dst=d1_p1_mac,
                         mode='create', transmit_mode='continuous', l2_encap='ethernet_ii',frame_size='4010',
                         ip_src_addr='1.1.1.1',ip_dst_addr='3.3.3.1',l3_protocol='ipv4',l3_length='512',
                         mac_discovery_gw="1.1.1.2",rate_pps=sent_rate_pps)['stream_id']

    hdrMsg("STEP 5: Check the system status")
    if not basic_obj.poll_for_system_status(vars.D1,iteration=5, delay=2):
        st.error("System is not in ready state")
        st.report_fail("test_case_failed")

    hdrMsg("STEP 6: Send jumbo frame routing packets")
    tg.tg_traffic_control(action='run', stream_handle=[tg_stream_handle])
    st.wait(5,"Waiting for 5 secs after sending traffic")

    hdrMsg("STEP 7: Verify cpu counter for L3 MTU violation traffic")
    if not verify_counter_cpu_asic_bcm(dut=vars.D1, queue=copp_queue, value=copp_cir_mtu, tol=deviation):
        st.error('CPU counter check for rate limiting L3 MTU violation traffic to {} pps is failed'.format(copp_cir_mtu))
        success = False

    hdrMsg("STEP 8: Verify cpu counter for L3 MTU violation traffic using show CPU queue counters")
    tolerance = (copp_cir_mtu*10)/100
    if not copp_obj.verify_cpu_queue_pkt_rate(vars.D1,queue_id=copp_queue,exp_rate=copp_cir_mtu,tolerance=tolerance):
        st.error('CPU counter check for rate limiting L3 MTU violation traffic to {} pps is failed'.format(copp_cir_mtu))

    stop_traffic_dump_debug(tg_stream_handle,success)

    ip_obj.delete_ip_interface(dut=vars.D1, interface_name=d1_p2, ip_address='3.3.3.2', subnet='24')
    intf.interface_properties_set(vars.D1,d1_p1,"mtu","4000",False,True)
    intf.interface_properties_set(vars.D1,d1_p2,"mtu","2000",False,True)

    if success:
        st.report_pass("test_case_passed","Copp375")
    else:
        st.report_fail("test_case_failed","Copp375")

@pytest.mark.copp_mgmt
def test_ft_coppmgmt_suppress():
    success = True
    hdrMsg("TestCase Copp376: Verify COPP for suppress ARP and ND")

    hdrMsg("STEP 1: Un-configure the routing interface")
    ip_obj.delete_ip_interface(dut=vars.D1, interface_name=d1_p1, ip_address='1.1.1.2', subnet='24')

    Vlan.create_vlan(vars.D1,"450")
    Vlan.add_vlan_member(vars.D1,"450",d1_p1,True)
    sag.config_sag_mac(vars.D1,mac="00:00:00:04:01:03",config="add")
    sag.config_sag_mac(vars.D1,ip_type="ipv6",config="enable")
    sag.config_sag_ip(vars.D1,interface="Vlan450",gateway="1.1.1.10",mask="24",config="add")
    sag.config_sag_ip(vars.D1,interface="Vlan450",gateway="1000::10",mask="96",config="add")
    Evpn.neigh_suppress_config(vars.D1,"450",'yes',False)

    hdrMsg("STEP 1: Check the CoPP L3 MTU class CIR and CPU queue")
    copp_cir_suppress, sent_rate_pps, deviation, copp_queue = get_cir_queue("copp-system-suppress")

    hdrMsg('STEP 2: Sending ARP packets for {} pps and expecting rate limit to {} pps '.format(sent_rate_pps,copp_cir_suppress))
    tg.tg_traffic_control(action='reset', port_handle=[tg_ph_1])
    tg_stream_handle = tg.tg_traffic_config(port_handle=[tg_ph_1], mac_src="00:00:00:11:11:80", mac_dst="FF:FF:FF:FF:FF:FF",
                         mode='create', transmit_mode='continuous',rate_pps=sent_rate_pps, l2_encap='ethernet_ii_vlan',
                         l3_protocol='arp', arp_src_hw_addr="00:00:00:11:11:80", arp_dst_hw_addr="00:00:00:00:00:00",
                         vlan_id="450",vlan="enable",
                         arp_operation='arpRequest', ip_src_addr='1.1.1.1', ip_dst_addr='1.1.1.2')['stream_id']

    hdrMsg("STEP 3: Check the system status")
    if not basic_obj.poll_for_system_status(vars.D1,iteration=5, delay=2):
        st.error("System is not in ready state")
        st.report_fail("test_case_failed")

    hdrMsg("STEP 4: Send ARP request packets..")
    tg.tg_traffic_control(action='run', stream_handle=[tg_stream_handle])
    st.wait(5,"Waiting for 5 secs after sending traffic")

    hdrMsg("STEP 5: Verify cpu counter for ARP suppress packets")
    if not verify_counter_cpu_asic_bcm(dut=vars.D1, queue=copp_queue, value=copp_cir_suppress, tol=deviation):
        st.error('CPU counter check for rate limiting suppress arp to {} pps is failed'.format(copp_cir_suppress))
        success = False

    hdrMsg("STEP 6: Verify cpu counter for ARP packets using show CPU queue counters")
    tolerance = (copp_cir_suppress*10)/100
    if not copp_obj.verify_cpu_queue_pkt_rate(vars.D1,queue_id=copp_queue,exp_rate=copp_cir_suppress,tolerance=tolerance):
        st.error('CPU counter check for rate limiting ARP to {} pps is failed'.format(copp_cir_suppress))

    hdrMsg("STEP 7: Stopping the ARP traffic")
    tg.tg_traffic_control(action='stop', stream_handle=[tg_stream_handle])
    tg.tg_traffic_control(action='reset', port_handle=[tg_ph_1])

    if vars.tgen_list[0] == 'ixia-01':
        tg_stream_handle = tg.tg_traffic_config(port_handle=[tg_ph_1], mac_src="00:00:00:11:11:81", mac_dst="33:33:00:00:00:11",
                         mode='create', transmit_mode='continuous',rate_pps=sent_rate_pps, l2_encap='ethernet_ii_vlan',
                         l3_protocol='ipv6', vlan_id="450",vlan="enable",l4_protocol="icmp",icmp_type="135",
                         ipv6_src_addr='::', ipv6_dst_addr='FF02::1:FF00:11')['stream_id']
    elif vars.tgen_list[0] == 'stc-01':
        tg_stream_handle = tg.tg_traffic_config(port_handle=[tg_ph_1], mac_src="00:00:00:11:11:81", mac_dst="33:33:00:00:00:11",
                         mode='create', transmit_mode='continuous',rate_pps=sent_rate_pps, l2_encap='ethernet_ii_vlan',
                         l3_protocol='ipv6', vlan_id="450",vlan="enable",l4_protocol="icmpv6",icmpv6_type="135",
                         ipv6_src_addr='::', ipv6_dst_addr='FF02::1:FF00:11')['stream_id']

    tg.tg_traffic_control(action='run', stream_handle=[tg_stream_handle])

    hdrMsg("STEP 8: Verify cpu counter for ND suppress packets")
    if not verify_counter_cpu_asic_bcm(dut=vars.D1, queue=copp_queue, value=copp_cir_suppress, tol=deviation):
        st.error('CPU counter check for rate limiting suppress arp to {} pps is failed'.format(copp_cir_suppress))
        success = False

    hdrMsg("STEP 9: Verify cpu counter for ND packets using show CPU queue counters")
    if not copp_obj.verify_cpu_queue_pkt_rate(vars.D1,queue_id=copp_queue,exp_rate=copp_cir_suppress,tolerance=tolerance):
        st.error('CPU counter check for rate limiting ND to {} pps is failed'.format(copp_cir_suppress))

    stop_traffic_dump_debug(tg_stream_handle,success)

    hdrMsg("STEP 10: Remove SAG and neighbor suppression config at the end of test case")
    Evpn.neigh_suppress_config(vars.D1,"450",'no',False)
    sag.config_sag_mac(vars.D1,ip_type="ipv6",config="disable")
    sag.config_sag_mac(vars.D1,mac="00:00:00:04:01:03",config="remove")
    sag.config_sag_ip(vars.D1,interface="Vlan450",gateway="1.1.1.10",mask="24",config="remove")
    sag.config_sag_ip(vars.D1,interface="Vlan450",gateway="1000::10",mask="96",config="remove")
    Vlan.delete_vlan_member(vars.D1,"450",d1_p1,True)
    Vlan.delete_vlan(vars.D1,"450")
    ip_obj.config_ip_addr_interface(dut=vars.D1, interface_name=d1_p1, ip_address='1.1.1.2', subnet='24')

    if success:
        st.report_pass("test_case_passed","Copp376")
    else:
        st.report_fail("test_case_failed","Copp376")

@pytest.mark.copp_mgmt
def test_ft_coppmgmt_lacp_igmp():
    success = True
    hdrMsg("TestCase Copp322: Verify default lacp class and igmp class having same trap queue and CIR")

    hdrMsg("STEP 1: Remove default LACP CoPP class from default CoPP Policy")
    copp_obj.bind_class_action_copp_policy(vars.D1,classifier="copp-system-lacp",action_group="copp-system-lacp",config="no")

    hdrMsg("STEP 2: Applied IGMP user CoPP class and user CoPP action group to default LACP CoPP Policy")
    copp_obj.bind_class_action_copp_policy(vars.D1,classifier="copp-system-lacp",action_group="copp-system-igmp")

    hdrMsg("STEP 3: Verify the LACP action related CIR and Queue ID")
    copp_cir_lacp = copp_obj.get_copp_applied_policy_param(dut=vars.D1,copp_fgroup="copp-system-lacp",param="cir")
    copp_queue_lacp = copp_obj.get_copp_applied_policy_param(dut=vars.D1,copp_fgroup="copp-system-igmp",param="trap_queue")

    hdrMsg("STEP 4: Verify the IGMP action related CIR and Queue ID")
    copp_cir_igmp, sent_rate_pps, deviation, copp_queue = get_cir_queue("copp-system-igmp")

    hdrMsg("STEP 5: Verify the LACP flow group related CIR same as IGMP flow group CIR")
    if copp_cir_lacp == copp_cir_igmp:
        st.log("PASS: CoPP LACP class has got the IGMP copp action related CIR after assigning the IGMP action to LACP class")
    else:
        st.log("FAIL: CoPP LACP class has NOT got the IGMP copp action related CIR even after assigning the IGMP action to LACP class")

    hdrMsg("STEP 6: Verify the LACP flow group related queue ID same as IGMP flow group queue ID")
    if copp_queue_lacp == copp_queue:
        st.log("PASS: CoPP LACP class has got the IGMP copp action queue ID after assigning the IGMP action to LACP class")
    else:
        st.log("FAIL: CoPP LACP class has NOT got the IGMP copp action queue ID even after assigning the IGMP action to LACP class")

    tg.tg_traffic_control(action='reset', port_handle=[tg_ph_1])
    hdrMsg('STEP 7: Sending lacp packets for {} pps and expecting rate limit to {} pps '.format(sent_rate_pps,copp_cir_igmp))

    tg_stream_handle = tg.tg_traffic_config(port_handle=tg_ph_1, mac_src="D8:C4:97:72:73:5F", mac_dst="01:80:C2:00:00:02",
                         mode='create', transmit_mode='continuous', data_pattern_mode='fixed',l2_encap='ethernet_ii',
                         data_pattern='01 01 01 14 FF FF D8 C4 97 72 73 5F 00 07 00 FF 00 20 85 00 00 00 02 14 00 00 '
                                      '00 00 00 00 00 00 00 00 00 00 00 00 02 00 00 00 03 10 00 00 00 00 00 00 00 00 '
                                      '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                                      '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                                      '00 00 00 00 00 00', ethernet_value='8809', rate_pps=sent_rate_pps)['stream_id']

    hdrMsg("STEP 8: Check the system status")
    if not basic_obj.poll_for_system_status(vars.D1,iteration=5, delay=2):
        st.error("System is not in ready state")
        st.report_fail("test_case_failed")

    hdrMsg("STEP 9: Send lacp request")
    tg.tg_traffic_control(action='run', stream_handle=[tg_stream_handle])
    st.wait(5,"Waiting for 5 secs after sending traffic")

    hdrMsg("STEP 10: Verify cpu counter for lacp packets")
    if not verify_counter_cpu_asic_bcm(dut=vars.D1, queue=copp_queue, value=copp_cir_lacp, tol=deviation):
        st.error('CPU counter check for rate limiting  lacp to {} pps is failed'.format(copp_cir_lacp))
        success = False

    hdrMsg("STEP 11: Stopping the LACP traffic")
    tg.tg_traffic_control(action='stop', stream_handle=[tg_stream_handle])

    ip_obj.delete_ip_interface(dut=vars.D1, interface_name=d1_p1, ip_address='1.1.1.2', subnet='24')
    Vlan.create_vlan(vars.D1,"3188")
    Vlan.add_vlan_member(vars.D1,"3188",d1_p1,True)
    ip_obj.config_ip_addr_interface(dut=vars.D1, interface_name="Vlan3188", ip_address='1.1.1.2', subnet='24')

    tg.tg_traffic_control(action='reset', port_handle=[tg_ph_1])
    hdrMsg('STEP 12: Sending igmp packets for {} pps and expecting rate limit to {} pps '.format(sent_rate_pps, copp_cir_igmp))

    tg_stream_handle = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create', transmit_mode='continuous',
                         length_mode='fixed', rate_pps=sent_rate_pps, mac_src='00:01:05:00:1A:00',
                         mac_dst='01:00:5e:01:01:02', ethernet_value='8100',
                         data_pattern_mode='fixed', l2_encap='ethernet_ii',
                         data_pattern='0C 74 08 00 46 00 00 20 00 00 00 00 01 02 2D CA 15 01 01 '
                                      '0A E0 01 01 02 94 04 00 00 16 64 08 98 E0 01 01 02 00 01 '
                                      '02 03 04 05 06 07 08 09 0A 0B 0C 0D 99 2C 9E 39')['stream_id']
    hdrMsg("STEP 13: Send igmp query packet and verify cpu counter")
    tg.tg_traffic_control(action='run', stream_handle=[tg_stream_handle])
    st.wait(5,"Waiting for 5 secs after sending traffic")
    if not verify_counter_cpu_asic_bcm(dut=vars.D1, queue=copp_queue, value=copp_cir_igmp, tol=deviation):
        st.error('CPU counter check for rate limiting igmp to {} pps is failed'.format(copp_cir_igmp))
        success = False

    stop_traffic_dump_debug(tg_stream_handle,success)

    hdrMsg("STEP 15: Remove default LACP CoPP class from default CoPP Policy")
    copp_obj.bind_class_action_copp_policy(vars.D1,classifier="copp-system-lacp",action_group="copp-system-igmp",config="no")

    hdrMsg("STEP 16: Applied IGMP user CoPP class and user CoPP action group to default LACP CoPP Policy")
    copp_obj.bind_class_action_copp_policy(vars.D1,classifier="copp-system-lacp",action_group="copp-system-lacp")

    ip_obj.delete_ip_interface(dut=vars.D1, interface_name="Vlan3188", ip_address='1.1.1.2', subnet='24')
    Vlan.delete_vlan_member(vars.D1,"3188",d1_p1,True)
    Vlan.delete_vlan(vars.D1,"3188")
    ip_obj.config_ip_addr_interface(dut=vars.D1, interface_name=d1_p1, ip_address='1.1.1.2', subnet='24')

    if success:
        st.report_pass("test_case_passed","Copp322")
    else:
        st.report_fail("test_case_failed","Copp322")

@pytest.mark.copp_mgmt
def test_ft_ip2me_defaultQ():
    success = True
    hdrMsg("TestCase Copp328: Verify IP2ME traffic going to default CPU queue when the same class is removed from CoPP policy")

    hdrMsg("STEP 1: Remove default ip2me CoPP class from default CoPP Policy")
    copp_obj.bind_class_action_copp_policy(vars.D1,classifier="copp-system-ip2me",action_group="copp-system-ip2me",config="no")

    hdrMsg("STEP 2: Check the CoPP ip2me class CIR and CPU queue")
    action = copp_obj.verify_copp_actions(dut=vars.D1,copp_agroup="default",return_output="yes")
    copp_cir_ip2me = int(action["cir"])
    sent_rate_pps = copp_cir_ip2me * 2
    copp_queue= action['trap_queue']
    deviation = copp_cir_ip2me * deviation_percentage

    hdrMsg("STEP 2: Verify the default CoPP class and actions using show policy type copp")
    res = copp_obj.verify_policy_type_copp(dut=vars.D1,copp_fgroup="default",copp_agroup="default",cir=copp_cir_ip2me,cbs=copp_cir_ip2me,trap_queue=copp_queue)
    if not res:
        st.log("STEP 5: FAIL User defined CIR, CBS do not show up in show policy type copp O/P")
        success = False

    hdrMsg("STEP 3: Configure ip address b/w D1 and D2 to send ip2me traffic")
    ip_obj.config_ip_addr_interface(dut=vars.D1, interface_name=d1_p2, ip_address='3.3.3.2', subnet='24')

    tg.tg_traffic_control(action='reset', port_handle=[tg_ph_1])
    tg.tg_traffic_control(action='reset', port_handle=[tg_ph_2])

    hdrMsg("STEP 4: Send ARP packet from other TG port")
    han = tg.tg_interface_config(port_handle=tg_ph_2, mode='config',intf_ip_addr='3.3.3.1',
                                 gateway="3.3.3.2", arp_send_req='1',
                                 gateway_step='0.0.0.0',intf_ip_addr_step='0.0.0.1', count=1,
                                 src_mac_addr='00:00:11:01:01:01')
    host1 = han["handle"]
    tg.tg_arp_control(handle=host1, arp_target='all')

    hdrMsg('STEP 5: Sending ip2me packets at {} pps and expecting rate limit to {} pps '.format(sent_rate_pps,copp_cir_ip2me))
    tg_stream_handle = tg.tg_traffic_config(port_handle=tg_ph_1, mac_src="00:00:00:11:11:79", mac_dst=d1_p1_mac,
                         mode='create', transmit_mode='continuous', l2_encap='ethernet_ii',frame_size='1000',
                         ip_src_addr='1.1.1.1',ip_dst_addr='3.3.3.2',l3_protocol='ipv4',l3_length='512',
                         mac_discovery_gw="1.1.1.2",rate_pps=sent_rate_pps)['stream_id']

    hdrMsg("STEP 6: Check the system status")
    if not basic_obj.poll_for_system_status(vars.D1,iteration=5, delay=2):
        st.error("System is not in ready state")
        st.report_fail("test_case_failed")

    hdrMsg("STEP 7: Send ip2me routing packets")
    tg.tg_traffic_control(action='run', stream_handle=[tg_stream_handle])
    st.wait(5,"Waiting for 5 secs after sending traffic")

    hdrMsg("STEP 8: Verify cpu counter for IP2ME traffic")
    if not verify_counter_cpu_asic_bcm(dut=vars.D1, queue=copp_queue, value=copp_cir_ip2me, tol=deviation):
        st.error('CPU counter check for rate limiting L3 MTU violation traffic to {} pps is failed'.format(copp_cir_ip2me))
        success = False

    hdrMsg("STEP 9: Verify cpu counter for IP2ME traffic using show CPU queue counters")
    tolerance = (copp_cir_ip2me*10)/100
    if not copp_obj.verify_cpu_queue_pkt_rate(vars.D1,queue_id=copp_queue,exp_rate=copp_cir_ip2me,tolerance=tolerance):
        st.error('CPU counter check for rate limiting L3 MTU violation traffic to {} pps is failed'.format(copp_cir_ip2me))

    stop_traffic_dump_debug(tg_stream_handle,success)

    hdrMsg("STEP 11: Add back the ip2me CoPP class to default CoPP Policy to restore base line config")
    copp_obj.bind_class_action_copp_policy(vars.D1,classifier="copp-system-ip2me",action_group="copp-system-ip2me")

    ip_obj.delete_ip_interface(dut=vars.D1, interface_name=d1_p2, ip_address='3.3.3.2', subnet='24')

    if success:
        st.report_pass("test_case_passed","Copp328")
    else:
        st.report_fail("test_case_failed","Copp328")

@pytest.mark.copp_mgmt
def test_ft_single_class_multi_protocol():
    success = True
    hdrMsg("TestCase Copp321: Verify CoPP single user defined class matching LACP and IGMP protocol traffic")

    hdrMsg("STEP 1: Remove default CoPP lacp and igmp class from default CoPP Policy")
    copp_obj.bind_class_action_copp_policy(vars.D1,classifier="copp-system-lacp",action_group="copp-system-lacp",config="no")
    copp_obj.bind_class_action_copp_policy(vars.D1,classifier="copp-system-igmp",action_group="copp-system-igmp",config="no")

    hdrMsg("STEP 2: Create LACP & IGMP user CoPP class and user CoPP action groups to be applied to default CoPP Policy")
    copp_obj.config_copp_classifier(vars.D1,classifier_name="copp-user-class",protocol_trap_id=["lacp"])
    copp_obj.config_copp_classifier(vars.D1,classifier_name="copp-user-class",protocol_trap_id=["igmp_query"])
    copp_obj.config_copp_action_group(vars.D1,copp_action_group="copp-user-action",trap_queue="14",cir="5000", \
        trap_priority="14",cbs="5000",trap_action="trap")

    hdrMsg("STEP 3: Applied LLDP user CoPP class and user CoPP action group to default CoPP Policy")
    copp_obj.bind_class_action_copp_policy(vars.D1,classifier="copp-user-class",action_group="copp-user-action")

    # There is a SW defect for STEP 4 so skiping for now
    #hdrMsg("STEP 4: Verify user CoPP class matching protocol as LACP and IGMP")
    #copp_obj.verify_copp_classifiers(dut=vars.D2,copp_class=["copp_user_class","copp_user_class"],protocol=["lacp","igmp_query"])

    hdrMsg("STEP 5: Verify user CoPP class action group bindings to system CoPP Policy and policer attributes")
    res = copp_obj.verify_policy_type_copp(dut=vars.D1,copp_fgroup="copp-user-class",copp_agroup="copp-user-action",cir="5000",cbs="5000",trap_queue="14")
    if not res:
        st.log("STEP 5: FAIL User defined CIR, CBS do not show up in show policy type copp O/P")
        success = False

    hdrMsg("STEP 6: Check the CoPP user class CIR and CPU queue")
    copp_cir_lacp, sent_rate_pps, deviation, copp_queue = get_cir_queue("copp-user-class")

    tg.tg_traffic_control(action='reset', port_handle=[tg_ph_1])
    hdrMsg('STEP 7: Sending lacp packets for {} pps and expecting rate limit to {} pps '.format(sent_rate_pps,copp_cir_lacp))

    tg_stream_handle = tg.tg_traffic_config(port_handle=tg_ph_1, mac_src="D8:C4:97:72:73:5F", mac_dst="01:80:C2:00:00:02",
                         mode='create', transmit_mode='continuous', data_pattern_mode='fixed',l2_encap='ethernet_ii',
                         data_pattern='01 01 01 14 FF FF D8 C4 97 72 73 5F 00 07 00 FF 00 20 85 00 00 00 02 14 00 00 '
                                      '00 00 00 00 00 00 00 00 00 00 00 00 02 00 00 00 03 10 00 00 00 00 00 00 00 00 '
                                      '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                                      '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                                      '00 00 00 00 00 00', ethernet_value='8809', rate_pps=sent_rate_pps)['stream_id']

    hdrMsg("STEP 8: Check the system status")
    if not basic_obj.poll_for_system_status(vars.D1,iteration=5, delay=2):
        st.error("System is not in ready state")
        st.report_fail("test_case_failed")

    hdrMsg("STEP 9: Send lacp request")
    tg.tg_traffic_control(action='run', stream_handle=[tg_stream_handle])
    st.wait(5,"Waiting for 5 secs after sending traffic")

    hdrMsg("STEP 10: Verify cpu counter for LACP packets")
    if not verify_counter_cpu_asic_bcm(dut=vars.D1, queue=copp_queue, value=copp_cir_lacp, tol=deviation):
        st.error('CPU counter check for rate limiting  lacp to {} pps is failed'.format(copp_cir_lacp))
        success = False

    hdrMsg("STEP 11: Stopping the LACP packets")
    tg.tg_traffic_control(action='stop', stream_handle=[tg_stream_handle])

    ip_obj.delete_ip_interface(dut=vars.D1, interface_name=d1_p1, ip_address='1.1.1.2', subnet='24')
    Vlan.create_vlan(vars.D1,"3188")
    Vlan.add_vlan_member(vars.D1,"3188",d1_p1,True)
    ip_obj.config_ip_addr_interface(dut=vars.D1, interface_name="Vlan3188", ip_address='1.1.1.2', subnet='24')

    hdrMsg("STEP 12: Check the CoPP IGMP class CIR and CPU queue")
    copp_cir_igmp = copp_obj.get_copp_applied_policy_param(dut=vars.D1,copp_fgroup="copp-user-class",param="cir")
    sent_rate_pps = copp_cir_igmp * 2
    deviation = copp_cir_igmp * deviation_percentage
    copp_queue = copp_obj.get_copp_applied_policy_param(dut=vars.D1,copp_fgroup="copp-user-class",param="trap_queue")

    tg.tg_traffic_control(action='reset', port_handle=[tg_ph_1])
    hdrMsg('STEP 13: Sending igmp packets for {} pps and expecting rate limit to {} pps '.format(sent_rate_pps, copp_cir_igmp))

    tg_stream_handle = tg.tg_traffic_config(port_handle=tg_ph_1, mode='create', transmit_mode='continuous',
                         length_mode='fixed', rate_pps=sent_rate_pps, mac_src='00:01:05:00:1A:00',
                         mac_dst='01:00:5e:01:01:02', ethernet_value='8100',
                         data_pattern_mode='fixed', l2_encap='ethernet_ii',
                         data_pattern='0C 74 08 00 46 00 00 20 00 00 00 00 01 02 2D CA 15 01 01 '
                                      '0A E0 01 01 02 94 04 00 00 16 64 08 98 E0 01 01 02 00 01 '
                                      '02 03 04 05 06 07 08 09 0A 0B 0C 0D 99 2C 9E 39')['stream_id']

    hdrMsg("STEP 14: Send igmp query packet and verify cpu counter")
    tg.tg_traffic_control(action='run', stream_handle=[tg_stream_handle])
    st.wait(5,"Waiting for 5 secs after sending traffic")

    hdrMsg("STEP 15: Verify cpu counter for IGMP packets")
    if not verify_counter_cpu_asic_bcm(dut=vars.D1, queue=copp_queue, value=copp_cir_igmp, tol=deviation):
        st.error('CPU counter check for rate limiting igmp to {} pps is failed'.format(copp_cir_igmp))
        success = False

    stop_traffic_dump_debug(tg_stream_handle,success)

    hdrMsg("STEP 17: Remove user class binding to default CoPP Policy")
    copp_obj.bind_class_action_copp_policy(vars.D1,classifier="copp-user-class",action_group="copp-user-action",config="no")

    hdrMsg("STEP 18: Remove user action groups and user classes")
    copp_obj.config_copp_action_group(vars.D1,copp_action_group="copp-user-action",trap_queue="14",cir="5000",cbs="5000",trap_action="trap",config="no")
    copp_obj.config_copp_classifier(vars.D1,classifier_name="copp-user-class",protocol_trap_id=["lacp"],config="no")
    copp_obj.config_copp_classifier(vars.D1,classifier_name="copp-user-class",protocol_trap_id=["igmp"],config="no")

    hdrMsg("STEP 19: Apply the default class and action groups to the system CoPP policy")
    copp_obj.bind_class_action_copp_policy(vars.D1,classifier="copp-system-lacp",action_group="copp-system-lacp")
    copp_obj.bind_class_action_copp_policy(vars.D1,classifier="copp-system-igmp",action_group="copp-system-igmp")

    ip_obj.delete_ip_interface(dut=vars.D1, interface_name="Vlan3188", ip_address='1.1.1.2', subnet='24')
    Vlan.delete_vlan_member(vars.D1,"3188",d1_p1,True)
    Vlan.delete_vlan(vars.D1,"3188")
    ip_obj.config_ip_addr_interface(dut=vars.D1, interface_name=d1_p1, ip_address='1.1.1.2', subnet='24')

    if success:
        st.report_pass("test_case_passed","Copp321")
    else:
        st.report_fail("test_case_failed","Copp321")

@pytest.mark.copp_mgmt
def test_ft_coppmgmt_user_lldp():
    success = True
    hdrMsg("TestCase Copp377: Verify CoPP functionality for LLDP with user defined class and action")
    result = copp_obj.verify_qos_scheduler_policy(dut=vars.D1,queue="10",return_output="yes")
    queue1 = int(result['pir'])
    queue1 = (queue1*1000)/8

    hdrMsg("STEP 1: Changing the queue shaper value to support higher CoPP rate limit 5250 PPS & 5270 PPS for queues 10")
    shaper_data = {'policy_name': "copp-scheduler-policy", 'shaper_data': [{'queue': "10", 'pir': "687500", 'meter_type': 'bytes'}]}
    if not shaper.apply_queue_shaping_config(vars.D1, shaper_data):
        st.log("Config of the queue shaper value to support higher CoPP rate limit 5250 PPS and 5270 PPS for queues 10 failed")
        success = False

    hdrMsg("STEP 2: Remove default CoPP lldp class from default CoPP Policy")
    copp_obj.bind_class_action_copp_policy(vars.D1,classifier="copp-system-lldp",action_group="copp-system-lldp",config="no")

    if not copp_obj.verify_qos_scheduler_policy(dut=vars.D1,queue="10",sch_policy_name="copp-scheduler-policy",pir="5500"):
        st.log("Change of the queue shaper value to support higher CoPP rate limit 5496 PPS for queues 10 FAIL")
        success = False

    hdrMsg("STEP 3: Create LLDP user CoPP class and user CoPP action group to be applied to default CoPP Policy")
    copp_obj.config_copp_classifier(vars.D1,classifier_name="copp-user-lldp",protocol_trap_id=["lldp"])
    copp_obj.config_copp_action_group(vars.D1,copp_action_group="copp-user-lldp-action",trap_queue="10",cir="5250",cbs="5270",trap_action="trap")

    hdrMsg("STEP 4: Applied LLDP user CoPP class and user CoPP action group to default CoPP Policy")
    copp_obj.bind_class_action_copp_policy(vars.D1,classifier="copp-user-lldp",action_group="copp-user-lldp-action")

    hdrMsg("STEP 5: Verify LLDP user CoPP class and user CoPP action group binding to system CoPP Policy")
    res = copp_obj.verify_policy_type_copp(dut=vars.D1,copp_fgroup="copp-user-lldp",copp_agroup="copp-user-lldp-action", \
        cir="5250",cbs="5270",trap_queue="10",trap_action="trap")
    if not res:
        st.log("STEP 5: FAIL User defined CIR, CBS do not show up in show policy type copp O/P")
        success = False

    hdrMsg("STEP 6: Get the LLDP CIR and queue ID from show polciy type copp output")
    copp_cir_lldp, sent_rate_pps, deviation, copp_queue = get_cir_queue("copp-user-lldp")

    tg.tg_traffic_control(action='reset', port_handle=[tg_ph_1])

    hdrMsg('STEP 7: Sending lldp packets for {} pps and expecting rate limit to {} pps '.format(sent_rate_pps,copp_cir_lldp))
    tg_stream_handle = tg.tg_traffic_config(port_handle=tg_ph_1, mac_src="00:11:97:2F:8E:82", mac_dst="01:80:C2:00:00:0E",
                         mode='create', transmit_mode='continuous', l2_encap='ethernet_ii',
                         data_pattern='02 07 04 00 11 97 2F 8E 80 04 07 03 00 11 97 2F 8E 82 06 02 00 78 00 00 00 00 '
                                      '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
                         ethernet_value='88CC',rate_pps=sent_rate_pps)['stream_id']

    hdrMsg("STEP 8: Check the system status")
    if not basic_obj.poll_for_system_status(vars.D1,iteration=5, delay=2):
        st.error("System is not in ready state")
        st.report_fail("test_case_failed")

    hdrMsg("STEP 9: Send lldp packets")
    tg.tg_traffic_control(action='run', stream_handle=[tg_stream_handle])
    st.wait(5,"Waiting for 5 secs after sending traffic")

    hdrMsg("STEP 10: Verify cpu counter for LLDP packets")
    if not verify_counter_cpu_asic_bcm(dut=vars.D1, queue=copp_queue, value=copp_cir_lldp, tol=deviation):
        st.error('CPU counter check for rate limiting  lldp to {} pps is failed'.format(copp_cir_lldp))
        success = False

    hdrMsg("STEP 11: Verify cpu counter for LLDP packets using show CPU queue counters")
    tolerance = (copp_cir_lldp*10)/100
    if not copp_obj.verify_cpu_queue_pkt_rate(vars.D1,queue_id=copp_queue,exp_rate=copp_cir_lldp,tolerance=tolerance):
        st.error('CPU counter check for rate limiting LLDP to {} pps is failed'.format(copp_cir_lldp))

    stop_traffic_dump_debug(tg_stream_handle,success)

    hdrMsg("STEP 12: Remove CoPP user class and action binding to syetem copp policy")
    copp_obj.bind_class_action_copp_policy(vars.D1,classifier="copp-user-lldp",action_group="copp-user-lldp-action",config="no")

    hdrMsg("STEP 13: Remove CoPP user class and action group binding")
    copp_obj.config_copp_action_group(vars.D1,copp_action_group="copp-user-lldp-action",trap_queue="10",cir="5250",cbs="5270",config="no")
    copp_obj.config_copp_classifier(vars.D1,classifier_name="copp-user-lldp",protocol_trap_id=["lldp"],config="no")

    hdrMsg("STEP 14: Apply the default class and action groups to the system CoPP policy")
    copp_obj.bind_class_action_copp_policy(vars.D1,classifier="copp-system-lldp",action_group="copp-system-lldp")

    hdrMsg("STEP 15: Restoring the queue shaper value to default value for queues 10 ")
    shaper_data = {'policy_name': "copp-scheduler-policy", 'shaper_data': [{'queue': "10", 'pir':queue1, 'meter_type': 'bytes'}]}
    if not shaper.apply_queue_shaping_config(vars.D1, shaper_data):
        st.log("Restoring the queue shaper value to default value failed for queues 10")

    if success:
        st.report_pass("test_case_passed","Copp377")
    else:
        st.report_fail("test_case_failed","Copp377")

@pytest.mark.copp_mgmt
def test_ft_change_policy():
    success = True
    hdrMsg("TestCase Copp327_2: Copp327,Copp329: Verify change of all flow group and action group inside default copp system policy")
    counter = 1;user_policy = []
    hdrMsg("STEP 1: Showing the default CoPP system policy flow group, action group and its attributes")
    for entry in policy:
        dict1 = {}
        st.log("Default Flow Group {} starts ======= :".format(counter))
        st.log("CoPP Flow group = {}, CoPP Action Group = {}, Trap Queue = {}, CIR = {}".format(entry['copp_fgroup'], \
            entry['copp_agroup'],entry['trap_queue'],entry['cir']))
        st.log("Default Flow Group {} ends   ======= :".format(counter))
        dict1['copp_fgroup'] = entry['copp_fgroup'].replace("system","user")
        dict1['copp_agroup'] = entry['copp_agroup'].replace("system","user")
        dict1['trap_queue'] = str(23 - int(entry['trap_queue']))
        if entry['copp_fgroup'] == "copp-system-dhcpl2":
            dict1['protocol'] = "dhcpl2"
        if "copp-system-" in entry['copp_agroup'] and entry['copp_fgroup'] != "copp-system-dhcpl2":
            dict1['protocol'] = entry['copp_agroup'].split("copp-system-")[1]
        elif "copp-user-" in entry['copp_agroup']:
            dict1['protocol'] = entry['copp_agroup'].split("copp-user-")[1]
        elif entry['copp_agroup'] == "default":
            dict1['protocol'] = "default"
        if (counter % 2) == 0:
            st.log("counter {} is even number so increased the CIR by 1000".format(counter))
            dict1['cir'] = int(entry['cir']) + 1000
            if int(entry['trap_queue']) > 23:
                dict1['trap_queue'] = int(dict1['trap_queue']) + 10
                dict1['trap_queue'] = str(dict1['trap_queue'])
        else:
            st.log("counter {} is odd number so decreased the CIR by 1000".format(counter))
            if int(entry['cir']) >= 1100:
                dict1['cir'] = int(entry['cir']) - 1000
            elif int(entry['cir']) < 1100 and int(entry['cir']) > 100:
                dict1['cir'] = int(entry['cir']) - 200
            elif int(entry['cir']) == 100:
                dict1['cir'] = int(entry['cir'])
            if int(entry['trap_queue']) > 23:
                dict1['trap_queue'] = int(dict1['trap_queue']) + 10
                dict1['trap_queue'] = str(dict1['trap_queue'])
        user_policy.append(dict1)
        counter += 1

    counter = 1
    hdrMsg("STEP 2: Showing the user defined CoPP system policy flow group, action group and its attributes")
    for entry in user_policy:
        st.log("======= User Flow Group {} starts ======= :".format(counter))
        st.log("CoPP Flow group = {}, CoPP Action Group = {}, Trap Queue = {}, CIR = {}".format(entry['copp_fgroup'],
            entry['copp_agroup'],entry['trap_queue'],entry['cir']))
        st.log("======= User Flow Group {} ends   ======= :".format(counter))
        counter += 1

    match_protocol = {}
    match_protocol = {"arp":"arp_req", "bfd":"bfdv6", "bgp":"bgp", "dhcp":"dhcp", "icmp":"icmpv6", "igmp":"igmp_query", "ip2me":"ip2me", \
                   "lacp":"lacp", "lldp":"lldp", "mtu":"l3_mtu_error", "nat":"src_nat_miss", "ospf":"ospf", "pim":"pim", "ptp":"ptp","iccp":"iccp", \
                   "sflow":"sample_packet", "stp":"pvrst", "subnet":"subnet", "suppress":"arp_suppress", "udld":"udld", "vrrp":"vrrp",
                   "dhcpl2":"dhcp_l2"}

    hdrMsg("STEP 3: Unbind the default CoPP class and bind user CoPP class for each protocol group")
    for entry,entry1 in zip(policy,user_policy):
        # adding of copp action group with matching protocol as subnet not yet supported so skipping it for now, need to add once support is added
        if entry1['protocol'] != "subnet" and entry1['protocol'] != "default":
            copp_obj.config_copp_classifier(vars.D1,classifier_name=entry1['copp_fgroup'],protocol_trap_id=[match_protocol[entry1['protocol']]])
            copp_obj.config_copp_action_group(vars.D1,copp_action_group=entry1['copp_agroup'],trap_queue=entry1['trap_queue'], \
                cir=entry1['cir'],cbs=entry1['cir'])
            copp_obj.bind_class_action_copp_policy(vars.D1,classifier=entry['copp_fgroup'],config="no")
            copp_obj.bind_class_action_copp_policy(vars.D1,classifier=entry1['copp_fgroup'],action_group=entry1['copp_agroup'])

    hdrMsg("STEP 4: Verify the changed CoPP Policy with user defined class and action group config")
    for entry1 in user_policy:
        result = copp_obj.verify_policy_type_copp(dut=vars.D1,copp_fgroup=entry1['copp_fgroup'],copp_agroup=entry1['copp_agroup'], \
            cir=entry1['cir'],cbs=entry1['cir'],trap_queue=entry1['trap_queue'])

    if result is False:
        success = False
        hdrMsg("STEP 5: Test case Fails so dumping debug commands")
        copp_obj.debug_copp_config(vars.D1)

    hdrMsg("STEP 6: Check the system status")
    if not basic_obj.poll_for_system_status(vars.D1,iteration=5, delay=2):
        st.error("System is not in ready state")
        st.report_fail("test_case_failed")

    hdrMsg("STEP 7: Unbind the default CoPP class and bind user CoPP clas for each protocol group")
    for entry,entry1 in zip(policy,user_policy):
        if entry1['protocol'] != "subnet" and entry1['protocol'] != "default":
            copp_obj.bind_class_action_copp_policy(vars.D1,classifier=entry1['copp_fgroup'],config="no")
            copp_obj.bind_class_action_copp_policy(vars.D1,classifier=entry['copp_fgroup'],action_group=entry['copp_agroup'])
            copp_obj.config_copp_action_group(vars.D1,copp_action_group=entry1['copp_agroup'],config="no")
            copp_obj.config_copp_classifier(vars.D1,classifier_name=entry1['copp_fgroup'],config="no")

    hdrMsg("STEP 8: Verify the default CoPP Policy after removing user defined class and action group config")
    for entry1 in policy:
        result = copp_obj.verify_policy_type_copp(dut=vars.D1,copp_fgroup=entry1['copp_fgroup'],copp_agroup=entry1['copp_agroup'], \
            cir=entry1['cir'],cbs=entry1['cir'],trap_queue=entry1['trap_queue'])

    if result is False:
        success = False
        hdrMsg("STEP 9: Test case Fails so dumping debug commands")
        copp_obj.debug_copp_config(vars.D1)

    hdrMsg("STEP 3: Check the system status")
    if not basic_obj.poll_for_system_status(vars.D1,iteration=5, delay=2):
        st.error("System is not in ready state")
        st.report_fail("test_case_failed")

    if success:
        st.report_pass("test_case_passed","Copp327_2")
    else:
        st.report_fail("test_case_failed","Copp327_2")

@pytest.mark.copp_mgmt
def test_ft_reboot_lldp():
    success = True
    hdrMsg("TestCase Copp343: Verify CoPP functionality for LLDP across system reboot")

    hdrMsg("STEP 1: Check the CoPP LLDP class CIR and CPU queue")
    copp_cir_lldp, sent_rate_pps, deviation, copp_queue = get_cir_queue("copp-system-lldp")

    tg.tg_traffic_control(action='reset', port_handle=[tg_ph_1])

    hdrMsg('STEP 2: Sending lldp packets for {} pps and expecting rate limit to {} pps '.format(sent_rate_pps,copp_cir_lldp))
    tg_stream_handle = tg.tg_traffic_config(port_handle=tg_ph_1, mac_src="00:11:97:2F:8E:82", mac_dst="01:80:C2:00:00:0E",
                         mode='create', transmit_mode='continuous', l2_encap='ethernet_ii',
                         data_pattern='02 07 04 00 11 97 2F 8E 80 04 07 03 00 11 97 2F 8E 82 06 02 00 78 00 00 00 00 '
                                      '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
                         ethernet_value='88CC',rate_pps=sent_rate_pps)['stream_id']


    hdrMsg("STEP 3: Check the system status")
    if not basic_obj.poll_for_system_status(vars.D1,iteration=5, delay=2):
        st.error("System is not in ready state")
        st.report_fail("test_case_failed")

    hdrMsg("STEP 4: Send lldp packets")
    tg.tg_traffic_control(action='run', stream_handle=[tg_stream_handle])
    st.wait(5,"Waiting for 5 secs after sending traffic")

    hdrMsg("STEP 5: Verify cpu counter for LLDP packets")
    if not verify_counter_cpu_asic_bcm(dut=vars.D1, queue=copp_queue, value=copp_cir_lldp, tol=deviation):
        st.error('CPU counter check for rate limiting  lldp to {} pps is failed'.format(copp_cir_lldp))
        success = False

    hdrMsg("STEP 6: Verify cpu counter for LLDP packets using show CPU queue counters")
    tolerance = (copp_cir_lldp*10)/100
    if not copp_obj.verify_cpu_queue_pkt_rate(vars.D1,queue_id=copp_queue,exp_rate=copp_cir_lldp,tolerance=tolerance):
        st.error('CPU counter check for rate limiting LLDP to {} pps is failed'.format(copp_cir_lldp))

    hdrMsg("STEP 7: Stopping the LLDP traffic")
    tg.tg_traffic_control(action='stop', stream_handle=[tg_stream_handle])

    if not success:
        hdrMsg("Test case Fails so dumping debug commands")
        copp_obj.debug_copp_config(vars.D1)

    hdrMsg("STEP 8: Save the DUT config before system reload")
    reboot.config_save(vars.D1)

    hdrMsg("STEP 9: Rerforming system reboot")
    st.reboot(vars.D1)

    if not basic_obj.poll_for_system_status(vars.D1):
        st.error("System is not in ready state")
        st.report_fail("test_case_failed")

    hdrMsg("STEP 10: Send lldp packets")
    tg.tg_traffic_control(action='run', stream_handle=[tg_stream_handle])
    st.wait(5,"Waiting for 5 secs after sending traffic")

    hdrMsg("STEP 11: Verify cpu counter for LLDP packets")
    if not verify_counter_cpu_asic_bcm(dut=vars.D1, queue=copp_queue, value=copp_cir_lldp, tol=deviation):
        st.error('CPU counter check for rate limiting  lldp to {} pps is failed'.format(copp_cir_lldp))
        success = False

    hdrMsg("STEP 12: Verify cpu counter for LLDP packets using show CPU queue counters")
    if not copp_obj.verify_cpu_queue_pkt_rate(vars.D1,queue_id=copp_queue,exp_rate=copp_cir_lldp,tolerance=tolerance):
        st.error('CPU counter check for rate limiting LLDP to {} pps is failed'.format(copp_cir_lldp))

    hdrMsg("STEP 13: Stopping the LLDP traffic")
    tg.tg_traffic_control(action='stop', stream_handle=[tg_stream_handle])

    if not success:
        hdrMsg("Test case Fails so dumping debug commands")
        copp_obj.debug_copp_config(vars.D1)

    if success:
        st.report_pass("test_case_passed","Copp343")
    else:
        st.report_fail("test_case_failed","Copp343")

@pytest.mark.copp_mgmt
def test_ft_swss_restart_lacp():
    success = True
    hdrMsg("TestCase Copp335: Verify CoPP functionality for LACP across swss docker restart")

    hdrMsg("STEP 1: Check the CoPP LACP class CIR and CPU queue")
    copp_cir_lacp, sent_rate_pps, deviation, copp_queue = get_cir_queue("copp-system-lacp")

    hdrMsg("STEP 2: Save the DUT config before swss docker restart")
    reboot.config_save(vars.D1)

    hdrMsg("STEP 3: Rerforming SwSS docker restart")
    basic_obj.service_operations_by_systemctl(vars.D1, 'swss', 'restart')

    hdrMsg("STEP 4: Check the system status")
    if not basic_obj.poll_for_system_status(vars.D1):
        st.error("System is not in ready state")
        st.report_fail("test_case_failed")

    tg.tg_traffic_control(action='reset', port_handle=[tg_ph_1])
    hdrMsg('STEP 5: Sending lacp packets for {} pps and expecting rate limit to {} pps '.format(sent_rate_pps,copp_cir_lacp))

    tg_stream_handle = tg.tg_traffic_config(port_handle=tg_ph_1, mac_src="D8:C4:97:72:73:5F", mac_dst="01:80:C2:00:00:02",
                         mode='create', transmit_mode='continuous', data_pattern_mode='fixed',l2_encap='ethernet_ii',
                         data_pattern='01 01 01 14 FF FF D8 C4 97 72 73 5F 00 07 00 FF 00 20 85 00 00 00 02 14 00 00 '
                                      '00 00 00 00 00 00 00 00 00 00 00 00 02 00 00 00 03 10 00 00 00 00 00 00 00 00 '
                                      '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                                      '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 '
                                      '00 00 00 00 00 00', ethernet_value='8809', rate_pps=sent_rate_pps)['stream_id']

    hdrMsg("STEP 6: Send lacp request")
    tg.tg_traffic_control(action='run', stream_handle=[tg_stream_handle])
    st.wait(5,"Waiting for 5 secs after sending traffic")

    hdrMsg("STEP 7: Verify cpu counter for LACP packets")
    if not verify_counter_cpu_asic_bcm(dut=vars.D1, queue=copp_queue, value=copp_cir_lacp, tol=deviation):
        st.error('CPU counter check for rate limiting  lacp to {} pps is failed'.format(copp_cir_lacp))
        success = False

    hdrMsg("STEP 8: Verify cpu counter for LACP packets using show CPU queue counters")
    tolerance = (copp_cir_lacp*10)/100
    if not copp_obj.verify_cpu_queue_pkt_rate(vars.D1,queue_id=copp_queue,exp_rate=copp_cir_lacp,tolerance=tolerance,from_pkts_count="yes"):
        st.error('CPU counter check for rate limiting LACP to {} pps is failed'.format(copp_cir_lacp))

    stop_traffic_dump_debug(tg_stream_handle,success)

    if success:
        st.report_pass("test_case_passed","Copp335")
    else:
        st.report_fail("test_case_failed","Copp335")

@pytest.mark.copp_mgmt
def test_ft_warm_reboot_dhcp():
    success = True
    hdrMsg("TestCase Copp341: Verify COPP for dhcp across system warm reboot")

    hdrMsg("STEP 1: Check the CoPP DHCP class CIR and CPU queue")
    copp_cir_dhcp, sent_rate_pps, deviation, copp_queue = get_cir_queue("copp-system-dhcp")

    hdrMsg("STEP 2: Save the DUT config before warm reboot")
    reboot.config_save(vars.D1)

    hdrMsg("STEP 3: Rerforming warm reboot now")
    st.reboot(vars.D1,'warm')

    tg.tg_traffic_control(action='reset', port_handle=[tg_ph_1])

    hdrMsg('STEP 4: Sending dhcp packets for {} pps and expecting rate limit to {} pps '.format(sent_rate_pps,copp_cir_dhcp))
    tg_stream_handle = tg.tg_traffic_config(port_handle=[tg_ph_1], mac_src="00:13:5F:1F:F2:80", mac_dst="33:33:00:01:00:02",
                         l3_protocol='ipv6', mode='create', transmit_mode='continuous',
                         rate_pps=sent_rate_pps, data_pattern='01 D1 49 5E 00 08 00 02 00 78 00 01 00 0A 00 03 00 01 00 13 '
                                                      '5F 1F F2 80 00 06 00 06 00 19 00 17 00 18 00 19 00 0C 00 33 '
                                                      '00 01 00 00 00 00 00 00 00 00', frame_size=116,
                         ipv6_dst_addr="FF02:0:0:0:0:0:1:2", ipv6_src_addr="FE80:0:0:0:201:5FF:FE00:500",
                         ipv6_next_header=17, ipv6_traffic_class=224,l4_protocol='udp',udp_dst_port=546,
                         udp_src_port=547, ipv6_hop_limit=255)['stream_id']


    hdrMsg("STEP 5: Check the system status")
    if not basic_obj.poll_for_system_status(vars.D1):
        st.error("System is not in ready state")
        st.report_fail("test_case_failed")

    hdrMsg("STEP 6: Send dhcpv6 solicit..")
    tg.tg_traffic_control(action='run', stream_handle=[tg_stream_handle])

    st.wait(5,"Waiting for 5 secs after sending traffic")

    hdrMsg("STEP 7: Verify cpu counter for DHCP packets")
    if not verify_counter_cpu_asic_bcm(dut=vars.D1, queue=copp_queue, value=copp_cir_dhcp, tol=deviation):
        st.error('CPU counter check for rate limiting  dhcp to {} pps is failed'.format(copp_cir_dhcp))
        success = False

    hdrMsg("STEP 8: Verify cpu counter for DHCP packets using show CPU queue counters")
    tolerance = (copp_cir_dhcp*10)/100
    if not copp_obj.verify_cpu_queue_pkt_rate(vars.D1,queue_id=copp_queue,exp_rate=copp_cir_dhcp,tolerance=tolerance,from_pkts_count="yes"):
        st.error('CPU counter check for rate limiting DHCP to {} pps is failed'.format(copp_cir_dhcp))

    stop_traffic_dump_debug(tg_stream_handle,success)

    if success:
        st.report_pass("test_case_passed","Copp341")
    else:
        st.report_fail("test_case_failed","Copp341")

@pytest.mark.copp_mgmt
def test_ft_fast_reboot_bgp():
    success = True
    hdrMsg("TestCase Copp342: Verify COPP for bgp across system fast reboot")

    hdrMsg("STEP 1: Check the CoPP BGP class CIR and CPU queue")
    copp_cir_bgp, sent_rate_pps, deviation, copp_queue = get_cir_queue("copp-system-bgp")

    hdrMsg("STEP 2: Save the DUT config before warm reboot")
    reboot.config_save(vars.D1)

    hdrMsg("STEP 3: Rerforming fast reboot now")
    st.reboot(vars.D1,'fast')

    hdrMsg('STEP 4: Sending bgp packets for {} pps and expecting rate limit to {} pps '.format(sent_rate_pps,copp_cir_bgp))
    tg.tg_traffic_control(action='reset', port_handle=[tg_ph_1])
    tg_stream_handle = tg.tg_traffic_config(port_handle=tg_ph_1, mac_src="E4:F0:04:38:07:DA", mac_dst=d1_p1_mac,
                         mode='create', transmit_mode='continuous',
                         data_pattern='FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF 00 2D 01 04 00 C8 00 5A 05 05 '
                                      '05 05 10 02 0E 01 04 00 01 00 01 02 00 41 04 00 00 00 C8',
                         rate_pps=sent_rate_pps, l3_protocol='ipv4', ip_protocol=6, ip_src_addr='1.1.1.1',
                         l4_protocol='tcp', ip_precedence=5, frame_size=103,
                         ip_dst_addr='1.1.1.2', tcp_dst_port=179, tcp_src_port=54821, tcp_window=115,
                         tcp_seq_num=1115372998, tcp_ack_num=1532875182,tcp_ack_flag=1, tcp_psh_flag=1, ip_ttl=1)['stream_id']

    hdrMsg("STEP 5: Check the system status")
    if not basic_obj.poll_for_system_status(vars.D1):
        st.error("System is not in ready state")
        st.report_fail("test_case_failed")

    hdrMsg("STEP 6: Send bgp open packets and verify cpu counter")
    tg.tg_traffic_control(action='run', stream_handle=[tg_stream_handle])
    st.wait(5,"Waiting for 5 secs after sending traffic")

    hdrMsg("STEP 7: Verify cpu counter for BGP packets")
    if not verify_counter_cpu_asic_bcm(dut=vars.D1,queue=copp_queue,value=copp_cir_bgp,tol=deviation):
        st.error('CPU counter check for rate limiting bgp to {} pps is failed'.format(copp_cir_bgp))
        success = False

    hdrMsg("STEP 8: Verify cpu counter for BGP packets using show CPU queue counters")
    tolerance = (copp_cir_bgp*10)/100
    if not copp_obj.verify_cpu_queue_pkt_rate(vars.D1,queue_id=copp_queue,exp_rate=copp_cir_bgp,tolerance=tolerance,from_pkts_count="yes"):
        st.error('CPU counter check for rate limiting BGP to {} pps is failed'.format(copp_cir_bgp))

    stop_traffic_dump_debug(tg_stream_handle,success)

    if success:
        st.report_pass("test_case_passed","Copp342")
    else:
        st.report_fail("test_case_failed","Copp342")

@pytest.mark.copp_mgmt
def test_ft_config_load_arp():
    success = True
    hdrMsg("TestCase Copp345: Verify COPP for arp traffic across config reload")

    hdrMsg("STEP 1: Check the CoPP ARP class CIR and CPU queue")
    copp_cir_arp, sent_rate_pps, deviation, copp_queue = get_cir_queue("copp-system-arp")

    hdrMsg("STEP 2: Save the DUT config before config reload")
    reboot.config_save(vars.D1)

    hdrMsg("STEP 3: Rerforming config reload now")
    reboot.config_reload(vars.D1)

    st.wait(5,"Waiting for 5 secs after config reload")

    hdrMsg('STEP 4: Sending ARP packets for {} pps and expecting rate limit to {} pps '.format(sent_rate_pps,copp_cir_arp))
    tg.tg_traffic_control(action='reset', port_handle=[tg_ph_1])
    tg_stream_handle = tg.tg_traffic_config(port_handle=[tg_ph_1], mac_src="00:00:00:11:11:80", mac_dst="FF:FF:FF:FF:FF:FF",
                         mode='create', transmit_mode='continuous',rate_pps=sent_rate_pps, l2_encap='ethernet_ii',
                         l3_protocol='arp', arp_src_hw_addr="00:00:00:11:11:80", arp_dst_hw_addr="00:00:00:00:00:00",
                         arp_operation='arpRequest', ip_src_addr='1.1.1.1', ip_dst_addr='1.1.1.2')['stream_id']


    hdrMsg("STEP 5: Check the system status")
    if not basic_obj.poll_for_system_status(vars.D1,iteration=5, delay=2):
        st.error("System is not in ready state")
        st.report_fail("test_case_failed")

    hdrMsg("STEP 6: Send ARP request packets..")
    tg.tg_traffic_control(action='run', stream_handle=[tg_stream_handle])
    st.wait(5,"Waiting for 5 secs after sending traffic")

    hdrMsg("STEP 7: Verify cpu counter for ARP packets")
    if not verify_counter_cpu_asic_bcm(dut=vars.D1, queue=copp_queue, value=copp_cir_arp, tol=deviation):
        st.error('CPU counter check for rate limiting  arp to {} pps is failed'.format(copp_cir_arp))
        success = False

    hdrMsg("STEP 8: Verify cpu counter for ARP packets using show CPU queue counters")
    tolerance = (copp_cir_arp*10)/100
    if not copp_obj.verify_cpu_queue_pkt_rate(vars.D1,queue_id=copp_queue,exp_rate=copp_cir_arp,tolerance=tolerance,from_pkts_count="yes"):
        st.error('CPU counter check for rate limiting ARP to {} pps is failed'.format(copp_cir_arp))

    hdrMsg("STEP 9: Stopping the ARP packets")
    tg.tg_traffic_control(action='stop', stream_handle=[tg_stream_handle])

    if not success:
        hdrMsg("STEP 10: Test case Fails so dumping debug commands")
        copp_obj.debug_copp_config(vars.D1)

    if success:
        st.report_pass("test_case_passed","Copp345")
    else:
        st.report_fail("test_case_failed","Copp345")

def hdrMsg(msg):
    st.log("\n######################################################################" \
    " \n%s\n######################################################################"%msg)

def stop_traffic_dump_debug(tg_stream_handle,result=True):

    hdrMsg("STEP : Stopping the control traffic")
    tg.tg_traffic_control(action='stop', stream_handle=[tg_stream_handle])

    if result is False:
        hdrMsg("STEP : Test case Fails so dumping debug commands")
        copp_obj.debug_copp_config(vars.D1)

def get_cir_queue(copp_fgroup):
    copp_cir = copp_obj.get_copp_applied_policy_param(dut=vars.D1,copp_fgroup=copp_fgroup,param="cir")
    sent_rate_pps = copp_cir * 2
    deviation = copp_cir * deviation_percentage
    copp_queue = copp_obj.get_copp_applied_policy_param(dut=vars.D1,copp_fgroup=copp_fgroup,param="trap_queue")
    return (copp_cir,sent_rate_pps,deviation,copp_queue)

