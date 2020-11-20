# This file contains the list of erspan functionality test scripts.

import pytest

from spytest import st, tgapi, SpyTestDict

import apis.qos.acl as acl
import apis.routing.ip as ip
import apis.system.mirroring as mirror
import apis.system.basic as basic
import apis.system.switch_configuration as sconf
import apis.system.reboot as reboot_obj
import apis.system.interface as intf_obj
import apis.qos.acl_dscp as acl_dscp
from utilities.common import poll_wait

data = SpyTestDict()

data.ip_D1T1P1 = "11.1.1.1"
data.ip_T1D1P1 = "11.1.1.2"
data.ip_D1T1P2 = "12.1.1.1"
data.ip_T1D1P2 = "12.1.1.2"
data.ip_D1D2P1 = "13.1.1.1"
data.ip_D2D1P1 = "13.1.1.2"
data.ip_D2T1P1 = "15.1.1.1"
data.ip_T1D2P1 = "15.1.1.2"
data.subnet_mask = "24"
data.sub_mask = "255.255.255.0"
data.ip_list_d1 = ["11.1.1.1", "12.1.1.1", "13.1.1.1"]
data.ip_list_d2 = ["13.1.1.2", "15.1.1.1"]
data.session_name = "Mirror_Ses"
data.mirror_session = "Mirror_Ses1"
data.gre_type = "0x88ee"
data.dscp = "50"
data.ttl = "60"
data.queue = "0"
data.acl_table_name = 'MIRROR_ACL'
data.type = 'monitoring'
data.description = 'Mirror_ACLV4_CREATION'
data.stage = 'INGRESS'
data.source_ip = '11.1.1.2'
data.destination_ip = '15.1.1.2'
data.acl_rule = "Mirror_Rule1"
data.mask = '32'
data.priority = '999'
data.mirror_action = data.session_name
data.src_ip_mask = "{}/{}".format(data.ip_T1D1P1, data.mask)
data.dst_ip_mask = "{}/{}".format(data.ip_T1D1P2, data.mask)
data.rate_pps = 10000
data.pkts_per_burst = 1000
data.flag = 1


def send_traffic(capture_values, capture_fields, neg_check=False, family='ipv4',
                 verify_capture=False, verify_count=True, tg_src_port= 'tg_ph_1' , **kwargs):
    """
    Author: Lakshminarayana D (lakshminarayana.d@broadcom.com)
    :param capture_values: To validate values in cpature packet(Ex: Src_ip: 11.1.1.2)
    :param capture_fields: To alter offset and header in capture packet
    :param neg_check: To verify negative traffic scenario
    :param family: Default address type is ipv4
    :param kwargs: Addition parameters to include to TG1 params based on script
    :return: None (Failed if any traffic step verification)
    :param tg_src_port: Port from which the traffic is triggered
    """

    #  printing arguments passed to function
    saved_args = locals()
    st.log("Validating traffic with following parameters: \n\t")
    for k, v in saved_args.items():
        st.log("\t{}: {}".format(k, v))

    # Altering required parameters for TG streams (Only for stream params on TG-1)
    # Altering ip addresses
    if 'ip_src_addr' in kwargs:
        ip_src_addr = kwargs['ip_src_addr']
        del kwargs['ip_src_addr']
    else:
        ip_src_addr = data.ip_T1D1P1
    if 'ip_dst_addr' in kwargs:
        ip_dst_addr = kwargs['ip_dst_addr']
        del kwargs['ip_dst_addr']
    else:
        ip_dst_addr = data.ip_T1D1P2
    # Altering mac addresses
    if 'mac_dst' in kwargs:
        mac_dst = kwargs['mac_dst']
        del kwargs['mac_dst']
    else:
        mac_dst = dut_mac
    # Altering l3 protocol type
    if 'l3_protocol' in kwargs:
        l3_protocol = kwargs['l3_protocol']
        del kwargs['l3_protocol']
    else:
        l3_protocol = "ipv4"

    # Altering pps
    if 'rate_pps' in kwargs:
        del kwargs['rate_pps']

    if 'pkts_per_burst' in kwargs:
        pkts_per_burst = kwargs['pkts_per_burst']
        del kwargs['pkts_per_burst']
    else:
        pkts_per_burst = data.pkts_per_burst

    # Altering l4_ports based based on l4 protocol(Ex: tcp : tcp_src_port,tcp_dst_port)
    if 'l4_protocol' in kwargs:
        l4proto = 'tcp' if kwargs['l4_protocol'].lower() == 'tcp' else 'udp'
        if not neg_check:
            if l4proto + '_src_port' not in kwargs:
                kwargs[l4proto + '_src_port'] = '2000'
            if l4proto + '_dst_port' not in kwargs:
                kwargs[l4proto + '_dst_port'] = '3000'
        else:
            if l4proto + '_src_port' not in kwargs:
                kwargs[l4proto + '_src_port'] = '2001'
            if l4proto + '_dst_port' not in kwargs:
                kwargs[l4proto + '_dst_port'] = '3001'

    # Rest & clear stats on TG ports
    for action in ['reset']:
        data.tg1.tg_traffic_control(action=action, port_handle=data.tg_ph_1)
        data.tg2.tg_traffic_control(action=action, port_handle=data.tg_ph_2)

    if family == 'ipv4':
        # Creating IPv4 routing interfaces on TG ports


        # Configuring ipv4 traffic stream on TG-1/TG-2 based on the tg_src_port argument
        handle, mac_disc_gw = data.tg_ph_1, data.ip_D1T1P1
        if tg_src_port == 'tg_ph_2': handle,mac_disc_gw = data.tg_ph_2, data.ip_D1T1P2

        stream = data.tg1.tg_traffic_config(port_handle=handle, mode='create', transmit_mode='single_burst',
                                            length_mode='fixed', rate_pps=data.rate_pps, l2_encap='ethernet_ii',
                                            mac_src='00:0a:01:00:00:01', mac_dst=mac_dst,
                                            l3_protocol=l3_protocol, ip_src_addr=ip_src_addr, ip_dst_addr=ip_dst_addr,
                                            mac_discovery_gw=mac_disc_gw, pkts_per_burst=pkts_per_burst, **kwargs)

        stream1 = stream['stream_id']
    else:
        # Configuring ipv6 traffic stream on TG-1
        stream = data.tg1.tg_traffic_config(port_handle=data.tg_ph_1, mode='create', transmit_mode='single_burst',
                                            length_mode='fixed', rate_pps=data.rate_pps, l3_protocol='ipv6',
                                            mac_discovery_gw='2001:1::1', ipv6_src_addr='2001:1::100',
                                            ipv6_dst_addr='2001:2::100', mac_src='00:0a:01:00:00:01',
                                            mac_dst=mac_dst, pkts_per_burst=pkts_per_burst)
        stream1 = stream['stream_id']

    ex_ratio = 1

    # Fields needed for collecting aggregate stats
    tx_port, rx_port = vars.T1D1P1, vars.T1D1P2
    if tg_src_port == 'tg_ph_2': tx_port, rx_port = vars.T1D1P2, vars.T1D1P1

    traffic_details = {
        '1': {
            'tx_ports': [tx_port],
            'tx_obj': [data.tg1],
            'exp_ratio': [1],
            'rx_ports': [rx_port],
            'rx_obj': [data.tg2],
            'stream_list': [stream1],
        },
        '2': {
            'tx_ports': [tx_port],
            'tx_obj': [data.tg1],
            'exp_ratio': [ex_ratio],
            'rx_ports': [vars.T1D2P1],
            'rx_obj': [data.tg3],
            'stream_list': [stream1],
        }
    }

    # Rest & clear stats on TG ports
    for action in ['clear_stats']:
        data.tg1.tg_traffic_control(action=action, port_handle=data.tg_ph_1)
        data.tg2.tg_traffic_control(action=action, port_handle=data.tg_ph_2)
        data.tg3.tg_traffic_control(action=action, port_handle=data.tg_ph_3)

    handle = data.tg_ph_1
    if tg_src_port == 'tg_ph_2': handle = data.tg_ph_2

    # start capture
    if verify_capture:
        data.tg3.tg_packet_control(port_handle=data.tg_ph_3, action='start')

    # Start streams on data.tg1
    data.tg1.tg_traffic_control(action='run',handle=stream1)

    # Stop the traffic
    data.tg1.tg_traffic_control(action='stop',handle=stream1)

    # stop capture
    if verify_capture:
        data.tg3.tg_packet_control(port_handle=data.tg_ph_3, action='stop')


    # verify filter statistics
    filter_result = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate',
                                          comp_type='packet_count', tolerance_factor='2')

    capture_result = None
    if verify_capture:
        # Collecting offset values based on capture_fields
        if data.tg3.tg_type == 'stc':
            offset = {'gre_protocol': 36, 'dst_mac': 38, 'src_mac': 44, 'ether_type': 50, 'ip_protocol': 61, 'dscp': 53,
                      'src_ip': 64, 'dst_ip': 68, 'tcp_src_port': 72, 'tcp_dst_port': 74, 'udp_src_port': 72,
                      'udp_dst_port': 74, 'tcp_flags': 85}
        else:
            # IXIA will display below parametrs only on GRE data packet.
            offset = {'gre_protocol': 36, 'dst_mac': 0, 'src_mac': 12, 'ether_type': 24}
        pack_header = []
        offset_li = []

        # Checking argument capture_fields is list or not
        if not isinstance(capture_fields, list):
            capture_fields = [capture_fields]

        # Appending header and offsets based on capture_fields
        for ele in capture_fields:
            if ele == "gre_protocol":
                pack_header.append("GRE:Protocol Type")
            pack_header.append("GRE:Data:" + str(offset[ele]))
            offset_li.append(offset[ele])

        # save the captured packets into a variable
        pkts_captured = data.tg2.tg_packet_stats(port_handle=data.tg_ph_3, format='var')

        # verify the capture packets
        st.log("Verifying capture packet with following parameters: offset: {}, fields: {}, headers {} and values: {}"
               .format(offset_li, capture_fields, pack_header, capture_values))
        capture_result = tgapi.validate_packet_capture(tg_type=data.tg3.tg_type, pkt_dict=pkts_captured,
                                                 header_list=pack_header,
                                                 offset_list=offset_li, value_list=capture_values)

    capture_result = False if capture_result is None else capture_result
    st.log("Traffic results: Rate-{}, Capture-{}".format(filter_result, capture_result))

    return filter_result, capture_result


def erspan_pre_config():
    """
    Author: Lakshminarayana D (lakshminarayana.d@broadcom.com)
    Using this pre config at module level. So, applicable for all test cases which includes in this module.
    :return: None
    """

    # IP address configuration on DUT-1
    for port, ip_addr, in zip(data.port_list_d1, data.ip_list_d1):
        ip.config_ip_addr_interface(vars.D1, port, ip_addr, data.subnet_mask)

    # IP address configuration on DUT-2
    for port, ip_addr in zip(data.port_list_d2, data.ip_list_d2):
        ip.config_ip_addr_interface(vars.D2, port, ip_addr, data.subnet_mask)

    # Create static route
    _, network = ip.get_network_addr("{}/{}".format(data.ip_T1D2P1, data.subnet_mask))
    ip.create_static_route(vars.D1, data.ip_D2D1P1, network)
    _, network = ip.get_network_addr("{}/{}".format(data.ip_T1D1P1, data.subnet_mask))
    ip.create_static_route(vars.D2, data.ip_D1D2P1, network)

    # creation and verification of Monitor session
    mirror.create_session(vars.D1, session_name=data.session_name, src_ip=data.ip_D1T1P1,
                          dst_ip=data.ip_T1D2P1, gre_type=data.gre_type, dscp=data.dscp,
                          ttl=data.ttl, queue=data.queue)

    # creation and verification of ACL Policy
    acl_dscp.config_policy_table(vars.D1, enable='create', policy_name=data.acl_table_name, policy_type=data.type)
    acl_dscp.config_service_policy_table(vars.D1, policy_kind="bind", interface_name=vars.D1T1P1, stage='in',
                                         service_policy_name=data.acl_table_name, policy_type=data.type)
    acl_dscp.config_service_policy_table(vars.D1, policy_kind="bind", interface_name=vars.D1T1P2, stage='in',
                                         policy_type=data.type, service_policy_name=data.acl_table_name)
    acl.create_acl_table(vars.D1, name="L3_IPV6_INGRESS", stage=data.stage, type="L3V6",
                         description="L3_IPV6_INGRESS", ports=[vars.D1T1P1])

def erspan_pre_config_verify():
    """
    Author: Lakshminarayana D (lakshminarayana.d@broadcom.com)
    Using this pre config at module level. So, applicable for all test cases which includes in this module.
    :return: True or False
    """
    retval = True
    # Displaying ip route table
    for dut in (vars.D1, vars.D2):
        st.log("Displaying routes on device {}....".format(dut))
        ip.show_ip_route(dut)

    # Veification of acl policy and table
    match = [{'policy_name': data.acl_table_name}]
    if not acl_dscp.verify(vars.D1, 'policy', verify_list=match):
        st.log("acl policy verification failed")
        retval = False
    # Verification of Monitor session
    if not mirror.verify_session(vars.D1, session_name=data.session_name, src_ip=data.ip_D1T1P1,
                                 dst_ip=data.ip_T1D2P1, gre_type=data.gre_type, dscp=data.dscp,
                                 ttl=data.ttl, queue=data.queue, status="active"):
        st.log("Failed to create mirror session '{}' ".format(data.session_name))
        retval = False

    return retval


def erspan_post_config():
    """
    Author: Lakshminarayana D (lakshminarayana.d@broadcom.com)
    Using this post config at module level. So, applicable for all test cases which includes in this module.
    :return: None
    """

    # Unconfig ip address on DUT-1
    for port, ip_addr, in zip(data.port_list_d1, data.ip_list_d1):
        ip.delete_ip_interface(vars.D1, port, ip_addr, data.subnet_mask)

    # Unconfig ip address on DUT-2
    for port, ip_addr in zip(data.port_list_d2, data.ip_list_d2):
        ip.delete_ip_interface(vars.D2, port, ip_addr, data.subnet_mask)

    # Unconfig static route
    _, network = ip.get_network_addr("{}/{}".format(data.ip_T1D2P1, data.subnet_mask))
    ip.delete_static_route(vars.D1, data.ip_D2D1P1, network)
    _, network = ip.get_network_addr("{}/{}".format(data.ip_T1D1P1, data.subnet_mask))
    ip.delete_static_route(vars.D2, data.ip_D1D2P1, network)

    # Unconfig mirror session
    mirror.delete_session(vars.D1, data.session_name)

    # Unconfig acl rule
    acl_dscp.config_classifier_table(dut=vars.D1, enable="del", class_name=data.acl_rule)

    # Unconfig acl table
    acl_dscp.config_service_policy_table(dut=vars.D1, policy_kind='unbind', interface_name=vars.D1T1P1, stage='in',
                                         service_policy_name=data.acl_table_name, policy_type=data.type)
    acl_dscp.config_service_policy_table(dut=vars.D1, policy_kind='unbind', interface_name=vars.D1T1P2, stage='in',
                                         service_policy_name=data.acl_table_name, policy_type=data.type)
    acl_dscp.config_policy_table(dut=vars.D1, enable='del', policy_name=data.acl_table_name)

    acl.delete_acl_table(vars.D1, acl_table_name="L3_IPV6_INGRESS", acl_type="L3V6")


@pytest.fixture(scope="module", autouse=True)
def erspan_module_hooks(request):
    # add things at the start of this module
    global vars, h1, h2, h3, h1_ipv6, h2_ipv6, dut_mac

    # Ensure Min topology and read the port details.
    vars = st.ensure_min_topology("D1D2:1", "D1T1:2", "D2T1:1")
    data.tg1, data.tg_ph_1 = tgapi.get_handle_byname("T1D1P1")
    data.tg2, data.tg_ph_2 = tgapi.get_handle_byname("T1D1P2")
    data.tg3, data.tg_ph_3 = tgapi.get_handle_byname("T1D2P1")
    data.port_list_d1 = [vars.D1T1P1, vars.D1T1P2, vars.D1D2P1]
    data.port_list_d2 = [vars.D2D1P1, vars.D2T1P1]

    # Applying Module configuration
    erspan_pre_config()
    st.log("######Verifying Pre_Configurtion on DUT#######")
    if not erspan_pre_config_verify():
        st.report_fail("module_config_verification_failed")

    dut_mac = basic.get_ifconfig_ether(vars.D1, vars.D1T1P1)
    if not dut_mac:
        st.log("Unable to get MAC address of {}".format(vars.D1T1P1))
        st.report_fail("module_config_failed"," for erspan")


    # Creating IPv4 routing interfaces on TG ports
    h1=data.tg1.tg_interface_config(port_handle=data.tg_ph_1, mode='config', intf_ip_addr=data.ip_T1D1P1,
                                 gateway=data.ip_D1T1P1, netmask=data.sub_mask, count=3, arp_send_req='1')
    h2=data.tg2.tg_interface_config(port_handle=data.tg_ph_2, mode='config', intf_ip_addr=data.ip_T1D1P2,
                                 gateway=data.ip_D1T1P2, netmask=data.sub_mask, count=3, arp_send_req='1')
    h3=data.tg3.tg_interface_config(port_handle=data.tg_ph_3, mode='config', intf_ip_addr=data.ip_T1D2P1,
                                 gateway=data.ip_D2T1P1, netmask=data.sub_mask, count=3, arp_send_req='1')

    # Creating IPv6 routing interfaces on TG ports
    h1_ipv6 = data.tg1.tg_interface_config(port_handle=data.tg_ph_1, mode='config', ipv6_intf_addr='2001:1::100',
                                           ipv6_prefix_length='64', ipv6_gateway='2001:1::1',
                                           src_mac_addr='00:0a:01:00:00:01', arp_send_req='1')
    h2_ipv6 = data.tg2.tg_interface_config(port_handle=data.tg_ph_2, mode='config', ipv6_intf_addr='2001:2::100',
                                           ipv6_prefix_length='64', ipv6_gateway='2001:2::1',
                                           src_mac_addr='00:0b:01:00:00:01', arp_send_req='1')

    yield
    # add things at the end of this module"
    erspan_post_config()
    data.tg1.tg_interface_config(port_handle=data.tg_ph_1, handle=h1['handle'], mode='destroy')
    data.tg2.tg_interface_config(port_handle=data.tg_ph_2, handle=h2['handle'], mode='destroy')
    data.tg3.tg_interface_config(port_handle=data.tg_ph_3, handle=h3['handle'], mode='destroy')
    data.tg1.tg_interface_config(port_handle=data.tg_ph_1, handle=h1_ipv6['handle'], mode='destroy')
    data.tg2.tg_interface_config(port_handle=data.tg_ph_2, handle=h2_ipv6['handle'], mode='destroy')


@pytest.fixture(scope="function", autouse=True)
def erspan_func_hooks(request):
    # add things at the start every test case
    # use 'request.node.name' to compare
    # if any thing specific a particular test case

    yield
    # add things at the end every test case
    # use 'request.node.name' to compare
    # if any thing specific a particular test case

    # Deleteing configured ACL rule at end of each test case
    if st.get_func_name(request) != 'test_ft_erspan_config_upload_save_reload_reboot':
        acl_dscp.config_flow_update_table(vars.D1, policy_name=data.acl_table_name, flow='del', policy_type=data.type,
                                          class_name=data.acl_rule)
        acl_dscp.config_classifier_table(dut=vars.D1, enable="del", class_name=data.acl_rule)

    if 'test_ft_erspan_action_ethertype_dscp_tcp_flags_l4range' in request.node.name:
        ip.delete_ip_interface(vars.D1, vars.D1T1P1, "2001:1::1", "64", family="ipv6")
        ip.delete_ip_interface(vars.D1, vars.D1T1P2, "2001:2::1", "64", family="ipv6")
        acl.delete_acl_rule(vars.D1, "L3_IPV6_INGRESS", "L3V6", "FWD_RULE1")
    if st.get_func_name(request) == 'test_ft_erspan_action_encapsulation':
        encap_list = ['0x88ee', '0x6558']
        for encap in encap_list:
            mirror.delete_session(vars.D1, "mirror_" + encap)
    if st.get_func_name(request) == 'test_ft_erspan_portchannel_shut_noshut':
        mirror.delete_session(vars.D1, data.mirror_session)


@pytest.mark.erspan
@pytest.mark.regression
def test_ft_erspan_action_encapsulation():
    """
    Author: Lakshminarayana D (lakshminarayana.d@broadcom.com)
    Verify that ERSPAN is working as expected and intended traffic is mirrored to remote interface using various
    encapsulation methods:
    1. Encapsulation method 0x6558
    2. Encapsulation method 0x88ee

    Topology:
    ---------

    TG1 ----
                DUT1 ---- DUT2 ---- TG3
    TG2 ----

    """
    encap_list = ['0x88ee', '0x6558']
    for encap in encap_list:
        st.log("############### Test started for encapusulation method : {} ###############".format(encap))
        mirror.create_session(vars.D1, session_name="mirror_" + encap, gre_type=encap,
                              dscp=data.dscp, ttl=data.ttl, queue=data.queue, src_ip=data.ip_D1T1P1,
                              dst_ip=data.ip_T1D2P1)

        # creation and verification of ACL Rule
        acl_dscp.config_classifier_table(vars.D1, enable='create', match_type="fields", class_name=data.acl_rule)
        acl_dscp.config_classifier_table(vars.D1, enable='yes', class_criteria='--src-ip', class_name=data.acl_rule,
                                         criteria_value=data.src_ip_mask, match_type="fields")
        acl_dscp.config_flow_update_table(vars.D1, policy_name=data.acl_table_name, flow='add',policy_type=data.type,
                                          class_name=data.acl_rule, priority_value=data.priority,
                                          description=data.description)
        acl_dscp.config_flow_update_table(vars.D1, policy_name=data.acl_table_name, flow='update',policy_type=data.type,
                                          class_name=data.acl_rule, priority_option='--mirror-session',
                                          priority_value="mirror_" + encap)

        # TG traffic verification: Needed arguments : capture_values='11.1.1.2, capture_fields='src_ip'
        retval = send_traffic(capture_values=[encap.strip('0x')], capture_fields=['gre_protocol'], pkts_per_burst=5,
                              verify_capture=True)
        if not retval[1]:
            st.report_fail("traffic_verification_fail", 'capture')
    st.report_pass("test_case_passed")


@pytest.mark.erspan
@pytest.mark.regression
def test_ft_erspan_action_ip_protocol_ip_addr_l4_ports():
    """
    Author: Lakshminarayana D (lakshminarayana.d@broadcom.com)
    Verify that ERSPAN is working as expected and intended traffic with configured IP Protocol, SRC_IP, DST_IP,
    L4_SRC_PORT and L4_DST_PORT from ACL rule is mirrored to remote interface .
    Topology:
    ---------

    TG1 ----
                DUT1 ---- DUT2 ---- TG3
    TG2 ----

    """
    # l4 port protocols
    l4_protocol_list = ['tcp']
    for proto in l4_protocol_list:
        # l4 port values
        ip_port_val = {'src_port': 2000, 'dst_port': 3000, 'src_ip': data.ip_T1D1P1, 'dst_ip': data.ip_T1D1P2}
        # Used this dict for ACL rule to TG argument mapping
        acl_to_tg = {'src_ip': 'ip_dst_addr', 'dst_ip': 'ip_dst_addr'}
        # Parsing capture values in hexa decimal format
        c_values = [hex(ip_port_val['src_port']).lstrip('0x').zfill(4),
                    hex(ip_port_val['dst_port']).lstrip('0x').zfill(4), ip_port_val['src_ip'], ip_port_val['dst_ip']]
        # Creating capture fileds for capture packet header and offset values formation
        c_fields = [proto + '_src_port', proto + '_dst_port', 'src_ip', 'dst_ip']
        # Incrementing src and dst ip addresses
        _, incr_src = ip.increment_ip_addr("{}/{}".format(ip_port_val['src_ip'], data.mask), "host")
        _, incr_dst = ip.increment_ip_addr("{}/{}".format(ip_port_val['dst_ip'], data.mask), "host")
        # Parsing capture values in hexa decimal format for negative scenario
        cn_values = [hex(ip_port_val['src_port'] + 1).lstrip('0x').zfill(4),
                     hex(ip_port_val['dst_port'] + 1).lstrip('0x').zfill(4), incr_src.split('/')[0],
                     incr_dst.split('/')[0]]
        # Creating ip addresses and l4_port parameters to form TG stream
        tg_arg = {c_fields[0]: ip_port_val['src_port'], c_fields[1]: ip_port_val['dst_port'],
                  acl_to_tg['src_ip']: ip_port_val['src_ip'], acl_to_tg['dst_ip']: ip_port_val['dst_ip']}
        # Creating ip addresses and l4_port parameters to form TG stream to verify negative scenario
        tg_argn = {c_fields[0]: ip_port_val['src_port'] + 1, c_fields[1]: ip_port_val['dst_port'] + 1,
                   acl_to_tg['src_ip']: incr_src.split('/')[0], acl_to_tg['dst_ip']: incr_dst.split('/')[0]}
        # Creating acl rule arguments
        acl_args = {'l4_src_port': ip_port_val['src_port'], 'l4_dst_port': ip_port_val['dst_port'],
                    'src_ip': "{}/{}".format(ip_port_val['src_ip'], data.mask),
                    'dst_ip': "{}/{}".format(ip_port_val['dst_ip'], data.mask)}

        # creation and verification of ACL Rule
        criteria_list = ['--ip-proto', '--src-port', '--dst-port', '--src-ip', '--dst-ip']
        criteria_values = ['6', ip_port_val['src_port'], ip_port_val['dst_port'],
                           "{}/{}".format(ip_port_val['src_ip'], data.mask),
                           "{}/{}".format(ip_port_val['dst_ip'], data.mask)]
        acl_dscp.config_classifier_table(vars.D1, enable='create', match_type="fields", class_name=data.acl_rule)
        acl_dscp.config_classifier_table(vars.D1, enable='yes', class_criteria=criteria_list, class_name=data.acl_rule,
                                         criteria_value=criteria_values, match_type="fields")
        acl_dscp.config_flow_update_table(vars.D1, policy_name=data.acl_table_name, flow='add', policy_type=data.type,
                                          class_name=data.acl_rule, priority_value=data.priority,
                                          description=data.description)
        acl_dscp.config_flow_update_table(vars.D1, policy_name=data.acl_table_name, flow='update',policy_type=data.type,
                                          class_name=data.acl_rule, priority_option='--mirror-session',
                                          priority_value=data.mirror_action)

        # TG traffic verification:
        retval = send_traffic(capture_values=c_values, capture_fields=c_fields, l4_protocol=proto, **tg_arg)
        if not retval[0]:
            st.report_fail("traffic_verification_fail", 'packet count')

        # TG traffic verification-Negetive check:
        retval = send_traffic(capture_values=cn_values, capture_fields=c_fields, l4_protocol=proto, neg_check=True,
                              **tg_argn)
        if retval[0]:
            st.report_fail("neg_traffic_verification_fail", 'packet count')
    st.report_pass("test_case_passed")


@pytest.mark.erspan
@pytest.mark.regression
def test_ft_erspan_action_ethertype_dscp_tcp_flags_l4range():
    """
    Author: Lakshminarayana D (lakshminarayana.d@broadcom.com)
    Verify that ERSPAN is working as expected and intended traffic with TCP_FLAGS, L4_Range_Ports and dscp from ACL
    rule is mirrored to remote interface.
    Topology:
    ---------

    TG1 ----
             DUT1 ---- DUT2 ---- TG3
    TG2 ----

    """
    # tcp_flag_info = {'fin': 1, 'syn': 2, 'rst': 4, 'psh': 8, 'ack':16, 'urg': 32}
    ip.config_ip_addr_interface(vars.D1, vars.D1T1P1, "2001:1::1", "64", family="ipv6")
    ip.config_ip_addr_interface(vars.D1, vars.D1T1P2, "2001:2::1", "64", family="ipv6")
    tcp_flag_info = {'fin': 1}
    for k, v in tcp_flag_info.items():
        kn = 'psh' if k == 'urg' else 'urg'
        vn = 8 if v == 32 else 32
        proto = 'tcp'
        # l4 port values
        port_val = {'src_port': 2000, 'dst_port': 3000}
        c_fields = [proto + '_src_port', proto + '_dst_port', 'dscp']
        # Creating l4_port range parameters to TG stream
        tg_arg = {c_fields[0]: port_val['src_port'], c_fields[1]: port_val['dst_port'],
                  proto + "_src_port_mode": 'incr', proto + "_src_port_count": '10',
                  proto + "_dst_port_mode": 'incr', proto + "_dst_port_count": '10',
                  proto + '_src_port_step': '1', proto + '_dst_port_step': '1', 'tcp_' + k + '_flag': 1}
        # Creating l4_port range parameters to TG stream to verify negative scenario
        tg_argn = {c_fields[0]: port_val['src_port'] + 11, c_fields[1]: port_val['dst_port'] + 11,
                   'tcp_' + kn + '_flag': 1}
        criteria_list = ['--ip-proto', '--dscp', '--tcp-flags', '--src-ip', '--dst-ip','--ether-type', '--src-port',
                         '--dst-port']
        criteria_values = ['6', '8','fin',data.src_ip_mask,data.dst_ip_mask,'0x0800','2000-2010','3000-3010']
        acl.create_acl_rule(vars.D1, table_name="L3_IPV6_INGRESS", rule_name="FWD_RULE1", packet_action="FORWARD",
                            priority=900, ether_type='0x86dd', type="L3V6", ip_protocol="ip")
        acl_dscp.config_classifier_table(vars.D1, enable='create', match_type="fields", class_name=data.acl_rule)
        acl_dscp.config_classifier_table(vars.D1, enable='yes', class_criteria=criteria_list, class_name=data.acl_rule,
                                         criteria_value=criteria_values, match_type="fields")
        acl_dscp.config_flow_update_table(vars.D1,policy_name=data.acl_table_name,flow='add',class_name=data.acl_rule,
                                          priority_value=data.priority, description=data.description, policy_type=data.type)
        acl_dscp.config_flow_update_table(vars.D1, policy_name=data.acl_table_name, flow='update',policy_type=data.type,
                                          class_name=data.acl_rule, priority_option='--mirror-session',
                                          priority_value=data.mirror_action)
        match = [{'class_name': data.acl_rule}]
        if not acl_dscp.verify(vars.D1, 'classifier', verify_list=match):
            st.report_fail("classifier_opeartion_failed")
        # TG traffic verification:
        retval = send_traffic(capture_values=[hex(v).lstrip('0x').zfill(2), '0800'],
                              capture_fields=['tcp_flags', 'ether_type'],
                              ip_dscp='8', l4_protocol='tcp', **tg_arg)
        if not retval[0]:
            st.report_fail("traffic_verification_fail", 'packet count')

        # TG traffic verification-Negetive check:
        retval = send_traffic(capture_values=[hex(vn).lstrip('0x').zfill(2), '86dd'],
                              capture_fields=['tcp_flags', 'ether_type'],
                              ip_dscp='56', l4_protocol='tcp', family='ipv6', neg_check=True, **tg_argn)
        if retval[0]:
            st.report_fail("neg_traffic_verification_fail", 'packet count')
        rule_counters=acl.show_acl_counters(vars.D1, acl_table="L3_IPV6_INGRESS", acl_rule="FWD_RULE1", acl_type="ipv6")
        if not rule_counters:
            st.report_fail("matched_traffic_forward_fail")
        if not rule_counters[0]['packetscnt'] or int(rule_counters[0]['packetscnt']) < data.pkts_per_burst:
            st.report_fail("matched_traffic_forward_fail")
    st.report_pass("test_case_passed")


@pytest.mark.erspan
@pytest.mark.regression
def test_ft_erspan_basic_functionality():

    """
    Author: Sesha Koilkonda  (sesharedy.koilkonda@broadcom.com)
    TC1 FtOpSoSyErspanFn019: Verify that maximum number of mirror sessions are created.
    TC2 FtOpSoSyErspanFn015: Verify that multiple mirror sessions can be created and assigned to rules from the same ACL.
    TC3 FtOpSoSyErspanFn011: Verify that ERSPAN is working as expected and intended traffic is mirrored to remote interface from multiple interfaces.
    Notes from dev: Only 1 Mirror ACL configuration is supported as of now.
                    maximum Acl rules that can be configured in mirror sesssion(s) is 3.
    :return:
    """
    ip_add_src, ip_add_dst = data.ip_T1D1P1, data.ip_T1D2P1
    max_sessions, data.mask = 4, '32'
    tc_fail = 0
    acl_dscp.config_classifier_table(vars.D1, enable='create', match_type="fields", class_name=data.acl_rule)
    acl_dscp.config_classifier_table(vars.D1, enable='yes', class_criteria='--src-ip', class_name=data.acl_rule,
                                     criteria_value="{}/{}".format(ip_add_src, data.mask), match_type="fields")
    acl_dscp.config_flow_update_table(vars.D1, policy_name=data.acl_table_name, flow='add', policy_type=data.type,
                                      class_name=data.acl_rule, priority_value=data.priority,
                                      description=data.description)
    acl_dscp.config_flow_update_table(vars.D1, policy_name=data.acl_table_name, flow='update',policy_type=data.type,
                                      class_name=data.acl_rule, priority_option='--mirror-session',
                                      priority_value=data.session_name)

    #Configure the maximum supported mirror sessions(Session1 alreday created as part of module config.)
    for ele in range(1, max_sessions):
        _, ip_add_src = ip.increment_ip_addr("{}/{}".format(ip_add_src.split('/')[0], data.mask), "host")
        _, ip_add_dst = ip.increment_ip_addr("{}/{}".format(ip_add_dst.split('/')[0], data.mask), "host")
        if ele == 2: _, ip_add_src = ip.increment_ip_addr("{}/{}".format(data.ip_D1T1P2, data.mask), "host")

        mirror_args = {'session_name': data.session_name + str(ele),'src_ip': ip_add_src.split('/')[0], 'dst_ip': ip_add_dst.split('/')[0],
                        'dscp':'50', 'ttl':'60', 'gre_type':'0x88ee', 'queue':data.queue}
        mirror.create_session(vars.D1, **mirror_args)

        if not mirror.verify_session(vars.D1, **mirror_args):
            st.log("failed to configure the mirror session: {} ".format(data.session_name + str(ele)))
            tc_fail = 1
        acl_dscp.config_classifier_table(vars.D1, enable='create', match_type="fields", class_name=data.acl_rule+ str(ele))
        acl_dscp.config_classifier_table(vars.D1, enable='yes', class_criteria='--src-ip', match_type="fields",
                                         class_name=data.acl_rule + str(ele),
                                         criteria_value="{}".format(ip_add_src))
        acl_dscp.config_flow_update_table(vars.D1, policy_name=data.acl_table_name, flow='add', policy_type=data.type,
                                          class_name=data.acl_rule+str(ele),priority_value=int(data.priority) + ele,
                                          description=data.description)
        acl_dscp.config_flow_update_table(vars.D1, policy_name=data.acl_table_name, flow='update',policy_type=data.type,
                                          class_name=data.acl_rule+str(ele), priority_option='--mirror-session',
                                          priority_value=data.session_name + str(ele))

    # Traffic validations for the mirror sessions.
    ip_add_src, ip_add_dst, tg_src = data.ip_T1D1P1, data.ip_T1D1P2, 'tg_ph_1'
    for ele in range(0, max_sessions):
        if ele == 2:
            _, ip_add_src = ip.increment_ip_addr("{}/{}".format(data.ip_D1T1P2.split('/')[0], data.mask), "host")
            _, ip_add_dst = ip.increment_ip_addr("{}/{}".format(data.ip_D1T1P1.split('/')[0], data.mask), "host")
            tg_src = 'tg_ph_2'

        retval = send_traffic(capture_values=[ip_add_dst], capture_fields=['dst_ip'], ip_src_addr= ip_add_src.split('/')[0],
                             ip_dst_addr= ip_add_dst.split('/')[0], tg_src_port=tg_src)
        if not retval[0]:
            st.log('Traffic validation failed for the mirror session combination: source_ip {} , destination_ip {}'.format(ip_add_src,ip_add_dst))
            tc_fail = ele
        _, ip_add_src = ip.increment_ip_addr("{}/{}".format(ip_add_src.split('/')[0], data.mask), "host")

    #Unconfigration part
    for ele in range(1, max_sessions):
        acl_dscp.config_flow_update_table(vars.D1, policy_name=data.acl_table_name, flow='del',
                                          policy_type=data.type, class_name=data.acl_rule + str(ele))
        acl_dscp.config_classifier_table(dut=vars.D1, enable="del", class_name=data.acl_rule+str(ele))
        mirror.delete_session(vars.D1, data.session_name + str(ele))
    if tc_fail == 1:
        st.report_fail("mirror_session_fail", "")
    elif tc_fail == 2:
        st.report_fail("traffic_verification_fail", "packet count")
    st.report_pass("test_case_passed")


@pytest.mark.erspan
@pytest.mark.regression
def test_ft_erspan_config_upload_save_reload_reboot():
    """
    Author: Prudviraj kristipati (prudviraj.kristipati@broadcom.com)
    Verify that ERSPAN configuration is stored to config_db file, after config save & reload and save & reboot.
    :return:
    """
    mirror.delete_session(vars.D1, data.session_name)
    mirror_args = {"session_name": data.session_name, "src_ip": data.ip_D1T1P1, "dst_ip": data.ip_T1D2P1,
                   "gre_type": data.gre_type, "dscp": data.dscp, "ttl": data.ttl, "queue": data.queue}
    retval = mirror.create_session_table(vars.D1, **mirror_args)

    if not retval:
        st.log("Failed to create mirror session using json file.")
        st.report_fail("mirror_session_fail", data.session_name)
    if not sconf.verify_running_config(vars.D1, "MIRROR_SESSION", "Mirror_Ses", "dst_ip", "15.1.1.2"):
        st.log("Failed to show mirror session details in running config.")
        st.report_fail("test_case_failure_message", "Failed to display mirror session details in running-config.")
    reboot_obj.config_save_reload(vars.D1)

    if not mirror.verify_session(vars.D1, **mirror_args):
        st.log("Failed to show mirror session details after reload.")
        st.report_fail("mirror_session_fail", data.session_name + "after config save and reload")
    if not sconf.verify_running_config(vars.D1, "MIRROR_SESSION", "Mirror_Ses", "dst_ip", "15.1.1.2"):
        st.log("Failed to show mirror session details in running config after reload.")
        st.report_fail("test_case_failure_message",
                       "Failed to display mirror session details in running-config after config save and reload")

    st.reboot(vars.D1)

    if not mirror.verify_session(vars.D1, **mirror_args):
        st.log("failed to show mirror session details after reboot.")
        st.report_fail("mirror_session_fail", data.session_name + "after save and reboot")
    if not sconf.verify_running_config(vars.D1, "MIRROR_SESSION", "Mirror_Ses", "dst_ip", "15.1.1.2"):
        st.log("failed to show mirror session details in running config after reboot.")
        st.report_fail("test_case_failure_message",
                       "Failed to display mirror session details in running-config after save and reboot")

    st.report_pass("test_case_passed")


def test_ft_erspan_portchannel_shut_noshut():

    """
    Author: Kanala Ramprakash Reddy ( ramprakash-reddy.kanala@broadcom.com)
    TC1 FtOpSoSyErspanFn020: Verify that ERSPAN is working as expected after portchannel shut/no shut.
    :return:
    """
    st.log("############### Test started to check ERSPAN status between multiple link flaps###############")
    st.log("Creating mirror session")
    mirror.create_session(vars.D1, session_name=data.mirror_session, gre_type=data.gre_type, dscp=data.dscp,
                          ttl=data.ttl, queue=data.queue, src_ip=data.ip_T1D1P2, dst_ip=data.ip_T1D2P1)

    st.log("Creating ACL Policy")
    acl_dscp.config_classifier_table(vars.D1, enable='create', match_type="fields", class_name=data.acl_rule)
    acl_dscp.config_classifier_table(vars.D1, enable='yes', class_criteria="--src-ip", class_name=data.acl_rule,
                                     criteria_value=data.src_ip_mask, match_type="fields")
    acl_dscp.config_flow_update_table(vars.D1, policy_name=data.acl_table_name, flow='add', policy_type=data.type,
                                      class_name=data.acl_rule, priority_value=data.priority,
                                      description=data.description)
    acl_dscp.config_flow_update_table(vars.D1, policy_name=data.acl_table_name, flow='update', policy_type=data.type,
                                      class_name=data.acl_rule, priority_option='--mirror-session',
                                      priority_value=data.mirror_action)
    stream = data.tg1.tg_traffic_config(port_handle=data.tg_ph_1, mode='create', transmit_mode='continuous', length_mode='fixed',
                               rate_pps=data.rate_pps, l2_encap='ethernet_ii', mac_src='00:0a:01:00:00:01',
                               mac_dst=dut_mac, l3_protocol="ipv4", ip_src_addr=data.ip_T1D1P1,
                               ip_dst_addr=data.ip_T1D1P2)['stream_id']
    intf_obj.clear_interface_counters(vars.D1)
    st.log("Starting the traffic")
    data.tg1.tg_traffic_control(action='run', stream_handle=stream)
    for _ in range(5):
        intf_obj.interface_shutdown(vars.D1, [vars.D1D2P1], skip_verify=True)
        if not poll_wait(mirror.verify_session_all, 20, vars.D1, mirror_type="erspan", status="inactive",
                         session_name=data.mirror_session):
            st.error("Mirror session status should be inactive after port shutdown")
            data.flag = 0
        intf_obj.interface_noshutdown(vars.D1, [vars.D1D2P1], skip_verify=True)
        if not poll_wait(mirror.verify_session_all, 20, vars.D1, mirror_type="erspan", status="active",
                         session_name=data.mirror_session):
            st.error("Mirror session status should be active after port startup")
            data.flag = 0
    data.tg1.tg_traffic_control(action='stop', stream_handle=stream)
    if data.flag == 0:
        st.report_fail("test_case_failed")
    else:
        st.report_pass("test_case_passed")

