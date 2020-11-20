import pytest

from spytest import st, tgapi, SpyTestDict

import apis.routing.ip as ip
import apis.system.mirroring as mirror
import apis.system.basic as basic
import apis.system.reboot as rb_obj
import apis.qos.acl_dscp as acl_dscp

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
data.acl_rule = "Mirror_Rule"
data.mask = '32'
data.priority = '999'
data.mirror_action = data.session_name
data.mask = "32"
data.src_ip_mask = "{}/{}".format(data.ip_T1D1P1, data.mask)
data.dst_ip_mask = "{}/{}".format(data.ip_T1D1P2, data.mask)
data.rate_pps = 10000
data.pkts_per_burst = 1000


def erspan_pre_config():
    """
    Author: Anil Kumar Kacharla<anilkumar.kacharla@broadcom.com>
    Using this pre config at module level. So, applicable for all test cases which includes in this module.
    :return: None
    """

    # IP address configuration on DUT-1
    for port, ip_addr, in zip(data.port_list_d1, data.ip_list_d1):
        ip.config_ip_addr_interface(data.dut1, port, ip_addr, data.subnet_mask)

    # IP address configuration on DUT-2
    for port, ip_addr in zip(data.port_list_d2, data.ip_list_d2):
        ip.config_ip_addr_interface(data.dut2, port, ip_addr, data.subnet_mask)

    # Create static route
    _, network = ip.get_network_addr("{}/{}".format(data.ip_T1D2P1, data.subnet_mask))
    ip.create_static_route(data.dut1, data.ip_D2D1P1, network)
    _, network = ip.get_network_addr("{}/{}".format(data.ip_T1D1P1, data.subnet_mask))
    ip.create_static_route(data.dut2, data.ip_D1D2P1, network)

    # creation and verification of Monitor session
    mirror.create_session(data.dut1, session_name=data.session_name, src_ip=data.ip_D1T1P1,
                          dst_ip=data.ip_T1D2P1, gre_type=data.gre_type, dscp=data.dscp,
                          ttl=data.ttl, queue=data.queue)

    # creation and verification of ACL policy
    acl_dscp.config_policy_table(vars.D1, enable='create', policy_name=data.acl_table_name, policy_type=data.type)
    acl_dscp.config_service_policy_table(vars.D1, policy_kind="bind", interface_name=vars.D1T1P1, stage='in',
                                         service_policy_name=data.acl_table_name, policy_type=data.type)
    # creation and verification of ACL classifier
    acl_dscp.config_classifier_table(vars.D1, enable='create', match_type="fields", class_name=data.acl_rule)
    acl_dscp.config_classifier_table(data.dut1, enable='yes', class_criteria=['--src-ip'], class_name=data.acl_rule,
                                     criteria_value=[data.src_ip_mask], match_type="fields")
    acl_dscp.config_flow_update_table(data.dut1, policy_name=data.acl_table_name, flow='add', class_name=data.acl_rule,
                                      priority_value=data.priority, description=data.description, policy_type=data.type)
    acl_dscp.config_flow_update_table(data.dut1, policy_name=data.acl_table_name, flow='update', policy_type=data.type,
                                      class_name=data.acl_rule, priority_option='--mirror-session',
                                      priority_value=data.mirror_action)

def erspan_pre_config_verify():
    """
    Author: Anil Kumar Kacharla<anilkumar.kacharla@broadcom.com>
    Using this pre config at module level. So, applicable for all test cases which includes in this module.
    :return: None
    """
    retval = True
    # Displaying ip route table
    for dut in (data.dut1, data.dut2):
        st.log("Displaying routes on device {}....".format(dut))
        ip.show_ip_route(dut)

    # Verification of ACL Table
    if not acl_dscp.verify(data.dut1, 'policy', verify_list=[{"policy_name":data.acl_table_name}]):
        st.log("Failed to create ACL policy '{}' ".format(data.acl_table_name))
        retval = False

    # Verification of Monitor session
    if not mirror.verify_session(data.dut1, session_name=data.session_name, src_ip=data.ip_D1T1P1,
                                 dst_ip=data.ip_T1D2P1, gre_type=data.gre_type, dscp=data.dscp,
                                 ttl=data.ttl, queue=data.queue, status="active"):
        st.log("Failed to create mirror session '{}' ".format(data.session_name))
        retval = False

    return retval


def erspan_post_config():
    """
    Author: Anil Kumar Kacharla<anilkumar.kacharla@broadcom.com>
    Using this post config at module level. So, applicable for all test cases which includes in this module.
    :return: None
    """

    # Unconfig ip address on DUT-1
    for port, ip_addr, in zip(data.port_list_d1, data.ip_list_d1):
        ip.delete_ip_interface(data.dut1, port, ip_addr, data.subnet_mask)

    # Unconfig ip address on DUT-2
    for port, ip_addr in zip(data.port_list_d2, data.ip_list_d2):
        ip.delete_ip_interface(data.dut2, port, ip_addr, data.subnet_mask)

    # Unconfig static route
    _, network = ip.get_network_addr("{}/{}".format(data.ip_T1D2P1, data.subnet_mask))
    ip.delete_static_route(data.dut1, data.ip_D2D1P1, network)
    _, network = ip.get_network_addr("{}/{}".format(data.ip_T1D1P1, data.subnet_mask))
    ip.delete_static_route(data.dut2, data.ip_D1D2P1, network)

    # Unconfig acl classifier
    acl_dscp.config_flow_update_table(data.dut1, policy_name=data.acl_table_name, flow='del', policy_type=data.type,
                                      class_name=data.acl_rule)
    acl_dscp.config_classifier_table(dut=data.dut1, enable="del", class_name=data.acl_rule)

    # Unconfig acl policy
    acl_dscp.config_service_policy_table(dut=data.dut1, policy_kind='unbind', interface_name=vars.D1T1P1, stage='in',
                                         service_policy_name=data.acl_table_name, policy_type=data.type)
    acl_dscp.config_policy_table(dut=data.dut1, enable='del', policy_name=data.acl_table_name)

    # Unconfig mirror session
    mirror.delete_session(data.dut1, data.session_name)

def tg_stream_config():
    for action in ['reset']:
        data.tg1.tg_traffic_control(action=action, port_handle=data.tg_ph_1)
        data.tg2.tg_traffic_control(action=action, port_handle=data.tg_ph_2)
    # Configuring ipv4 traffic stream on TG-1
    data.stream={}
    stream = data.tg1.tg_traffic_config(port_handle=data.tg_ph_1, mode='create', transmit_mode='continuous',
                                        length_mode='fixed', rate_pps=data.rate_pps, l2_encap='ethernet_ii',
                                        mac_src='00:0a:01:00:00:01', mac_dst=basic.get_ifconfig_ether(data.dut1, vars.D1T1P1),
                                        l3_protocol="ipv4", ip_src_addr=data.ip_T1D1P1, ip_dst_addr=data.ip_T1D1P2,
                                        mac_discovery_gw=data.ip_D1T1P1)
    data.stream = stream['stream_id']
    ex_ratio = 0.98
    # Fields needed for collecting aggregate stats
    traffic_details = {
        '1': {
            'tx_ports': [vars.T1D1P1],
            'tx_obj': [data.tg1],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D1P2],
            'rx_obj': [data.tg2],
            'stream_list': [data.stream],
        },
        '2': {
            'tx_ports': [vars.T1D1P1],
            'tx_obj': [data.tg1],
            'exp_ratio': [ex_ratio],
            'rx_ports': [vars.T1D2P1],
            'rx_obj': [data.tg3],
            'stream_list': [data.stream],
        }
    }
    data.traffic_details =traffic_details
    # Start streams on data.tg1
    # data.tg1.tg_traffic_control(action='run', port_handle=data.tg_ph_1,stream_handle=data.stream)


@pytest.fixture(scope="module", autouse=True)
def erspan_long_run_module_hooks(request):
    # add things at the start of this module
    global vars, h1, h2, h3
    vars = st.ensure_min_topology("D1D2:1", "D1T1:2", "D2T1:1")
    data.dut1 = vars.D1
    data.dut2 = vars.D2
    data.tg1, data.tg_ph_1 = tgapi.get_handle_byname("T1D1P1")
    data.tg2, data.tg_ph_2 = tgapi.get_handle_byname("T1D1P2")
    data.tg3, data.tg_ph_3 = tgapi.get_handle_byname("T1D2P1")
    data.port_list_d1 = [vars.D1T1P1, vars.D1T1P2, vars.D1D2P1]
    data.port_list_d2 = [vars.D2D1P1, vars.D2T1P1]

    st.log("Configuring ERSPAN")
    erspan_pre_config()
    h1=data.tg1.tg_interface_config(port_handle=data.tg_ph_1, mode='config', intf_ip_addr=data.ip_T1D1P1,
                                 gateway=data.ip_D1T1P1, netmask=data.sub_mask)
    h2=data.tg2.tg_interface_config(port_handle=data.tg_ph_2, mode='config', intf_ip_addr=data.ip_T1D1P2,
                                 gateway=data.ip_D1T1P2, netmask=data.sub_mask)
    h3=data.tg3.tg_interface_config(port_handle=data.tg_ph_3, mode='config', intf_ip_addr=data.ip_T1D2P1,
                                 gateway=data.ip_D2T1P1, netmask=data.sub_mask)
    st.log("ERSPAN verification")
    erspan_pre_config_verify()
    tg_stream_config()
    yield
    # add things at the end of this module"
    erspan_post_config()
    data.tg1.tg_interface_config(port_handle=data.tg_ph_1, handle=h1['handle'], mode='destroy')
    data.tg2.tg_interface_config(port_handle=data.tg_ph_2, handle=h2['handle'], mode='destroy')
    data.tg3.tg_interface_config(port_handle=data.tg_ph_3, handle=h3['handle'], mode='destroy')

@pytest.fixture(scope="function", autouse=True)
def erspan_long_run_func_hooks(request):
    # add things at the start every test case
    # use 'request.node.name' to compare
    # if any thing specific a particular test case

    yield
    # add things at the end every test case
    # use 'request.node.name' to compare
    # if any thing specific a particular test case

    # Deleteing configured ACL classifier at end of each test case
    acl_dscp.config_classifier_table(dut=data.dut1, enable="del", class_name=data.acl_rule)

    if not erspan_pre_config_verify():
        st.log("######Test case cleanup verification failed. Cleanup existing config and applying pre_config#######")
        erspan_post_config()
        erspan_pre_config()


@pytest.mark.erspan_warm_reboot
@pytest.mark.regression
def test_ft_erspan_warm_reboot():
    """
    Author: Anil Kumar Kacharla<anilkumar.kacharla@broadcom.com>
    Verify that ERSPAN is working as expected and intended traffic is mirrored to remote interface while warm reboot
    """
    data.tg1.tg_traffic_control(action="clear_stats", port_handle=data.tg_ph_1)
    data.tg2.tg_traffic_control(action="clear_stats", port_handle=data.tg_ph_2)
    data.tg1.tg_traffic_control(action='run', stream_handle=data.stream)
    st.wait(5)
    st.log("performing Config save")
    rb_obj.config_save(vars.D1)
    st.log("performing warm-reboot")
    st.reboot(vars.D1, 'warm')
    st.log("Stop  the traffic")
    data.tg1.tg_traffic_control(action='stop', stream_handle=data.stream)
    st.wait(10)
    st.log("verifying traffic after warm reboot")
    filter_result = tgapi.validate_tgen_traffic(traffic_details=data.traffic_details, mode='aggregate',
                                          comp_type='packet_count')
    if not filter_result:
        st.log("traffic verification failed")
        st.report_fail("operation_failed")
    else:
        st.log("ERSPAN traffic verification is successful")

    st.log("verifying erspan configuration after warm reboot")
    erspan_pre_config_verify()
    st.report_pass("test_case_passed")

