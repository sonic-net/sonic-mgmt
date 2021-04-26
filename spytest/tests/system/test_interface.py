import pytest

from spytest import st, tgapi, SpyTestDict
import apis.switching.vlan as vlanapi
import apis.system.interface as intfapi
import apis.routing.ip as ipapi
import apis.system.reboot as rbapi
import apis.system.basic as base_obj

from utilities.common import random_vlan_list

intf_data = SpyTestDict()

@pytest.fixture(scope="module", autouse=True)
def interface_module_hooks(request):
    global vars
    vars = st.ensure_min_topology("D1D2:2", "D1T1:2")
    initialize_variables()
    if not vlanapi.create_vlan(vars.D1, intf_data.vlan_id):
        st.report_fail("vlan_create_fail", intf_data.vlan_id)
    if not vlanapi.add_vlan_member(vars.D1, intf_data.vlan_id, [vars.D1T1P1, vars.D1T1P2]):
        st.report_fail("vlan_untagged_member_fail", [vars.D1T1P1, vars.D1T1P2], intf_data.vlan_id)
    st.log("Getting TG handlers")

    _, intf_data.tg_ph_1 = tgapi.get_handle_byname("T1D1P1")
    _, intf_data.tg_ph_2 = tgapi.get_handle_byname("T1D1P2")
    intf_data.tg = tgapi.get_chassis(vars)

    st.log("Reset and clear statistics of TG ports")
    intf_data.tg.tg_traffic_control(action='reset', port_handle=[intf_data.tg_ph_1, intf_data.tg_ph_2])
    intf_data.tg.tg_traffic_control(action='clear_stats', port_handle=[intf_data.tg_ph_1, intf_data.tg_ph_2])

    st.log("Creating TG streams")
    intf_data.streams = {}
    stream = intf_data.tg.tg_traffic_config(port_handle=intf_data.tg_ph_1, mode='create', port_handle2=intf_data.tg_ph_2,
                                            length_mode='fixed', rate_pps=100, frame_size=intf_data.mtu1,
                                            l2_encap='ethernet_ii_vlan', transmit_mode='single_burst',
                                            pkts_per_burst=100, vlan_id=intf_data.vlan_id,
                                            mac_src=intf_data.source_mac, mac_dst=intf_data.destination_mac,
                                            vlan="enable")
    st.log('Stream output:{}'.format(stream))
    intf_data.streams['mtu1'] = stream['stream_id']

    stream = intf_data.tg.tg_traffic_config(port_handle=intf_data.tg_ph_1, mode='create', port_handle2=intf_data.tg_ph_2,
                                            length_mode='fixed', rate_pps=100, frame_size=intf_data.mtu2,
                                            l2_encap='ethernet_ii_vlan', transmit_mode='single_burst',
                                            pkts_per_burst=100, vlan_id=intf_data.vlan_id,
                                            mac_src=intf_data.source_mac, mac_dst=intf_data.destination_mac,
                                            vlan="enable")
    st.log('Stream output:{}'.format(stream))
    intf_data.streams['mtu2'] = stream['stream_id']

    stream = intf_data.tg.tg_traffic_config(port_handle=intf_data.tg_ph_1, mode='create',
                                            length_mode='fixed', frame_size='5000',
                                            transmit_mode='continuous')
    st.log('Stream output:{}'.format(stream))
    intf_data.streams['traffic_tg1'] = stream['stream_id']

    stream = intf_data.tg.tg_traffic_config(port_handle=intf_data.tg_ph_2, mode='create',
                                            length_mode='fixed', frame_size='5000',
                                            transmit_mode='continuous')
    st.log('Stream output:{}'.format(stream))
    intf_data.streams['traffic_tg2'] = stream['stream_id']

    yield
    vlanapi.clear_vlan_configuration(st.get_dut_names(), thread=True)
    # intf_data.tg.tg_traffic_control(action='stop', port_handle=[intf_data.tg_ph_1, intf_data.tg_ph_2])
    intf_data.tg.tg_traffic_control(action='reset', port_handle=[intf_data.tg_ph_1, intf_data.tg_ph_2])
    #intf_data.tg.tg_traffic_control(action='clear_stats',port_handle=[intf_data.tg_ph_1, intf_data.tg_ph_2])


@pytest.fixture(scope="function", autouse=True)
def interface_func_hooks(request):
    yield
    if st.get_func_name(request) == 'test_ft_ovr_counters':
        intfapi.interface_properties_set(vars.D1, vars.D1T1P1, 'mtu', intf_data.mtu_default)


def initialize_variables():
    intf_data.clear()
    intf_data.ip_address = '11.11.11.11'
    intf_data.ip_address1 = "11.11.11.9"
    intf_data.mask = "24"
    intf_data.mtu = '2000'
    intf_data.mtu1 = '4096'
    intf_data.mtu2 = '9216'
    intf_data.source_mac = "00:00:02:00:00:01"
    intf_data.destination_mac = "00:00:01:00:00:01"
    intf_data.vlan_id = str(random_vlan_list()[0])
    intf_data.mtu_default = intfapi.get_interface_property(vars.D1, vars.D1T1P1, 'mtu')[0]
    intf_data.wait_sec = 10


def port_fec_no_fec(vars, speed, fec=["none", "rs"]):
    """
    Author : Nagarjuna Suravarapu <nagarjuna.suravarapu@broadcom.com
    By using this function we can pass parameters where we required (In my usage only fec parameter is changed )
    and we can also reuse the code so that we can reduce the codes of line.
    """
    if not isinstance(fec, list):
        st.log("FEC is not matching the criteria ..")
        st.report_fail("interface_is_down_on_dut", [vars.D1D2P1, vars.D1D2P2])
    st.log("Observed that speed as {} on interface {}".format(speed, vars.D1D2P1))
    if not st.poll_wait(intfapi.verify_interface_status, 20, vars.D1, [vars.D1D2P1, vars.D1D2P2], 'oper', 'up'):
        st.report_fail("interface_is_down_on_dut", [vars.D1D2P1, vars.D1D2P2])
    if not st.poll_wait(intfapi.verify_interface_status, 20, vars.D2, [vars.D2D1P1, vars.D2D1P2], 'oper', 'up'):
        st.report_fail("interface_is_down_on_dut", [vars.D2D1P1, vars.D2D1P2])
    if base_obj.get_hwsku(vars.D1).lower() in vars.constants[vars.D1]["TH3_PLATFORMS"]:
        if speed not in ['400G', '400000']:
            st.log("enabling the fec on Dut1")
            st.log(" if the fec on both duts interfaces mismatch then the ports should be down")
            intfapi.interface_properties_set(vars.D1, [vars.D1D2P1, vars.D1D2P2], "fec", fec[0], skip_error=False)
            if not st.poll_wait(intfapi.verify_interface_status, 20, vars.D1, [vars.D1D2P1, vars.D1D2P2], 'oper', 'down'):
                st.report_fail("interface_is_up_on_dut", [vars.D1D2P1, vars.D1D2P2])
            if not st.poll_wait(intfapi.verify_interface_status, 20, vars.D2, [vars.D2D1P1, vars.D2D1P2], 'oper', 'down'):
                st.report_fail("interface_is_up_on_dut", [vars.D2D1P1, vars.D2D1P2])
            st.log("disabling the fec on Dut1")
            intfapi.interface_properties_set(vars.D1, [vars.D1D2P1, vars.D1D2P2], "fec", fec[1], skip_error=False,
                                             no_form=True)
            if not st.poll_wait(intfapi.verify_interface_status, 20, vars.D1, [vars.D1D2P1, vars.D1D2P2], 'oper', 'up'):
                st.report_fail("interface_is_down_on_dut", [vars.D1D2P1, vars.D1D2P2])
            if not st.poll_wait(intfapi.verify_interface_status, 20, vars.D2, [vars.D2D1P1, vars.D2D1P2], 'oper', 'up'):
                st.report_fail("interface_is_down_on_dut", [vars.D2D1P1, vars.D2D1P2])
    else:
        st.log("enabling the fec on Dut1")
        st.log("if the fec on both duts interfaces mismatch then the ports should be down")
        intfapi.interface_properties_set(vars.D1, [vars.D1D2P1, vars.D1D2P2], "fec", fec[1], skip_error=False)
        if not st.poll_wait(intfapi.verify_interface_status, 20, vars.D1, [vars.D1D2P1, vars.D1D2P2], 'oper', 'down'):
            st.report_fail("interface_is_up_on_dut", [vars.D1D2P1, vars.D1D2P2])
        if not st.poll_wait(intfapi.verify_interface_status, 20, vars.D2, [vars.D2D1P1, vars.D2D1P2], 'oper', 'down'):
            st.report_fail("interface_is_up_on_dut", [vars.D2D1P1, vars.D2D1P2])
        st.log("disabling the fec on Dut1")
        intfapi.interface_properties_set(vars.D1, [vars.D1D2P1, vars.D1D2P2], "fec", fec[0], skip_error=False)
        if not st.poll_wait(intfapi.verify_interface_status, 20, vars.D1, [vars.D1D2P1, vars.D1D2P2], 'oper', 'up'):
            st.report_fail("interface_is_down_on_dut", [vars.D1D2P1, vars.D1D2P2])
        if not st.poll_wait(intfapi.verify_interface_status, 20, vars.D2, [vars.D2D1P1, vars.D2D1P2], 'oper', 'up'):
            st.report_fail("interface_is_down_on_dut", [vars.D2D1P1, vars.D2D1P2])


@pytest.mark.regression
@pytest.mark.interface_ft
def test_ft_port_frame_fwd_diff_mtu():
    intfapi.get_interface_property(vars.D1, vars.D1T1P1, "mtu")
    intfapi.get_interface_property(vars.D1, vars.D1T1P2, "mtu")
    st.log("Configuring MTU values for each interface")
    intfapi.interface_properties_set(vars.D1, [vars.D1T1P1, vars.D1T1P2], 'mtu', intf_data.mtu1)

    intf_data.tg.tg_traffic_control(action='run', stream_handle=[intf_data.streams['mtu1'], intf_data.streams['mtu2']])
    st.wait(2)
    intf_data.tg.tg_traffic_control(action='stop', stream_handle=[intf_data.streams['mtu1'], intf_data.streams['mtu2']])
    st.log("Fetching TGen statistics")
    traffic_details = {
        '1': {
            'tx_ports': [vars.T1D1P1],
            'tx_obj': [intf_data.tg],
            'exp_ratio': [[1, 0]],
            'rx_ports': [vars.T1D1P2],
            'rx_obj': [intf_data.tg],
            'stream_list': [[intf_data.streams['mtu1'], intf_data.streams['mtu2']]],
        },
    }
    streamResult = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='streamblock',
                                               comp_type='packet_count')
    if not streamResult:
        st.report_fail("traffic_transmission_failed", vars.T1D1P1)
    st.report_pass("test_case_passed")


@pytest.mark.regression
@pytest.mark.interface_ft
def test_ft_port_fec_nofec():
    """
    Author : Nagarjuna Suravarapu <nagarjuna.suravarapu@broadcom.com>
    Testbed :  D1====== D2(two links)
    Verify the port status by enabling / disabling fec when we connected it with other device.
    """
    speed = intfapi.get_interface_property(vars.D1, vars.D1D2P1, "speed")
    if not speed:
        st.report_fail("Dut_failed_to_get_speed")
    if speed[0] in ['10G', '10000', '1G', '1000']:
        port_fec_no_fec(vars, speed[0], fec=["none", "fc"])
    else:
        port_fec_no_fec(vars, speed[0], fec=["none", "rs"])
    st.report_pass("test_case_passed")


@pytest.mark.regression
@pytest.mark.interface_ft
@pytest.mark.community
@pytest.mark.community_pass
def test_ft_port_fn_verify_shut_noshut():
    if not ipapi.config_ip_addr_interface(vars.D1, interface_name=vars.D1D2P1, ip_address=intf_data.ip_address,
                                          subnet=intf_data.mask, family="ipv4", config='add'):
        st.report_fail("operation_failed")
    if not ipapi.config_ip_addr_interface(vars.D2, interface_name=vars.D2D1P1, ip_address=intf_data.ip_address1,
                                          subnet=intf_data.mask, family="ipv4", config='add'):
        st.report_fail("operation_failed")
    if not ipapi.ping(vars.D1, intf_data.ip_address1, family='ipv4', count=1):
        st.report_fail("ping_fail", intf_data.ip_address, intf_data.ip_address1)
    if not ipapi.ping(vars.D2, intf_data.ip_address, family='ipv4', count=1):
        st.report_fail("ping_fail", intf_data.ip_address1, intf_data.ip_address)
    for _ in range(3):
        intfapi.interface_shutdown(vars.D1, [vars.D1D2P1], skip_verify=True)
        intfapi.interface_noshutdown(vars.D1, [vars.D1D2P1], skip_verify=True)
    if not ipapi.ping(vars.D1, intf_data.ip_address1, family='ipv4', count=5):
        st.report_fail("ping_fail", intf_data.ip_address, intf_data.ip_address1)
    if not ipapi.ping(vars.D2, intf_data.ip_address, family='ipv4', count=1):
        st.report_fail("ping_fail", intf_data.ip_address1, intf_data.ip_address)
    rbapi.config_save_reload(vars.D1)
    if not ipapi.config_ip_addr_interface(vars.D1, interface_name=vars.D1D2P1, ip_address=intf_data.ip_address,
                                          subnet=intf_data.mask, family="ipv4", config='remove'):
        st.report_fail("operation_failed")
    if not ipapi.config_ip_addr_interface(vars.D2, interface_name=vars.D2D1P1, ip_address=intf_data.ip_address1,
                                          subnet=intf_data.mask, family="ipv4", config='remove'):
        st.report_fail("operation_failed")
    for _ in range(3):
        intfapi.interface_shutdown(vars.D1, [vars.D1D2P1], skip_verify=True)
        intfapi.interface_noshutdown(vars.D1, [vars.D1D2P1], skip_verify=True)
    if not st.poll_wait(intfapi.verify_interface_status, 15, vars.D1, vars.D1D2P1, "oper", "up"):
        st.report_fail("interface_is_down_on_dut", [vars.D1D2P1])
    if not st.poll_wait(intfapi.verify_interface_status, 15, vars.D2, vars.D2D1P1, "oper", "up"):
        st.report_fail("interface_is_down_on_dut", [vars.D2D1P1])
    st.report_pass("test_case_passed")


@pytest.mark.regression
@pytest.mark.interface_ft
def test_ft_ovr_counters():
    """
    Author: Ramprakash Reddy (ramprakash-reddy.kanala@broadcom.com)
    Verify tx_ovr and rx_ovr counters should not increment.
    Verify rx_err counters should increment, when framesize is more than MTU.
    """
    flag = 1
    properties = ['rx_ovr','tx_ovr']
    intf_data.port_list = [vars.D1T1P1, vars.D1T1P2]
    intfapi.clear_interface_counters(vars.D1)
    intf_data.tg.tg_traffic_control(action='clear_stats', port_handle=[intf_data.tg_ph_1, intf_data.tg_ph_2])

    intf_data.tg.tg_traffic_control(action='run', stream_handle=[intf_data.streams['traffic_tg1'],
                                                         intf_data.streams['traffic_tg2']])
    st.wait(intf_data.wait_sec)
    intf_data.tg.tg_traffic_control(action='stop', stream_handle=[intf_data.streams['traffic_tg1'],
                                                         intf_data.streams['traffic_tg2']])
    counters = intfapi.get_interface_counter_value(vars.D1, intf_data.port_list, properties)
    for each_port in intf_data.port_list:
        for each_property in properties:
            value = counters[each_port][each_property]
            if value:
                flag = 0
                st.error("{} counters value expected 0, but found {} for port {}".format(each_property,value,each_port))
    if flag == 1:
        st.log("rx_ovr and tx_ovr counters is not increasing as expected")
    intfapi.clear_interface_counters(vars.D1)
    intfapi.interface_properties_set(vars.D1, vars.D1T1P1, 'mtu', intf_data.mtu)
    intf_data.tg.tg_traffic_control(action='clear_stats', port_handle=[intf_data.tg_ph_1])
    intf_data.tg.tg_traffic_control(action='run', stream_handle=intf_data.streams['traffic_tg1'])
    st.wait(intf_data.wait_sec)
    intf_data.tg.tg_traffic_control(action='stop', stream_handle=intf_data.streams['traffic_tg1'])
    rx_err = intfapi.get_interface_counter_value(vars.D1, vars.D1T1P1,
                                                     properties="rx_err")[vars.D1T1P1]['rx_err']

    if not rx_err:
        st.report_fail("interface_rx_err_counters_fail", vars.D1T1P1)
    if flag == 1:
        st.log("rx_err counters is increasing as expected")
    if flag == 0:
        st.report_fail("test_case_failed")
    st.report_pass("test_case_passed")
