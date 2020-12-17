import pytest

from spytest import st, tgapi, SpyTestDict
from spytest.utils import random_vlan_list

import apis.switching.vlan as vlan
import apis.system.logging as slog
import apis.switching.mac as mac
import apis.system.storm_control as scapi
import apis.system.interface as ifapi
import apis.switching.portchannel as portchannel
import apis.system.reboot as reboot
import apis.common.wait as waitapi
import apis.system.basic as basic_obj
import apis.system.snmp as snmp_obj

import utilities.utils as utils
from utilities.common import poll_wait
from utilities.parallel import  exec_all,ensure_no_exception

sc_data = SpyTestDict()
tg_info = dict()

@pytest.fixture(scope="module", autouse=True)
def vlan_module_hooks(request):
    global vars
    vars = st.ensure_min_topology("D1D2:2", "D1T1:2", "D2T1:2")
    sc_data.version_data = basic_obj.show_version(vars.D1)
    vlan_variables()
    if not st.is_feature_supported("vlan-range", vars.D1):
        sc_data.max_vlan = 100
    [_, exceptions] = exec_all(True, [[config_tg_stream], [vlan_module_prolog]], first_on_main=True)
    ensure_no_exception(exceptions)
    yield
    vlan.clear_vlan_configuration(st.get_dut_names(), thread=False)


@pytest.fixture(scope="function", autouse=True)
def vlan_func_hooks(request):
    bum_test_functions = ["test_ft_stormcontrol_verification", "test_ft_stormcontrol_portchannel_intf",
                          "test_ft_stormcontrol_incremental_bps_max_vlan",
                          "test_ft_stormcontrol_fast_reboot", "test_ft_stormcontrol_warm_reboot"]
    if st.get_func_name(request) in bum_test_functions:
        platform_check()
    if request.function.func_name == "test_ft_snmp_max_vlan_scale":
        vlan.clear_vlan_configuration(st.get_dut_names(), thread=False, cli_type="click")
        portchannel.clear_portchannel_configuration(st.get_dut_names(), thread=True)
    yield


def platform_check():
        if sc_data.version_data['hwsku'].lower() in hw_constants_DUT['TH3_PLATFORMS']:
            st.log("--- Detected BUM UnSupported Platform..")
            st.report_unsupported("storm_control_unsupported")


def vlan_variables():
    global tg
    global tg_handler,hw_constants_DUT
    sc_data.cli_type_click = "click"
    sc_data.cli_type= st.get_ui_type(vars.D1, cli_type="")
    sc_data.vlan_list = random_vlan_list(count=2)
    sc_data.vlan_id = str(sc_data.vlan_list[0])
    sc_data.vlan = str(sc_data.vlan_list[1])
    sc_data.kbps = 1000
    sc_data.frame_size = 68
    sc_data.rate_pps =5000
    sc_data.packets = (sc_data.kbps*1024)/(sc_data.frame_size*8)
    sc_data.bum_deviation = int(0.10 * sc_data.packets)
    sc_data.lower_pkt_count = int(sc_data.packets - sc_data.bum_deviation)
    sc_data.higher_pkt_count = int(sc_data.packets + sc_data.bum_deviation)
    sc_data.max_vlan = 4093
    sc_data.source_mac = "00:0A:01:00:00:01"
    sc_data.source_mac1 = "00:0A:02:00:00:01"
    sc_data.line_rate = 100
    sc_data.wait_stream_run = 10
    sc_data.wait_for_stats = 10
    sc_data.free_port = st.get_free_ports(vars.D1)[0]
    tg_handler = tgapi.get_handles_byname("T1D1P1", "T1D1P2", "T1D2P1", "T1D2P2")
    tg = tg_handler["tg"]
    tg_info['tg_info'] = tg_handler
    tg_info['vlan_id'] = sc_data.vlan
    sc_data.vlan_id_start = 1
    sc_data.mac_count = 100
    sc_data.dut_platform = basic_obj.get_hwsku(vars.D1)
    sc_data.vlan_data = [{"dut": [vars.D1], "vlan_id": sc_data.vlan, "tagged": [vars.D1T1P1, vars.D1T1P2]}]
    hw_constants_DUT = st.get_datastore(vars.D1, "constants")
    sc_data.warm_reboot_supported_platforms = hw_constants_DUT['WARM_REBOOT_SUPPORTED_PLATFORMS']
    sc_data.oid_sysName = '1.3.6.1.2.1.1.5.0'
    sc_data.ro_community = 'test_community'
    sc_data.location = 'hyderabad'
    sc_data.oid_dot1qBase = '1.3.6.1.2.1.17.7.1.1'
    sc_data.mgmt_int = 'eth0'


def vlan_module_prolog():
    """
    Module prolog for module configuration
    :return:
    """
    st.log("Creating vlan in device and adding members ...")
    vlan.create_vlan_and_add_members(sc_data.vlan_data)
    if st.is_feature_supported("strom-control", vars.D1):
        st.banner("Configuring BUM Storm control on interfaces")
        interface_list = [vars.D1T1P1, vars.D1T1P2]
        storm_control_type = ["broadcast", "unknown-multicast", "unknown-unicast"]
        for interface in interface_list:
            for stc_type in storm_control_type:
                scapi.config(vars.D1, type=stc_type, action="add", interface_name=interface, bits_per_sec=sc_data.kbps)
                if not scapi.verify_config(vars.D1, interface_name=interface, type=stc_type, rate=sc_data.kbps):
                    st.report_fail("storm_control_config_verify_failed", stc_type, interface)


def config_tg_stream():
    st.log("Traffic Config for verifying BUM storm control feature")
    tg.tg_traffic_control(action="reset", port_handle=tg_handler["tg_ph_list"])
    tg_1 = tg.tg_traffic_config(port_handle=tg_handler["tg_ph_1"], mode='create',
                                transmit_mode='continuous', length_mode='fixed', rate_pps=100,
                                l2_encap='ethernet_ii_vlan', vlan_id=sc_data.vlan, mac_src='00:0a:01:00:00:01',
                                mac_dst='00:0a:02:00:00:01', high_speed_result_analysis=0, vlan="enable",
                                track_by='trackingenabled0 vlanVlanId0', vlan_id_tracking=1,
                                port_handle2=tg_handler["tg_ph_2"],frame_size= sc_data.frame_size)
    tg_info['tg1_stream_id'] = tg_1['stream_id']

    tg_2 = tg.tg_traffic_config(port_handle=tg_handler["tg_ph_2"], mode='create',
                                transmit_mode='continuous', length_mode='fixed', rate_pps=100,
                                l2_encap='ethernet_ii_vlan', vlan_id=sc_data.vlan, mac_src='00:0a:02:00:00:01',
                                mac_dst='00:0a:01:00:00:01', high_speed_result_analysis=0, vlan="enable",
                                track_by='trackingenabled0 vlanVlanId0', vlan_id_tracking=1,
                                port_handle2=tg_handler["tg_ph_1"],frame_size= sc_data.frame_size)
    tg_info['tg2_stream_id'] = tg_2['stream_id']
    return tg_info


def vlan_module_epilog():
    if st.is_feature_supported("strom-control", vars.D1):
        interface_list = [vars.D1T1P1, vars.D1T1P2]
        storm_control_type = ["broadcast", "unknown-multicast", "unknown-unicast"]
        for interface in interface_list:
            for stc_type in storm_control_type:
                scapi.config(vars.D1, type=stc_type, action="del", interface_name=interface, bits_per_sec=sc_data.kbps)
    vlan.clear_vlan_configuration(st.get_dut_names(), thread=False)
    portchannel.clear_portchannel_configuration(st.get_dut_names(),thread=True)


def verify_bum_traffic_mode(mode, tg_stream, skip_traffic_verify=False, duration=10):
    """
    :param mode:
    :param tg_stream:
    :param skip_traffic_verify:
    :param duration:
    :return:
    """
    if mode not in ["unknown-unicast", "unknown-multicast", "broadcast"]:
        st.log("Unsupported mode provided")
        return False
    st.banner("verifying  {} traffic ".format(mode))
    st.log("Clearing stats before sending traffic ...")
    tg.tg_traffic_control(action="clear_stats", port_handle=tg_handler["tg_ph_list"])
    st.wait(2)
    if mode == 'broadcast':
        st.log("Enabling {} traffic ".format(mode))
        tg.tg_traffic_config(port_handle=tg_handler["tg_ph_1"], mode='modify',duration=10, stream_id=tg_stream,
                             mac_src="00:00:00:00:00:01", mac_dst="ff:ff:ff:ff:ff:ff", rate_pps=5000)
    elif mode == 'unknown-multicast':
        st.log("Enabling {} traffic ".format(mode))
        tg.tg_traffic_config(port_handle=tg_handler["tg_ph_1"], mode='modify', duration=10,stream_id=tg_stream,
                             mac_src="00:00:00:00:00:01",mac_dst="01:00:5e:01:02:03",rate_pps=5000)
    elif mode == 'unknown-unicast':
        st.log("Enabling {} traffic ".format(mode))
        tg.tg_traffic_config(port_handle=tg_handler["tg_ph_1"],duration=10, mode='modify', stream_id=tg_stream,
                             mac_src="00:00:00:00:00:01", mac_dst="00:00:00:00:00:02",
                             rate_pps=5000)
    if not skip_traffic_verify:
        ifapi.clear_interface_counters(vars.D1,interface_type="all")
        ifapi.show_interface_counters_all(vars.D1)
        st.log("Starting of traffic from TGen")
        tg.tg_traffic_control(action='run', stream_handle=tg_stream, duration=10)
        st.wait(sc_data.wait_stream_run)
        st.log("Stopping of traffic from TGen to get interface counters")
        tg.tg_traffic_control(action='stop', stream_handle=tg_stream)
        st.wait(sc_data.wait_for_stats)
        ifapi.show_interface_counters_all(vars.D1)
        tg_1_stats = tgapi.get_traffic_stats(tg, mode='aggregate', port_handle=tg_handler["tg_ph_1"], direction='tx')
        tg_2_stats = tgapi.get_traffic_stats(tg, mode='aggregate', port_handle=tg_handler["tg_ph_2"])
        counter = tg_2_stats.rx.total_packets
        counter2 = tg_1_stats.tx.total_packets
        if counter2 == 0:
            st.report_fail("storm_control_traffic_verification_failed")
        counters_avg = counter / duration
        st.log("Average of counters are : {}".format(counters_avg))
        st.log("Higher packet count value is : {}".format(sc_data.higher_pkt_count ))
        st.log("Lower packet count value is : {}".format(sc_data.lower_pkt_count))
        if  counters_avg > sc_data.higher_pkt_count or counters_avg < sc_data.lower_pkt_count:
            st.report_fail("storm_control_traffic_verification_failed")
    return True


def report_result(status, msg_id):
    if status:
        st.report_pass(msg_id)
    else:
        st.report_fail(msg_id)


@pytest.mark.vlan_qa_add
@pytest.mark.community
@pytest.mark.community_fail
def test_ft_add_unknownvlan_interface():
    """
    Author: Surendra Kumar Vella (surendrakumar.vella@broadcom.com)

    verify that DUT should not assign unknown pvid

    """
    st.log(" Adding TGen connected interface {} to non-existing vlan {} with untagged mode".format(vars.D1D2P1,
                                                                                                   sc_data.vlan_id))
    if vlan.add_vlan_member(vars.D1, sc_data.vlan_id, [vars.D1D2P1], tagging_mode=False, skip_error=True):
        st.report_fail("unknown_vlan_untagged_member_add_fail", vars.D1D2P1, sc_data.vlan_id)
    if not vlan.add_vlan_member(vars.D1, sc_data.vlan, [vars.D1D2P1], tagging_mode=True):
        st.report_fail("vlan_tagged_member_fail", vars.D1D2P1, sc_data.vlan)
    if not vlan.delete_vlan_member(vars.D1, sc_data.vlan, vars.D1D2P1, tagging_mode=True):
        st.report_fail("vlan_tagged_member_fail", vars.D1D2P1, sc_data.vlan)
    st.report_pass("test_case_passed")


@pytest.mark.ft_vlan_delete_with_member
@pytest.mark.community
@pytest.mark.community_fail
def test_ft_vlan_delete_with_member():
    """
    Author: Surendra Kumar Vella (surendrakumar.vella@broadcom.com)

    Verify that user is not able to delete a valn till its members are deleted

    """
    vlan_data = [{"dut": [vars.D1], "vlan_id": sc_data.vlan_id, "tagged": [sc_data.free_port]}]
    st.log("checking whether vlan with member is deleted or not ")
    if not vlan.create_vlan_and_add_members(vlan_data):
        st.report_fail("vlan_tagged_member_fail", sc_data.free_port, sc_data.vlan_id)
    if st.is_feature_supported("prevent-delete-vlans-with-members", vars.D1):
        if sc_data.cli_type == "click":
            if vlan.delete_vlan(vars.D1, sc_data.vlan_id):
                st.report_fail("vlan_deletion_successfull_albiet_having_member", sc_data.vlan_id)
            if not vlan.delete_vlan_member(vars.D1, sc_data.vlan_id, sc_data.free_port, tagging_mode=True):
                st.report_fail("vlan_tagged_member_fail", sc_data.free_port, sc_data.vlan_id)
            if not vlan.delete_vlan(vars.D1, sc_data.vlan_id):
                st.report_fail("vlan_delete_fail", sc_data.vlan_id)
        else:
            if not vlan.delete_vlan(vars.D1, sc_data.vlan_id):
                st.report_fail("vlan_delete_fail", sc_data.vlan_id)
    else:
        if not vlan.delete_vlan(vars.D1, sc_data.vlan_id):
            st.report_fail("vlan_delete_fail", sc_data.vlan_id)
    st.report_pass("test_case_passed")


@pytest.mark.vlan_trunk_tagged
@pytest.mark.community
@pytest.mark.community_fail
def test_ft_vlan_trunk_tagged():
    """
    Author:Parvez Alam (parvez.alam@broadcom.com)
    Verify that over vlan trunk tagged packets received and be sent out with tag or without tag determined
    by traffic received from TGen.
    """
    # Start L2 traffic on tg1 and apply vlan_id analayzer filter
    ifapi.clear_interface_counters(vars.D1)
    tg.tg_traffic_control(action="clear_stats", port_handle=tg_handler["tg_ph_list"])
    tg.tg_traffic_control(action='run', stream_handle=[tg_info['tg1_stream_id'], tg_info['tg2_stream_id']], get='vlan_id')
    st.wait(5)
    waitapi.vsonic_mac_learn()
    learned_mac_address = mac.get_mac_all(vars.D1, sc_data.vlan)
    if sc_data.source_mac and sc_data.source_mac1 not in learned_mac_address:
        tg.tg_traffic_control(action='stop', stream_handle=[tg_info['tg1_stream_id'], tg_info['tg2_stream_id']])
        st.report_fail("mac_failed_to_learn_in_Particular_vlan", sc_data.vlan)
    # Stop the traffic and analyzers
    tg.tg_traffic_control(action='stop', stream_handle=[tg_info['tg1_stream_id'], tg_info['tg2_stream_id']])
    st.wait(sc_data.wait_stream_run)
    st.log("Checking the stats and verifying the traffic flow")
    traffic_details = {
        '1': {
            'tx_ports': [vars.T1D1P1],
            'tx_obj': [tg],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D1P2],
            'rx_obj': [tg],
        },
        '2': {
            'tx_ports': [vars.T1D1P2],
            'tx_obj': [tg],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D1P1],
            'rx_obj': [tg],
        }
    }
    aggregate_result = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='aggregate', comp_type='packet_count')

    # get tx-pkt count for each streams on tg1
    traffic_details = {
        '1': {
            'tx_ports': [vars.T1D1P1],
            'tx_obj': [tg],
            'exp_ratio': [1],
            'rx_ports': [vars.T1D1P2],
            'rx_obj': [tg],
            'stream_list': [(tg_info['tg1_stream_id'])],
            'filter_param': [('vlan')],
            'filter_val': [sc_data.vlan],
        }
    }

    # verify analyzer filter statistics
    filter_result = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='filter', comp_type='packet_count')

    if not aggregate_result:
        st.report_fail("traffic_verification_failed")
    elif filter_result:
        st.log("ALl packets with created vlan tagged received on TG2")
        st.report_pass("test_case_passed")
    else:
        st.log("Drop seen on TG2 for Packets with created vlan")
        st.report_fail("test_case_failed")


@pytest.mark.vlan_syslog_verify
@pytest.mark.regression
def test_ft_vlan_syslog_verify():
    """
    Author:Anil Kumar Kacharla <anilkumar.kacharla@broadcom.com>
    Referrence Topology :   Test bed ID:4 D1--Mgmt network
    verify VLAN syslog functionality.
    """
    vars = st.ensure_min_topology("D1")
    sc_data.vlan_test = str(random_vlan_list(1, [int(sc_data.vlan)])[0])
    result = 1
    slog.clear_logging(vars.D1)
    st.log("checking vlan count before vlan addition or deletion")
    count_before_add = slog.get_logging_count(vars.D1, severity="NOTICE", filter_list=["addVlan"])
    count_before_delete = slog.get_logging_count(vars.D1, severity="NOTICE", filter_list=["removeVlan"])
    st.log("vlan count before  adding vlan:{}".format(count_before_add))
    st.log("vlan count before  deleting vlan:{}".format(count_before_delete))
    vlan.create_vlan(vars.D1, sc_data.vlan_test)
    vlan.delete_vlan(vars.D1, sc_data.vlan_test)
    st.log("checking vlan count after adding vlan")
    count_after_add = slog.get_logging_count(vars.D1, severity="NOTICE", filter_list=["addVlan:"])
    st.log("vlan count after  adding vlan:{}".format(count_after_add))
    count_after_delete = slog.get_logging_count(vars.D1, severity="NOTICE", filter_list=["removeVlan:"])
    st.log("vlan count after  deleting vlan:{}".format(count_after_delete))
    if not count_after_add > count_before_add:
        st.error("vlan log count increamented after adding vlan:{}".format(count_after_add))
        result = 0
    if not count_after_delete > count_before_delete:
        st.error("vlan log count increamented after deleting vlan:{}".format(count_after_delete))
        result = 0
    if not result:
        st.report_fail("test_case_fail")
    st.log(" vlan count after adding or deleting vlan is incremented")
    st.report_pass("test_case_passed")


@pytest.mark.stormcontrol
def test_ft_stormcontrol_verification():
    status = 1
    msg_id = "storm_control_traffic_verification_successful"
    new_kbps_value = 1010
    st.log("Module config got passed")
    st.report_tc_pass('ft_stormcontrol_config_all_same_interface', 'test_case_passed')
    if not verify_bum_traffic_mode('broadcast', tg_info['tg1_stream_id'], skip_traffic_verify=False):
        st.error("Broadcast traffic verification got failed")
        status = 0
    if not verify_bum_traffic_mode('unknown-unicast', tg_info['tg1_stream_id'], skip_traffic_verify=False):
        st.error("Unknown-unicast traffic verification got failed")
        status = 0
    if not verify_bum_traffic_mode('unknown-multicast', tg_info['tg1_stream_id'], skip_traffic_verify=False):
        st.error("Unknown-multicast traffic verification got failed")
        status = 0
    if status:
        st.report_tc_pass('ft_stormcontrol_BUM_traffic_policer_params', 'test_case_passed')
        st.report_tc_pass('ft_stormcontrol_traffic_rate_limited_bpsvalue', 'test_case_passed')
    else:
        st.report_tc_fail('ft_stormcontrol_BUM_traffic_policer_params', 'test_case_failed')
        st.report_tc_fail('ft_stormcontrol_traffic_rate_limited_bpsvalue', 'test_case_failed')
    status=1
    st.log("Configuring kbps value on interface to verify kpbs value is independent of interface")
    scapi.config(vars.D1, type="broadcast", action="add", interface_name=vars.D1T1P1, bits_per_sec=new_kbps_value)
    if not scapi.verify_config(vars.D1, interface_name=vars.D1T1P1, type="broadcast", rate=new_kbps_value):
        st.error("KBPS value configured on interface is dependent to other interface")
        status = 0
    if status:
        st.report_tc_pass('ft_stormcontrol_bps_intf_indp', 'test_case_passed')
        st.report_tc_pass('ft_stormcontrol_bps_overwrite_new_bps_value', 'test_case_passed')
    else:
        st.report_tc_fail('ft_stormcontrol_bps_intf_indp', 'test_case_failed')
        st.report_tc_fail('ft_stormcontrol_bps_overwrite_new_bps_value', 'test_case_failed')
    status = 1
    st.log("configuring back to previous config")
    scapi.config(vars.D1, type="broadcast", action="add", interface_name=vars.D1T1P1, bits_per_sec=sc_data.kbps)
    scapi.verify_config(vars.D1, interface_name=vars.D1T1P1, type="broadcast", rate=sc_data.kbps)
    if not verify_bum_traffic_mode('broadcast', tg_info['tg1_stream_id'], skip_traffic_verify=False):
        st.error("Broadcast traffic verification got failed")
        status = 0
    if status:
        st.report_tc_pass('ft_stormcontrol_config_clear_noaffect_traffic', 'test_case_passed')
    else:
        st.report_tc_fail('ft_stormcontrol_config_clear_noaffect_traffic', 'test_case_failed')
    status = 1
    st.log("clearing bum traffic type to verify othertraffic does not effect bum storm-control")
    scapi.config(vars.D1, type="unknown-unicast", action="del", interface_name=vars.D1T1P1, bits_per_sec=sc_data.kbps)
    st.log("verifying the other traffic is not get effected.")
    if not verify_bum_traffic_mode('unknown-unicast', tg_info['tg1_stream_id'], skip_traffic_verify=True):
        st.error("Other_traffic traffic verification got failed")
        status = 0
    if status:
        st.report_tc_pass('ft_stormcontrol_config_unaffect_other_traffic', 'test_case_passed')
    else:
        st.report_tc_fail('ft_stormcontrol_config_unaffect_other_traffic', 'test_case_failed')
    st.log("configuring back to previous config")
    scapi.config(vars.D1, type="unknown-unicast", action="add", interface_name=vars.D1T1P1, bits_per_sec=sc_data.kbps)
    if not status:
        msg_id = "storm_control_traffic_verification_failed"
    report_result(status, msg_id)


@pytest.mark.stormcontrol
def test_ft_stormcontrol_portchannel_intf():
    status = 1
    msg_id = "storm_control_portchannel_verification_successful"
    portchannel_name = 'PortChannel13'
    vlan_info = [{"dut": [vars.D2], "vlan_id": sc_data.vlan, "tagged": [vars.D2T1P1, vars.D2T1P2, portchannel_name]}]
    portchannel_interfaces_dut1 = [vars.D1D2P1, vars.D1D2P2]
    portchannel_interfaces_dut2 = [vars.D2D1P1, vars.D2D1P2]
    portchannel.config_portchannel(vars.D1, vars.D2, portchannel_name, portchannel_interfaces_dut1,
                                   portchannel_interfaces_dut2,
                                   config="add", thread=True)
    vlan.add_vlan_member(vars.D1, sc_data.vlan, portchannel_name, tagging_mode=True)
    vlan.create_vlan_and_add_members(vlan_info)
    st.log("Verifying whether stormcontrol config can be applied on portchannel {} interfaces".format(portchannel_name))
    if scapi.config(vars.D1, type="broadcast", action="add", interface_name=portchannel_name, rate=sc_data.kbps,
                    skip_error_check=True):
        st.error("storm-control config can be applied on portchannel interface")
        status = 0
    else:
        st.log("storm-control config cannot be applied on portchannel interface.")
    if status:
        st.report_tc_pass('ft_stormcontrol_neg_config_vlan_portchannel', 'test_case_passed')
    else:
        st.report_tc_fail('ft_stormcontrol_neg_config_vlan_portchannel', 'test_case_failed')
    status = 1
    st.log("configuring bum stormcontrol on portchannel interfaces")
    scapi.config(vars.D1, type="broadcast", action="del", interface_name=vars.D1T1P1, bits_per_sec=sc_data.kbps)
    scapi.config(vars.D1, type="broadcast", action="del", interface_name=vars.D1T1P2, bits_per_sec=sc_data.kbps)
    scapi.config(vars.D2, type="broadcast", action="add", interface_name=vars.D2D1P1,  bits_per_sec=sc_data.kbps)
    scapi.config(vars.D2, type="broadcast", action="add", interface_name=vars.D2D1P2, bits_per_sec=sc_data.kbps)
    verify_bum_traffic_mode('broadcast', tg_info['tg1_stream_id'], skip_traffic_verify=True)
    st.log("Clearing interface counters")
    ifapi.clear_interface_counters(vars.D2)
    tg.tg_traffic_control(action='run',stream_handle=tg_info['tg1_stream_id'], duration=10)
    st.wait(sc_data.wait_stream_run)
    st.log("Stopping of traffic from TGen to get interface counters")
    tg.tg_traffic_control(action='stop', stream_handle=tg_info['tg1_stream_id'])
    st.wait(sc_data.wait_for_stats)
    tg_1_stats = tgapi.get_traffic_stats(tg, mode='aggregate', port_handle=tg_handler["tg_ph_1"])
    tg_3_stats = tgapi.get_traffic_stats(tg, mode='aggregate', port_handle=tg_handler["tg_ph_3"])
    counter = tg_3_stats.rx.total_packets
    counter2 = tg_1_stats.tx.total_packets
    try:
        time = int(counter2 / sc_data.rate_pps)
        counters_avg = counter / time
    except Exception:
        counters_avg = 0
    st.log("Average of counters are : {}".format(counters_avg))
    st.log("Higher packet count value is : {}".format(sc_data.higher_pkt_count))
    st.log("Lower packet count value is : {}".format(sc_data.lower_pkt_count))
    st.log("value of status is : {}".format(status))
    if counters_avg > sc_data.higher_pkt_count or counters_avg < sc_data.lower_pkt_count:
        st.error("storm control traffic verification failed")
        status = 0
    if status:
        st.report_tc_pass('ft_stormcontrol_portchannel_intf', 'test_case_passed')
    else:
        st.report_tc_fail('ft_stormcontrol_portchannel_intf', 'test_case_failed')
    status = 1
    st.log("Configuring stormcontrol without providing bps value")
    if scapi.config(vars.D1, type="broadcast", action="add", interface_name=vars.D1T1P1, skip_error_check=True):
        st.error("Storm-control config is accepting not throwing any error")
        status = 0
    else:
        st.log("Config is not accepted and thrown an error")
    if status:
        st.report_tc_pass('ft_stormcontrol_neg_config_without_bpsvalue', 'test_case_passed')
    else:
        st.report_tc_fail('ft_stormcontrol_neg_config_without_bpsvalue', 'test_case_failed')
    status = 1
    st.log("unconfiguring of bum stormcontrol type by providing bps value")
    if scapi.config(vars.D1, type="broadcast", action="del", interface_name=vars.D1T1P1, rate=sc_data.kbps,
                    skip_error_check=True):
        st.error("Storm-control config is removed and not throwing any error")
        status = 0
    else:
        st.log("Config is not accepted and thrown an error")
    if status:
        st.report_tc_pass('ft_stormcontrol_neg_unconfig_with_bpsvalue', 'test_case_passed')
    else:
        st.report_tc_fail('ft_stormcontrol_neg_unconfig_with_bpsvalue', 'test_case_failed')

    st.log("Back to module config")
    scapi.config(vars.D2, type="broadcast", action="del", interface_name=vars.D2D1P1,  bits_per_sec=sc_data.kbps)
    scapi.config(vars.D2, type="broadcast", action="del", interface_name=vars.D2D1P2,   bits_per_sec=sc_data.kbps)
    scapi.config(vars.D1, type="broadcast", action="add", interface_name=vars.D1T1P1,  bits_per_sec=sc_data.kbps)
    scapi.config(vars.D1, type="broadcast", action="add", interface_name=vars.D1T1P2,   bits_per_sec=sc_data.kbps)
    st.log("Unconfiguring portchannel config in both devices and only vlan configuration in device2")
    vlan.clear_vlan_configuration(vars.D2)
    vlan.delete_vlan_member(vars.D1, sc_data.vlan, portchannel_name, tagging_mode=True)
    portchannel.clear_portchannel_configuration(st.get_dut_names(), thread=True)
    if not status:
        msg_id = "storm_control_portchannel_verification_failed"
    report_result(status, msg_id)


@pytest.mark.stormcontrol
def test_ft_stormcontrol_incremental_bps_max_vlan():
    status = 1
    counters_avg =0
    msg_id = "storm_control_traffic_incremental_bps_max_vlan_successful"
    initial_kbps_value = 600
    last_kbps_value = 1000
    interface_list = [vars.D1T1P1, vars.D1T1P2]
    for kbps_value in range(initial_kbps_value, last_kbps_value, 200):
        for interf in interface_list:
            scapi.config(vars.D1, type="broadcast", action="add", interface_name=interf, bits_per_sec=kbps_value)
            if not scapi.verify_config(vars.D1, interface_name=interf, type="broadcast", rate=kbps_value):
                st.error("incremental kbps is not working")
                status = 0
        sc_data.packets = (kbps_value * 1024) / (sc_data.frame_size * 8)
        sc_data.bum_deviation1 = int(0.10 * sc_data.packets)
        sc_data.lower_pkt_cnt = int(sc_data.packets - sc_data.bum_deviation1)
        sc_data.higher_pkt_cnt = int(sc_data.packets + sc_data.bum_deviation1)
        for _ in range(1,3,1):
            verify_bum_traffic_mode('broadcast', tg_info['tg1_stream_id'], skip_traffic_verify=True)
            st.log("Clearing interface counters")
            ifapi.clear_interface_counters(vars.D1)
            st.log("Starting of traffic from TGen")
            tg.tg_traffic_control(action='run',stream_handle=tg_info['tg1_stream_id'], duration=10)
            st.wait(sc_data.wait_stream_run)
            st.log("Stopping of traffic from TGen to get counters")
            tg.tg_traffic_control(action='stop', stream_handle=tg_info['tg1_stream_id'])
            st.wait(sc_data.wait_for_stats)
            tg_1_stats = tgapi.get_traffic_stats(tg, mode='aggregate', port_handle=tg_handler["tg_ph_1"])
            tg_2_stats = tgapi.get_traffic_stats(tg, mode='aggregate', port_handle=tg_handler["tg_ph_2"])
            counter = tg_2_stats.rx.total_packets
            counter2 = tg_1_stats.tx.total_packets
            try:
                time = int(counter2 / sc_data.rate_pps)
                counters_avg = counter / time
            except Exception:
                counters_avg = 0
            st.log("Average of counters are : {}".format(counters_avg))
            st.log("Higher packet count value is : {}".format(sc_data.higher_pkt_cnt))
            st.log("Lower packet count value is : {}".format(sc_data.lower_pkt_cnt))
            st.log("value of status is : {}".format(status))
            if counters_avg <= sc_data.higher_pkt_cnt and counters_avg >= sc_data.lower_pkt_cnt:
                break
        if  counters_avg > sc_data.higher_pkt_cnt or counters_avg < sc_data.lower_pkt_cnt:
            st.error("storm control traffic verification failed")
            status = 0
    st.log("Unconfiguring back to previous config")
    for interf in interface_list:
        scapi.config(vars.D1, type="broadcast", action="add", interface_name=interf, bits_per_sec=sc_data.kbps)
    if not status:
        msg_id = "storm_control_traffic_incremental_bps_max_vlan_failed"
    report_result(status, msg_id)


@pytest.mark.stormcontrol
def test_ft_stormcontrol_fast_reboot():
    status = 1
    interface_list = [vars.D1T1P1, vars.D1T1P2]
    storm_control_type = ["broadcast", "unknown-multicast", "unknown-unicast"]
    msg_id = "storm_control_reboot_successful"
    utils.banner_log("Verifying BUM storm control before fast reboot")
    if not verify_bum_traffic_mode('broadcast', tg_info['tg1_stream_id'], skip_traffic_verify=False):
        st.error("Broadcast traffic verification got failed")
        status = 0
    st.log("performing Config save")
    reboot.config_save(vars.D1)
    #############################################################################################
    utils.banner_log("Performing fast-reboot operation --STARTED")
    #############################################################################################
    st.log("performing fast-reboot")
    st.reboot(vars.D1, 'fast')
    #############################################################################################
    utils.banner_log("Performing fast-reboot operation --COMPLETED")
    #############################################################################################
    for interface in interface_list:
        for stc_type in storm_control_type:
            if not scapi.verify_config(vars.D1, interface_name=interface, type=stc_type, rate=sc_data.kbps):
                st.report_fail("storm_control_config_verify_failed", stc_type, interface)
                status = 0
    st.log("Traffic Config for verifying BUM storm control feature")
    tg.tg_traffic_control(action="reset", port_handle=tg_handler["tg_ph_list"])
    tg_1 = tg.tg_traffic_config(port_handle=tg_handler["tg_ph_1"], mode='create', rate_pps=5000, duration=10,
                                l2_encap = 'ethernet_ii_vlan', vlan_id = sc_data.vlan, mac_src = "00:00:00:00:00:01",
                                mac_dst = "ff:ff:ff:ff:ff:ff", high_speed_result_analysis = 0, vlan = "enable",
                                port_handle2 = tg_handler["tg_ph_2"], frame_size = sc_data.frame_size, length_mode='fixed')
    tg_info['tg1_stream_id'] = tg_1['stream_id']
    utils.banner_log("Verifying BUM storm control after fast reboot")
    if not verify_bum_traffic_mode('broadcast', tg_info['tg1_stream_id'], skip_traffic_verify=False):
        st.error("Broadcast traffic verification got failed")
        status = 0
    if not status:
        msg_id = "storm_control_reboot_failed"
    report_result(status, msg_id)


@pytest.mark.stormcontrol
def test_ft_stormcontrol_warm_reboot():
    status = 1
    interface_list = [vars.D1T1P1, vars.D1T1P2]
    storm_control_type = ["broadcast", "unknown-multicast", "unknown-unicast"]
    msg_id = "storm_control_reboot_successful"
    utils.banner_log("Verifying BUM storm control before warm reboot")
    if not verify_bum_traffic_mode('broadcast', tg_info['tg1_stream_id'], skip_traffic_verify=False):
        st.error("Broadcast traffic verification got failed")
        status = 0
    st.log("performing Config save")
    reboot.config_save(vars.D1)
    #############################################################################################
    utils.banner_log("Performing warm-reboot operation --STARTED")
    #############################################################################################
    st.log("performing warm-reboot")
    st.reboot(vars.D1, 'warm')
    #############################################################################################
    utils.banner_log("Performing warm-reboot operation --COMPLETED")
    #############################################################################################
    for interface in interface_list:
        for stc_type in storm_control_type:
            if not scapi.verify_config(vars.D1, interface_name=interface, type=stc_type, rate=sc_data.kbps):
                st.report_fail("storm_control_config_verify_failed", stc_type, interface)
                status = 0
    st.log("Traffic Config for verifying BUM storm control feature")
    tg.tg_traffic_control(action="reset", port_handle=tg_handler["tg_ph_list"])
    tg_1 = tg.tg_traffic_config(port_handle=tg_handler["tg_ph_1"], mode='create', rate_pps=5000, duration=10,
                                l2_encap = 'ethernet_ii_vlan', vlan_id = sc_data.vlan, mac_src = "00:00:00:00:00:01",
                                mac_dst = "ff:ff:ff:ff:ff:ff", high_speed_result_analysis = 0, vlan = "enable",
                                port_handle2 = tg_handler["tg_ph_2"], frame_size = sc_data.frame_size, length_mode='fixed')
    tg_info['tg1_stream_id'] = tg_1['stream_id']
    utils.banner_log("Verifying BUM storm control after warm reboot")
    if not verify_bum_traffic_mode('broadcast', tg_info['tg1_stream_id'], skip_traffic_verify=False):
        st.error("Broadcast traffic verification got failed")
        status = 0
    if not status:
        msg_id = "storm_control_reboot_failed"
    if status:
        st.report_tc_pass('ft_stormcontrol_config_active_intf_warmboot', 'test_case_passed')
        st.report_tc_pass('ft_stormcontrol_rate_limit_across_warmboot', 'test_case_passed')
        st.report_tc_pass('ft_stormcontrol_config_restore_warmboot', 'test_case_passed')
    else:
        st.report_tc_fail('ft_stormcontrol_config_active_intf_warmboot', 'test_case_failed')
        st.report_tc_fail('ft_stormcontrol_rate_limit_across_warmboot', 'test_case_failed')
        st.report_tc_fail('ft_stormcontrol_config_restore_warmboot', 'test_case_failed')
    report_result(status, msg_id)


def vlan_module_config(config='yes'):
    if config == 'yes':
        st.log("Creating max number of vlans")
        max_vlan_create()
        max_vlan_verify()
        add_vlan_members()
    else:
        vlan.clear_vlan_configuration([vars.D1])


def max_vlan_create():
    vlan.config_vlan_range(vars.D1, "1 {}".format(sc_data.max_vlan), config='add')


def max_vlan_verify():
    st.log("verifying whether max vlans are created or not")
    if not len(vlan.get_vlan_list(vars.D1)) == sc_data.max_vlan:
        st.error("max_vlan_creation_failed")
        return False
    else:
        st.log("creation of max vlans is successful")
    return True


def add_vlan_members():
    st.log("Participating TGen connected interfaces into max vlans")
    vlan.config_vlan_range_members(vars.D1, "1 {}".format(sc_data.max_vlan), vars.D1T1P1, config='add')
    vlan.config_vlan_range_members(vars.D1, "1 {}".format(sc_data.max_vlan), vars.D1T1P2, config='add')

def mac_verify():
    mac_count = mac.get_mac_address_count(vars.D1, vlan=sc_data.vlan, port=vars.D1T1P1, type=None,
                                              mac_search=None)
    st.log("Total mac address learnt are : {}".format(mac_count))
    if int(mac_count) != sc_data.mac_count:
        st.error("mac_address_verification_fail")
        return False
    else:
        st.log("Mac address verification got passed")
    return True


@pytest.mark.vlan_reboot_config_fast_reboot
def test_ft_vlan_save_config_warm_and_fast_reboot():
    '''
    Author: Sai Durga <pchvsai.durga@broadcom.com>
    This script covers the below scenarios

    ft_max_vlan_save_reload	    Verify the save and reload functionality with max vlan configuration.
    ft_max_vlan_fast_reload	    Verify the max vlan configuration is retained after fast-reboot.
    FtOpSoSwVlFn026	            Verify that VLAN is present and traffic is not disturbed during and after warm reboot
    FtOpSoSysFRFn005            Verify the Fast-Reboot must disrupt control plane not more than 90 seconds (from sonic test suite -configuration tests)
    ft_reboot_fdb_fast_reboot   Verify that the FDB entry is retained after fast reboot.

    '''
    status = True
    msg_id = "max_vlan_config_retain_after_save_fast_warm_reboot"
    vlan_module_epilog()
    vlan_module_config(config='yes')
    st.log("Device name is : {}".format(sc_data.dut_platform))

    st.log("Saving the MAX VLAN config on the device")
    reboot.config_save(vars.D1)

    st.log("Performing reboot and checking the VLAN configuration")
    st.reboot(vars.D1)
    st.log("Checking VLAN config after reboot")
    max_vlan_verify()

    st.log(
        "Sending traffic with 100 MAC,Checking FDB table updated with 100 MAC addresses and performing reboot and checking the VLAN configuration")
    tg.tg_traffic_control(action="reset", port_handle=tg_handler["tg_ph_list"])
    tg_1 = tg.tg_traffic_config(port_handle=tg_handler["tg_ph_1"], mode='create', length_mode='fixed',
                         frame_size=72,
                         mac_src='00:01:00:00:00:01', mac_src_step='00:00:00:00:00:01',
                         mac_src_mode='increment', mac_src_count=sc_data.mac_count,
                         mac_dst='00:02:00:00:00:02',
                         rate_pps=2000, l2_encap='ethernet_ii_vlan', vlan="enable",
                         vlan_id=sc_data.vlan,
                         transmit_mode='continuous')
    tg_info['tg1_stream_id'] = tg_1['stream_id']
    tg.tg_traffic_control(action='run', stream_handle=tg_info['tg1_stream_id'])
    st.wait(2)
    tg.tg_traffic_control(action='stop', stream_handle=tg_info['tg1_stream_id'])

    if not poll_wait(mac_verify, 300):
        st.error("mac_address_verification_fail")

    st.log("Performing fast-reboot and checking the VLAN configuration")
    st.reboot(vars.D1, 'fast')
    st.log("Checking VLAN config after fast-reboot")
    max_vlan_verify()
    st.log("Sending traffic after fast reboot and checking the FDB table")
    tg.tg_traffic_control(action='run', stream_handle=tg_info['tg1_stream_id'])
    st.wait(2)
    tg.tg_traffic_control(action='stop', stream_handle=tg_info['tg1_stream_id'])

    if not poll_wait(mac_verify, 300):
        st.error("mac_address_verification_fail")

    st.log("Performing warm reboot and checking the traffic")
    ifapi.clear_interface_counters(vars.D1)
    st.wait(2)
    ifapi.show_interface_counters_all(vars.D1)
    st.wait(2)
    tg.tg_traffic_control(action='run', stream_handle=tg_info['tg1_stream_id'])
    st.wait(2)
    st.reboot(vars.D1, 'warm')
    st.log("Checking VLAN config after warm-reboot")
    max_vlan_verify()
    tg.tg_traffic_control(action='stop', stream_handle=tg_info['tg1_stream_id'])
    st.log("Checking traffic is forwarded without any loss after warm-reboot")
    st.log("Fetching TGen statistics")
    st.wait(2)
    ifapi.show_interface_counters_all(vars.D1)

    stats_tg1 = tgapi.get_traffic_stats(tg, mode="aggregate", port_handle=tg_handler["tg_ph_1"])
    total_tx_tg1 = stats_tg1.tx.total_bytes

    stats_tg2 = tgapi.get_traffic_stats(tg, mode="aggregate", port_handle=tg_handler["tg_ph_2"])
    total_rx_tg2 = stats_tg2.rx.total_bytes

    percentage_95_total_tx_tg1 = (95 * int(total_tx_tg1)) / 100
    st.log("###############")
    st.log("Sent bytes: {} and Received bytes : {}".format(percentage_95_total_tx_tg1, total_rx_tg2))
    st.log("##############")
    if int(percentage_95_total_tx_tg1) > int(total_rx_tg2):
        st.report_fail("traffic_transmission_failed", vars.T1D1P1)

    report_result(status, msg_id)

@pytest.mark.snmp_hardening
def test_ft_snmp_max_vlan_scale():
    '''
    Author: Prasad Darnasi <prasad.darnasi@broadcom.com>
    verify The BRIDGE-MIB requirements functionality by scaling DUT with max Vlans
    '''

    vlan_module_config(config='yes')

    st.log("Checking VLAN config after reboot")
    max_vlan_verify()
    global ipaddress
    ipaddress_list = basic_obj.get_ifconfig_inet(vars.D1, sc_data.mgmt_int)
    st.log("Checking Ip address of the Device ")
    if not ipaddress_list:
        st.report_env_fail("ip_verification_fail")
    ipaddress = ipaddress_list[0]
    st.log("Device ip addresse - {}".format(ipaddress))
    snmp_obj.set_snmp_config(vars.D1, snmp_rocommunity=sc_data.ro_community, snmp_location=sc_data.location)
    if not snmp_obj.poll_for_snmp(vars.D1, 30, 1, ipaddress=ipaddress,
                                  oid=sc_data.oid_sysName, community_name=sc_data.ro_community):
        st.log("Post SNMP config , snmp is not working")
        st.report_fail("operation_failed")
    basic_obj.get_top_info(vars.D1, proc_name='snmpd')
    get_snmp_output = snmp_obj.poll_for_snmp_walk(vars.D1, 15, 1, ipaddress=ipaddress, oid=sc_data.oid_dot1qBase,
                                                  community_name=sc_data.ro_community)
    if not get_snmp_output:
        st.report_fail("get_snmp_output_fail")
    st.report_pass("test_case_passed")
