import pytest

from spytest import st, tgapi, SpyTestDict
from spytest.utils import poll_wait

import tests.qos.wred_ecn_config_json as wred_config
import apis.qos.qos as qos_obj
import apis.system.switch_configuration as sconf_obj
import apis.switching.vlan as vlan_obj
import apis.common.asic as asicapi
import apis.qos.cos as cos_obj
from apis.qos.wred import apply_wred_ecn_config
import apis.switching.mac as mac_obj
import apis.system.interface as ifapi
import utilities.common as utils

data = SpyTestDict()
data.ageout_time = 600
data.rate_percent = 100
data.vlan = 555
data.dscp_dest_mac = "00:00:00:00:00:03"
data.dscp_src1 = "00:00:00:00:00:01"
data.dscp_src2 = "00:00:00:00:00:02"
data.vlan_priority1 = "4"
data.cos_name = "COS"
data.dscp_name = "DSCP"
data.queue = "5"

@pytest.fixture(scope="module", autouse=True)
def wred_module_hooks(request):
    # add things at the start of this module
    global vars
    vars = st.ensure_min_topology("D1T1:3")
    wred_data = wred_config.init_vars(vars, apply_wred=True)
    st.log('Creating WRED table')
    utils.exec_all(True, [utils.ExecAllFunc(apply_wred_ecn_config, vars.D1, wred_data['wred_config_json'])])

    st.log("Getting TG handlers")
    data.tg1, data.tg_ph_1 = tgapi.get_handle_byname("T1D1P1")
    data.tg2, data.tg_ph_2 = tgapi.get_handle_byname("T1D1P2")
    data.tg3, data.tg_ph_3 = tgapi.get_handle_byname("T1D1P3")
    data.tg = data.tg1

    st.log("Reset and clear statistics of TG ports")
    data.tg.tg_traffic_control(action='reset', port_handle=[data.tg_ph_1, data.tg_ph_2, data.tg_ph_3])
    data.tg.tg_traffic_control(action='clear_stats', port_handle=[data.tg_ph_1, data.tg_ph_2, data.tg_ph_3])
    st.log("Creating TG streams")
    data.streams = {}
    stream = data.tg.tg_traffic_config(port_handle=data.tg_ph_3, mode='create', length_mode='fixed', frame_size=64,
                                       pkts_per_burst=10, l2_encap='ethernet_ii_vlan', transmit_mode='single_burst',
                                       vlan_id=data.vlan, mac_src=data.dscp_dest_mac, mac_dst='00:0a:12:00:00:01',
                                       vlan="enable")
    data.streams['vlan_tagged_egress'] = stream['stream_id']
    stream = data.tg.tg_traffic_config(port_handle=data.tg_ph_1, mode='create', transmit_mode='continuous',
                                       length_mode='fixed', rate_percent=10, l2_encap='ethernet_ii_vlan',
                                       vlan_id=data.vlan, vlan="enable",
                                       mac_src=data.dscp_src1, mac_dst=data.dscp_dest_mac, l3_protocol='ipv4',
                                       ip_src_addr='1.1.1.1', ip_dst_addr='5.5.5.5',
                                       ip_dscp="8", high_speed_result_analysis=0,
                                       track_by='trackingenabled0 ipv4DefaultPhb0',
                                       ip_dscp_tracking=1)
    data.streams['dscp1']= stream['stream_id']
    stream = data.tg.tg_traffic_config(port_handle=data.tg_ph_1, mode='create', transmit_mode='continuous',
                                       length_mode='fixed', rate_percent=10, l2_encap='ethernet_ii_vlan',
                                       vlan_id=data.vlan, vlan="enable",
                                       mac_src=data.dscp_src2, mac_dst=data.dscp_dest_mac, l3_protocol='ipv4',
                                       ip_src_addr='1.1.1.1', ip_dst_addr='5.5.5.5',
                                       ip_dscp="24", high_speed_result_analysis=0,
                                       track_by='trackingenabled0 ipv4DefaultPhb0',
                                       ip_dscp_tracking=1)
    data.streams['dscp2'] = stream['stream_id']
    yield
    #clearing WRED config
    qos_obj.clear_qos_config(vars.D1)
    vlan_obj.clear_vlan_configuration(vars.D1, thread=True)


@pytest.fixture(scope="function", autouse=True)
def wred_func_hooks(request):
    # add things at the start every test case
    # use 'st.get_func_name(request)' to compare
    # if any thing specific a particular test case
    yield
    # add things at the end of this module"


def wred_running_config():
    if not sconf_obj.verify_running_config(vars.D1, "WRED_PROFILE", "WRED", "green_max_threshold","900000",):
        st.report_fail("wred_config_not_updated_in_config_db")

def configuring_tc_to_queue_map():
    cos_obj.config_tc_to_queue_map(vars.D1, data.cos_name, {"3": "3", "4": "4",})

def configuring_dscp_to_tc_map():
    cos_obj.config_dscp_to_tc_map(vars.D1, data.dscp_name, {"8": "3", "24": "4",})

def binding_queue_map_to_interfaces():
    qos_maps = [{'port': vars.D1T1P1, 'map': 'tc_to_queue_map', 'obj_name': data.cos_name}, {'port': vars.D1T1P1, 'map': 'dscp_to_tc_map', 'obj_name': data.dscp_name}, {'port': vars.D1T1P2, 'map': 'tc_to_queue_map', 'obj_name': data.cos_name}, {'port': vars.D1T1P2, 'map': 'dscp_to_tc_map', 'obj_name': data.dscp_name}, {'port': vars.D1T1P3, 'map': 'tc_to_queue_map', 'obj_name': data.cos_name}, {'port': vars.D1T1P3, 'map': 'dscp_to_tc_map', 'obj_name': data.dscp_name}]
    cos_obj.config_port_qos_map_all(vars.D1, qos_maps)


def fdb_config():
    mac_obj.config_mac_agetime(vars.D1, data.ageout_time)
    if not (mac_obj.get_mac_agetime(vars.D1) == data.ageout_time):
        st.report_fail("mac_aging_time_failed_config")

def vlan_config():
    vlan_obj.create_vlan(vars.D1, data.vlan)
    st.log("Adding TGen port connected interface to the vlan with tagging mode")
    if not vlan_obj.add_vlan_member(vars.D1, data.vlan, [vars.D1T1P1, vars.D1T1P2, vars.D1T1P3], tagging_mode=True):
        st.report_fail("vlan_tagged_member_fail")
    if not vlan_obj.verify_vlan_brief(vars.D1, data.vlan):
        st.report_fail("vlan_create_fail",data.vlan)

def cos_counters_checking(value=None):
    queue_dict_list = asicapi.get_counters(vars.D1)
    for queue_dict in queue_dict_list:
        if (queue_dict['key'] == 'WRED_PKT_GRE.'):
            if int(queue_dict['value'].replace(",", "")) == 0:
                st.error("{} queue_traffic_failed".format(value))
                return False
    return True

@pytest.mark.wred
@pytest.mark.qos_wred_ecn
@pytest.mark.community_unsupported
def test_ft_wred_functionality():
    """
    Author : Sai Durga <pchvsai.durga@broadcom.com>
    FtOpSoQsWdFn012 : Verify that WRED fnctionality working fine and WRED green drop counters incremented properly.
    Setup:
    ===========
    DUT-----3---- TGen

    Procedure:
    ===========
    1. Create a VLAN 10 and participate all the 3 ports in VLAN 10.
    2. Send tagged traffic from 3rd port and check the FDB table.
    3. Now configure WRED, dscp_to_tc_map and tc to queue map tables and bind it to 3 ports.
    4. Now send matched traffic from port1 to port3 and unmatched traffic from port2 to port3.

    Expected Results:
    =====================
    1. Verify that VLAN 10 created and all the 3 ports added to vlan 10
    2. Verify that FDB table updated with 3rd port MAC addresses.
    3. Verify that WRED, dscp_to_tc_map and tc to queue map tables created and binded to 3 ports
    5. Verify that matched traffic forwared to configured queues based on the min and max threshold values and unmatched traffic is dropped and WRED green incremented properly.


    """


    st.log("Configuring MAC age time out")
    fdb_config()
    st.log("Creating vlan and adding the TGen connected ports to it")
    vlan_config()
    st.log("Clearing the interface counters before sending the traffic")
    ifapi.clear_interface_counters(vars.D1, interface_type="all")
    st.log("Sending traffic from port 3 to learn the MAC in FDB table")
    data.tg.tg_traffic_control(action='run', stream_handle=data.streams['vlan_tagged_egress'])
    st.log("Verifying FDB table")
    if not poll_wait(mac_obj.verify_mac_address_table, 30, vars.D1, data.dscp_dest_mac):
        st.log("Displaying the interface counters to verify traffic is sent or not")
        ifapi.show_interface_counters_all(vars.D1)
        st.report_fail("mac_address_verification_fail")
    wred_running_config()
    configuring_tc_to_queue_map()
    configuring_dscp_to_tc_map()
    binding_queue_map_to_interfaces()
    st.log("Clearing the interface counters before sending the traffic")
    ifapi.clear_interface_counters(vars.D1, interface_type="all")
    st.log("Sending traffic from 1st and 2nd port")
    data.tg.tg_traffic_control(action='run', stream_handle=[data.streams['dscp1'], data.streams['dscp2']])
    st.wait(3)
    data.tg.tg_traffic_control(action='stop', stream_handle=[data.streams['dscp1'], data.streams['dscp2'], data.streams['vlan_tagged_egress']])
    st.log("Displaying the interface counters after traffic test")
    ifapi.show_interface_counters_all(vars.D1)
    cos_counters_checking()
    st.report_pass("test_case_passed")
