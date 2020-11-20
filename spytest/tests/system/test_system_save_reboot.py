import pytest

from spytest import st, tgapi, SpyTestDict, poll_wait
from spytest.utils import random_vlan_list

import apis.system.crm as crm_obj
import apis.system.switch_configuration as sconf_obj
import apis.system.interface as intf_obj
import apis.system.threshold as tf_obj
import apis.system.mirroring as mirror
import apis.system.reboot as reboot_obj
import apis.system.storm_control as scapi
import apis.switching.vlan as vlan
import apis.switching.portchannel as portchannel
import apis.system.basic as basic_obj

tg_info = dict()

def initialize_variables():
    global data
    global tg
    global tg_handler
    data = SpyTestDict()
    data.session_name = "Mirror_Ses"
    data.gre_type = "0x88ee"
    data.dscp = "50"
    data.ttl = "100"
    data.queue = "0"
    data.type = 'mirror'
    data.source_ip = '11.1.1.2'
    data.destination_ip = '15.1.1.2'
    data.mode_high = 'high'
    data.mode_low = 'low'
    data.polling_interval = '1'
    data.threshold_percentage_type = 'percentage'
    data.threshold_used_type = 'used'
    data.threshold_free_type = 'free'
    data.ipv4_route_family = "ipv4_route"
    data.ipv6_route_family = "ipv6_route"
    data.fdb_family = "fdb"
    data.ipv4_neighbor_family = "ipv4_neighbor"
    data.ipv6_neighbor_family = "ipv6_neighbor"
    data.acl_group_entry_family = 'acl_group_entry'
    data.acl_group_counter_family = 'acl_group_counter'
    data.ipv6_nexthop_family = 'ipv6_nexthop'
    data.ipv4_nexthop_family = 'ipv4_nexthop'
    data.acl_table_family = "acl_table"
    data.mode_high_percentage = 50
    data.mode_low_percentage = 20
    data.mode_high_used = 1000
    data.mode_low_used = 10
    data.mode_high_free = 1000
    data.mode_low_free = 10
    data.mtu = "9216"
    data.eth = st.get_free_ports(vars.D1)[0]
    data.property = "mtu"
    data.mtu_default = "9100"
    data.vlan = str(random_vlan_list()[0])
    data.kbps = 1000
    data.frame_size = 68
    data.rate_pps = 5000
    data.packets = (data.kbps * 1024) / (data.frame_size * 8)
    data.bum_deviation = int(0.10 * data.packets)
    data.lower_pkt_count = int(data.packets - data.bum_deviation)
    data.higher_pkt_count = int(data.packets + data.bum_deviation)
    data.wait_stream_run = 10
    data.wait_for_stats = 10
    data.session_name_port = "Mirror1"
    data.mirror_type = "span"
    data.mirror_interface = vars.D1T1P2
    data.source_interface = vars.D1T1P1
    data.direction_list = "rx"
    data.collector_name_1 = "collector_1"
    data.collector_name_2 = "collector_2"
    data.shell_sonic = "sonic"
    data.ip4_addr = ["192.168.4.4"]
    data.ip6_addr = ["2001::1"]
    data.non_default_udp_port = "4451"
    data.default_udp_port = "6343"
    tg_handler = tgapi.get_handles_byname("T1D1P1", "T1D1P2")
    tg = tg_handler["tg"]
    tg_info['tg_info'] = tg_handler
    data.hw_constants_DUT = st.get_datastore(vars.D1, "constants")
    data.version_data = basic_obj.show_version(vars.D1)

@pytest.fixture(scope="module", autouse=True)
def system_save_reboot_module_hooks(request):
    # add things at the start of this module
    global vars, tg_stream
    vars = st.ensure_min_topology("D1T1:2")
    initialize_variables()
    st.log("Configuring CRM")
    crm_config()
    st.log("Checking CRM config before save and reboot")
    crm_config_verify()
    if st.is_feature_supported("interface-mtu", vars.D1):
        st.log("Configuring MTU on interface")
        mtu_config()
        st.log("Checking the configured MTU value before save and reboot")
        mtu_verify()
    if st.is_feature_supported("threshold", vars.D1):
        st.log("configuring threshold values on interface")
        threshold_config()
        st.log("configured threshold values verification")
        threshold_verify()
    st.log("Configuration of erspan")
    mirror_action_config()
    st.log("Checking ERSPAN config before save and reboot")
    mirror_action_verify()
    if st.is_feature_supported("span-mirror-session", vars.D1):
        st.log("Configuring port mirror session")
        port_mirror_config()
        st.log("Checking port mirroring(SPAN) before save and reboot")
        port_mirror_verify()
    if st.is_feature_supported("strom-control", vars.D1):
        st.log("Configuring BUM/Storm control")
        storm_control_config()
    tg_stream = config_tg_stream()

    yield
    # delete things at the end of this module"
    crm_obj.set_crm_clear_config(vars.D1)
    if st.is_feature_supported("interface-mtu", vars.D1):
        intf_obj.interface_properties_set(vars.D1, data.eth, data.property, data.mtu_default)
    if st.is_feature_supported("threshold", vars.D1):
        tf_obj.clear_threshold(vars.D1, breach='all')
        tf_obj.clear_threshold(vars.D1, threshold_type='priority-group', buffer_type='all')
        tf_obj.clear_threshold(vars.D1, threshold_type='queue', buffer_type='all')
    mirror.delete_session(vars.D1, mirror_session=data.session_name)
    bum_clear_config()
    reboot_obj.config_save(vars.D1)


@pytest.fixture(scope="function", autouse=True)
def system_save_reboot_func_hooks(request):
    yield


def report_result(status, msg_id):
    if status:
        st.report_pass(msg_id)
    else:
        st.report_fail(msg_id)


def crm_config():
    st.log("CRM config for ACL table")
    crm_obj.set_crm_polling_interval(vars.D1, data.polling_interval)
    crm_obj.set_crm_thresholds_type(vars.D1, family=data.acl_table_family, type=data.threshold_free_type)
    crm_obj.set_crm_thresholds_value(vars.D1, family=data.acl_table_family, mode=data.mode_high,
                                     value=data.mode_high_free)
    crm_obj.set_crm_thresholds_value(vars.D1, family=data.acl_table_family, mode=data.mode_low,
                                     value=data.mode_low_free)
    st.log("CRM config for IPv4 route family")
    crm_obj.set_crm_thresholds_type(vars.D1, family=data.ipv4_route_family, type=data.threshold_percentage_type)
    crm_obj.set_crm_thresholds_value(vars.D1, family=data.ipv4_route_family, mode=data.mode_high,
                                     value=data.mode_high_percentage)
    crm_obj.set_crm_thresholds_value(vars.D1, family=data.ipv4_route_family, mode=data.mode_low,
                                     value=data.mode_low_percentage)
    st.log("CRM config for IPv6 route family")
    crm_obj.set_crm_thresholds_type(vars.D1, family=data.ipv6_route_family, type=data.threshold_percentage_type)
    crm_obj.set_crm_thresholds_value(vars.D1, family=data.ipv6_route_family, mode=data.mode_high,
                                     value=data.mode_high_percentage)
    crm_obj.set_crm_thresholds_value(vars.D1, family=data.ipv6_route_family, mode=data.mode_low,
                                     value=data.mode_low_percentage)
    st.log("CRM config for fdb")
    crm_obj.set_crm_thresholds_type(vars.D1, family=data.fdb_family, type=data.threshold_used_type)
    crm_obj.set_crm_thresholds_value(vars.D1, family=data.fdb_family, mode=data.mode_high,
                                     value=data.mode_high_used)
    crm_obj.set_crm_thresholds_value(vars.D1, family=data.fdb_family, mode=data.mode_low,
                                     value=data.mode_low_used)
    st.log("CRM config for IPv4 neighbor family")
    crm_obj.set_crm_thresholds_type(vars.D1, family=data.ipv4_neighbor_family, type=data.threshold_percentage_type)
    crm_obj.set_crm_thresholds_value(vars.D1, family=data.ipv4_neighbor_family, mode=data.mode_high,
                                     value=data.mode_high_percentage)
    crm_obj.set_crm_thresholds_value(vars.D1, family=data.ipv4_neighbor_family, mode=data.mode_low,
                                     value=data.mode_low_percentage)
    st.log("CRM config for IPv6 neighbor family")
    crm_obj.set_crm_thresholds_type(vars.D1, family=data.ipv6_neighbor_family, type=data.threshold_percentage_type)
    crm_obj.set_crm_thresholds_value(vars.D1, family=data.ipv6_neighbor_family, mode=data.mode_high,
                                     value=data.mode_high_percentage)
    crm_obj.set_crm_thresholds_value(vars.D1, family=data.ipv6_neighbor_family, mode=data.mode_low,
                                     value=data.mode_low_percentage)
    st.log("CRM config for ACL group entry family")
    crm_obj.set_crm_thresholds_type(vars.D1, family=data.acl_group_entry_family, type=data.threshold_percentage_type)
    crm_obj.set_crm_thresholds_value(vars.D1, family=data.acl_group_entry_family, mode=data.mode_high,
                                     value=data.mode_high_percentage)
    crm_obj.set_crm_thresholds_value(vars.D1, family=data.acl_group_entry_family, mode=data.mode_low,
                                     value=data.mode_low_percentage)
    st.log("CRM config for IPv6 nexthop family")
    crm_obj.set_crm_thresholds_type(vars.D1, family=data.ipv6_nexthop_family, type=data.threshold_percentage_type)
    crm_obj.set_crm_thresholds_value(vars.D1, family=data.ipv6_nexthop_family, mode=data.mode_high,
                                     value=data.mode_high_percentage)
    crm_obj.set_crm_thresholds_value(vars.D1, family=data.ipv6_nexthop_family, mode=data.mode_low,
                                     value=data.mode_low_percentage)
    st.log("CRM config for IPv4 nexthop family")
    crm_obj.set_crm_thresholds_type(vars.D1, family=data.ipv4_nexthop_family, type=data.threshold_percentage_type)
    crm_obj.set_crm_thresholds_value(vars.D1, family=data.ipv4_nexthop_family, mode=data.mode_high,
                                     value=data.mode_high_percentage)
    crm_obj.set_crm_thresholds_value(vars.D1, family=data.ipv4_nexthop_family, mode=data.mode_low,
                                     value=data.mode_low_percentage)
    st.log("CRM config for ACL group counter family")
    crm_obj.set_crm_thresholds_type(vars.D1, family=data.acl_group_counter_family, type=data.threshold_percentage_type)
    crm_obj.set_crm_thresholds_value(vars.D1, family=data.acl_group_counter_family, mode=data.mode_high,
                                     value=data.mode_high_percentage)
    crm_obj.set_crm_thresholds_value(vars.D1, family=data.acl_group_counter_family, mode=data.mode_low,
                                     value=data.mode_low_percentage)


def crm_config_verify():
    st.log("CRM ACL table config verification - ft_crm_fdb_save_reload, ft_crm_config_reboot")
    if not crm_obj.verify_crm_thresholds(vars.D1, family=data.acl_table_family, thresholdtype=data.threshold_free_type,
                                         highthreshold=data.mode_high_free,
                                         lowthreshold=data.mode_low_free):
        st.report_fail("threshold_config_fail")
    else:
        st.log("CRM ACL table config verified successfully")

    st.log("CRM IPv4 route family config verification - ft_crm_fdb_save_reload, ft_crm_config_reboot")
    if not crm_obj.verify_crm_thresholds(vars.D1, family=data.ipv4_route_family,
                                         thresholdtype=data.threshold_percentage_type,
                                         highthreshold=data.mode_high_percentage,
                                         lowthreshold=data.mode_low_percentage):
        st.report_fail("threshold_config_fail")
    else:
        st.log("CRM IPv4 route family config verified successfully")

    st.log("CRM IPv6 route family config verification - ft_crm_fdb_save_reload, ft_crm_config_reboot")
    if not crm_obj.verify_crm_thresholds(vars.D1, family=data.ipv6_route_family,
                                         thresholdtype=data.threshold_percentage_type,
                                         highthreshold=data.mode_high_percentage,
                                         lowthreshold=data.mode_low_percentage):
        st.report_fail("threshold_config_fail")
    else:
        st.log("CRM IPv6 route family config verified successfully")

    st.log("CRM FDB config verification - ft_crm_fdb_save_reload, ft_crm_config_reboot")
    if not crm_obj.verify_crm_thresholds(vars.D1, family=data.fdb_family, thresholdtype=data.threshold_used_type,
                                         highthreshold=data.mode_high_used,
                                         lowthreshold=data.mode_low_used):
        st.report_fail("threshold_config_fail")
    else:
        st.log("CRM FDB config verified successfully")

    st.log("CRM IPv4 neighbor route family config verification - ft_crm_fdb_save_reload, ft_crm_config_reboot")
    if not crm_obj.verify_crm_thresholds(vars.D1, family=data.ipv4_neighbor_family,
                                         thresholdtype=data.threshold_percentage_type,
                                         highthreshold=data.mode_high_percentage,
                                         lowthreshold=data.mode_low_percentage):
        st.report_fail("threshold_config_fail")
    else:
        st.log("CRM IPv4 neighbor route family config verified successfully")

    st.log("CRM IPv6 neighbor route family config verification - ft_crm_fdb_save_reload, ft_crm_config_reboot")
    if not crm_obj.verify_crm_thresholds(vars.D1, family=data.ipv6_neighbor_family,
                                         thresholdtype=data.threshold_percentage_type,
                                         highthreshold=data.mode_high_percentage,
                                         lowthreshold=data.mode_low_percentage):
        st.report_fail("threshold_config_fail")
    else:
        st.log("CRM IPv6 neighbor route family config verified successfully")

    st.log("CRM ACL group entry family config verification - ft_crm_fdb_save_reload, ft_crm_config_reboot")
    if not crm_obj.verify_crm_thresholds(vars.D1, family=data.acl_group_entry_family,
                                         thresholdtype=data.threshold_percentage_type,
                                         highthreshold=data.mode_high_percentage,
                                         lowthreshold=data.mode_low_percentage):
        st.report_fail("threshold_config_fail")
    else:
        st.log("CRM ACL group entry family config verified successfully")

    st.log("CRM IPv6 nexthop family config verification - ft_crm_fdb_save_reload, ft_crm_config_reboot")
    if not crm_obj.verify_crm_thresholds(vars.D1, family=data.ipv6_nexthop_family,
                                         thresholdtype=data.threshold_percentage_type,
                                         highthreshold=data.mode_high_percentage,
                                         lowthreshold=data.mode_low_percentage):
        st.report_fail("threshold_config_fail")
    else:
        st.log("CRM IPv6 nexthop family config verified successfully")

    st.log("CRM IPv4 nexthop family config verification - ft_crm_fdb_save_reload, ft_crm_config_reboot")
    if not crm_obj.verify_crm_thresholds(vars.D1, family=data.ipv4_nexthop_family,
                                         thresholdtype=data.threshold_percentage_type,
                                         highthreshold=data.mode_high_percentage,
                                         lowthreshold=data.mode_low_percentage):
        st.report_fail("threshold_config_fail")
    else:
        st.log("CRM IPv4 nexthop family config verified successfully")

    st.log("CRM ACL group counter family config verification - ft_crm_fdb_save_reload, ft_crm_config_reboot")
    if not crm_obj.verify_crm_thresholds(vars.D1, family=data.acl_group_counter_family,
                                         thresholdtype=data.threshold_percentage_type,
                                         highthreshold=data.mode_high_percentage,
                                         lowthreshold=data.mode_low_percentage):
        st.report_fail("threshold_config_fail")
    else:
        st.log("CRM ACL group counter family config verified successfully")


def mtu_config():
    st.log("configuring mtu value {} on interface".format(data.mtu))
    intf_obj.interface_properties_set(vars.D1, data.eth, data.property, data.mtu)


def mtu_verify():
    st.log("Verifying mtu configuration on interface - ft_port_mtu_fn")
    if not intf_obj.poll_for_interface_status(vars.D1, data.eth, data.property, data.mtu):
        st.report_fail("fail_to_configure_mtu_on_Device", 1)
    else:
        st.log("mtu config verification on interface successful")


def threshold_config():
    st.log("configuring threshold with threshold type as priority-group and buffer type as shared")
    tf_obj.config_threshold(vars.D1, threshold_type='priority-group', port_alias=vars.D1T1P1, index=7,
                            buffer_type='shared', value=12)

    st.log("configuring threshold with threshold type as priority-group and buffer type as headroom")
    tf_obj.config_threshold(vars.D1, threshold_type='priority-group', port_alias=vars.D1T1P1, index=7,
                            buffer_type='headroom', value=17)

    st.log("configuring threshold with threshold type as queue and buffer type as unicast")
    tf_obj.config_threshold(vars.D1, threshold_type='queue', port_alias=vars.D1T1P1, index=0, buffer_type='unicast',
                            value=20)

    st.log("configuring threshold with threshold type as queue and buffer type as multicast")
    tf_obj.config_threshold(vars.D1, threshold_type='queue', port_alias=vars.D1T1P1, index=1, buffer_type='multicast',
                            value=15)


def threshold_verify():
    result = True
    st.log("threshold type as priority-group and buffer type as shared threshold values verification - "
           "ft_tf_save_reload")
    if not tf_obj.verify_threshold(vars.D1, threshold_type='priority-group', buffer_type='shared',
                                   port_alias=vars.D1T1P1, pg7=12):
        st.error("Unable to configure the PG index and corresponding threshold value on PG shared buffer")
        result = False
    else:
        st.log("configuring PG index and corresponding threshold value on PG shared buffer is successful")

    st.log("threshold type as priority-group and buffer type as headroom threshold values verification - "
           "ft_tf_save_reload")
    if not tf_obj.verify_threshold(vars.D1, threshold_type='priority-group', buffer_type='headroom',
                                   port_alias=vars.D1T1P1, pg7=17):
        st.error("Unable to configure the PG index and corresponding threshold value on PG headroom buffer")
        result = False
    else:
        st.log("configuring PG index and corresponding threshold value on PG headroom buffer is successful")

    st.log("threshold type as queue and buffer type as unicast threshold values verification - ft_tf_save_reload")
    if not tf_obj.verify_threshold(vars.D1, threshold_type='queue', buffer_type='unicast', port_alias=vars.D1T1P1,
                                   uc0=20):
        st.error("Unable to configure unicast queue threshold value on unicast-queue buffer")
        result = False
    else:
        st.log("configuring unicast queue threshold value on unicast-queue buffer is successful")

    st.log("threshold type as queue and buffer type as multicast threshold values verification - ft_tf_save_reload")
    if not tf_obj.verify_threshold(vars.D1, threshold_type='queue', buffer_type='multicast', port_alias=vars.D1T1P1,
                                   mc1=15):
        st.error("Unable to configure multicast queue threshold value on multicast-queue buffer")
        result = False
    else:
        st.log("configuring multicast queue threshold value on multicast-queue buffer is successful")
    if not result:
        st.error("Threshold feature config verification failed.")
        st.report_fail('operation_failed')


def mirror_action_config():
    mirror_args = {"session_name": data.session_name, "gre_type": data.gre_type, "dscp": data.dscp, "ttl": data.ttl,
                   "queue": data.queue,
                   "src_ip": data.source_ip, "dst_ip": data.destination_ip}
    retval = mirror.create_session_table(vars.D1, **mirror_args)
    if not retval:
        st.log("Failed to create mirror session using json file.")
        st.report_fail("operation_failed")
    if not poll_wait(sconf_obj.verify_running_config, 60, vars.D1, "MIRROR_SESSION", "Mirror_Ses", "dst_ip", "15.1.1.2"):
        st.log("Failed to show mirror session details in running config.")
        st.report_fail("operation_failed")


def mirror_action_verify():
    mirror_args = {"session_name": data.session_name, "gre_type": data.gre_type, "dscp": data.dscp, "ttl": data.ttl,
                   "queue": data.queue, "src_ip": data.source_ip, "dst_ip": data.destination_ip}
    if not mirror.verify_session(vars.D1, **mirror_args):
        st.log("failed to show mirror session details after reboot.")
        st.report_fail("operation_failed")
    if not poll_wait(sconf_obj.verify_running_config,60,vars.D1, "MIRROR_SESSION", "Mirror_Ses", "dst_ip", "15.1.1.2"):
        st.log("failed to show mirror session details in running config after reboot.")
        st.report_fail("operation_failed")


def port_mirror_config():
    mirror.create_session(vars.D1, session_name=data.session_name_port, mirror_type=data.mirror_type,
                          destination_ifname=data.mirror_interface,
                          source_ifname=data.source_interface, rx_tx=data.direction_list)


def port_mirror_verify():
    if not mirror.verify_session(vars.D1, mirror_type=data.mirror_type, session_name=data.session_name_port):
        st.report_fail("mirror_session_verification_failed")


#
def storm_control_config():
    st.banner("Configuring BUM Storm control on interfaces")
    interface_list = [vars.D1T1P1, vars.D1T1P2]
    storm_control_type = ["broadcast", "unknown-multicast", "unknown-unicast"]
    for interface_li in interface_list:
        for stc_type in storm_control_type:
            scapi.config(vars.D1, type=stc_type, action="add", interface_name=interface_li, bits_per_sec=data.kbps)
            if not scapi.verify_config(vars.D1, interface_name=interface_li, type=stc_type, rate=data.kbps):
                st.report_fail("storm_control_config_verify_failed", stc_type, interface_li)


def config_tg_stream():
    st.log("Traffic Config for verifying BUM storm control feature")
    tg.tg_traffic_control(action="reset", port_handle=tg_handler["tg_ph_list"])
    tg_1 = tg.tg_traffic_config(port_handle=tg_handler["tg_ph_1"], mode='create',
                                transmit_mode='continuous', length_mode='fixed', rate_pps=100,
                                l2_encap='ethernet_ii_vlan', vlan_id=data.vlan, mac_src='00:0a:01:00:00:01',
                                mac_dst='00:0a:02:00:00:01', high_speed_result_analysis=0, vlan="enable",
                                track_by='trackingenabled0 vlanVlanId0', vlan_id_tracking=1,
                                port_handle2=tg_handler["tg_ph_2"],frame_size= data.frame_size)
    tg_info['tg1_stream_id'] = tg_1['stream_id']

    tg_2 = tg.tg_traffic_config(port_handle=tg_handler["tg_ph_2"], mode='create',
                                transmit_mode='continuous', length_mode='fixed', rate_pps=100,
                                l2_encap='ethernet_ii_vlan', vlan_id=data.vlan, mac_src='00:0a:02:00:00:01',
                                mac_dst='00:0a:01:00:00:01', high_speed_result_analysis=0, vlan="enable",
                                track_by='trackingenabled0 vlanVlanId0', vlan_id_tracking=1,
                                port_handle2=tg_handler["tg_ph_1"],frame_size= data.frame_size)
    tg_info['tg2_stream_id'] = tg_2['stream_id']
    return tg_info


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
        st.log("Starting of traffic from TGen")
        tg.tg_traffic_control(action='run', stream_handle=tg_stream, duration=10)
        st.wait(data.wait_stream_run)
        st.log("Stopping of traffic from TGen to get interface counters")
        tg.tg_traffic_control(action='stop', stream_handle=tg_stream)
        st.wait(data.wait_for_stats)
        tg_1_stats = tgapi.get_traffic_stats(tg, mode='aggregate', port_handle=tg_handler["tg_ph_1"])
        tg_2_stats = tgapi.get_traffic_stats(tg, mode='aggregate', port_handle=tg_handler["tg_ph_2"])
        counter = tg_2_stats.rx.total_packets
        counter2 = tg_1_stats.tx.total_packets
        if counter2 == 0:
            st.report_fail("storm_control_traffic_verification_failed")
        counters_avg = counter / duration
        st.log("Average of counters are : {}".format(counters_avg))
        st.log("Higher packet count value is : {}".format(data.higher_pkt_count ))
        st.log("Lower packet count value is : {}".format(data.lower_pkt_count))
        if  counters_avg > data.higher_pkt_count or counters_avg < data.lower_pkt_count:
            st.report_fail("storm_control_traffic_verification_failed")
    return True


def storm_control_verify():
    status = 1
    platform_check()
    st.log("Removing mirror session related information to ensure that BUM is unaffected due to mirror sessions")
    mirror.delete_session(vars.D1, mirror_session=data.session_name_port)
    st.log("Creating vlan in device and adding members ...")
    vlan_data = [{"dut": [vars.D1], "vlan_id": data.vlan, "tagged": [vars.D1T1P1, vars.D1T1P2]}]
    vlan.create_vlan_and_add_members(vlan_data)
    msg_id = "storm_control_reboot_successful"
    interface_list = [vars.D1T1P1, vars.D1T1P2]
    storm_control_type = ["broadcast", "unknown-multicast", "unknown-unicast"]
    for interface_li in interface_list:
        for stc_type in storm_control_type:
            if not scapi.verify_config(vars.D1, interface_name=interface_li, type=stc_type, rate=data.kbps):
                st.report_fail("storm_control_config_verify_failed", stc_type, interface_li)
    if not verify_bum_traffic_mode('broadcast', tg_info['tg1_stream_id'], skip_traffic_verify=False):
        st.error("Broadcast traffic verification got failed")
        status = 0
    if not verify_bum_traffic_mode('unknown-unicast', tg_info['tg1_stream_id'], skip_traffic_verify=False):
        st.error("Unknown-unicast traffic verification got failed")
        status = 0
    if not verify_bum_traffic_mode('unknown-multicast', tg_info['tg1_stream_id'], skip_traffic_verify=False):
        st.error("Unknown-multicast traffic verification got failed")
        status = 0
    if not status:
        msg_id = "storm_control_reboot_failed"
    if status:
        st.report_tc_pass('ft_stormcontrol_cold_reboot', 'test_case_passed')
    else:
        st.report_tc_fail('ft_stormcontrol_cold_reboot', 'test_case_failed')
    report_result(status, msg_id)


def bum_clear_config():
    interface_list = [vars.D1T1P1, vars.D1T1P2]
    storm_control_type = ["broadcast", "unknown-multicast", "unknown-unicast"]
    for interface in interface_list:
        for stc_type in storm_control_type:
            scapi.config(vars.D1, type=stc_type, action="del", interface_name=interface, bits_per_sec=data.kbps)
    vlan.clear_vlan_configuration(st.get_dut_names(), thread=False)
    portchannel.clear_portchannel_configuration(st.get_dut_names(), thread=True)

def platform_check():
    if data.version_data['hwsku'].lower() in data.hw_constants_DUT['TH3_PLATFORMS']:
        st.log("--- Detected BUM UnSupported Platform..")
        st.report_unsupported("storm_control_unsupported")


@pytest.mark.savereboot_save
def test_ft_system_config_mgmt_verifying_config_with_save_reboot():
    st.log("performing Config save")
    reboot_obj.config_save(vars.D1)
    st.log("performing Reboot")
    st.reboot(vars.D1)
    st.log("Checking whether config is loaded to running config from config_db after save and reboot")
    st.log("Checking CRM config after save and reload")
    crm_config_verify()
    if st.is_feature_supported("interface-mtu", vars.D1):
        st.log("Checking the configured MTU value after save and reboot")
        mtu_verify()
    if st.is_feature_supported("threshold", vars.D1):
        st.log("configured threshold values verification")
        threshold_verify()
    st.log("Checking ERSPAN config after save and reboot")
    mirror_action_verify()
    if st.is_feature_supported("span-mirror-session", vars.D1):
        st.log("Checking SPAN config after save and reboot")
        port_mirror_verify()
    st.log("configuration successfully stored to config_db file after save and reboot")
    st.report_pass("test_case_passed")

@pytest.mark.savereboot_save
@pytest.mark.community_unsupported
def test_ft_storm_control_cold_reboot():
    st.log("moving stormcontrol verify in next testfunction as platform specific check is added it might effect other testcase results")
    storm_control_verify()
    st.log("configuration successfully stored to config_db file after save and reboot")
    st.report_pass("test_case_passed")

