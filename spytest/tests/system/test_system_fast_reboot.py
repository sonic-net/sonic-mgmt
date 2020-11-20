import pytest

from spytest import st, tgapi, SpyTestDict
from spytest.utils import random_vlan_list

import apis.system.reboot as rb_obj
import apis.system.crm as crm_obj
import apis.system.switch_configuration as sconf_obj
import apis.system.interface as intf_obj
import apis.system.threshold as tf_obj
import apis.system.mirroring as mirror
import apis.switching.vlan as vlan_obj
import apis.switching.portchannel as po_obj
import apis.qos.acl_dscp as acl_dscp

from utilities.parallel import exec_all, ensure_no_exception
from utilities.common import make_list

def initialize_variables():
    global data
    data=SpyTestDict()
    data.session_name = "Mirror_Ses"
    data.gre_type = "0x88ee"
    data.dscp = "50"
    data.ttl = "100"
    data.queue = "0"
    data.type = 'monitoring'
    data.source_ip = '11.1.1.2'
    data.destination_ip = '15.1.1.2'
    data.source_mac = "00:00:02:00:00:01"
    data.destination_mac = "00:00:01:00:00:01"
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
    data.eth = data.eth_name = st.get_free_ports(vars.D1)[0]
    if any("/" in interface for interface in make_list(data.eth_name)):
        data.eth_name = st.get_other_names(vars.D1, make_list(data.eth))[0]
    data.property = "mtu"
    data.mtu_default = "9100"
    data.portchannel_name = "PortChannel7"
    data.members_dut1 = [vars.D1D2P1, vars.D1D2P2]
    data.members_dut2 = [vars.D2D1P1, vars.D2D1P2]
    data.session_name_port = "Mirror1"
    data.mirror_type = "span"
    data.mirror_interface = vars.D1T1P2
    data.source_interface = vars.D1T1P1
    data.direction_list = "rx"


@pytest.fixture(scope="module", autouse=True)
def system_fast_reboot_module_hooks(request):
    # add things at the start of this module
    global vars
    vars = st.ensure_min_topology("D1T1:2", 'D1D2:2', 'D2T1:1')
    initialize_variables()
    st.log("Configuring CRM")
    crm_config()
    st.log("Checking CRM config before save and fast-reboot")
    crm_config_verify()
    if st.is_feature_supported("interface-mtu", vars.D1):
        st.log("Configuring MTU on interface")
        mtu_config()
        st.log("Checking the configured MTU value before save and fast-reboot")
        mtu_verify()
    if st.is_feature_supported("threshold", vars.D1):
        st.log("configuring threshold values on interface")
        threshold_config()
        st.log("configured threshold values verification")
        threshold_verify()
    st.log("configure mirror session values")
    mirror_action_config()
    st.log("configured mirror session verification")
    mirror_action_verify()
    if st.is_feature_supported("span-mirror-session", vars.D1):
        st.log("Configuring port mirroring values")
        port_mirror_config()
        st.log("Checking port mirroring before save and reboot")
        port_mirror_verify()
    st.log("Configuring Port-Channel")
    config_portchannel()
    st.log("Configuring VLAN related configuration")
    dut_vlan_config()
    st.log("Configuring TGEN handlers and streams")
    tgen_config()
    yield
    # add things at the end of this module"
    #Setting the MTU value to default
    intf_obj.interface_properties_set(vars.D1, data.eth, data.property, data.mtu_default)
    #Below step will clear all CRM config from the device.
    crm_obj.set_crm_clear_config(vars.D1)
    #Below steps will clear all threshold values configured on the device
    tf_obj.clear_threshold(vars.D1, breach='all')
    tf_obj.clear_threshold(vars.D1, threshold_type='priority-group', buffer_type='all')
    tf_obj.clear_threshold(vars.D1, threshold_type='queue', buffer_type='all')
    mirror.delete_session(vars.D1, "Mirror_Ses")
    mirror.delete_session(vars.D1, mirror_session=data.session_name_port)
    rb_obj.config_save(vars.D1)

@pytest.fixture(scope="function", autouse=True)
def system_fast_reboot_func_hooks(request):
    # add things at the start every test case
    # use 'st.get_func_name(request)' to compare
    # if any thing specific a particular test case
    yield
    # add things at the end every test case
    # use 'st.get_func_name(request)' to compare
    # if any thing specific a particular test case

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
    st.log("CRM ACL table config verification - ft_crm_fast_reboot")
    if not crm_obj.verify_crm_thresholds(vars.D1, family=data.acl_table_family, thresholdtype=data.threshold_free_type,
                                         highthreshold=data.mode_high_free,
                                         lowthreshold=data.mode_low_free):
        st.report_fail("threshold_config_fail")
    else:
        st.log("CRM ACL table config verified successfully")

    st.log("CRM IPv4 route family config verification - ft_crm_fast_reboot")
    if not crm_obj.verify_crm_thresholds(vars.D1, family=data.ipv4_route_family,
                                         thresholdtype=data.threshold_percentage_type,
                                         highthreshold=data.mode_high_percentage,
                                         lowthreshold=data.mode_low_percentage):
        st.report_fail("threshold_config_fail")
    else:
        st.log("CRM IPv4 route family config verified successfully")

    st.log("CRM IPv6 route family config verification - ft_crm_fast_reboot")
    if not crm_obj.verify_crm_thresholds(vars.D1, family=data.ipv6_route_family,
                                         thresholdtype=data.threshold_percentage_type,
                                         highthreshold=data.mode_high_percentage,
                                         lowthreshold=data.mode_low_percentage):
        st.report_fail("threshold_config_fail")
    else:
        st.log("CRM IPv6 route family config verified successfully")

    st.log("CRM FDB config verification - ft_crm_fast_reboot")
    if not crm_obj.verify_crm_thresholds(vars.D1, family=data.fdb_family, thresholdtype=data.threshold_used_type,
                                         highthreshold=data.mode_high_used,
                                         lowthreshold=data.mode_low_used):
        st.report_fail("threshold_config_fail")
    else:
        st.log("CRM FDB config verified successfully")

    st.log("CRM IPv4 neighbor route family config verification - ft_crm_fast_reboot")
    if not crm_obj.verify_crm_thresholds(vars.D1, family=data.ipv4_neighbor_family,
                                         thresholdtype=data.threshold_percentage_type,
                                         highthreshold=data.mode_high_percentage,
                                         lowthreshold=data.mode_low_percentage):
        st.report_fail("threshold_config_fail")
    else:
        st.log("CRM IPv4 neighbor route family config verified successfully")

    st.log("CRM IPv6 neighbor route family config verification - ft_crm_fast_reboot")
    if not crm_obj.verify_crm_thresholds(vars.D1, family=data.ipv6_neighbor_family,
                                         thresholdtype=data.threshold_percentage_type,
                                         highthreshold=data.mode_high_percentage,
                                         lowthreshold=data.mode_low_percentage):
        st.report_fail("threshold_config_fail")
    else:
        st.log("CRM IPv6 neighbor route family config verified successfully")

    st.log("CRM ACL group entry family config verification - ft_crm_fast_reboot")
    if not crm_obj.verify_crm_thresholds(vars.D1, family=data.acl_group_entry_family,
                                         thresholdtype=data.threshold_percentage_type,
                                         highthreshold=data.mode_high_percentage,
                                         lowthreshold=data.mode_low_percentage):
        st.report_fail("threshold_config_fail")
    else:
        st.log("CRM ACL group entry family config verified successfully")

    st.log("CRM IPv6 nexthop family config verification - ft_crm_fast_reboot")
    if not crm_obj.verify_crm_thresholds(vars.D1, family=data.ipv6_nexthop_family,
                                         thresholdtype=data.threshold_percentage_type,
                                         highthreshold=data.mode_high_percentage,
                                         lowthreshold=data.mode_low_percentage):
        st.report_fail("threshold_config_fail")
    else:
        st.log("CRM IPv6 nexthop family config verified successfully")

    st.log("CRM IPv4 nexthop family config verification - ft_crm_fast_reboot")
    if not crm_obj.verify_crm_thresholds(vars.D1, family=data.ipv4_nexthop_family,
                                         thresholdtype=data.threshold_percentage_type,
                                         highthreshold=data.mode_high_percentage,
                                         lowthreshold=data.mode_low_percentage):
        st.report_fail("threshold_config_fail")
    else:
        st.log("CRM IPv4 nexthop family config verified successfully")

    st.log("CRM ACL group counter family config verification - ft_crm_fast_reboot")
    if not crm_obj.verify_crm_thresholds(vars.D1, family=data.acl_group_counter_family,
                                         thresholdtype=data.threshold_percentage_type,
                                         highthreshold=data.mode_high_percentage,
                                         lowthreshold=data.mode_low_percentage):
        st.report_fail("threshold_config_fail")
    else:
        st.log("CRM ACL group counter family config verified successfully")


def mtu_config():
    st.log("configuring mtu value of 9216 on interface")
    intf_obj.interface_properties_set(vars.D1, data.eth, data.property, data.mtu)


def mtu_verify():
    st.log("Verifying mtu configuration on interface - FtOpSoSysMTUCmFn003")
    if not sconf_obj.verify_running_config(vars.D1, "PORT", data.eth_name, data.property, data.mtu):
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
    tf_obj.config_threshold(vars.D1, threshold_type='queue', port_alias=vars.D1T1P1, index=7, buffer_type='multicast',
                            value=15)


def threshold_verify():
    st.log("threshold type as priority-group and buffer type as shared threshold values verification - ft_tf_fast_reboot")
    if not tf_obj.verify_threshold(vars.D1, threshold_type='priority-group', buffer_type='shared',
                                   port_alias=vars.D1T1P1, pg7=12):
        st.error("Unable to configure the PG index and corresponding threshold value on PG shared buffer")
    else:
        st.log("configuring PG index and corresponding threshold value on PG shared buffer is successful")

    st.log("threshold type as priority-group and buffer type as headroom threshold values verification - ft_tf_fast_reboot")
    if not tf_obj.verify_threshold(vars.D1, threshold_type='priority-group', buffer_type='headroom',
                                   port_alias=vars.D1T1P1, pg7=17):
        st.error("Unable to configure the PG index and corresponding threshold value on PG headroom buffer")
    else:
        st.log("configuring PG index and corresponding threshold value on PG headroom buffer is successful")

    st.log("threshold type as queue and buffer type as unicast threshold values verification - ft_tf_fast_reboot")
    if not tf_obj.verify_threshold(vars.D1, threshold_type='queue', buffer_type='unicast', port_alias=vars.D1T1P1,
                                   uc0=20):
        st.error("Unable to configure unicast queue threshold value on unicast-queue buffer")
    else:
        st.log("configuring unicast queue threshold value on unicast-queue buffer is successful")

    st.log("threshold type as queue and buffer type as multicast threshold values verification - ft_tf_fast_reboot")
    if not tf_obj.verify_threshold(vars.D1, threshold_type='queue', buffer_type='multicast', port_alias=vars.D1T1P1,
                                   mc8=15):
        st.error("Unable to configure multicast queue threshold value on multicast-queue buffer")
    else:
        st.log("configuring multicast queue threshold value on multicast-queue buffer is successful")


def mirror_action_config():
    mirror_args = {"session_name": data.session_name, "gre_type": data.gre_type, "dscp": data.dscp, "ttl": data.ttl,
                   "queue": data.queue,
                   "src_ip": data.source_ip, "dst_ip": data.destination_ip}
    retval = mirror.create_session_table(vars.D1, **mirror_args)
    if not retval:
        st.log("Failed to create mirror session using json file.")
        st.report_fail("operation_failed")
        acl_dscp.config_policy_table(vars.D1, enable='create', policy_name=data.acl_table_name,
                                     policy_type=data.type)
        acl_dscp.config_service_policy_table(vars.D1, policy_kind='bind', policy_type=data.type, stage='in',
                                             interface_name=vars.D1T1P1, service_policy_name=data.acl_table_name)
    if not sconf_obj.verify_running_config(vars.D1, "MIRROR_SESSION", "Mirror_Ses", "dst_ip", "15.1.1.2"):
        st.log("Failed to show mirror session details in running config.")
        st.report_fail("operation_failed")


def mirror_action_verify():
    mirror_args = {"session_name": data.session_name, "gre_type": data.gre_type, "dscp": data.dscp, "ttl": data.ttl,
              "queue": data.queue, "src_ip": data.source_ip, "dst_ip": data.destination_ip}
    if not mirror.verify_session(vars.D1, **mirror_args):
        st.log("failed to show mirror session details after reboot.")
        st.report_fail("operation_failed")
    if not sconf_obj.verify_running_config(vars.D1, "MIRROR_SESSION", "Mirror_Ses", "dst_ip", "15.1.1.2"):
        st.log("failed to show mirror session details in running config after reboot.")
        st.report_fail("operation_failed")


def config_portchannel():
    po_obj.config_portchannel(vars.D1, vars.D2, data.portchannel_name, data.members_dut1, data.members_dut2, "add")


def dut_vlan_config():
    st.log("creating vlan and participating TGEN ports")
    data.vlan = str(random_vlan_list()[0])
    exceptions = exec_all(True, [[vlan_obj.create_vlan, vars.D1, data.vlan], [vlan_obj.create_vlan, vars.D2, data.vlan]])[1]
    ensure_no_exception(exceptions)
    exceptions = exec_all(True, [[vlan_obj.add_vlan_member, vars.D1, data.vlan, [vars.D1T1P1, vars.D1T1P2], True],
                                 [vlan_obj.add_vlan_member, vars.D2, data.vlan, [vars.D2T1P1], True]])[1]
    ensure_no_exception(exceptions)


def tgen_config():
    data.tg_handler = tgapi.get_handles_byname("T1D1P1", "T1D1P2", "T1D2P1")
    data.tg = data.tg_handler['tg']
    data.tg.tg_traffic_control(action="reset", port_handle=data.tg_handler["tg_ph_list"])
    data.tg.tg_traffic_control(action="clear_stats", port_handle=data.tg_handler["tg_ph_list"])

    data.stream = data.tg_handler['tg'].tg_traffic_config(port_handle=data.tg_handler["tg_ph_1"],
                                                                   mode='create',
                                                                   transmit_mode="single_burst", pkts_per_burst=100,
                                                                   length_mode='fixed', l2_encap='ethernet_ii_vlan',
                                                                   vlan_id=data.vlan, rate_pps=100, frame_size=64,
                                                                   vlan="enable", mac_src=data.source_mac,
                                                                   mac_dst=data.destination_mac)


def port_mirror_config():
    mirror.create_session(vars.D1, session_name=data.session_name_port, mirror_type=data.mirror_type,
                          destination_ifname=data.mirror_interface,
                          source_ifname=data.source_interface, rx_tx=data.direction_list)


def port_mirror_verify():
    if not mirror.verify_session(vars.D1,mirror_type=data.mirror_type,session_name=data.session_name_port):
        st.report_fail("mirror_session_verification_failed")



@pytest.mark.fast_reboot11000
def test_ft_system_config_mgmt_verifying_config_with_save_fast_reboot():
    st.log("performing Config save")
    rb_obj.config_save(vars.D1)
    st.log("performing fast-reboot")
    st.reboot(vars.D1, 'fast')
    st.log("Checking whether config is loaded to running config from config_db after fast-reboot")
    st.log("Checking CRM config after save and fast-reboot")
    crm_config_verify()
    if st.is_feature_supported("interface-mtu", vars.D1):
        st.log("Checking the configured MTU value after save and fast-reboot")
        mtu_verify()
    if st.is_feature_supported("threshold", vars.D1):
        st.log("configured threshold values verification")
        threshold_verify()
    st.log("Checking ERSPAN config after fast-reboot")
    mirror_action_verify()
    if st.is_feature_supported("span-mirror-session", vars.D1):
        st.log("Checking SPAN config after save and reboot")
        port_mirror_verify()
    st.log("configuration is successfully stored to config_db file after save and fast-reboot")
    st.report_pass("test_case_passed")


@pytest.mark.fastreboot1000
def test_ft_system_verify_traffic_fast_reboot():
    data.tg_handler["tg"].tg_traffic_control(action='clear_stats',
                                             port_handle=[data.tg_handler["tg_ph_1"], data.tg_handler["tg_ph_2"]])
    data.tg_handler["tg"].tg_traffic_control(action='run', stream_handle=data.stream['stream_id'])
    st.log("Fetching TGEN statistics")
    stats_tg1 = tgapi.get_traffic_stats(data.tg_handler["tg"], mode="aggregate", port_handle=data.tg_handler["tg_ph_1"])
    total_tx_tg1 = stats_tg1.tx.total_bytes
    stats_tg2 = tgapi.get_traffic_stats(data.tg_handler["tg"], mode="aggregate", port_handle=data.tg_handler["tg_ph_2"])
    total_rx_tg2 = stats_tg2.rx.total_bytes
    percentage_98_total_tx_tg1 = (98 * int(total_tx_tg1)) / 100
    st.log("###############")
    st.log("Sent bytes: {} and Received bytes : {}".format(percentage_98_total_tx_tg1, total_rx_tg2))
    st.log("##############")
    if not int(percentage_98_total_tx_tg1) <= int(total_rx_tg2):
        st.report_fail("traffic_transmission_failed", vars.T1D1P1)
    data.tg.tg_traffic_control(action="clear_stats", port_handle=data.tg_handler["tg_ph_list"])
    data.tg.tg_traffic_control(action='run', stream_handle=data.stream['stream_id'])
    st.reboot(vars.D1, 'fast')
    data.tg.tg_traffic_control(action='stop', stream_handle=data.stream['stream_id'])
    stats_tg1 = tgapi.get_traffic_stats(data.tg_handler["tg"], mode="aggregate", port_handle=data.tg_handler["tg_ph_1"])
    total_tx_tg1 = stats_tg1.tx.total_bytes
    stats_tg2 = tgapi.get_traffic_stats(data.tg_handler["tg"], mode="aggregate", port_handle=data.tg_handler["tg_ph_2"])
    total_rx_tg2 = stats_tg2.rx.total_bytes
    percentage_98_total_tx_tg1 = (98 * int(total_tx_tg1)) / 100
    st.log("###############")
    st.log("Sent bytes: {} and Received bytes : {}".format(percentage_98_total_tx_tg1, total_rx_tg2))
    st.log("##############")
    if not int(percentage_98_total_tx_tg1) <= int(total_rx_tg2):
        st.report_fail("traffic_transmission_failed", vars.T1D1P1)
    st.report_pass("test_case_passed")


@pytest.mark.fast_reboot11000
def test_ft_system_verify_traffic_during_fast_reboot():
    data.tg_handler["tg"].tg_traffic_config(mode='modify', stream_id=data.stream['stream_id'],
                                            transmit_mode = 'continuous', port_handle=data.tg_handler["tg_ph_1"])
    st.log("performing Config save")
    rb_obj.config_save(vars.D1)
    data.tg_handler["tg"].tg_traffic_control(action='clear_stats',
                                             port_handle=[data.tg_handler["tg_ph_1"], data.tg_handler["tg_ph_2"]])
    data.tg_handler["tg"].tg_traffic_control(action='run', stream_handle=data.stream['stream_id'])
    st.log("performing fast-reboot")
    st.reboot(vars.D1, 'fast')
    data.tg_handler["tg"].tg_traffic_control(action='stop', stream_handle=data.stream['stream_id'])
    loss_pkts_count = 26 * 100
    stats_tg1 = tgapi.get_traffic_stats(data.tg_handler["tg"], mode="aggregate", port_handle=data.tg_handler["tg_ph_1"])
    tx_pkts = stats_tg1.tx.total_packets
    stats_tg2 = tgapi.get_traffic_stats(data.tg_handler["tg"], mode="aggregate", port_handle=data.tg_handler["tg_ph_2"])
    rx_pkts = stats_tg2.rx.total_packets
    st.log("Traffic sent from TGEN: {}".format(tx_pkts))
    st.log("Traffic received on TGEN: {}".format(rx_pkts))
    if not loss_pkts_count > int(tx_pkts)-int(rx_pkts):
        st.report_fail('data_traffic_loss_during_fast_reboot')
    st.report_pass("test_case_passed")


@pytest.mark.fast_reboot11000
def test_ft_system_verify_traffic_through_port_channel_during_fast_reboot():
    [output, exceptions] = exec_all(True, [[po_obj.verify_portchannel_member, vars.D1, data.portchannel_name, data.members_dut1],
                                 [po_obj.verify_portchannel_member, vars.D2, data.portchannel_name, data.members_dut2]])
    if False in output:
        st.report_fail('portchannel_member_verification_failed',data.portchannel_name, vars.D1, data.members_dut1)
    ensure_no_exception(exceptions)
    exceptions = exec_all(True, [[vlan_obj.add_vlan_member, vars.D1, data.vlan, data.portchannel_name, True],
                                 [vlan_obj.add_vlan_member, vars.D2, data.vlan, data.portchannel_name, True]])[1]
    ensure_no_exception(exceptions)
    data.tg_handler["tg"].tg_traffic_config(mode='modify', stream_id=data.stream['stream_id'],
                                            transmit_mode='continuous', port_handle=data.tg_handler["tg_ph_1"])
    st.log("performing Config save")
    rb_obj.config_save(vars.D1)
    data.tg_handler["tg"].tg_traffic_control(action='clear_stats',
                               port_handle=[data.tg_handler["tg_ph_1"], data.tg_handler["tg_ph_3"]])
    data.tg_handler["tg"].tg_traffic_control(action='run', stream_handle=data.stream['stream_id'])
    st.log("performing fast-reboot")
    st.reboot(vars.D1, 'fast')
    data.tg_handler["tg"].tg_traffic_control(action='stop', stream_handle=data.stream['stream_id'])
    loss_pkts_count = 26 * 100
    stats_tg1 = tgapi.get_traffic_stats(data.tg_handler["tg"], mode="aggregate",
                                                          port_handle=data.tg_handler["tg_ph_1"])
    tx_pkts = stats_tg1.tx.total_packets
    stats_tg2 = tgapi.get_traffic_stats(data.tg_handler["tg"], mode="aggregate",
                                                          port_handle=data.tg_handler["tg_ph_3"])
    rx_pkts = stats_tg2.rx.total_packets
    st.log("Traffic sent from TGEN: {}".format(tx_pkts))
    st.log("Traffic received on TGEN: {}".format(rx_pkts))
    if not loss_pkts_count > int(tx_pkts) - int(rx_pkts):
        st.report_fail('data_traffic_loss_during_fast_reboot')
    st.report_pass("test_case_passed")
