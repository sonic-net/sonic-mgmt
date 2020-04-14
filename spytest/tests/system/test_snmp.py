import pytest
import re

from spytest import st, tgapi, SpyTestDict
from spytest.utils import random_vlan_list

import apis.system.snmp as snmp_obj
import apis.system.basic as basic_obj
import apis.system.box_services as box_obj
import utilities.utils as util_obj
import apis.switching.vlan as vlan_obj
import apis.switching.mac as mac_obj
import apis.routing.ip as ipfeature
import apis.system.interface as intf_obj
from apis.system.connection import execute_command
from apis.system.connection import connect_to_device
import apis.system.reboot as reboot

from utilities.utils import ensure_service_params

data = SpyTestDict()

@pytest.fixture(scope="module", autouse=True)
def snmp_module_hooks(request):
    global vars
    vars = st.ensure_min_topology("D1T1:2")
    initialize_variables()
    snmp_pre_config()
    vlan_preconfig()
    snmp_traffic_config()
    snmp_trap_pre_config()

    yield
    snmp_post_config()
    vlan_postconfig()
    snmp_trap_post_config()


@pytest.fixture(scope="function", autouse=True)
def snmp_func_hooks(request):
    global ipaddress
    ipaddress = st.get_mgmt_ip(vars.D1)
    yield


def initialize_variables():
    data.clear()
    data.ro_community = 'test_123'
    data.location = 'hyderabad'
    data.contact = "Admin"
    data.sysname = "Sonic_device"
    data.mgmt_int = 'eth0'
    data.wait_time = 30
    data.filter_cli = "-One"
    data.oid_sysName = '1.3.6.1.2.1.1.5.0'
    data.oid_syUpTime = '1.3.6.1.2.1.25.1.1.0'
    data.oid_sysLocation = '1.3.6.1.2.1.1.6.0'
    data.oid_sysDescr = '1.3.6.1.2.1.1.1.0'
    data.oid_sysContact = '1.3.6.1.2.1.1.4.0'
    data.oid_sysObjectId = '1.3.6.1.2.1.1.2.0'
    data.oid_mib_2 ='1.3.6.1.2.1'
    data.oid_if_mib_all = '1.3.6.1.2.1.31'
    data.oid_entity_mib_all = '1.3.6.1.2.1.47'
    data.oid_entity_sensor_mib = '1.3.6.1.2.1.99'
    data.oid_dot1q_mib = '1.3.6.1.2.1.17.7'
    data.oid_dot1db_mib = '1.3.6.1.2.1.17'
    data.oid_root_node_walk = '.'
    data.oid_IP_MIB_ipAddressRowStatus_ipv6='1.3.6.1.2.1.4.34.1.10.2'
    data.oid_IP_MIB_ipAddressStorageType_ipv6 = '1.3.6.1.2.1.4.34.1.11'
    data.oid_IPV6_MIB_ipv6IfDescr = '1.3.6.1.2.1.55.1.5.1.2'
    data.oid_IPV6_MIB_ipv6IfAdminStatus = '1.3.6.1.2.1.55.1.5.1.9'
    data.oid_IPV6_MIB_ipv6IpForwarding = '1.3.6.1.2.1.4.25.0'
    data.oid_IPV6_MIB_ipv6IpDefaultHopLimit = '1.3.6.1.2.1.4.26'
    data.oid_IPV6_MIB_ipv6ScopeZoneIndexTable = '1.3.6.1.2.1.4.36'
    data.oid_ipcidr_route_table = '1.3.6.1.2.1.4.24.4'
    data.af_ipv4 = "ipv4"
    data.loopback_addr = '67.66.66.66'
    data.loopback0= 'Loopback0'
    data.oid_dot1d_Base = '1.3.6.1.2.1.17.1'
    data.oid_dot1d_Base_Bridge_Address = '1.3.6.1.2.1.17.1.1'
    data.oid_dot1d_Base_Num_Ports = '1.3.6.1.2.1.17.1.2'
    data.oid_dot1d_Base_Type = '1.3.6.1.2.1.17.1.3'
    data.oid_dot1d_Base_Port = '1.3.6.1.2.1.17.1.4.1.1'
    data.oid_dot1d_Base_PortIf_Index = '1.3.6.1.2.1.17.1.4.1.2'
    data.oid_dot1d_Base_Port_Delay_Exceeded_Discards = '1.3.6.1.2.1.17.1.4.1.4'
    data.oid_dot1d_Base_Port_Mtu_Exceeded_Discards = '1.3.6.1.2.1.17.1.4.1.5'
    data.oid_dot1d_Tp_Aging_Time = '1.3.6.1.2.1.17.4.2'
    data.oid_dot1q_Vlan_Version_Number = '1.3.6.1.2.1.17.7.1.1.1'
    data.oid_dot1q_Max_VlanId = '1.3.6.1.2.1.17.7.1.1.2'
    data.oid_dot1q_Max_Supported_Vlans = '1.3.6.1.2.1.17.7.1.1.3'
    data.oid_dot1q_Num_Vlans = '1.3.6.1.2.1.17.7.1.1.4'
    data.oid_dot1q_Vlan_Num_Deletes = '1.3.6.1.2.1.17.7.1.4.1'
    data.oid_dot1q_Fdb_Dynamic_Count = '1.3.6.1.2.1.17.7.1.2.1.1.2'
    data.oid_dot1q_Tp_Fdb_Address = '1.3.6.1.2.1.17.7.1.2.2.1.1'
    data.oid_dot1q_Tp_Fdb_Port = '1.3.6.1.2.1.17.7.1.2.2.1.2'
    data.oid_dot1q_Tp_Fdb_Status = '1.3.6.1.2.1.17.7.1.2.2.1.3'
    data.oid_dot1q_Vlan_Index = '1.3.6.1.2.1.17.7.1.4.2.1.2'
    data.oid_dot1q_Vlan_Current_Egress_Ports = '1.3.6.1.2.1.17.7.1.4.2.1.4'
    data.oid_dot1q_Vlan_Current_Untagged_Ports = '1.3.6.1.2.1.17.7.1.4.2.1.5'
    data.oid_dot1q_Vlan_Static_Name = '1.3.6.1.2.1.17.7.1.4.3.1.1'
    data.oid_dot1q_Vlan_Static_Egress_Ports = '1.3.6.1.2.1.17.7.1.4.3.1.2'
    data.oid_dot1q_Vlan_Static_Untagged_Ports = '1.3.6.1.2.1.17.7.1.4.3.1.4'
    data.oid_dot1q_Vlan_Static_Row_Status = '1.3.6.1.2.1.17.7.1.4.3.1.5'
    data.oid_dot1q_Pvid = '1.3.6.1.2.1.17.7.1.4.5.1.1'
    data.source_mac = "00:0a:01:00:00:01"
    data.source_mac1 = "00:0a:02:00:00:01"
    data.vlan = str(random_vlan_list()[0])
    data.dot1q_Vlan_Static_Table = '1.3.6.1.2.1.17.7.1.4.3'
    data.dot1q_Vlan_Current_Table = '1.3.6.1.2.1.17.7.1.4.2'
    data.dot1q_Tp_Fdb_Table = '1.3.6.1.2.1.17.7.1.2.2'
    data.dot1q_Fdb_Table = '1.3.6.1.2.1.17.7.1.2.1'
    data.nsNotifyShutdown='8072.4.0.2'
    data.filter = '-Oqv'


def snmp_pre_config():
    """
    SNMP pre config
    """
    global ipaddress
    ipaddress_list = basic_obj.get_ifconfig_inet(vars.D1, data.mgmt_int)
    st.log("Checking Ip address of the Device ")
    if not ipaddress_list:
        st.report_env_fail("ip_verification_fail")
    ipaddress = ipaddress_list[0]
    st.log("Device ip addresse - {}".format(ipaddress))
    snmp_obj.set_snmp_config(vars.D1, snmp_rocommunity= data.ro_community, snmp_location=data.location)
    if not st.is_community_build():
        ipfeature.configure_loopback(vars.D1, loopback_name="Loopback0", config="yes")
        ipfeature.config_ip_addr_interface(vars.D1, data.loopback0, data.loopback_addr, 32, family=data.af_ipv4)
    if not ipfeature.ping(vars.D1, ipaddress, family='ipv4', external=True):
        st.error("Ping reachability is failed between SNMP server and Device.")
    if not snmp_obj.poll_for_snmp(vars.D1, data.wait_time, 1, ipaddress=ipaddress,
                                  oid=data.oid_sysName, community_name=data.ro_community):
        st.log("Post SNMP config , snmp is not working")
        st.report_fail("operation_failed")

def vlan_preconfig():
    if not vlan_obj.create_vlan(vars.D1, data.vlan):
        st.report_fail("vlan_create_fail", data.vlan)
    if not st.is_community_build():
        mac_obj.config_mac(vars.D1, data.source_mac, data.vlan, vars.D1T1P1)
    st.log("Adding TGen-1 connected interface to newly created vlan in un tagging mode.")
    if not vlan_obj.add_vlan_member(vars.D1, data.vlan, vars.D1T1P1, tagging_mode=False):
            st.report_fail("vlan_untagged_member_fail", vars.D1T1P1, data.vlan)
    st.log("Adding TGen-2 connected interface to newly created vlan in tagging mode.")
    if not vlan_obj.add_vlan_member(vars.D1, data.vlan, vars.D1T1P2, tagging_mode=True):
            st.report_fail("vlan_untagged_member_fail", vars.D1T1P2, data.vlan)


def snmp_traffic_config():
    tg_handler = tgapi.get_handles_byname("T1D1P1", "T1D1P2")
    tg = tg_handler["tg"]
    tg.tg_traffic_control(action="reset", port_handle=tg_handler["tg_ph_list"])
    tg.tg_traffic_control(action="clear_stats", port_handle=tg_handler["tg_ph_list"])

    data.streams = {}
    stream = tg.tg_traffic_config(port_handle=tg_handler["tg_ph_1"], mode='create',
                                  transmit_mode='continuous', length_mode='fixed', rate_pps=100, frame_size=72,
                                  l2_encap='ethernet_ii_vlan', vlan_id=data.vlan, mac_src='00:0a:01:00:00:01',
                                  mac_src_step='00:00:00:00:00:01', mac_src_mode='increment', mac_src_count=10,
                                  mac_dst='00:0a:12:00:00:01', vlan="enable")
    data.streams['stream1'] = stream['stream_id']
    stream = tg.tg_traffic_config(port_handle=tg_handler["tg_ph_2"], mode='create',
                                  transmit_mode='continuous', length_mode='fixed', rate_pps=10,
                                  l2_encap='ethernet_ii_vlan', vlan_id=data.vlan, mac_src='00:0a:12:00:00:01',
                                  mac_dst='00:0a:01:00:00:01', vlan="enable")
    data.streams['stream2'] = stream['stream_id']
    intf_obj.clear_interface_counters(vars.D1)
    tg.tg_traffic_control(action='run', stream_handle=[data.streams['stream1'], data.streams['stream2']])
    st.wait(2)
    tg.tg_traffic_control(action='stop', stream_handle=[data.streams['stream1'], data.streams['stream2']])


def snmp_trap_pre_config():
    global capture_file, ssh_conn_obj
    ip = ensure_service_params(vars.D1, "snmptrap", "ip")
    username = ensure_service_params(vars.D1, "snmptrap", "username")
    password = ensure_service_params(vars.D1, "snmptrap", "password")
    path = ensure_service_params(vars.D1, "snmptrap", "path")

    # Connect to the linux machine and check
    ssh_conn_obj = connect_to_device(ip, username, password)
    if not ssh_conn_obj:
        st.report_tc_fail("ssh_connection_failed", ip)

    # enable traps on DUT
    snmp_obj.config_snmp_trap(vars.D1, version=2, ip_addr=ip, community= data.ro_community)

    # start capture on the linux machine
    capture_file = path


def snmp_post_config():
    """
    SNMP post config
    """
    snmp_obj.restore_snmp_config(vars.D1)
    if not st.is_community_build():
        ipfeature.configure_loopback(vars.D1, loopback_name="Loopback0", config="no")


def vlan_postconfig():
    if not st.is_community_build(vars.D1):
        mac_obj.clear_mac(vars.D1, port=vars.D1T1P1, vlan=data.vlan)
    else:
        mac_obj.clear_mac(vars.D1)
    vlan_obj.delete_vlan_member(vars.D1, data.vlan, [vars.D1T1P1, vars.D1T1P2])
    vlan_obj.delete_vlan(vars.D1, data.vlan)


def snmp_trap_post_config():
    snmp_obj.config_snmp_trap(vars.D1, version=2, ip_addr=None, no_form=True)
    clear_cmd = "echo > {}".format(capture_file)
    st.log("Clearing the snmptrap log with command '{}'".format(clear_cmd))
    execute_command(ssh_conn_obj, clear_cmd)

def snmptrapd_checking():
    retval = False

    # check and start the snmptrap on the given server.
    ps_cmd = "ps -ealf | grep snmptrapd | grep -v grep"
    st.log("Checking for snmptrap process existence with command '{}'".format(ps_cmd))
    output = execute_command(ssh_conn_obj,ps_cmd)
    ps_lines = "\n".join(output.split("\n")[:-1])

    if "snmptrapd" in ps_lines:
        retval = True

    return retval


def device_eth0_ip_addr():
    """
    To get the ip address of device after reboot.
    """
    ipaddress = st.get_mgmt_ip(vars.D1)
    st.log("Device ip address - {}".format(ipaddress))
    if not ipfeature.ping(vars.D1, ipaddress, family='ipv4', external=True):
        st.error("Ping reachability is failed between SNMP server and Device.")


@pytest.mark.snmp_sysName
@pytest.mark.regression
@pytest.mark.community
@pytest.mark.community_pass
def test_ft_snmp_sysName():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that the sysName MIB object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    st.log("Ensuring minimum topology")
    hostname = basic_obj.get_hostname(vars.D1)
    get_snmp_output= snmp_obj.get_snmp_operation(ipaddress=ipaddress, oid=data.oid_sysName,
                                                 community_name=data.ro_community)
    st.log("hostname Device('{}') and SNMP('{}')".format(hostname, get_snmp_output[0]))
    if not get_snmp_output[0] == hostname:
        st.report_fail("sysName_verification_fail")
    st.report_pass("test_case_passed")


@pytest.mark.regression
@pytest.mark.snmp_sysUpTime
@pytest.mark.community
@pytest.mark.community_pass
def test_ft_snmp_test_syUpTime():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that the sysUpTime MIB object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    st.log("Ensuring minimum topology")
    get_snmp_output = snmp_obj.get_snmp_operation(ipaddress=ipaddress, oid=data.oid_syUpTime,
                                                  community_name=data.ro_community)
    uptime_cli_sec = box_obj.get_system_uptime_in_seconds(vars.D1)
    days, hours,minutes, seconds = re.findall(r"(\d+):(\d+):(\d+):(\d+).\d+", get_snmp_output[0])[0]
    get_snmp_output = util_obj.convert_time_to_seconds(days, hours,minutes, seconds)
    st.log("Up time value from DUT is :{} & get_snmp_output value is :{} &"
           " get_snmp_output tolerance value is : {}"
           .format(uptime_cli_sec, get_snmp_output, get_snmp_output + 3))
    if not (get_snmp_output >= uptime_cli_sec or get_snmp_output+3 >= uptime_cli_sec):
        st.report_fail("sysUptime_verification_fail")
    st.report_pass("test_case_passed")


@pytest.mark.regression
@pytest.mark.snmp_sysLocation
@pytest.mark.community
@pytest.mark.community_pass
def test_ft_snmp_sysLocation():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that the sysLocation MIB object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    location_output = snmp_obj.get_snmp_config(vars.D1)[0]["snmp_location"]
    st.log("System Location from the device is : {} ".format(location_output))
    get_snmp_output = snmp_obj.get_snmp_operation(ipaddress=ipaddress,
                                                  oid=data.oid_sysLocation, community_name=data.ro_community)
    st.log("System Location from the SNMP output: {} ".format(get_snmp_output[0]))
    if not get_snmp_output[0] == location_output:
        st.log(" Up time is not matching between device sysuptime and snmp uptime ")
        st.report_fail("sysLocation_verification_fail")
    st.report_pass("test_case_passed")


@pytest.mark.regression
@pytest.mark.snmp_sysDescr
@pytest.mark.community
@pytest.mark.community_pass
def test_ft_snmp_sysDescr():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that the sysDescr MIB object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    descrip_output= basic_obj.show_version(vars.D1)["hwsku"]
    get_snmp_output = snmp_obj.get_snmp_operation(ipaddress=ipaddress, oid=data.oid_sysDescr,
                                                  community_name=data.ro_community)
    get_snmp_output = get_snmp_output[0]
    get_snmp_output_value = get_snmp_output.split(' - ')[1].split(':')[1].strip()
    if not descrip_output == get_snmp_output_value:
        st.report_fail("sysDescr_verification_fail")
    st.report_pass("test_case_passed")


@pytest.mark.regression
@pytest.mark.snmp_sysContact
@pytest.mark.community
@pytest.mark.community_pass
def test_ft_snmp_sysContact():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that the sysContact MIB object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    contact_output = ""
    get_snmp_output = snmp_obj.get_snmp_operation(ipaddress=ipaddress, oid=data.oid_sysContact,
                                                  community_name=data.ro_community)
    get_snmp_output = get_snmp_output[0]
    st.log("System Contact from the SNMP output: {} ".format(get_snmp_output))
    st.log("System Contact from the DUT output: {} ".format(contact_output))
    if not contact_output == get_snmp_output:
        st.log(" Contact  is not matching between device Contact and snmp Contact ")
        st.report_fail("sysContact_verification_fail")
    st.report_pass("test_case_passed")

@pytest.mark.regression
@pytest.mark.snmp_mib_2
@pytest.mark.community
@pytest.mark.community_pass
def test_ft_snmp_mib_2():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that snmpwalk on mib_2 MIB object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_mib_2,
                                                   community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("get_snmp_output_fail")
    st.report_pass("test_case_passed")


@pytest.mark.regression
@pytest.mark.snmp_if_mib_all
@pytest.mark.community
@pytest.mark.community_pass
def test_ft_snmp_if_mib_all():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that snmpwalk on if_mib_all MIB object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_if_mib_all,
                                                  community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("Fail")
    st.report_pass("test_case_passed")


@pytest.mark.regression
@pytest.mark.snmp_entity_mib_all
@pytest.mark.community
@pytest.mark.community_pass
def test_ft_snmp_entity_mib_all():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that snmpwalk on entity_mib_all MIB object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_entity_mib_all,
                                                  community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("get_snmp_output_fail")
    st.report_pass("test_case_passed")


@pytest.mark.regression
@pytest.mark.snmp_entity_sensor
@pytest.mark.community
@pytest.mark.community_pass
def test_ft_snmp_entity_sensor_mib():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that snmpwalk on entity_sensor_mib MIB object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_entity_sensor_mib,
                                                  community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("get_snmp_output_fail")
    st.report_pass("test_case_passed")


@pytest.mark.regression
@pytest.mark.snmp_dot1q_dot1db
@pytest.mark.community
@pytest.mark.community_pass
def test_ft_snmp_dot1q_dot1db_mib():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that snmpwalk on dot1q MIB object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    snmp_obj.poll_for_snmp_walk(vars.D1, data.wait_time, 3, ipaddress=ipaddress,
                           oid=data.oid_dot1q_mib, community_name=data.ro_community)
    get_snmp_output_dot1q = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_dot1q_mib,
                                                  community_name=data.ro_community)
    if not get_snmp_output_dot1q:
        st.report_fail("get_snmp_output_fail")
    get_snmp_output_dot1db = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_dot1db_mib,
                                                   community_name=data.ro_community)
    if not get_snmp_output_dot1db:
        st.report_fail("get_snmp_output_fail")

    st.report_pass("test_case_passed")


@pytest.mark.regression
@pytest.mark.snmp_root_node_walk
@pytest.mark.community
@pytest.mark.community_pass
def test_ft_snmp_root_node_walk():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that snmpwalk on entity_sensor_mib MIB object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    snmp_obj.poll_for_snmp_walk(vars.D1, data.wait_time, 3, ipaddress=ipaddress,
                                oid=data.oid_root_node_walk, community_name=data.ro_community)
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_root_node_walk,
                                                  community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("get_snmp_output_fail")
    st.report_pass("test_case_passed")

@pytest.mark.regression
@pytest.mark.snmp_ipAddressRowStatus_ipv6
@pytest.mark.community
@pytest.mark.community_pass
def test_ft_snmp_ipAddressRowStatus_ipv6():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that snmpwalk on IP-MIB::ipAddressRowStatus.ipv6 MIB object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_IP_MIB_ipAddressRowStatus_ipv6,
                                                  community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("get_snmp_output_fail")
    st.report_pass("test_case_passed")


@pytest.mark.regression
@pytest.mark.snmp_ipAddressStorageType_ipv6
@pytest.mark.community
@pytest.mark.community_pass
def test_ft_snmp_ipAddressStorageType_ipv6():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that snmpwalk on IP-MIB::ipAddressStorageType.ipv6 MIB object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_IP_MIB_ipAddressStorageType_ipv6,
                                                  community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("get_snmp_output_fail")
    st.report_pass("test_case_passed")


@pytest.mark.regression
@pytest.mark.snmp_ipv6IfDescr
@pytest.mark.community
@pytest.mark.community_pass
def test_ft_snmp_ipv6_If_Descr():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that snmpwalk on IPV6-MIB::ipv6IfDescr MIB object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_IPV6_MIB_ipv6IfDescr,
                                                  community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("get_snmp_output_fail")
    st.report_pass("test_case_passed")


@pytest.mark.regression
@pytest.mark.snmp_ipv6IfAdminStatus
@pytest.mark.community
@pytest.mark.community_pass
def test_ft_snmp_ipv6_If_AdminStatus():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that snmpwalk on IPV6-MIB::ipv6IfAdminStatus MIB object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_IPV6_MIB_ipv6IfAdminStatus,
                                                  community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("get_snmp_output_fail")
    st.report_pass("test_case_passed")


@pytest.mark.regression
@pytest.mark.snmp_ipv6IpForwarding_and_DefaultHopLimit
@pytest.mark.community
@pytest.mark.community_pass
def test_ft_snmp_ipv6_If_Forward_default_HopLimit():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that snmpwalk on  ipv6IpForwarding and ipv6IpDefaultHopLimit MIB object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_IPV6_MIB_ipv6IpForwarding,
                                                  community_name=data.ro_community)
    get_snmp_output_1 = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_IPV6_MIB_ipv6IpDefaultHopLimit,
                                                  community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("get_snmp_output_fail")
    if not get_snmp_output_1:
        st.report_fail("get_snmp_output_fail")

    st.report_pass("test_case_passed")


@pytest.mark.regression
@pytest.mark.snmp_ipv6IpForwarding_and_DefaultHopLimit
@pytest.mark.community
@pytest.mark.community_pass
def test_ft_snmp_ipv6scope_index_table():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that snmpwalk on ipv6ScopeZoneIndexTable MIB object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_IPV6_MIB_ipv6ScopeZoneIndexTable,
                                                  community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("get_snmp_output_fail")
    st.report_pass("test_case_passed")


@pytest.mark.regression
@pytest.mark.snmp_ipcidrroutetable
def test_ft_snmp_ipcidr_route_table():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that snmpwalk walk on ipCidrroutetable MIB functions properly
    Reference Test Bed : D1 --- Mgmt Network
    """
    snmp_obj.poll_for_snmp_walk(vars.D1, data.wait_time,3, ipaddress=ipaddress,
                                oid=data.oid_ipcidr_route_table, community_name=data.ro_community)
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_ipcidr_route_table,
                                                   community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("get_snmp_output_fail")
    st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1d_bridge
@pytest.mark.regression
def test_ft_snmp_dot1d_base_bridge_address():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that the dot1dBaseBridgeAddress Object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_dot1d_Base_Bridge_Address,
                                                   community_name=data.ro_community)
    mac_address=basic_obj.get_ifconfig_ether(vars.D1,'eth0')
    if not str(mac_address) in get_snmp_output[0]:
        st.report_fail("snmp_output_failed", "dot1dBaseBridgeAddress")
    st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1d_bridge
@pytest.mark.regression
def test_ft_snmp_dot1d_base_num_ports():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that the dot1dBaseNumPorts Object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_dot1d_Base_Num_Ports,
                                                   community_name=data.ro_community,filter=data.filter)
    if str(2) not in get_snmp_output:
        st.report_fail("snmp_output_failed", "dot1dBaseNumPorts")
    st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1d_bridge
@pytest.mark.regression
def test_ft_snmp_dot1d_base_type():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that the dot1dBaseType Object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_dot1d_Base_Type,
                                                   community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("snmp_output_failed", "dot1dBaseType")
    st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1d_bridge
@pytest.mark.regression
def test_ft_snmp_dot1d_base_port():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that the dot1dBasePort Object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid= data.oid_dot1d_Base_Port,
                                                   community_name=data.ro_community,filter=data.filter)
    intf_name1=util_obj.get_interface_number_from_name(vars.D1T1P1)
    intf_name2 = util_obj.get_interface_number_from_name(vars.D1T1P2)
    if (intf_name1.get('number') not in str(get_snmp_output)) and (intf_name2.get('number') not in str(get_snmp_output)):
        st.report_fail("snmp_output_failed", "dot1dBasePort")
    st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1d_bridge
@pytest.mark.regression
def test_ft_snmp_dot1d_base_port_ifindex():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that the dot1dBasePortIfIndex Object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid= data.oid_dot1d_Base_PortIf_Index,
                                                   community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("snmp_output_failed", "dot1dBasePortIfIndex")
    st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1d_bridge
@pytest.mark.regression
def test_ft_snmp_dot1d_base_port_delay_exceeded_discards():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that the dot1dBasePortDelayExceededDiscards Object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid= data.oid_dot1d_Base_Port_Delay_Exceeded_Discards,
                                                   community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("snmp_output_failed", "dot1dBasePortDelayExceededDiscards")
    st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1d_bridge
@pytest.mark.regression
def test_ft_snmp_dot1d_base_port_mtu_exceeded_discards():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that the dot1dBasePortMtuExceededDiscards Object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid= data.oid_dot1d_Base_Port_Mtu_Exceeded_Discards,
                                                   community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("snmp_output_failed", "dot1dBasePortMtuExceededDiscards")
    st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1d_bridge
@pytest.mark.regression
def test_ft_snmp_dot1d_tp_aging_time():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that the dot1dTpAgingTime Object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid= data.oid_dot1d_Tp_Aging_Time,
                                                   community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("snmp_output_failed", "dot1dTpAgingTime")
    st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1q_table_requirement
@pytest.mark.regression
def test_ft_snmp_dot1q_fdb_dynamic_count():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that the dot1qFdbDynamicCount Object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid= data.oid_dot1q_Fdb_Dynamic_Count,
                                                   community_name=data.ro_community)
    count=mac_obj.get_mac_count(vars.D1)
    if str(count-1) not in get_snmp_output[0]:
        st.report_fail("snmp_output_failed", "dot1qFdbDynamicCount")
    st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1q_table_requirement
@pytest.mark.regression
def test_ft_snmp_dot1q_tp_fdb_port():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that the dot1qTpFdbPort Object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid= data.oid_dot1q_Tp_Fdb_Port,
                                                   community_name=data.ro_community)
    intf_name = util_obj.get_interface_number_from_name(vars.D1T1P2)
    if intf_name.get('number') not in get_snmp_output[0]:
        st.report_fail("snmp_output_failed", "dot1qTpFdbPort")
    st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1q_table_requirement
@pytest.mark.regression
def test_ft_snmp_dot1q_tp_fdb_status():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that the dot1qTpFdbStatus Object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid= data.oid_dot1q_Tp_Fdb_Status,
                                                   community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("snmp_output_failed", "dot1qTpFdbStatus")
    st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1q_table_requirement
@pytest.mark.regression
def test_ft_snmp_dot1q_vlan_current_egress_ports():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that the dot1qVlanCurrentEgressPorts Object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid= data.oid_dot1q_Vlan_Current_Egress_Ports,
                                                   community_name=data.ro_community,filter=data.filter)
    if len(get_snmp_output[0].split(" ")) != 2:
        st.report_fail("snmp_output_failed", "dot1qVlanCurrentEgressPorts")
    st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1q_table_requirement
@pytest.mark.regression
def test_ft_snmp_dot1q_vlan_current_untagged_ports():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that the dot1qVlanCurrentUntaggedPorts Object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=  data.oid_dot1q_Vlan_Current_Untagged_Ports,
                                                   community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("snmp_output_failed", "dot1qVlanCurrentUntaggedPorts")
    st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1q_table_requirement
@pytest.mark.regression
def test_ft_snmp_dot1q_vlan_static_untagged_ports():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that the dot1qVlanStaticUntaggedPorts Object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=  data.oid_dot1q_Vlan_Static_Untagged_Ports,
                                                   community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("snmp_output_failed", "dot1qVlanStaticUntaggedPorts")
    st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1q_table_requirement
@pytest.mark.regression
def test_ft_snmp_dot1q_vlan_static_row_status():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that the dot1qVlanStaticRowStatus Object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=   data.oid_dot1q_Vlan_Static_Row_Status,
                                                   community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("snmp_output_failed", "dot1qVlanStaticRowStatus")
    st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1q_table_requirement
@pytest.mark.regression
def test_ft_snmp_dot1q_pvid():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that the dot1qPvid Object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=   data.oid_dot1q_Pvid,
                                                   community_name=data.ro_community,filter=data.filter)
    if str(data.vlan) not in str(get_snmp_output):
        st.report_fail("snmp_output_failed", "dot1qPvid")
    st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1q_table_requirement
@pytest.mark.regression
def test_ft_snmp_dot1q_vlan_static_name():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that the dot1qVlanStaticName Object functions properly.
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_dot1q_Vlan_Static_Name,
                                                   community_name=data.ro_community,filter=data.filter)
    if data.vlan not in get_snmp_output[0]:
        st.report_fail("snmp_output_failed", "dot1qVlanStaticName")
    st.report_pass("test_case_passed")


@pytest.mark.snmp_dot1q_table_requirement
@pytest.mark.regression
def test_ft_snmp_dot1q_vlan_static_egress_ports():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that the dot1qVlanStaticEgressPorts Object functions properly.
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_dot1q_Vlan_Static_Egress_Ports,
                                                   community_name=data.ro_community,filter=data.filter)
    if len(get_snmp_output[0].split(" ")) != 2:
        st.report_fail("snmp_output_failed", "dot1qVlanStaticEgressPorts")
    st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1q_dot1q_scale_and_performance
@pytest.mark.regression
def test_ft_snmp_dot1q_vlan_version_number():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that the dot1qVlanVersionNumber Object functions properly.
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_dot1q_Vlan_Version_Number,
                                                   community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("snmp_output_failed", "dot1qVlanVersionNumber")
    st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1q_scale_and_performance
@pytest.mark.regression
def test_ft_snmp_dot1q_max_vlanid():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that the dot1qMaxVlanId Object functions properly.
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_dot1q_Max_VlanId,
                                                   community_name=data.ro_community,filter=data.filter)
    if st.get_datastore(vars.D1, "constants","default")['MAX_VLAN_ID'] not in get_snmp_output[0]:
        st.report_fail("snmp_output_failed", "dot1qMaxVlanId")
    st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1q_scale_and_performance
@pytest.mark.regression
def test_ft_snmp_dot1q_max_supported_vlans():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that the dot1qMaxSupportedVlans Object functions properly.
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_dot1q_Max_Supported_Vlans,
                                                   community_name=data.ro_community,filter=data.filter)
    if st.get_datastore(vars.D1, "constants", "default")['MAX_SUPPORTED_VLANS'] not in get_snmp_output[0]:
        st.report_fail("snmp_output_failed", "dot1qMaxSupportedVlans")
    st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1q_scale_and_performance
@pytest.mark.regression
def test_ft_snmp_dot1q_num_vlans():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that the dot1qNumVlans Object functions properly.
    """
    count=vlan_obj.get_vlan_count(vars.D1)
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_dot1q_Num_Vlans,
                                                   community_name=data.ro_community,filter=data.filter)
    if str(count) not in get_snmp_output:
        st.report_fail("snmp_output_failed", "dot1qNumVlans")
    st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1q_scale_and_performance
@pytest.mark.regression
def test_ft_snmp_dot1q_vlan_num_deletes():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that the dot1qVlanNumDeletes Object functions properly.
    """
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_dot1q_Vlan_Num_Deletes,
                                                   community_name=data.ro_community)
    if not get_snmp_output:
        st.report_fail("snmp_output_failed", "dot1qVlanNumDeletes")
    st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1q_table_requirement
@pytest.mark.regression
def test_ft_snmp_vlan_static_table():
   """
   Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
   Verify that the dot1qVlanStaticEntry Object functions properly.
   """
   get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.dot1q_Vlan_Static_Table,
                                                       community_name=data.ro_community)
   out = snmp_obj.get_oids_from_walk_output(get_snmp_output)
   out = [str(x) for x in out]
   for x in out:
       get_snmp_output = snmp_obj.get_snmp_operation(ipaddress=ipaddress, oid=x,
                                                          community_name=data.ro_community)
       if not get_snmp_output:
           st.report_fail("snmp_output_failed", "dot1qVlanStaticTable")
       get_snmp_output = snmp_obj.get_snmp_operation(ipaddress=ipaddress, oid=x,
                                                         community_name=data.ro_community,get_next=True)
       if not get_snmp_output:
           st.report_fail("snmp_output_failed", "dot1qVlanStaticTable")
   st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1q_table_requirement
@pytest.mark.regression
def test_ft_snmp_dot1q_vlan_index():
   """
   Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
   Verify that the dot1qVlanIndex Object functions properly.
   """
   get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid= data.dot1q_Vlan_Current_Table,
                                                       community_name=data.ro_community)
   out = snmp_obj.get_oids_from_walk_output(get_snmp_output)
   out = [str(x) for x in out]
   for x in out:
       get_snmp_output = snmp_obj.get_snmp_operation(ipaddress=ipaddress, oid=x,
                                                          community_name=data.ro_community)
       if not get_snmp_output:
           st.report_fail("snmp_output_failed", "dot1qVlanIndex")
       get_snmp_output = snmp_obj.get_snmp_operation(ipaddress=ipaddress, oid=x,
                                                         community_name=data.ro_community,get_next=True)
       if not get_snmp_output:
           st.report_fail("snmp_output_failed", "dot1qVlanIndex")
   st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1q_table_requirement
@pytest.mark.regression
def test_ft_snmp_dot1q_tp_fdb_address():
   """
   Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
   Verify that the dot1qTpFdbAddress Object functions properly.
   """
   snmp_obj.poll_for_snmp_walk(vars.D1, data.wait_time,1, ipaddress=ipaddress,
                               oid=data.dot1q_Tp_Fdb_Table, community_name=data.ro_community)
   get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.dot1q_Tp_Fdb_Table,
                                                       community_name=data.ro_community)
   out = snmp_obj.get_oids_from_walk_output(get_snmp_output)
   out = [str(x) for x in out]
   for x in out:
       get_snmp_output = snmp_obj.get_snmp_operation(ipaddress=ipaddress, oid=x,
                                                          community_name=data.ro_community)
       if not get_snmp_output:
           st.report_fail("snmp_output_failed", "dot1qTpFdbAddress")
       get_snmp_output = snmp_obj.get_snmp_operation(ipaddress=ipaddress, oid=x,
                                                         community_name=data.ro_community,get_next=True)
       if not get_snmp_output:
           st.report_fail("snmp_output_failed", "dot1qTpFdbAddress")
   st.report_pass("test_case_passed")

@pytest.mark.snmp_dot1q_table_requirement
@pytest.mark.regression
def test_ft_snmp_dot1q_fdb_table():
   """
   Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
   Verify that the dot1qFdbEntry Object functions properly.
   """
   get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.dot1q_Fdb_Table,
                                                       community_name=data.ro_community)
   out = snmp_obj.get_oids_from_walk_output(get_snmp_output)
   out = [str(x) for x in out]
   for x in out:
       get_snmp_output = snmp_obj.get_snmp_operation(ipaddress=ipaddress, oid=x,
                                                          community_name=data.ro_community)
       if not get_snmp_output:
           st.report_fail("snmp_output_failed", "dot1qFdbTable")
       get_snmp_output = snmp_obj.get_snmp_operation(ipaddress=ipaddress, oid=x,
                                                         community_name=data.ro_community,get_next=True)
       if not get_snmp_output:
           st.report_fail("snmp_output_failed", "dot1qFdbTable")
   st.report_pass("test_case_passed")

@pytest.mark.snmp_trap
def test_ft_snmp_link_down_trap():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that trap is sent when a link is down.
    """
    check_flag = snmptrapd_checking()
    if not check_flag:
        st.report_fail("snmptrapd_not_running")

    # trigger trap on DUT
    intf_obj.interface_shutdown(vars.D1, vars.D1T1P1)
    intf_obj.interface_noshutdown(vars.D1, vars.D1T1P1)

    # get data from capture
    read_cmd = "cat {}".format(capture_file)

    output = execute_command(ssh_conn_obj, read_cmd)
    trap_lines = output.split("\n")[:-1]

    result=any('linkDown' in x for x in trap_lines)
    if result == 0:
        st.report_fail("snmp_output_failed", "linkDown")
    else:
         st.report_pass("test_case_passed")

@pytest.mark.snmp_trap
def test_ft_snmp_link_up_trap():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that trap is sent when a link is UP.
    """
    check_flag = snmptrapd_checking()
    if not check_flag:
        st.report_fail("snmptrapd_not_running")

    # trigger trap on DUT
    intf_obj.interface_shutdown(vars.D1, vars.D1T1P1)
    intf_obj.interface_noshutdown(vars.D1, vars.D1T1P1)

    # get data from capture
    read_cmd = "cat {}".format(capture_file)

    output = execute_command(ssh_conn_obj, read_cmd)
    trap_lines = output.split("\n")[:-1]

    result = any('linkUp' in x for x in trap_lines)
    if result == 0:
        st.report_fail("snmp_output_failed", "linkUp")
    else:
        st.report_pass("test_case_passed")

@pytest.mark.snmp_trap
def test_ft_snmp_coldstart_trap():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that trap is sent when rps reboot is performed.
    """
    check_flag = snmptrapd_checking()
    if not check_flag:
        st.report_fail("snmptrapd_not_running")

    # trigger trap on DUT
    st.reboot(vars.D1)

    # Get the ip address of the switch after reboot
    device_eth0_ip_addr()

    # get data from capture
    read_cmd = "cat {}".format(capture_file)

    output = execute_command(ssh_conn_obj,read_cmd)
    trap_lines = output.split("\n")[:-1]

    result = any('coldStart' in x for x in trap_lines)
    if result == 0:
        st.report_fail("snmp_output_failed", "coldStart")
    else:
        st.report_pass("test_case_passed")

@pytest.mark.snmp_trap
def test_ft_snmp_nsnotifyshutdown_trap():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that trap is sent when snmp docker is restarted.
    """
    check_flag = snmptrapd_checking()
    if not check_flag:
        st.report_fail("snmptrapd_not_running")

    # trigger trap on DUT
    basic_obj.docker_operation(vars.D1,"snmp","restart")

    # get data from capture
    read_cmd = "cat {}".format(capture_file)
    output = execute_command(ssh_conn_obj,read_cmd)
    trap_lines = output.split("\n")[:-1]

    result = any(data.nsNotifyShutdown in x for x in trap_lines)
    if result == 0:
        st.report_fail("snmp_output_failed", "nsNotifyShutdown")
    else:
        st.report_pass("test_case_passed")

@pytest.mark.snmp_trap
def test_ft_snmp_warmstart_trap():
    """
    Author : Prasad Darnasi<prasad.darnasi@broadcom.com>
    Verify that trap is sent when reboot is performed.
    """
    check_flag = snmptrapd_checking()
    if not check_flag:
        st.report_fail("snmptrapd_not_running")

    # trigger trap on DUT
    reboot.config_save(vars.D1)
    st.reboot(vars.D1, 'warm')

    # Get the ip address of the switch after reboot
    device_eth0_ip_addr()

    # get data from capture
    read_cmd = "cat {}".format(capture_file)
    output = execute_command(ssh_conn_obj,read_cmd)
    trap_lines = output.split("\n")[:-1]

    result = any('warmStart' in x for x in trap_lines)
    if result == 0:
        for i in range(1, 4):
            read_cmd = "cat {}".format(capture_file)
            output = execute_command(ssh_conn_obj, read_cmd)
            trap_lines = output.split("\n")[:-1]
            result = any('warmStart' in x for x in trap_lines)
            if result == 1:
              break
            st.wait(10)
    if result == 0:
        st.report_fail("snmp_output_failed", "warmStart")
    else:
        st.report_pass("test_case_passed")

@pytest.mark.snmp_docker_restart
def test_ft_snmp_docker_restart():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that the sysName MIB object functions properly after docker restart
    Reference Test Bed : D1--- Mgmt Network
    """
    basic_obj.service_operations_by_systemctl(vars.D1, 'snmp', 'restart')
    if not basic_obj.poll_for_system_status(vars.D1, 'snmp', 30, 1):
        st.report_fail("service_not_running".format('snmp'))
    if not basic_obj.verify_service_status(vars.D1, 'snmp'):
        st.report_fail("snmp_service_not_up")
    hostname =basic_obj.get_hostname(vars.D1)
    get_snmp_output= snmp_obj.get_snmp_operation(ipaddress=ipaddress, oid=data.oid_sysName,
                                                 community_name=data.ro_community)
    st.log("hostname Device('{}') and SNMP('{}')".format(hostname, get_snmp_output[0]))
    if not get_snmp_output[0] == hostname:
        st.report_fail("sysName_verification_fail_after_docker_restart")
    st.report_pass("test_case_passed")



