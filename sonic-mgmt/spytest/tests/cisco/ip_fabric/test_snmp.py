import pytest
import re
from spytest import st, SpyTestDict

import apis.routing.ip as ip_obj
import apis.system.snmp as snmp_obj
import apis.system.basic as basic_obj
import apis.system.box_services as box_obj
import utilities.utils as util_obj

data = SpyTestDict()


@pytest.fixture(scope="module", autouse=True)
def snmp_module_hooks(request):
    global vars
    vars = st.ensure_min_topology("D1")
    initialize_variables()
    snmp_pre_config()

    yield
    snmp_post_config()


@pytest.fixture(scope="function", autouse=True)
def snmp_func_hooks(request):
    global ipaddress
    ipaddress = st.get_mgmt_ip(vars.D1)
    yield


def initialize_variables():
    data.clear()
    data.ro_community = 'test_123'
    data.location = 'US.MSC.02.01.2100.15.01.44'
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
    data.oid_mib_2 = '1.3.6.1.2.1'
    data.oid_root_node_walk = '.'
    data.af_ipv4 = "ipv4"
    data.loopback_addr = '67.66.66.66'
    data.loopback0 = 'Loopback0'


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
    snmp_obj.set_snmp_config(vars.D1, snmp_rocommunity=data.ro_community, snmp_location=data.location)
    ip_obj.configure_loopback(vars.D1, loopback_name=data.loopback0, config="yes")
    ip_obj.config_ip_addr_interface(vars.D1, data.loopback0, data.loopback_addr, 32, family=data.af_ipv4)
    if not ip_obj.ping(vars.D1, ipaddress, family='ipv4', external=True):
        st.error("Ping reachability is failed between SNMP server and Device.")
    if not snmp_obj.poll_for_snmp(vars.D1, data.wait_time, 1, ipaddress=ipaddress,
                                  oid=data.oid_sysName, community_name=data.ro_community):
        st.log("Post SNMP config , snmp is not working")
        st.report_fail("operation_failed")


def snmp_post_config():
    """
    SNMP post config
    """
    ip_obj.configure_loopback(vars.D1, loopback_name=data.loopback0, config="no")


@pytest.mark.drop_1
def test_ft_snmp_sysName():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that the sysName MIB object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    st.log("Ensuring minimum topology")
    hostname = basic_obj.get_hostname(vars.D1)
    get_snmp_output = snmp_obj.get_snmp_operation(ipaddress=ipaddress, oid=data.oid_sysName,
                                                  community_name=data.ro_community)
    st.log("hostname Device('{}') and SNMP('{}')".format(hostname, get_snmp_output[0]))
    if not get_snmp_output[0] == hostname:
        st.report_fail("sysName_verification_fail")
    st.report_pass("test_case_passed")


@pytest.mark.drop_1
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
    days, hours, minutes, seconds = re.findall(r"(\d+):(\d+):(\d+):(\d+).\d+", get_snmp_output[0])[0]
    get_snmp_output = util_obj.convert_time_to_seconds(days, hours, minutes, seconds)
    st.log("Up time value from DUT is :{} & get_snmp_output value is :{} &"
           " get_snmp_output tolerance value is : {}"
           .format(uptime_cli_sec, get_snmp_output, get_snmp_output + 3))
    if not (get_snmp_output >= uptime_cli_sec or get_snmp_output+3 >= uptime_cli_sec):
        st.report_fail("sysUptime_verification_fail")
    st.report_pass("test_case_passed")


@pytest.mark.drop_1
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
        st.log("System location does not match with SNMP output ")
        st.report_fail("sysLocation_verification_fail")
    st.report_pass("test_case_passed")


@pytest.mark.drop_1
def test_ft_snmp_sysDescr():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that the sysDescr MIB object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    result = dict()
    descrip_output = basic_obj.show_version(vars.D1)['version'].strip("'")
    hwsku = basic_obj.get_hwsku(vars.D1)
    get_snmp_output = snmp_obj.get_snmp_operation(ipaddress=ipaddress, oid=data.oid_sysDescr,
                                                  community_name=data.ro_community)
    st.log("SNMP GET output: {}".format(get_snmp_output))
    get_snmp_output = get_snmp_output[0]
    get_snmp_output = get_snmp_output.split(" - ")
    for entry in get_snmp_output:
        key, value = entry.split(":")
        if 'version' in key.lower():
            result['version'] = value.strip(" SONiC.")
        elif 'hwsku' in key.lower():
            result['hwsku'] = value.strip()
        elif 'distribution' in key.lower():
            result['distribution'] = value.strip()
        elif 'kernel' in key.lower():
            result['kernel'] = value.lower()
    if not (hwsku == result['hwsku'] and result['version'] in descrip_output):
        st.log("SNMP GET Output after processing is: {}".format(result))
        st.log("Version output is: {}".format(descrip_output))
        st.log("hwsku: {}".format(hwsku))
        st.report_fail("sysDescr_verification_fail")
    st.report_pass("test_case_passed")


@pytest.mark.drop_1
def test_ft_snmp_sysContact():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that the sysContact MIB object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    contact_output = "gns-dc:gio-dc-networks:P1:PROD aspant@cisco.com"
    get_snmp_output = snmp_obj.get_snmp_operation(ipaddress=ipaddress, oid=data.oid_sysContact,
                                                  community_name=data.ro_community)
    get_snmp_output = get_snmp_output[0]
    st.log("System Contact from the SNMP output: {} ".format(get_snmp_output))
    st.log("System Contact from the DUT output: {} ".format(contact_output))
    if not contact_output == get_snmp_output:
        st.log(" Contact  is not matching between device Contact and snmp Contact ")
        st.report_fail("sysContact_verification_fail")
    st.report_pass("test_case_passed")


@pytest.mark.drop_1
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
