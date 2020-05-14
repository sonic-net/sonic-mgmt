import pytest
from spytest import st
import apis.system.lldp as lldp_obj
import apis.system.snmp as snmp_obj
import apis.system.basic as basic_obj
import apis.system.interface as intf_obj
from spytest.dicts import SpyTestDict

@pytest.fixture(scope="module", autouse=True)
def lldp_snmp_module_hooks(request):
    global vars
    vars = st.ensure_min_topology("D1D2:1")
    global_vars()
    lldp_snmp_pre_config()
    yield
    lldp_snmp_post_config()


@pytest.fixture(scope="function", autouse=True)
def lldp_snmp_func_hooks(request):
    global_vars()
    yield


def global_vars():
    global data
    data = SpyTestDict()
    data.ro_community = 'test_community'
    data.mgmt_int = 'eth0'
    data.wait_time = 30
    data.location = 'hyderabad'
    data.oid_sysName = '1.3.6.1.2.1.1.5.0'
    data.oid_lldplocportid = '1.0.8802.1.1.2.1.3.7.1.3'
    data.oid_lldplocsysname = '1.0.8802.1.1.2.1.3.3'
    data.oid_lldplocsysdesc = '1.0.8802.1.1.2.1.3.4'
    data.oid_lldplocportdesc = '1.0.8802.1.1.2.1.4.1'
    data.oid_locmanaddrtable = '1.0.8802.1.1.2.1.1.7'
    data.oid_locmanaddrsubtype = '1.0.8802.1.1.2.1.3.8.1.1'
    data.oid_locmanaddroid = '1.0.8802.1.1.2.1.3.8.1.6'
    data.oid_locmanaddrlen = '1.0.8802.1.1.2.1.3.8.1.3'
    data.oid_locmanaddrlfld = '1.0.8802.1.1.2.1.3.8.1.5'
    data.oid_locmanaddrentry = '1.0.8802.1.1.2.1.3.8.1'
    data.oid_configmanaddrtable = '1.0.8802.1.1.2.1.1.7'
    data.oid_configmanaddrentry = '1.0.8802.1.1.2.1.1.7.1'
    data.filter = '-Oqv'

def lldp_snmp_pre_config():
    """
    LLDP Pre Config
    """
    global lldp_value
    global ipaddress
    global lldp_value_remote, lldp_value_gran
    global lldp_total_value
    data.ipaddress_d1 = basic_obj.get_ifconfig_inet(vars.D1, data.mgmt_int)
    data.ipaddress_d2 = basic_obj.get_ifconfig_inet(vars.D2, data.mgmt_int)
    if not data.ipaddress_d1:
        st.error(" Ip address is not a valid one or the ip is not presented on the device")
        st.report_fail("operation_failed")
    ipaddress = data.ipaddress_d1[0]
    if not intf_obj.poll_for_interfaces(vars.D1,iteration_count=60,delay=1):
        st.report_fail("interfaces_not_up_after_poll")
    if not intf_obj.poll_for_interfaces(vars.D2,iteration_count=60,delay=1):
        st.report_fail("interfaces_not_up_after_poll")
    if not lldp_obj.poll_lldp_neighbors(vars.D1, iteration_count=30, delay=1, interface=vars.D1D2P1):
        st.report_fail("lldp_neighbors_info_not_found_after_poll")
    if not lldp_obj.poll_lldp_neighbors(vars.D2, iteration_count=30, delay=1, interface=vars.D2D1P1):
        st.report_fail("lldp_neighbors_info_not_found_after_poll")
    st.log(" Getting Ip address of the Device")
    lldp_value = lldp_obj.get_lldp_neighbors(vars.D1, interface=vars.D1D2P1)
    lldp_value_remote = lldp_obj.get_lldp_neighbors(vars.D2, interface=vars.D2D1P1)
    st.log(" LLDP Neighbors value is: {} ".format(lldp_value))
    st.log(" Remote LLDP Neighbors value is: {} ".format(lldp_value_remote))
    if not lldp_value:
        st.error("No lldp entries are available")
        st.report_fail("operation_failed")
    if not lldp_value_remote:
        st.error(" No lldp entries are available in Remote")
        st.report_fail("operation_failed")
    lldp_value = lldp_value[0]
    lldp_total_value = lldp_value_remote
    lldp_value_remote = lldp_value_remote[0]
    lldp_value_gran = lldp_value['chassis_mgmt_ip']
    if not data.ipaddress_d2[0] == lldp_value_gran:
        st.error("LLDP info IP and device IP are not matching")
        st.report_fail("operation_failed")
    # TODO : Need to check the below once the infra defect SONIC-5374 is Fixed
    '''
    mac_output = basic_obj.get_platform_syseeprom(vars.D1, 'Serial Number', 'Value')
    lldp_value_mac = lldp_value['chassis_id_value']
    st.log("lldp_value_gran is :{}".format(lldp_value_gran))
    if not mac_output == lldp_value_mac:
        st.report_fail(" MAC Addresses are not matching ")
    '''
    snmp_obj.set_snmp_config(vars.D1, snmp_rocommunity=data.ro_community, snmp_location=data.location)
    if not snmp_obj.poll_for_snmp(vars.D1, 30 , 1 , ipaddress= data.ipaddress_d1[0],
                                  oid=data.oid_sysName, community_name=data.ro_community):
        st.log("Post SNMP config , snmp is not working")
        st.report_fail("operation_failed")


def lldp_snmp_post_config():
    """
    LLDP Post Config
    """
    snmp_obj.restore_snmp_config(vars.D1)


@pytest.mark.lldp_LocManAddrTable
@pytest.mark.regression
def test_ft_lldp_LocManAddrTable():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that the LocManAddrTable MIB object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    #### ToDo the below steps for validation as we have a open defect for testing this TC(SONIC-5258)
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_locmanaddrtable,
                                                  community_name=data.ro_community,filter=data.filter)
    st.log(" Getting LLDP port description:{} from the snmp output ".format(get_snmp_output))
    st.report_pass("test_case_passed")


@pytest.mark.lldp_LocManAddrSubType
@pytest.mark.regression
def test_ft_lldp_LocManAddrSubType():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that the LocManAddrSubType MIB object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    #### ToDo the below steps for validation as we have a open defect for testing this TC(SONIC-5258)
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_locmanaddrsubtype,
                                                  community_name=data.ro_community,filter=data.filter)
    st.log(" Getting LLDP port description:{} from the snmp output ".format(get_snmp_output))
    st.report_pass("test_case_passed")


@pytest.mark.lldp_LocManAddrOID
@pytest.mark.regression
@pytest.mark.community
@pytest.mark.community_pass
def test_ft_lldp_LocManAddrOID():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that the LocManAddrOID MIB object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    #### ToDo the below steps for validation as we have a open defect for testing this TC(SONIC-5258)
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_locmanaddroid,
                                                  community_name=data.ro_community,filter=data.filter)
    st.log(" Getting LLDP port description:{} from the snmp output ".format(get_snmp_output))
    st.report_pass("test_case_passed")


@pytest.mark.lldp_LocManAddrLen
@pytest.mark.regression
@pytest.mark.community
@pytest.mark.community_pass
def test_ft_lldp_LocManAddrLen():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that the LocManAddrLen MIB object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    #### ToDo the below steps for validation as we have a open defect for testing this TC(SONIC-5258)
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_locmanaddrlen,
                                                  community_name=data.ro_community,filter=data.filter)
    st.log(" Getting LLDP port description:{} from the snmp output ".format(get_snmp_output))
    st.report_pass("test_case_passed")


@pytest.mark.lldp_LocManAddrlfld
@pytest.mark.regression
@pytest.mark.community
@pytest.mark.community_pass
def test_ft_lldp_LocManAddrlfld():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that the LocManAddrlfld MIB object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    #### ToDo the below steps for validation as we have a open defect for testing this TC(SONIC-5258)
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_locmanaddrlfld,
                                                  community_name=data.ro_community,filter=data.filter)
    st.log(" Getting LLDP port description:{} from the snmp output ".format(get_snmp_output))
    st.report_pass("test_case_passed")


@pytest.mark.lldp_LocManAddrEntry
@pytest.mark.regression
@pytest.mark.community
@pytest.mark.community_pass
def test_ft_lldp_LocManAddrEntry():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that the LocManAddrEntry MIB object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    #### ToDo the below steps for validation as we have a open defect for testing this TC(SONIC-5258)
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_locmanaddrentry,
                                                  community_name=data.ro_community,filter=data.filter)
    st.log(" Getting LLDP port description:{} from the snmp output ".format(get_snmp_output))
    st.report_pass("test_case_passed")


@pytest.mark.lldp_ConfigManAddrTable
@pytest.mark.regression
def test_ft_lldp_ConfigManAddrTable():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that the ConfigManAddrTable MIB object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    #### ToDo the below steps for validation as we have a open defect for testing this TC(SONIC-5258)
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_configmanaddrtable,
                                                  community_name=data.ro_community,filter=data.filter)
    st.log(" Getting LLDP port description:{} from the snmp output ".format(get_snmp_output))
    st.report_pass("test_case_passed")


@pytest.mark.lldp_ConfigManAddrEntry
@pytest.mark.regression
@pytest.mark.community
@pytest.mark.community_pass
def test_ft_lldp_ConfigManAddrEntry():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify that the ConfigManAddrEntry MIB object functions properly.
    Reference Test Bed : D1 --- Mgmt Network
    """
    #### ToDo the below steps for validation as we have a open defect for testing this TC(SONIC-5258)
    get_snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid=data.oid_locmanaddrentry,
                                                  community_name=data.ro_community,filter=data.filter)
    st.log(" Getting LLDP port description:{} from the snmp output ".format(get_snmp_output))
    st.report_pass("test_case_passed")


@pytest.mark.lldp_lldplocportid
@pytest.mark.community
@pytest.mark.community_pass
def test_ft_lldp_lldplocportid():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify the syntax check of the object lldplocportid.
    Reference Test Bed : D1 <---> D2
    """
    lldp_value_remote_val = lldp_obj.get_lldp_neighbors(vars.D2, interface=vars.D2D1P1)
    snmp_output = snmp_obj.walk_snmp_operation(ipaddress= ipaddress, oid= data.oid_lldplocportid,
                                              community_name= data.ro_community,filter=data.filter)
    if not snmp_output:
        st.report_fail(" No SNMP Entries are available")
    st.log(" Getting LLDP port description:{} from the snmp output ".format(snmp_output))
    output = lldp_value_remote_val[-1]
    for port_id in output:
        if port_id == "portid_type":
            if output[port_id].lower() == 'local':
                cli_output = output['portid_value']
                break
    cli_output = '"{}"'.format(cli_output)
    st.log(" lldp value port is : {} ".format(cli_output))
    if not cli_output in snmp_output:
        st.report_fail("lldp_snmp_not_matching")
    st.log(" LLDP value is passed ")
    st.report_pass("test_case_passed")


@pytest.mark.lldp_lldplocsysname
@pytest.mark.community
@pytest.mark.community_pass
def test_ft_lldp_lldplocsysname():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify the syntax check of the object lldplocsysname.
    Reference Test Bed : D1 <---> D2
    """
    snmp_output = snmp_obj.get_snmp_operation(ipaddress= ipaddress, oid= data.oid_lldplocsysname,
                                              community_name=data.ro_community)
    if not snmp_output:
        st.report_fail(" No SNMP Entries are available")
    snmp_output = snmp_output[0]
    st.log(" Getting LLDP port description:{} from the snmp output ".format(snmp_output))
    cli_output = lldp_value_remote['chassis_name']
    st.log(" lldp value port is : {} ".format(cli_output))
    if not cli_output in snmp_output:
        st.report_fail("lldp_snmp_not_matching")
    st.log(" LLDP value is passed ")
    st.report_pass("test_case_passed")


@pytest.mark.lldp_lldplocsysdesc
@pytest.mark.community
@pytest.mark.community_pass
def test_ft_lldp_lldplocsysdesc():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify the syntax check of the object lldplocsysdesc.
    Reference Test Bed : D1 <---> D2
    """
    snmp_output = snmp_obj.get_snmp_operation(ipaddress=ipaddress, oid= data.oid_lldplocsysdesc,
                                              community_name=data.ro_community)
    if not snmp_output:
        st.report_fail(" No SNMP Entries are available")
    snmp_output = snmp_output[0]
    st.log(" Getting LLDP port description:{} from the snmp output ".format(snmp_output))
    cli_output = lldp_value_remote['chassis_descr']
    st.log(" lldp value port is : {} ".format(cli_output))
    if not cli_output in snmp_output:
        st.report_fail("lldp_snmp_not_matching")
    st.log(" LLDP value is passed ")
    st.report_pass("test_case_passed")

@pytest.mark.lldp_lldplocportdesc
def test_ft_lldp_lldplocportdesc():
    """
    Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
    Verify the syntax check of the object lldplocsysdesc.
    Reference Test Bed : D1 <---> D2
    """
    snmp_output = snmp_obj.walk_snmp_operation(ipaddress=ipaddress, oid= data.oid_lldplocportdesc,
                                              community_name=data.ro_community,filter=data.filter)
    if not snmp_output:
        st.report_fail(" No SNMP Entries are available")
    st.log(" Getting LLDP port description:{} from the snmp output ".format(snmp_output))
    cli_output = lldp_value['portdescr']
    st.log(" lldp value port is : {} ".format(cli_output))
    if not cli_output in str(snmp_output):
        st.report_fail("lldp_snmp_not_matching")
    st.log(" LLDP value is passed ")
    st.report_pass("test_case_passed")


@pytest.mark.lldp_non_default_config
@pytest.mark.community
@pytest.mark.community_pass
def test_ft_lldp_non_default_config():
    """
     Author : Prasad Darnasi <prasad.darnasi@broadcom.com>
     Verify non default LLDP neighbor config.
     Reference Test Bed : D1 <--2--> D2
     """
    tc_fall = 0

    lldp_obj.lldp_config(vars.D2, txinterval= 2)
    lldp_obj.lldp_config(vars.D2, txhold = 2)
    lldp_obj.lldp_config(vars.D2, capability= 'management-addresses-advertisements' , config= 'no')
    lldp_obj.lldp_config(vars.D2, capability= 'capabilities-advertisements', config='no')
    lldp_obj.lldp_config(vars.D2, interface = vars.D2D1P2, status = 'disabled')
    lldp_obj.lldp_config(vars.D2, hostname = 'SonicTest')

    st.log("Waiting for the lldp update timer to expire")
    st.wait(4)
    lldp_value = lldp_obj.get_lldp_neighbors(vars.D1, interface=vars.D1D2P1)
    lldp_value_1 = lldp_obj.get_lldp_neighbors(vars.D1, interface=vars.D1D2P2)

    lldp_value_gran_new = lldp_value[0]['chassis_mgmt_ip']
    lldp_value_capability_new = lldp_value[0]['chassis_capability_router']
    lldp_value_chassis_name_new = lldp_value[0]['chassis_name']

    if lldp_value_gran_new is lldp_value_gran:
        tc_fall = 1
        st.log('Failed: LLDP neighbor management is seen even though disabled ')
    if lldp_value_capability_new != '':
        tc_fall = 1
        st.log('Failed: LLDP neighbor capabilities are present even though disabled')
    if lldp_value_chassis_name_new != 'SonicTest':
        tc_fall = 1
        st.log('Failed: LLDP neighbor system name is not changed to non default ')
    if len(lldp_value_1)  != 0 :
        tc_fall = 1
        st.log('Failed: LLDP neighbor interface is still seen even though LLDP disabled on that ')

    st.log("Unconfig section")
    lldp_obj.lldp_config(vars.D2, capability='management-addresses-advertisements', config='yes')
    lldp_obj.lldp_config(vars.D2, capability='capabilities-advertisements', config='yes')
    lldp_obj.lldp_config(vars.D2, interface=vars.D2D1P2, status='rx-and-tx')
    lldp_obj.lldp_config(vars.D2, hostname='sonic')
    lldp_obj.lldp_config(vars.D2, txinterval=30)
    lldp_obj.lldp_config(vars.D2, txhold=6)
    if tc_fall:
        st.report_fail('LLDP_non_default_config_is_failed')
    st.log("LLDP neighbor values are advertised as configured ")
    st.report_pass("test_case_passed")


@pytest.mark.lldp_docker_restart
def test_ft_lldp_docker_restart():
    """
     Author : Karthikeya Kumar CH<karthikeya.kumarch@broadcom.com>
     Verify the LLDP functionality after docker restart.
     Reference Test Bed : D1 <--2--> D2
     """
    st.log("Checking the LLDP functionality with docker restart")
    basic_obj.service_operations_by_systemctl(vars.D1, 'lldp', 'stop')
    basic_obj.service_operations_by_systemctl(vars.D1,'lldp','restart')
    if not basic_obj.poll_for_system_status(vars.D1,'lldp',30,1):
        st.report_fail("service_not_running".format('lldp'))
    if not basic_obj.verify_service_status(vars.D1, 'lldp'):
        st.report_fail("lldp_service_not_up")
    if not intf_obj.poll_for_interfaces(vars.D1,iteration_count=30,delay=1):
        st.report_fail("interfaces_not_up_after_poll")
    if not lldp_obj.poll_lldp_neighbors(vars.D1, iteration_count=30, delay=1, interface=vars.D1D2P1):
        st.report_fail("lldp_neighbors_info_not_found_after_poll")
    lldp_info = lldp_obj.get_lldp_neighbors(vars.D1, interface=vars.D1D2P1)
    if not lldp_info:
        st.error("No lldp entries are available")
        st.report_fail("operation_failed")
    lldp_value_dut1 = lldp_info[0]
    lldp_output_dut1 = lldp_value_dut1['chassis_name']
    hostname_cli_output = basic_obj.get_hostname(vars.D2)
    if lldp_output_dut1 != hostname_cli_output:
        st.report_fail("lldp_cli_not_matching")
    st.log("LLDP and CLI output values are : LLDP:{} , CLI:{} ".format(lldp_output_dut1,hostname_cli_output))
    st.report_pass("test_case_passed")

