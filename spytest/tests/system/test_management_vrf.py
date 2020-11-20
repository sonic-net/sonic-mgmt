import pytest
from spytest import st, SpyTestDict, mutils
import apis.system.management_vrf as mvrf
from apis.system.interface import get_all_interfaces
from apis.system.basic import get_ifconfig_inet, service_operations,get_ifconfig
from apis.system.connection import connect_to_device
from utilities.common import poll_wait
from apis.routing.ip import ping, traceroute, config_ip_addr_interface, verify_interface_ip_address,delete_ip_interface
from apis.system.reboot import config_save, config_save_reload
from apis.system.snmp import poll_for_snmp, config_snmp_agent, set_snmp_config, restore_snmp_config
from apis.system.ssh import enable_ssh_in_user_vrf
from apis.system.gnmi import gnmi_get
from apis.system.chef import sync_with_server_time
from apis.system.ntp import verify_ntp_server_details, add_ntp_servers, verify_ntp_service_status, verify_ntp_status
from apis.security.tacacs import set_tacacs_server, verify_tacacs_server, set_aaa_authentication_properties, set_tacacs_properties

mgmt_vrf = SpyTestDict()

def mgmt_vrf_initialize_variables():
    mgmt_vrf.extip = "10.59.132.240"
    mgmt_vrf.secondagent = "1.2.3.4"
    mgmt_vrf.staticip = "12.12.12.1"
    mgmt_vrf.username_default = 'admin'
    mgmt_vrf.password_default = 'broadcom'
    mgmt_vrf.password_alt = 'YourPaSsWoRd'
    mgmt_vrf.vrfname = "mgmt"
    mgmt_vrf.vrf_global = "vrf_global"
    mgmt_vrf.wait_time = 10
    mgmt_vrf.oid_sysName = '1.3.6.1.2.1.1.5.0'
    mgmt_vrf.tacusername = 'test'
    mgmt_vrf.tacpassword = 'test'
    mgmt_vrf.protocol = 'ssh'
    mgmt_vrf.ssh_port = '22'
    mgmt_vrf.af_ipv4 = 'ipv4'
    mgmt_vrf.ro_community = 'mvrf_snmp'
    mgmt_vrf.location = 'sonic-devtest'


@pytest.fixture(scope="module", autouse=True)
def mgmt_vrf_module_config(request):
    mgmt_vrf_initialize_variables()
    mgmt_vrf_prolog()
    yield
    mgmt_vrf_epilog()


@pytest.mark.mgmt_vrf_regression
def test_mgmt_vrf_bind():
    report_flag = 0
    #intf = ['mgmt','eth0']
    intf = ['eth0']
    if not mvrf.verify(vars.D1, mvrfstate ='Enabled', interfaces=intf):
        st.log("FAILED")
        report_flag=1
    if report_flag:
        st.report_tc_fail("ft_mgmtVrf_bind","mgmt_vrf_eth0_bind_fail")
    else:
        st.report_tc_pass("ft_mgmtVrf_bind", "mgmt_vrf_eth0_bind_success")
    report_flag = 0
    intf_li = get_all_interfaces(vars.D1)
    if not mvrf.verify(vars.D1, mvrfstate ='Enabled', interfaces=intf_li, dataport=True):
        report_flag=1
    if report_flag:
        st.report_tc_fail("ft_mgmtVrf_dataport","mgmt_vrf_dataport_bind")
    else:
        st.report_tc_pass("ft_mgmtVrf_dataport", "mgmt_vrf_dataport_nobind")
    report_flag = 0
    ip_addr = get_ifconfig_inet(vars.D1, 'eth0')
    if not ip_addr:
        st.log("IP Address not found on eth0")
        report_flag=1
    ssh_conn_obj = connect_to_device(ip_addr[0],
                            mgmt_vrf.username_default, mgmt_vrf.password_default)
    if not ssh_conn_obj:
        if not connect_to_device(ip_addr[0],
                            mgmt_vrf.username_default, mgmt_vrf.password_alt):
            report_flag = 1
    if report_flag:
        st.report_tc_fail("ft_mgmtVrf_ssh","mgmt_vrf_ssh_fail")
    else:
        st.report_tc_pass("ft_mgmtVrf_ssh","mgmt_vrf_ssh_pass")
    if report_flag:
        st.report_fail("mgmt_vrf_eth0_bind_fail")
    else:
        st.report_pass("mgmt_vrf_eth0_bind_success")


@pytest.mark.mgmt_vrf_regression
def test_mgmt_vrf_ping_traceroute():
    report_flag = 0
    ip_addr = get_ifconfig_inet(vars.D1, 'eth0')
    if not ip_addr:
        st.report_fail('ip_verification_fail')
    if not ping(vars.D1, mgmt_vrf.extip, interface = mgmt_vrf.vrfname):
        report_flag = 1
    if not ping(vars.D1, ip_addr[0], external=True):
        report_flag = 1
    if report_flag:
        st.report_tc_fail("ft_mgmtVrf_ping","mgmt_vrf_ping_fail")
    else:
        st.report_tc_pass("ft_mgmtVrf_ping","mgmt_vrf_ping_pass")
    report_flag = 0
    if not traceroute(vars.D1, mgmt_vrf.extip, vrf_name= mgmt_vrf.vrfname):
        report_flag = 1
    if not traceroute(vars.D1, ip_addr[0], external=True):
        report_flag = 1
    if report_flag:
        st.report_tc_fail("ft_mgmtVrf_traceroute","mgmt_vrf_tr_fail")
    else:
        st.report_tc_pass("ft_mgmtVrf_traceroute","mgmt_vrf_tr_pass")
    if report_flag:
        st.report_fail("mgmt_vrf_tr_fail")
    else:
        st.report_pass("mgmt_vrf_tr_pass")


@pytest.mark.mgmt_vrf_regression1
def test_mgmt_vrf_reboot_cfgreload():
    st.banner('mgmt_vrf_reboot, mgmt_vrf_cfgreload')
    st.log("Config reload the DUT")
    report_flag = 0
    config_save_reload(vars.D1)
    ip_addr = get_ifconfig_inet(vars.D1, 'eth0')
    if not ip_addr:
        st.report_fail('ip_verification_fail')
    if not ping(vars.D1, mgmt_vrf.extip, interface=mgmt_vrf.vrfname):
        report_flag = 1
    if not ping(vars.D1, ip_addr[0], external=True):
        report_flag = 1
    if report_flag == 1:
        st.report_tc_fail("ft_mgmtVrf_cfgreload", "mgmt_vrf_cfgreload_fail")
        st.generate_tech_support(vars.D1,"ft_mgmtVrf_cfgreload")
    else:
        st.report_tc_pass("ft_mgmtVrf_cfgreload", "mgmt_vrf_cfgreload_pass")
    config_save(vars.D1, "sonic")
    config_save(vars.D1, "vtysh")
    st.reboot(vars.D1)
    ip_addr = get_ifconfig_inet(vars.D1, 'eth0')
    if not ip_addr:
        st.report_fail('ip_verification_fail')
    if not ping(vars.D1, mgmt_vrf.extip, interface = mgmt_vrf.vrfname):
        report_flag = 2
    if not ping(vars.D1, ip_addr[0], external=True):
        report_flag = 2
    if report_flag == 2:
        st.report_tc_fail("ft_mgmtVrf_reboot","mgmt_vrf_reboot_fail")
        st.generate_tech_support(vars.D1, "ft_mgmtVrf_reboot")
    else:
        st.report_tc_pass("ft_mgmtVrf_reboot","mgmt_vrf_reboot_pass")
    if report_flag:
        st.report_fail("test_case_failed")
    else:
        st.report_pass("test_case_passed")


@pytest.mark.mgmt_vrf_regression
def test_mgmt_vrf_curl_snmp():
    report_flag,module_flag = 0,0
    ip_addr = get_ifconfig_inet(vars.D1, 'eth0')
    if not ip_addr:
        st.report_fail('ip_verification_fail')
    set_snmp_config(vars.D1, snmp_rocommunity=mgmt_vrf.ro_community, snmp_location=mgmt_vrf.location)
    config_snmp_agent(vars.D1, ip_addr= ip_addr[0], vrf= 'mgmt')
    if not poll_for_snmp(vars.D1, mgmt_vrf.wait_time, 1, ipaddress=ip_addr[0],
                                  oid=mgmt_vrf.oid_sysName, community_name=mgmt_vrf.ro_community):
        st.log("Post MGMT VRF creation and snmpagent addition, snmp is not working")
        config_snmp_agent(vars.D1, ip_addr=ip_addr[0], vrf='mgmt',no_form=True)
        report_flag,module_flag = 1,1
    config_snmp_agent(vars.D1, ip_addr=mgmt_vrf.secondagent, vrf='mgmt')
    if not poll_for_snmp(vars.D1, mgmt_vrf.wait_time, 1, ipaddress=ip_addr[0],
                                  oid=mgmt_vrf.oid_sysName, community_name=mgmt_vrf.ro_community):
        st.log("After second agent within same VRF, snmp is not working")
        config_snmp_agent(vars.D1, ip_addr=mgmt_vrf.secondagent, vrf='mgmt',no_form=True)
        report_flag,module_flag = 1,1
    config_snmp_agent(vars.D1, ip_addr=ip_addr[0], vrf='mgmt',no_form=True)
    if report_flag:
        st.report_tc_fail("ft_mgmtVrf_snmp","mgmt_vrf_snmp_fail")
    else:
        st.report_tc_pass("ft_mgmtVrf_snmp","mgmt_vrf_snmp_pass")

    if module_flag:
        st.report_fail("test_case_failed")
    else:
        st.report_pass("test_case_passed")


def config_ntp_server_on_config_db_file(dut, iplist):
    st.log("Configuring NTP servers in Config_db file")
    add_ntp_servers(dut, iplist=iplist)
    st.log("verifying ntp service status")
    if verify_ntp_service_status(vars.D1, 'active (running)'):
        st.log("ntpd is running")
    else:
        st.log("ntpd is exited and restarting ntp service")
        service_operations(vars.D1, 'ntp', action="restart")
    if not verify_ntp_server_details(dut,iplist,remote=iplist):
        st.log("ip not matching")
        st.report_fail("operation_failed")
    if not verify_ntp_service_status(dut, 'active (running)', iteration=65, delay=2):
        st.log("ntp is exited")
        st.report_fail("operation_failed")



@pytest.mark.mgmt_vrf_regression
def test_mgmt_vrf_ntp():
    servers = mutils.ensure_service_params(vars.D1, "ntp", "host")
    config_ntp_server_on_config_db_file(vars.D1, servers)
    if not verify_ntp_status(vars.D1, iteration=65, delay=2, server=servers, mvrf=True):
        st.log("ntp syncronization failed after enable and disable ntp")
        st.report_fail("mgmt_vrf_ntp", "failed")
    st.report_pass("mgmt_vrf_ntp", "successful")


@pytest.mark.mgmt_vrf_regression1
def test_mgmt_vrf_warmboot():
    st.log("Warmboot the DUT")
    report_flag = 0
    st.reboot(vars.D1, "warm")
    ip_addr = get_ifconfig_inet(vars.D1, 'eth0')
    if not ip_addr:
        st.report_fail('ip_verification_fail')
    if not ping(vars.D1, mgmt_vrf.extip, interface=mgmt_vrf.vrfname):
        report_flag = 1
    if not ping(vars.D1, ip_addr[0], external=True):
        report_flag = 1
    if report_flag:
        st.report_tc_fail("ft_mgmtVrf_warmboot", "mgmt_vrf_warmboot", "failed")
    else:
        st.report_tc_pass("ft_mgmtVrf_warmboot", "mgmt_vrf_warmboot", "successful")
    if report_flag:
        st.report_fail("test_case_failed")
    else:
        st.report_pass("test_case_passed")

@pytest.mark.mgmt_vrf_regression
def test_mgmt_vrf_tacacs():
    tacacs_params = st.get_service_info(vars.D1, "tacacs")
    if not set_aaa_authentication_properties(vars.D1, 'failthrough', 'enable'):
        st.report_fail("authentication failthrough config fail")
    set_tacacs_server(vars.D1, 'add', tacacs_params.hosts[0].ip, tacacs_params.hosts[0].tcp_port,
                                 tacacs_params.hosts[0].timeout, tacacs_params.hosts[0].passkey,
                                 tacacs_params.hosts[0].auth_type, tacacs_params.hosts[0].priority,use_mgmt_vrf=True)
    if not verify_tacacs_server(vars.D1, tacacs_params.hosts[0].ip, tacacs_params.hosts[0].tcp_port,
                                           tacacs_params.hosts[0].timeout, tacacs_params.hosts[0].passkey,
                                           tacacs_params.hosts[0].auth_type, tacacs_params.hosts[0].priority):
        st.report_fail("Tacacs_server_configs_are_not_successful", tacacs_params.hosts[0].ip)
    set_aaa_authentication_properties(vars.D1, 'login', 'tacacs+ local')
    ip_addr = get_ifconfig_inet(vars.D1, 'eth0')
    if not ip_addr:
        st.report_fail('ip_verification_fail')
    if not poll_wait(connect_to_device, 10, ip_addr[0], mgmt_vrf.tacusername, mgmt_vrf.tacpassword, mgmt_vrf.protocol,
                     mgmt_vrf.ssh_port):
        tacacs_cleanup(vars.D1, tacacs_params)
        st.report_fail("mgmt_vrf_tacacs", "failed")
    tacacs_cleanup(vars.D1, tacacs_params)
    st.report_pass("mgmt_vrf_tacacs", "successful")


@pytest.mark.mgmt_vrf_regression
def test_mgmt_vrf_static_dhcp():
    config_ip_addr_interface(vars.D1, "eth0", mgmt_vrf.staticip, 20, mgmt_vrf.af_ipv4)
    if not poll_wait(verify_interface_ip_address, 10, vars.D1, "eth0", mgmt_vrf.staticip + '/20', family="ipv4",
                     vrfname='mgmt'):
        st.log("IP Address not matched")
        delete_ip_interface(vars.D1, "eth0", mgmt_vrf.staticip, 20, mgmt_vrf.af_ipv4)
        st.report_fail("mgmt_vrf_static_dhcp", "failed")
    output = get_ifconfig(vars.D1, "eth0")
    if output[0]['broadcast'][0] == '0.0.0.0':
        st.log("Broadcast IP address not assigned")
        delete_ip_interface(vars.D1, "eth0", mgmt_vrf.staticip, 20, mgmt_vrf.af_ipv4)
        st.report_fail("test_case_failed")
    delete_ip_interface(vars.D1, "eth0", mgmt_vrf.staticip, 20, mgmt_vrf.af_ipv4)
    if not poll_wait(get_ifconfig_inet, 30, vars.D1, 'eth0'):
        st.log("IP Address not assigned to eth0 after dhcp")
        st.report_fail("mgmt_vrf_static_dhcp", "failed")
    st.report_pass("mgmt_vrf_static_dhcp", "successful")


@pytest.mark.mgmt_vrf_regression
def test_mgmt_vrf_gnmi():
    gnmi_url = "/sonic-mgmt-vrf:sonic-mgmt-vrf/MGMT_VRF_CONFIG/MGMT_VRF_CONFIG_LIST[vrf_global_name={}]/mgmtVrfEnabled/".format(mgmt_vrf.vrf_global)
    get_resp = gnmi_get(dut=vars.D1, xpath=gnmi_url)
    if not get_resp:
        st.report_fail("msg","gnmi_get output not found")
    if not get_resp["sonic-mgmt-vrf:mgmtVrfEnabled"]:
        st.report_fail("msg","Mgmt-vrf should be enabled")
    st.report_pass("test_case_passed")


def tacacs_cleanup(dut, tacacs_params):
    set_aaa_authentication_properties(dut, 'login', 'local')
    set_tacacs_properties(dut, 'default', 'authtype')
    set_tacacs_properties(dut, 'default', 'passkey')
    set_tacacs_properties(dut, 'default', 'timeout')
    set_tacacs_server(dut, 'delete', tacacs_params.hosts[0].ip)
    set_aaa_authentication_properties(dut, 'failthrough', 'default')


def mgmt_vrf_prolog():
    global vars
    vars = st.ensure_min_topology("D1")
    ip = mutils.ensure_service_params(vars.D1, "chef", "ip")
    username = mutils.ensure_service_params(vars.D1, "chef", "username")
    password = mutils.ensure_service_params(vars.D1, "chef", "password")
    st.log("Setting the date on DUT")
    if not sync_with_server_time(vars.D1, ip, username, password):
        st.log("Failed to set time")
    st.wait(mgmt_vrf.wait_time)
    mvrf.config(vars.D1)
    enable_ssh_in_user_vrf(vars.D1, config='add', vrf_name='mgmt')
    if not poll_wait(get_ifconfig_inet, 30, vars.D1, 'eth0'):
        st.log("IP Address not assigned to eth0 after prologue")
        mgmt_vrf_epilog()
        st.report_fail("mgmt_vrf_eth0_bind_fail")

def mgmt_vrf_epilog():
    restore_snmp_config(vars.D1)
    enable_ssh_in_user_vrf(vars.D1, config='del', vrf_name='mgmt')
    mvrf.config(vars.D1, no_form= True)

