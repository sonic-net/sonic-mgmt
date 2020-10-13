import pytest,random, json
from spytest import st
from spytest.dicts import SpyTestDict
from apis.system.ssh import enable_ssh, disable_ssh, enable_sshv6, disable_sshv6
from apis.system.reboot import config_save
from apis.security.user import config_user
from utilities.common import random_username, random_password
import tests.qos.acl.acl_json_config as acl_data
import apis.routing.ip as ip_obj
from utilities import parallel
import apis.qos.acl as acl_obj
from utilities.utils import ensure_service_params
from spytest.utils import poll_wait
import apis.system.snmp as snmp_obj
import apis.system.basic as basic_obj
from apis.system.connection import connect_to_device, ssh_disconnect, execute_command
from apis.system.basic import get_docker_ps, get_and_match_docker_count, verify_docker_status


ssh_data = SpyTestDict()

def initialize_variables():
    ssh_data.clear()
    ssh_data.usr_default = 'admin'
    ssh_data.pwd_default = ['YourPaSsWoRd', 'broadcom']
    ssh_data.pwd_final = ''
    ssh_data.usr_non_default = random_username(random.randint(5, 31))
    ssh_data.pwd_non_default = random_password(random.randint(6, 12))
    ssh_data.commands_to_verify = ['show system status']
    ssh_data.ipv4_address_D1D2P1 = "2.2.2.1"
    ssh_data.ipv4_address_D2D1P1 = "2.2.2.2"
    ssh_data.ipv4_address_D1D2P2 = "2.2.3.1"
    ssh_data.ipv4_address_D2D1P2 = "2.2.3.2"
    ssh_data.ipv4_network = "2.2.2.0/24"
    ssh_data.ipv6_address_D1D2P1 = "1001::1"
    ssh_data.ipv6_address_D2D1P1 = "1001::2"
    ssh_data.ipv6_address_D1D2P2 = "2001::1"
    ssh_data.ipv6_address_D2D1P2 = "2001::2"
    ssh_data.ipv6_network_D1 = "1001::0/64"
    ssh_data.ipv4_mask = "24"
    ssh_data.ipv6_mask = "64"
    ssh_data.ro_community = 'test_123'
    ssh_data.location = 'hyderabad'
    ssh_data.contact = "Admin"
    ssh_data.sysname = "Sonic_device"
    ssh_data.oid_sysName = '1.3.6.1.2.1.1.5.0'


@pytest.fixture(scope="module", autouse=True)
def ssh_module_hooks(request):
    global vars
    vars = st.ensure_min_topology("D1D2:2")
    initialize_variables()
    ssh_module_prolog()
    config_ip_address()
    enable_sshv6(vars.D1)

    yield
    config_ip_address(oper='remove')
    acl_obj.delete_acl_table(vars.D1)
    disable_sshv6(vars.D1)
    snmp_config(config='remove')


@pytest.fixture(scope="function", autouse=True)
def ssh_func_hooks(request):
    yield


def config_nondefault_user(config='add'):
    if config == 'add':
        st.log("creating non-default username={},password={}".format(ssh_data.usr_non_default, ssh_data.pwd_non_default))
        config_user(vars.D1, ssh_data.usr_non_default, 'add')
        if not st.change_passwd(vars.D1, ssh_data.usr_non_default, ssh_data.pwd_non_default):
            st.error("Failed to create non-default username={},password={}".format(ssh_data.usr_non_default,
                                                                                   ssh_data.pwd_non_default))
            return False
        st.log('Saving the configuration')
        config_save(vars.D1)
    else:
        config_user(vars.D1, ssh_data.usr_non_default, 'del')
    return True


def config_ip_address(oper ='add'):
    st.log("Configuring ipv4 address on D1 and D2 connected port")
    dict1 = {'interface_name': vars.D1D2P1, 'ip_address': ssh_data.ipv4_address_D1D2P1, 'subnet': ssh_data.ipv4_mask,
             'family': "ipv4", 'config': oper}
    dict2 = {'interface_name': vars.D2D1P1, 'ip_address': ssh_data.ipv4_address_D2D1P1, 'subnet': ssh_data.ipv4_mask,
             'family': "ipv4", 'config': oper}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ip_obj.config_ip_addr_interface, [dict1, dict2])

    dict1 = {'interface_name': vars.D1D2P2, 'ip_address': ssh_data.ipv4_address_D1D2P2, 'subnet': ssh_data.ipv4_mask,
             'family': "ipv4", 'config': oper}
    dict2 = {'interface_name': vars.D2D1P2, 'ip_address': ssh_data.ipv4_address_D2D1P2, 'subnet': ssh_data.ipv4_mask,
             'family': "ipv4", 'config': oper}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ip_obj.config_ip_addr_interface, [dict1, dict2])

    st.log("Configuring ipv6 address on D1 and D2 connected port")
    dict1 = {'interface_name': vars.D1D2P1, 'ip_address': ssh_data.ipv6_address_D1D2P1, 'subnet': ssh_data.ipv6_mask,
             'family': "ipv6", 'config': oper}
    dict2 = {'interface_name': vars.D2D1P1, 'ip_address': ssh_data.ipv6_address_D2D1P1, 'subnet': ssh_data.ipv6_mask,
             'family': "ipv6", 'config': oper}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ip_obj.config_ip_addr_interface, [dict1, dict2])

    dict1 = {'interface_name': vars.D1D2P2, 'ip_address': ssh_data.ipv6_address_D1D2P2, 'subnet': ssh_data.ipv6_mask,
             'family': "ipv6", 'config': oper}
    dict2 = {'interface_name': vars.D2D1P2, 'ip_address': ssh_data.ipv6_address_D2D1P2, 'subnet': ssh_data.ipv6_mask,
             'family': "ipv6", 'config': oper}
    parallel.exec_parallel(True, [vars.D1, vars.D2], ip_obj.config_ip_addr_interface, [dict1, dict2])


def snmp_config(config='add'):
    global ssh_conn_obj
    if config == 'add':
        ip = ensure_service_params(vars.D1, "snmptrap", "ip")
        username = ensure_service_params(vars.D1, "snmptrap", "username")
        password = ensure_service_params(vars.D1, "snmptrap", "password")
        snmp_obj.set_snmp_config(vars.D1, snmp_rocommunity=ssh_data.ro_community, snmp_location=ssh_data.location)
        # Connect to the linux machine and check
        ssh_conn_obj = connect_to_device(ip, username, password)
        if not ssh_conn_obj:
            return  False
    else:
        snmp_obj.restore_snmp_config(vars.D1)
    return True


def ssh_module_prolog():
    enable_ssh(vars.D1)
    st.log('connecting to device with username={},password={}'.format(ssh_data.usr_default, ssh_data.pwd_default[0]))
    ssh_data.pwd_final = ssh_data.pwd_default[0]
    if not st.exec_ssh(vars.D1, ssh_data.usr_default, ssh_data.pwd_default[0], ssh_data.commands_to_verify):
        ssh_data.pwd_final = ssh_data.pwd_default[1]
        st.log('Retry - connecting to device with username={},password={}'.format(ssh_data.usr_default,
                                                                                  ssh_data.pwd_default[1]))
        if not st.exec_ssh(vars.D1, ssh_data.usr_default, ssh_data.pwd_default[1], ssh_data.commands_to_verify):
            st.log("SSH connection failed with default Credentials.")
            st.report_fail("ssh_failed")
    st.banner("--> Detected device default password = {}".format(ssh_data.pwd_final))


def change_acl_rules(config, rule_name, attribute, value):
    config["ACL_RULE"][rule_name][attribute] = value


def apply_acl_config(dut, config):
    json_config = json.dumps(config)
    json.loads(json_config)
    st.apply_json2(dut, json_config)


def verify_ssh_connection(dut, ip, username, password, cmds="show vlan config"):
    output = st.exec_ssh_remote_dut(dut, ip, username, password, cmds)
    if "Connection timed out" in output or "option requires an argument" in output or "Connection refused" in output:
        st.error("SSH Connection Failed: IP-{}, User-{}, Password-{}".format(ip, username, password))
        return False
    st.log("SSH Connection sucess: IP-{}, User-{}, Password-{}".format(ip, username, password))
    return True


@pytest.mark.ssh_disable
@pytest.mark.regression
@pytest.mark.community
@pytest.mark.community_pass
def test_ft_ssh_service_disable():
    """
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    """
    disable_ssh(vars.D1)
    st.log('connecting to device with username={},password={}'.format(ssh_data.usr_default, ssh_data.pwd_final))
    output = st.exec_ssh(vars.D1, ssh_data.usr_default, ssh_data.pwd_final, ssh_data.commands_to_verify)
    enable_ssh(vars.D1)
    if output:
        st.error("SSH connection Success even when disabled the SSH service.")
        st.report_fail("test_case_failed")
    else:
        st.report_pass("test_case_passed")

@pytest.mark.acl_test_controlplane
@pytest.mark.ssh_verify
@pytest.mark.regression
def test_ft_ssh_add_user_verify():
    """
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    """
    user_ssh = 0
    acl_sshv4 = 0
    acl_sshv6 = 0
    acl_snmp = 0

    if not snmp_config(config='add'): acl_snmp = + 1

    ipaddress = st.get_mgmt_ip(vars.D1)
    if not ipaddress:
        st.report_env_fail("ip_verification_fail")

    snmp_cmd = "snmpget -Oqv -v 2c -c {} {} {}".format(ssh_data.ro_community, ipaddress, ssh_data.oid_sysName)

    out = config_nondefault_user()
    if not out: user_ssh = + 1

    st.log("connecting to device with username={},password={}".format(ssh_data.usr_default, ssh_data.pwd_final))
    if not st.exec_ssh(vars.D1, ssh_data.usr_default, ssh_data.pwd_final, ssh_data.commands_to_verify):
        st.error('Cannot SSH into Device with default credentials')
        user_ssh = + 1

    st.log('connecting to device with username={},password={}'.format(ssh_data.usr_non_default,
                                                                      ssh_data.pwd_non_default))
    if not st.exec_ssh(vars.D1, ssh_data.usr_non_default, ssh_data.pwd_non_default, ssh_data.commands_to_verify):
        st.error('Cannot SSH into Device with non-default credentials')
        user_ssh = + 1

    output = verify_ssh_connection(vars.D2, ssh_data.ipv4_address_D1D2P2, ssh_data.usr_default, ssh_data.pwd_final)
    if not output:
        user_ssh = + 1

    IPAddr = ensure_service_params(vars.D1, "snmptrap", "ip") + "/32"
    change_acl_rules(acl_data.acl_json_config_control_plane, "SNMP_ACL|RULE_1", "SRC_IP", IPAddr)
    change_acl_rules(acl_data.acl_json_config_control_plane, "SSH_ONLY|RULE_1", "SRC_IP", IPAddr)
    change_acl_rules(acl_data.acl_json_config_control_plane, "SSH_ONLY|RULE_2", "SRC_IP", ssh_data.ipv4_network)
    change_acl_rules(acl_data.acl_json_config_control_plane, "V6_SSH_ONLY|RULE_1", "SRC_IPV6", ssh_data.ipv6_network_D1)
    acl_config = acl_data.acl_json_config_control_plane
    st.log("ACL_DATA: {}".format(acl_config))
    apply_acl_config(vars.D1, acl_config)
    acl_obj.show_acl_table(vars.D1)
    acl_obj.show_acl_rule(vars.D1)

    if not poll_wait(acl_obj.verify_acl_table_rule, 5, vars.D1, "SNMP_ACL", "RULE_1"):
        st.error("Failed to create ACL rule '{}' ".format("SNMP_ACL"))
        acl_snmp =+ 1

    if not poll_wait(acl_obj.verify_acl_table_rule, 5, vars.D1, "SSH_ONLY", "RULE_1"):
        st.error("Failed to create ACL rule '{}' ".format("SSH_ONLY"))
        acl_sshv4 =+ 1

    if not poll_wait(acl_obj.verify_acl_table_rule, 5, vars.D1, "V6_SSH_ONLY", "RULE_1"):
        st.error("Failed to create ACL rule '{}' ".format("V6_SSH_ONLY"))
        acl_sshv6 =+ 1

    hostname = basic_obj.get_hostname(vars.D1)
    st.log("HOSTNAME: {}".format(hostname))
    snmp_out = execute_command(ssh_conn_obj, snmp_cmd)
    if hostname not in snmp_out: acl_snmp = + 1

    st.log("connecting to device with default username={},password={}".format(ssh_data.usr_default, ssh_data.pwd_final))
    output = verify_ssh_connection(vars.D2, ssh_data.ipv4_address_D1D2P2, ssh_data.usr_default, ssh_data.pwd_final)
    if output: acl_sshv4 =+ 1

    output = verify_ssh_connection(vars.D2, ssh_data.ipv6_address_D1D2P2, ssh_data.usr_default, ssh_data.pwd_final)
    if output: acl_sshv6 = + 1

    output = verify_ssh_connection(vars.D2, ssh_data.ipv4_address_D1D2P1, ssh_data.usr_default, ssh_data.pwd_final)
    if not output: acl_sshv4 = + 1

    output = verify_ssh_connection(vars.D2, ssh_data.ipv6_address_D1D2P1, ssh_data.usr_default, ssh_data.pwd_final)
    if not output: acl_sshv6 = + 1

    st.log("connecting to device with non default username={},password={}".format(ssh_data.usr_non_default, ssh_data.pwd_non_default))
    output = verify_ssh_connection(vars.D2, ssh_data.ipv4_address_D1D2P1, ssh_data.usr_non_default, ssh_data.pwd_non_default)
    if not output: acl_sshv4 = + 1

    output = verify_ssh_connection(vars.D2, ssh_data.ipv6_address_D1D2P1, ssh_data.usr_non_default, ssh_data.pwd_non_default)
    if not output: acl_sshv6 = + 1

    config_save(vars.D1)
    st.log('rebooting the device.')
    st.reboot(vars.D1, 'fast')

    acl_obj.show_acl_table(vars.D1)
    acl_obj.show_acl_rule(vars.D1)

    if not poll_wait(acl_obj.verify_acl_table_rule, 5, vars.D1, "SSH_ONLY", "RULE_1"):
        st.log("Failed to create ACL rule '{}' ".format("SSH_ONLY"))
        acl_sshv4 = + 1

    if not poll_wait(acl_obj.verify_acl_table_rule, 5, vars.D1, "V6_SSH_ONLY", "RULE_1"):
        st.log("Failed to create ACL rule '{}' ".format("V6_SSH_ONLY"))
        acl_sshv4 = + 1

    if not poll_wait(acl_obj.verify_acl_table_rule, 5, vars.D1, "SNMP_ACL", "RULE_1"):
        st.error("Failed to create ACL rule '{}' ".format("SNMP_ACL"))
        acl_snmp =+ 1

    hostname = basic_obj.get_hostname(vars.D1)
    snmp_out = execute_command(ssh_conn_obj, snmp_cmd)
    if hostname not in snmp_out: acl_snmp = + 1
    '''
    change_acl_rules(acl_data.acl_json_config_control_plane, "SNMP_ACL|RULE_1", "SRC_IP", "2.2.2.2/24")
    acl_config = acl_data.acl_json_config_control_plane
    apply_acl_config(vars.D1, acl_config)
    acl_obj.show_acl_rule(vars.D1)

    snmp_out = execute_command(ssh_conn_obj, snmp_cmd)
    if "Timeout" not in snmp_out: acl_snmp = + 1
    '''
    st.log("connecting to device with default username={},password={}".format(ssh_data.usr_default, ssh_data.pwd_final))
    output = verify_ssh_connection(vars.D2, ssh_data.ipv4_address_D1D2P2, ssh_data.usr_default, ssh_data.pwd_final)
    if output: acl_sshv4 = + 1

    output = verify_ssh_connection(vars.D2, ssh_data.ipv6_address_D1D2P2, ssh_data.usr_default, ssh_data.pwd_final)
    if output: acl_sshv6 = + 1

    output = verify_ssh_connection(vars.D2, ssh_data.ipv4_address_D1D2P1, ssh_data.usr_default, ssh_data.pwd_final)
    if not output: acl_sshv4 = + 1

    output = verify_ssh_connection(vars.D2, ssh_data.ipv6_address_D1D2P1, ssh_data.usr_default, ssh_data.pwd_final)
    if not output: acl_sshv6 = + 1

    if acl_sshv4:
        st.report_tc_fail("test_ft_controlplane_acl_service_sshv4", "ssh_failed", "with control plane ACL service SSHv4 after reboot")
    else:
        st.report_tc_pass("test_ft_controlplane_acl_service_sshv4", "ssh_failed", "with control plane ACL service SSHv4 after reboot")

    if acl_sshv6:
        st.report_tc_fail("test_ft_controlplane_acl_service_sshv6", "ssh_failed", "with control plane ACL service SSHv6 after reboot")
    else:
        st.report_tc_pass("test_ft_controlplane_acl_service_sshv6", "ssh_failed", "with control plane ACL service SSHv6 after reboot")

    if acl_snmp:
        st.report_tc_fail("test_ft_controlplane_acl_service_snmp", "snmp_output_failed", "with control plane ACL service SNMP after reboot")
    else:
        st.report_tc_pass("test_ft_controlplane_acl_service_snmp", "snmp_output_failed", "with control plane ACL service SNMP after reboot")

    acl_obj.delete_acl_table(vars.D1)

    if acl_sshv4 or acl_sshv6 or acl_snmp:
        st.generate_tech_support(vars.D1, "controlplane_acl_services_after_reboot")

    st.log("connecting to device with username={},password={}".format(ssh_data.usr_default, ssh_data.pwd_final))
    if not st.exec_ssh(vars.D1, ssh_data.usr_default, ssh_data.pwd_final, ssh_data.commands_to_verify):
        st.error('Cannot SSH into Device with default credentials after reboot')
        user_ssh = + 1

    st.log('connecting to device with username={},password={}'.format(ssh_data.usr_non_default,
                                                                      ssh_data.pwd_non_default))
    if not st.exec_ssh(vars.D1, ssh_data.usr_non_default, ssh_data.pwd_non_default, ssh_data.commands_to_verify):
        st.error('Cannot SSH into Device with non-default credentials after reboot')
        user_ssh = + 1

    config_nondefault_user(config='remove')

    if user_ssh:
        st.report_fail("ssh_failed")
    st.report_pass("test_case_passed")


@pytest.mark.ssh_verify
@pytest.mark.regression
def test_ft_ssh_config_reload_docker():
    """
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    """
    result = True
    get_docker_ps(vars.D1)
    count = get_and_match_docker_count(vars.D1)
    ssh_d1 = connect_to_device(st.get_mgmt_ip(vars.D1), ssh_data.usr_default, ssh_data.pwd_final)
    if ssh_d1:
        st.log("Executing command - 'sudo config reload -y &' in to the SSH session.")
        st.log(execute_command(ssh_d1, 'sudo config reload -y &'))
        st.wait(5, 'After executing "config reload" cmd on SSH session.')
        st.log("Forcefully disconnecting the SSH session..")
        ssh_disconnect(ssh_d1)
    else:
        st.error('Cannot SSH into Device with default credentials')
        st.report_fail("ssh_failed")

    if not poll_wait(verify_docker_status, 180, vars.D1, 'Exited'):
        st.error("Post 'config reload' from SSH, dockers are not auto recovered.")
        result = False

    if result:
        if not poll_wait(get_and_match_docker_count, 180, vars.D1, count):
            st.error("Post 'config reload' from SSH, ALL dockers are not UP.")
            result = False

    if not result:
        st.log("Test Failed: So recovering the device by reboot.")
        st.reboot(vars.D1)
        st.report_fail("test_case_failed")
    st.report_pass("test_case_passed")

