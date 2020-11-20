import pytest
from spytest import st, SpyTestDict

import apis.system.ssh as sshapi
import json
import apis.system.basic as bc_obj
import apis.system.rest as rest_obj
from utilities.utils import ensure_service_params
from apis.routing.ip import ping_poll, dump_mgmt_connectivity_info
from apis.security.user import config, verify
import apis.system.connection as ssh
from apis.security.rbac import  rest_rbac_call
from apis.system.rest import client_auth as rest_client_auth

rbac = SpyTestDict()

@pytest.fixture(scope="module", autouse=True)
def rbac_module_hooks():
    global vars
    vars = st.ensure_min_topology("D1 D2")
    rbac_variables_init()
    rbac_module_prolog()
    rbac_variables()
    st.log("Getting IP address of the DUT")
    ensure_device_ipaddress()
    yield
    rbac_module_epilog()


@pytest.fixture(scope="function", autouse=True)
def rbac_func_hooks(request):
    yield

def rbac_variables():
    rbac.host_username = ensure_service_params(vars.D1, "radius", "hosts", 0, "username")
    rbac.host_password = ensure_service_params(vars.D1, "radius", "hosts", 0, "password")
    rbac.global_auth_type = ensure_service_params(vars.D1, "radius", "globals", 0, "auth_type")
    rbac.host_ip = ensure_service_params(vars.D1, "radius", "hosts", 0, "ip")
    rbac.feature = "RADIUS"


def ensure_device_ipaddress():
    rbac.ip_address_list = bc_obj.get_ifconfig_inet(vars.D1, 'eth0')
    if not rbac.ip_address_list:
        st.report_fail("DUT_does_not_have_IP_address")
    rbac.ip_address = rbac.ip_address_list[0]

def rbac_variables_init():
    rbac.clear()
    port = st.get_free_ports(vars.D1)[0]
    rbac.url = '/restconf/data/openconfig-interfaces:interfaces/interface={}/config/mtu'.format(port)
    rbac.default_user = {'username': 'admin',
                         'password': 'broadcom',
                         'alt_password': 'YourPaSsWoRd',
                         'mode': 'rw'}
    rbac.linux_rw = {'username': 'testlirw',
                     'password': 'testli123rw',
                     'role': 'sudo',
                     'mode': 'rw',
                     'cli_type': 'click'}
    rbac.linux_ro = {'username': 'testliro',
                     'password': 'testli123ro',
                     'role': 'operator',
                     'mode': 'ro',
                     'cli_type': 'click'}
    rbac.local_rw = {'username': 'testlorw',
                     'password': 'testlo123rw',
                     'role': 'admin',
                     'mode': 'rw',
                     'model': 'oc-yang',
                     'cli_type': 'klish'}
    rbac.local_ro = {'username': 'testloro',
                     'password': 'testlo123ro',
                     'role': 'operator',
                     'mode': 'ro',
                     'model': 'oc-yang',
                     'cli_type': 'klish'}
    rbac.local_no_group = {'username': 'test_no_group',
                           'password': 'no_group',
                           'mode': 'ro',
                           'cli_type': 'click'}

    rbac.client_keygen_path = r'/home/admin/.ssh/'
    rbac.rest_auth = 'password,jwt'
    rbac.rest_cert = (r"/home/admin/.cert/key.pem", r"/home/admin/.cert/certificate.pem")
    rbac.ca_crt = r"/host/cli-ca/cert.pem"
    rbac.server_key = r"/host_home/admin/.cert/key.pem"
    rbac.server_crt = r"/host_home/admin/.cert/certificate.pem"
    rbac.cred_list = [rbac.linux_rw, rbac.linux_ro, rbac.local_rw, rbac.local_ro, rbac.local_no_group]
    rbac.group_list = list(set([e['role'] for e in rbac.cred_list if 'role' in e]))
    rbac.user_list = list(set([e['username'] for e in rbac.cred_list if 'username' in e]))
    rbac.user_group = {e['username']: e['role'] for e in rbac.cred_list if 'username' in e and 'role' in e}


def rbac_module_prolog():
    ping_validation()
    rbac_config_user(0)
    rest_client_auth(vars.D1, auth_type=rbac.rest_auth)


def rbac_module_epilog():
    rbac_config_user(1)
    rest_client_auth(vars.D1, auth_type='')


def ping_validation():
    if not ping_poll(vars.D2, st.get_mgmt_ip(vars.D1), family='ipv4', iter=3, delay=10):
        dump_mgmt_connectivity_info(vars.D1)
        st.error("D2->D1: Ping reachability is failed.")
        st.report_fail('ping_fail_from_DUT_to_DUt', "D2", "D1")


def rbac_config_user(no_form=0):
    result = True
    st.banner("{}Configuring User(s) to the DUT.".format("Un-" if no_form else ''))
    for each in rbac.cred_list:
        each.update({'no_form': no_form})
        st.banner("Configuring - {}".format(each), delimiter='*')
        config(vars.D1, **each)
        if each['cli_type'] == 'klish':
            st.config(vars.D1, 'usermod -s /bin/bash {}'.format(each['username']))
        if not no_form:
            sshapi.ssh_copyid(vars.D2, st.get_mgmt_ip(vars.D1), **each)
    if not no_form:
        if not verify(vars.D1, 'user_list', verify_list=rbac.user_list):
            st.error("Failed to config User in DUT")
            result = False
        if not verify(vars.D1, 'group_list', verify_list=rbac.group_list):
            st.error("Failed to config Groups in DUT")
            result = False
        for username, role in rbac.user_group.items():
            if not verify(vars.D1, user_group=username, verify_list=[{'group': role}]):
                st.error('Failed to config User with group in DUT')
                result = False
        if not result:
            st.report_fail('rbac_user_config')


def rbac_cleanup():
    rbac_config_user(1)


@pytest.mark.rbac
@pytest.mark.rbac_rest
def test_ft_rbac_rw_local_cred_rest_ocyang():
    """
    Testcase1: Verify that admin user will have all permissions when authenticate to REST server with
                        username/password.
    """
    rest_rbac_call(vars.D1, login_type='cred', url = rbac.url, **rbac.local_rw)


@pytest.mark.rbac
@pytest.mark.rbac_rest
def test_ft_rbac_ro_local_cred_rest_ocyang():
    """
    Testcase2: Verify that non-admin user doesn?t have all permissions except show (get) commands
                       when authenticate to REST server with username/password.
    """
    rest_rbac_call(vars.D1, login_type='cred', url = rbac.url, **rbac.local_ro)


@pytest.mark.rbac
@pytest.mark.rbac_rest
def test_ft_rbac_rw_local_jwt_token_rest_ocyang():
    """
    Testcase3: Verify that admin user have all permissions when authenticate to REST server with token.
    """
    rest_rbac_call(vars.D1, login_type='token', url = rbac.url, **rbac.local_rw)


@pytest.mark.rbac
@pytest.mark.rbac_rest
def test_ft_rbac_ro_local_jwt_token_rest_ocyang():
    """
    Testcase4: Verify that non-admin user doesn't have all permissions except show (get) commands
                       when authenticate to REST server with token.
    """
    rest_rbac_call(vars.D1, login_type='token', url = rbac.url, **rbac.local_ro)

def test_ft_radius_login_rest():
    """
    Verify that aaa authentication can be configured to radius and login authentication is successful.

    """
    data1 = json.loads("""
	{
		"openconfig-system-ext:auth-type": "pap"
	}   
    """)
    data2 = json.loads("""
    {
      "openconfig-system:config": {
        "auth-port": 1812,
        "secret-key": "Lvl7india"
      }
    }             
		""")
    data3 = json.loads("""
	{
	  "openconfig-system:authentication-method": [
		"radius",
		"local"
	  ]
	}                     
    """)
    rest_url1 = "/restconf/data/openconfig-system:system/aaa/server-groups/server-group={}/servers/server={}/config/openconfig-system-ext:auth-type".format(rbac.feature, rbac.host_ip)


    rest_url2 = "/restconf/data/openconfig-system:system/aaa/server-groups/server-group={}/servers/server={}/radius/config".format(rbac.feature, rbac.host_ip)
    rest_url3 = "/restconf/data/openconfig-system:system/aaa/authentication/config/authentication-method"
    st.log("Configuring Radius server configuration with REST")
    if not rest_obj.config_rest(vars.D1, http_method = 'put', rest_url = rest_url1, json_data = data1):
        st.report_fail("rest_call_failed", "PUT")
    if not rest_obj.config_rest(vars.D1, http_method = 'patch', rest_url = rest_url2, json_data = data2):
        st.report_fail("rest_call_failed", "PATCH")
    st.log("Setting login authentication to radius and local")
    if not rest_obj.config_rest(vars.D1, http_method = 'put', rest_url = rest_url3, json_data = data3):
        st.report_fail("rest_call_failed", "PUT")
    st.log("SSH to device using radius credentials with auth_type pap")
    if not ssh.connect_to_device(rbac.ip_address, rbac.host_username, rbac.host_password):
        st.report_fail("ssh_login_failed", rbac.global_auth_type)
    st.report_pass("ssh_login_with_radius_successful", rbac.global_auth_type)