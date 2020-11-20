"""
RBAC Feature FT tests cases.
Author1 : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
"""
import pytest
from spytest import st, SpyTestDict

import apis.system.ssh as sshapi
from apis.routing.ip import ping_poll, dump_mgmt_connectivity_info
from apis.security.user import config, verify
from apis.security.rbac import *
from apis.system.gnmi import client_auth as gnmi_client_auth
from apis.system.rest import client_auth as rest_client_auth
from apis.system.basic import change_permissions
import os

rbac = SpyTestDict()

@pytest.fixture(scope="module", autouse=True)
def rbac_module_hooks():
    global vars
    vars = st.ensure_min_topology("D1 D2")
    rbac_variables_init()
    rbac_module_prolog()
    yield
    rbac_module_epilog()


@pytest.fixture(scope="function", autouse=True)
def rbac_func_hooks(request):
    if st.get_func_name(request) == "test_ft_rbac_rw_local_cert_rest":
        rest_client_auth(vars.D1, auth_type='cert', ca_crt=rbac.ca_crt)
    if st.get_func_name(request) == "test_ft_rbac_rw_local_cert_gnmi":
        gnmi_client_auth(vars.D1, auth_type='cert', server_key=rbac.server_key, server_crt=rbac.server_crt, ca_crt=rbac.ca_crt)
    yield
    if st.get_func_name(request) == 'test_ft_rbac_rw_local_cert_rest':
        rest_client_auth(vars.D1, auth_type=rbac.rest_auth, ca_crt='')
    if st.get_func_name(request) == 'test_ft_rbac_rw_local_cert_gnmi':
        gnmi_client_auth(vars.D1, auth_type=rbac.rest_auth, ca_crt='')


def rbac_variables_init():
    rbac.clear()
    port = st.get_free_ports(vars.D1)[0].replace("/", "%2F")
    rbac.url = 'restconf/data/sonic-port:sonic-port/PORT/PORT_LIST={}/admin_status'.format(port)
    rbac.default_user = {'username': 'admin',
                         'password': 'broadcom',
                         'alt_password': 'YourPaSsWoRd',
                         'mode': 'rw'}
    rbac.local_rw = {'username': 'testlorw',
                     'password': 'testlo123rw',
                     'role': 'admin',
                     'mode': 'rw'}
    rbac.local_ro = {'username': 'testloro',
                     'password': 'testlo123ro',
                     'role': 'operator',
                     'mode': 'ro'}
    rbac.local_no_group = {'username': 'test_no_group',
                           'password': 'no_group',
                           'mode': 'ro',
                           'cli_type': 'click'}

    rbac.client_keygen_path = r'/home/admin/.ssh/'
    rbac.rest_auth = 'password,jwt'
    rbac.gnmi_auth = 'password,jwt'
    rbac.ssh_key = r"~/.ssh/id_rsa"
    rbac.rest_cert = (r"/home/admin/.cert/key.pem", r"/home/admin/.cert/certificate.pem")
    rbac.ca_crt = r"/host/cli-ca/cert.pem"
    rbac.server_key = r"/host_home/admin/.cert/key.pem"
    rbac.server_crt = r"/host_home/admin/.cert/certificate.pem"
    rbac.gnmi_cert = r"/host_home/admin/.cert/certificate.pem -key /host_home/admin/.cert/key.pem -ca /host/cli-ca/cert.pem"
    rbac.cred_list = [rbac.local_rw, rbac.local_ro, rbac.local_no_group]
    rbac.group_list = list(set([e['role'] for e in rbac.cred_list if 'role' in e]))
    rbac.user_list = list(set([e['username'] for e in rbac.cred_list if 'username' in e]))
    rbac.user_group = {e['username']: e['role'] for e in rbac.cred_list if 'username' in e and 'role' in e}


def rbac_module_prolog():
    ping_validation()
    sshapi.enable_ssh(vars.D1)
    rbac.default_user['password'] = sshapi.default_user_password_finder(vars.D1, rbac.default_user['username'],
                                                                        [rbac.default_user['password'],
                                                                        rbac.default_user['alt_password']])
    sshapi.ssh_keygen(vars.D2, mode='create', path=rbac.client_keygen_path)
    rbac_config_user(0)
    generating_certificates_to_dut()
    rest_client_auth(vars.D1, auth_type=rbac.rest_auth)
    gnmi_client_auth(vars.D1, auth_type=rbac.gnmi_auth)


def rbac_module_epilog():
    sshapi.ssh_keygen(vars.D2, mode='destroy', path=rbac.client_keygen_path)
    rbac_config_user(1)
    rest_client_auth(vars.D1, auth_type='')
    gnmi_client_auth(vars.D1, auth_type='')
    password = sshapi.default_user_password_finder(vars.D1, rbac.default_user['username'],
                                                                        [rbac.default_user['password'],
                                                                        rbac.default_user['alt_password']])
    st.debug("The password for user: {} is: {}".format(rbac.default_user['username'], password))


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
    sshapi.ssh_keygen(vars.D2, mode='destroy', path=rbac.client_keygen_path)
    rbac_config_user(1)

def generating_certificates_to_dut():
    local_path = os.path.dirname(__file__)
    local_certificates_path = "{}/certificates/".format(local_path)
    file_name1 = "rootgen"
    file_name2 = "certgen"
    file_path1 = "{}{}".format(local_certificates_path, file_name1)
    file_path2 = "{}{}".format(local_certificates_path, file_name2)
    st.upload_file_to_dut(vars.D1, file_path1, "/home/admin/")
    st.upload_file_to_dut(vars.D1, file_path2, "/home/admin/")
    change_permissions(vars.D1, folder_path=file_name1)
    change_permissions(vars.D1, folder_path=file_name2)
    # Api's are not availale to generate cert
    st.config(vars.D1, "sudo ./rootgen")
    st.config(vars.D1, "sudo ./certgen admin")


@pytest.mark.rbac
@pytest.mark.rbac_ssh
def test_ft_rbac_rw_default_cred_ssh():
    """
    FtOpSoScRBACFn020: Verify that default user will have all permissions when SSH to the system with username/password
    """
    ssh_call(vars.D1, vars.D2, login_type='cred', **rbac.default_user)


@pytest.mark.rbac
def test_ft_rbac_ro_local_cred_ssh():
    """
     FtOpSoScRBACFn001: Verify that non-admin user doesn't have all permissions except show (get) commands
                        when SSH to the system with username/password.
    """
    ssh_call(vars.D1, vars.D2, login_type='cred', **rbac.local_ro)


@pytest.mark.rbac
@pytest.mark.rbac_ssh
def test_ft_rbac_rw_local_cred_ssh():
    """
    FtOpSoScRBACFn003 : Verify that admin user will have all permissions when SSH to the system with username/password.
    """
    ssh_call(vars.D1, vars.D2, login_type='cred', **rbac.local_rw)


@pytest.mark.rbac
@pytest.mark.rbac_ssh
def test_ft_rbac_rw_local_no_group_cred_ssh():
    """
    FtOpSoScRBACFn007 : Verify that user doesn't have any permissions while user is configured with non-existing
                        group role when SSH to the system with username/password.
    """
    ssh_call(vars.D1, vars.D2, login_type='cred', **rbac.local_no_group)


@pytest.mark.rbac
@pytest.mark.rbac_ssh
def test_ft_rbac_ro_local_pubkey_ssh():
    """
    FtOpSoScRBACFn002: Verify that non-admin user doesn't have all permissions except show (get) commands
                       when SSH to the system with pubkey.
    """
    ssh_call(vars.D1, vars.D2, login_type='pubkey', **rbac.local_ro)


@pytest.mark.rbac
@pytest.mark.rbac_ssh
def test_ft_rbac_rw_local_pubkey_ssh():
    """
    FtOpSoScRBACFn004: Verify that admin user will have all permissions when SSH to the system with with pubkey.
    """
    ssh_call(vars.D1, vars.D2, login_type='pubkey', **rbac.local_rw)


@pytest.mark.rbac
@pytest.mark.rbac_rest
def test_ft_rbac_rw_local_cred_rest():
    """
    FtOpSoScRBACFn014: Verify that admin user will have all permissions when authenticate to REST server with
                        username/password.
    """
    rest_rbac_call(vars.D1, login_type='cred', url = rbac.url, **rbac.local_rw)


@pytest.mark.rbac
@pytest.mark.rbac_rest
def test_ft_rbac_ro_local_cred_rest():
    """
    FtOpSoScRBACFn012: Verify that non-admin user doesn?t have all permissions except show (get) commands
                       when authenticate to REST server with username/password.
    """
    rest_rbac_call(vars.D1, login_type='cred', url = rbac.url, **rbac.local_ro)


@pytest.mark.rbac
@pytest.mark.rbac_rest
def test_ft_rbac_rw_local_jwt_token_rest():
    """
    FtOpSoScRBACFn021: Verify that admin user have all permissions when authenticate to REST server with token.
    """
    rest_rbac_call(vars.D1, login_type='token', url = rbac.url, **rbac.local_rw)


@pytest.mark.rbac
@pytest.mark.rbac_rest
def test_ft_rbac_ro_local_jwt_token_rest():
    """
    FtOpSoScRBACFn013: Verify that non-admin user doesn't have all permissions except show (get) commands
                       when authenticate to REST server with token.
    """
    rest_rbac_call(vars.D1, login_type='token', url = rbac.url, **rbac.local_ro)


@pytest.mark.rbac
@pytest.mark.rbac_rest1
def test_ft_rbac_rw_local_cert_rest():
    """
    FtOpSoScRBACFn015: Verify that admin user will have all permissions
                    when authenticate to REST server ( based on certificate )
    """
    st.wait(30)
    rest_rbac_call(vars.D1, login_type='cert', cert=rbac.rest_cert, url = rbac.url, **rbac.local_rw)


@pytest.mark.rbac
@pytest.mark.rbac_gnmi
def test_ft_rbac_rw_local_cred_gnmi():
    """
    FtOpSoScRBACFn018: Verify that admin user will have all permissions when authenticate to gNMI server with
                       username/password.
    """
    gnmi_call(vars.D1, login_type='cred', **rbac.local_rw)


@pytest.mark.rbac
@pytest.mark.rbac_gnmi
def test_ft_rbac_ro_local_cred_gnmi():
    """
    FtOpSoScRBACFn016: Verify that non-admin user doesn?t have all permissions except show (get)
                       commands when authenticate to gNMI server with username/password.
    """
    gnmi_call(vars.D1, login_type='cred', **rbac.local_ro)


@pytest.mark.rbac
@pytest.mark.rbac_gnmi
def test_ft_rbac_rw_local_cert_gnmi():
    """
    FtOpSoScRBACFn019: Verify that admin user will have all permissions when authenticate to gNMI server with token
                        ( based on certificate )
    """
    gnmi_call(vars.D1, login_type='cert', cert=rbac.gnmi_cert, **rbac.local_rw)

