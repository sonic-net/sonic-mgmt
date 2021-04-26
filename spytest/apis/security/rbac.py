# This file contains the list of RBAC APIs.
# Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

from spytest import st
from apis.system.gnmi import gnmi_get, gnmi_set
from apis.system.rest import rest_call, get_jwt_token


def ssh_call(dut, remote_dut=None, **kwargs):
    """
    Call to test SSH session using diff users w.r.t RBAC.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param remote_dut:
    :param kwargs:
    :return:
    """
    st.log('Performing SSH call using - {}'.format(kwargs))
    for each in ['login_type', 'username', 'password', 'mode']:
        if not kwargs.get(each):
            st.error("Mandatory argument is not found - {}".format(each))
            return False

    dut_ip = st.get_mgmt_ip(dut)
    result = {'show': True, 'config': True}
    result2 = True
    username = kwargs.get('username')
    password = kwargs.get('password')
    login_type = kwargs.get('login_type')
    mode = kwargs.get('mode')

    if login_type == 'cred':
        ssh_out = st.exec_ssh(dut, username, password,
                              ['show vlan config', 'sudo config vlan add 100\n{}'.format(password)])
        st.log(ssh_out)
    elif login_type == 'pubkey':
        show_out = st.exec_ssh_remote_dut(remote_dut, dut_ip, username, password, 'show vlan config')
        config_out = st.exec_ssh_remote_dut(remote_dut, dut_ip, username, password,
                                            'sudo config vlan add 100\n{}'.format(password))
        ssh_out = show_out + "\n" + config_out
    else:
        st.error("Invalid 'login_type' used = {}".format(login_type))
        return False

    if not ssh_out:
        st.report_fail('rbac_call_fail', "SSH", mode, login_type)

    if 'Sorry, user {} is not allowed to execute'.format(username) in ssh_out or \
            "no askpass program specified" in ssh_out:
        result['config'] = False
    if 'VID' not in ssh_out:
        result['show'] = False
    st.log(result)

    msg = 'Failed to execute show command using ssh session with mode- {mode}, type- {login_type}'
    if mode == 'rw' and not all(result.values()):
        st.error(msg.format(**kwargs))
        result2 = False
    if mode == 'ro' and not (result['show'] and not result['config']):
        st.error(msg.format(**kwargs))
        result2 = False

    if not result2:
        st.report_fail('rbac_test_status', 'Fail', mode, 'SSH', login_type, result)
    st.report_pass('rbac_test_status', 'Pass', mode, 'SSH', login_type, result)


def gnmi_call(dut, **kwargs):
    """
    Call to test gnmi session using diff users w.r.t RBAC.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param kwargs:
    :return:
    """
    st.log('Performing gnmi operations using - {}'.format(kwargs))

    for each in ['login_type', 'username', 'password', 'mode']:
        if not kwargs.get(each):
            st.error("Mandatory argument is not found - {}".format(each))
            return False

    dut_ip = "127.0.0.1"
    result = {'gnmi_get_out': True, 'gnmi_set_out': True}
    result2 = True
    username = kwargs.get('username')
    password = kwargs.get('password')
    cert = kwargs.get('cert')
    login_type = kwargs.get('login_type')
    mode = kwargs.get('mode')
    port = st.get_free_ports(dut)[0]
    if "/" in port:
        port = st.get_other_names(dut, [port])[0]
    xpath = '/openconfig-interfaces:interfaces/interface[name={}]/config/description'.format(port)
    json_content = {"openconfig-interfaces:description": "Eth"}

    if login_type == 'cred':
        gnmi_set_out = gnmi_set(dut, xpath, json_content=json_content, ip_address=dut_ip, username=username,
                                password=password)
        st.log(gnmi_set_out)
        gnmi_get_out = gnmi_get(dut, xpath, ip_address=dut_ip, username=username, password=password)
        st.log(gnmi_get_out)

    elif login_type == 'cert':
        gnmi_set_out = gnmi_set(dut, xpath, json_content=json_content, ip_address=dut_ip, cert=cert,
                                username=None, password=None, insecure='none', target_name='admin')
        st.log(gnmi_set_out)
        gnmi_get_out = gnmi_get(dut, xpath, ip_address=dut_ip, cert=cert, username=None, password=None, insecure='none',
                                target_name='admin')
        st.log(gnmi_get_out)

    else:
        st.error("Invalid 'login_type' used = {}".format(login_type))
        return False

    if mode == 'rw':
        if not (gnmi_set_out and gnmi_get_out):
            st.report_fail('rbac_call_fail', "gNMI", mode, login_type)
    else:
        if not (not gnmi_set_out and gnmi_get_out):
            st.report_fail('rbac_call_fail', "gNMI", mode, login_type)

    msg = 'Failed to execute set command using gNMI session with mode- {mode}, type- {login_type}'
    if mode == 'rw' and "op: UPDATE" not in str(gnmi_set_out) and "description" not in str(gnmi_get_out):
        st.error(msg.format(**kwargs))
        result2 = False
    if mode == 'ro' and not gnmi_set_out and "description" not in str(gnmi_get_out):
        st.error(msg.format(**kwargs))
        result2 = False

    if not result2:
        st.report_fail('rbac_test_status', 'Fail', mode, 'gNMI', login_type, result)
    st.report_pass('rbac_test_status', 'Pass', mode, 'gNMI', login_type, result)


def rest_rbac_call(dut, **kwargs):
    """
    Call to test REST sessions using diff users w.r.t RBAC.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param kwargs:
    :return:
    """
    st.log('Performing REST call using - {}'.format(kwargs))
    for each in ['login_type', 'username', 'password', 'mode']:
        if not kwargs.get(each):
            st.error("Mandatory argument is not found - {}".format(each))
            return False

    result = {'get': True, 'put': True}
    result2 = True
    pass_status = [200, 204]
    fail_status = [401, 403]
    username = kwargs.get('username')
    password = kwargs.get('password')
    login_type = kwargs.get('login_type')
    mode = kwargs.get('mode')
    cert = kwargs.get("cert")
    model = kwargs.get('model')
    url = kwargs.get('url')
    if model == 'oc-yang':
        operation1 = {"openconfig-interfaces:mtu": 9216}
        operation2 = {"openconfig-interfaces:mtu": 9100}
    else:
        operation1 = {"sonic-port:admin_status": "down"}
        operation2 = {"sonic-port:admin_status": "up"}

    if login_type == 'cred':
        headers1 = {'Content-Type': 'application/yang-data+json', 'Accept': 'application/yang-data+json'}
        rest_get_out = rest_call(dut, headers=headers1, username=username, password=password, url=url, call_type='get')
        st.log(rest_get_out)
        rest_put_out = rest_call(dut, headers=headers1, username=username, password=password, url=url, call_type='put',
                                 data=operation1)
        st.log(rest_put_out)

    elif login_type == 'token':
        headers2 = {'Content-Type': 'application/yang-data+json', 'Accept': 'application/yang-data+json',
                    'Authorization': 'Bearer {}'}
        tocken = get_jwt_token(dut, username=username, password=password)
        if not tocken:
            st.report_fail('rbac_test_jwt_token_fail', mode, login_type)
        headers2['Authorization'] = headers2['Authorization'].format(tocken)
        rest_get_out = rest_call(dut, headers=headers2, url=url, call_type='get')
        st.log(rest_get_out)
        rest_put_out = rest_call(dut, headers=headers2, url=url, call_type='put', data=operation2)
        st.log(rest_put_out)

    elif login_type == 'cert':
        port1 = st.get_free_ports(dut)[0].replace("/", "%2F")
        url2 = '/restconf/data/sonic-port:sonic-port/PORT/PORT_LIST={}/admin_status'.format(port1)
        get_curl = 'curl --key {} --cert {} ' "'https://localhost{}'" ' -k'.format(cert[0], cert[1], url2)
        out = st.show(dut, get_curl, skip_tmpl=True, skip_error_check=True)
        rest_get_out = {'status': 401}
        rest_put_out = {'status': 200}
        if 'sonic-port:admin_status' in out:
            rest_get_out = {'status': 200}

    else:
        st.error("Invalid 'login_type' used = {}".format(login_type))
        return False

    if not (rest_get_out and rest_put_out):
        st.report_fail('rbac_call_fail', "REST", mode, login_type)

    msg = 'Failed to authenticate  using rest session with mode- {mode}, type- {login_type}'
    if mode == 'rw' and not (rest_get_out["status"] in pass_status and rest_put_out["status"] in pass_status):
        st.error(msg.format(**kwargs))
        result2 = False
    if mode == 'ro' and not (rest_get_out["status"] in pass_status and rest_put_out["status"] in fail_status):
        st.error(msg.format(**kwargs))
        result2 = False

    if not result2:
        st.report_fail('rbac_test_status', 'Fail', mode, 'REST', login_type, result)
    st.report_pass('rbac_test_status', 'Pass', mode, 'REST', login_type, result)

def add_user(dut, username):
    """
    Call to add user.
    Author : Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param dut:
    :param username:
    :return:
    """
    st.config(dut, 'usermod -s /bin/bash {}'.format(username))
    return True
