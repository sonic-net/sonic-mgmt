# This file contains the list of RBAC APIs.
# Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

from spytest import st
from apis.system.gnmi import gnmi_get, gnmi_set
from apis.system.rest import rest_call, get_jwt_token
from apis.system.connection import connect_to_device, execute_command, ssh_disconnect
from apis.switching.vlan import show_vlan_from_rest_response
from apis.system.rest import config_rest, get_rest, rest_status
from utilities.utils import get_supported_ui_type_list


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
    role = kwargs.get('role')
    mode = kwargs.get('mode')
    ssh_out = False
    ssh_out1 = False

    if login_type == 'cred':
        if role == 'admin':
            ssh_out = st.exec_ssh(dut, username, password,
                                  ['sudo show vlan config', 'sudo config vlan add 100\n{}'.format(password)])
            st.log("output start")
            st.log(ssh_out)
            st.log("output End")
        elif role == 'operator':
            ssh_out = st.exec_ssh(dut, username, password,
                                  ['show vlan', 'configure terminal \n interface vlan 100\n{}'.format(password)])
            st.log(ssh_out)
        elif role == 'secadmin':
            ssh_out = st.exec_ssh(dut, username, password,
                                  ['configure terminal \n radius-server host 1.1.1.1 \n exit \n', 'show radius \n'])
            st.log("output start")
            st.log(ssh_out)
            st.log("output End")
            ssh_out1 = st.exec_ssh(dut, username, password,
                                   ['configure terminal \n priority-flow-control watchdog polling-interval 100 \nexit \n'])
            st.log("output start")
            st.log(ssh_out1)
            st.log("output End")
        elif role == 'netadmin':
            ssh_out = st.exec_ssh(dut, username, password,
                                  ['configure terminal \n priority-flow-control watchdog polling-interval 100 \nexit \n', 'show priority-flow-control watchdog \n'])
            st.log(ssh_out)
            ssh_out1 = st.exec_ssh(dut, username, password,
                                   ['configure terminal \n radius-server host 1.1.1.1 \n exit \n'])
            st.log("output start")
            st.log(ssh_out1)
            st.log("output End")
        elif role == 'operator,secadmin':
            ssh_out = st.exec_ssh(dut, username, password,
                                  ['configure terminal \n radius-server host 1.1.1.1 \n exit \n', 'show radius \n'])
            st.log(ssh_out)
        elif role == 'operator,netadmin':
            ssh_out = st.exec_ssh(dut, username, password,
                                  ['configure terminal \n priority-flow-control watchdog polling-interval 100 \nexit \n', 'show priority-flow-control watchdog \n'])
            st.log(ssh_out)
        elif role == 'secadmin,netadmin':
            ssh_out = st.exec_ssh(dut, username, password,
                                  ['configure terminal \n radius-server host 1.1.1.1\n exit \n', 'show radius \n'])
            st.log(ssh_out)
    elif login_type == 'pubkey':
        config_out = st.exec_ssh_remote_dut(remote_dut, dut_ip, username, password,
                                            'sudo config vlan add 200')
        show_out = st.exec_ssh_remote_dut(remote_dut, dut_ip, username, password, 'sudo show vlan config')
        ssh_out = show_out + "\n" + config_out
    else:
        st.error("Invalid 'login_type' used = {}".format(login_type))
        return False

    if not ssh_out and not ssh_out1:
        st.report_fail('rbac_call_fail', "SSH", mode, login_type)

    if 'Sorry, user {} is not allowed to execute'.format(username) in ssh_out or \
            "no askpass program specified" in ssh_out or "Invalid input detected" in ssh_out or 'Client is not authorized to perform this operation' in ssh_out:
        result['config'] = False
    if role == 'admin':
        if 'VID' not in ssh_out:
            result['show'] = False
    elif role == 'operator':
        if '100' not in ssh_out:
            result['show'] = False
    elif role == 'secadmin':
        if '1812' not in ssh_out or 'Invalid input detected' not in ssh_out1:
            result['show'] = False
    elif role == 'operator,secadmin' and role == 'secadmin,netadmin':
        if '1812' not in ssh_out or 'Invalid input detected' in ssh_out:
            result['show'] = False
    elif role == 'netadmin':
        if 'Polling Interval' not in ssh_out or 'Invalid input detected' not in ssh_out1:
            result['show'] = False
    elif role == 'operator,netadmin':
        if 'Polling Interval' not in ssh_out or 'Invalid input detected' in ssh_out:
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
    gnmi_get_out = False
    gnmi_set_out = False
    gnmi_get_out_type = False
    result2 = True
    username = kwargs.get('username')
    password = kwargs.get('password')
    cert = kwargs.get('cert')
    login_type = kwargs.get('login_type')
    mode = kwargs.get('mode')
    role = kwargs.get('role')
    port = st.get_free_ports(dut)[0]
    st.log("portdetails========>{}".format(port))
    xpath = '/openconfig-interfaces:interfaces/interface[name={}]/config/description'.format(port)
    xpath_type = '/openconfig-interfaces:interfaces/interface[name={}]/config/type'.format(port)
    xpath_net = '/openconfig-qos:qos/pfc-watchdog/poll/config/poll-interval'
    xpath_sec = '/openconfig-system:system/aaa/server-groups'
    xpath_sec_get = '/openconfig-system:system/aaa/server-groups/server-group[name=RADIUS]/config'
    json_content = {"openconfig-interfaces:description": "Eth"}
    # json_content_type = {"openconfig-interfaces:type": "iana-if-type:ethernetCsmacd"}
    json_content_sec = {"openconfig-system:server-groups": {"openconfig-system:server-group": [{"openconfig-system:name": "RADIUS", "openconfig-system:config": {"openconfig-system:name": "RADIUS"}, "openconfig-system:servers": {"openconfig-system:server": [{"openconfig-system:address": "10.193.81.61", "openconfig-system:config": {"address": "10.193.81.61"}, "openconfig-system:radius": {"openconfig-system:config": {"encrypted": False}}}]}}]}}
    json_content_net = {"openconfig-qos:poll-interval": 100}

    if login_type == 'cred':
        if role == 'admin':
            gnmi_set_out = gnmi_set(dut, xpath, json_content=json_content, ip_address=dut_ip, username=username,
                                    password=password)
            st.log("output start")
            st.log(gnmi_set_out)
            st.log("output End")
            gnmi_get_out = gnmi_get(dut, xpath, ip_address=dut_ip, username=username, password=password)
            st.log(gnmi_get_out)
            gnmi_get_out_type = gnmi_get(dut, xpath_type, ip_address=dut_ip, username=username, password=password)
            st.log(gnmi_get_out_type)
        elif role == 'operator':
            gnmi_set_out = gnmi_set(dut, xpath, json_content=json_content, ip_address=dut_ip, username=username,
                                    password=password)
            st.log(gnmi_set_out)
            gnmi_get_out = gnmi_get(dut, xpath, ip_address=dut_ip, username=username, password=password)
            st.log(gnmi_get_out)
        elif role == 'secadmin':
            gnmi_set_out = gnmi_set(dut, xpath_sec, json_content=json_content_sec, ip_address=dut_ip, username=username,
                                    password=password)
            st.log(gnmi_set_out)
            gnmi_get_out = gnmi_get(dut, xpath_sec_get, ip_address=dut_ip, username=username, password=password)
            st.log(gnmi_get_out)
        elif role == 'netadmin':
            gnmi_set_out = gnmi_set(dut, xpath_net, json_content=json_content_net, ip_address=dut_ip, username=username,
                                    password=password)
            st.log(gnmi_set_out)
            gnmi_get_out = gnmi_get(dut, xpath_net, ip_address=dut_ip, username=username, password=password)
            st.log(gnmi_get_out)
        elif role == 'operator,secadmin':
            gnmi_set_out = gnmi_set(dut, xpath_sec, json_content=json_content_sec, ip_address=dut_ip, username=username,
                                    password=password)
            st.log(gnmi_set_out)
            gnmi_get_out = gnmi_get(dut, xpath_sec_get, ip_address=dut_ip, username=username, password=password)
            st.log(gnmi_get_out)
        elif role == 'operator,netadmin':
            gnmi_set_out = gnmi_set(dut, xpath_net, json_content=json_content_net, ip_address=dut_ip, username=username,
                                    password=password)
            st.log(gnmi_set_out)
            gnmi_get_out = gnmi_get(dut, xpath_net, ip_address=dut_ip, username=username, password=password)
            st.log(gnmi_get_out)
        elif role == 'secadmin,netadmin':
            gnmi_set_out = gnmi_set(dut, xpath_sec, json_content=json_content_sec, ip_address=dut_ip, username=username,
                                    password=password)
            st.log(gnmi_set_out)
            gnmi_get_out = gnmi_get(dut, xpath_sec_get, ip_address=dut_ip, username=username, password=password)
            st.log(gnmi_get_out)
    elif login_type == 'cert':
        gnmi_get_out_type = True
        gnmi_set_out = gnmi_set(dut, xpath, json_content=json_content, ip_address=dut_ip, cert=cert,
                                username=None, password=None, insecure='none', target_name='localhost')
        st.log(gnmi_set_out)
        gnmi_get_out = gnmi_get(dut, xpath, ip_address=dut_ip, cert=cert, username=None, password=None, insecure='none',
                                target_name='localhost')
        st.log(gnmi_get_out)

    else:
        st.error("Invalid 'login_type' used = {}".format(login_type))
        return False

    if mode == 'rw':
        if not (gnmi_set_out and gnmi_get_out):
            st.report_fail('rbac_call_fail', "gNMI", mode, login_type)
        if role == 'admin':
            if not (gnmi_get_out_type):
                st.report_fail('rbac_call_fail', "gNMI", mode, login_type)
    else:
        if not (not gnmi_set_out and gnmi_get_out):
            st.report_fail('rbac_call_fail', "gNMI", mode, login_type)

    msg = 'Failed to execute set command using gNMI session with mode- {mode}, type- {login_type}'
    if mode == 'rw' and role == 'admin' and "op: UPDATE" not in gnmi_set_out and "description" not in str(gnmi_get_out) and "type" not in str(gnmi_get_out_type):
        st.error(msg.format(**kwargs))
        result2 = False
    elif mode == 'rw' and "op: UPDATE" not in gnmi_set_out and "description" not in str(gnmi_get_out):
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
    rest_put_out = False
    rest_get_out = False
    result2 = True
    pass_status = [200, 204]
    fail_status = [401, 403]
    username = kwargs.get('username')
    password = kwargs.get('password')
    login_type = kwargs.get('login_type')
    mode = kwargs.get('mode')
    cert = kwargs.get("cert")
    model = kwargs.get('model')
    role = kwargs.get('role')
    url = kwargs.get('url')
    if model == 'oc-yang':
        operation1 = {"openconfig-interfaces:mtu": 9216}
        operation2 = {"openconfig-interfaces:mtu": 9100}
    else:
        operation1 = {"sonic-port:admin_status": "down"}
        operation2 = {"sonic-port:admin_status": "up"}
        sec_data = {"openconfig-system:server-group": [{"config": {"name": "LDAP"}, "name": "LDAP", "servers":
                                                        {"server": [{"openconfig-aaa-ldap-ext:ldap": {"config": {}}, "config": {"address": '2.2.2.2'},
                                                                     "address": '2.2.2.2'}]}}]}
        net_data = {"openconfig-qos:scheduler-policies": {"scheduler-policy": [{"name": "test", "config": {"name": "test"}}]}}

    if login_type == 'cred':
        if role == 'admin':
            headers1 = {'Content-Type': 'application/yang-data+json', 'Accept': 'application/yang-data+json'}
            rest_get_out = rest_call(dut, headers=headers1, username=username, password=password, url=url, call_type='get')
            st.log("output start")
            st.log(rest_get_out)
            st.log("output end")
            rest_put_out = rest_call(dut, headers=headers1, username=username, password=password, url=url, call_type='put',
                                     data=operation1)
            st.log("output start")
            st.log(rest_put_out)
            st.log("output end")
        elif role == 'operator':
            headers1 = {'Content-Type': 'application/yang-data+json', 'Accept': 'application/yang-data+json'}
            rest_get_out = rest_call(dut, headers=headers1, username=username, password=password, url=url, call_type='get')
            st.log(rest_get_out)
            rest_put_out = rest_call(dut, headers=headers1, username=username, password=password, url=url, call_type='put',
                                     data=operation1)
            st.log(rest_put_out)
        elif role == 'secadmin':
            headers1 = {'Content-Type': 'application/yang-data+json', 'Accept': 'application/yang-data+json'}
            rest_put_out = rest_call(dut, headers=headers1, username=username, password=password, url=url, call_type='put',
                                     data=sec_data)
            st.log(rest_put_out)
            rest_get_out = rest_call(dut, headers=headers1, username=username, password=password, url=url, call_type='get')
            st.log(rest_get_out)
        elif role == 'netadmin':
            headers1 = {'Content-Type': 'application/yang-data+json', 'Accept': 'application/yang-data+json'}
            rest_put_out = rest_call(dut, headers=headers1, username=username, password=password, url=url, call_type='put',
                                     data=net_data)
            st.log(rest_put_out)
            rest_get_out = rest_call(dut, headers=headers1, username=username, password=password, url=url, call_type='get')
            st.log(rest_get_out)
        elif role == 'operator,secadmin':
            headers1 = {'Content-Type': 'application/yang-data+json', 'Accept': 'application/yang-data+json'}
            rest_get_out = rest_call(dut, headers=headers1, username=username, password=password, url=url, call_type='get')
            st.log(rest_get_out)
            rest_put_out = rest_call(dut, headers=headers1, username=username, password=password, url=url, call_type='put',
                                     data=sec_data)
            st.log(rest_put_out)
        elif role == 'operator,netadmin':
            headers1 = {'Content-Type': 'application/yang-data+json', 'Accept': 'application/yang-data+json'}
            rest_get_out = rest_call(dut, headers=headers1, username=username, password=password, url=url, call_type='get')
            st.log(rest_get_out)
            rest_put_out = rest_call(dut, headers=headers1, username=username, password=password, url=url, call_type='put',
                                     data=net_data)
            st.log(rest_put_out)
        elif role == 'secadmin,netadmin':
            headers1 = {'Content-Type': 'application/yang-data+json', 'Accept': 'application/yang-data+json'}
            rest_put_out = rest_call(dut, headers=headers1, username=username, password=password, url=url, call_type='put',
                                     data=sec_data)
            st.log(rest_put_out)
            rest_get_out = rest_call(dut, headers=headers1, username=username, password=password, url=url, call_type='get')
            st.log(rest_get_out)

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


def config_cmd_ssh_call(dut, username, password, role, vlan_id, cli_type=''):
    """
    ssh call to create vlan
    :param dut:
    :param username:
    :param password:
    :param user_type:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = "klish" if cli_type in get_supported_ui_type_list() else cli_type

    dut_ip = st.get_mgmt_ip(dut)
    ssh_obj = connect_to_device(dut_ip, username, password, sudo=False)
    if ssh_obj is None:
        return False

    if cli_type == "click":
        cmd = 'config vlan add {}'.format(vlan_id)
        ssh_out = execute_command(ssh_obj, cmd)
        st.debug("run command: {}".format(cmd))
        st.debug("command output:{}".format(ssh_out))
        ssh_disconnect(ssh_obj)
        if "Error" in ssh_out:
            return False
        else:
            return True
    elif cli_type == "klish":
        cmd = 'interface Vlan {}'.format(vlan_id)
        if role in ["admin", "root"]:
            execute_command(ssh_obj, "sonic-cli")
        execute_command(ssh_obj, "configure terminal")
        ssh_out = execute_command(ssh_obj, cmd)
        st.debug("run command: {}".format(cmd))
        st.debug("command output:{}".format(ssh_out))
        ssh_disconnect(ssh_obj)
        if "Error" in ssh_out:
            return False
        else:
            return True
    elif cli_type in ["rest-put", "rest-patch"]:
        vlan_data = dict()
        vlan_data["openconfig-interfaces:interface"] = list()
        vlan_data["openconfig-interfaces:interface"].append(
            {"name": "Vlan{}".format(vlan_id), "config": {"name": "Vlan{}".format(vlan_id)}})
        url = st.get_datastore(dut, "rest_urls")["config_interface"]
        if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=vlan_data):
            return False
        else:
            return True


def show_cmd_ssh_call(dut, username, password, role, vlan_id, **kwargs):
    """
    ssh call to show vlan
    :param dut:
    :param username:
    :param password:
    :param user_type:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=kwargs)
    cli_type = "klish" if cli_type in get_supported_ui_type_list() else cli_type

    dut_ip = st.get_mgmt_ip(dut)
    ssh_obj = connect_to_device(dut_ip, username, password, sudo=False)
    if ssh_obj is None:
        return False

    if cli_type == "click":
        cmd = 'show vlan config'
        ssh_out = execute_command(ssh_obj, cmd)
        st.debug("run command: {}".format(cmd))
        st.debug("command output:{}".format(ssh_out))
        ssh_disconnect(ssh_obj)
        if vlan_id in ssh_out:
            return True
        else:
            return False
    elif cli_type == "klish":
        cmd = 'show vlan'
        if role in ["admin", "root"]:
            execute_command(ssh_obj, "sonic-cli")
        ssh_out = execute_command(ssh_obj, cmd)
        st.debug("run command: {}".format(cmd))
        st.debug("command output:{}".format(ssh_out))
        ssh_disconnect(ssh_obj)
        if vlan_id in ssh_out:
            return True
        else:
            return False
    elif cli_type in ["rest-put", "rest-patch"]:
        timeout = kwargs.get('timeout', 180)
        rest_url = st.get_datastore(dut, "rest_urls")["config_interface"]
        get_resp = get_rest(dut, rest_url=rest_url, timeout=timeout)
        if get_resp and rest_status(get_resp["status"]):
            vlan_data = show_vlan_from_rest_response(get_resp["output"])
            st.debug(vlan_data)
            filter_vlan_data = list()
            for vlans in vlan_data:
                if str(vlans["vid"].replace("Vlan", "")) == vlan_id:
                    filter_vlan_data.append(vlans)
            return filter_vlan_data
        else:
            return False
