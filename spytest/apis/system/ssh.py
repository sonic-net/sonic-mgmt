from spytest import st
from apis.system.basic import deploy_package
from utilities.common import make_list, filter_and_select
from apis.system.rest import config_rest, delete_rest
from utilities.utils import get_supported_ui_type_list, convert_intf_name_to_component
import apis.system.system_server as sys_server_api


def enable_ssh(dut):
    st.log(" # enable ssh")
    command = "/etc/init.d/ssh start"
    st.config(dut, command)
    return True


def disable_ssh(dut):
    st.log(" # disable ssh")
    command = "/etc/init.d/ssh stop"
    st.config(dut, command)
    return True


def enable_sshv6(dut):
    #    st.log(" # Enable SSH on a device to listen on IPv6")
    #    command = "sed -i 's/#ListenAddress ::/ListenAddress ::/g' /etc/ssh/sshd_config"
    #    st.config(dut, command)
    #    command = "/etc/init.d/ssh restart"
    #    st.config(dut, command)
    return True


def disable_sshv6(dut):
    #    st.log(" # Disable SSH on a device to listen on IPv6")
    #    command = "sed -i 's/ListenAddress ::/#ListenAddress ::/g' /etc/ssh/sshd_config"
    #    st.config(dut, command)
    #    command = "/etc/init.d/ssh restart"
    #    st.config(dut, command)
    return True


def ssh_keygen(dut, mode='create', path=r'/home/admin/.ssh/'):
    """
    To generate the SSH keys to DUT
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param mode: create | destroy
    :param path:
    :return:
    """
    st.banner(" Generate SSH keys to DUT - Mode={}".format(mode))
    if mode == 'create':
        cmd_list = ['mkdir {}', 'touch {}authorized_keys', 'chmod 0700 {}', 'chmod 0600 {}authorized_keys',
                    "echo -e 'y\n' | ssh-keygen -o -b 4096 -t rsa -f ~/.ssh/id_rsa -N ''", 'ls -lrt {}']
    else:
        cmd_list = ['sudo rm -rf {}', 'ls -lrt {}']
    for each_cmd in cmd_list:
        st.show(dut, each_cmd.format(path), skip_tmpl=True, skip_error_check=True)


def ssh_copyid(dut, ip, **kwargs):
    """
    To copy SSH ID from DUT to server.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param ip:
    :param kwargs:
    :return:
    """
    result = True
    st.log(" # Copy SSH ID from DUT to server")
    if not (kwargs.get('username') and kwargs.get('password')):
        st.error("Mandatory arguments are missing.")
        return False
    if 'sshpass' not in st.config(dut, 'which sshpass', skip_error_check=True):
        deploy_package(dut, mode='update')
        result = deploy_package(dut, packane_name='sshpass', mode='install')
    # nosemgrep-next-line
    st.show(dut, 'sshpass -p "{}" ssh-copy-id -o StrictHostKeyChecking=no {}@{} -f'.format(
        kwargs['password'], kwargs['username'], ip), skip_tmpl=True)
    return result


def default_user_password_finder(dut, username, password_list):
    """
    To Find default user password.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param username:
    :param password_list:
    :return:
    """
    st.log(" # Finding default user password.")
    for each_pass in make_list(password_list):
        st.log('Trying SSH connection to device with username={},password={}'.format(username, each_pass))
        if st.exec_ssh(dut, username, each_pass, ['show system status']):
            st.log("Detected password = {}".format(each_pass))
            return each_pass


def enable_ssh_in_user_vrf(dut, **kwargs):
    """
    To enable SSH-in over user defined VRF
    :param dut:
    :param kwargs:
    :return:
    Usage:enable_ssh_in_user_vrf(vars.D1, config='add',vrf_name='mgmt')
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    st.log(" Configure SSH-in for user VRF")
    if not kwargs.get('vrf_name'):
        st.error("Mandatory arguments are missing.")
        return False
    if kwargs.get('config') not in ['add', 'del']:
        st.error("Incorrect config type")
        return False
    if cli_type in get_supported_ui_type_list():
        kwargs['config'] = 'no' if kwargs.pop('config', 'add') == 'del' else 'yes'
        return sys_server_api.config_system_server_properties(dut, server_name='SSH-SERVER', **kwargs)
    elif cli_type == "click":
        command = "config ssh-server vrf {} {}".format(kwargs.get('config'), kwargs.get('vrf_name'))
        st.config(dut, command, type=cli_type, skip_error_check=True)
    elif cli_type == "klish":
        config = "no " if kwargs.get('config') == "del" else ""
        command = "{}ssh-server vrf {}".format(config, kwargs.get('vrf_name'))
        st.config(dut, command, type=cli_type, skip_error_check=True)
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['config_ssh_server'].format(kwargs.get('vrf_name'))
        ssh_config = {"openconfig-system-ext:ssh-server-vrf": [{"vrf-name": kwargs.get('vrf_name'), "config": {
            "vrf-name": kwargs.get('vrf_name'), "port": 22}}]}
        if kwargs.get('config') == 'add':
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=ssh_config):
                st.error("ssh server configuration failed")
                return False
        else:
            if not delete_rest(dut, rest_url=url):
                st.error("ssh server deletion failed")
                return False
    else:
        st.error("Unsupported cli_type: {}".format(cli_type))
        return False
    return True


def get_ssh_server_vrf(dut, vrf_name=None, cli_type=''):
    """
    To Get SSH server VRF
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param vrf_name:
    :param cli_type:
    :return:

    Usage:
    get_ssh_server_vrf(vars.D1)
    get_ssh_server_vrf(vars.D1, vrf_name='VRF_1')

    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = 'klish' if cli_type in ['rest-patch', 'rest-put'] + get_supported_ui_type_list() else cli_type
    command = "show ssh-server vrfs"
    output = st.show(dut, command, type=cli_type)
    if vrf_name not in output:
        return output
    else:
        out = filter_and_select(output, None, {'vrf_name': vrf_name})
        if not out:
            return False
        else:
            return out[0]['status']


def verify_ssh_connection(dut, ip, username, password, cmds="show vlan breif"):
    '''
    This change for intf naming change in C+. Commented code will be removed after one FT run
    sub_intf = st.get_args("routed_sub_intf")
    if sub_intf:
        if '/' in ip:
            ll_intf = ip.split('%')
            if '.' in ll_intf[1]:
                ll_intf1 = ll_intf[1].split('.')
                ip = ll_intf[0] + '%'+st.get_other_names(dut, [ll_intf1[0]])[0]+'.'+ll_intf1[1]
                if 'Ethernet' in ip:
                    ip = ip.replace('Ethernet', 'Eth')
        else:
            ip = ip.replace('Ethernet', 'Eth')
        if 'PortChannel' in ip:
                ip = ip.replace('PortChannel', 'Po')
    else:
        if '/' in ip:
            ll_intf = ip.split('%')
            ip = ll_intf[0] + '%' + st.get_other_names(dut, [ll_intf[1]])[0]
    '''

    if '%' in ip:
        ll_intf = ip.split('%')
        ip = ll_intf[0] + '%' + convert_intf_name_to_component(dut, intf_list=ll_intf[1])
    else:
        ip = convert_intf_name_to_component(dut, intf_list=ip)

    output = st.exec_ssh_remote_dut(dut, ip, username, password, cmds)
    if "Connection timed out" in output or "option requires an argument" in output or "Connection refused" in output\
            or 'Could not resolve hostname' in output:
        st.error("SSH Connection Failed: IP-{}, User-{}, Password-{}".format(ip, username, password))
        return False
    st.log("SSH Connection success: IP-{}, User-{}, Password-{}".format(ip, username, password))
    return True
