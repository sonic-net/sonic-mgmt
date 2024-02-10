# This file contains the list of API's which performs User operations.
# Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
import re
import crypt

from spytest import st
from apis.system.rest import config_rest, delete_rest, get_rest
import apis.system.system_server as sys_server_api

from utilities.common import make_list, get_query_params
from utilities.utils import remove_last_line_from_string, get_supported_ui_type_list
from utilities.common import filter_and_select

try:
    import apis.yang.codegen.messages.primary_encryption_key as umf_pek
except ImportError:
    pass


def config_user(dut, username, mode='add', cli_type=""):
    """
    Add/Delete the user name to the device.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param username:
    :param mode: add|del
    :return:
    """
    # cli_type = st.get_ui_type(dut, cli_type=cli_type)
    username = username.strip()
    if mode == 'add':
        command = "useradd {}".format(username)
        rv = st.config(dut, command)
        if "already exists" in rv:
            st.error("User '{}' already exists".format(username))
            return False
    else:
        command = "userdel {}".format(username)
        rv = st.config(dut, command)
        if "does not exist" in rv:
            st.log("User '{}' does not exist".format(username))
            return False
    return True


def show(dut, *argv, **kwargs):
    """
    Generic show API.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param argv:
    :param kwargs:
    :Usage:
        show(vars.D1, 'logged_users')
        show(vars.D1, 'user_list')
        show(vars.D1, 'group_list')
        show(vars.D1, user_group='admin')
    """
    cli_type = kwargs.get("cli_type", "click")
    cli_type = "klish" if cli_type in get_supported_ui_type_list() else cli_type
    if 'logged_users' in argv:
        return st.show(dut, "show users", type=cli_type)
    if 'user_list' in argv:
        command = "cat /etc/passwd | awk -F: '{ print $1}'"
        return st.show(dut, command, skip_tmpl=True, skip_error_check=True, faster_cli=False).split('\n')[:-1]
    if 'group_list' in argv:
        command = "getent group | awk -F: '{ print $1}'"
        return st.show(dut, command, skip_tmpl=True, skip_error_check=True, faster_cli=False).split('\n')[:-1]
    if kwargs.get('user_group'):
        return st.show(dut, "id {}".format(kwargs['user_group']), type=cli_type)


def verify(dut, *argv, **kwargs):
    """
    Generic verify API.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param argv:
    :param kwargs:
    :Usage:
        verify(vars.D1, 'logged_users', verify_list=[{'user':'admin'}, {'user':'test1}])
        verify(vars.D1, 'user_list', verify_list=['admin', 'test1'])
        verify(vars.D1, 'group_list', verify_list=['admin','operator'])
        verify(vars.D1, user_group='admin', verify_list=[{'group':'admin'}])
    """
    cli_type = kwargs.get("cli_type", "")
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = "klish" if cli_type in get_supported_ui_type_list() else cli_type
    result = True
    if not kwargs.get('verify_list'):
        st.error("Mandatory parameter -verify_list is missing")
        return False
    out = show(dut, *argv, **kwargs)
    if not out:
        return False
    if 'logged_users' in argv or kwargs.get('user_group'):
        for each in make_list(kwargs.get('verify_list')):
            out[0]['secondary_group'] = re.findall(r'\(([^)]+)', out[0]['secondary_group'])
            if each['group'] == 'sudo':
                each['group'] = 'operator'
            if each['group'] not in out[0]['secondary_group']:
                st.log("{} - {} is not match".format(each, out))
                result = False
    if 'user_list' in argv or 'group_list' in argv:
        for each in make_list(kwargs.get('verify_list')):
            if each not in out:
                st.log("{} - is not found in {}".format(each, out))
                result = False

    return result


def config(dut, **kwargs):
    """
    Add/Delete  username with password and role to the device.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param :dut:
    :param :username:
    :param :password:
    :param :role:   admin | operator
    :param :group:
    :param :cli_type:  click | klish
    :param :no_form: 0[False] | 1[True]

    :Usage:
    config(vars.D1, username='test', password='test123', role='operator', cli_type='kilsh')
    config(vars.D1, username='test', cli_type='kilsh', no_form=True)
    config(vars.D1, username='test', password='test123', role='admin', cli_type='click', no_form=0)
    config(vars.D1, username='test', password_update='test1234', cli_type='click', no_form=0)
    config(vars.D1, group='admin_test', cli_type='click', no_form=0)
    config(vars.D1, group='admin_test', cli_type='click', no_form=1)
    config(vars.D1, username='test', password='test123', role='admin', cli_type='click', no_form=1)
    """
    skip_error_check = kwargs.get("skip_error_check", False)
    cli_type = kwargs.get("cli_type", "")
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    no_form = kwargs.get("no_form", False)
    if kwargs.get('username') and kwargs.get('password') and kwargs.get('role') and kwargs.get('mode'):
        if st.is_feature_supported("klish", dut):
            cli_type = 'klish' if cli_type == 'click' else cli_type  # As per SW jira SONIC-31937 forced klish for click

    if cli_type in get_supported_ui_type_list():
        if not kwargs.get('username'):
            st.error("Mandatory parameter 'username' is missing")
            return False
        no_form = kwargs.pop('no_form', False)
        kwargs['config'] = 'no' if no_form else 'yes'
        if not no_form:
            if not kwargs.get("password") and not kwargs.get('role'):
                st.error("Mandatory parameter 'password' and 'role' is missing")
                return False
            if kwargs['role'] == 'sudo':
                kwargs['role'] = 'operator'
        return sys_server_api.config_system_properites(dut, **kwargs)
    elif cli_type == "click":
        if not no_form:
            if kwargs.get('group'):
                st.config(dut, "groupadd {}".format(kwargs['group']))
            if kwargs.get('username'):
                command = "useradd {} -m".format(kwargs['username'])
                if kwargs.get('role'):
                    command += " -g {}".format(kwargs['role'])
                st.config(dut, command)
            if kwargs.get('username') and kwargs.get('password'):
                st.change_passwd(dut, kwargs['username'], kwargs['password'])
            if kwargs.get('username') and kwargs.get('append_role'):
                st.config(dut, "usermod -aG {} {}".format(kwargs['append_role'], kwargs['username']))
        else:
            if kwargs.get('username') and kwargs.get('role'):
                st.config(dut, "gpasswd -d {} {}".format(kwargs['username'], kwargs['role']))
            if kwargs.get('group'):
                st.config(dut, "groupdel {}".format(kwargs['group']))
            if kwargs.get('username'):
                st.config(dut, "userdel {} -r".format(kwargs['username']))

    elif cli_type == "klish":
        if not kwargs.get('username'):
            st.error("Mandatory parameter 'username' is missing")
            return False
        if not no_form:
            if not kwargs.get("password") and not kwargs.get('role'):
                st.error("Mandatory parameter 'password' and 'role' is missing")
                return False
            if kwargs['role'] == 'sudo':
                kwargs['role'] = 'operator'
            command = "username {} password {} role {}".format(kwargs['username'], kwargs['password'], kwargs['role'])
        if no_form:
            command = "no username {} ".format(kwargs['username'])
        st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)
        # add_user(dut, kwargs['username'])
    elif cli_type in ['rest-patch', 'rest-put']:
        if not no_form:
            if kwargs['role'] == 'sudo':
                kwargs['role'] = 'operator'
            data = {
                "openconfig-system:user": [
                    {
                        "username": str(kwargs['username']),
                        "config": {
                            "username": str(kwargs['username']),
                            "password": "",
                            "password-hashed": str(hashed_pwd(str(kwargs['password']))),
                            "role": str(kwargs['role'])
                        }
                    }
                ]
            }
            rest_urls = st.get_datastore(dut, "rest_urls")
            url1 = rest_urls['user_creation_del'].format(kwargs['username'])
            if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=data):
                st.error("Failed to configure user {} ".format(kwargs['username']))
                return False
        if no_form:
            rest_urls = st.get_datastore(dut, "rest_urls")
            url1 = rest_urls['user_creation_del'].format(kwargs['username'])
            if not delete_rest(dut, http_method=cli_type, rest_url=url1):
                st.error("Failed to delete user {} ".format(kwargs['username']))
    else:
        st.log("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False
    return True


def hashed_pwd(pwd):
    pwd = pwd.replace("\\", "")
    if pwd[:3] == '$6$':
        return pwd
    return crypt.crypt(pwd, crypt.mksalt(crypt.METHOD_SHA512))


def get_root_privilege(docker_name='', ssh_obj=""):
    """
    Api to get root access using docker exec command
    :param dut:
    :param docker_name:
    :param username:
    :param password:
    :return:
    """
    prompt = ssh_obj.find_prompt()
    command = 'sudo docker exec -it {} sh -c "/bin/bash;# ps aux"'.format(docker_name)
    output = ssh_obj.send_command(command, expect_string="{}|:|$|#".format(prompt), max_loops=50, delay_factor=5)
    if "password for {}:".format(ssh_obj.username).lower() in output.lower():
        command = "{}".format(ssh_obj.password)
        result = ssh_obj.send_command(command, expect_string="{}|:|$|#".format(prompt), max_loops=50, delay_factor=5)
        if ("sorry" in result.lower() or "not allowed" in result.lower()):
            st.log("User {} doesn't have root access".format(ssh_obj.username))
            return False
        else:
            st.debug(result)
            return True
    elif "/#" in output:
        ssh_obj.send_command("exit", expect_string="{}|#|$".format(prompt))
        st.log("User {} has root access".format(ssh_obj.username))
        return True
    else:
        st.debug(output)
        return False


def vtysh_chain(ssh_obj='', commands=[]):
    """
    Api to run chain commands using vtysh -c
    :param dut:
    :param username:
    :param password:
    :param commands:
    :return:
    """
    prompt = ssh_obj.find_prompt()
    cmd = "sudo vtysh -c 'show version'"
    for each in commands:
        cmd = "{} -c '{}'".format(cmd, each)
    output = ssh_obj.send_command(cmd, expect_string="{}".format(prompt), max_loops=50, delay_factor=5)
    if "error" in output.lower():
        st.log("command failed to execute")
        st.debug(output)
        return []
    elif "frrouting" in output.lower():
        st.log("vtysh chain commands successfully executed")
        st.debug(output)
        return output
    else:
        st.debug(output)
        return []


def get_docker_privileges(dut, docker_name):
    """
    Api to get docker privileges
    :param dut:
    :param docker_name:
    :return:
    """
    if not docker_name:
        st.error("mandatory argument docker name is missing")
        return False
    command = "docker inspect {} | grep Privilege".format(docker_name)
    output = remove_last_line_from_string(st.show(dut, command, skip_tmpl=True))
    if "false" in output:
        st.log("docker {} running without privileges".format(docker_name))
        return False
    elif "true" in output:
        st.log("docker {} running with privileges".format(docker_name))
        return True
    else:
        st.debug(output)
        return False


def arbitrary_file_read(ssh_obj='', files=[]):
    """
    Api to read arbitrary file(s)
    :param ssh_obj:
    :param files:
    :return:
    """
    cmd = "sudo /bin/cat"
    if not files:
        st.error("Please send atleast 1 file to read file")
        return False
    prompt = ssh_obj.find_prompt()
    for each in files:
        cmd = "{} {}".format(cmd, each)
    output = ssh_obj.send_command(cmd, expect_string="{}|password for {}:".format(prompt, ssh_obj.username),
                                  max_loops=50, delay_factor=5)
    if "password for {}:".format(ssh_obj.username).lower() in output.lower():
        cmd = "{}".format(ssh_obj.password)
        result = ssh_obj.send_command(cmd, expect_string=prompt, max_loops=50, delay_factor=5)
        if ("sorry" in result.lower() or "not allowed" in result.lower()):
            st.log("User {} doesn't have root access".format(ssh_obj.username))
        else:
            st.debug(result)
        return False
    else:
        st.log("file content")
        st.log(output)
        return output


def config_primary_key_encryption(dut, key, **kwargs):
    """
    Author: Pavan Kumar Kasula(pavan.kasula@broadcom.com)
    Function to configure add/del/update Primary key config
    :param dut:
    :param key, old_key:
    :param cli_type:
    :return:
    usage:user_api.config_primary_key_encryption(data.dut1, key='Broadcom@123', config_mode='del_key')
          user_api.config_primary_key_encryption(data.dut1, key='Broadcom@123')
          user_api.config_primary_key_encryption(data.dut1, key='Brcmkey@123', config_mode='update_key', old_key = 'Broadcom@123')
    """
    override = kwargs.get("override", False)
    config_mode = kwargs.get("config_mode", 'new_key')
    skip_error = kwargs.get('skip_error', False)
    save_config = kwargs.get("save_config", 'Y')
    # supports only klish
    cli_type = 'klish'
    if cli_type == "klish":
        command = "key config-key password-encrypt"
        if config_mode == 'new_key':
            return st.config(dut, command, type=cli_type, confirm=[["New key:", key], ["Confirm key:", key], "confirm:", save_config])
        elif config_mode == 'update_key':
            output = st.config(dut, command, skip_error_check=skip_error, type=cli_type, confirm=[["New key:", key], ["Confirm key:", key], ["Old key:", kwargs['old_key']], "confirm:", save_config])
            if "Error" in output:
                st.error("Error seen while configuring.")
                return False
            else:
                return True
        elif config_mode == 'del_key':
            command = 'no ' + command
            if override:
                command = command + ' override'
                return st.config(dut, command, type=cli_type)
            output = st.config(dut, command, skip_error_check=skip_error, type=cli_type, confirm=save_config)
            if "Error" in output:
                st.error("Error seen while configuring.")
                return False
            else:
                return True


def verify_primary_key(dut, **kwargs):
    """
    Author: Pavan Kumar Kasula(pavan.kasula@broadcom.com)
    Function to verify the Master key config status
    :param dut:
    :param status:
    :param cli_type:
    :return:
    """
    cli_type = kwargs.get("cli_type", st.get_ui_type(dut))
    # cli_type = 'klish' if cli_type in get_supported_ui_type_list() else cli_type
    cli_type = 'klish' if cli_type in ["click"] else cli_type

    if cli_type in get_supported_ui_type_list():
        filter_type = kwargs.get('filter_type', 'NON_CONFIG')
        query_param_obj = get_query_params(yang_data_type=filter_type, cli_type=cli_type)
        configured = 'true' if kwargs['status'] == 'True' else False
        pek_obj = umf_pek.PrimaryEncryptionKey(Configured=configured)
        result = pek_obj.verify(dut, match_subset=True, query_param=query_param_obj, cli_type=cli_type)
        if not result.ok():
            output = result.payload
            if not output and kwargs['status'] != 'True':
                st.log('Expected blank o/p, when key is not configured')
                return True
            st.log('test_step_failed: Match Not Found')
            return False
        return True

    if cli_type == "klish":
        output = st.show(dut, cmd="show config-key password-encrypt", type=cli_type)

    elif cli_type in ['rest-patch', 'rest-put']:
        status = ''
        rest_urls = st.get_datastore(dut, 'rest_urls')
        rest_url = rest_urls['show_primary_key_encr']
        out = get_rest(dut, rest_url=rest_url)
        if 'ietf-restconf:errors' in out['output']:
            status = 'False'
        else:
            status = out['output']['openconfig-primary-encryption-key:configured']
        single_var = {'status': status}
        output = [single_var]
    if len(output) == 0:
        st.error("OUTPUT is Empty")
        return False

    if 'return_output' in kwargs:
        return output
    for each in kwargs.keys():
        match = {each: kwargs[each]}
        entries = filter_and_select(output, None, match)
        if not entries:
            st.error("Match not found for {}:   Expected - {} Actual - {} ".format(each, kwargs[each], output[0][each]))
            return False
    return True
